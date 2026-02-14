#include "interval_boost.h"
#include <boost/range/adaptor/strided.hpp>
#include <stdio.h>
#include "logging.h"
#include <string.h>
#include <iostream>
#include <sstream>
#include <chrono>

bool debug = false;

const char* order_types[] = {"out of order", "nerwest in order", "in order fill", "new request", "timeout request"};


unsigned int IntervalList::size()
{
    std::shared_lock lock(smtx); 
    return boost::icl::interval_count(Intervals);
}


void IntervalList::clear()
{
    std::unique_lock lock(smtx);
    Intervals.clear();
}


interval_map::iterator IntervalList::begin() 
{ 
    std::shared_lock lock(smtx); 
    return Intervals.begin(); 
}


interval_map::iterator IntervalList::end() 
{ 
    std::shared_lock lock(smtx);
    return Intervals.end(); 
}


unsigned int IntervalList::total_bytes()
{
    std::shared_lock lock(smtx);
    return Intervals.size();
}


unsigned int IntervalList::getFirstStart()
{
    std::shared_lock lock(smtx);
    if (!Intervals.empty()){
        return Intervals.begin()->first.lower();
    }
    else
        return 0;
}
unsigned int IntervalList::getFirstEnd()
{
    std::shared_lock lock(smtx);
    if (!Intervals.empty())
        return Intervals.begin()->first.upper();
    else
        return 0;
}

unsigned int IntervalList::getLastEnd()
{
    std::shared_lock lock(smtx);
    if (!Intervals.empty())
        return prev(Intervals.end())->first.upper();
    else
        return 0;
}


bool IntervalList::contains(unsigned int start, unsigned int end)
{
    std::shared_lock lock(smtx);
    return boost::icl::contains(Intervals, interval_type::right_open(start, end));
}


// Function to insert new interval and
void IntervalList::insertNewInterval(unsigned int start, unsigned int end)
{
    std::unique_lock lock(smtx);
    Intervals += std::make_pair(interval_type::right_open(start, end), 0.01);
}


interval_map IntervalList::removeInterval(unsigned int start, unsigned int end)
{
    interval_map overlaps;
    overlaps += std::make_pair(interval_type::right_open(start, end), 0.01);
    std::unique_lock lock(smtx);
    overlaps &= Intervals;
    for(auto it = overlaps.begin(); it != overlaps.end(); it++){
        Intervals -= it->first;
        uint first_start = Intervals.begin()->first.lower();
        if(first_start == end)
            it->second = IN_ORDER_NEWEST;
        else if(first_start > end)
            it->second = IN_ORDER_FILL;
        else
            it->second = OUT_OF_ORDER;
    }
    return overlaps;
}

double now_ns(){
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count()/1000000000.0;
}

interval_map IntervalList::getGapsAndUpdateTimer(uint min_seq, int num, int timeout){

    interval_map result;
    double time_now = now_ns();
    std::vector<uint> candidates;
    
    // Reserve memory to prevent reallocations during the loop
    candidates.reserve(num);

    // --- Phase 1: Read (Shared Lock) ---
    // Identify potential candidates without blocking other readers or writers.
    {
        std::shared_lock lock(smtx);
        int cnt = 0, skip = 0;
        for(auto it = Intervals.begin(); it != Intervals.end(); ++it){
            // Skip gaps that are newer than the min_seq (not yet eligible for retrans)
            if(it->first.upper() - 1 >= min_seq)
                continue; //
            
            // if((skip++) % timeout != 0)
            //     continue;

            // Check eligibility: either new (0.01) or timed out
            if((it->second == 0.01) || (time_now - it->second >= timeout)){
                candidates.push_back(it->first.lower());
                // Collect slightly more than needed to handle potential race conditions
                if(++cnt >= num){
                    // std::cout << num << std::endl;
                    break;
                }
            }
        }
    }

    // If no work is found, return immediately.
    if(candidates.empty())
        return result;

    // --- Phase 2: Write (Unique Lock) ---
    {
        // OPTIMIZATION: Use try_to_lock. 
        // If another thread is currently writing, we yield immediately instead of 
        // queuing up and causing a convoy effect.
        std::unique_lock lock(smtx); //, std::try_to_lock
        
        // if (!lock.owns_lock()) {
        //     // Contention detected: Another thread is likely handling gaps.
        //     // Return empty result to yield.
        //     return result;
        // }

        int cnt = 0;
        for(const auto& start_seq : candidates){
            // Re-find the interval. It might have changed since we released the read lock.
            auto it = Intervals.find(start_seq);

            // Validation checks under write lock:
            if(it == Intervals.end()) 
                continue;
            
            // Re-check strict sequence limit
            if(it->first.lower() == 1 || it->first.upper() - 1 >= min_seq) 
                continue;

            double code = 0;
            // Re-check timing conditions
            if(it->second == 0.01)
                code = REQUEST_NEW;
            else if(time_now - it->second >= timeout)
                code = REQUEST_TIMEOUT;
            else 
                continue; // It was updated by another thread just before we got the lock

            // Add to result set
            result += std::make_pair(it->first, code);
            // if(timeout == 100)
            //     std::cout << "add " << it->first << " - " << order_types[int(code)] << ", ";

            // Update timestamp in the main map
            // Note: Using the exact same 'time_now' for all items in this batch
            // helps boost::icl merge adjacent intervals if they become contiguous.
            Intervals.set(std::make_pair(it->first, time_now)); //

            if(++cnt == num)
                break;
        }
        // if(timeout == 100)
        //     std::cout << "min_seq: " << min_seq << ", " << Intervals << std::endl;
    }
    
    return result;
}



void IntervalList::substract(IntervalList* other)
{
    std::unique_lock lock(smtx);
    Intervals -= other->Intervals;
}



void IntervalList::printIntervals(){

    std::shared_lock lock(smtx);
    std::stringstream ss;
    ss << Intervals;
    std::cout << ss.str().substr(0,100) << std::endl;
}

std::string IntervalList::Intervals2str(){

    std::shared_lock lock(smtx);
    if(!size())
        return "";

    std::string result = "";
    char temp[100] = {0};
    for(auto it = Intervals.begin(); it != Intervals.end(); it++){
        memset(temp, 0, 100);
        sprintf(temp, "[%u, %u), ", it->first.lower(), it->first.upper());
        result += temp;
    }
    return result;
}