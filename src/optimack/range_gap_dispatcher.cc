#include "range_gap_dispatcher.h"

#include "logging.h"

RangeGapDispatcher::RangeGapDispatcher(int group_count, bool debug)
    : group_count_(group_count),
      debug_(debug),
      next_group_(0)
{
}

void RangeGapDispatcher::distribute(const interval_map& gaps, IntervalList** group_queue)
{
    for (auto it = gaps.begin(); it != gaps.end(); ++it) {
        if (debug_) {
            print_func("[Range]: range_watch_multi: insert [%u, %u] to group %d",
                       it->first.lower(),
                       it->first.upper(),
                       next_group_ + 1);
        }
        group_queue[next_group_]->insertNewInterval(it->first.lower(), it->first.upper());
        next_group_ = (next_group_ + 1) % group_count_;
    }
}
