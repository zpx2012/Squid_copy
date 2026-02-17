#ifndef OPTIMACK_RANGE_GAP_DISPATCHER_H
#define OPTIMACK_RANGE_GAP_DISPATCHER_H

#include "interval_boost.h"

class RangeGapDispatcher {
public:
    RangeGapDispatcher(int group_count, bool debug);
    void distribute(const interval_map& gaps, IntervalList** group_queue);

private:
    int group_count_;
    bool debug_;
    int next_group_;
};

#endif // OPTIMACK_RANGE_GAP_DISPATCHER_H
