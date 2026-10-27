#pragma once
#include <chrono>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include "proctree.h"

namespace procrib {

struct CollectOpts {
    bool signatures = false;
};

std::vector<Proc> collect(const CollectOpts& o);

// Fills cpu_pct from the difference against the previous call.
class CpuTracker {
public:
    void update(std::vector<Proc>& procs);

private:
    struct Sample {
        uint64_t start;
        uint64_t cpu;
    };
    std::unordered_map<uint32_t, Sample> prev_;
    std::chrono::steady_clock::time_point prev_time_;
    bool have_prev_ = false;
};

}  // namespace procrib
