// progress_tracker.h — shared progress/speed/ETA accounting for jobs
#pragma once
#include "core/common.h"

#include <chrono>
#include <mutex>

namespace wrc {

class ProgressTracker {
public:
    ProgressTracker(Progress::Phase phase, uint64_t totalBytes, ProgressFn pf);

    void setFile(const std::wstring& name);
    void addDone(uint64_t originalBytes);
    void addCompressed(uint64_t packedBytes);
    void setDone(uint64_t originalBytes);   // absolute form
    // Calls cf(); throws CancelledError when the user cancels.
    void check(ControlFn cf);

    uint64_t done() const;
    uint64_t total() const { return total_; }

private:
    void emitLocked();

    Progress::Phase phase_;
    uint64_t total_;
    ProgressFn pf_;
    mutable std::mutex m_;
    uint64_t done_ = 0;
    uint64_t packed_ = 0;
    std::wstring file_;
    std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point lastEmit_ = start_;
    double speed_ = 0;  // EMA
};

}  // namespace wrc
