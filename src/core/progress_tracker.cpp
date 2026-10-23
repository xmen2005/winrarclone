// progress_tracker.cpp
#include "core/progress_tracker.h"

#include <algorithm>

namespace wrc {

ProgressTracker::ProgressTracker(Progress::Phase phase, uint64_t totalBytes, ProgressFn pf)
    : phase_(phase), total_(totalBytes), pf_(std::move(pf)) {}

void ProgressTracker::setFile(const std::wstring& name) {
    std::lock_guard<std::mutex> lk(m_);
    file_ = name;
}

void ProgressTracker::addDone(uint64_t originalBytes) {
    std::lock_guard<std::mutex> lk(m_);
    done_ += originalBytes;
}

void ProgressTracker::setDone(uint64_t originalBytes) {
    std::lock_guard<std::mutex> lk(m_);
    done_ = originalBytes;
}

void ProgressTracker::addCompressed(uint64_t packedBytes) {
    std::lock_guard<std::mutex> lk(m_);
    packed_ += packedBytes;
}

uint64_t ProgressTracker::done() const {
    std::lock_guard<std::mutex> lk(m_);
    return done_;
}

void ProgressTracker::emitLocked() {
    if (!pf_) return;
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - start_).count();
    double inst = elapsed > 0.25 ? double(done_) / elapsed : 0;
    speed_ = speed_ == 0 ? inst : speed_ * 0.7 + inst * 0.3;
    Progress p;
    p.phase = phase_;
    p.currentFile = file_;
    p.bytesDone = done_;
    p.bytesTotal = total_;
    p.bytesCompressed = packed_;
    p.totalRatio = total_ ? double(std::min(done_, total_)) / double(total_) : 1.0;
    p.fileRatio = p.totalRatio;
    p.elapsed = elapsed;
    p.speed = speed_;
    p.eta = speed_ > 1 && total_ > done_ ? double(total_ - done_) / speed_ : 0;
    lastEmit_ = now;
    pf_(p);
}

void ProgressTracker::check(ControlFn cf) {
    if (cf && !cf()) throw CancelledError();
    std::lock_guard<std::mutex> lk(m_);
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration<double>(now - lastEmit_).count() >= 0.05) emitLocked();
}

}  // namespace wrc
