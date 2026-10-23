// dictionary_mgr.cpp
#include "core/dictionary_mgr.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace wrc {

uint64_t DictionaryManager::systemTotalRam() {
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) return ms.ullTotalPhys;
    return 0;
}

uint64_t DictionaryManager::systemAvailableRam() {
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) return ms.ullAvailPhys;
    return 0;
}

DictionaryCheck DictionaryManager::validate(uint64_t dictSizeBytes) {
    DictionaryCheck c;
    c.availableRam = systemAvailableRam();
    c.requiredRam = dictSizeBytes * 2;  // spec pseudo-code
    c.safeThreshold = c.availableRam / 10 * 9;
    c.ok = c.requiredRam <= c.availableRam;
    return c;
}

uint64_t DictionaryManager::maxSupportedDict() {
    uint64_t avail = systemAvailableRam();
    uint64_t d = 1ull << 20;
    while (d < (64ull << 30) && d * 2 <= avail) d <<= 1;
    return d;
}

uint64_t DictionaryManager::effectiveEncoderWindow(uint64_t dictSizeBytes) {
    // Encoder memory: window (1 B/byte) + prev-chain table (4 B/byte) + head.
    // Keep total under ~60 % of available RAM, hard-capped at 2 GiB window.
    uint64_t avail = systemAvailableRam();
    uint64_t budget = avail / 3;
    uint64_t w = dictSizeBytes;
    const uint64_t cap2g = 2ull << 30;
    if (w > cap2g) w = cap2g;
    if (w > budget) {
        w = budget / 5;  // window + 4x prev table
    }
    // Round down to power of two, floor 1 MiB.
    uint64_t p = 1ull << 20;
    while (p * 2 <= w) p *= 2;
    return p;
}

DictionaryManager::DictionaryManager(uint64_t dictSizeBytes) : dictSize_(dictSizeBytes) {}

DictionaryManager::~DictionaryManager() { release(); }

bool DictionaryManager::allocate() {
    if (dictSize_ == 0) return true;
    try {
        window_.resize(static_cast<size_t>(dictSize_));
        // Touch pages so the commit happens now, not mid-compression.
        volatile unsigned char sink = 0;
        for (size_t i = 0; i < window_.size(); i += 4096) window_[i] = 0, sink ^= window_[i];
        (void)sink;
        return true;
    } catch (...) {
        window_.clear();
        return false;
    }
}

void DictionaryManager::release() {
    window_.clear();
    window_.shrink_to_fit();
}

}  // namespace wrc
