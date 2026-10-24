// dictionary_mgr.h — giant dictionary memory management (spec §3.a)
//
// Compression typically needs ~1.5x to 2.5x of the dictionary size in RAM.
// Per the specification pseudo-code we require  dict*2  bytes of AVAILABLE
// RAM before allowing a compression job with the selected dictionary.
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace wrc {

struct DictionaryCheck {
    bool ok = true;              // required fits inside available RAM
    uint64_t availableRam = 0;   // bytes currently available
    uint64_t requiredRam = 0;    // dictionary * 2
    uint64_t safeThreshold = 0;  // 90 % of available
    bool withinSafeThreshold() const { return requiredRam <= safeThreshold; }
};

class DictionaryManager {
public:
    static uint64_t systemTotalRam();
    static uint64_t systemAvailableRam();
    static DictionaryCheck validate(uint64_t dictSizeBytes);
    static uint64_t maxSupportedDict();       // largest dict passing validation
    // Window the encoder can really afford (window + hash-chain tables).
    // Archives may still declare any dictionary up to 64 GB — the decoder is
    // file-backed and needs O(1) RAM (see lzss.h).
    static uint64_t effectiveEncoderWindow(uint64_t dictSizeBytes);

    explicit DictionaryManager(uint64_t dictSizeBytes);
    ~DictionaryManager();
    DictionaryManager(const DictionaryManager&) = delete;
    DictionaryManager& operator=(const DictionaryManager&) = delete;

    bool allocate();   // reserve & commit dictionary memory (touch pages)
    void release();
    // The chain-table allocated by allocate() - borrowed by the LZSS encoder.
    std::vector<uint32_t>& table() { return table_; }
    void* data() { return table_.data(); }
    uint64_t size() const { return dictSize_; }

private:
    uint64_t dictSize_;
    std::vector<uint32_t> table_;
};

}  // namespace wrc
