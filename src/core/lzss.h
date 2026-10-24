// lzss.h — LZ77-class codec with configurable dictionary window
//
// Token stream: groups of 8 tokens prefixed by a flag byte
//   bit=1 -> literal byte          bit=0 -> match
// Match encoding: varint(distance-1), varint(length-4)   (LEB128)
//
// The decoder is file-backed: matches are copied by reading back the output
// sink, so archives declaring dictionaries up to 64 GB decode with O(1) RAM.
// The encoder uses a RAM-bounded window (see dictionary_mgr).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace wrc {

struct LzssParams {
    uint64_t window = 64ull << 20;  // effective encoder window (power of two)
    int chainDepth = 64;
    bool lazy = true;
    bool longRange = false;         // search the whole window
    bool exhaustive = false;        // very deep chains, no early exit
    int zlibLevel = 6;             // deflate level used when wrapping LZSS output
};

// Method -> effort mapping (Store/Fastest/Fast normally use Deflate instead).
LzssParams lzssParamsForMethod(uint8_t method, bool longRange, bool exhaustive);

struct LzssOutSink {
    virtual void write(const void* buf, size_t len) = 0;
    // Read back bytes [offset, offset+len) of ALREADY WRITTEN output.
    virtual void readBack(uint64_t offset, void* buf, size_t len) = 0;
    virtual ~LzssOutSink() = default;
};

// RAM sink (decode into memory).
class LzssMemSink : public LzssOutSink {
public:
    std::vector<uint8_t> data;
    explicit LzssMemSink(size_t reserveBytes = 0) { if (reserveBytes) data.reserve(reserveBytes); }
    void write(const void* buf, size_t len) override {
        const uint8_t* p = static_cast<const uint8_t*>(buf);
        data.insert(data.end(), p, p + len);
    }
    void readBack(uint64_t offset, void* buf, size_t len) override {
        memcpy(buf, data.data() + offset, len);
    }
};

// File-backed sink with a small tail cache for fast overlap copies.
class LzssFileSink : public LzssOutSink {
public:
    explicit LzssFileSink(class File& f);
    void write(const void* buf, size_t len) override;
    void readBack(uint64_t offset, void* buf, size_t len) override;

private:
    File& f_;
    std::vector<uint8_t> cache_;
    uint64_t base_ = 0;
    static const size_t kCache = 32u << 20;
};

void lzssEncode(const uint8_t* in, uint64_t inLen, const LzssParams& params,
                std::vector<uint8_t>& out, std::vector<uint32_t>* borrowedChainTable);
bool lzssDecode(const uint8_t* in, uint64_t inLen, LzssOutSink& out, std::string& err);

}  // namespace wrc
