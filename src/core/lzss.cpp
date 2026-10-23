// lzss.cpp
#include "core/lzss.h"

#include "utils/file_system.h"

#include <algorithm>
#include <cstring>

namespace wrc {

// ------------------------------------------------------------------- varint
static inline void putVarint(std::vector<uint8_t>& v, uint64_t x) {
    while (x >= 0x80) {
        v.push_back(uint8_t((x & 0x7F) | 0x80));
        x >>= 7;
    }
    v.push_back(uint8_t(x));
}

struct VarReader {
    const uint8_t* p;
    uint64_t n;
    uint64_t pos = 0;
    bool ok = true;
    int readByte() {
        if (pos >= n) {
            ok = false;
            return 0;
        }
        return p[pos++];
    }
    uint64_t readVarint() {
        uint64_t r = 0;
        int shift = 0;
        for (;;) {
            int b = readByte();
            if (!ok) return 0;
            r |= uint64_t(b & 0x7F) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
            if (shift > 63) {
                ok = false;
                return 0;
            }
        }
        return r;
    }
};

// -------------------------------------------------------------------- sinks
LzssFileSink::LzssFileSink(File& f) : f_(f) { cache_.reserve(kCache + (1u << 20)); }

void LzssFileSink::write(const void* buf, size_t len) {
    if (len == 0) return;
    f_.write(buf, uint32_t(len));
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    cache_.insert(cache_.end(), p, p + len);
    if (cache_.size() > kCache) {
        size_t drop = cache_.size() - kCache;
        cache_.erase(cache_.begin(), cache_.begin() + ptrdiff_t(drop));
        base_ += drop;
    }
}

void LzssFileSink::readBack(uint64_t offset, void* buf, size_t len) {
    if (len == 0) return;
    if (offset >= base_ && offset + len <= base_ + cache_.size()) {
        memcpy(buf, cache_.data() + (offset - base_), len);
        return;
    }
    uint32_t got = 0;
    f_.pread(buf, uint32_t(len), offset, got);
}

// ------------------------------------------------------------------ encoder
LzssParams lzssParamsForMethod(uint8_t method, bool longRange, bool exhaustive) {
    LzssParams p;
    p.longRange = longRange;
    p.exhaustive = exhaustive;
    switch (method) {
        case 3:  // Normal
            p.chainDepth = 64;
            break;
        case 4:  // Good
            p.chainDepth = 512;
            break;
        case 5:  // Best
            p.chainDepth = 4096;
            break;
        default:
            p.chainDepth = 32;
            break;
    }
    return p;
}

static const int HS_BITS = 22;
static const uint32_t HS_SIZE = 1u << HS_BITS;

static inline uint32_t hash4(const uint8_t* p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return (v * 2654435761u) >> (32 - HS_BITS);
}

void lzssEncode(const uint8_t* in, uint64_t inLen, const LzssParams& params,
                std::vector<uint8_t>& out, std::vector<uint32_t>* borrowedChainTable) {
    out.clear();
    if (inLen == 0) return;
    out.reserve(size_t(inLen + inLen / 8 + 4096));

    // window: power of two, >= 4 KiB
    uint64_t W = params.window;
    uint64_t p2 = 1ull << 12;
    while (p2 * 2 <= W) p2 *= 2;
    W = p2;
    if (W > inLen) {
        W = p2;
        while (W / 2 >= (1ull << 12) && W / 2 >= inLen) W /= 2;
    }
    const uint64_t mask = W - 1;
    const uint64_t maxDist = params.longRange ? W : std::min<uint64_t>(W, 256ull << 20);

    std::vector<uint32_t> tableStorage;
    std::vector<uint32_t>& prev = borrowedChainTable ? *borrowedChainTable : tableStorage;
    if (&prev != borrowedChainTable) prev.resize(size_t(W));
    prev.assign(size_t(W), 0);
    std::vector<int64_t> head(HS_SIZE, -1);

    auto insert = [&](uint64_t pos) {
        if (pos + 4 <= inLen) {
            uint32_t h = hash4(in + pos);
            prev[size_t(pos & mask)] = uint32_t(head[h] & 0xFFFFFFFF);
            head[h] = int64_t(pos);
        }
    };
    auto matchLen = [&](uint64_t cand, uint64_t at, uint32_t cap) {
        uint64_t maxl = std::min<uint64_t>(cap, inLen - at);
        uint64_t l = 0;
        while (l < maxl && in[cand + l] == in[at + l]) ++l;
        return uint32_t(l);
    };
    // search longest match at `at`; no insertion
    auto search = [&](uint64_t at, uint32_t& bestLen, uint64_t& bestDist) {
        bestLen = 0;
        bestDist = 0;
        if (at + 4 > inLen) return;
        int64_t cand = head[hash4(in + at)];
        int depth = params.exhaustive ? 8192 : params.chainDepth;
        while (cand >= 0) {
            uint64_t d = at - uint64_t(cand);
            if (d == 0 || d > maxDist) break;
            uint32_t l = matchLen(uint64_t(cand), at, 0xFFFF);
            if (l > bestLen) {
                bestLen = l;
                bestDist = d;
                if (bestLen >= (params.exhaustive ? 0xFFFFu : 4096u)) break;
            }
            if (--depth <= 0) break;
            uint32_t low = prev[size_t(uint64_t(cand) & mask)];
            int64_t next = (cand & ~int64_t(0xFFFFFFFF)) | int64_t(low);
            if (next >= cand) next -= int64_t(1) << 32;
            cand = next;
        }
    };

    // token writer
    size_t flagPos = 0;
    uint8_t flag = 0;
    int nbits = 0;
    auto beginGroup = [&] {
        flagPos = out.size();
        out.push_back(0);
        flag = 0;
        nbits = 0;
    };
    auto endToken = [&] { out[flagPos] = flag; };
    beginGroup();
    auto lit = [&](uint8_t b) {
        if (nbits == 8) beginGroup();
        out.push_back(b);
        flag |= uint8_t(1 << nbits);
        ++nbits;
        endToken();
    };
    auto emitMatch = [&](uint64_t dist, uint32_t len) {
        if (nbits == 8) beginGroup();
        putVarint(out, dist - 1);
        putVarint(out, len - 4);
        ++nbits;
        endToken();
    };

    const uint32_t kNice = 192;
    for (uint64_t ip = 0; ip < inLen;) {
        if (ip + 4 > inLen) {
            for (; ip < inLen; ++ip) lit(in[ip]);
            break;
        }
        uint32_t bestLen = 0;
        uint64_t bestDist = 0;
        search(ip, bestLen, bestDist);
        if (params.lazy && bestLen < kNice && ip + 1 + 4 <= inLen) {
            uint32_t l2 = 0;
            uint64_t d2 = 0;
            search(ip + 1, l2, d2);
            if (l2 > bestLen) {
                lit(in[ip]);
                insert(ip);
                ++ip;
                continue;
            }
        }
        if (bestLen >= 4) {
            emitMatch(bestDist, bestLen);
            for (uint32_t k = 0; k < bestLen; ++k) insert(ip + k);
            ip += bestLen;
        } else {
            lit(in[ip]);
            insert(ip);
            ++ip;
        }
    }
}

// ------------------------------------------------------------------ decoder
bool lzssDecode(const uint8_t* in, uint64_t inLen, LzssOutSink& out, std::string& err) {
    VarReader rd{in, inLen};
    uint64_t outPos = 0;
    std::vector<uint8_t> tmp(1u << 16);
    for (;;) {
        if (rd.pos >= rd.n) break;
        uint8_t flag = uint8_t(rd.readByte());
        if (!rd.ok) break;
        for (int b = 0; b < 8 && rd.pos < rd.n; ++b) {
            if (flag & (1 << b)) {
                uint8_t lit = uint8_t(rd.readByte());
                if (!rd.ok) {
                    err = "truncated stream";
                    return false;
                }
                out.write(&lit, 1);
                ++outPos;
            } else {
                uint64_t d = rd.readVarint() + 1;
                uint64_t len = rd.readVarint() + 4;
                if (!rd.ok || d == 0 || d > outPos) {
                    err = "corrupt match";
                    return false;
                }
                while (len > 0) {
                    uint64_t chunk = std::min<uint64_t>({len, d, uint64_t(tmp.size())});
                    out.readBack(outPos - d, tmp.data(), size_t(chunk));
                    out.write(tmp.data(), size_t(chunk));
                    outPos += chunk;
                    len -= chunk;
                }
            }
        }
    }
    return true;
}

}  // namespace wrc
