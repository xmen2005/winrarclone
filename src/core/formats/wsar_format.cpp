// wsar_format.cpp — native WSAR container implementation
// (open RAR5-style format, see docs/FORMAT_WSAR.md)
#include "core/formats/wsar_format.h"

#include "core/crc32.h"
#include "core/dictionary_mgr.h"
#include "core/lzss.h"
#include "core/progress_tracker.h"
#include "core/thread_pool.h"
#include "utils/file_system.h"
#include "utils/security.h"

#include <bcrypt.h>
#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <functional>

namespace wrc {
namespace wsar {

static const uint8_t kMagic[8] = {'W', 'S', 'A', 'R', 0x1A, 0x07, 0x01, 0x00};
static const uint64_t kFrameFixed = 26;  // magic8+crc4+hsize2+type1+flags1+rsv2+dlen8
enum : uint8_t { H_MAIN = 1, H_FILE = 2, H_END = 3 };
enum : uint32_t { AF_VOLUME = 1, AF_ENC_NAMES = 2, AF_SOLID = 4 };

static void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(uint8_t(x));
    v.push_back(uint8_t(x >> 8));
}
static void put32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(uint8_t(x >> (8 * i)));
}
static void put64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(uint8_t(x >> (8 * i)));
}
static uint16_t rd16(const uint8_t* p) { return uint16_t(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
           (uint32_t(p[3]) << 24);
}
static uint64_t rd64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
    return v;
}

// ------------------------------------------------------------------ CNG RAII
namespace {

class CngAes {
public:
    CngAes() {
        BCryptOpenAlgorithmProvider(&hAlg_, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (hAlg_)
            BCryptSetProperty(hAlg_, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    }
    ~CngAes() {
        if (hKey_) BCryptDestroyKey(hKey_);
        if (hAlg_) BCryptCloseAlgorithmProvider(hAlg_, 0);
    }
    bool setKey(const std::vector<uint8_t>& key) {
        if (!hAlg_ || key.size() != 32) return false;
        return BCryptGenerateSymmetricKey(hAlg_, &hKey_, nullptr, 0, (PUCHAR)key.data(),
                                          32, 0) == 0;
    }
    bool encrypt(const uint8_t* in, size_t n, uint8_t* out, size_t cap, size_t& outN,
                 std::vector<uint8_t>& iv, bool padding) {
        if (iv.size() != 16) return false;
        ULONG cb = 0;
        if (BCryptEncrypt(hKey_, (PUCHAR)in, ULONG(n), nullptr, iv.data(), ULONG(iv.size()),
                          out, ULONG(cap), &cb,
                          padding ? BCRYPT_BLOCK_PADDING : 0) != 0)
            return false;
        outN = cb;
        return true;
    }
    bool decrypt(const uint8_t* in, size_t n, uint8_t* out, size_t cap, size_t& outN,
                 std::vector<uint8_t>& iv, bool padding) {
        if (iv.size() != 16) return false;
        ULONG cb = 0;
        if (BCryptDecrypt(hKey_, (PUCHAR)in, ULONG(n), nullptr, iv.data(), ULONG(iv.size()),
                          out, ULONG(cap), &cb,
                          padding ? BCRYPT_BLOCK_PADDING : 0) != 0)
            return false;
        outN = cb;
        return true;
    }

private:
    BCRYPT_ALG_HANDLE hAlg_ = nullptr;
    BCRYPT_KEY_HANDLE hKey_ = nullptr;
};

class CngHmac {
public:
    ~CngHmac() {
        if (hHash_) BCryptDestroyHash(hHash_);
        if (hAlg_) BCryptCloseAlgorithmProvider(hAlg_, 0);
    }
    bool start(const std::vector<uint8_t>& key) {
        if (BCryptOpenAlgorithmProvider(&hAlg_, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return false;
        ULONG objLen = 0, cb = 0;
        if (BCryptGetProperty(hAlg_, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, 4, &cb, 0) != 0)
            return false;
        obj_.resize(objLen);
        return BCryptCreateHash(hAlg_, &hHash_, obj_.data(), objLen, (PUCHAR)key.data(),
                                ULONG(key.size()), 0) == 0;
    }
    void update(const uint8_t* p, size_t n) {
        while (n > 0) {
            ULONG step = n > 0x10000000u ? 0x10000000u : ULONG(n);
            BCryptHashData(hHash_, (PUCHAR)p, step, 0);
            p += step;
            n -= step;
        }
    }
    bool finish(std::vector<uint8_t>& mac32) {
        mac32.assign(32, 0);
        return BCryptFinishHash(hHash_, mac32.data(), 32, 0) == 0;
    }

private:
    BCRYPT_ALG_HANDLE hAlg_ = nullptr;
    BCRYPT_HASH_HANDLE hHash_ = nullptr;
    std::vector<uint8_t> obj_;
};

// ------------------------------------------------------------ multi writer
class MultiWriter {
public:
    bool open(const std::wstring& firstPath, const std::wstring& baseForParts,
              uint64_t volumeSize) {
        firstPath_ = firstPath;
        base_ = baseForParts;
        volSize_ = volumeSize;
        return nextPart();
    }
    bool write(const void* p, size_t len) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        while (len > 0) {
            if (volSize_ && usedInVol_ > 0 && usedInVol_ + len > volSize_) {
                if (!nextPart()) return false;
            }
            uint64_t cap = len;
            if (volSize_) cap = std::min<uint64_t>(cap, volSize_ - usedInVol_);
            uint32_t step = uint32_t(std::min<uint64_t>(cap, 1u << 20));
            if (!file_.write(b, step)) return false;
            b += step;
            len -= step;
            usedInVol_ += step;
            total_ += step;
        }
        return true;
    }
    uint64_t bytes() const { return total_; }
    const std::vector<std::wstring>& parts() const { return parts_; }
    void close() { file_.close(); }

private:
    bool nextPart() {
        file_.close();
        std::wstring name;
        if (volSize_ > 0) {
            wchar_t buf[24];
            swprintf(buf, 24, L".part%05d.wrc", int(parts_.size() + 1));
            name = base_ + buf;
        } else {
            name = firstPath_;
        }
        parts_.push_back(name);
        if (!file_.openWriteTruncate(name)) return false;
        usedInVol_ = 0;
        return true;
    }
    File file_;
    std::wstring firstPath_, base_;
    uint64_t volSize_ = 0, usedInVol_ = 0, total_ = 0;
    std::vector<std::wstring> parts_;
};

// ------------------------------------------------------------ frame writer
class FrameWriter {
public:
    explicit FrameWriter(MultiWriter& out) : out_(out) {}
    void start(uint8_t type, uint8_t flags, uint64_t dataLen) {
        buf_.clear();
        buf_.insert(buf_.end(), kMagic, kMagic + 8);
        for (int i = 0; i < 4; ++i) buf_.push_back(0);  // crc placeholder
        hsizePos_ = buf_.size();
        put16(buf_, 0);  // headerSize placeholder
        buf_.push_back(type);
        buf_.push_back(flags);
        put16(buf_, 0);  // reserved
        put64(buf_, dataLen);
    }
    void payload(const void* p, size_t n) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        buf_.insert(buf_.end(), b, b + n);
    }
    bool commit() {
        uint16_t hsize = uint16_t(buf_.size() - kFrameFixed);
        buf_[hsizePos_] = uint8_t(hsize);
        buf_[hsizePos_ + 1] = uint8_t(hsize >> 8);
        uint32_t crc = crc32Update(crc32Init(), buf_.data() + 12, buf_.size() - 12);
        for (int i = 0; i < 4; ++i) buf_[8 + i] = uint8_t(crc >> (8 * i));
        return out_.write(buf_.data(), buf_.size());
    }

private:
    MultiWriter& out_;
    std::vector<uint8_t> buf_;
    size_t hsizePos_ = 0;
};

// ------------------------------------------------------------ part stream
class PartStream {
public:
    bool open(const std::wstring& path) {
        std::wstring ext = extensionOf(path);
        std::wstring base = stripExtension(path);
        bool looksVolume = false;
        if (base.size() > 10 && ext == L".wrc") {
            std::wstring tail = base.substr(base.size() - 10);  // "partNNNNN"
            if (tail.compare(0, 4, L"part") == 0) looksVolume = true;
        }
        std::vector<std::wstring> parts;
        if (looksVolume) {
            base = stripExtension(stripExtension(path));
            for (int n = 1;; ++n) {
                wchar_t buf[24];
                swprintf(buf, 24, L".part%05d.wrc", n);
                std::wstring name = base + buf;
                if (!fileExists(name)) break;
                parts.push_back(name);
            }
            if (parts.empty()) parts.push_back(path);
        } else if (fileExists(base + L".part00001.wrc")) {
            for (int n = 1;; ++n) {
                wchar_t buf[24];
                swprintf(buf, 24, L".part%05d.wrc", n);
                std::wstring name = base + buf;
                if (!fileExists(name)) break;
                parts.push_back(name);
            }
        } else {
            parts.push_back(path);
        }
        uint64_t acc = 0;
        for (auto& p : parts) {
            starts_.push_back(acc);
            uint64_t sz = fileSizeOf(p);
            sizes_.push_back(sz);
            acc += sz;
            parts_.push_back(p);
        }
        totalSize_ = acc;
        return !parts_.empty();
    }

    bool pread(uint8_t* buf, size_t len, uint64_t pos, size_t& got) {
        got = 0;
        while (len > 0) {
            size_t idx = locatePart(pos + got);
            if (idx >= parts_.size()) break;
            if (idx != openIdx_) {
                file_.close();
                if (!file_.openRead(parts_[idx])) return false;
                openIdx_ = idx;
            }
            uint64_t inPart = pos + got - starts_[idx];
            uint64_t avail = sizes_[idx] > inPart ? sizes_[idx] - inPart : 0;
            if (avail == 0) break;
            uint32_t want = uint32_t(std::min<uint64_t>(len - got, avail));
            uint32_t g = 0;
            if (!file_.pread(buf + got, want, inPart, g)) return false;
            if (g == 0) break;
            got += g;
        }
        return true;
    }

    uint64_t size() const { return totalSize_; }
    const std::vector<std::wstring>& parts() const { return parts_; }
    void close() {
        file_.close();
        openIdx_ = SIZE_MAX;
    }

private:
    size_t locatePart(uint64_t pos) {
        size_t lo = 0, hi = starts_.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (starts_[mid] <= pos)
                lo = mid + 1;
            else
                hi = mid;
        }
        return lo == 0 ? 0 : lo - 1;
    }
    std::vector<std::wstring> parts_;
    std::vector<uint64_t> starts_, sizes_;
    File file_;
    size_t openIdx_ = SIZE_MAX;
    uint64_t totalSize_ = 0;
};

// ------------------------------------------------------------ frame reader
struct Frame {
    uint8_t type = 0, flags = 0;
    uint64_t dataLen = 0;
    std::vector<uint8_t> payload;
    uint64_t startOffset = 0;
    uint64_t endOffset = 0;
};

class FrameReader {
public:
    FrameReader(PartStream& st, uint64_t start = 0) : st_(st), pos_(start) {}
    bool next(Frame& fr, std::string& err) {
        if (pos_ + kFrameFixed > st_.size()) return false;
        uint8_t h[26];
        size_t got = 0;
        if (!st_.pread(h, 26, pos_, got) || got != 26) {
            err = "read failed";
            return false;
        }
        if (memcmp(h, kMagic, 8) != 0) {
            err = "bad magic";
            return false;
        }
        uint32_t crcStored = rd32(h + 8);
        uint16_t hsize = rd16(h + 12);
        fr.type = h[14];
        fr.flags = h[15];
        fr.dataLen = rd64(h + 18);
        fr.startOffset = pos_;
        fr.payload.resize(hsize);
        if (hsize) {
            if (!st_.pread(fr.payload.data(), hsize, pos_ + kFrameFixed, got) ||
                got != hsize) {
                err = "read failed";
                return false;
            }
        }
        std::vector<uint8_t> crcBuf(h + 12, h + kFrameFixed);
        crcBuf.insert(crcBuf.end(), fr.payload.begin(), fr.payload.end());
        uint32_t crcCalc = crc32Update(crc32Init(), crcBuf.data(), crcBuf.size());
        if (crcCalc != crcStored) {
            err = "header CRC mismatch";
            return false;
        }
        fr.endOffset = pos_ + kFrameFixed + hsize + fr.dataLen;
        pos_ = fr.endOffset;
        return true;
    }
    uint64_t pos() const { return pos_; }

private:
    PartStream& st_;
    uint64_t pos_ = 0;
};

// ------------------------------------------------- encrypted region reading
// data region layout: [16B IV][cipher..][16B MAC(truncated)]
bool readRegionEncrypted(PartStream& st, uint64_t dataOff, uint64_t dataLen,
                         const std::vector<uint8_t>& key,
                         const std::function<void(const uint8_t*, size_t)>& sink,
                         std::string& err) {
    if (dataLen < 32 + 16) {
        err = "encrypted block too small";
        return false;
    }
    uint64_t cipherTotal = dataLen - 16;  // IV + cipher, minus mac
    uint8_t head[16];
    size_t got = 0;
    if (!st.pread(head, 16, dataOff, got) || got != 16) {
        err = "read failed";
        return false;
    }
    CngAes aes;
    if (!aes.setKey(key)) {
        err = "crypto init failed";
        return false;
    }
    CngHmac mac;
    if (!mac.start(key)) {
        err = "crypto init failed";
        return false;
    }
    std::vector<uint8_t> iv(head, head + 16);
    std::vector<uint8_t> inBuf(1u << 20), outBuf((1u << 20) + 16);
    uint64_t consumed = 16;
    // stream full blocks, always keeping the FINAL cipher block in reserve so
    // the PKCS#7 padding is processed with the padding flag
    while (consumed + 16 < cipherTotal) {
        uint64_t left = cipherTotal - consumed - 16;
        uint64_t want = std::min<uint64_t>(left, inBuf.size());
        want -= want % 16;
        if (want == 0) break;
        if (!st.pread(inBuf.data(), size_t(want), dataOff + consumed, got) ||
            got != want) {
            err = "read failed";
            return false;
        }
        mac.update(inBuf.data(), size_t(want));
        size_t outN = 0;
        if (!aes.decrypt(inBuf.data(), size_t(want), outBuf.data(), outBuf.size(), outN,
                         iv, false)) {
            err = "decrypt failed";
            return false;
        }
        sink(outBuf.data(), outN);
        consumed += want;
    }
    uint64_t left = cipherTotal - consumed;  // >= 16: final block(s) + padding
    std::vector<uint8_t> tail(size_t(left) + 16, 0);
    if (left && (!st.pread(tail.data(), uint32_t(left), dataOff + consumed, got) ||
                 got != left)) {
        err = "read failed";
        return false;
    }
    uint8_t macBuf[16];
    if (!st.pread(macBuf, 16, dataOff + dataLen - 16, got) || got != 16) {
        err = "read failed";
        return false;
    }
    mac.update(tail.data(), size_t(left));
    std::vector<uint8_t> macCalc;
    if (!mac.finish(macCalc) || memcmp(macCalc.data(), macBuf, 16) != 0) {
        err = "authentication failed (wrong password or corrupted data)";
        return false;
    }
    if (left > 0) {
        size_t outN = 0;
        if (!aes.decrypt(tail.data(), size_t(left), outBuf.data(), outBuf.size(), outN,
                         iv, true)) {
            err = "decrypt failed";
            return false;
        }
        if (outN) sink(outBuf.data(), outN);
    }
    return true;
}

// Streaming encryptor used while WRITING a data region.
class DataEncryptor {
public:
    DataEncryptor(const std::vector<uint8_t>& key, MultiWriter& out) : out_(out) {
        if (!aes_.setKey(key)) throw WrcError("crypto init failed");
        if (!mac_.start(key)) throw WrcError("crypto init failed");
        iv_ = randomBytes(16);
        out_.write(iv_.data(), 16);
        written_ = 16;
    }
    void feed(const uint8_t* p, size_t n, bool final) {
        if (n) pend_.insert(pend_.end(), p, p + n);
        if (!final) {
            size_t blocks = pend_.size() / 16 * 16;
            if (blocks) emit(pend_.data(), blocks, false);
            pend_.erase(pend_.begin(), pend_.begin() + ptrdiff_t(blocks));
        } else {
            emit(pend_.data(), pend_.size(), true);
            pend_.clear();
            std::vector<uint8_t> mac32;
            mac_.finish(mac32);
            out_.write(mac32.data(), 16);
            written_ += 16;
        }
    }
    uint64_t bytes() const { return written_; }

private:
    void emit(const uint8_t* p, size_t n, bool padding) {
        if (n == 0 && !padding) return;
        std::vector<uint8_t> out(n + 16);
        size_t outN = 0;
        if (!aes_.encrypt(p, n, out.data(), out.size(), outN, iv_, padding))
            throw WrcError("encrypt failed");
        out_.write(out.data(), outN);
        mac_.update(out.data(), outN);
        written_ += outN;
    }
    std::vector<uint8_t> iv_, pend_;
    MultiWriter& out_;
    CngAes aes_;
    CngHmac mac_;
    uint64_t written_ = 0;
};

// -------------------------------------------------------------- compression
struct PackedItem {
    std::wstring tempPath;
    uint64_t packedSize = 0;
    uint32_t crc = 0;
    uint8_t method = 0;
};

PackedItem deflateToTemp(const ScanItem& it, int level, const std::wstring& tempDir,
                         int idx, ProgressTracker& pt, ControlFn cf) {
    PackedItem res;
    res.method = 1;
    res.tempPath = tempDir + L"\\~wsar" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                   std::to_wstring(idx) + L".tmp";
    File src;
    if (!src.openRead(it.fullPath)) throw WrcError("cannot open: " + toUtf8(it.fullPath));
    File dst;
    if (!dst.openWriteTruncate(res.tempPath)) throw WrcError("temp file failed");
    z_stream zs{};
    if (deflateInit2(&zs, level, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK)
        throw WrcError("zlib init failed");
    std::vector<uint8_t> in(1u << 20), out(1u << 20);
    uint32_t crc = crc32Init();
    uint64_t done = 0;
    try {
        while (done < it.size) {
            if (cf && !cf()) throw CancelledError();
            uint64_t want = std::min<uint64_t>(in.size(), it.size - done);
            uint32_t got = 0;
            if (!src.read(in.data(), uint32_t(want), got) || got == 0) break;
            crc = crc32Update(crc, in.data(), got);
            zs.next_in = in.data();
            zs.avail_in = got;
            do {
                zs.next_out = out.data();
                zs.avail_out = uint32_t(out.size());
                deflate(&zs, Z_NO_FLUSH);
                size_t have = out.size() - zs.avail_out;
                if (have && !dst.write(out.data(), uint32_t(have)))
                    throw WrcError("write failed");
                res.packedSize += have;
            } while (zs.avail_out == 0);
            done += got;
            pt.addDone(got);
            pt.setFile(fileNameOf(it.fullPath));
            pt.check(cf);
        }
        zs.next_in = nullptr;
        zs.avail_in = 0;
        for (;;) {
            zs.next_out = out.data();
            zs.avail_out = uint32_t(out.size());
            int rc = deflate(&zs, Z_FINISH);
            size_t have = out.size() - zs.avail_out;
            if (have && !dst.write(out.data(), uint32_t(have))) throw WrcError("write failed");
            res.packedSize += have;
            if (rc == Z_STREAM_END) break;
            if (rc != Z_OK && rc != Z_BUF_ERROR) throw WrcError("deflate failed");
        }
    } catch (...) {
        deflateEnd(&zs);
        throw;
    }
    deflateEnd(&zs);
    res.crc = crc;
    if (res.packedSize >= it.size) {
        res.method = 0;
        res.packedSize = it.size;
    }
    return res;
}

PackedItem lzssToTemp(const ScanItem& it, const LzssParams& lp,
                      const std::wstring& tempDir, int idx, ProgressTracker& pt,
                      ControlFn cf, std::vector<uint32_t>& table) {
    PackedItem res;
    res.method = 2;
    res.tempPath = tempDir + L"\\~wsar" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                   std::to_wstring(idx) + L".tmp";
    File f;
    if (!f.openRead(it.fullPath)) throw WrcError("cannot open: " + toUtf8(it.fullPath));
    HANDLE map = CreateFileMappingW(f.handle(), nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map) throw WrcError("mapping failed");
    const uint8_t* view = static_cast<const uint8_t*>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
    if (!view) {
        CloseHandle(map);
        throw WrcError("mapping failed");
    }
    std::vector<uint8_t> packed;
    try {
        pt.setFile(fileNameOf(it.fullPath));
        lzssEncode(view, it.size, lp, packed, &table);
        res.crc = crc32Update(crc32Init(), view, it.size);
        pt.addDone(it.size);
        pt.check(cf);
    } catch (...) {
        UnmapViewOfFile(view);
        CloseHandle(map);
        throw;
    }
    UnmapViewOfFile(view);
    CloseHandle(map);
    File dst;
    if (!dst.openWriteTruncate(res.tempPath)) throw WrcError("temp file failed");
    if (!dst.write(packed.data(), packed.size() ? uint32_t(packed.size()) : 0u))
        throw WrcError("write failed");
    res.packedSize = packed.size();
    return res;
}

// ------------------------------------------------------------------ sinks
class CrcFileSink : public LzssOutSink {
public:
    CrcFileSink(File& f) : f_(f) {}
    void write(const void* buf, size_t len) override {
        if (len) {
            f_.write(buf, uint32_t(len));
            crc_ = crc32Update(crc_, buf, len);
            written_ += len;
        }
    }
    void readBack(uint64_t offset, void* buf, size_t len) override {
        if (!len) return;
        uint32_t got = 0;
        if (!f_.pread(buf, uint32_t(len), offset, got)) got = 0;
        if (got < len) memset(static_cast<uint8_t*>(buf) + got, 0, len - got);
    }
    uint32_t crc() const { return crc_; }
    uint64_t written() const { return written_; }

private:
    File& f_;
    uint32_t crc_ = crc32Init();
    uint64_t written_ = 0;
};

// sanitize archive member name (zip-slip protection)
bool safeRelName(const std::wstring& name, std::wstring& clean) {
    if (name.empty()) return false;
    std::wstring n = name;
    std::replace(n.begin(), n.end(), L'\\', L'/');
    while (!n.empty() && n.front() == L'/') n.erase(n.begin());
    if (n.find(L':') != std::wstring::npos) return false;
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= n.size()) {
        size_t p = n.find(L'/', start);
        std::wstring seg =
            n.substr(start, p == std::wstring::npos ? std::wstring::npos : p - start);
        if (seg.empty() || seg == L".") {
        } else if (seg == L"..") {
            return false;
        } else {
            parts.push_back(seg);
        }
        if (p == std::wstring::npos) break;
        start = p + 1;
    }
    if (parts.empty()) return false;
    clean = parts[0];
    for (size_t i = 1; i < parts.size(); ++i) clean += L"/" + parts[i];
    return true;
}

FILETIME unixToFileTime(uint64_t unixSec) {
    ULARGE_INTEGER li;
    li.QuadPart = (unixSec + 11644473600ull) * 10000000ull;
    FILETIME ft;
    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = li.HighPart;
    return ft;
}

void applyMeta(const std::wstring& path, uint64_t mtime, uint32_t attrs) {
    HANDLE h = CreateFileW(toExtendedPath(path).c_str(), FILE_WRITE_ATTRIBUTES, 0, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        FILETIME ft = unixToFileTime(mtime);
        SetFileTime(h, nullptr, nullptr, &ft);
        CloseHandle(h);
    }
    if (attrs & 0xFF) SetFileAttributesW(toExtendedPath(path).c_str(), attrs & 0xFF);
}

// ------------------------------------------------------- entry decompression
// Decompress one entry into `outFile`; verifies nothing (CRC by caller).
bool extractEntry(PartStream& st, const FileEntry& e, uint64_t dataOff,
                  const std::vector<uint8_t>& dataKey, File& outFile, uint32_t& crcOut,
                  ControlFn cf, std::string& err) {
    CrcFileSink sink(outFile);
    if (e.method == 2) {
        // LZSS needs read-back into prior output — file-backed window
        if (e.encrypted) {
            std::vector<uint8_t> plain;
            if (!readRegionEncrypted(st, dataOff, e.packedSize, dataKey,
                                     [&](const uint8_t* p, size_t n) {
                                         plain.insert(plain.end(), p, p + n);
                                     },
                                     err))
                return false;
            if (!lzssDecode(plain.data(), plain.size(), sink, err)) return false;
            crcOut = sink.crc();
            return true;
        }
        std::vector<uint8_t> packed(size_t(e.packedSize));
        size_t got = 0;
        if (!st.pread(packed.data(), size_t(e.packedSize), dataOff, got) ||
            got != e.packedSize) {
            err = "read failed";
            return false;
        }
        if (!lzssDecode(packed.data(), packed.size(), sink, err)) return false;
        crcOut = sink.crc();
        return true;
    }
    if (e.encrypted) {
        if (e.method == 0) {
            if (!readRegionEncrypted(st, dataOff, e.packedSize, dataKey,
                                     [&](const uint8_t* p, size_t n) { sink.write(p, n); },
                                     err))
                return false;
            crcOut = sink.crc();
            return true;
        }
        if (e.method == 1) {
            std::vector<uint8_t> plain;
            if (!readRegionEncrypted(st, dataOff, e.packedSize, dataKey,
                                     [&](const uint8_t* p, size_t n) {
                                         plain.insert(plain.end(), p, p + n);
                                     },
                                     err))
                return false;
            z_stream zs{};
            if (inflateInit2(&zs, -15) != Z_OK) {
                err = "zlib init failed";
                return false;
            }
            std::vector<uint8_t> out(1u << 20);
            uint32_t crc = crc32Init();
            zs.next_in = plain.data();
            zs.avail_in = uInt(plain.size());
            int rc = Z_OK;
            bool bad = false;
            do {
                zs.next_out = out.data();
                zs.avail_out = uint32_t(out.size());
                rc = inflate(&zs, Z_NO_FLUSH);
                if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
                    bad = true;
                    break;
                }
                size_t have = out.size() - zs.avail_out;
                if (have) {
                    crc = crc32Update(crc, out.data(), have);
                    sink.write(out.data(), have);
                }
            } while (rc != Z_STREAM_END && zs.avail_in > 0);
            inflateEnd(&zs);
            if (bad) {
                err = "inflate failed";
                return false;
            }
            crcOut = crc;
            return true;
        }
        err = "unknown method";
        return false;
    }
    // unencrypted store / deflate streaming
    if (e.method == 0) {
        std::vector<uint8_t> buf(1u << 20);
        uint64_t off = 0;
        while (off < e.packedSize) {
            if (cf && !cf()) throw CancelledError();
            uint64_t want = std::min<uint64_t>(buf.size(), e.packedSize - off);
            size_t got = 0;
            if (!st.pread(buf.data(), size_t(want), dataOff + off, got) || got == 0) {
                err = "read failed";
                return false;
            }
            sink.write(buf.data(), got);
            off += got;
        }
        crcOut = sink.crc();
        return true;
    }
    if (e.method == 1) {
        z_stream zs{};
        if (inflateInit2(&zs, -15) != Z_OK) {
            err = "zlib init failed";
            return false;
        }
        std::vector<uint8_t> in(1u << 20), out(1u << 20);
        uint64_t off = 0;
        bool endReached = false;
        while (off < e.packedSize && !endReached) {
            if (cf && !cf()) throw CancelledError();
            uint64_t want = std::min<uint64_t>(in.size(), e.packedSize - off);
            size_t got = 0;
            if (!st.pread(in.data(), size_t(want), dataOff + off, got) || got == 0) {
                inflateEnd(&zs);
                err = "read failed";
                return false;
            }
            zs.next_in = in.data();
            zs.avail_in = uInt(got);
            do {
                zs.next_out = out.data();
                zs.avail_out = uint32_t(out.size());
                int rc = inflate(&zs, Z_NO_FLUSH);
                if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) {
                    inflateEnd(&zs);
                    err = "inflate failed";
                    return false;
                }
                if (rc == Z_STREAM_END) endReached = true;
                size_t have = out.size() - zs.avail_out;
                if (have) sink.write(out.data(), have);
            } while (zs.avail_out == 0);
            off += got;
        }
        inflateEnd(&zs);
        crcOut = sink.crc();
        return true;
    }
    err = "unknown method";
    return false;
}

}  // namespace

// -------------------------------------------------------------------- build
bool build(const std::vector<ScanItem>& items, const ArchiveOptions& opt,
           const ProgressFn& pf, ControlFn cf, uint64_t& totalIn, uint64_t& totalOut) {
    totalIn = 0;
    totalOut = 0;
    uint64_t total = scanTotalSize(items);
    ProgressTracker pt(Progress::Phase::Compress, total, pf);
    pt.check(cf);

    bool encrypt = !opt.password.empty();
    bool encNames = encrypt && opt.encryptNames;
    std::vector<uint8_t> salt, dataKey, nameKey;
    if (encrypt) {
        salt = opt.forcedSalt.size() == 16 ? opt.forcedSalt : randomBytes(16);
        dataKey = pbkdf2Sha256(toUtf8(opt.password), salt, 200000, 32, 0x01);
        nameKey = pbkdf2Sha256(toUtf8(opt.password), salt, 200000, 32, 0x02);
        if (dataKey.empty() || nameKey.empty()) throw WrcError("crypto init failed");
    }

    // pass 1 — compress (dictionary RAM gate per spec §3.a); the chain table
    // is allocated through DictionaryManager and borrowed by the encoder
    std::wstring tempDir = directoryOf(opt.archivePath);
    std::vector<PackedItem> packed(items.size());
    bool useLzss = int(opt.method) >= int(Method::Normal);
    uint64_t effWindow = DictionaryManager::effectiveEncoderWindow(opt.dictSize);
    try {
        if (useLzss) {
            DictionaryManager dm(effWindow);
            if (!dm.allocate()) throw WrcError("out of memory for dictionary allocation");
            std::vector<uint32_t>& dictTable = dm.table();
            LzssParams lp = lzssParamsForMethod(uint8_t(opt.method), opt.longRangeSearch,
                                                opt.exhaustiveSearch);
            lp.window = effWindow;
            for (size_t i = 0; i < items.size(); ++i) {
                if (items[i].isDir) continue;
                packed[i] = lzssToTemp(items[i], lp, tempDir, int(i), pt, cf, dictTable);
            }
        } else {
            unsigned hw = opt.multiThread
                              ? (opt.threads > 0 ? unsigned(opt.threads)
                                                 : std::thread::hardware_concurrency())
                              : 1;
            if (!hw) hw = 4;
            std::vector<std::future<void>> futs;
            {
                ThreadPool pool(hw);
                for (size_t i = 0; i < items.size(); ++i) {
                    if (items[i].isDir) continue;
                    int level = deflateLevel(opt.method);
                    futs.push_back(pool.submit([&items, &packed, &pt, cf, tempDir, i, level] {
                        packed[i] = deflateToTemp(items[i], level, tempDir, int(i), pt, cf);
                    }));
                }
                pool.waitIdle();
            }
            for (auto& f : futs) f.get();
        }
    } catch (...) {
        for (auto& p : packed)
            if (!p.tempPath.empty()) deleteFileForever(p.tempPath);
        throw;
    }

    // pass 2 — write container
    std::wstring base = stripExtension(opt.archivePath);
    MultiWriter out;
    if (!out.open(opt.archivePath, base, opt.volumeSize))
        throw WrcError("cannot create archive: " + toUtf8(opt.archivePath));
    FrameWriter fw(out);
    try {
        // MAIN
        uint32_t aflags = 0;
        if (opt.volumeSize) aflags |= AF_VOLUME;
        if (encNames) aflags |= AF_ENC_NAMES;
        if (opt.solid) aflags |= AF_SOLID;
        std::vector<uint8_t> mainPayload;
        put64(mainPayload, opt.dictSize);
        put32(mainPayload, aflags);
        put64(mainPayload, opt.volumeSize);  // v1.1: preserved for rebuild
        if (encrypt) {  // salt always stored when data/name encryption is used
            put32(mainPayload, uint32_t(salt.size()));
            mainPayload.insert(mainPayload.end(), salt.begin(), salt.end());
        }
        fw.start(H_MAIN, 0, 0);
        fw.payload(mainPayload.data(), mainPayload.size());
        if (!fw.commit()) throw WrcError("write failed");

        // FILE frames + data regions
        for (size_t i = 0; i < items.size(); ++i) {
            if (cf && !cf()) throw CancelledError();
            const ScanItem& it = items[i];
            std::vector<uint8_t> pl;
            put64(pl, it.isDir ? 0 : it.size);
            uint64_t dataLen = 0;
            uint8_t method = 0, encFlag = 0;
            if (!it.isDir) {
                const PackedItem& r = packed[i];
                method = r.method;
                if (encrypt) {
                    // IV + PKCS7-cipher + MAC (PKCS7 always adds >= 1 block)
                    dataLen = 16 + (r.packedSize / 16 + 1) * 16 + 16;
                    encFlag = 1;
                } else {
                    dataLen = r.packedSize;
                }
                put64(pl, dataLen);
                put32(pl, r.crc);
            } else {
                put64(pl, 0);
                put32(pl, 0);
            }
            put32(pl, it.attrs & 0xFF);
            put64(pl, it.mtime);
            pl.push_back(it.isDir ? uint8_t(0) : method);
            pl.push_back(encFlag);
            std::string n8 = toUtf8(it.relPath + (it.isDir ? L"/" : L""));
            put16(pl, uint16_t(n8.size()));
            pl.insert(pl.end(), n8.begin(), n8.end());

            if (encNames) {
                // encrypt whole payload: [IV][AES-CBC(payload)][MAC16]
                std::vector<uint8_t> iv = randomBytes(16);
                std::vector<uint8_t> cipher;
                if (!aes256CbcEncrypt(nameKey, iv, pl, cipher))
                    throw WrcError("encrypt failed");
                std::vector<uint8_t> macIn = iv;
                macIn.insert(macIn.end(), cipher.begin(), cipher.end());
                std::vector<uint8_t> mac32;
                hmacSha256(nameKey, macIn.data(), macIn.size(), mac32);
                std::vector<uint8_t> encPayload = iv;
                encPayload.insert(encPayload.end(), cipher.begin(), cipher.end());
                encPayload.insert(encPayload.end(), mac32.begin(), mac32.begin() + 16);
                fw.start(H_FILE, 0, dataLen);
                fw.payload(encPayload.data(), encPayload.size());
            } else {
                fw.start(H_FILE, 0, dataLen);
                fw.payload(pl.data(), pl.size());
            }
            if (!fw.commit()) throw WrcError("write failed");

            // data region
            if (!it.isDir) {
                const PackedItem& r = packed[i];
                // store-fallback: the temp holds deflate bytes - read the ORIGINAL
                const std::wstring& srcPath = r.method == 0 ? it.fullPath : r.tempPath;
                File src;
                if (!src.openRead(srcPath)) throw WrcError("temp read failed");
                std::vector<uint8_t> buf(1u << 20);
                if (encrypt) {
                    DataEncryptor de(dataKey, out);
                    uint64_t done = 0;
                    while (done < r.packedSize) {
                        uint64_t want = std::min<uint64_t>(buf.size(), r.packedSize - done);
                        uint32_t got = 0;
                        if (!src.read(buf.data(), uint32_t(want), got) || got == 0)
                            throw WrcError("temp read failed");
                        de.feed(buf.data(), got, false);
                        done += got;
                    }
                    de.feed(nullptr, 0, true);  // flush remainder + padding + MAC
                } else {
                    uint64_t done = 0;
                    while (done < r.packedSize) {
                        uint64_t want = std::min<uint64_t>(buf.size(), r.packedSize - done);
                        uint32_t got = 0;
                        if (!src.read(buf.data(), uint32_t(want), got) || got == 0)
                            throw WrcError("temp read failed");
                        if (!out.write(buf.data(), got)) throw WrcError("write failed");
                        done += got;
                    }
                }
            }
            pt.setFile(fileNameOf(it.fullPath));
            pt.check(cf);
        }

        // END
        std::vector<uint8_t> endPl;
        put32(endPl, uint32_t(out.parts().size()));
        put32(endPl, 0);
        fw.start(H_END, 0, 0);
        fw.payload(endPl.data(), endPl.size());
        if (!fw.commit()) throw WrcError("write failed");
    } catch (...) {
        for (auto& p : packed)
            if (!p.tempPath.empty()) deleteFileForever(p.tempPath);
        out.close();
        throw;
    }

    for (auto& p : packed)
        if (!p.tempPath.empty()) deleteFileForever(p.tempPath);

    totalIn = total;
    for (auto& pp : out.parts()) totalOut += fileSizeOf(pp);
    return true;
}

// --------------------------------------------------------------------- list
bool list(const std::wstring& path, const std::wstring& password, WsarInfo& out,
          std::string& err) {
    out = WsarInfo{};
    out.format = Format::Wsar;
    out.path = path;
    PartStream st;
    if (!st.open(path)) {
        err = "cannot open archive";
        return false;
    }
    FrameReader rd(st);
    Frame fr;
    if (!rd.next(fr, err) || fr.type != H_MAIN) {
        err = err.empty() ? "not a WSAR archive" : err;
        return false;
    }
    const std::vector<uint8_t>& mp = fr.payload;
    if (mp.size() < 12) {
        err = "corrupt main header";
        return false;
    }
    out.dictSize = rd64(mp.data());
    out.archiveFlags = rd32(mp.data() + 8);
    out.multiVolume = (out.archiveFlags & AF_VOLUME) != 0;
    out.encryptedNames = (out.archiveFlags & AF_ENC_NAMES) != 0;
    size_t mpOff = 12;
    // v1.1 archives carry the volume size so rebuilds preserve the layout;
    // v1.0 payloads continue with the salt length field instead
    if (mp.size() >= mpOff + 8 && rd64(mp.data() + mpOff) <= (64ull << 30)) {
        out.volumeSize = rd64(mp.data() + mpOff);
        mpOff += 8;
    }
    if (mp.size() >= mpOff + 4) {
        // salt is stored whenever encryption is used (data or names)
        uint32_t saltLen = rd32(mp.data() + mpOff);
        if (saltLen && saltLen <= 64 && mp.size() >= mpOff + 4 + saltLen) {
            out.salt.assign(mp.begin() + long(mpOff + 4),
                            mp.begin() + long(mpOff + 4 + saltLen));
            mpOff += 4 + saltLen;
        }
    }
    std::vector<uint8_t> dataKey, nameKey;
    if (out.encryptedNames) {
        if (password.empty()) {
            out.hasPassword = true;
            err = "password required";
            return false;
        }
        std::vector<uint8_t> salt =
            out.salt.empty() ? std::vector<uint8_t>(16, 0) : out.salt;
        dataKey = pbkdf2Sha256(toUtf8(password), salt, 200000, 32, 0x01);
        nameKey = pbkdf2Sha256(toUtf8(password), salt, 200000, 32, 0x02);
        if (dataKey.empty() || nameKey.empty()) {
            err = "crypto init failed";
            return false;
        }
    }
    while (rd.next(fr, err)) {
        if (fr.type == H_END) break;
        if (fr.type != H_FILE) continue;
        std::vector<uint8_t> pl = fr.payload;
        if (out.encryptedNames) {
            if (pl.size() < 48) {
                err = "corrupt header";
                return false;
            }
            std::vector<uint8_t> iv(pl.begin(), pl.begin() + 16);
            std::vector<uint8_t> cipher(pl.begin() + 16, pl.end() - 16);
            std::vector<uint8_t> macTag(pl.end() - 16, pl.end());
            std::vector<uint8_t> macIn = iv;
            macIn.insert(macIn.end(), cipher.begin(), cipher.end());
            std::vector<uint8_t> mac32;
            hmacSha256(nameKey, macIn.data(), macIn.size(), mac32);
            if (memcmp(mac32.data(), macTag.data(), 16) != 0) {
                err = "authentication failed (wrong password or corrupted data)";
                return false;
            }
            if (!aes256CbcDecrypt(nameKey, iv, cipher, pl)) {
                err = "decrypt failed";
                return false;
            }
        }
        if (pl.size() < size_t(28)) {
            err = "corrupt file header";
            return false;
        }
        FileEntry e;
        e.size = rd64(pl.data());
        e.packedSize = fr.dataLen;
        e.crc32 = rd32(pl.data() + 16);
        e.attrs = rd32(pl.data() + 20);
        e.mtime = rd64(pl.data() + 24);
        e.method = pl[32];
        uint8_t encFlag = pl[33];
        uint16_t nameLen = rd16(pl.data() + 34);
        if (pl.size() < size_t(36) + nameLen) {
            err = "corrupt file header";
            return false;
        }
        std::string n8(reinterpret_cast<const char*>(pl.data() + 36), nameLen);
        std::wstring name = fromUtf8(n8);
        bool isDir = !name.empty() && name.back() == L'/';
        if (isDir) name.pop_back();
        if (name.empty()) continue;
        std::wstring clean;
        if (!safeRelName(isDir ? name + L"/x" : name, clean)) continue;  // hostile name
        e.name = isDir ? clean.substr(0, clean.size() - 2) : clean;
        e.isDir = isDir;
        e.encrypted = encFlag != 0;
        e.headerStart = fr.startOffset;
        e.dataEnd = fr.endOffset;
        out.entries.push_back(e);
        if (!e.isDir) {
            out.totalOriginal += e.size;
            out.totalPacked += e.packedSize;
        }
    }
    err.clear();
    return true;
}

// ----------------------------------------------------------------- extract
bool extract(const std::wstring& path, const std::wstring& destDir,
             const std::wstring& password, const std::vector<std::wstring>& only,
             const ProgressFn& pf, ControlFn cf, std::vector<std::wstring>& extracted,
             std::string& err) {
    WsarInfo info;
    if (!list(path, password, info, err)) return false;
    std::vector<uint8_t> dataKey;
    if (password.size()) {
        std::vector<uint8_t> salt =
            info.salt.empty() ? std::vector<uint8_t>(16, 0) : info.salt;
        dataKey = pbkdf2Sha256(toUtf8(password), salt, 200000, 32, 0x01);
    }
    bool anyEnc = false;
    for (auto& e : info.entries)
        if (e.encrypted && !e.isDir) anyEnc = true;
    if (anyEnc && dataKey.empty()) {
        err = "password required";
        return false;
    }
    PartStream st;
    if (!st.open(path)) {
        err = "cannot open archive";
        return false;
    }
    uint64_t total = 0;
    for (auto& e : info.entries)
        if (!e.isDir &&
            (only.empty() || std::find(only.begin(), only.end(), e.name) != only.end()))
            total += e.size;
    ProgressTracker pt(Progress::Phase::Extract, total, pf);
    pt.check(cf);

    for (auto& e : info.entries) {
        if (!only.empty() && std::find(only.begin(), only.end(), e.name) == only.end())
            continue;
        std::wstring clean;
        if (!safeRelName(e.isDir ? e.name + L"/x" : e.name, clean)) continue;
        std::wstring rel = e.isDir ? clean.substr(0, clean.size() - 2) : clean;
        // Windows APIs (especially \\?\ paths) do not normalize '/' — use '\'
        std::replace(rel.begin(), rel.end(), L'/', L'\\');
        std::wstring dest = destDir + L"\\" + rel;
        if (e.isDir) {
            if (!makeDirs(dest)) {
                err = "cannot create folder: " + toUtf8(dest);
                return false;
            }
            continue;
        }
        if (!makeDirs(directoryOf(dest))) {
            err = "cannot create folder: " + toUtf8(directoryOf(dest));
            return false;
        }
        pt.setFile(e.name);
        File outFile;
        if (!outFile.openWriteTruncate(dest)) {
            err = "cannot create: " + toUtf8(dest);
            return false;
        }
        uint32_t crc = 0;
        uint64_t payloadLen = e.dataEnd - e.headerStart - kFrameFixed - e.packedSize;
        uint64_t dataOff = e.headerStart + kFrameFixed + payloadLen;
        if (!extractEntry(st, e, dataOff, dataKey, outFile, crc, cf, err)) return false;
        outFile.close();
        if (crc != e.crc32) {
            err = "CRC mismatch: " + toUtf8(e.name);
            return false;
        }
        applyMeta(dest, e.mtime, e.attrs);
        extracted.push_back(dest);
        pt.addDone(e.size);
        pt.check(cf);
    }
    return true;
}

// -------------------------------------------------------------------- test
bool test(const std::wstring& path, const std::wstring& password, const ProgressFn& pf,
          ControlFn cf, int& badEntries, std::string& err) {
    badEntries = 0;
    WsarInfo info;
    if (!list(path, password, info, err)) return false;
    std::vector<uint8_t> dataKey;
    if (password.size()) {
        std::vector<uint8_t> salt =
            info.salt.empty() ? std::vector<uint8_t>(16, 0) : info.salt;
        dataKey = pbkdf2Sha256(toUtf8(password), salt, 200000, 32, 0x01);
    }
    bool anyEnc = false;
    for (auto& e : info.entries)
        if (e.encrypted && !e.isDir) anyEnc = true;
    if (anyEnc && dataKey.empty()) {
        err = "password required";
        return false;
    }
    PartStream st;
    if (!st.open(path)) {
        err = "cannot open archive";
        return false;
    }
    uint64_t total = 0;
    for (auto& e : info.entries)
        if (!e.isDir) total += e.size;
    ProgressTracker pt(Progress::Phase::Test, total, pf);
    pt.check(cf);
    std::wstring tempDir = directoryOf(path);
    for (auto& e : info.entries) {
        if (e.isDir) continue;
        pt.setFile(e.name);
        std::wstring tmp =
            tempDir + L"\\~wsartest" + std::to_wstring(GetCurrentProcessId()) + L".tmp";
        File outFile;
        if (!outFile.openWriteTruncate(tmp)) {
            err = "cannot create temp file";
            return false;
        }
        uint32_t crc = 0;
        uint64_t payloadLen = e.dataEnd - e.headerStart - kFrameFixed - e.packedSize;
        uint64_t dataOff = e.headerStart + kFrameFixed + payloadLen;
        bool ok = extractEntry(st, e, dataOff, dataKey, outFile, crc, cf, err);
        outFile.close();
        deleteFileForever(tmp);
        if (!ok) return false;
        if (crc != e.crc32) ++badEntries;
        pt.addDone(e.size);
        pt.check(cf);
    }
    return true;
}

// ----------------------------------------------------------------- rebuild
bool rebuild(const std::wstring& path, const std::wstring& password,
             const std::vector<std::wstring>& keepNames,
             const std::vector<ScanItem>& newItems, const ArchiveOptions& opt,
             const ProgressFn& pf, ControlFn cf) {
    WsarInfo info;
    std::string lerr;
    if (!list(path, password, info, lerr)) throw WrcError(lerr);

    // pass 1 for the new items (into a temp dir next to the archive)
    ArchiveOptions o2 = opt;
    o2.dictSize = info.dictSize ? info.dictSize : opt.dictSize;
    o2.volumeSize = 0;  // temp build is always single-file
    std::vector<ScanItem> newScanned = newItems;
    uint64_t keptBytes = 0;
    std::vector<uint32_t> keepIdx;
    for (size_t i = 0; i < info.entries.size(); ++i) {
        const auto& e = info.entries[i];
        if (std::find(keepNames.begin(), keepNames.end(), e.name) != keepNames.end()) {
            keepIdx.push_back(uint32_t(i));
            if (!e.isDir) keptBytes += e.size;
        }
    }
    uint64_t newBytes = scanTotalSize(newScanned);
    ProgressTracker pt(Progress::Phase::Compress, keptBytes + newBytes, pf);
    pt.check(cf);

    std::wstring tempArchive = path + L".~newitems";
    if (!newScanned.empty()) {
        // Encryption for new entries must reuse the existing salt so old and
        // new ciphertexts stay consistent under one MAIN header.
        o2.archivePath = tempArchive;
        o2.inputs.clear();
        o2.password = password;
        o2.encryptNames = info.encryptedNames && !password.empty();
        o2.forcedSalt = info.salt;
        uint64_t ti = 0, to = 0;
        build(newScanned, o2, pf, cf, ti, to);
    }
    WsarInfo newInfo;
    std::vector<FileEntry> newEntries;
    if (!newScanned.empty()) {
        std::string e2;
        if (!list(tempArchive, password, newInfo, e2)) {
            deleteFileForever(tempArchive);
            throw WrcError(e2);
        }
        newEntries = newInfo.entries;
    }

    // pass 2 — assemble new container next to the original, preserving the
    // original volume layout (delete/append must not collapse multi-part sets)
    const uint64_t volSize = opt.volumeSize ? opt.volumeSize : info.volumeSize;
    std::wstring base = stripExtension(path);
    std::wstring newFirst = base + L".~new";
    MultiWriter out;
    if (!out.open(newFirst, newFirst, volSize)) throw WrcError("cannot create temp");
    FrameWriter fw(out);
    PartStream stOld;
    if (!stOld.open(path)) {
        out.close();
        deleteFileForever(tempArchive);
        throw WrcError("cannot reopen original");
    }
    try {
        // MAIN (preserve flags, dict, volume size; keep old salt, or adopt the
        // temp build's salt when the archive had none and new entries are
        // encrypted)
        std::vector<uint8_t> salt = info.salt;
        uint32_t aflags = info.archiveFlags;
        if (volSize) aflags |= AF_VOLUME;
        if (salt.empty() && !newInfo.salt.empty()) salt = newInfo.salt;
        std::vector<uint8_t> mainPayload;
        put64(mainPayload, info.dictSize);
        put32(mainPayload, aflags);
        put64(mainPayload, volSize);
        if (!salt.empty()) {
            put32(mainPayload, uint32_t(salt.size()));
            mainPayload.insert(mainPayload.end(), salt.begin(), salt.end());
        }
        fw.start(H_MAIN, 0, 0);
        fw.payload(mainPayload.data(), mainPayload.size());
        if (!fw.commit()) throw WrcError("write failed");

        // kept entries — raw byte copy across the logical stream
        std::vector<uint8_t> buf(1u << 20);
        for (uint32_t idx : keepIdx) {
            if (cf && !cf()) throw CancelledError();
            const FileEntry& e = info.entries[idx];
            uint64_t len = e.dataEnd - e.headerStart;
            uint64_t off = 0;
            while (off < len) {
                uint64_t want = std::min<uint64_t>(buf.size(), len - off);
                size_t got = 0;
                if (!stOld.pread(buf.data(), size_t(want), e.headerStart + off, got) ||
                    got == 0)
                    throw WrcError("copy failed");
                if (!out.write(buf.data(), got)) throw WrcError("write failed");
                off += got;
            }
            pt.addDone(e.isDir ? 0 : e.size);
            pt.setFile(e.name);
            pt.check(cf);
        }

        // new entries — raw copy of frames from the temp build (skip MAIN)
        if (!newEntries.empty()) {
            PartStream stNew;
            if (!stNew.open(tempArchive)) throw WrcError("temp read failed");
            for (auto& e : newEntries) {
                if (cf && !cf()) throw CancelledError();
                uint64_t len = e.dataEnd - e.headerStart;
                uint64_t off = 0;
                while (off < len) {
                    uint64_t want = std::min<uint64_t>(buf.size(), len - off);
                    size_t got = 0;
                    if (!stNew.pread(buf.data(), size_t(want), e.headerStart + off, got) ||
                        got == 0)
                        throw WrcError("copy failed");
                    if (!out.write(buf.data(), got)) throw WrcError("write failed");
                    off += got;
                }
                pt.addDone(e.isDir ? 0 : e.size);
                pt.setFile(e.name);
                pt.check(cf);
            }
            stNew.close();
        }

        // END
        std::vector<uint8_t> endPl;
        put32(endPl, uint32_t(out.parts().size()));
        put32(endPl, 0);
        fw.start(H_END, 0, 0);
        fw.payload(endPl.data(), endPl.size());
        if (!fw.commit()) throw WrcError("write failed");
    } catch (...) {
        out.close();
        stOld.close();
        deleteFileForever(tempArchive);
        for (auto& pp : out.parts()) deleteFileForever(pp);
        throw;
    }
    out.close();
    stOld.close();
    deleteFileForever(tempArchive);

    // swap: remove old parts, move new parts into place
    std::vector<std::wstring> oldParts;
    {
        PartStream stTmp;
        if (stTmp.open(path)) oldParts = stTmp.parts();
    }
    for (auto& p : oldParts) deleteFileForever(p);
    const auto& newParts = out.parts();
    if (volSize > 0) {
        for (size_t i = 0; i < newParts.size(); ++i) {
            wchar_t nb[24];
            swprintf(nb, 24, L".part%05d.wrc", int(i + 1));
            std::wstring target = base + nb;
            if (!MoveFileExW(toExtendedPath(newParts[i]).c_str(),
                             toExtendedPath(target).c_str(),
                             MOVEFILE_REPLACE_EXISTING))
                throw WrcError("rename failed");
        }
    } else {
        if (!MoveFileExW(toExtendedPath(newParts[0]).c_str(),
                         toExtendedPath(path).c_str(), MOVEFILE_REPLACE_EXISTING))
            throw WrcError("rename failed");
    }
    return true;
}

}  // namespace wsar
}  // namespace wrc
