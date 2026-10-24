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
#include <windows.h>
#include <zlib.h>
#include <zstd.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <set>

namespace wrc {
namespace wsar {

static const uint8_t kMagic[8] = {'W', 'S', 'A', 'R', 0x1A, 0x07, 0x01, 0x00};
static const uint64_t kFrameFixed = 26;  // magic8+crc4+hsize2+type1+flags1+rsv2+dlen8
enum : uint8_t { H_MAIN = 1, H_FILE = 2, H_END = 3, H_SOLID = 4 };
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

    // Temp file for plaintext (bounded memory).
    wchar_t tmpDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpDir);
    wchar_t tmpPath[MAX_PATH];
    if (!GetTempFileNameW(tmpDir, L"wrc", 0, tmpPath)) {
        err = "cannot create temp file";
        return false;
    }
    File tmpFile;
    if (!tmpFile.openWriteTruncate(tmpPath)) {
        DeleteFileW(tmpPath);
        err = "cannot create temp file";
        return false;
    }

    uint64_t consumed = 16;
    bool ok = true;
    while (consumed + 16 < cipherTotal) {
        uint64_t left = cipherTotal - consumed - 16;
        uint64_t want = std::min<uint64_t>(left, inBuf.size());
        want -= want % 16;
        if (want == 0) break;
        if (!st.pread(inBuf.data(), size_t(want), dataOff + consumed, got) ||
            got != want) {
            ok = false; break;
        }
        mac.update(inBuf.data(), size_t(want));
        size_t outN = 0;
        if (!aes.decrypt(inBuf.data(), size_t(want), outBuf.data(), outBuf.size(), outN,
                         iv, false)) {
            ok = false; break;
        }
        if (outN && !tmpFile.write(outBuf.data(), (uint32_t)outN)) { ok = false; break; }
        consumed += want;
    }
    uint64_t left = cipherTotal - consumed;
    std::vector<uint8_t> tail(size_t(left) + 16, 0);
    if (ok && left && (!st.pread(tail.data(), uint32_t(left), dataOff + consumed, got) ||
                       got != left)) {
        ok = false;
    }
    uint8_t macBuf[16];
    if (ok && (!st.pread(macBuf, 16, dataOff + dataLen - 16, got) || got != 16)) {
        ok = false;
    }
    if (ok) {
        mac.update(tail.data(), size_t(left));
        std::vector<uint8_t> macCalc;
        if (!mac.finish(macCalc) || memcmp(macCalc.data(), macBuf, 16) != 0) {
            ok = false;
        }
    }
    if (ok && left > 0) {
        size_t outN = 0;
        if (!aes.decrypt(tail.data(), size_t(left), outBuf.data(), outBuf.size(), outN,
                         iv, true)) {
            ok = false;
        } else if (outN && !tmpFile.write(outBuf.data(), (uint32_t)outN)) {
            ok = false;
        }
    }
    tmpFile.close();

    if (!ok) {
        DeleteFileW(tmpPath);
        err = "authentication failed (wrong password or corrupted data)";
        // distinguish read errors
        return false;
    }

    // MAC verified: stream temp file to sink.
    File tmpIn;
    if (!tmpIn.openRead(tmpPath)) {
        DeleteFileW(tmpPath);
        err = "read failed";
        return false;
    }
    std::vector<uint8_t> buf(1u << 20);
    uint64_t remaining = tmpIn.size();
    while (remaining > 0) {
        uint64_t want = std::min<uint64_t>(buf.size(), remaining);
        uint32_t g = 0;
        if (!tmpIn.read(buf.data(), (uint32_t)want, g) || g != want) {
            tmpIn.close();
            DeleteFileW(tmpPath);
            err = "read failed";
            return false;
        }
        sink(buf.data(), g);
        remaining -= g;
    }
    tmpIn.close();
    DeleteFileW(tmpPath);
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
                      ControlFn cf, std::vector<uint32_t>* table) {
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
        lzssEncode(view, it.size, lp, packed, table);
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

    // Wrap LZSS output in Deflate (entropy coding) when it helps.
    std::vector<uint8_t> deflated;
    if (lp.zlibLevel > 0 && !packed.empty()) {
        z_stream zs{};
        if (deflateInit2(&zs, lp.zlibLevel, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) == Z_OK) {
            std::vector<uint8_t> outBuf(1u << 20);
            zs.next_in = packed.data();
            zs.avail_in = uInt(packed.size());
            int rc = Z_OK;
            do {
                zs.next_out = outBuf.data();
                zs.avail_out = uint32_t(outBuf.size());
                rc = deflate(&zs, Z_FINISH);
                size_t have = outBuf.size() - zs.avail_out;
                if (have) deflated.insert(deflated.end(), outBuf.data(), outBuf.data() + have);
            } while (rc != Z_STREAM_END && zs.avail_out == 0);
            deflateEnd(&zs);
            if (rc != Z_STREAM_END) deflated.clear();
        }
    }

    bool useDeflated = !deflated.empty() && deflated.size() < packed.size();
    const std::vector<uint8_t>& toWrite = useDeflated ? deflated : packed;
    res.method = useDeflated ? 3 : 2;  // 3 = LZSS+Deflate, 2 = raw LZSS

    File dst;
    if (!dst.openWriteTruncate(res.tempPath)) throw WrcError("temp file failed");
    if (!dst.write(toWrite.data(), toWrite.size() ? uint32_t(toWrite.size()) : 0u))
        throw WrcError("write failed");
    res.packedSize = toWrite.size();
    return res;
}

PackedItem zstdToTemp(const ScanItem& it, const std::wstring& tempDir, int idx,
                      ProgressTracker& pt, ControlFn cf, int level) {
    PackedItem res;
    res.method = 4;  // 4 = Zstd
    res.tempPath = tempDir + L"\\~wsar" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                   std::to_wstring(idx) + L".tmp";
    File src;
    if (!src.openRead(it.fullPath)) throw WrcError("cannot open: " + toUtf8(it.fullPath));
    File dst;
    if (!dst.openWriteTruncate(res.tempPath)) throw WrcError("temp file failed");
    if (level < 1) level = 1;
    if (level > 22) level = 22;
    ZSTD_CCtx* cctx = ZSTD_createCCtx();
    if (!cctx) throw WrcError("zstd init failed");
    ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level);
    std::vector<uint8_t> inBuf(1u << 20);
    std::vector<uint8_t> outBuf(ZSTD_CStreamOutSize());
    uint32_t crc = crc32Init();
    uint64_t done = 0;
    ZSTD_inBuffer input = {nullptr, 0, 0};
    int finished = 0;
    try {
        while (!finished) {
            if (cf && !cf()) throw CancelledError();
            if (input.pos == input.size && done < it.size) {
                uint64_t want = std::min<uint64_t>(inBuf.size(), it.size - done);
                uint32_t got = 0;
                if (!src.read(inBuf.data(), uint32_t(want), got) || got == 0) throw WrcError("read failed");
                crc = crc32Update(crc, inBuf.data(), got);
                input.src = inBuf.data();
                input.size = got;
                input.pos = 0;
                done += got;
            }
            ZSTD_outBuffer output = {outBuf.data(), outBuf.size(), 0};
            size_t ret = ZSTD_compressStream2(cctx, &output, &input,
                                             (done >= it.size && input.pos == input.size) ? ZSTD_e_end : ZSTD_e_continue);
            if (ZSTD_isError(ret)) throw WrcError("zstd compress failed");
            if (output.pos && !dst.write(outBuf.data(), uint32_t(output.pos)))
                throw WrcError("write failed");
            res.packedSize += output.pos;
            pt.addDone(input.size > 0 && input.pos == input.size ? input.size : 0);
            pt.setFile(fileNameOf(it.fullPath));
            pt.check(cf);
            if (done >= it.size && input.pos == input.size && ret == 0) finished = 1;
        }
    } catch (...) {
        ZSTD_freeCCtx(cctx);
        throw;
    }
    ZSTD_freeCCtx(cctx);
    src.close();
    res.crc = crc;
    pt.check(cf);
    return res;
}

// ------------------------------------------------------------------ sinks
class CrcFileSink : public LzssOutSink {
public:
    CrcFileSink(File& f) : f_(f) {}
    void write(const void* buf, size_t len) override {
        if (len) {
            if (!f_.write(buf, uint32_t(len))) throw WrcError("write failed");
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
    if (e.method == 3) {
        // LZSS wrapped in Deflate (entropy coding), streaming (bounded memory).
        wchar_t tmpDir[MAX_PATH];
        GetTempPathW(MAX_PATH, tmpDir);
        wchar_t packedTmp[MAX_PATH];
        if (!GetTempFileNameW(tmpDir, L"wrc", 0, packedTmp)) { err = "cannot create temp"; return false; }

        // Produce packed (deflated LZSS) bytes into packedTmp.
        if (e.encrypted) {
            File pf;
            if (!pf.openWriteTruncate(packedTmp)) { DeleteFileW(packedTmp); err = "cannot create temp"; return false; }
            std::string rerr;
            if (!readRegionEncrypted(st, dataOff, e.packedSize, dataKey,
                                     [&](const uint8_t* p, size_t n) { pf.write(p, (uint32_t)n); },
                                     rerr)) {
                pf.close(); DeleteFileW(packedTmp); err = rerr; return false;
            }
            pf.close();
        } else {
            File pf;
            if (!pf.openWriteTruncate(packedTmp)) { DeleteFileW(packedTmp); err = "cannot create temp"; return false; }
            // copy deflated bytes (packed region) directly
            uint64_t remaining = e.packedSize;
            uint64_t offset = dataOff;
            std::vector<uint8_t> buf(1u << 20);
            while (remaining > 0) {
                uint64_t want = std::min<uint64_t>(buf.size(), remaining);
                size_t got = 0;
                if (!st.pread(buf.data(), (uint32_t)want, offset, got) || got != want) {
                    pf.close(); DeleteFileW(packedTmp); err = "read failed"; return false;
                }
                if (!pf.write(buf.data(), (uint32_t)got)) { pf.close(); DeleteFileW(packedTmp); err = "write failed"; return false; }
                offset += got;
                remaining -= got;
            }
            pf.close();
        }

        // Inflate packedTmp -> lzssTmp (bounded memory).
        wchar_t lzssTmp[MAX_PATH];
        if (!GetTempFileNameW(tmpDir, L"wrc", 0, lzssTmp)) { DeleteFileW(packedTmp); err = "cannot create temp"; return false; }
        File lzssFile;
        if (!lzssFile.openWriteTruncate(lzssTmp)) { DeleteFileW(packedTmp); DeleteFileW(lzssTmp); err = "cannot create temp"; return false; }
        File packedIn;
        if (!packedIn.openRead(packedTmp)) { lzssFile.close(); DeleteFileW(packedTmp); DeleteFileW(lzssTmp); err = "read failed"; return false; }
        z_stream zs{};
        if (inflateInit2(&zs, -15) != Z_OK) { packedIn.close(); lzssFile.close(); DeleteFileW(packedTmp); DeleteFileW(lzssTmp); err = "zlib init failed"; return false; }
        std::vector<uint8_t> inBuf(1u << 20);
        std::vector<uint8_t> outBuf(1u << 20);
        uint64_t remaining = packedIn.size();
        int rc = Z_OK;
        do {
            if (zs.avail_in == 0 && remaining > 0) {
                uint64_t want = std::min<uint64_t>(inBuf.size(), remaining);
                uint32_t got = 0;
                if (!packedIn.read(inBuf.data(), (uint32_t)want, got) || got != want) { inflateEnd(&zs); packedIn.close(); lzssFile.close(); DeleteFileW(packedTmp); DeleteFileW(lzssTmp); err = "read failed"; return false; }
                zs.next_in = inBuf.data();
                zs.avail_in = (uInt)got;
                remaining -= got;
            }
            zs.next_out = outBuf.data();
            zs.avail_out = (uInt)outBuf.size();
            rc = inflate(&zs, Z_NO_FLUSH);
            if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) { inflateEnd(&zs); packedIn.close(); lzssFile.close(); DeleteFileW(packedTmp); DeleteFileW(lzssTmp); err = "inflate failed"; return false; }
            size_t have = outBuf.size() - zs.avail_out;
            if (have && !lzssFile.write(outBuf.data(), (uint32_t)have)) { inflateEnd(&zs); packedIn.close(); lzssFile.close(); DeleteFileW(packedTmp); DeleteFileW(lzssTmp); err = "write failed"; return false; }
        } while (rc != Z_STREAM_END && (remaining > 0 || zs.avail_in > 0));
        inflateEnd(&zs);
        packedIn.close();
        lzssFile.close();
        DeleteFileW(packedTmp);

        // memory-map lzssTmp and lzss-decode
        File src;
        if (!src.openRead(lzssTmp)) { DeleteFileW(lzssTmp); err = "read failed"; return false; }
        uint64_t sz = src.size();
        HANDLE map = CreateFileMappingW(src.handle(), nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!map) { src.close(); DeleteFileW(lzssTmp); err = "mapping failed"; return false; }
        const uint8_t* view = static_cast<const uint8_t*>(MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0));
        if (!view) { CloseHandle(map); src.close(); DeleteFileW(lzssTmp); err = "mapping failed"; return false; }
        bool ok = lzssDecode(view, sz, sink, err);
        UnmapViewOfFile(view);
        CloseHandle(map);
        src.close();
        DeleteFileW(lzssTmp);
        if (!ok) return false;
        crcOut = sink.crc();
        return true;
    }
    if (e.method == 4) {
        // Zstd (streaming decompression, bounded memory)
        ZSTD_DCtx* dctx = ZSTD_createDCtx();
        if (!dctx) { err = "zstd init failed"; return false; }
        std::vector<uint8_t> outBuf(1u << 20);
        std::vector<uint8_t> inBuf(1u << 20);

        if (e.encrypted) {
            // Buffer decrypted data to temp file (MAC verified inside).
            std::wstring tmpPacked = directoryOf(outFile.handle() ? L"" : L"") + L"\\~zstdpacked" + std::to_wstring(GetCurrentProcessId()) + L".tmp";
            // Use destDir? We don't have destDir here; use system temp.
            wchar_t tmpDir[MAX_PATH];
            GetTempPathW(MAX_PATH, tmpDir);
            tmpPacked = std::wstring(tmpDir) + L"~zstdpacked" + std::to_wstring(GetCurrentProcessId()) + L".tmp";
            File tmpF;
            if (!tmpF.openWriteTruncate(tmpPacked)) { ZSTD_freeDCtx(dctx); err = "cannot create temp"; return false; }
            std::string rerr;
            if (!readRegionEncrypted(st, dataOff, e.packedSize, dataKey,
                                     [&](const uint8_t* p, size_t n) { tmpF.write(p, (uint32_t)n); },
                                     rerr)) {
                tmpF.close(); deleteFileForever(tmpPacked); ZSTD_freeDCtx(dctx); err = rerr; return false;
            }
            tmpF.close();
            // stream decompress from temp file
            File src;
            if (!src.openRead(tmpPacked)) { deleteFileForever(tmpPacked); ZSTD_freeDCtx(dctx); err = "read failed"; return false; }
            uint64_t remaining = src.size();
            ZSTD_inBuffer input = {nullptr, 0, 0};
            std::vector<uint8_t> chunk(1u << 20);
            while (true) {
                if (input.pos == input.size && remaining > 0) {
                    uint64_t want = std::min<uint64_t>(chunk.size(), remaining);
                    uint32_t got = 0;
                    if (!src.read(chunk.data(), (uint32_t)want, got) || got == 0) { src.close(); deleteFileForever(tmpPacked); ZSTD_freeDCtx(dctx); err = "read failed"; return false; }
                    input.src = chunk.data();
                    input.size = got;
                    input.pos = 0;
                    remaining -= got;
                }
                ZSTD_outBuffer output = {outBuf.data(), outBuf.size(), 0};
                size_t r = ZSTD_decompressStream(dctx, &output, &input);
                if (ZSTD_isError(r)) { src.close(); deleteFileForever(tmpPacked); ZSTD_freeDCtx(dctx); err = "zstd decompress failed"; return false; }
                if (output.pos) sink.write(outBuf.data(), (uint32_t)output.pos);
                if (remaining == 0 && input.pos == input.size && r == 0) break;
            }
            src.close();
            deleteFileForever(tmpPacked);
        } else {
            uint64_t remaining = e.packedSize;
            std::vector<uint8_t> chunk(1u << 20);
            ZSTD_inBuffer input = {nullptr, 0, 0};
            while (true) {
                if (input.pos == input.size && remaining > 0) {
                    uint64_t want = std::min<uint64_t>(chunk.size(), remaining);
                    size_t got = 0;
                    if (!st.pread(chunk.data(), (uint32_t)want, dataOff + (e.packedSize - remaining), got) || got != want) {
                        ZSTD_freeDCtx(dctx); err = "read failed"; return false;
                    }
                    input.src = chunk.data();
                    input.size = got;
                    input.pos = 0;
                    remaining -= got;
                }
                ZSTD_outBuffer output = {outBuf.data(), outBuf.size(), 0};
                size_t r = ZSTD_decompressStream(dctx, &output, &input);
                if (ZSTD_isError(r)) { ZSTD_freeDCtx(dctx); err = "zstd decompress failed"; return false; }
                if (output.pos) sink.write(outBuf.data(), (uint32_t)output.pos);
                if (remaining == 0 && input.pos == input.size && r == 0) break;
            }
        }
        ZSTD_freeDCtx(dctx);
        crcOut = sink.crc();
        return true;
    }
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

    // ---- Solid archive build (single compressed stream over all files) ----
    if (opt.solid) {
        uint64_t total = scanTotalSize(items);
        ProgressTracker pt(Progress::Phase::Compress, total, pf);
        pt.check(cf);

        bool encrypt = !opt.password.empty();
        std::vector<uint8_t> salt, dataKey;
        if (encrypt) {
            salt = opt.forcedSalt.size() == 16 ? opt.forcedSalt : randomBytes(16);
            dataKey = pbkdf2Sha256(toUtf8(opt.password), salt, 200000, 32, 0x01);
            if (dataKey.empty()) throw WrcError("crypto init failed");
        }

        // First pass: compute per-file metadata (bounded memory).
        struct SF { std::wstring name; uint64_t size; uint32_t crc; uint32_t attrs; uint64_t mtime; };
        std::vector<SF> files;
        std::wstring tempDir = directoryOf(opt.archivePath);
        for (const auto& it : items) {
            if (it.isDir) continue;
            if (cf && !cf()) throw CancelledError();
            File f;
            if (!f.openRead(it.fullPath)) throw WrcError("cannot open: " + toUtf8(it.fullPath));
            std::vector<uint8_t> buf(1u << 20);
            uint32_t crc = crc32Init();
            uint64_t done = 0;
            while (done < it.size) {
                uint64_t want = std::min<uint64_t>(buf.size(), it.size - done);
                uint32_t got = 0;
                if (!f.read(buf.data(), uint32_t(want), got) || got == 0) throw WrcError("read failed");
                crc = crc32Update(crc, buf.data(), got);
                done += got;
                pt.addDone(got);
                pt.check(cf);
            }
            f.close();
            files.push_back({fromUtf8(toUtf8(it.relPath)), it.size, crc, it.attrs & 0xFF, it.mtime});
        }

        // Second pass: stream-compress concatenated data into a temp file (bounded memory).
        int level = deflateLevel(opt.method);
        uint8_t codec = (level == 0) ? 0 : 1;
        std::wstring packedTmp = tempDir + L"\\~solidpacked" + std::to_wstring(GetCurrentProcessId()) + L".tmp";
        File packedFile;
        if (!packedFile.openWriteTruncate(packedTmp)) throw WrcError("cannot create temp file");
        uint64_t packedSize = 0;
        if (level == 0) {
            for (const auto& it : items) {
                if (it.isDir) continue;
                if (cf && !cf()) { packedFile.close(); deleteFileForever(packedTmp); throw CancelledError(); }
                File f;
                if (!f.openRead(it.fullPath)) { packedFile.close(); deleteFileForever(packedTmp); throw WrcError("cannot open"); }
                std::vector<uint8_t> buf(1u << 20);
                uint64_t done = 0;
                while (done < it.size) {
                    uint64_t want = std::min<uint64_t>(buf.size(), it.size - done);
                    uint32_t got = 0;
                    if (!f.read(buf.data(), uint32_t(want), got) || got == 0) { f.close(); packedFile.close(); deleteFileForever(packedTmp); throw WrcError("read failed"); }
                    if (!packedFile.write(buf.data(), got)) { f.close(); packedFile.close(); deleteFileForever(packedTmp); throw WrcError("write failed"); }
                    packedSize += got;
                    done += got;
                    pt.check(cf);
                }
                f.close();
            }
        } else {
            z_stream zs{};
            if (deflateInit2(&zs, level, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK) {
                packedFile.close(); deleteFileForever(packedTmp); throw WrcError("zlib init failed");
            }
            std::vector<uint8_t> inBuf(1u << 20);
            std::vector<uint8_t> outBuf(1u << 20);
            for (const auto& it : items) {
                if (it.isDir) continue;
                if (cf && !cf()) { deflateEnd(&zs); packedFile.close(); deleteFileForever(packedTmp); throw CancelledError(); }
                File f;
                if (!f.openRead(it.fullPath)) { deflateEnd(&zs); packedFile.close(); deleteFileForever(packedTmp); throw WrcError("cannot open"); }
                uint64_t done = 0;
                while (done < it.size) {
                    uint64_t want = std::min<uint64_t>(inBuf.size(), it.size - done);
                    uint32_t got = 0;
                    if (!f.read(inBuf.data(), uint32_t(want), got) || got == 0) { deflateEnd(&zs); f.close(); packedFile.close(); deleteFileForever(packedTmp); throw WrcError("read failed"); }
                    zs.next_in = inBuf.data();
                    zs.avail_in = got;
                    int rc = Z_OK;
                    while (zs.avail_in > 0) {
                        zs.next_out = outBuf.data();
                        zs.avail_out = uint32_t(outBuf.size());
                        rc = deflate(&zs, Z_NO_FLUSH);
                        if (rc != Z_OK && rc != Z_BUF_ERROR) { deflateEnd(&zs); f.close(); packedFile.close(); deleteFileForever(packedTmp); throw WrcError("deflate failed"); }
                        size_t have = outBuf.size() - zs.avail_out;
                        if (have && !packedFile.write(outBuf.data(), uint32_t(have))) { deflateEnd(&zs); f.close(); packedFile.close(); deleteFileForever(packedTmp); throw WrcError("write failed"); }
                        packedSize += have;
                    }
                    done += got;
                    pt.addDone(got);
                    pt.check(cf);
                }
                f.close();
            }
            zs.next_in = nullptr;
            zs.avail_in = 0;
            int rc = Z_OK;
            do {
                zs.next_out = outBuf.data();
                zs.avail_out = uint32_t(outBuf.size());
                rc = deflate(&zs, Z_FINISH);
                size_t have = outBuf.size() - zs.avail_out;
                if (have && !packedFile.write(outBuf.data(), uint32_t(have))) { deflateEnd(&zs); packedFile.close(); deleteFileForever(packedTmp); throw WrcError("write failed"); }
                packedSize += have;
            } while (rc != Z_STREAM_END);
            deflateEnd(&zs);
        }
        packedFile.close();

        // Write container (copy from packedTmp).
        std::wstring base = stripExtension(opt.archivePath);
        MultiWriter out;
        if (!out.open(opt.archivePath, base, opt.volumeSize))
            throw WrcError("cannot create archive: " + toUtf8(opt.archivePath));
        FrameWriter fw(out);
        try {
            // MAIN
            uint32_t aflags = AF_SOLID;
            if (opt.volumeSize) aflags |= AF_VOLUME;
            std::vector<uint8_t> mainPayload;
            put64(mainPayload, opt.dictSize);
            put32(mainPayload, aflags);
            if (encrypt) {
                put32(mainPayload, uint32_t(salt.size()));
                mainPayload.insert(mainPayload.end(), salt.begin(), salt.end());
            }
            fw.start(H_MAIN, 0, 0);
            fw.payload(mainPayload.data(), mainPayload.size());
            if (!fw.commit()) throw WrcError("write failed");

            // H_SOLID frame
            uint8_t encFlag = encrypt ? 1 : 0;
            std::vector<uint8_t> pl;
            pl.push_back(codec);
            pl.push_back(encFlag);
            put32(pl, uint32_t(files.size()));
            for (const auto& fe : files) {
                put64(pl, fe.size);
                put32(pl, fe.crc);
                put32(pl, fe.attrs);
                put64(pl, fe.mtime);
                std::string n8 = toUtf8(fe.name);
                put16(pl, uint16_t(n8.size()));
                pl.insert(pl.end(), n8.begin(), n8.end());
            }
            uint64_t dataLen = encrypt ? (16 + ((packedSize / 16 + 1) * 16) + 16) : packedSize;
            fw.start(H_SOLID, 0, dataLen);
            fw.payload(pl.data(), pl.size());
            if (!fw.commit()) throw WrcError("write failed");

            // data region (copy from packedTmp, encrypt if needed)
            File packedIn;
            if (!packedIn.openRead(packedTmp)) throw WrcError("cannot read temp");
            if (encrypt) {
                DataEncryptor de(dataKey, out);
                std::vector<uint8_t> buf(1u << 20);
                uint64_t done = 0;
                while (done < packedSize) {
                    uint64_t want = std::min<uint64_t>(buf.size(), packedSize - done);
                    uint32_t got = 0;
                    if (!packedIn.read(buf.data(), uint32_t(want), got) || got == 0) throw WrcError("read failed");
                    de.feed(buf.data(), got, false);
                    done += got;
                }
                de.feed(nullptr, 0, true);
            } else {
                std::vector<uint8_t> buf(1u << 20);
                uint64_t done = 0;
                while (done < packedSize) {
                    uint64_t want = std::min<uint64_t>(buf.size(), packedSize - done);
                    uint32_t got = 0;
                    if (!packedIn.read(buf.data(), uint32_t(want), got) || got == 0) throw WrcError("read failed");
                    if (!out.write(buf.data(), got)) throw WrcError("write failed");
                    done += got;
                }
            }
            packedIn.close();
            deleteFileForever(packedTmp);

            // END
            std::vector<uint8_t> endPl;
            put32(endPl, uint32_t(out.parts().size()));
            put32(endPl, 0);
            fw.start(H_END, 0, 0);
            fw.payload(endPl.data(), endPl.size());
            if (!fw.commit()) throw WrcError("write failed");
        } catch (...) {
            out.close();
            deleteFileForever(packedTmp);
            throw;
        }
        out.close();

        totalIn = total;
        for (auto& pp : out.parts()) totalOut += fileSizeOf(pp);
        return true;
    }
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
    bool useZstd = (opt.method == Method::Zstd);
    bool useLzss = !useZstd && int(opt.method) >= int(Method::Normal);
    uint64_t effWindow = DictionaryManager::effectiveEncoderWindow(opt.dictSize);
    try {
        if (useLzss) {
            LzssParams lp = lzssParamsForMethod(uint8_t(opt.method), opt.longRangeSearch,
                                                opt.exhaustiveSearch);
            lp.window = effWindow;
            lp.zlibLevel = deflateLevel(opt.method);
            // Parallel per-file compression (each file gets its own hash table).
            unsigned hw = opt.multiThread
                              ? (opt.threads > 0 ? unsigned(opt.threads)
                                                 : std::thread::hardware_concurrency())
                              : 1;
            if (!hw) hw = 4;
            std::vector<std::future<void>> futs;
            {
                ThreadPool pool(hw);
                for (size_t i = 0; i < items.size(); ++i) {
                    if (items[i].isDir || items[i].size == 0) continue;
                    futs.push_back(pool.submit([&items, &packed, &pt, cf, tempDir, i, lp] {
                        packed[i] = lzssToTemp(items[i], lp, tempDir, int(i), pt, cf, nullptr);
                    }));
                }
                pool.waitIdle();
            }
            for (auto& f : futs) f.get();
        } else if (useZstd) {
            unsigned hw = opt.multiThread
                              ? (opt.threads > 0 ? unsigned(opt.threads)
                                                 : std::thread::hardware_concurrency())
                              : 1;
            if (!hw) hw = 4;
            std::vector<std::future<void>> futs;
            {
                ThreadPool pool(hw);
                for (size_t i = 0; i < items.size(); ++i) {
                    if (items[i].isDir || items[i].size == 0) continue;
                    futs.push_back(pool.submit([&items, &packed, &pt, cf, tempDir, i, &opt] {
                        packed[i] = zstdToTemp(items[i], tempDir, int(i), pt, cf, opt.zstdLevel);
                    }));
                }
                pool.waitIdle();
            }
            for (auto& f : futs) f.get();
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
                    if (items[i].isDir || items[i].size == 0) continue;
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
        if (fr.type == H_SOLID) {
            const std::vector<uint8_t>& pl = fr.payload;
            if (pl.size() < 6) continue;
            size_t pos = 0;
            uint8_t codec = pl[pos++];
            uint8_t encFlag = pl[pos++];
            uint32_t fileCount = rd32(pl.data() + pos); pos += 4;
            uint64_t cum = 0;
            for (uint32_t fi = 0; fi < fileCount; ++fi) {
                if (pl.size() < pos + 8 + 4 + 4 + 8 + 2) break;
                FileEntry e;
                e.size = rd64(pl.data() + pos); pos += 8;
                e.crc32 = rd32(pl.data() + pos); pos += 4;
                e.attrs = rd32(pl.data() + pos); pos += 4;
                e.mtime = rd64(pl.data() + pos); pos += 8;
                uint16_t nameLen = rd16(pl.data() + pos); pos += 2;
                if (pl.size() < pos + nameLen) break;
                std::string n8(reinterpret_cast<const char*>(pl.data() + pos), nameLen);
                pos += nameLen;
                std::wstring name = fromUtf8(n8);
                bool isDir = !name.empty() && name.back() == L'/';
                if (isDir) name.pop_back();
                std::wstring clean;
                if (name.empty() || !safeRelName(isDir ? name + L"/x" : name, clean)) continue;
                e.name = isDir ? clean.substr(0, clean.size() - 2) : clean;
                e.isDir = isDir;
                e.method = codec;
                e.encrypted = encFlag != 0;
                e.solid = true;
                e.solidOffset = cum;
                cum += e.size;
                e.headerStart = fr.startOffset;
                e.dataEnd = fr.endOffset;
                out.entries.push_back(e);
                if (!e.isDir) out.totalOriginal += e.size;
            }
            out.totalPacked += fr.dataLen;
            continue;
        }
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

// ----------------------------------------------------------------- helpers
static bool isReparsePoint(const std::wstring& path) {
    DWORD a = GetFileAttributesW(toExtendedPath(path).c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return false;
    return (a & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

static bool checkOverwrite(const std::wstring& dest, OverwritePolicy policy, std::string& err) {
    if (!fileExists(dest)) return true;
    if (policy == OverwritePolicy::Replace) return true;
    if (policy == OverwritePolicy::Skip) return false;
    err = "file exists: " + toUtf8(dest);
    return false;
}

// ----------------------------------------------------------------- extract
bool extract(const std::wstring& path, const std::wstring& destDir,
             const std::wstring& password, const std::vector<std::wstring>& only,
             const ProgressFn& pf, ControlFn cf, std::vector<std::wstring>& extracted,
             std::string& err, const ExtractLimits& limits, OverwritePolicy overwrite) {
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

    std::set<uint64_t> processedSolid;
    uint64_t totalExtracted = 0;
    uint32_t entriesExtracted = 0;
    for (auto& e : info.entries) {
        if (e.solid) {
            if (processedSolid.count(e.headerStart)) continue;
            // ---- solid block extraction (see implementation) ----
            // parse + decompress + write files
            uint8_t h[26]; size_t g0 = 0;
            if (!st.pread(h, 26, e.headerStart, g0) || g0 != 26) { err = "read failed"; return false; }
            uint16_t hsize = rd16(h + 12);
            uint64_t dataLen = rd64(h + 18);
            std::vector<uint8_t> payload(hsize);
            if (hsize && (!st.pread(payload.data(), hsize, e.headerStart + kFrameFixed, g0) || g0 != hsize)) { err = "read failed"; return false; }
            size_t pos = 0;
            if (payload.size() < 6) { processedSolid.insert(e.headerStart); continue; }
            uint8_t codec = payload[pos++];
            uint8_t encFlag = payload[pos++];
            uint32_t fileCount = rd32(payload.data() + pos); pos += 4;
            struct SF { std::wstring name; uint64_t size; uint32_t crc; uint32_t attrs; uint64_t mtime; uint64_t off; };
            std::vector<SF> files;
            uint64_t cum = 0;
            for (uint32_t fi = 0; fi < fileCount; ++fi) {
                if (payload.size() < pos + 8 + 4 + 4 + 8 + 2) break;
                SF f;
                f.size = rd64(payload.data() + pos); pos += 8;
                f.crc = rd32(payload.data() + pos); pos += 4;
                f.attrs = rd32(payload.data() + pos); pos += 4;
                f.mtime = rd64(payload.data() + pos); pos += 8;
                uint16_t nameLen = rd16(payload.data() + pos); pos += 2;
                if (payload.size() < pos + nameLen) break;
                std::string n8(reinterpret_cast<const char*>(payload.data() + pos), nameLen);
                pos += nameLen;
                f.name = fromUtf8(n8);
                f.off = cum;
                cum += f.size;
                files.push_back(f);
            }
            uint64_t dataOff = e.headerStart + kFrameFixed + hsize;
            std::vector<uint8_t> packed;
            if (encFlag) {
                std::string rerr;
                if (!readRegionEncrypted(st, dataOff, dataLen, dataKey,
                                         [&](const uint8_t* p, size_t n) { packed.insert(packed.end(), p, p + n); },
                                         rerr)) { err = rerr; return false; }
            } else {
                packed.resize(size_t(dataLen));
                size_t g = 0;
                if (!st.pread(packed.data(), size_t(dataLen), dataOff, g) || g != dataLen) { err = "read failed"; return false; }
            }
            if (cum > (512ull << 20)) {
                err = "solid block too large for in-memory extraction";
                return false;
            }
            std::wstring solidTmp = destDir + L"\\\\~solidtmp" + std::to_wstring(GetCurrentProcessId()) + L".tmp";
            File solidFile;
            if (!solidFile.openWriteTruncate(solidTmp)) { err = "cannot create temp file"; return false; }
            if (codec == 0) {
                if (!solidFile.write(packed.data(), uint32_t(packed.size()))) { solidFile.close(); err = "write failed"; return false; }
            } else {
                z_stream zs{};
                if (inflateInit2(&zs, -15) != Z_OK) { solidFile.close(); err = "zlib init failed"; return false; }
                std::vector<uint8_t> outBuf(1u << 20);
                zs.next_in = packed.data();
                zs.avail_in = uInt(packed.size());
                int rc = Z_OK;
                do {
                    zs.next_out = outBuf.data();
                    zs.avail_out = uint32_t(outBuf.size());
                    rc = inflate(&zs, Z_NO_FLUSH);
                    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) { inflateEnd(&zs); solidFile.close(); err = "inflate failed"; return false; }
                    size_t have = outBuf.size() - zs.avail_out;
                    if (have && !solidFile.write(outBuf.data(), uint32_t(have))) { inflateEnd(&zs); solidFile.close(); err = "write failed"; return false; }
                } while (rc != Z_STREAM_END && zs.avail_out == 0);
                inflateEnd(&zs);
            }
            solidFile.close();
            std::set<std::wstring> want(only.begin(), only.end());
            for (const auto& sf : files) {
                if (limits.maxEntries && entriesExtracted >= limits.maxEntries) { err = "too many entries"; return false; }
                if (limits.maxEntrySize && sf.size > limits.maxEntrySize) { err = "entry too large"; return false; }
                if (limits.maxTotalBytes && totalExtracted + sf.size > limits.maxTotalBytes) { err = "extraction exceeds limit"; return false; }
                if (!only.empty() && !want.count(sf.name)) continue;
                std::wstring clean;
                if (!safeRelName(sf.name, clean)) continue;
                std::wstring rel = clean;
                std::replace(rel.begin(), rel.end(), L'/', L'\\');
                std::wstring dest = destDir + L"\\" + rel;
                if (isReparsePoint(destDir) || isReparsePoint(dest)) { err = "reparse point detected"; return false; }
                if (fileExists(dest) && !checkOverwrite(dest, overwrite, err)) {
                    if (overwrite == OverwritePolicy::Skip) { pt.addDone(sf.size); pt.check(cf); continue; }
                    return false;
                }
                if (!makeDirs(directoryOf(dest))) { err = "cannot create folder: " + toUtf8(directoryOf(dest)); return false; }
                pt.setFile(sf.name);
                File outFile;
                if (!outFile.openWriteTruncate(dest)) { err = "cannot create: " + toUtf8(dest); return false; }
                if (sf.size) {
                    File sfIn;
                    if (!sfIn.openRead(solidTmp)) { outFile.close(); err = "read failed"; return false; }
                    sfIn.seek(sf.off);
                    std::vector<uint8_t> buf(1u << 20);
                    uint64_t remaining = sf.size;
                    while (remaining > 0) {
                        uint32_t chunk = (uint32_t)std::min<uint64_t>(remaining, buf.size());
                        uint32_t got = 0;
                        if (!sfIn.read(buf.data(), chunk, got) || got != chunk) { sfIn.close(); outFile.close(); err = "read failed"; return false; }
                        if (!outFile.write(buf.data(), got)) { sfIn.close(); outFile.close(); err = "write failed"; return false; }
                        remaining -= got;
                    }
                    sfIn.close();
                }
                outFile.close();
                // verify CRC by reading back from temp file
                File crcIn;
                uint32_t crc = crc32Init();
                if (crcIn.openRead(solidTmp)) {
                    crcIn.seek(sf.off);
                    std::vector<uint8_t> buf(1u << 20);
                    uint64_t remaining = sf.size;
                    while (remaining > 0) {
                        uint32_t chunk = (uint32_t)std::min<uint64_t>(remaining, buf.size());
                        uint32_t got = 0;
                        if (!crcIn.read(buf.data(), chunk, got) || got != chunk) break;
                        crc = crc32Update(crc, buf.data(), got);
                        remaining -= got;
                    }
                    crcIn.close();
                }
                if (crc != sf.crc) { err = "CRC mismatch: " + toUtf8(sf.name); return false; }
                applyMeta(dest, sf.mtime, sf.attrs);
                extracted.push_back(dest);
                totalExtracted += sf.size;
                entriesExtracted++;
                pt.addDone(sf.size);
                pt.check(cf);
            }
            deleteFileForever(solidTmp);
            processedSolid.insert(e.headerStart);
            continue;
        }
        if (e.solid) { /* handled above */ }

        // Limits
        if (limits.maxEntries && entriesExtracted >= limits.maxEntries) { err = "too many entries"; return false; }
        if (limits.maxEntrySize && e.size > limits.maxEntrySize) { err = "entry too large"; return false; }
        if (limits.maxTotalBytes && totalExtracted + e.size > limits.maxTotalBytes) { err = "extraction exceeds limit"; return false; }
        if (limits.maxExpansionRatio > 0 && e.packedSize > 0) {
            double ratio = (double)e.size / (double)e.packedSize;
            if (ratio > limits.maxExpansionRatio) { err = "expansion ratio exceeded"; return false; }
        }

        // Reparse point check on destination and parents
        // (check each path component)
        {
            std::wstring destCheck = destDir;
            // We'll check after building dest; do below.
        }

        if (!only.empty() && std::find(only.begin(), only.end(), e.name) == only.end())
            continue;
        std::wstring clean;
        if (!safeRelName(e.isDir ? e.name + L"/x" : e.name, clean)) continue;
        std::wstring rel = e.isDir ? clean.substr(0, clean.size() - 2) : clean;
        // Windows APIs (especially \\?\ paths) do not normalize '/' — use '\'
        std::replace(rel.begin(), rel.end(), L'/', L'\\');
        std::wstring dest = destDir + L"\\" + rel;
        // Reparse point check
        if (isReparsePoint(destDir) || isReparsePoint(dest)) { err = "reparse point detected"; return false; }
        // Overwrite policy
        if (fileExists(dest) && !checkOverwrite(dest, overwrite, err)) {
            if (overwrite == OverwritePolicy::Skip) { pt.addDone(e.size); pt.check(cf); continue; }
            return false;
        }
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
        totalExtracted += e.size;
        entriesExtracted++;
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
    std::set<uint64_t> processedSolid;
    for (auto& e : info.entries) {
        if (e.isDir) continue;
        if (e.solid) {
            if (processedSolid.count(e.headerStart)) continue;
            // parse + decompress + verify CRCs
            uint8_t h[26]; size_t g0 = 0;
            if (!st.pread(h, 26, e.headerStart, g0) || g0 != 26) { err = "read failed"; return false; }
            uint16_t hsize = rd16(h + 12);
            uint64_t dataLen = rd64(h + 18);
            std::vector<uint8_t> payload(hsize);
            if (hsize && (!st.pread(payload.data(), hsize, e.headerStart + kFrameFixed, g0) || g0 != hsize)) { err = "read failed"; return false; }
            size_t pos = 0;
            if (payload.size() < 6) { processedSolid.insert(e.headerStart); continue; }
            uint8_t codec = payload[pos++];
            uint8_t encFlag = payload[pos++];
            uint32_t fileCount = rd32(payload.data() + pos); pos += 4;
            struct SF { std::wstring name; uint64_t size; uint32_t crc; uint64_t off; };
            std::vector<SF> files;
            uint64_t cum = 0;
            for (uint32_t fi = 0; fi < fileCount; ++fi) {
                if (payload.size() < pos + 8 + 4 + 4 + 8 + 2) break;
                SF f;
                f.size = rd64(payload.data() + pos); pos += 8;
                f.crc = rd32(payload.data() + pos); pos += 4;
                pos += 4; // attrs
                pos += 8; // mtime
                uint16_t nameLen = rd16(payload.data() + pos); pos += 2;
                if (payload.size() < pos + nameLen) break;
                std::string n8(reinterpret_cast<const char*>(payload.data() + pos), nameLen);
                pos += nameLen;
                f.name = fromUtf8(n8);
                f.off = cum;
                cum += f.size;
                files.push_back(f);
            }
            uint64_t dataOff = e.headerStart + kFrameFixed + hsize;
            std::vector<uint8_t> packed;
            if (encFlag) {
                std::string rerr;
                if (!readRegionEncrypted(st, dataOff, dataLen, dataKey,
                                         [&](const uint8_t* p, size_t n) { packed.insert(packed.end(), p, p + n); },
                                         rerr)) { err = rerr; return false; }
            } else {
                packed.resize(size_t(dataLen));
                size_t g = 0;
                if (!st.pread(packed.data(), size_t(dataLen), dataOff, g) || g != dataLen) { err = "read failed"; return false; }
            }
            if (cum > (512ull << 20)) {
                err = "solid block too large for in-memory extraction";
                return false;
            }
            std::vector<uint8_t> solidOut;
            solidOut.reserve(size_t(cum));
            if (codec == 0) solidOut = packed;
            else {
                z_stream zs{};
                if (inflateInit2(&zs, -15) != Z_OK) { err = "zlib init failed"; return false; }
                std::vector<uint8_t> outBuf(1u << 20);
                zs.next_in = packed.data();
                zs.avail_in = uInt(packed.size());
                int rc = Z_OK;
                do {
                    zs.next_out = outBuf.data();
                    zs.avail_out = uint32_t(outBuf.size());
                    rc = inflate(&zs, Z_NO_FLUSH);
                    if (rc != Z_OK && rc != Z_STREAM_END && rc != Z_BUF_ERROR) { inflateEnd(&zs); err = "inflate failed"; return false; }
                    size_t have = outBuf.size() - zs.avail_out;
                    if (have) solidOut.insert(solidOut.end(), outBuf.data(), outBuf.data() + have);
                } while (rc != Z_STREAM_END && zs.avail_out == 0);
                inflateEnd(&zs);
            }
            for (const auto& sf : files) {
                pt.setFile(sf.name);
                uint32_t crc = crc32Update(crc32Init(), solidOut.data() + sf.off, sf.size);
                if (crc != sf.crc) ++badEntries;
                pt.addDone(sf.size);
                pt.check(cf);
            }
            processedSolid.insert(e.headerStart);
            continue;
        }
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
    // Solid archives cannot be patched in place; convert kept solid entries to
    // a non-solid rebuild by extracting them first.
    bool hasSolid = false;
    for (uint32_t idx : keepIdx)
        if (info.entries[idx].solid) { hasSolid = true; break; }
    if (hasSolid) {
        std::wstring solidTemp = directoryOf(path) + L"\\~solidrebuild";
        makeDirs(solidTemp);
        std::vector<std::wstring> solidInputs;
        std::vector<uint32_t> newKeepIdx;
        std::vector<std::wstring> newKeepNames;
        for (uint32_t idx : keepIdx) {
            if (info.entries[idx].solid) {
                std::vector<std::wstring> out;
                std::string ex;
                if (wsar::extract(path, solidTemp, password, {info.entries[idx].name}, nullptr, cf, out, ex))
                    for (auto& f : out) solidInputs.push_back(f);
            } else {
                newKeepIdx.push_back(idx);
                newKeepNames.push_back(info.entries[idx].name);
            }
        }
        keepIdx = newKeepIdx;
        std::vector<ScanItem> solidScanned = scanInputs(solidInputs);
        newScanned.insert(newScanned.end(), solidScanned.begin(), solidScanned.end());
        keptBytes = 0;
        for (uint32_t idx : keepIdx)
            if (!info.entries[idx].isDir) keptBytes += info.entries[idx].size;
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
