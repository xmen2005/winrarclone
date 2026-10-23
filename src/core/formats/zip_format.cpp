// zip_format.cpp — native ZIP container (store/deflate, Zip64, split volumes)
#include "core/formats/zip_format.h"

#include "core/crc32.h"
#include "core/progress_tracker.h"
#include "core/thread_pool.h"
#include "core/volumes.h"
#include "utils/file_system.h"

#include <zlib.h>

#include <algorithm>
#include <chrono>
#include <cstdio>

namespace wrc {
namespace zipfmt {

// ------------------------------------------------------------------- helpers
static void dosTime(uint64_t unixSec, uint16_t& dtime, uint16_t& ddate) {
    time_t t = time_t(unixSec ? unixSec : 0);
    struct tm tmv {};
    if (gmtime_s(&tmv, &t) != 0) {
        dtime = 0;
        ddate = 0x21;  // 1980-01-01
        return;
    }
    int y = tmv.tm_year + 1900;
    if (y < 1980) y = 1980;
    ddate = uint16_t(((y - 1980) << 9) | ((tmv.tm_mon + 1) << 5) | tmv.tm_mday);
    dtime = uint16_t((tmv.tm_hour << 11) | (tmv.tm_min << 5) | (tmv.tm_sec / 2));
}

static uint64_t unixFromDos(uint16_t ddate, uint16_t dtime) {
    struct tm tmv {};
    tmv.tm_year = ((ddate >> 9) & 0x7F) + 80;
    tmv.tm_mon = ((ddate >> 5) & 0x0F) - 1;
    tmv.tm_mday = ddate & 0x1F;
    tmv.tm_hour = (dtime >> 11) & 0x1F;
    tmv.tm_min = (dtime >> 5) & 0x3F;
    tmv.tm_sec = (dtime & 0x1F) * 2;
    time_t t = _mkgmtime(&tmv);
    return t > 0 ? uint64_t(t) : 0;
}

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

// --------------------------------------------------------------- ZipWriter
namespace {

struct CentralRec {
    std::string name;
    uint16_t method = 0;
    uint16_t flags = 0;
    uint16_t dtime = 0, ddate = 0;
    uint32_t crc = 0;
    uint64_t uncomp = 0, comp = 0;
    uint32_t attrs = 0;
    bool isDir = false;
    uint64_t localOff = 0;
};

class ZipWriter {
public:
    bool open(const std::wstring& path) { return f_.openWriteTruncate(path); }

    // dataFile: file containing the PACKED bytes (null for dirs).
    bool addEntry(const std::wstring& name, uint64_t uncomp, uint32_t crc, uint16_t method,
                  uint32_t attrs, uint64_t mtime, bool isDir, const std::wstring* dataFile,
                  ProgressTracker* pt) {
        CentralRec r;
        r.name = toUtf8(name);
        r.method = method;
        r.flags = 0x0800;  // UTF-8 names
        dosTime(mtime, r.dtime, r.ddate);
        r.crc = crc;
        r.uncomp = uncomp;
        r.comp = isDir ? 0 : (dataFile ? fileSizeOf(*dataFile) : uncomp);
        r.attrs = attrs ? (attrs & 0xFF) : (isDir ? 0x10 : 0x20);
        r.isDir = isDir;
        r.localOff = f_.tell();
        if (r.uncomp >= 0xFFFFFFFFull || r.comp >= 0xFFFFFFFFull ||
            r.localOff >= 0xFFFFFFFFull)
            zip64_ = true;

        std::vector<uint8_t> h;
        put32(h, 0x04034b50);
        put16(h, r.localOff >= 0xFFFFFFFFull ? 45 : 20);  // version needed
        put16(h, r.flags);
        put16(h, r.method);
        put16(h, r.dtime);
        put16(h, r.ddate);
        put32(h, r.crc);
        put32(h, r.comp >= 0xFFFFFFFFull ? 0xFFFFFFFFu : uint32_t(r.comp));
        put32(h, r.uncomp >= 0xFFFFFFFFull ? 0xFFFFFFFFu : uint32_t(r.uncomp));
        put16(h, uint16_t(r.name.size()));
        std::vector<uint8_t> extra;
        bool e64 = r.uncomp >= 0xFFFFFFFFull || r.comp >= 0xFFFFFFFFull;
        if (e64) {
            put16(extra, 0x0001);
            put16(extra, 16);
            put64(extra, r.uncomp);
            put64(extra, r.comp);
        }
        put16(h, uint16_t(extra.size()));
        h.insert(h.end(), r.name.begin(), r.name.end());
        h.insert(h.end(), extra.begin(), extra.end());
        if (!f_.write(h.data(), uint32_t(h.size()))) return false;

        if (dataFile) {
            File src;
            if (!src.openRead(*dataFile)) return false;
            uint64_t sz = src.size(), done = 0;
            std::vector<uint8_t> buf(1u << 20);
            while (done < sz) {
                uint64_t want = std::min<uint64_t>(buf.size(), sz - done);
                uint32_t got = 0;
                if (!src.read(buf.data(), uint32_t(want), got) || got != want) return false;
                if (!f_.write(buf.data(), got)) return false;
                done += got;
                if (pt) pt->check(nullptr);
            }
        }
        recs_.push_back(std::move(r));
        return true;
    }

    // Append RAW packed data already read elsewhere (rebuild path).
    bool addRawEntry(const ZipCentral::Rec& rec, const std::wstring& srcZip) {
        std::wstring name = rec.name;
        uint64_t comp = rec.packedSize;
        uint64_t off = f_.tell();
        std::vector<uint8_t> h;
        put32(h, 0x04034b50);
        put16(h, off >= 0xFFFFFFFFull ? 45 : 20);
        put16(h, 0x0800);
        put16(h, rec.methodZip);
        uint16_t dt = 0, dd = 0;
        dosTime(rec.mtime, dt, dd);
        put16(h, dt);
        put16(h, dd);
        put32(h, rec.crc32);
        put32(h, comp >= 0xFFFFFFFFull ? 0xFFFFFFFFu : uint32_t(comp));
        put32(h, rec.size >= 0xFFFFFFFFull ? 0xFFFFFFFFu : uint32_t(rec.size));
        std::vector<uint8_t> extra;
        if (comp >= 0xFFFFFFFFull || rec.size >= 0xFFFFFFFFull) {
            put16(extra, 0x0001);
            put16(extra, 16);
            put64(extra, rec.size);
            put64(extra, comp);
        }
        put16(h, uint16_t(extra.size()));
        std::string n8 = toUtf8(name);
        put16(h, uint16_t(n8.size()));
        h.insert(h.end(), n8.begin(), n8.end());
        h.insert(h.end(), extra.begin(), extra.end());
        if (!f_.write(h.data(), uint32_t(h.size()))) return false;

        File src;
        if (!src.openRead(srcZip)) return false;
        uint64_t done = 0;
        std::vector<uint8_t> buf(1u << 20);
        while (done < comp) {
            uint64_t want = std::min<uint64_t>(buf.size(), comp - done);
            uint32_t got = 0;
            if (!src.pread(buf.data(), uint32_t(want), rec.dataOff + done, got) ||
                got != want)
                return false;
            if (!f_.write(buf.data(), got)) return false;
            done += got;
        }

        CentralRec r;
        r.name = n8;
        r.method = rec.methodZip;
        r.flags = 0x0800;
        dosTime(rec.mtime, r.dtime, r.ddate);
        r.crc = rec.crc32;
        r.uncomp = rec.size;
        r.comp = comp;
        r.attrs = rec.attrs ? (rec.attrs & 0xFF) : (rec.isDir ? 0x10 : 0x20);
        r.isDir = rec.isDir;
        r.localOff = off;
        recs_.push_back(std::move(r));
        return true;
    }

    bool finish() {
        uint64_t cdOff = f_.tell();
        uint64_t cdSize = 0;
        std::vector<uint8_t> cd;
        for (auto& r : recs_) {
            bool e64 = r.uncomp >= 0xFFFFFFFFull || r.comp >= 0xFFFFFFFFull ||
                       r.localOff >= 0xFFFFFFFFull;
            put32(cd, 0x02014b50);
            put16(cd, (3 << 8) | 45);   // made by: unix, zip64 capable
            put16(cd, e64 ? 45 : 20);   // needed
            put16(cd, r.flags);
            put16(cd, r.method);
            put16(cd, r.dtime);
            put16(cd, r.ddate);
            put32(cd, r.crc);
            put32(cd, r.comp >= 0xFFFFFFFFull ? 0xFFFFFFFFu : uint32_t(r.comp));
            put32(cd, r.uncomp >= 0xFFFFFFFFull ? 0xFFFFFFFFu : uint32_t(r.uncomp));
            put16(cd, uint16_t(r.name.size()));
            std::vector<uint8_t> extra;
            if (e64) {
                put16(extra, 0x0001);
                put16(extra, 0);
                size_t lenPos = extra.size() - 2;
                if (r.uncomp >= 0xFFFFFFFFull) put64(extra, r.uncomp);
                if (r.comp >= 0xFFFFFFFFull) put64(extra, r.comp);
                if (r.localOff >= 0xFFFFFFFFull) put64(extra, r.localOff);
                extra[lenPos] = uint8_t(extra.size() - 4);
            }
            put16(cd, uint16_t(extra.size()));
            put16(cd, 0);  // comment
            put16(cd, 0);  // disk
            put16(cd, 0);  // internal attrs
            put32(cd, r.isDir ? (r.attrs | 0x10) : r.attrs);
            put32(cd, r.localOff >= 0xFFFFFFFFull ? 0xFFFFFFFFu : uint32_t(r.localOff));
            cd.insert(cd.end(), r.name.begin(), r.name.end());
            cd.insert(cd.end(), extra.begin(), extra.end());
        }
        cdSize = cd.size();
        if (!f_.write(cd.data(), cd.size() ? uint32_t(cd.size()) : 0u)) return false;

        uint64_t cdOffEnd = cdOff + cdSize;
        uint16_t n = uint16_t(std::min<uint64_t>(recs_.size(), 0xFFFF));
        bool z64 = zip64_ || recs_.size() >= 0xFFFF || cdOffEnd >= 0xFFFFFFFFull ||
                   cdSize >= 0xFFFFFFFFull;
        if (z64) {
            std::vector<uint8_t> z;
            put32(z, 0x06064b50);
            put64(z, 44);
            put16(z, 45);
            put16(z, 45);
            put32(z, 0);
            put32(z, 0);
            put64(z, recs_.size());
            put64(z, recs_.size());
            put64(z, cdSize);
            put64(z, cdOff);
            put32(z, 0);
            if (!f_.write(z.data(), uint32_t(z.size()))) return false;
            uint64_t z64Off = cdOffEnd;
            std::vector<uint8_t> loc;
            put32(loc, 0x07064b50);
            put32(loc, 0);
            put64(loc, z64Off);
            put32(loc, 1);
            if (!f_.write(loc.data(), uint32_t(loc.size()))) return false;
            n = 0xFFFF;
            cdOff = 0xFFFFFFFF;
            cdSize = 0xFFFFFFFF;
        }
        std::vector<uint8_t> e;
        put32(e, 0x06054b50);
        put16(e, 0);
        put16(e, 0);
        put16(e, n);
        put16(e, n);
        put32(e, uint32_t(cdSize));
        put32(e, uint32_t(cdOff));
        put16(e, 0);
        if (!f_.write(e.data(), uint32_t(e.size()))) return false;
        f_.close();
        return true;
    }

private:
    File f_;
    std::vector<CentralRec> recs_;
    bool zip64_ = false;
};

// ------------------------------------------------------- parallel first pass
struct TempResult {
    std::wstring tempPath;
    uint64_t compSize = 0;
    uint32_t crc = 0;
    uint16_t method = 0;  // 0 store, 8 deflate
};

// Compress one file into a temp file (streaming deflate), verify CRC.
TempResult compressOne(const ScanItem& it, int level, const std::wstring& tempDir,
                       int idx, ProgressTracker& pt, ControlFn cf) {
    TempResult res;
    res.tempPath = tempDir + L"\\~wrc" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                   std::to_wstring(idx) + L".tmp";
    File src;
    if (!src.openRead(it.fullPath)) throw WrcError("cannot open input: " + toUtf8(it.fullPath));
    uint64_t uncomp = it.size;
    uint32_t crc = crc32Init();
    z_stream zs{};
    if (deflateInit2(&zs, level, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) != Z_OK)
        throw WrcError("zlib init failed");
    File dst;
    if (!dst.openWriteTruncate(res.tempPath)) {
        deflateEnd(&zs);
        throw WrcError("cannot create temp file");
    }
    std::vector<uint8_t> in(1u << 20), out(1u << 20);
    uint64_t done = 0;
    try {
        while (done < uncomp) {
            if (cf && !cf()) throw CancelledError();
            uint64_t want = std::min<uint64_t>(in.size(), uncomp - done);
            uint32_t got = 0;
            if (!src.read(in.data(), uint32_t(want), got) || got == 0) {
                if (got == 0 && want > 0) break;  // file shrank
            }
            crc = crc32Update(crc, in.data(), got);
            zs.next_in = in.data();
            zs.avail_in = got;
            do {
                zs.next_out = out.data();
                zs.avail_out = uint32_t(out.size());
                int rc = deflate(&zs, Z_NO_FLUSH);
                if (rc != Z_OK && rc != Z_BUF_ERROR) throw WrcError("deflate failed");
                size_t have = out.size() - zs.avail_out;
                if (have) {
                    if (cf && !cf()) throw CancelledError();
                    if (!dst.write(out.data(), uint32_t(have))) throw WrcError("write failed");
                    res.compSize += have;
                }
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
            if (have) {
                if (!dst.write(out.data(), uint32_t(have))) throw WrcError("write failed");
                res.compSize += have;
            }
            if (rc == Z_STREAM_END) break;
            if (rc != Z_OK && rc != Z_BUF_ERROR) throw WrcError("deflate finish failed");
            if (cf && !cf()) throw CancelledError();
        }
    } catch (...) {
        deflateEnd(&zs);
        throw;
    }
    deflateEnd(&zs);
    res.crc = crc;
    // store beats tiny deflate gains
    if (level == 0 || res.compSize >= uncomp) {
        res.method = 0;
        res.compSize = uncomp;
    } else {
        res.method = 8;
    }
    return res;
}

}  // namespace

// -------------------------------------------------------------------- build
bool build(const std::vector<ScanItem>& items, const std::wstring& outPath, int level,
           int threads, uint64_t volumeSize, const ProgressFn& pf, ControlFn cf,
           uint64_t& totalIn, uint64_t& totalOut) {
    totalIn = 0;
    totalOut = 0;
    uint64_t total = scanTotalSize(items);
    ProgressTracker pt(Progress::Phase::Compress, total, pf);
    pt.check(cf);

    std::wstring tempDir = directoryOf(outPath);
    std::vector<std::wstring> tempFiles(items.size());
    std::vector<TempResult> results(items.size());

    unsigned hw = threads > 0 ? unsigned(threads) : std::thread::hardware_concurrency();
    if (!hw) hw = 4;
    try {
        std::vector<std::future<void>> futs;
        {
            ThreadPool pool(hw);
            for (size_t i = 0; i < items.size(); ++i) {
                if (items[i].isDir) continue;
                futs.push_back(pool.submit([&items, &results, &pt, cf, level, tempDir, i] {
                    results[i] = compressOne(items[i], level, tempDir, int(i), pt, cf);
                }));
            }
            pool.waitIdle();
        }
        for (auto& f : futs) f.get();  // rethrow worker exceptions
    } catch (...) {
        for (auto& t : results)
            if (!t.tempPath.empty()) deleteFileForever(t.tempPath);
        throw;
    }

    // second pass: assemble container
    ZipWriter w;
    if (!w.open(outPath)) throw WrcError("cannot create archive: " + toUtf8(outPath));
    try {
        for (size_t i = 0; i < items.size(); ++i) {
            const auto& it = items[i];
            if (it.isDir) {
                if (!w.addEntry(it.relPath + L"/", 0, 0, 0, it.attrs, it.mtime, true,
                                nullptr, &pt))
                    throw WrcError("zip write failed");
            } else {
                const TempResult& r = results[i];
                const std::wstring* data = r.method == 8 ? &r.tempPath : &it.fullPath;
                pt.setFile(fileNameOf(it.fullPath));
                if (!w.addEntry(it.relPath, it.size, r.crc, r.method, it.attrs, it.mtime,
                                false, data, &pt))
                    throw WrcError("zip write failed");
                pt.addDone(0);  // sizes already added during pass 1
                if (cf && !cf()) throw CancelledError();
                if (!r.tempPath.empty() && r.method == 8) deleteFileForever(r.tempPath);
            }
        }
        if (!w.finish()) throw WrcError("zip finalize failed");
    } catch (...) {
        for (auto& r : results)
            if (!r.tempPath.empty()) deleteFileForever(r.tempPath);
        throw;
    }

    for (auto& r : results)
        if (!r.tempPath.empty()) deleteFileForever(r.tempPath);

    totalIn = total;
    totalOut = fileSizeOf(outPath);
    if (volumeSize > 0 && totalOut > volumeSize) {
        std::vector<std::wstring> parts;
        if (!splitIntoVolumes(outPath, volumeSize, parts))
            throw WrcError("volume split failed");
    }
    return true;
}

// -------------------------------------------------------------- readCentral
bool readCentral(const std::wstring& path, ZipCentral& out) {
    out = ZipCentral{};
    File f;
    if (!f.openRead(path)) {
        out.err = "cannot open file";
        return false;
    }
    uint64_t sz = f.size();
    if (sz < 22) {
        out.err = "not a zip archive";
        return false;
    }
    // locate EOCD
    uint64_t scanStart = sz > (65557ull) ? sz - 65557ull : 0;
    uint64_t scanLen = sz - scanStart;
    std::vector<uint8_t> tail(static_cast<size_t>(scanLen));
    uint32_t got = 0;
    if (!f.pread(tail.data(), uint32_t(scanLen), scanStart, got)) {
        out.err = "read failed";
        return false;
    }
    int64_t eocdPos = -1;
    for (int64_t i = int64_t(scanLen) - 22; i >= 0; --i) {
        if (tail[size_t(i)] == 0x50 && tail[size_t(i) + 1] == 0x4B &&
            tail[size_t(i) + 2] == 0x05 && tail[size_t(i) + 3] == 0x06) {
            eocdPos = scanStart + i;
            break;
        }
    }
    if (eocdPos < 0) {
        out.err = "end of central directory not found";
        return false;
    }
    auto rd16 = [&](const uint8_t* p) { return uint16_t(p[0] | (p[1] << 8)); };
    auto rd32 = [&](const uint8_t* p) {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
               (uint32_t(p[3]) << 24);
    };
    auto rd64 = [&](const uint8_t* p) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= uint64_t(p[i]) << (8 * i);
        return v;
    };
    const uint8_t* e = tail.data() + (eocdPos - scanStart);
    uint64_t count = rd32(e + 10);
    uint64_t cdSize = rd32(e + 12);
    uint64_t cdOff = rd32(e + 16);
    if (count == 0xFFFF || cdSize == 0xFFFFFFFFull || cdOff == 0xFFFFFFFFull) {
        // zip64 EOCD locator sits 20 bytes before EOCD
        if (eocdPos >= 20) {
            uint8_t loc[20];
            uint32_t g = 0;
            if (f.pread(loc, 20, eocdPos - 20, g) && rd32(loc) == 0x07064b50) {
                uint64_t z64Off = rd64(loc + 8);
                uint8_t z[56];
                uint32_t g2 = 0;
                if (f.pread(z, 56, z64Off, g2) && rd32(z) == 0x06064b50) {
                    count = rd64(z + 32);
                    cdSize = rd64(z + 40);
                    cdOff = rd64(z + 48);
                }
            }
        }
    }
    std::vector<uint8_t> cd(size_t(cdSize ? cdSize : 1));
    uint32_t g = 0;
    if (cdSize && (!f.pread(cd.data(), uint32_t(cdSize), cdOff, g) || g != cdSize)) {
        out.err = "cannot read central directory";
        return false;
    }
    uint64_t p = 0;
    for (uint64_t i = 0; i < count && p + 46 <= cdSize; ++i) {
        const uint8_t* r = cd.data() + p;
        if (rd32(r) != 0x02014b50) {
            out.err = "corrupt central directory";
            return false;
        }
        ZipCentral::Rec rec;
        rec.methodZip = rd16(r + 10);
        rec.method = rec.methodZip == 0 ? 0 : 1;
        rec.crc32 = rd32(r + 16);
        uint32_t csize = rd32(r + 20);
        uint32_t usize = rd32(r + 24);
        uint16_t nameLen = rd16(r + 28);
        uint16_t extraLen = rd16(r + 30);
        uint16_t commLen = rd16(r + 32);
        uint32_t extAttr = rd32(r + 38);
        uint32_t localOff = rd32(r + 42);
        std::string name8(reinterpret_cast<const char*>(r + 46), nameLen);
        rec.name = fromUtf8(name8);
        rec.attrs = extAttr & 0xFF;
        rec.isDir = !rec.name.empty() && rec.name.back() == L'/';
        if (rec.isDir) rec.name.pop_back();
        // zip64 extra
        uint64_t eoff = p + 46 + nameLen;
        uint64_t eend = eoff + extraLen;
        rec.zip64 = false;
        while (eoff + 4 <= eend) {
            uint16_t id = rd16(&cd[size_t(eoff)]);
            uint16_t ln = rd16(&cd[size_t(eoff) + 2]);
            if (id == 0x0001) {
                const uint8_t* x = &cd[size_t(eoff) + 4];
                size_t used = 0;
                if (usize == 0xFFFFFFFFu && used + 8 <= ln) {
                    rec.size = rd64(x + used);
                    used += 8;
                }
                if (csize == 0xFFFFFFFFu && used + 8 <= ln) {
                    rec.packedSize = rd64(x + used);
                    used += 8;
                }
                if (localOff == 0xFFFFFFFFu && used + 8 <= ln) rec.dataOff = rd64(x + used);
                rec.zip64 = true;
            }
            eoff += 4 + ln;
        }
        if (!rec.zip64) {
            rec.size = usize;
            rec.packedSize = csize;
        }
        rec.mtime = unixFromDos(rd16(r + 12), rd16(r + 14));
        // data offset: parse local header sizes
        uint8_t lh[30];
        uint32_t g3 = 0;
        uint64_t loff = rec.zip64 && localOff == 0xFFFFFFFFu && rec.dataOff ? rec.dataOff
                                                                            : localOff;
        if (f.pread(lh, 30, loff, g3) && rd32(lh) == 0x04034b50) {
            uint16_t lnameLen = rd16(lh + 26);
            uint16_t lextraLen = rd16(lh + 28);
            rec.dataOff = loff + 30 + lnameLen + lextraLen;
        }
        out.recs.push_back(std::move(rec));
        p += 46 + nameLen + extraLen + commLen;
    }
    out.ok = true;
    return true;
}

// ------------------------------------------------------------------ rebuild
bool rebuild(const std::wstring& srcZip, const std::vector<uint32_t>& keepIndices,
             const std::vector<ScanItem>& newItems, const std::wstring& dstZip, int level,
             int threads, const ProgressFn& pf, ControlFn cf) {
    ZipCentral central;
    if (!readCentral(srcZip, central)) throw WrcError(central.err);

    std::vector<ScanItem> allNew = newItems;
    uint64_t total = 0;
    for (auto idx : keepIndices) total += central.recs[idx].size;
    total += scanTotalSize(allNew);
    ProgressTracker pt(Progress::Phase::Compress, total, pf);
    pt.check(cf);

    // compress the new items via build() into a temp zip? — reuse parallel pass:
    // simplest correct approach: write new items to a temp zip, then raw-copy.
    std::wstring tempZip = dstZip + L"~new.tmp";
    if (!allNew.empty()) {
        ArchiveOptions o;
        std::vector<ScanItem> v = allNew;
        uint64_t ti = 0, to = 0;
        build(v, tempZip, level, threads, 0, pf, cf, ti, to);
    }
    ZipCentral newCentral;
    if (!allNew.empty()) readCentral(tempZip, newCentral);

    ZipWriter w;
    if (!w.open(dstZip)) throw WrcError("cannot create archive");
    for (uint32_t idx : keepIndices) {
        if (cf && !cf()) throw CancelledError();
        if (!w.addRawEntry(central.recs[idx], srcZip)) throw WrcError("zip copy failed");
        pt.addDone(central.recs[idx].size);
        pt.setFile(central.recs[idx].name);
        pt.check(cf);
    }
    if (!newCentral.recs.empty()) {
        File src2;
        if (!src2.openRead(tempZip)) throw WrcError("temp read failed");
        for (auto& rec : newCentral.recs) {
            ZipCentral::Rec r = rec;
            if (!w.addRawEntry(r, tempZip)) throw WrcError("zip copy failed");
            pt.addDone(rec.size);
            pt.check(cf);
        }
    }
    if (!w.finish()) throw WrcError("zip finalize failed");
    if (fileExists(tempZip)) deleteFileForever(tempZip);
    return true;
}

}  // namespace zipfmt
}  // namespace wrc
