// sevenzip_format.cpp — native 7z container writer
// Architecture: ONE FOLDER PER FILE (each folder = 1 coder over that file's
// own packed stream). This keeps per-file compressed streams independent and
// is fully compatible with 7-Zip / libarchive / py7zr.
// Codecs: Copy (0x00) for Store, Deflate (0x040108) otherwise.
#include "core/formats/sevenzip_format.h"

#include "core/crc32.h"
#include "core/progress_tracker.h"
#include "core/thread_pool.h"
#include "core/volumes.h"
#include "utils/file_system.h"

#include <zlib.h>

#include <algorithm>

namespace wrc {
namespace sevenzip {

enum : uint8_t {
    kEnd = 0x00,
    kHeader = 0x01,
    kMainStreamsInfo = 0x04,
    kFilesInfo = 0x05,
    kPackInfo = 0x06,
    kUnPackInfo = 0x07,
    kSubStreamsInfo = 0x08,
    kSize = 0x09,
    kCRC = 0x0A,
    kFolder = 0x0B,
    kCodersUnPackSize = 0x0C,
    kNumUnPackStream = 0x0D,
    kEmptyStream = 0x0E,
    kEmptyFile = 0x0F,
    kName = 0x11,
    kMTime = 0x14,
    kWinAttributes = 0x15,
};

// 7z variable-length number (little-endian base 128 with prefix bits)
static void putNum(std::vector<uint8_t>& v, uint64_t value) {
    int n = 1;
    while (n < 8 && value >= (1ull << (7 * n))) ++n;
    if (n == 8 && value >= (1ull << 56)) {
        v.push_back(0xFF);
        for (int j = 0; j < 8; ++j) v.push_back(uint8_t(value >> (8 * j)));
        return;
    }
    uint8_t first = 0;
    for (int i = 0; i < n - 1; ++i) first |= uint8_t(0x80 >> i);
    first |= uint8_t((value >> (8 * (n - 1))) & (0xFF >> n));
    v.push_back(first);
    for (int j = n - 2; j >= 0; --j) v.push_back(uint8_t(value >> (8 * j)));
}

static void putU64(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(uint8_t(x >> (8 * i)));
}
static void putU32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(uint8_t(x >> (8 * i)));
}

static uint64_t unixToFileTime100(uint64_t unixSec) {
    return unixSec * 10000000ull + 116444736000000000ull;
}

namespace {

struct Packed {
    std::wstring src;  // data source (temp file for deflate, original for copy)
    uint64_t packedSize = 0;
    uint32_t crc = 0;
    bool isTemp = false;
};

Packed deflateToTemp(const ScanItem& it, int level, const std::wstring& tempDir, int idx,
                     ProgressTracker& pt, ControlFn cf) {
    Packed res;
    res.isTemp = true;
    res.src = tempDir + L"\\~7z" + std::to_wstring(GetCurrentProcessId()) + L"_" +
              std::to_wstring(idx) + L".tmp";
    File src;
    if (!src.openRead(it.fullPath)) throw WrcError("cannot open: " + toUtf8(it.fullPath));
    File dst;
    if (!dst.openWriteTruncate(res.src)) throw WrcError("temp file failed");
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
    return res;
}

Packed crcOnly(const ScanItem& it, ProgressTracker& pt, ControlFn cf) {
    Packed res;
    res.src = it.fullPath;
    res.packedSize = it.size;
    File f;
    if (!f.openRead(it.fullPath)) throw WrcError("cannot open: " + toUtf8(it.fullPath));
    std::vector<uint8_t> buf(1u << 20);
    uint32_t crc = crc32Init();
    uint64_t done = 0;
    while (done < it.size) {
        if (cf && !cf()) throw CancelledError();
        uint64_t want = std::min<uint64_t>(buf.size(), it.size - done);
        uint32_t got = 0;
        if (!f.read(buf.data(), uint32_t(want), got) || got == 0) break;
        crc = crc32Update(crc, buf.data(), got);
        done += got;
        pt.addDone(got);
        pt.setFile(fileNameOf(it.fullPath));
        pt.check(cf);
    }
    res.crc = crc;
    return res;
}

}  // namespace

bool build(const std::vector<ScanItem>& items, const std::wstring& outPath, Method method,
           int threads, uint64_t volumeSize, const ProgressFn& pf, ControlFn cf,
           uint64_t& totalIn, uint64_t& totalOut) {
    totalIn = 0;
    totalOut = 0;
    uint64_t total = scanTotalSize(items);
    ProgressTracker pt(Progress::Phase::Compress, total, pf);
    pt.check(cf);

    const bool useCopy = method == Method::Store;
    const int level = deflateLevel(method);

    // pass 1 — pack every non-empty file (one packed stream per file)
    std::vector<Packed> packed(items.size());
    std::wstring tempDir = directoryOf(outPath);
    try {
        unsigned hw = threads > 0 ? unsigned(threads) : std::thread::hardware_concurrency();
        if (!hw) hw = 4;
        std::vector<std::future<void>> futs;
        {
            ThreadPool pool(hw);
            for (size_t i = 0; i < items.size(); ++i) {
                if (items[i].isDir || items[i].size == 0) continue;
                if (useCopy) {
                    futs.push_back(pool.submit([&items, &packed, &pt, cf, i] {
                        packed[i] = crcOnly(items[i], pt, cf);
                    }));
                } else {
                    futs.push_back(pool.submit([&items, &packed, &pt, cf, tempDir, i, level] {
                        packed[i] = deflateToTemp(items[i], level, tempDir, int(i), pt, cf);
                    }));
                }
            }
            pool.waitIdle();
        }
        for (auto& f : futs) f.get();
    } catch (...) {
        for (size_t i = 0; i < items.size(); ++i)
            if (packed[i].isTemp) deleteFileForever(packed[i].src);
        throw;
    }

    uint64_t totalPacked = 0, totalUnpacked = 0, nonEmpty = 0;
    for (size_t i = 0; i < items.size(); ++i) {
        if (items[i].isDir || items[i].size == 0) continue;
        totalPacked += packed[i].packedSize;
        totalUnpacked += items[i].size;
        ++nonEmpty;
    }

    // pass 2 — write container
    File f;
    if (!f.openWriteTruncate(outPath))
        throw WrcError("cannot create archive: " + toUtf8(outPath));
    try {
        std::vector<uint8_t> sig(32, 0);
        sig[0] = '7';
        sig[1] = 'z';
        sig[2] = 0xBC;
        sig[3] = 0xAF;
        sig[4] = 0x27;
        sig[5] = 0x1C;
        sig[7] = 4;  // version minor
        if (!f.write(sig.data(), 32)) throw WrcError("write failed");

        // packed streams (folder order = file order)
        for (size_t i = 0; i < items.size(); ++i) {
            if (items[i].isDir || items[i].size == 0) continue;
            if (cf && !cf()) throw CancelledError();
            File src;
            if (!src.openRead(packed[i].src)) throw WrcError("pack read failed");
            uint64_t sz = src.size(), done = 0;
            std::vector<uint8_t> buf(1u << 20);
            while (done < sz) {
                uint64_t want = std::min<uint64_t>(buf.size(), sz - done);
                uint32_t got = 0;
                if (!src.read(buf.data(), uint32_t(want), got) || got == 0)
                    throw WrcError("pack read failed");
                if (!f.write(buf.data(), got)) throw WrcError("write failed");
                done += got;
            }
        }

        // ---- next header blob
        std::vector<uint8_t> h;
        h.push_back(kHeader);
        if (!items.empty()) {
            h.push_back(kMainStreamsInfo);
            if (nonEmpty) {
                // PackInfo
                h.push_back(kPackInfo);
                putNum(h, 0);  // packPos — data starts right after signature header
                putNum(h, nonEmpty);
                h.push_back(kSize);
                for (size_t i = 0; i < items.size(); ++i) {
                    if (items[i].isDir || items[i].size == 0) continue;
                    putNum(h, packed[i].packedSize);
                }
                h.push_back(kEnd);
                // UnPackInfo — one folder per file
                h.push_back(kUnPackInfo);
                h.push_back(kFolder);
                putNum(h, nonEmpty);
                h.push_back(0);  // external
                for (size_t k = 0; k < nonEmpty; ++k) {
                    putNum(h, 1);  // numCoders
                    if (useCopy) {
                        h.push_back(0x01);  // flags: idSize = 1
                        h.push_back(0x00);  // Copy
                    } else {
                        h.push_back(0x03);  // flags: idSize = 3
                        h.push_back(0x04);
                        h.push_back(0x01);
                        h.push_back(0x08);  // Deflate (0x040108)
                    }
                }
                h.push_back(kCodersUnPackSize);
                for (size_t i = 0; i < items.size(); ++i) {
                    if (items[i].isDir || items[i].size == 0) continue;
                    putNum(h, items[i].size);
                }
                h.push_back(kEnd);  // unpackinfo
                // SubStreamsInfo — every folder holds exactly 1 substream, so
                // sizes come from the folders; only the CRC list is needed.
                h.push_back(kSubStreamsInfo);
                h.push_back(kCRC);
                h.push_back(1);  // all defined
                for (size_t i = 0; i < items.size(); ++i) {
                    if (items[i].isDir || items[i].size == 0) continue;
                    putU32(h, packed[i].crc);
                }
                h.push_back(kEnd);  // substreams
                h.push_back(kEnd);  // streams info
            }
        }
        // FilesInfo
        if (!items.empty()) {
            h.push_back(kFilesInfo);
            putNum(h, items.size());
            std::vector<uint8_t> emptyBits((items.size() + 7) / 8, 0);
            size_t emptyCount = 0, emptyFileCount = 0;
            for (size_t i = 0; i < items.size(); ++i) {
                if (items[i].isDir || items[i].size == 0) {
                    emptyBits[i / 8] |= uint8_t(0x80 >> (i % 8));  // MSB-first bits
                    ++emptyCount;
                    if (!items[i].isDir) ++emptyFileCount;
                }
            }
            if (emptyCount) {
                h.push_back(kEmptyStream);
                putNum(h, emptyBits.size());
                h.insert(h.end(), emptyBits.begin(), emptyBits.end());
                if (emptyFileCount) {
                    std::vector<uint8_t> fileBits((emptyCount + 7) / 8, 0);
                    size_t k = 0;
                    for (size_t i = 0; i < items.size(); ++i) {
                        if (items[i].isDir || items[i].size > 0) continue;
                        fileBits[k / 8] |= uint8_t(0x80 >> (k % 8));
                        ++k;
                    }
                    h.push_back(kEmptyFile);
                    putNum(h, fileBits.size());
                    h.insert(h.end(), fileBits.begin(), fileBits.end());
                }
            }
            std::vector<uint8_t> names;
            for (auto& it : items) {
                for (wchar_t c : it.relPath) {
                    names.push_back(uint8_t(c));
                    names.push_back(uint8_t(c >> 8));
                }
                names.push_back(0);
                names.push_back(0);
            }
            h.push_back(kName);
            putNum(h, names.size() + 1);  // + external byte
            h.push_back(0);               // external = 0 (names inline)
            h.insert(h.end(), names.begin(), names.end());
            h.push_back(kMTime);
            putNum(h, 2 + items.size() * 8);
            h.push_back(1);  // all defined
            h.push_back(0);  // external
            for (auto& it : items) putU64(h, unixToFileTime100(it.mtime));
            h.push_back(kWinAttributes);
            putNum(h, 2 + items.size() * 4);
            h.push_back(1);
            h.push_back(0);
            for (auto& it : items) {
                uint32_t a = it.attrs & 0xFF;
                if (it.isDir)
                    a |= 0x10;
                else if (!a)
                    a = 0x20;
                putU32(h, a);
            }
            h.push_back(kEnd);  // files info
        }
        h.push_back(kEnd);  // header

        uint32_t nextHeaderCRC = crc32Update(crc32Init(), h.data(), h.size());
        if (!f.write(h.data(), uint32_t(h.size()))) throw WrcError("write failed");
        std::vector<uint8_t> start;
        for (int i = 0; i < 8; ++i) start.push_back(uint8_t(totalPacked >> (8 * i)));
        for (int i = 0; i < 8; ++i) start.push_back(uint8_t(h.size() >> (8 * i)));
        for (int i = 0; i < 4; ++i) start.push_back(uint8_t(nextHeaderCRC >> (8 * i)));
        uint32_t startCRC = crc32Update(crc32Init(), start.data(), 20);
        std::vector<uint8_t> s2;
        for (int i = 0; i < 4; ++i) s2.push_back(uint8_t(startCRC >> (8 * i)));
        if (!f.seek(8)) throw WrcError("seek failed");
        if (!f.write(s2.data(), 4)) throw WrcError("write failed");
        if (!f.write(start.data(), 20)) throw WrcError("write failed");
    } catch (...) {
        for (size_t i = 0; i < items.size(); ++i)
            if (packed[i].isTemp) deleteFileForever(packed[i].src);
        throw;
    }
    f.close();

    for (size_t i = 0; i < items.size(); ++i)
        if (packed[i].isTemp) deleteFileForever(packed[i].src);

    totalIn = total;
    totalOut = fileSizeOf(outPath);
    if (volumeSize > 0 && totalOut > volumeSize) {
        std::vector<std::wstring> parts;
        if (!splitIntoVolumes(outPath, volumeSize, parts))
            throw WrcError("volume split failed");
    }
    return true;
}

}  // namespace sevenzip
}  // namespace wrc
