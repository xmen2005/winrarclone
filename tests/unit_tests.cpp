// unit_tests.cpp — core engine regression tests
// Covers: path normalization, makeDirs, CRC32, LZSS round-trips, and full
// WSAR / ZIP / 7Z archive round-trips (nested dirs, absolute extract paths,
// files > 16 KiB to exercise multi-byte 7z number encoding).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "core/crc32.h"
#include "core/formats/libarchive_reader.h"
#include "core/formats/sevenzip_format.h"
#include "core/formats/wsar_format.h"
#include "core/formats/zip_format.h"
#include "core/lzss.h"
#include "utils/file_system.h"

#include <cstdio>
#include <random>
#include <string>
#include <vector>

using namespace wrc;

static int g_pass = 0, g_fail = 0;

#define CHECK(name, cond)                                   \
    do {                                                    \
        if (cond) {                                         \
            ++g_pass;                                       \
            printf("PASS: %s\n", name);                     \
        } else {                                            \
            ++g_fail;                                       \
            printf("FAIL: %s (line %d)\n", name, __LINE__); \
        }                                                   \
    } while (0)

static std::wstring g_tmp;

static std::wstring tpath(const std::wstring& name) { return g_tmp + L"\\" + name; }

static void writeFile(const std::wstring& path, const std::string& data) {
    makeDirs(directoryOf(path));
    File f;
    if (!f.openWriteTruncate(path)) {
        printf("cannot write %ls\n", path.c_str());
        exit(2);
    }
    if (!data.empty()) f.write(data.data(), uint32_t(data.size()));
}

static bool readFile(const std::wstring& path, std::string& out) {
    return readFileBytes(path, out);
}

static std::string randomData(size_t n, uint32_t seed) {
    std::mt19937 rng(seed);
    std::string s(n, 0);
    for (auto& c : s) c = char(rng() & 0xFF);
    return s;
}

static std::string repetitiveData(size_t n) {
    std::string s;
    const char* unit = "The quick brown fox jumps over the lazy dog. ";
    while (s.size() < n) s += unit;
    s.resize(n);
    return s;
}

// ------------------------------------------------------------ path helpers
static void testPaths() {
    std::wstring e = toExtendedPath(L"C:\\foo\\bar.txt");
    CHECK("toExtendedPath drive", e == L"\\\\?\\C:\\foo\\bar.txt");
    // forward slashes are normalized (\\?\ does not treat them as separators)
    std::wstring ef = toExtendedPath(L"C:/foo/bar.txt");
    CHECK("toExtendedPath forward slashes", ef == L"\\\\?\\C:\\foo\\bar.txt");
    std::wstring e2 = toExtendedPath(L"\\\\?\\C:\\x");
    CHECK("toExtendedPath already extended", e2 == L"\\\\?\\C:\\x");
    std::wstring e3 = toExtendedPath(L"\\\\server\\share\\x");
    CHECK("toExtendedPath UNC", e3 == L"\\\\?\\UNC\\server\\share\\x");

    bool ok = makeDirs(tpath(L"unit\\a\\b\\c"));
    CHECK("makeDirs nested", ok && isDirectoryPath(tpath(L"unit\\a\\b\\c")));

    // long path (>260) creation + write via the helpers
    std::wstring longDir = tpath(L"unit\\long");
    for (int i = 0; i < 10; ++i)
        longDir += L"\\segment_with_a_rather_long_name_0123456789_abcdefghij";
    bool made = makeDirs(longDir);
    writeFile(longDir + L"\\f.txt", "long path payload");
    std::string back;
    bool read = readFile(longDir + L"\\f.txt", back);
    CHECK("long path (>260) makeDirs+write+read",
          made && read && back == "long path payload");
}

static void testCrc() {
    CHECK("crc32 known vector", crc32Update(crc32Init(), "123456789", 9) == 0xCBF43926u);
}

static void testLzss() {
    struct Case {
        const char* name;
        std::string data;
    } cases[] = {
        {"lzss tiny", std::string("abc")},
        {"lzss small", randomData(1000, 1)},
        {"lzss random 1MB", randomData(1 << 20, 2)},
        {"lzss repetitive 5MB", repetitiveData(5 << 20)},
    };
    for (auto& c : cases) {
        LzssParams p;
        p.window = 1ull << 20;
        p.chainDepth = 64;
        std::vector<uint8_t> packed;
        lzssEncode(reinterpret_cast<const uint8_t*>(c.data.data()), c.data.size(), p,
                   packed, nullptr);
        LzssMemSink sink(size_t(c.data.size()));
        std::string err;
        bool ok = lzssDecode(packed.data(), packed.size(), sink, err);
        bool same = ok && sink.data.size() == c.data.size() &&
                    memcmp(sink.data.data(), c.data.data(), c.data.size()) == 0;
        CHECK((std::string(c.name) + " round-trip").c_str(), same);
    }
}

// ------------------------------------------------------- archive round-trips
static void makeSampleTree() {
    // nested tree with a >16 KiB file (exercises multi-byte 7z numbers)
    writeFile(tpath(L"unit\\tree\\readme.txt"), "hello nested world");
    writeFile(tpath(L"unit\\tree\\src\\big.bin"), randomData(20000, 7));
    writeFile(tpath(L"unit\\tree\\src\\deep\\rep.txt"), repetitiveData(70000));
    makeDirs(tpath(L"unit\\tree\\empty_dir"));
}

static void testWsar() {
    std::vector<ScanItem> items = scanInputs({tpath(L"unit\\tree")});
    CHECK("wsar scan found files", items.size() >= 5);

    ArchiveOptions opt;
    opt.archivePath = tpath(L"unit\\t.wsar.wrc");
    opt.method = Method::Best;
    opt.dictSize = 4ull << 20;
    uint64_t ti = 0, to = 0;
    bool built = false;
    try {
        wsar::build(items, opt, nullptr, [] { return true; }, ti, to);
        built = true;
    } catch (const std::exception& ex) {
        printf("  wsar build error: %s\n", ex.what());
    }
    CHECK("wsar build", built);

    WsarInfo info;
    std::string err;
    CHECK("wsar list", wsar::list(opt.archivePath, L"", info, err));
    CHECK("wsar entry count", info.entries.size() == items.size());

    // extract into an ABSOLUTE destination with nested dirs (regression: B1)
    std::wstring dest = tpath(L"unit\\wsar_out");
    std::vector<std::wstring> extracted;
    CHECK("wsar extract (absolute dest, nested)",
          wsar::extract(opt.archivePath, dest, L"", {}, nullptr, [] { return true; },
                        extracted, err) &&
              extracted.size() >= 3);
    std::string back;
    CHECK("wsar nested content",
          readFile(dest + L"\\tree\\src\\deep\\rep.txt", back) && back == repetitiveData(70000));
    CHECK("wsar >16KiB content",
          readFile(dest + L"\\tree\\src\\big.bin", back) && back == randomData(20000, 7));

    int bad = 0;
    CHECK("wsar test",
          wsar::test(opt.archivePath, L"", nullptr, [] { return true; }, bad, err) &&
              bad == 0);
}

static void testZip() {
    std::vector<ScanItem> items = scanInputs({tpath(L"unit\\tree")});
    uint64_t ti = 0, to = 0;
    bool built = false;
    try {
        zipfmt::build(items, tpath(L"unit\\t.zip"), 9, 4, 0, nullptr, [] { return true; },
                      ti, to);
        built = true;
    } catch (const std::exception& ex) {
        printf("  zip build error: %s\n", ex.what());
    }
    CHECK("zip build", built);

    ZipCentral central;
    CHECK("zip readCentral", zipfmt::readCentral(tpath(L"unit\\t.zip"), central));
    CHECK("zip entry count", central.recs.size() == items.size());

    std::wstring dest = tpath(L"unit\\zip_out");
    std::vector<std::wstring> extracted;
    std::string err;
    CHECK("zip extract (absolute dest, nested)",
          la::extract(tpath(L"unit\\t.zip"), dest, L"", {}, nullptr, [] { return true; },
                      extracted, err) &&
              extracted.size() >= 3);
    std::string back;
    CHECK("zip nested content",
          readFile(dest + L"\\tree\\src\\deep\\rep.txt", back) && back == repetitiveData(70000));
    CHECK("zip >16KiB content",
          readFile(dest + L"\\tree\\src\\big.bin", back) && back == randomData(20000, 7));
}

static void test7z() {
    std::vector<ScanItem> items = scanInputs({tpath(L"unit\\tree")});
    uint64_t ti = 0, to = 0;
    bool built = false;
    try {
        sevenzip::build(items, tpath(L"unit\\t.7z"), Method::Best, 4, 0, nullptr,
                        [] { return true; }, ti, to);
        built = true;
    } catch (const std::exception& ex) {
        printf("  7z build error: %s\n", ex.what());
    }
    CHECK("7z build", built);

    // independent validation through libarchive
    ArchiveInfo info;
    std::string err;
    CHECK("7z libarchive list", la::list(tpath(L"unit\\t.7z"), L"", info, err));

    std::wstring dest = tpath(L"unit\\7z_out");
    std::vector<std::wstring> extracted;
    CHECK("7z extract (absolute dest, nested)",
          la::extract(tpath(L"unit\\t.7z"), dest, L"", {}, nullptr, [] { return true; },
                      extracted, err) &&
              extracted.size() >= 3);
    std::string back;
    CHECK("7z nested content",
          readFile(dest + L"\\tree\\src\\deep\\rep.txt", back) && back == repetitiveData(70000));
    // >16KiB exercises multi-byte number encoding (regression: B2)
    CHECK("7z >16KiB content",
          readFile(dest + L"\\tree\\src\\big.bin", back) && back == randomData(20000, 7));
    int bad = 0;
    CHECK("7z libarchive test",
          la::test(tpath(L"unit\\t.7z"), L"", nullptr, [] { return true; }, bad, err) &&
              bad == 0);
}

static void testEncryption() {
    std::vector<ScanItem> items = scanInputs({tpath(L"unit\\tree")});
    ArchiveOptions opt;
    opt.archivePath = tpath(L"unit\\t_enc.wrc");
    opt.method = Method::Normal;
    opt.dictSize = 4ull << 20;
    opt.password = L"unittest-P@ss";
    opt.encryptNames = true;
    uint64_t ti = 0, to = 0;
    wsar::build(items, opt, nullptr, [] { return true; }, ti, to);

    WsarInfo info;
    std::string err;
    CHECK("encrypted list requires password",
          !wsar::list(opt.archivePath, L"", info, err));
    CHECK("encrypted list with password",
          wsar::list(opt.archivePath, opt.password, info, err) &&
              info.entries.size() == items.size());

    std::wstring dest = tpath(L"unit\\enc_out");
    std::vector<std::wstring> extracted;
    CHECK("encrypted extract",
          wsar::extract(opt.archivePath, dest, opt.password, {}, nullptr,
                        [] { return true; }, extracted, err) &&
              extracted.size() >= 3);
    std::string back;
    CHECK("encrypted content",
          readFile(dest + L"\\tree\\src\\deep\\rep.txt", back) && back == repetitiveData(70000));
}

static void testEncryptionWrongPassword() {
    std::vector<ScanItem> items = scanInputs({tpath(L"unit\\tree")});
    ArchiveOptions opt;
    opt.archivePath = tpath(L"unit\\t_enc2.wrc");
    opt.method = Method::Normal;
    opt.dictSize = 4ull << 20;
    opt.password = L"secret";
    opt.encryptNames = true;
    uint64_t ti = 0, to = 0;
    wsar::build(items, opt, nullptr, [] { return true; }, ti, to);

    WsarInfo info;
    std::string err;
    CHECK("wrong password rejected (list)",
          !wsar::list(opt.archivePath, L"wrong", info, err));
    int bad = 0;
    CHECK("wrong password rejected (test)",
          !wsar::test(opt.archivePath, L"wrong", nullptr, [] { return true; }, bad, err));
}

static void testTruncated() {
    std::vector<ScanItem> items = scanInputs({tpath(L"unit\\tree")});
    ArchiveOptions opt;
    opt.archivePath = tpath(L"unit\\t_trunc.wrc");
    opt.method = Method::Fast;
    opt.dictSize = 4ull << 20;
    uint64_t ti = 0, to = 0;
    wsar::build(items, opt, nullptr, [] { return true; }, ti, to);

    // Truncate the file.
    File f;
    if (f.openWriteAppend(opt.archivePath)) {
        // shrink by 50 bytes
        uint64_t sz = f.size();
        if (sz > 50) {
            // reopen truncate not possible; use SetEndOfFile via handle
        }
        f.close();
    }
    // Use deleteFileForever? No. Instead create a copy truncated.
    std::wstring truncPath = tpath(L"unit\\t_trunc_cut.wrc");
    File src;
    if (src.openRead(opt.archivePath)) {
        uint64_t sz = src.size();
        uint64_t newSz = sz > 50 ? sz - 50 : 0;
        File dst;
        if (dst.openWriteTruncate(truncPath)) {
            std::vector<uint8_t> buf(1u << 16);
            uint64_t done = 0;
            while (done < newSz) {
                uint64_t want = std::min<uint64_t>(buf.size(), newSz - done);
                uint32_t got = 0;
                if (!src.read(buf.data(), uint32_t(want), got) || got == 0) break;
                dst.write(buf.data(), got);
                done += got;
            }
        }
        src.close();
    }
    int bad = 0;
    std::string err;
    // Truncated archive should not pass integrity test.
    bool ok = wsar::test(truncPath, L"", nullptr, [] { return true; }, bad, err);
    CHECK("truncated archive rejected", !ok || bad > 0 || !err.empty());
}

static void testEmptyFile() {
    writeFile(tpath(L"unit\\empty.txt"), "");
    std::vector<ScanItem> items = scanInputs({tpath(L"unit\\empty.txt")});
    ArchiveOptions opt;
    opt.archivePath = tpath(L"unit\\t_empty.wrc");
    opt.method = Method::Normal;
    opt.dictSize = 4ull << 20;
    uint64_t ti = 0, to = 0;
    bool built = false;
    try {
        wsar::build(items, opt, nullptr, [] { return true; }, ti, to);
        built = true;
    } catch (...) { built = false; }
    CHECK("empty file build", built);

    WsarInfo info;
    std::string err;
    CHECK("empty file list", wsar::list(opt.archivePath, L"", info, err));
    std::wstring dest = tpath(L"unit\\empty_out");
    std::vector<std::wstring> extracted;
    CHECK("empty file extract",
          wsar::extract(opt.archivePath, dest, L"", {}, nullptr, [] { return true; }, extracted, err));
    std::string back;
    CHECK("empty file content", readFile(dest + L"\\empty.txt", back) && back.empty());
}

static void testUnicodeName() {
    writeFile(tpath(L"unit\\café_✓.txt"), "unicode content");
    std::vector<ScanItem> items = scanInputs({tpath(L"unit\\café_✓.txt")});
    ArchiveOptions opt;
    opt.archivePath = tpath(L"unit\\t_unicode.wrc");
    opt.method = Method::Normal;
    opt.dictSize = 4ull << 20;
    uint64_t ti = 0, to = 0;
    wsar::build(items, opt, nullptr, [] { return true; }, ti, to);

    std::wstring dest = tpath(L"unit\\unicode_out");
    std::vector<std::wstring> extracted;
    std::string err;
    CHECK("unicode extract",
          wsar::extract(opt.archivePath, dest, L"", {}, nullptr, [] { return true; }, extracted, err));
    std::string back;
    CHECK("unicode content", readFile(dest + L"\\café_✓.txt", back) && back == "unicode content");
}

static void testLongPathArchive() {
    std::wstring longDir = tpath(L"unit\\longarch");
    for (int i = 0; i < 10; ++i)
        longDir += L"\\segment_with_a_rather_long_name_0123456789_abcdefghij";
    makeDirs(longDir);
    writeFile(longDir + L"\\deep.txt", "deep content");
    std::vector<ScanItem> items = scanInputs({longDir + L"\\deep.txt"});
    ArchiveOptions opt;
    opt.archivePath = tpath(L"unit\\t_longpath.wrc");
    opt.method = Method::Fast;
    opt.dictSize = 4ull << 20;
    uint64_t ti = 0, to = 0;
    bool built = false;
    try {
        wsar::build(items, opt, nullptr, [] { return true; }, ti, to);
        built = true;
    } catch (...) { built = false; }
    CHECK("long path archive build", built);
    std::wstring dest = tpath(L"unit\\longarch_out");
    std::vector<std::wstring> extracted;
    std::string err;
    CHECK("long path archive extract",
          wsar::extract(opt.archivePath, dest, L"", {}, nullptr, [] { return true; }, extracted, err));
}

int main() {
    wchar_t tmpDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpDir);
    g_tmp = std::wstring(tmpDir) + L"wrc_tests";
    makeDirs(g_tmp);

    testPaths();
    testCrc();
    testLzss();
    makeSampleTree();
    testWsar();
    testZip();
    test7z();
    testEncryption();
    testEncryptionWrongPassword();
    testTruncated();
    testEmptyFile();
    testUnicodeName();
    testLongPathArchive();

    printf("\nTOTAL: pass=%d fail=%d\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
