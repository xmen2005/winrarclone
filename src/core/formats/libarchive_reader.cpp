// libarchive_reader.cpp
#include "core/formats/libarchive_reader.h"

#include "core/crc32.h"
#include "core/progress_tracker.h"
#include "utils/file_system.h"

#include <archive.h>
#include <archive_entry.h>

#include <set>
#include <sys/stat.h>

namespace wrc {
namespace la {

static Format guessFormat(const std::wstring& path) {
    std::wstring e = extensionOf(path);
    if (e == L".7z" || e == L".001") return Format::SevenZip;
    return Format::Zip;
}

static void setErr(struct archive* a, std::string& err, const char* ctx) {
    const char* m = archive_error_string(a);
    err = std::string(ctx) + (m ? ": " : "") + (m ? m : "");
}

// sanitize entry path (zip-slip / absolute path protection)
static std::wstring safeName(const char* pathname) {
    if (!pathname || !*pathname) return L"";
    std::wstring n = fromUtf8(pathname);
    std::replace(n.begin(), n.end(), L'\\', L'/');
    while (!n.empty() && n.front() == L'/') n.erase(n.begin());
    if (n.find(L':') != std::wstring::npos) return L"";
    std::vector<std::wstring> parts;
    size_t start = 0;
    while (start <= n.size()) {
        size_t p = n.find(L'/', start);
        std::wstring seg =
            n.substr(start, p == std::wstring::npos ? std::wstring::npos : p - start);
        if (seg.empty() || seg == L".") {
        } else if (seg == L"..") {
            return L"";
        } else {
            parts.push_back(seg);
        }
        if (p == std::wstring::npos) break;
        start = p + 1;
    }
    if (parts.empty()) return L"";
    std::wstring out = parts[0];
    for (size_t i = 1; i < parts.size(); ++i) out += L"/" + parts[i];
    return out;
}

static void applyEntryMeta(const std::wstring& path, struct archive_entry* ae) {
    HANDLE h = CreateFileW(toExtendedPath(path).c_str(), FILE_WRITE_ATTRIBUTES, 0,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        ULARGE_INTEGER li;
        li.QuadPart = uint64_t(archive_entry_mtime(ae)) * 10000000ull +
                      116444736000000000ull +
                      uint64_t(archive_entry_mtime_nsec(ae)) / 100;
        FILETIME ft;
        ft.dwLowDateTime = li.LowPart;
        ft.dwHighDateTime = li.HighPart;
        SetFileTime(h, nullptr, nullptr, &ft);
        CloseHandle(h);
    }
    mode_t mode = archive_entry_mode(ae);
    DWORD attrs = (mode & S_IFDIR) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
    if (!(mode & 0222)) attrs |= FILE_ATTRIBUTE_READONLY;
    SetFileAttributesW(toExtendedPath(path).c_str(), attrs);
}

struct Reader {
    struct archive* a = nullptr;
    Reader() { a = archive_read_new(); }
    ~Reader() {
        if (a) archive_read_free(a);
    }
    bool open(const std::wstring& path, const std::wstring& password, std::string& err) {
        archive_read_support_format_all(a);
        archive_read_support_filter_all(a);
        if (!password.empty()) archive_read_add_passphrase(a, toUtf8(password).c_str());
        if (archive_read_open_filename_w(a, path.c_str(), 65536) != ARCHIVE_OK) {
            setErr(a, err, "open failed");
            return false;
        }
        return true;
    }
};

static std::wstring entryName(struct archive_entry* ae) {
    const char* n = archive_entry_pathname_utf8(ae);
    if (!n) n = archive_entry_pathname(ae);
    return safeName(n);
}

bool list(const std::wstring& path, const std::wstring& password, ArchiveInfo& out,
          std::string& err) {
    out = ArchiveInfo{};
    out.path = path;
    Reader r;
    if (!r.open(path, password, err)) return false;
    struct archive_entry* ae;
    bool needPw = false;
    for (;;) {
        int rc = archive_read_next_header(r.a, &ae);
        if (rc == ARCHIVE_EOF) break;
        if (rc == ARCHIVE_FATAL) {
            setErr(r.a, err, "read failed");
            return false;
        }
        if (rc == ARCHIVE_RETRY) continue;
        const char* es = archive_error_string(r.a);
        if (rc == ARCHIVE_WARN && es && strstr(es, "assphrase")) needPw = true;
        std::wstring name = entryName(ae);
        if (name.empty()) continue;
        FileEntry e;
        e.name = name;
        e.isDir = archive_entry_filetype(ae) == AE_IFDIR;
        e.size = e.isDir ? 0 : uint64_t(archive_entry_size(ae));
        e.mtime = uint64_t(archive_entry_mtime(ae));
        e.method = 0xFF;
        out.entries.push_back(e);
        if (!e.isDir) out.totalOriginal += e.size;
    }
    out.hasPassword = needPw;
    out.format = guessFormat(path);
    return true;
}

bool extract(const std::wstring& path, const std::wstring& destDir,
             const std::wstring& password, const std::vector<std::wstring>& only,
             const ProgressFn& pf, ControlFn cf, std::vector<std::wstring>& extracted,
             std::string& err) {
    ArchiveInfo pre;
    if (!list(path, password, pre, err)) return false;
    std::set<std::wstring> want(only.begin(), only.end());
    uint64_t total = 0;
    for (auto& e : pre.entries)
        if (!e.isDir && (only.empty() || want.count(e.name))) total += e.size;
    ProgressTracker pt(Progress::Phase::Extract, total, pf);
    pt.check(cf);

    Reader r;
    if (!r.open(path, password, err)) return false;
    struct archive_entry* ae;
    for (;;) {
        if (cf && !cf()) throw CancelledError();
        int rc = archive_read_next_header(r.a, &ae);
        if (rc == ARCHIVE_EOF) break;
        if (rc == ARCHIVE_FATAL) {
            setErr(r.a, err, "read failed");
            return false;
        }
        if (rc == ARCHIVE_RETRY) continue;
        std::wstring name = entryName(ae);
        if (name.empty()) continue;
        bool isDir = archive_entry_filetype(ae) == AE_IFDIR;
        if (!only.empty() && !want.count(name)) {
            archive_read_data_skip(r.a);
            continue;
        }
        // Windows APIs (especially \\?\ paths) do not normalize '/' — use '\'
        std::replace(name.begin(), name.end(), L'/', L'\\');
        std::wstring dest = destDir + L"\\" + name;
        if (isDir) {
            makeDirs(dest);
            continue;
        }
        makeDirs(directoryOf(dest));
        pt.setFile(name);
        File outFile;
        if (!outFile.openWriteTruncate(dest)) {
            err = "cannot create: " + toUtf8(dest);
            return false;
        }
        const void* buf = nullptr;
        size_t sz = 0;
        int64_t off = 0;
        for (;;) {
            if (cf && !cf()) throw CancelledError();
            rc = archive_read_data_block(r.a, &buf, &sz, &off);
            if (rc == ARCHIVE_EOF) break;
            if (rc < ARCHIVE_OK) {
                outFile.close();
                setErr(r.a, err, "data failed");
                return false;
            }
            if (sz) {
                if (!outFile.write(buf, uint32_t(sz))) {
                    outFile.close();
                    err = "write failed";
                    return false;
                }
                pt.addDone(sz);
                pt.check(cf);
            }
        }
        outFile.close();
        applyEntryMeta(dest, ae);
        extracted.push_back(dest);
    }
    return true;
}

bool test(const std::wstring& path, const std::wstring& password, const ProgressFn& pf,
          ControlFn cf, int& badEntries, std::string& err) {
    badEntries = 0;
    ArchiveInfo info;
    if (!list(path, password, info, err)) return false;
    ProgressTracker pt(Progress::Phase::Test, info.totalOriginal, pf);
    pt.check(cf);

    Reader r;
    if (!r.open(path, password, err)) return false;
    struct archive_entry* ae;
    for (;;) {
        if (cf && !cf()) throw CancelledError();
        int rc = archive_read_next_header(r.a, &ae);
        if (rc == ARCHIVE_EOF) break;
        if (rc == ARCHIVE_FATAL) {
            setErr(r.a, err, "read failed");
            return false;
        }
        if (rc == ARCHIVE_RETRY) {
            ++badEntries;
            continue;
        }
        if (archive_entry_filetype(ae) == AE_IFDIR) continue;
        pt.setFile(entryName(ae));
        const void* buf = nullptr;
        size_t sz = 0;
        int64_t off = 0;
        uint64_t bytes = 0;
        bool failed = false;
        for (;;) {
            rc = archive_read_data_block(r.a, &buf, &sz, &off);
            if (rc == ARCHIVE_EOF) break;
            if (rc < ARCHIVE_OK) {
                ++badEntries;
                failed = true;
                archive_read_data_skip(r.a);
                break;
            }
            bytes += sz;
            pt.addDone(sz);
            pt.check(cf);
        }
        if (!failed && bytes != uint64_t(archive_entry_size(ae))) ++badEntries;
    }
    return true;
}

}  // namespace la
}  // namespace wrc
