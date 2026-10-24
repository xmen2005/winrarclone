// file_system.cpp
#include "utils/file_system.h"

#include <shellapi.h>
#include <shlwapi.h>
#include <shobjidl.h>

namespace wrc {

// extended-path prefixes built programmatically (no escape pitfalls)
static const std::wstring kExt = [] {
    std::wstring p;
    p += L"\\"; p += L"\\"; p += L"?"; p += L"\\";
    return p;
}();
static const std::wstring kExtUNC = [] {
    std::wstring p = kExt;
    p += L"UNC"; p += L"\\";
    return p;
}();
std::wstring toExtendedPath(const std::wstring& path) {
    if (path.size() >= 4 && path.compare(0, 4, kExt) == 0) return path;
    if (path.size() >= 2 && path[1] == L':') return kExt + path;
    if (path.size() >= 2 && path[0] == L'\\' &&
        path[1] == L'\\')
        return kExtUNC + path.substr(2);
    return path;
}

bool pathNeedsExtension(const std::wstring& path) {
    return path.size() >= 248;  // MAX_PATH - some margin
}

std::wstring fileNameOf(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? path : path.substr(p + 1);
}

std::wstring directoryOf(const std::wstring& path) {
    size_t p = path.find_last_of(L"\\/");
    if (p == std::wstring::npos) return L".";
    if (p < 3) return path.substr(0, p + 1);
    return path.substr(0, p);
}

std::wstring stripExtension(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    size_t dot = path.find_last_of(L'.');
    if (dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash))
        return path.substr(0, dot);
    return path;
}

std::wstring extensionOf(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    size_t dot = path.find_last_of(L'.');
    if (dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash))
        return path.substr(dot);
    return L"";
}

static WIN32_FILE_ATTRIBUTE_DATA attrDataOf(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA ad{};
    GetFileAttributesExW(toExtendedPath(path).c_str(), GetFileExInfoStandard, &ad);
    return ad;
}

bool fileExists(const std::wstring& path) {
    DWORD a = GetFileAttributesW(toExtendedPath(path).c_str());
    return a != INVALID_FILE_ATTRIBUTES;
}

bool isDirectoryPath(const std::wstring& path) {
    DWORD a = GetFileAttributesW(toExtendedPath(path).c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

uint64_t fileSizeOf(const std::wstring& path) {
    auto ad = attrDataOf(path);
    return (uint64_t(ad.nFileSizeHigh) << 32) | ad.nFileSizeLow;
}

uint64_t fileMtimeOf(const std::wstring& path) {
    auto ad = attrDataOf(path);
    return fileTimeToUnix((uint64_t(ad.ftLastWriteTime.dwHighDateTime) << 32) |
                          ad.ftLastWriteTime.dwLowDateTime);
}

uint32_t fileAttrsOf(const std::wstring& path) {
    return GetFileAttributesW(toExtendedPath(path).c_str());
}

// ------------------------------------------------------------------ scanning
static void walkDir(const std::wstring& dir, const std::wstring& relPrefix,
                    std::vector<ScanItem>& out) {
    std::wstring pattern = toExtendedPath(dir) + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd,
                                FindExSearchNameMatch, nullptr,
                                FIND_FIRST_EX_LARGE_FETCH);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring name = fd.cFileName;
        if (name == L"." || name == L"..") continue;
        std::wstring full = dir + L"\\" + name;
        std::wstring rel = relPrefix.empty() ? name : relPrefix + L"/" + name;
        bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        uint64_t mtime = fileTimeToUnix((uint64_t(fd.ftLastWriteTime.dwHighDateTime) << 32) |
                                        fd.ftLastWriteTime.dwLowDateTime);
        if (isDir) {
            out.push_back({full, rel, 0, mtime, fd.dwFileAttributes, true});
            walkDir(full, rel, out);
        } else {
            out.push_back({full, rel,
                           (uint64_t(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow,
                           mtime, fd.dwFileAttributes, false});
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

std::vector<ScanItem> scanInputs(const std::vector<std::wstring>& inputs) {
    std::vector<ScanItem> out;
    for (const auto& in : inputs) {
        if (isDirectoryPath(in)) {
            std::wstring base = fileNameOf(in.size() && in.back() == L'\\' || in.back() == L'/'
                                               ? in.substr(0, in.size() - 1)
                                               : in);
            std::wstring full = in.size() && (in.back() == L'\\' || in.back() == L'/')
                                    ? in.substr(0, in.size() - 1)
                                    : in;
            out.push_back({full, base, 0, fileMtimeOf(full), fileAttrsOf(full), true});
            walkDir(full, base.empty() ? L"" : base, out);
        } else if (fileExists(in)) {
            out.push_back({in, fileNameOf(in), fileSizeOf(in), fileMtimeOf(in),
                           fileAttrsOf(in), false});
        }
    }
    return out;
}

uint64_t scanTotalSize(const std::vector<ScanItem>& items) {
    uint64_t t = 0;
    for (const auto& it : items)
        if (!it.isDir) t += it.size;
    return t;
}

// ------------------------------------------------------------------ File RAII
File::~File() { close(); }

void File::close() {
    if (h_ != INVALID_HANDLE_VALUE) {
        CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }
}

static HANDLE openFileGeneric(const std::wstring& path, DWORD access, DWORD share,
                              DWORD creation) {
    return CreateFileW(toExtendedPath(path).c_str(), access, share, nullptr, creation,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
}

bool File::openRead(const std::wstring& path) {
    close();
    h_ = openFileGeneric(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         OPEN_EXISTING);
    return h_ != INVALID_HANDLE_VALUE;
}

bool File::openWriteTruncate(const std::wstring& path) {
    close();
    // read access too: LZSS decode reads back its own output
    h_ = openFileGeneric(path, GENERIC_READ | GENERIC_WRITE, 0, CREATE_ALWAYS);
    return h_ != INVALID_HANDLE_VALUE;
}

bool File::openWriteAppend(const std::wstring& path) {
    close();
    h_ = openFileGeneric(path, GENERIC_WRITE, 0, OPEN_ALWAYS);
    if (h_ != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER z{};
        SetFilePointerEx(h_, z, nullptr, FILE_END);
    }
    return h_ != INVALID_HANDLE_VALUE;
}

bool File::createAlways(const std::wstring& path) { return openWriteTruncate(path); }

bool File::read(void* buf, uint32_t len, uint32_t& got) {
    DWORD g = 0;
    BOOL ok = ReadFile(h_, buf, len, &g, nullptr);
    got = static_cast<uint32_t>(g);
    return ok && (g == len || got < len);
}

bool File::write(const void* buf, uint32_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    while (len > 0) {
        DWORD w = 0;
        uint32_t step = len > 0x40000000u ? 0x40000000u : len;
        if (!WriteFile(h_, p, step, &w, nullptr) || w != step) return false;
        p += step;
        len -= step;
    }
    return true;
}

bool File::seek(uint64_t pos) {
    LARGE_INTEGER li{};
    li.QuadPart = static_cast<LONGLONG>(pos);
    return SetFilePointerEx(h_, li, nullptr, FILE_BEGIN);
}

uint64_t File::tell() const {
    LARGE_INTEGER li{}, cur{};
    li.QuadPart = 0;
    if (!SetFilePointerEx(h_, li, &cur, FILE_CURRENT)) return ~0ull;
    return static_cast<uint64_t>(cur.QuadPart);
}

uint64_t File::size() const {
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h_, &sz)) return 0;
    return static_cast<uint64_t>(sz.QuadPart);
}

bool File::pread(void* buf, uint32_t len, uint64_t pos, uint32_t& got) {
    // Synchronous handles ignore OVERLAPPED offsets, so move the file pointer
    // explicitly and restore it afterwards.
    got = 0;
    LARGE_INTEGER cur{}, li{}, back{};
    li.QuadPart = static_cast<LONGLONG>(pos);
    if (!SetFilePointerEx(h_, {}, &cur, FILE_CURRENT)) return false;
    if (!SetFilePointerEx(h_, li, nullptr, FILE_BEGIN)) return false;
    DWORD g = 0;
    BOOL ok = ReadFile(h_, buf, len, &g, nullptr);
    got = static_cast<uint32_t>(g);
    back.QuadPart = cur.QuadPart;
    SetFilePointerEx(h_, back, nullptr, FILE_BEGIN);
    return ok || GetLastError() == ERROR_HANDLE_EOF;
}

bool readFileBytes(const std::wstring& path, std::string& out, uint64_t maxBytes) {
    File f;
    if (!f.openRead(path)) return false;
    uint64_t sz = f.size();
    if (sz > maxBytes) return false;
    out.resize(static_cast<size_t>(sz));
    uint64_t done = 0;
    while (done < sz) {
        uint32_t chunk = 1u << 20;
        if (sz - done < chunk) chunk = static_cast<uint32_t>(sz - done);
        uint32_t got = 0;
        if (!f.read(out.data() + done, chunk, got) || got != chunk) return false;
        done += got;
    }
    return true;
}

bool writeFileBytes(const std::wstring& path, const void* data, size_t len) {
    File f;
    if (!f.openWriteTruncate(path)) return false;
    if (len && !f.write(data, static_cast<uint32_t>(len))) return false;
    return true;
}

bool makeDirs(const std::wstring& path) {
    wchar_t absBuf[32768];
    uint32_t n = GetFullPathNameW(path.c_str(), 32768, absBuf, nullptr);
    if (!n) return false;
    std::wstring ext = toExtendedPath(std::wstring(absBuf, n));
    if (isDirectoryPath(ext)) return true;

    // Collect missing ancestors (deepest first), create them top-down.
    std::vector<std::wstring> missing;
    std::wstring probe = ext;
    while (probe.size() > 7) {  // stop at "\\\\?X:\"
        size_t slash = probe.find_last_of(L"\\");
        if (slash == std::wstring::npos || slash <= 6) break;
        probe.resize(slash);
        if (isDirectoryPath(probe)) break;
        missing.push_back(probe);
    }
    for (size_t k = missing.size(); k-- > 0;) {
        if (!CreateDirectoryW(missing[k].c_str(), nullptr) &&
            GetLastError() != ERROR_ALREADY_EXISTS)
            return false;
    }
    if (!isDirectoryPath(ext)) {
        if (!CreateDirectoryW(ext.c_str(), nullptr) &&
            GetLastError() != ERROR_ALREADY_EXISTS)
            return false;
    }
    return isDirectoryPath(ext);
}

bool deleteFileForever(const std::wstring& path) {
    DWORD a = GetFileAttributesW(toExtendedPath(path).c_str());
    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY))
        return RemoveDirectoryW(toExtendedPath(path).c_str()) != 0;
    return DeleteFileW(toExtendedPath(path).c_str()) != 0;
}

bool deleteToRecycleBin(const std::wstring& path) {
    // Preferred: IFileOperation — supports long paths and Recycle Bin properly.
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    bool comHere = SUCCEEDED(hrInit);
    if (comHere || hrInit == RPC_E_CHANGED_MODE) {
        IFileOperation* fo = nullptr;
        if (SUCCEEDED(CoCreateInstance(CLSID_FileOperation, nullptr, CLSCTX_ALL,
                                       IID_IFileOperation, (void**)&fo))) {
            fo->SetOperationFlags(FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT |
                                  FOF_NOERRORUI);
            IShellItem* item = nullptr;
            bool ok = false;
            if (SUCCEEDED(SHCreateItemFromParsingName(path.c_str(), nullptr,
                                                      IID_IShellItem, (void**)&item))) {
                if (SUCCEEDED(fo->DeleteItem(item, nullptr)) &&
                    SUCCEEDED(fo->PerformOperations()))
                    ok = true;
                item->Release();
            }
            fo->Release();
            if (comHere) CoUninitialize();
            if (ok) return true;
        } else if (comHere) {
            CoUninitialize();
        }
    }
    // Legacy fallback: SHFileOperation (raw path, MAX_PATH limited).
    std::wstring buf = path;
    buf.push_back(L'\0');
    buf.push_back(L'\0');
    SHFILEOPSTRUCTW op{};
    op.hwnd = nullptr;
    op.wFunc = FO_DELETE;
    op.pFrom = buf.c_str();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    return SHFileOperationW(&op) == 0;
}

// --------------------------------------------------------------- conversion
std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), nullptr, 0,
                                nullptr, nullptr);
    std::string s(size_t(n), 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), s.data(), n, nullptr,
                        nullptr);
    return s;
}

std::wstring fromUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n), 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

}  // namespace wrc
