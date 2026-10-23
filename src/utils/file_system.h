// file_system.h — long-path file I/O utilities (\\?\, up to 65,535 chars)
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace wrc {

// ---------------------------------------------------------------- long paths
// Normalizes any absolute path to the extended-length form so Windows APIs
// accept paths well beyond MAX_PATH (spec §3.b: up to 65,535 characters).
std::wstring toExtendedPath(const std::wstring& path);
bool pathNeedsExtension(const std::wstring& path);

std::wstring fileNameOf(const std::wstring& path);
std::wstring directoryOf(const std::wstring& path);
std::wstring stripExtension(const std::wstring& path);
std::wstring extensionOf(const std::wstring& path);

bool fileExists(const std::wstring& path);
bool isDirectoryPath(const std::wstring& path);
uint64_t fileSizeOf(const std::wstring& path);
uint64_t fileMtimeOf(const std::wstring& path);   // unix seconds
uint32_t fileAttrsOf(const std::wstring& path);

// ------------------------------------------------------------- file scanning
struct ScanItem {
    std::wstring fullPath;   // extended-path ready
    std::wstring relPath;    // path inside archive ('/' separators)
    uint64_t size = 0;
    uint64_t mtime = 0;
    uint32_t attrs = 0;
    bool isDir = false;
};

// Recursively scan files/directories (like adding inputs to WinRAR).
std::vector<ScanItem> scanInputs(const std::vector<std::wstring>& inputs);
uint64_t scanTotalSize(const std::vector<ScanItem>& items);

// --------------------------------------------------------------- RAII handle
class File {
public:
    File() = default;
    ~File();
    File(const File&) = delete;
    File& operator=(const File&) = delete;

    bool openRead(const std::wstring& path);
    bool openWriteTruncate(const std::wstring& path);
    bool openWriteAppend(const std::wstring& path);
    bool createAlways(const std::wstring& path);
    void close();
    bool isOpen() const { return h_ != INVALID_HANDLE_VALUE; }

    bool read(void* buf, uint32_t len, uint32_t& got);
    bool write(const void* buf, uint32_t len);
    bool seek(uint64_t pos);
    uint64_t tell() const;
    uint64_t size() const;
    // Positional read — does not disturb the logical cursor.
    bool pread(void* buf, uint32_t len, uint64_t pos, uint32_t& got);
    HANDLE handle() const { return h_; }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

bool readFileBytes(const std::wstring& path, std::string& out, uint64_t maxBytes = ~0ull);
bool writeFileBytes(const std::wstring& path, const void* data, size_t len);
bool makeDirs(const std::wstring& path);
bool deleteFileForever(const std::wstring& path);
bool deleteToRecycleBin(const std::wstring& path);

// ---------------------------------------------------------------- conversion
std::string toUtf8(const std::wstring& w);
std::wstring fromUtf8(const std::string& s);
inline uint64_t fileTimeToUnix(uint64_t winFileTime100ns) {
    return winFileTime100ns / 10000000ull - 11644473600ull;
}

}  // namespace wrc
