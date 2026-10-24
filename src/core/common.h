// common.h — shared engine types (WinRAR Clone core)
#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace wrc {

enum class Format { Wsar, Zip, SevenZip };

enum class Method : int { Store = 0, Fastest = 1, Fast = 2, Normal = 3, Good = 4, Best = 5, Zstd = 6 };

inline int deflateLevel(Method m) {
    switch (m) {
        case Method::Store:   return 0;
        case Method::Fastest: return 1;
        case Method::Fast:    return 3;
        case Method::Good:    return 8;
        case Method::Best:    return 9;
        default:              return 6;
    }
}

inline const wchar_t* formatExtension(Format f) {
    switch (f) {
        case Format::Zip:      return L".zip";
        case Format::SevenZip: return L".7z";
        default:               return L".wrc";
    }
}

// One entry inside an archive (or a scanned source file).
struct FileEntry {
    std::wstring name;        // relative path, '/' separators
    uint64_t size = 0;        // original size
    uint64_t packedSize = 0;  // stored size
    uint32_t crc32 = 0;       // CRC32 of original data
    uint64_t mtime = 0;       // unix seconds (UTC)
    uint32_t attrs = 0;       // Windows attributes
    uint8_t method = 0;       // 0=store 1=deflate 2=lzss 0xFF=unknown
    bool isDir = false;
    bool encrypted = false;
    bool solid = false;       // part of a solid block
    uint64_t solidOffset = 0; // uncompressed offset within the solid block

    // rebuild bookkeeping (logical stream offsets, WSAR/ZIP)
    uint64_t headerStart = 0;
    uint64_t dataEnd = 0;
};

struct ArchiveInfo {
    Format format = Format::Wsar;
    std::wstring path;
    std::vector<FileEntry> entries;
    uint64_t dictSize = 0;
    bool encryptedNames = false;
    bool hasPassword = false;
    bool multiVolume = false;
    uint64_t totalOriginal = 0;
    uint64_t totalPacked = 0;
};

// Live progress snapshot pushed to the UI (spec §4: percentage, compressed
// size, speed, ETA).
struct Progress {
    enum class Phase { Scan, Compress, Extract, Test, Done };
    Phase phase = Phase::Scan;
    std::wstring currentFile;
    double fileRatio = 0.0;   // 0..1 — current file
    double totalRatio = 0.0;  // 0..1 — whole job
    uint64_t bytesDone = 0;
    uint64_t bytesTotal = 0;
    uint64_t bytesCompressed = 0;
    double speed = 0.0;       // bytes / second
    double eta = 0.0;         // seconds remaining
    double elapsed = 0.0;     // seconds
    uint64_t dictSize = 0;
};

struct ArchiveOptions {
    Format format = Format::Wsar;
    std::wstring archivePath;
    std::vector<std::wstring> inputs;   // files / directories to add
    Method method = Method::Normal;
    uint64_t dictSize = 64ull << 20;    // 1 MB … 64 GB (spec §2.b)
    uint64_t volumeSize = 0;            // 0 = single volume
    bool longRangeSearch = false;       // spec §2.b Advanced
    bool exhaustiveSearch = false;
    bool multiThread = true;
    bool solid = false;
    bool deleteAfter = false;
    std::wstring password;              // AES-256 when non-empty
    bool encryptNames = false;
    int threads = 0;                    // 0 = hardware concurrency
    int zstdLevel = 3;                  // Zstd compression level (1..22)
    std::vector<uint8_t> forcedSalt;    // internal: rebuild reuses archive salt
};

using ProgressFn = std::function<void(const Progress&)>;
// Returns false => user requested cancel. Also services pause internally.
using ControlFn = std::function<bool()>;

struct WrcError : std::runtime_error {
    explicit WrcError(const std::string& m) : std::runtime_error(m) {}
};
struct CancelledError : std::runtime_error {
    CancelledError() : std::runtime_error("cancelled") {}
};

// Human friendly helpers shared by CLI & GUI.
std::wstring humanSize(uint64_t bytes);
std::wstring formatSpeed(double bytesPerSec);
std::wstring formatDuration(double seconds);

}  // namespace wrc
