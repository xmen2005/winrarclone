// zip_format.h — native ZIP writer / central-directory reader (deflate, Zip64)
#pragma once
#include "core/common.h"
#include "utils/file_system.h"

namespace wrc {

struct ZipCentral {
    struct Rec : FileEntry {
        uint16_t methodZip = 0;
        uint16_t flags = 0;
        uint64_t dataOff = 0;   // absolute offset of packed data
        bool zip64 = false;
    };
    std::vector<Rec> recs;
    bool ok = false;
    std::string err;
};

namespace zipfmt {

// Parse the central directory (names, sizes, CRC32, attrs, mtime, offsets).
bool readCentral(const std::wstring& path, ZipCentral& out);

// Build a zip from scanned items. Multithreaded first pass compresses every
// file into a temp file, second pass writes the container.
bool build(const std::vector<ScanItem>& items, const std::wstring& outPath, int level,
           int threads, uint64_t volumeSize, const ProgressFn& pf, ControlFn cf,
           uint64_t& totalIn, uint64_t& totalOut);

// Rebuild keeping recs[keepIndices] + adding newItems (delete / append).
bool rebuild(const std::wstring& srcZip, const std::vector<uint32_t>& keepIndices,
             const std::vector<ScanItem>& newItems, const std::wstring& dstZip, int level,
             int threads, const ProgressFn& pf, ControlFn cf);

}  // namespace zipfmt
}  // namespace wrc
