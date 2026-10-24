// wsar_format.h — native open container (RAR5-style headers, see docs/FORMAT_WSAR.md)
#pragma once
#include "core/common.h"
#include "utils/file_system.h"

namespace wrc {

struct WsarInfo : ArchiveInfo {
    std::vector<uint8_t> salt;
    uint32_t archiveFlags = 0;  // 1=volume 2=encryptedNames 4=solid
    uint64_t volumeSize = 0;    // 0 = single volume (v1.1 archives)
};

namespace wsar {

bool build(const std::vector<ScanItem>& items, const ArchiveOptions& opt,
           const ProgressFn& pf, ControlFn cf, uint64_t& totalIn, uint64_t& totalOut);

bool list(const std::wstring& path, const std::wstring& password, WsarInfo& out,
          std::string& err);

// Extract selected entry names (empty = all) into destDir.
bool extract(const std::wstring& path, const std::wstring& destDir,
             const std::wstring& password, const std::vector<std::wstring>& only,
             const ProgressFn& pf, ControlFn cf, std::vector<std::wstring>& extracted,
             std::string& err, const ExtractLimits& limits = ExtractLimits{},
             OverwritePolicy overwrite = OverwritePolicy::Skip);

bool test(const std::wstring& path, const std::wstring& password, const ProgressFn& pf,
          ControlFn cf, int& badEntries, std::string& err);

// Rebuild keeping keepNames + adding newItems (delete / append operations).
bool rebuild(const std::wstring& path, const std::wstring& password,
             const std::vector<std::wstring>& keepNames,
             const std::vector<ScanItem>& newItems, const ArchiveOptions& opt,
             const ProgressFn& pf, ControlFn cf);

}  // namespace wsar
}  // namespace wrc
