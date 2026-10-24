// libarchive_reader.h — generic foreign-archive support (7z, RAR, tar, …)
// Uses libarchive — the C++ analog of the "libarchive / unrar (extraction)"
// external libraries named in the specification.
#pragma once
#include "core/common.h"

namespace wrc {
namespace la {

bool list(const std::wstring& path, const std::wstring& password, ArchiveInfo& out,
          std::string& err);

// Extract entries (empty `only` = all). Returns extracted file paths.
bool extract(const std::wstring& path, const std::wstring& destDir,
             const std::wstring& password, const std::vector<std::wstring>& only,
             const ProgressFn& pf, ControlFn cf, std::vector<std::wstring>& extracted,
             std::string& err, const ExtractLimits& limits = ExtractLimits{},
             OverwritePolicy overwrite = OverwritePolicy::Skip);

// Full read-through integrity verification.
bool test(const std::wstring& path, const std::wstring& password, const ProgressFn& pf,
          ControlFn cf, int& badEntries, std::string& err);

}  // namespace la
}  // namespace wrc
