// sevenzip_format.h — minimal native 7z writer (Copy + Deflate codecs)
#pragma once
#include "core/common.h"
#include "utils/file_system.h"

namespace wrc {
namespace sevenzip {

// Build a .7z archive. Extraction/listing of .7z is handled via libarchive.
bool build(const std::vector<ScanItem>& items, const std::wstring& outPath,
           Method method, int threads, uint64_t volumeSize, const ProgressFn& pf,
           ControlFn cf, uint64_t& totalIn, uint64_t& totalOut);

}  // namespace sevenzip
}  // namespace wrc
