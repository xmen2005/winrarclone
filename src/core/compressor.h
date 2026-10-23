// compressor.h — archive creation orchestration (core engine, Phase 1)
#pragma once
#include "core/common.h"
#include "utils/file_system.h"

namespace wrc {

std::vector<ScanItem> scanForArchive(const std::vector<std::wstring>& inputs);

// Creates an archive. Throws WrcError / CancelledError on failure.
// Returns packed-size stats through the out parameters.
void createArchive(const ArchiveOptions& opt, const std::vector<ScanItem>* scanned,
                   const ProgressFn& pf, ControlFn cf, uint64_t& totalIn,
                   uint64_t& totalOut);

}  // namespace wrc
