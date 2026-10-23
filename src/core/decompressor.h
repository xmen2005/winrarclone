// decompressor.h — listing / extraction / testing / repair orchestration
#pragma once
#include "core/common.h"

namespace wrc {

Format detectFormat(const std::wstring& path);
bool isArchiveFile(const std::wstring& path);

std::string listArchive(const std::wstring& path, const std::wstring& password,
                        ArchiveInfo& out);
std::string extractArchive(const std::wstring& path, const std::wstring& destDir,
                           const std::wstring& password, const ProgressFn& pf,
                           ControlFn cf, std::vector<std::wstring>* extracted);
std::string testArchive(const std::wstring& path, const std::wstring& password,
                        const ProgressFn& pf, ControlFn cf, int& badEntries);
// Rebuild keeping only entries that decompress + verify (WSAR archives).
std::string repairArchive(const std::wstring& path, const std::wstring& password,
                          const ProgressFn& pf, ControlFn cf, int& kept, int& dropped);
std::string deleteEntries(const std::wstring& path, const std::wstring& password,
                          const std::vector<std::wstring>& namesToRemove,
                          const ProgressFn& pf, ControlFn cf);
std::string appendFiles(const std::wstring& path, const std::wstring& password,
                        const std::vector<std::wstring>& inputs, const ProgressFn& pf,
                        ControlFn cf);

}  // namespace wrc
