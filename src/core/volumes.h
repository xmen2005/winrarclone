// volumes.h — file split / join helpers for ZIP & 7Z volume support
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace wrc {

// Splits `path` into `<base>.001`, `<base>.002`, … each <= volumeSize bytes.
// Returns false on I/O error. Source file is removed on success.
bool splitIntoVolumes(const std::wstring& path, uint64_t volumeSize,
                      std::vector<std::wstring>& parts);

// If `path` looks like "<name>.001" and sibling parts exist, concatenates
// all parts into `joinedPath` (temp). Returns true when a join happened.
bool joinVolumesIfNeeded(const std::wstring& path, const std::wstring& joinedPath,
                         bool& joined);

}  // namespace wrc
