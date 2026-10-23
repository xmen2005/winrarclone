// volumes.cpp
#include "core/volumes.h"

#include "utils/file_system.h"

#include <algorithm>
#include <cstdio>

namespace wrc {

static std::wstring volumeName(const std::wstring& base, int n) {
    wchar_t buf[32];
    swprintf(buf, 32, L".%03d", n);
    return base + buf;
}

bool splitIntoVolumes(const std::wstring& path, uint64_t volumeSize,
                      std::vector<std::wstring>& parts) {
    File src;
    if (!src.openRead(path)) return false;
    uint64_t total = src.size();
    const uint64_t chunk = 1u << 20;
    std::vector<uint8_t> buf(chunk);
    int n = 1;
    uint64_t written = 0;
    File dst;
    std::wstring base = path;  // keep full name: x.zip -> x.zip.001
    while (written < total || n == 1) {
        std::wstring name = volumeName(base, n);
        dst.close();
        if (!dst.openWriteTruncate(name)) return false;
        parts.push_back(name);
        uint64_t left = volumeSize;
        while (left > 0 && written < total) {
            uint64_t want = std::min<uint64_t>({chunk, left, total - written});
            uint32_t got = 0;
            if (!src.read(buf.data(), uint32_t(want), got) || got != want) return false;
            if (!dst.write(buf.data(), got)) return false;
            left -= got;
            written += got;
        }
        ++n;
        if (total == 0) break;
    }
    dst.close();
    src.close();
    return deleteFileForever(path);
}

bool joinVolumesIfNeeded(const std::wstring& path, const std::wstring& joinedPath,
                         bool& joined) {
    joined = false;
    std::wstring ext = extensionOf(path);
    if (ext.size() != 4 || ext[1] < L'0' || ext[1] > L'9') return true;
    std::wstring base = stripExtension(path);
    std::vector<std::wstring> parts;
    for (int n = 1;; ++n) {
        std::wstring name = volumeName(base, n);
        if (!fileExists(name)) break;
        parts.push_back(name);
    }
    if (parts.empty()) return true;
    File dst;
    if (!dst.openWriteTruncate(joinedPath)) return false;
    std::vector<uint8_t> buf(1u << 20);
    for (const auto& p : parts) {
        File src;
        if (!src.openRead(p)) return false;
        uint64_t sz = src.size(), done = 0;
        while (done < sz) {
            uint64_t want = std::min<uint64_t>(buf.size(), sz - done);
            uint32_t got = 0;
            if (!src.read(buf.data(), uint32_t(want), got) || got == 0) return false;
            if (!dst.write(buf.data(), got)) return false;
            done += got;
        }
    }
    joined = true;
    return true;
}

}  // namespace wrc
