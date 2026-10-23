// crc32.h — CRC32 (zlib) helpers
#pragma once
#include <cstddef>
#include <cstdint>
#include <zlib.h>

namespace wrc {

inline uint32_t crc32Init() { return ::crc32(0L, Z_NULL, 0); }

inline uint32_t crc32Update(uint32_t crc, const void* data, size_t len) {
    // zlib takes uInt (unsigned int); callers chunk at <= 1 MB.
    while (len > 0) {
        uInt step = len > 0x40000000u ? 0x40000000u : static_cast<uInt>(len);
        crc = ::crc32(crc, static_cast<const Bytef*>(data), step);
        data = static_cast<const uint8_t*>(data) + step;
        len -= step;
    }
    return crc;
}

}  // namespace wrc
