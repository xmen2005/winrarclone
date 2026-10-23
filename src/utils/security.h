// security.h — Mark of the Web (MOTW) + AES-256 via Windows CNG
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace wrc {

// ------------------------------------------------- Mark of the Web (spec 3.c)
// Zone.Identifier is an NTFS Alternate Data Stream carrying the download zone.
// 0=Local 1=Intranet 2=Trusted 3=Internet 4=Restricted
bool readMotw(const std::wstring& file, int& zoneId);
bool writeMotw(const std::wstring& file, int zoneId);
bool hasInternetMark(const std::wstring& file);
void removeMotw(const std::wstring& file);

// ------------------------------------------------------------------- AES-256
std::vector<uint8_t> randomBytes(size_t n);

// PBKDF2-HMAC-SHA256; `info` byte is appended to the salt to derive
// independent keys from one password.
std::vector<uint8_t> pbkdf2Sha256(const std::string& password,
                                  const std::vector<uint8_t>& salt,
                                  uint32_t iterations, size_t keyLen, uint8_t info);

bool aes256CbcEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                      const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher);
bool aes256CbcDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                      const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain);
bool hmacSha256(const std::vector<uint8_t>& key, const uint8_t* data, size_t len,
                std::vector<uint8_t>& mac /* 32 bytes */);

}  // namespace wrc
