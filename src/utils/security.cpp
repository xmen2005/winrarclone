// security.cpp — MOTW (Zone.Identifier ADS) + AES-256-CBC/HMAC/PBKDF2 via CNG
#include "utils/security.h"

#include "utils/file_system.h"

#include <bcrypt.h>

#pragma comment(lib, "bcrypt")

namespace wrc {

// --------------------------------------------------------------------- MOTW
static std::wstring adsPath(const std::wstring& file) {
    // ADS is an NTFS concept - not available on UNC/network paths
    if (file.rfind(L"\\\\?\\UNC\\", 0) == 0 || file.rfind(L"\\\\", 0) == 0)
        return L"";
    std::wstring base = toExtendedPath(file);
    return base + L":Zone.Identifier";
}

bool readMotw(const std::wstring& file, int& zoneId) {
    std::wstring ads = adsPath(file);
    if (ads.empty()) return false;
    File f;
    if (!f.openRead(ads)) return false;
    std::string txt;
    char buf[512] = {};
    uint32_t got = 0;
    while (f.read(buf, sizeof(buf), got) && got > 0) {
        txt.append(buf, got);
        if (txt.size() > 4096) break;
    }
    auto p = txt.find("ZoneId=");
    if (p == std::string::npos) return false;
    // strict numeric parse, clamped to the documented 0..4 range
    long v = 0;
    bool any = false;
    for (const char* c = txt.c_str() + p + 7; *c; ++c) {
        if (*c >= '0' && *c <= '9') {
            v = v * 10 + (*c - '0');
            any = true;
        } else if (any) {
            break;
        } else if (*c != ' ' && *c != '\t') {
            return false;
        }
        if (v > 4) {
            v = 4;
            break;
        }
    }
    if (!any) return false;
    zoneId = int(v);
    return true;
}

bool writeMotw(const std::wstring& file, int zoneId) {
    std::wstring ads = adsPath(file);
    if (ads.empty()) return false;
    File f;
    if (!f.createAlways(ads)) return false;
    std::string txt = "[ZoneTransfer]\r\nZoneId=" + std::to_string(zoneId) + "\r\n";
    return f.write(txt.data(), uint32_t(txt.size()));
}

bool hasInternetMark(const std::wstring& file) {
    int z = 0;
    return readMotw(file, z) && z >= 2;
}

void removeMotw(const std::wstring& file) {
    DeleteFileW(adsPath(file).c_str());
}

// ---------------------------------------------------------------------- CNG
std::vector<uint8_t> randomBytes(size_t n) {
    std::vector<uint8_t> out(n);
    if (n == 0) return out;
    if (BCryptGenRandom(nullptr, out.data(), ULONG(n),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        out.clear();  // callers must check - empty = RNG failure
    return out;
}

std::vector<uint8_t> pbkdf2Sha256(const std::string& password,
                                  const std::vector<uint8_t>& salt, uint32_t iterations,
                                  size_t keyLen, uint8_t info) {
    std::vector<uint8_t> salt2 = salt;
    salt2.push_back(info);
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    std::vector<uint8_t> out;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return out;
    out.resize(keyLen);
    NTSTATUS st = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password.data(),
                                        ULONG(password.size()), salt2.data(),
                                        ULONG(salt2.size()), iterations, out.data(),
                                        ULONG(keyLen), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0) out.clear();
    return out;
}

bool aes256CbcEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                      const std::vector<uint8_t>& plain, std::vector<uint8_t>& cipher) {
    if (key.size() != 32 || iv.size() != 16) return false;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;
    do {
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) break;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0)
            break;
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       (PUCHAR)key.data(), ULONG(key.size()), 0) != 0)
            break;
        ULONG cb = 0;
        std::vector<uint8_t> ivc = iv;  // CNG mutates the IV buffer
        if (BCryptEncrypt(hKey, (PUCHAR)plain.data(), ULONG(plain.size()), nullptr,
                          ivc.data(), ULONG(ivc.size()), nullptr, 0, &cb,
                          BCRYPT_BLOCK_PADDING) != 0)
            break;
        cipher.resize(cb);
        ivc = iv;
        if (BCryptEncrypt(hKey, (PUCHAR)plain.data(), ULONG(plain.size()), nullptr,
                          ivc.data(), ULONG(ivc.size()), cipher.data(), cb, &cb,
                          BCRYPT_BLOCK_PADDING) != 0)
            break;
        cipher.resize(cb);
        ok = true;
    } while (false);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

bool aes256CbcDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv,
                      const std::vector<uint8_t>& cipher, std::vector<uint8_t>& plain) {
    if (key.size() != 32 || iv.size() != 16) return false;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;
    do {
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) break;
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0)
            break;
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       (PUCHAR)key.data(), ULONG(key.size()), 0) != 0)
            break;
        ULONG cb = 0;
        std::vector<uint8_t> ivc = iv;
        if (BCryptDecrypt(hKey, (PUCHAR)cipher.data(), ULONG(cipher.size()), nullptr,
                          ivc.data(), ULONG(ivc.size()), nullptr, 0, &cb,
                          BCRYPT_BLOCK_PADDING) != 0)
            break;
        plain.resize(cb);
        ivc = iv;
        if (BCryptDecrypt(hKey, (PUCHAR)cipher.data(), ULONG(cipher.size()), nullptr,
                          ivc.data(), ULONG(ivc.size()), plain.data(), cb, &cb,
                          BCRYPT_BLOCK_PADDING) != 0)
            break;
        plain.resize(cb);
        ok = true;
    } while (false);
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

bool hmacSha256(const std::vector<uint8_t>& key, const uint8_t* data, size_t len,
                std::vector<uint8_t>& mac) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;
    mac.clear();
    do {
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            break;
        DWORD objLen = 0, cbData = 0;
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen),
                              &cbData, 0) != 0)
            break;
        std::vector<uint8_t> obj(objLen);
        if (BCryptCreateHash(hAlg, &hHash, obj.data(), objLen,
                             (PUCHAR)key.data(), ULONG(key.size()), 0) != 0)
            break;
        const uint8_t* p = data;
        size_t left = len;
        while (left > 0) {
            ULONG step = left > 0x40000000u ? 0x40000000u : ULONG(left);
            if (BCryptHashData(hHash, (PUCHAR)p, step, 0) != 0) goto done;
            p += step;
            left -= step;
        }
        mac.resize(32);
        if (BCryptFinishHash(hHash, mac.data(), 32, 0) != 0) {
            mac.clear();
            goto done;
        }
        ok = true;
    done:
        break;
    } while (false);
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

}  // namespace wrc
