// context_menu.cpp
#include "os_integration/context_menu.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

namespace wrc {
namespace shell {

static const wchar_t* kAddKey = L"Software\\Classes\\*\\shell\\WrcAdd";
static const wchar_t* kExtractKey = L"Software\\Classes\\*\\shell\\WrcExtract";
static const wchar_t* kDirAddKey = L"Software\\Classes\\Directory\\shell\\WrcAdd";

std::wstring exePath() {
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
    return std::wstring(buf, n);
}

// The shell verbs should invoke the GUI binary so the user gets a progress
// dialog (WinRAR-like).  Resolve wrclone_gui.exe next to the current module;
// fall back to the current module if it is missing.
static std::wstring uiExePath() {
    std::wstring cur = exePath();
    std::wstring dir = cur;
    size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir = dir.substr(0, slash + 1);
    std::wstring ui = dir + L"wrclone_gui.exe";
    DWORD a = GetFileAttributesW(ui.c_str());
    if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY))
        return ui;
    return cur;
}

static std::wstring quoted(const std::wstring& s) { return L"\"" + s + L"\""; }

static bool writeValue(HKEY root, const wchar_t* sub, const wchar_t* name,
                       const std::wstring& value) {
    HKEY k;
    if (RegCreateKeyExW(root, sub, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k,
                        nullptr) != ERROR_SUCCESS)
        return false;
    LRESULT r = RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)value.c_str(),
                               DWORD((value.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

static bool keyExists(const wchar_t* sub) {
    HKEY k;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, sub, 0, KEY_READ, &k) != ERROR_SUCCESS)
        return false;
    RegCloseKey(k);
    return true;
}

bool isIntegrated() { return keyExists(kAddKey); }

bool integrate() {
    std::wstring exe = uiExePath();
    if (exe.empty()) return false;
    std::wstring cmdAdd = quoted(exe) + L" add \"%1\"";
    std::wstring cmdX = quoted(exe) + L" x \"%1\"";
    bool ok = true;
    ok &= writeValue(HKEY_CURRENT_USER, kAddKey, nullptr, L"Add to WRC archive");
    ok &= writeValue(HKEY_CURRENT_USER, (std::wstring(kAddKey) + L"\\command").c_str(),
                     nullptr, cmdAdd);
    ok &= writeValue(HKEY_CURRENT_USER, kDirAddKey, nullptr, L"Add to WRC archive");
    ok &= writeValue(HKEY_CURRENT_USER,
                     (std::wstring(kDirAddKey) + L"\\command").c_str(), nullptr, cmdAdd);
    ok &= writeValue(HKEY_CURRENT_USER, kExtractKey, nullptr, L"Extract with WRC");
    ok &= writeValue(HKEY_CURRENT_USER,
                     (std::wstring(kExtractKey) + L"\\command").c_str(), nullptr, cmdX);
    return ok;
}

bool unintegrate() {
    bool ok = true;
    ok &= RegDeleteTreeW(HKEY_CURRENT_USER, kAddKey) == ERROR_SUCCESS ||
          GetLastError() == ERROR_FILE_NOT_FOUND;
    ok &= RegDeleteTreeW(HKEY_CURRENT_USER, kExtractKey) == ERROR_SUCCESS ||
          GetLastError() == ERROR_FILE_NOT_FOUND;
    ok &= RegDeleteTreeW(HKEY_CURRENT_USER, kDirAddKey) == ERROR_SUCCESS ||
          GetLastError() == ERROR_FILE_NOT_FOUND;
    return ok;
}

}  // namespace shell
}  // namespace wrc
