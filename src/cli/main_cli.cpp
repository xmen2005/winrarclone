// main_cli.cpp — wrclone: headless core engine front-end (spec Phase 1)
//
// wrclone a <archive> <inputs...> [--format wsar|zip|7z] [-m0..-m5] [--dict 64M]
//                                  [-v 700M|4.7G] [-p pass] [-hp pass] [--threads N]
//                                  [--long-range] [--exhaustive] [--encrypt-names]
// wrclone x <archive> [-o outdir] [-p pass]
// wrclone t <archive> [-p pass]
// wrclone l <archive> [-p pass]
// wrclone r <archive> [-p pass]          (repair, .wrc only)
// wrclone d <archive> <names...> [-p pass]
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include "core/common.h"
#include "core/compressor.h"
#include "core/decompressor.h"
#include "core/dictionary_mgr.h"

#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

using namespace wrc;

static std::vector<std::wstring> cmdlineArgs() {
    int n = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &n);
    std::vector<std::wstring> out;
    for (int i = 0; i < n; ++i) out.push_back(argv[i]);
    LocalFree(argv);
    return out;
}

static uint64_t parseSize(const std::wstring& s) {
    uint64_t mult = 1;
    std::wstring t = s;
    for (wchar_t& c : t) c = towlower(c);
    auto stripSuffix = [&](wchar_t c, uint64_t m) {
        if (!t.empty() && t.back() == c) {
            t.pop_back();
            mult = m;
            if (!t.empty() && t.back() == L'b') t.pop_back();
            return true;
        }
        return false;
    };
    if (stripSuffix(L'g', 1ull << 30)) {
    } else if (stripSuffix(L'm', 1ull << 20)) {
    } else if (stripSuffix(L'k', 1ull << 10)) {
    }
    return uint64_t(wcstoull(t.c_str(), nullptr, 10)) * mult;
}

// narrow UTF-8 output (MinGW wcout is unreliable with CP_UTF8)
static void wout(const std::wstring& s) { std::cout << toUtf8(s) << "\n"; }
static void werr(const std::wstring& s) { std::cerr << toUtf8(s) << "\n"; }

static void printEntry(const FileEntry& e) {
    std::wstring size = e.isDir ? L"—" : humanSize(e.size);
    std::wstring packed = e.isDir ? L"—" : humanSize(e.packedSize);
    std::wstring ratio = L"—";
    if (!e.isDir && e.size) ratio = std::to_wstring(e.packedSize * 100 / e.size) + L"%";
    wchar_t crc[16] = L"";
    if (!e.isDir) swprintf(crc, 16, L"%08X", e.crc32);
    wchar_t line[1024];
    swprintf(line, 1024, L"%-42ls %10ls %10ls %6ls %8ls", e.name.c_str(), size.c_str(),
             packed.c_str(), ratio.c_str(), crc);
    wout(line);
}

static void printUsage() {
    wout(L"WinRAR Clone Engine 7.0.0");
    wout(L"usage:");
    wout(L"  wrclone a <archive> <inputs...> [options]");
    wout(L"  wrclone x <archive> [-o outdir] [-p pass]");
    wout(L"  wrclone t <archive> [-p pass]");
    wout(L"  wrclone l <archive> [-p pass]");
    wout(L"  wrclone r <archive> [-p pass]");
    wout(L"  wrclone d <archive> <names...> [-p pass]");
    wout(L"options: --format wsar|zip|7z  -m0..-m5  --dict 64M  -v 4.7G");
    wout(L"         -p pass  -hp pass (encrypt names)  --threads N");
    wout(L"         --long-range  --exhaustive");
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::vector<std::wstring> args = cmdlineArgs();
    if (args.size() < 2) {
        printUsage();
        return 2;
    }
    std::wstring cmd = args[1];
    try {
        if (cmd == L"a") {
            if (args.size() < 4) {
                werr(L"error: need archive and inputs");
                return 2;
            }
            ArchiveOptions opt;
            opt.archivePath = args[2];
            for (int i = 3; i < int(args.size()); ++i) {
                const std::wstring& a = args[i];
                if (a == L"--format" && i + 1 < int(args.size())) {
                    std::wstring f = args[++i];
                    if (f == L"zip")
                        opt.format = Format::Zip;
                    else if (f == L"7z")
                        opt.format = Format::SevenZip;
                    else
                        opt.format = Format::Wsar;
                } else if (a.rfind(L"-m", 0) == 0 && a.size() == 3) {
                    opt.method = Method(a[2] - L'0');
                } else if (a == L"--dict" && i + 1 < int(args.size())) {
                    opt.dictSize = parseSize(args[++i]);
                } else if (a == L"-v" && i + 1 < int(args.size())) {
                    opt.volumeSize = parseSize(args[++i]);
                } else if (a == L"-p" && i + 1 < int(args.size())) {
                    opt.password = args[++i];
                } else if (a == L"-hp" && i + 1 < int(args.size())) {
                    opt.password = args[++i];
                    opt.encryptNames = true;
                } else if (a == L"--threads" && i + 1 < int(args.size())) {
                    opt.threads = wcstol(args[++i].c_str(), nullptr, 10);
                } else if (a == L"--long-range") {
                    opt.longRangeSearch = true;
                } else if (a == L"--exhaustive") {
                    opt.exhaustiveSearch = true;
                } else if (a == L"--encrypt-names") {
                    opt.encryptNames = true;
                } else {
                    opt.inputs.push_back(a);
                }
            }
            // dictionary RAM advisory (spec §3.a)
            if (opt.format == Format::Wsar && int(opt.method) >= int(Method::Normal)) {
                DictionaryCheck c = DictionaryManager::validate(opt.dictSize);
                if (!c.withinSafeThreshold())
                    werr(L"warning: dictionary requires ~" + humanSize(c.requiredRam) +
                         L" of RAM (available: " + humanSize(c.availableRam) + L")");
            }
            uint64_t ti = 0, to = 0;
            createArchive(opt, nullptr, [](const Progress&) {}, [] { return true; }, ti,
                          to);
            wout(L"created " + opt.archivePath + L" — " + humanSize(ti) + L" -> " +
                 humanSize(to));
            return 0;
        }
        if (cmd == L"x" || cmd == L"e") {
            std::wstring archive, out = L".", pass;
            for (int i = 2; i < int(args.size()); ++i) {
                if (args[i] == L"-o" && i + 1 < int(args.size()))
                    out = args[++i];
                else if (args[i] == L"-p" && i + 1 < int(args.size()))
                    pass = args[++i];
                else if (archive.empty())
                    archive = args[i];
            }
            std::vector<std::wstring> extracted;
            std::string err =
                extractArchive(archive, out, pass, nullptr, [] { return true; }, &extracted);
            if (!err.empty()) {
                werr(L"error: " + fromUtf8(err));
                return 1;
            }
            wout(L"extracted " + std::to_wstring(extracted.size()) + L" files to " + out);
            return 0;
        }
        if (cmd == L"t") {
            std::wstring archive, pass;
            for (int i = 2; i < int(args.size()); ++i) {
                if (args[i] == L"-p" && i + 1 < int(args.size()))
                    pass = args[++i];
                else if (archive.empty())
                    archive = args[i];
            }
            int bad = 0;
            std::string err = testArchive(archive, pass, nullptr, [] { return true; }, bad);
            if (!err.empty()) {
                werr(L"error: " + fromUtf8(err));
                return 1;
            }
            wout(bad == 0 ? L"OK — all files passed" : L"FAILED (" +
                                                              std::to_wstring(bad) +
                                                              L" bad)");
            return bad == 0 ? 0 : 3;
        }
        if (cmd == L"l") {
            std::wstring archive, pass;
            for (int i = 2; i < int(args.size()); ++i) {
                if (args[i] == L"-p" && i + 1 < int(args.size()))
                    pass = args[++i];
                else if (archive.empty())
                    archive = args[i];
            }
            ArchiveInfo info;
            std::string err = listArchive(archive, pass, info);
            if (!err.empty()) {
                werr(L"error: " + fromUtf8(err));
                return 1;
            }
            for (auto& e : info.entries) printEntry(e);
            wout(L"total: " + std::to_wstring(info.entries.size()) + L" entries, " +
                 humanSize(info.totalOriginal) + L" -> " + humanSize(info.totalPacked));
            return 0;
        }
        if (cmd == L"r") {
            std::wstring archive, pass;
            for (int i = 2; i < int(args.size()); ++i) {
                if (args[i] == L"-p" && i + 1 < int(args.size()))
                    pass = args[++i];
                else if (archive.empty())
                    archive = args[i];
            }
            int kept = 0, dropped = 0;
            std::string err =
                repairArchive(archive, pass, nullptr, [] { return true; }, kept, dropped);
            if (!err.empty()) {
                werr(L"error: " + fromUtf8(err));
                return 1;
            }
            wout(L"repaired: kept " + std::to_wstring(kept) + L", dropped " +
                 std::to_wstring(dropped));
            return 0;
        }
        if (cmd == L"d") {
            std::wstring archive, pass;
            std::vector<std::wstring> names;
            for (int i = 2; i < int(args.size()); ++i) {
                if (args[i] == L"-p" && i + 1 < int(args.size()))
                    pass = args[++i];
                else if (archive.empty())
                    archive = args[i];
                else
                    names.push_back(args[i]);
            }
            std::string err =
                deleteEntries(archive, pass, names, nullptr, [] { return true; });
            if (!err.empty()) {
                werr(L"error: " + fromUtf8(err));
                return 1;
            }
            wout(L"deleted " + std::to_wstring(names.size()) + L" entries");
            return 0;
        }
        if (cmd == L"add") {  // shell integration entry point: add <path>
            std::wstring dir = directoryOf(args[2]);
            ArchiveOptions opt;
            opt.archivePath = dir + L"\\" + fileNameOf(args[2]) + L".wrc";
            opt.inputs.push_back(args[2]);
            uint64_t ti = 0, to = 0;
            createArchive(opt, nullptr, [](const Progress&) {}, [] { return true; }, ti,
                          to);
            wout(L"created " + opt.archivePath);
            return 0;
        }
        werr(L"unknown command: " + cmd);
        return 2;
    } catch (const CancelledError&) {
        werr(L"cancelled");
        return 4;
    } catch (const std::exception& ex) {
        werr(L"error: " + fromUtf8(ex.what()));
        return 1;
    }
}
