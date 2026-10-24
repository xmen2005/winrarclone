// decompressor.cpp
#include "core/decompressor.h"

#include "core/formats/libarchive_reader.h"
#include "core/formats/wsar_format.h"
#include "core/formats/zip_format.h"
#include "core/progress_tracker.h"
#include "core/volumes.h"
#include "utils/file_system.h"
#include "utils/security.h"

#include <algorithm>

namespace wrc {

static bool hasMagic(const std::wstring& path, const uint8_t* magic, size_t n) {
    File f;
    if (!f.openRead(path)) return false;
    uint8_t buf[8] = {};
    uint32_t got = 0;
    if (!f.pread(buf, uint32_t(n), 0, got) || got != n) return false;
    return memcmp(buf, magic, n) == 0;
}

Format detectFormat(const std::wstring& path) {
    static const uint8_t kWsar[8] = {'W', 'S', 'A', 'R', 0x1A, 0x07, 0x01, 0x00};
    static const uint8_t kZip[4] = {'P', 'K', 0x03, 0x04};
    static const uint8_t k7z[6] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
    std::wstring ext = extensionOf(path);
    if (ext == L".wrc") return Format::Wsar;
    if (hasMagic(path, kWsar, 8)) return Format::Wsar;
    if (hasMagic(path, k7z, 6)) return Format::SevenZip;
    if (hasMagic(path, kZip, 4)) return Format::Zip;
    if (ext == L".zip") return Format::Zip;
    if (ext == L".7z") return Format::SevenZip;
    return Format::Zip;  // foreign formats handled through libarchive
}

bool isArchiveFile(const std::wstring& path) {
    std::wstring e = extensionOf(path);
    if (e == L".wrc" || e == L".zip" || e == L".7z" || e == L".rar" || e == L".tar" ||
        e == L".gz" || e == L".bz2" || e == L".xz" || e == L".iso")
        return true;
    // volume part: strictly .NNN (three digits)
    if (e.size() == 4 && e[1] >= L'0' && e[1] <= L'9' && e[2] >= L'0' && e[2] <= L'9' &&
        e[3] >= L'0' && e[3] <= L'9')
        return true;
    static const uint8_t kWsar[8] = {'W', 'S', 'A', 'R', 0x1A, 0x07, 0x01, 0x00};
    static const uint8_t kZip[4] = {'P', 'K', 0x03, 0x04};
    static const uint8_t k7z[6] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
    return hasMagic(path, kWsar, 8) || hasMagic(path, kZip, 4) || hasMagic(path, k7z, 6);
}

// Resolve multi-part .001/.002 (zip/7z split) archives into one temp file.
static std::wstring resolveInput(const std::wstring& path, std::vector<std::wstring>& temps) {
    std::wstring ext = extensionOf(path);
    if (ext.size() == 4 && ext[1] >= L'0' && ext[1] <= L'9') {
        std::wstring joined = path + L"~joined.tmp";
        bool did = false;
        if (joinVolumesIfNeeded(path, joined, did) && did) {
            temps.push_back(joined);
            return joined;
        }
    }
    return path;
}

// ------------------------------------------------------ MOTW propagation
// spec §3.c: propagate the archive's Zone.Identifier to extracted files.
// Threshold is consistent with sec::hasInternetMark: zones >= 2
// (Internet/Restricted) are "downloaded from the network" marks worth copying.
static void propagateMotw(const std::wstring& archivePath,
                          const std::vector<std::wstring>& extracted) {
    int zone = 0;
    if (!readMotw(archivePath, zone)) return;
    if (zone < 2) return;
    for (const auto& f : extracted) writeMotw(f, zone);
}

// --------------------------------------------------------------- dispatch
std::string listArchive(const std::wstring& pathIn, const std::wstring& password,
                        ArchiveInfo& out) {
    std::vector<std::wstring> temps;
    std::wstring path = resolveInput(pathIn, temps);
    std::string err;
    Format fmt = detectFormat(path);
    if (fmt == Format::Wsar) {
        WsarInfo wi;
        if (!wsar::list(path, password, wi, err)) {
            out = wi;
            return err;
        }
        out = wi;
    } else if (fmt == Format::Zip) {
        ZipCentral central;
        if (!zipfmt::readCentral(path, central)) return central.err;
        out = ArchiveInfo{};
        out.format = Format::Zip;
        out.path = path;
        for (auto& r : central.recs) {
            FileEntry e = r;
            out.entries.push_back(e);
            if (!e.isDir) {
                out.totalOriginal += e.size;
                out.totalPacked += e.packedSize;
            }
        }
    } else {
        if (!la::list(path, password, out, err)) return err;
    }
    return {};
}

std::string extractArchive(const std::wstring& pathIn, const std::wstring& destDir,
                           const std::wstring& password, const ProgressFn& pf,
                           ControlFn cf, std::vector<std::wstring>* extracted) {
    std::vector<std::wstring> temps;
    std::wstring path = resolveInput(pathIn, temps);
    std::vector<std::wstring> files;
    std::string err;
    Format fmt = detectFormat(path);
    if (fmt == Format::Wsar) {
        if (!wsar::extract(path, destDir, password, {}, pf, cf, files, err)) return err;
    } else {
        if (!la::extract(path, destDir, password, {}, pf, cf, files, err)) return err;
    }
    propagateMotw(pathIn, files);
    if (extracted) *extracted = files;
    for (auto& t : temps) deleteFileForever(t);
    return {};
}

std::string testArchive(const std::wstring& pathIn, const std::wstring& password,
                        const ProgressFn& pf, ControlFn cf, int& badEntries) {
    badEntries = 0;
    std::vector<std::wstring> temps;
    std::wstring path = resolveInput(pathIn, temps);
    std::string err;
    Format fmt = detectFormat(path);
    if (fmt == Format::Wsar) {
        if (!wsar::test(path, password, pf, cf, badEntries, err)) return err;
    } else {
        if (!la::test(path, password, pf, cf, badEntries, err)) return err;
    }
    return {};
}

std::string repairArchive(const std::wstring& path, const std::wstring& password,
                          const ProgressFn& pf, ControlFn cf, int& kept, int& dropped) {
    kept = 0;
    dropped = 0;
    Format fmt = detectFormat(path);
    if (fmt != Format::Wsar)
        return "repair is currently supported for native (.wrc) archives only";
    WsarInfo info;
    std::string lerr;
    if (!wsar::list(path, password, info, lerr)) return lerr;
    std::vector<uint8_t> dataKey;
    if (password.size()) {
        std::vector<uint8_t> salt =
            info.salt.empty() ? std::vector<uint8_t>(16, 0) : info.salt;
        dataKey = pbkdf2Sha256(toUtf8(password), salt, 200000, 32, 0x01);
    }
    uint64_t total = info.totalOriginal;
    ProgressTracker pt(Progress::Phase::Test, total, pf);
    pt.check(cf);
    std::vector<std::wstring> keep;
    std::wstring tempDir = directoryOf(path);
    for (auto& e : info.entries) {
        if (e.isDir) {
            keep.push_back(e.name);
            continue;
        }
        pt.setFile(e.name);
        // verify via a mini extract of this single entry (always cleaned up)
        bool good = false;
        std::vector<std::wstring> outFiles;
        try {
            std::string ex;
            if (wsar::extract(path, tempDir, password, {e.name}, nullptr, cf, outFiles,
                              ex) &&
                !outFiles.empty())
                good = true;
        } catch (const CancelledError&) {
            for (auto& f : outFiles) deleteFileForever(f);
            throw;
        } catch (...) {
            good = false;
        }
        for (auto& f : outFiles) deleteFileForever(f);
        if (good)
            keep.push_back(e.name);
        else
            ++dropped;
        pt.addDone(e.size);
        pt.check(cf);
    }
    kept = int(keep.size());
    if (dropped == 0) return {};  // nothing to fix
    ArchiveOptions opt;
    opt.archivePath = path;
    wsar::rebuild(path, password, keep, {}, opt, pf, cf);
    return {};
}

std::string deleteEntries(const std::wstring& path, const std::wstring& password,
                          const std::vector<std::wstring>& namesToRemove,
                          const ProgressFn& pf, ControlFn cf) {
    Format fmt = detectFormat(path);
    ArchiveOptions opt;
    opt.archivePath = path;
    if (fmt == Format::Wsar) {
        WsarInfo info;
        std::string err;
        if (!wsar::list(path, password, info, err)) return err;
        std::vector<std::wstring> keep;
        for (auto& e : info.entries)
            if (std::find(namesToRemove.begin(), namesToRemove.end(), e.name) == 
                namesToRemove.end())
                keep.push_back(e.name);
        wsar::rebuild(path, password, keep, {}, opt, pf, cf);
        return {};
    }
    if (fmt == Format::Zip) {
        ZipCentral central;
        if (!zipfmt::readCentral(path, central)) return central.err;
        std::vector<uint32_t> keepIdx;
        for (uint32_t i = 0; i < central.recs.size(); ++i)
            if (std::find(namesToRemove.begin(), namesToRemove.end(),
                          central.recs[i].name) == namesToRemove.end())
                keepIdx.push_back(i);
        std::wstring tmp = path + L"~rebuild.tmp";
        zipfmt::rebuild(path, keepIdx, {}, tmp, 6, 1, pf, cf);
        deleteFileForever(path);
        MoveFileExW(toExtendedPath(tmp).c_str(), toExtendedPath(path).c_str(),
                    MOVEFILE_REPLACE_EXISTING);
        return {};
    }
    return "delete inside archive is supported for .wrc and .zip only";
}

std::string appendFiles(const std::wstring& path, const std::wstring& password,
                        const std::vector<std::wstring>& inputs, const ProgressFn& pf,
                        ControlFn cf) {
    Format fmt = detectFormat(path);
    ArchiveOptions opt;
    opt.archivePath = path;
    if (fmt == Format::Wsar) {
        WsarInfo info;
        std::string err;
        if (!wsar::list(path, password, info, err)) return err;
        std::vector<std::wstring> keep;
        for (auto& e : info.entries) keep.push_back(e.name);
        std::vector<ScanItem> newItems = scanInputs(inputs);
        wsar::rebuild(path, password, keep, newItems, opt, pf, cf);
        return {};
    }
    if (fmt == Format::Zip) {
        ZipCentral central;
        if (!zipfmt::readCentral(path, central)) return central.err;
        std::vector<uint32_t> keepIdx;
        for (uint32_t i = 0; i < central.recs.size(); ++i) keepIdx.push_back(i);
        std::vector<ScanItem> newItems = scanInputs(inputs);
        std::wstring tmp = path + L"~rebuild.tmp";
        zipfmt::rebuild(path, keepIdx, newItems, tmp, 6, 1, pf, cf);
        deleteFileForever(path);
        MoveFileExW(toExtendedPath(tmp).c_str(), toExtendedPath(path).c_str(),
                    MOVEFILE_REPLACE_EXISTING);
        return {};
    }
    return "appending is supported for .wrc and .zip only";
}

}  // namespace wrc
