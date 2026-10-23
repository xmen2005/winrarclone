// compressor.cpp
#include "core/compressor.h"

#include "core/formats/sevenzip_format.h"
#include "core/formats/wsar_format.h"
#include "core/formats/zip_format.h"
#include "utils/file_system.h"

#include <sstream>

namespace wrc {

std::vector<ScanItem> scanForArchive(const std::vector<std::wstring>& inputs) {
    return scanInputs(inputs);
}

void createArchive(const ArchiveOptions& opt, const std::vector<ScanItem>* scanned,
                   const ProgressFn& pf, ControlFn cf, uint64_t& totalIn,
                   uint64_t& totalOut) {
    std::vector<ScanItem> own;
    const std::vector<ScanItem>* items = scanned;
    if (!items) {
        own = scanInputs(opt.inputs);
        items = &own;
    }
    if (items->empty()) throw WrcError("nothing to archive (inputs not found)");

    switch (opt.format) {
        case Format::Zip:
            zipfmt::build(*items, opt.archivePath, deflateLevel(opt.method),
                          opt.multiThread ? opt.threads : 1, opt.volumeSize, pf, cf,
                          totalIn, totalOut);
            break;
        case Format::SevenZip:
            sevenzip::build(*items, opt.archivePath, opt.method,
                            opt.multiThread ? opt.threads : 1, opt.volumeSize, pf, cf,
                            totalIn, totalOut);
            break;
        default:
            wsar::build(*items, opt, pf, cf, totalIn, totalOut);
            break;
    }

    if (opt.deleteAfter) {
        for (const auto& it : *items) {
            if (it.isDir) continue;
            deleteToRecycleBin(it.fullPath);
        }
    }
}

// ------------------------------------------------------ human formatting
std::wstring humanSize(uint64_t bytes) {
    const wchar_t* units[] = {L"B", L"KB", L"MB", L"GB", L"TB"};
    double v = double(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        ++u;
    }
    wchar_t buf[64];
    if (u == 0)
        swprintf(buf, 64, L"%llu B", (unsigned long long)bytes);
    else
        swprintf(buf, 64, L"%.1f %s", v, units[u]);
    return buf;
}

std::wstring formatSpeed(double bytesPerSec) {
    if (bytesPerSec <= 0) return L"—";
    return humanSize(uint64_t(bytesPerSec)) + L"/s";
}

std::wstring formatDuration(double seconds) {
    if (seconds < 0 || seconds > 3600.0 * 24 * 365) return L"--:--:--";
    int total = int(seconds);
    wchar_t buf[32];
    swprintf(buf, 32, L"%02d:%02d:%02d", total / 3600, (total / 60) % 60, total % 60);
    return buf;
}

}  // namespace wrc
