# WinRAR 7.0 Core & UI Clone Engine

> Local desktop archive manager replicating the classic **WinRAR 7.0** workflow:
> high-performance compression, giant dictionaries (up to **64 GB**), a responsive
> Qt 6 interface and full OS integration. 100% open source.

| | |
|---|---|
| **Language / Toolkit** | C++20 · Qt 6 (Widgets) |
| **Build system** | CMake ≥ 3.24 + Ninja (MSYS2 / MinGW-w64) |
| **Archive formats** | `.wrc` (RAR5-style, native) · `.zip` (native read/write) · `.7z` (native write, read via libarchive) · extraction of foreign archives (RAR5, tar, …) via **libarchive** |
| **Platform** | Windows 10/11 (x64) |
| **License** | MIT |

---

## ✨ Features (per Technical Specification)

### 1. Core Engine (`src/core`)
- **dictionary_mgr** — RAM allocator & safety validation. Compression typically needs
  ~1.5x–2.5x of the dictionary size in RAM; the engine requires `dict * 2` bytes of
  available RAM (per spec pseudo-code) and warns before starting heavy jobs.
- **compressor / decompressor** — streaming pipelines with CRC32 verification.
- **lzss** — real LZ77-class encoder with configurable dictionary window; the decoder
  is file-backed so archives written with huge declared dictionaries (up to 64 GB)
  decode with O(1) RAM.
- **Thread pool** — non-blocking async workers; the UI never freezes.

### 2. Desktop UI (`src/ui`, Qt 6)
Classic WinRAR layout exactly as in the specification mock-ups:
- Menu bar: *File, Commands, Tools, Favorites, Options, Help*
- Action toolbar: *Add, Extract To, Test, View, Delete, Info, Repair*
- Address & navigation bar with *Up* button
- Detailed file list: *Name, Original Size, Compressed Size, Ratio, Modified, Attr, CRC32*
- Status bar: selected/total files & bytes, active dictionary size
- **Archive dialog** (tabbed): *General / Advanced / Security & Password* —
  format selection (RAR5-style / ZIP / 7Z), compression method, **dictionary size
  selector 1 MB → 64 GB** with dynamic RAM check warning, split-to-volumes
  (700 MB · 4.7 GB · custom), Long Range Search, Exhaustive Search, Multi-threaded,
  AES-256 password + *Encrypt file names*.
- **Progress dialog**: elapsed / remaining / speed, per-file + total progress,
  compressed size, ratio, dictionary label, *Background / Pause / Cancel*.

### 3. OS integration (`src/os_integration`, `src/utils`)
- **Long paths** — `\\?\` prefix normalization, > 260 chars up to **65,535**.
- **Mark of the Web (MOTW)** — `Zone.Identifier` ADS read from the archive and
  propagated automatically to every extracted file.
- **Shell context menu** — registry-based right-click integration
  (Options → *Integrate into Windows shell*).
- Zip-slip protection: hostile `../` entry names are rejected on extraction.

### 4. CLI (`wrclone.exe`)
```text
wrclone a <archive> <files...> [--format wsar|zip|7z] [-m0..-m5] [--dict 64M]
                                [-v 4.7G] [-p pass] [-hp pass] [--threads N]
wrclone x <archive> [-o outdir] [-p pass]
wrclone t <archive> [-p pass]
wrclone l <archive>
```

---

## 🔨 Build (MSYS2 / MinGW-w64)

```powershell
# one-time: install toolchain
D:\msys64\usr\bin\bash.exe -lc "pacman -S --needed --noconfirm \
  mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
  mingw-w64-x86_64-qt6-base mingw-w64-x86_64-qt6-tools \
  mingw-w64-x86_64-zlib mingw-w64-x86_64-libarchive"

# build
.\scripts\build_msys2.ps1          # configures build/ and builds Release
.\scripts\deploy.ps1               # optional: self-contained dist/ with windeployqt
```

## 🚀 Run

```powershell
.\build\wrclone_gui.exe     # GUI
.\build\wrclone.exe a demo.wrc docs\*.md    # CLI
```

## 📁 Project layout (per Technical Specification §1.b)

```
WinRAR_Clone/
├── src/
│   ├── core/                  # compression engine
│   │   ├── dictionary_mgr.cpp # dictionary memory (RAM allocator)
│   │   ├── compressor.cpp     # streams & algorithms
│   │   └── decompressor.cpp   # extraction & index reading
│   ├── ui/                    # Qt 6 interface
│   │   ├── main_window.cpp    # main screen & file table
│   │   ├── archive_dialog.cpp # compression options & parameters
│   │   └── progress_dialog.cpp# live progress
│   ├── os_integration/
│   │   └── context_menu.cpp   # shell extension registry integration
│   └── utils/
│       ├── file_system.cpp    # long paths (>=65535)
│       └── security.cpp       # Mark of the Web (MOTW) + AES-256 (CNG)
├── docs/FORMAT_WSAR.md        # native RAR5-style container specification
├── scripts/                   # build & deploy helpers
└── .github/workflows/         # CI (windows-latest, MSYS2)
```

## 📚 Native container

`.wrc` (WSAR) is a fully open, RAR5-*inspired* container defined in
[`docs/FORMAT_WSAR.md`](docs/FORMAT_WSAR.md): CRC32-protected headers,
per-file Store/Deflate/LZSS payload, optional AES-256-CBC (CNG) with
PBKDF2-HMAC-SHA256 (200k iterations), encrypt-then-MAC integrity,
encrypted file names and native multi-volume support.
It is **not** bit-compatible with proprietary RAR5 — that is intentional and legal.

> Note: the images in the original specification are illustrative mock-ups of the
> proposed UI, not official screenshots of any commercial program.
