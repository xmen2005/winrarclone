# Changelog

All notable changes to this project will be documented in this file.

## [7.0.0] - 2026-10-24

### Added
- Native WSAR container (RAR5-style) with per-file Store/Deflate/LZSS/Zstd.
- Solid archive mode (single compressed stream over multiple files).
- AES-256-CBC encryption with PBKDF2-HMAC-SHA256 (200k) and encrypted file names.
- ZIP (Zip64) and 7Z (Copy/Deflate) writers.
- Foreign archive extraction via libarchive (RAR, tar, 7z, ...).
- Qt 6 GUI (classic WinRAR layout) with live progress dialog.
- CLI front-end (`wrclone a/x/t/l/r/d`).
- Windows shell integration (HKCU context menu, no admin).
- Long paths up to 65,535 chars (`\\?\`).
- Mark-of-the-Web propagation on extraction.
- Multi-volume archives (`.partNNNNN.wrc`, `.NNN`).
- Repair (rebuild keeping valid entries).
- Embedded application icon and `.wrc` file association.

### Changed
- LZSS: parallel per-file compression, tuned chain depths, hash table 23 bits.
- LZSS output wrapped in Deflate (entropy coding) for Normal/Good/Best.
- Added Zstd codec (method 6) with level control.

### Fixed
- `nothing to archive (inputs not found)` (inputs not passed to ArchiveDialog).
- Context menu "Add/Extract" now shows progress UI.
- libarchive extraction handles sparse files and large blocks.
- WSAR spec frame size corrected (24 → 26 bytes).
- README corrected (no false "solid shared window" claim).

### Security
- MAC verified before decryption; reject on auth failure.
- Random bytes generation checked.
- Zip-slip and hostile-name protection on extraction.
