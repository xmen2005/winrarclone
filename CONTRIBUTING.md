# Contributing to WinRAR Clone Engine

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository and clone your fork.
2. Install the toolchain (MSYS2 / MinGW-w64 + Qt 6):
   ```powershell
   D:\msys64\usr\bin\bash.exe -lc "pacman -S --needed --noconfirm \
     mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
     mingw-w64-x86_64-qt6-base mingw-w64-x86_64-qt6-tools \
     mingw-w64-x86_64-zlib mingw-w64-x86_64-libarchive"
   ```
3. Build:
   ```powershell
   .\scripts\build_msys2.ps1
   ```
4. Run tests:
   ```powershell
   cd build; ctest --output-on-failure
   ```

## Code Style

- C++20, follow existing naming (`camelCase` for functions, `PascalCase` for types).
- Keep core engine (`src/core`) free of Qt dependencies.
- Add unit tests for new functionality in `tests/unit_tests.cpp`.

## Pull Requests

- One feature/fix per PR.
- Ensure `ctest` passes and CI is green.
- Update `docs/FORMAT_WSAR.md` if you change the container format.
- Update `README.md` if you add user-facing features.

## Reporting Issues

- Include OS version, build type, and steps to reproduce.
- For crashes, attach the archive (if small) or a minimal reproduction.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
