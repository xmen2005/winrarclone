# Build script — WinRAR Clone (MSYS2 / MinGW-w64 + Qt6)
# Usage: powershell -File scripts\build_msys2.ps1 [-Clean]
param(
    [switch]$Clean,
    [string]$MsysRoot = 'D:\msys64'
)

$ErrorActionPreference = 'Stop'
$env:PATH = "$MsysRoot\mingw64\bin;$MsysRoot\usr\bin;$env:PATH"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

if ($Clean -and (Test-Path build)) { Remove-Item -Recurse -Force build }

cmake -S . -B build -G Ninja `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_PREFIX_PATH="$MsysRoot\mingw64"
if ($LASTEXITCODE -ne 0) { exit 1 }

cmake --build build
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "`nBuild OK -> $repo\build\wrclone_gui.exe" -ForegroundColor Green
Write-Host "Run with: `$env:PATH = `"$MsysRoot\mingw64\bin;`$env:PATH`"; .\build\wrclone_gui.exe"
