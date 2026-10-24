# Deploy script — self-contained dist/ with Qt runtime DLLs
# Usage: powershell -File scripts\deploy.ps1
param([string]$MsysRoot = 'D:\msys64')

$ErrorActionPreference = 'Stop'
$env:PATH = "$MsysRoot\mingw64\bin;$env:PATH"
$repo = Split-Path -Parent $PSScriptRoot

if (!(Test-Path "$repo\build\wrclone_gui.exe")) { throw "build first (scripts\build_msys2.ps1)" }

$dist = "$repo\dist"
if (Test-Path $dist) { Remove-Item -Recurse -Force $dist }
New-Item -ItemType Directory -Force -Path $dist | Out-Null

Copy-Item "$repo\build\wrclone.exe" $dist
Copy-Item "$repo\build\wrclone_gui.exe" $dist
& "$MsysRoot\mingw64\bin\windeployqt6.exe" --no-compiler-runtime --no-translations `
    "$dist\wrclone_gui.exe"
# core engine runtime deps for the CLI
foreach ($dll in @('zlib1.dll','libarchive-19.dll','liblzma-5.dll','libbz2.dll',
                   'libzstd.dll','liblz4.dll','libb2-1.dll','libcrypto-3-x64.dll',
                   'libssl-3-x64.dll','libwinpthread-1.dll','libgcc_s_seh-1.dll',
                   'libstdc++-6.dll','libxml2-2.dll','libiconv-2.dll','libcharset-1.dll',
                   'libexpat-1.dll','libbrotlidec.dll','libbrotlicommon.dll')) {
    $p = "$MsysRoot\mingw64\bin\$dll"
    if (Test-Path $p) { Copy-Item $p $dist }
}

Write-Host "`nDeployed to $dist" -ForegroundColor Green
