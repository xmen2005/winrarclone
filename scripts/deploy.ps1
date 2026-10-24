
# Deploy script — self-contained dist/ with Qt runtime DLLs
# Usage: powershell -ExecutionPolicy Bypass -File scripts\deploy.ps1

param(
    [string]$MsysRoot = 'D:\msys64'
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $repo 'build'
$dist = Join-Path $repo 'dist'

# Validate build outputs
$guiExe = Join-Path $buildDir 'wrclone_gui.exe'
$cliExe = Join-Path $buildDir 'wrclone.exe'

if (!(Test-Path $guiExe)) {
    throw "GUI executable not found: $guiExe. Run scripts\build_msys2.ps1 first."
}
if (!(Test-Path $cliExe)) {
    throw "CLI executable not found: $cliExe. Run scripts\build_msys2.ps1 first."
}

# Locate MSYS2 toolchain and Qt deployment utility
$toolchains = @('ucrt64', 'mingw64')
$deployTool = $null
$toolchain = $null

foreach ($candidate in $toolchains) {
    $bin = Join-Path $MsysRoot "$candidate\bin"

    foreach ($toolName in @('windeployqt.exe', 'windeployqt6.exe')) {
        $candidateTool = Join-Path $bin $toolName

        if (Test-Path $candidateTool) {
            $deployTool = $candidateTool
            $toolchain = $candidate
            break
        }
    }

    if ($deployTool) { break }
}

if (!$deployTool) {
    throw @"
Could not find windeployqt.exe or windeployqt6.exe.
MSYS2 root: $MsysRoot
Checked toolchains: ucrt64, mingw64
Install the Qt tools package for the toolchain used to build the application.
"@
}

$binDir = Join-Path $MsysRoot "$toolchain\bin"
$env:PATH = "$binDir;$env:PATH"

Write-Host "Using toolchain: $toolchain"
Write-Host "Using Qt deploy tool: $deployTool"

# Recreate dist directory
if (Test-Path $dist) {
    Remove-Item -Recurse -Force $dist
}
New-Item -ItemType Directory -Force -Path $dist | Out-Null

Copy-Item $cliExe $dist
Copy-Item $guiExe $dist

# Deploy Qt runtime dependencies
& $deployTool --no-compiler-runtime --no-translations `
    (Join-Path $dist 'wrclone_gui.exe')

if ($LASTEXITCODE -ne 0) {
    throw "Qt deployment failed with exit code $LASTEXITCODE"
}

# Copy additional MSYS2 runtime dependencies when available
$dlls = @(
    'zlib1.dll', 'libarchive-13.dll', 'liblzma-5.dll',
    'libbz2-1.dll', 'libzstd.dll', 'liblz4.dll', 'libb2-1.dll',
    'libcrypto-3-x64.dll', 'libssl-3-x64.dll',
    'libwinpthread-1.dll', 'libgcc_s_seh-1.dll',
    'libstdc++-6.dll', 'libiconv-2.dll', 'libcharset-1.dll',
    'libexpat-1.dll', 'libbrotlidec.dll', 'libbrotlicommon.dll',
    'libdouble-conversion.dll', 'libicuuc78.dll', 'libicuin78.dll',
    'libicudt78.dll', 'libfreetype-6.dll', 'libpng16-16.dll',
    'libharfbuzz-0.dll', 'libgraphite2.dll', 'libglib-2.0-0.dll',
    'libintl-8.dll', 'libpcre2-8-0.dll', 'libpcre2-16-0.dll',
    'libmd4c.dll'
)

foreach ($dll in $dlls) {
    $source = Join-Path $binDir $dll

    if (Test-Path $source) {
        Copy-Item $source $dist -Force
    }
}

Write-Host "`nDeployment completed: $dist" -ForegroundColor Green
