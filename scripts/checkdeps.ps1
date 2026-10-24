$ErrorActionPreference = 'Continue'
$have = @{}
Get-ChildItem D:\winrarsetup\dist\*.dll | ForEach-Object { $have[$_.Name.ToLower()] = $true }
# Windows system DLLs (always resolvable from System32)
$system = @('advapi32.dll','kernel32.dll','msvcrt.dll','ole32.dll','shell32.dll','user32.dll',
    'gdi32.dll','dwmapi.dll','uxtheme.dll','d3d11.dll','dxgi.dll','wtsapi32.dll','imm32.dll',
    'shcore.dll','oleaut32.dll','winmm.dll','ws2_32.dll','ntdll.dll','sechost.dll',
    'rpcrt4.dll','ucrtbase.dll','combase.dll','msimg32.dll','opengl32.dll','glu32.dll',
    'wintrust.dll','crypt32.dll','ncrypt.dll','bcrypt.dll','bcryptprimitives.dll',
    'shlwapi.dll','version.dll','win32u.dll','gdi32full.dll','wldp.dll','ntmarta.dll',
    'xmllite.dll','dwrite.dll','d3d12.dll','userenv.dll','netapi32.dll','secur32.dll',
    'authz.dll','winhttp.dll','dnsapi.dll','iphlpapi.dll','mpr.dll','kernelbase.dll',
    'usp10.dll')
$missing = @{}
Get-ChildItem D:\winrarsetup\dist\*.dll | ForEach-Object {
    $exe = $_.FullName
    $imports = & D:\msys64\mingw64\bin\objdump.exe -p $exe | Select-String 'DLL Name'
    foreach ($line in $imports) {
        $n = ($line.ToString().Trim() -replace 'DLL Name: ', '').ToLower()
        if (-not $have.ContainsKey($n) -and $system -notcontains $n) {
            $missing[$n] = $_.Name
        }
    }
}
if ($missing.Count) {
    Write-Host "MISSING DLLs:"
    $missing.GetEnumerator() | ForEach-Object { Write-Host "  $($_.Key)  (needed by $($_.Value))" }
} else {
    Write-Host "no missing DLLs"
}
