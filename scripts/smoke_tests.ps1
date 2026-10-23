# smoke_tests.ps1 - full engine test battery
$ErrorActionPreference = 'Continue'
Set-Location D:\winrarsetup\build
$env:PATH = "D:\msys64\mingw64\bin;$env:PATH"
$script:pass = 0
$script:fail = 0
function Check($name, $cond) {
    if ($cond) { $script:pass++; Write-Host "PASS: $name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "FAIL: $name" -ForegroundColor Red }
}

Remove-Item ..\test_data\t_* -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path ..\test_data\t_out | Out-Null

# 1) round-trips for all formats
foreach ($fmt in @('wsar', 'zip', '7z')) {
    $ext = @{ wsar = 'wrc'; zip = 'zip'; z7 = '7z' }[$fmt]
    if ($fmt -eq '7z') { $ext = '7z' }
    $arc = "..\test_data\t_$fmt.$ext"
    .\wrclone.exe a $arc ..\test_data\hello.txt ..\test_data\sub -m5 --format $fmt
    .\wrclone.exe t $arc
    .\wrclone.exe x $arc -o "..\test_data\t_out\$fmt"
    $same = (Get-Content "..\test_data\t_out\$fmt\sub\repetitive.txt" -Raw) -ceq (Get-Content ..\test_data\sub\repetitive.txt -Raw)
    Check "$fmt round-trip" $same
}

# 2) encryption round-trip
.\wrclone.exe a ..\test_data\t_enc.wrc ..\test_data\sub -m3 -hp "S3cret!" --dict 4M
.\wrclone.exe t ..\test_data\t_enc.wrc -p "S3cret!"
.\wrclone.exe x ..\test_data\t_enc.wrc -o ..\test_data\t_out\enc -p "S3cret!"
Check "AES-256 round-trip" ((Get-Content "..\test_data\t_out\enc\sub\repetitive.txt" -Raw) -ceq (Get-Content ..\test_data\sub\repetitive.txt -Raw))
$wrong = .\wrclone.exe t ..\test_data\t_enc.wrc -p "wrong" 2>&1
Check "wrong password rejected" ($LASTEXITCODE -ne 0)

# 3) multi-volume
.\wrclone.exe a ..\test_data\t_vols.wrc ..\test_data\sub -m1 -v 100
$parts = (Get-ChildItem ..\test_data\t_vols.part*.wrc).Count
.\wrclone.exe x ..\test_data\t_vols.wrc -o ..\test_data\t_out\vols
Check "multi-volume split+join" (($parts -gt 1) -and ((Get-Content "..\test_data\t_out\vols\sub\repetitive.txt" -Raw) -ceq (Get-Content ..\test_data\sub\repetitive.txt -Raw)))

# 4) delete + append
.\wrclone.exe a ..\test_data\t_app.wrc ..\test_data\hello.txt -m1
.\wrclone.exe d ..\test_data\t_app.wrc "hello.txt"
.\wrclone.exe l ..\test_data\t_app.wrc
Check "delete entries" ($LASTEXITCODE -eq 0)

# 5) MOTW propagation
.\wrclone.exe a ..\test_data\t_dl.wrc ..\test_data\hello.txt -m1
Set-Content -Path (Resolve-Path ..\test_data\t_dl.wrc) -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3"
.\wrclone.exe x ..\test_data\t_dl.wrc -o ..\test_data\t_out\motw
$zm = Get-Content -Path "..\test_data\t_out\motw\hello.txt" -Stream Zone.Identifier -ErrorAction SilentlyContinue
Check "MOTW propagated" ($zm -like "*ZoneId=3*")

# 6) long path (>260 chars)
$deep = "D:\winrarsetup\test_data\t_out\long"
$p = $deep
for ($i = 0; $i -lt 12; $i++) { $p += "\directory_level_with_a_long_name_abcdefghijklmnopqrstuvwxyz_0123456789" }
New-Item -ItemType Directory -Force -Path ("\\?\" + $p) | Out-Null
Set-Content -LiteralPath ("\\?\" + $p + "\deepfile.txt") -Value "deep content!" -Encoding utf8
.\wrclone.exe a ..\test_data\t_long.wrc $p\deepfile.txt -m1
.\wrclone.exe x ..\test_data\t_long.wrc -o ..\test_data\t_out\longx
Check "long path (>260) archive+extract" ($LASTEXITCODE -eq 0)

Write-Host ""
Write-Host "TOTAL: pass=$pass fail=$fail" -ForegroundColor Cyan
