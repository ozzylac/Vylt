# Builds the release exe, then the installer: target\installer\Vylt-Setup-<version>.exe
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$version = (Select-String -Path Cargo.toml -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches.Groups[1].Value
# cargo reports progress on stderr: do not let PowerShell treat it as a failure.
$ErrorActionPreference = "Continue"
cargo build --release --locked
if ($LASTEXITCODE) { throw "cargo build failed" }
$ErrorActionPreference = "Stop"
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 introuvable (winget install JRSoftware.InnoSetup)" }
& $iscc "/DAppVersion=$version" "installer\vylt.iss"
Get-FileHash "target\installer\Vylt-Setup-$version.exe" -Algorithm SHA256 | Format-List Algorithm, Hash, Path
