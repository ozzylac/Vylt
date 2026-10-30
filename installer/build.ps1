# Builds a signed MSIX package of Vylt, which gives the app the package identity Windows
# requires to use it as a passkey provider. First run creates a self-signed certificate; the
# resulting .cer must be imported once into "Trusted People" (the script offers to do it).
#
#   powershell -ExecutionPolicy Bypass -File installer\msix\build.ps1
#
# Output: target\installer\Vylt-0.1.1.0.msix (+ Vylt-selfsign.cer the first time).

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$root = Split-Path (Split-Path $here -Parent) -Parent
Set-Location $root

$version = "0.1.0.0"
$publisher = "CN=ozzylac"
$out = Join-Path $root "target\installer"
$stage = Join-Path $out "msix-stage"
New-Item -ItemType Directory -Force $out, $stage, (Join-Path $stage "assets") | Out-Null

# 1. Release build.
$env:PATH = "$HOME\.cargo\bin;$env:PATH"
$ErrorActionPreference = "Continue"
cargo build --release --locked
if ($LASTEXITCODE) { throw "cargo build failed" }
$ErrorActionPreference = "Stop"

# 2. Stage payload: exe + manifest + scaled logos (from assets\icon.png).
Copy-Item (Join-Path $root "target\release\vylt.exe") $stage -Force
Copy-Item (Join-Path $here "AppxManifest.xml") $stage -Force
Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Image]::FromFile((Join-Path $root "assets\icon.png"))
foreach ($s in @(@{n="Square44x44Logo";px=44}, @{n="Square150x150Logo";px=150}, @{n="StoreLogo";px=50})) {
    $bmp = New-Object System.Drawing.Bitmap($s.px, $s.px)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.DrawImage($icon, 0, 0, $s.px, $s.px)
    $bmp.Save((Join-Path $stage "assets\$($s.n).png"), [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}
$icon.Dispose()

# 3. Locate the Windows SDK tools.
function Find-SdkTool($name) {
    $hit = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\$name" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $hit) { throw "$name not found (install the Windows 10/11 SDK)" }
    $hit.FullName
}
$makeappx = Find-SdkTool "makeappx.exe"
$signtool = Find-SdkTool "signtool.exe"

# 4. Pack.
$msix = Join-Path $out "Vylt-$version.msix"
& $makeappx pack /o /d $stage /p $msix
if ($LASTEXITCODE) { throw "makeappx failed" }

# 5. Self-signed certificate (created once, reused afterwards).
$pfx = Join-Path $out "Vylt-selfsign.pfx"
$cer = Join-Path $out "Vylt-selfsign.cer"
$pwd = ConvertTo-SecureString "vylt-dev" -AsPlainText -Force
if (-not (Test-Path $pfx)) {
    $cert = New-SelfSignedCertificate -Type Custom -Subject $publisher -KeyUsage DigitalSignature `
        -FriendlyName "Vylt self-signed" -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
    Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd | Out-Null
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    Write-Host "Created $cer — import it once (the script can do it below)." -ForegroundColor Yellow
}

# 6. Sign.
& $signtool sign /fd SHA256 /a /f $pfx /p "vylt-dev" $msix
if ($LASTEXITCODE) { throw "signtool failed" }

Write-Host "`nPackage: $msix" -ForegroundColor Green
Write-Host "Certificate: $cer"
Write-Host "To install on this PC (needs an elevated PowerShell the first time, for the cert):"
Write-Host "  Import-Certificate -FilePath `"$cer`" -CertStoreLocation Cert:\LocalMachine\TrustedPeople"
Write-Host "  Add-AppxPackage -Path `"$msix`""
Write-Host "Then enable Vylt in Settings > Accounts > Passkeys, or from the app."
Get-FileHash $msix -Algorithm SHA256 | Format-List Algorithm, Hash, Path
