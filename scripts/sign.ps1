# Authenticode-sign files with signtool (used by the release pipeline and by ISCC for Setup.exe).
#
#   scripts\sign.ps1 <file> [<file> ...]
#
# The certificate comes from the environment, never from the command line (ISCC echoes
# sign-tool command lines into the build log):
#   SIGNING_CERT_PFX_BASE64   base64-encoded .pfx (code-signing certificate with private key)
#   SIGNING_CERT_PASSWORD     its password
#   SIGNING_TIMESTAMP_URL     RFC 3161 timestamp server (default: DigiCert)
param([Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Files)

$ErrorActionPreference = 'Stop'
if (-not $env:SIGNING_CERT_PFX_BASE64) { throw "SIGNING_CERT_PFX_BASE64 is not set" }
$timestamp = if ($env:SIGNING_TIMESTAMP_URL) { $env:SIGNING_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }

# Newest x64 signtool from the installed Windows SDKs.
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object { [version]($_.Directory.Parent.Name) } | Select-Object -Last 1 -ExpandProperty FullName
if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK)" }

$pfx = Join-Path ([IO.Path]::GetTempPath()) ("promailer-sign-{0}.pfx" -f [guid]::NewGuid())
try {
    [IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:SIGNING_CERT_PFX_BASE64))
    $signArgs = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $timestamp,
        '/d', 'Promailer', '/du', 'https://github.com/parthh37/promailer', '/f', $pfx)
    if ($env:SIGNING_CERT_PASSWORD) { $signArgs += @('/p', $env:SIGNING_CERT_PASSWORD) }
    # Timestamp servers fail transiently; retry before giving up.
    for ($attempt = 1; ; $attempt++) {
        & $signtool @signArgs @Files
        if ($LASTEXITCODE -eq 0) { break }
        if ($attempt -ge 3) { throw "signtool failed with exit code $LASTEXITCODE" }
        Start-Sleep -Seconds (10 * $attempt)
    }
} finally {
    Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}

foreach ($f in $Files) {
    $sig = Get-AuthenticodeSignature $f
    if (-not $sig.SignerCertificate) { throw "$f has no Authenticode signature after signing" }
    Write-Host "Signed $f by $($sig.SignerCertificate.Subject) [$($sig.Status)]"
}
