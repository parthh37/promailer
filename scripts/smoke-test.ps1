# End-to-end smoke test of a built installer (Setup.exe or MSI) on a clean Windows machine,
# used by the release pipeline. Installs silently, configures a local domain and a TLS
# certificate from the Windows certificate store, starts the service, sends mail via SMTP,
# STARTTLS and the Pickup directory, verifies Drop-directory delivery and Event Log entries,
# switches certificates with a hot reload, checks start-up failure reporting, then uninstalls.
param([Parameter(Mandatory = $true)][string]$Installer)

$ErrorActionPreference = 'Stop'
$isMsi = [IO.Path]::GetExtension($Installer) -eq '.msi'
$app = Join-Path $env:ProgramFiles 'Promailer'
$exe = Join-Path $app 'promailer.exe'
$data = Join-Path $env:ProgramData 'Promailer'
$config = Join-Path $data 'promailer.toml'
$sourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Promailer'
$started = Get-Date
$createdCerts = @()

function Step($msg) { Write-Host "`n=== $msg" -ForegroundColor Cyan }
function Fail($msg) {
    Write-Host "SMOKE TEST FAILED: $msg" -ForegroundColor Red
    Get-ChildItem (Join-Path $data 'logs') -Filter *.log -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "--- $($_.Name)"; Get-Content $_.FullName -Tail 40
    }
    $svcErr = Join-Path $env:TEMP 'promailer-service-error.log'
    if (Test-Path $svcErr) { Get-Content $svcErr }
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Promailer'; StartTime = $started } -ErrorAction Stop |
            Format-List TimeCreated, Id, LevelDisplayName, Message | Out-String | Write-Host
    } catch { Write-Host "(no Promailer events: $_)" }
    foreach ($log in 'install.log', 'msi-install.log', 'msi-uninstall.log') {
        if (-not (Test-Path $log)) { continue }
        Write-Host "--- $log"
        # In MSI logs the action that failed is the one followed by "Return value 3".
        Select-String -Path $log -Pattern 'Return value 3' -Context 40, 3 | Select-Object -First 1 | Out-String | Write-Host
        Get-Content $log -Tail 60
    }
    exit 1
}

# Wait for a Promailer Application-log event (since this test started) whose text matches.
function Expect-Event([int]$Id, [string]$Pattern) {
    $deadline = (Get-Date).AddSeconds(20)
    do {
        # Get-WinEvent throws (even with SilentlyContinue) when nothing matches or the source is missing.
        $events = @(try { Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Promailer'; Id = $Id; StartTime = $started } -ErrorAction Stop } catch { })
        $match = $events | Where-Object { $_.Message -match $Pattern } | Select-Object -First 1
        if ($match) { Write-Host "Event $Id ok: $(($match.Message -split "`n")[0])"; return $match }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    $seen = ($events | ForEach-Object { $_.Message }) -join ' | '
    Fail "Event Log entry $Id matching '$Pattern' not found (seen: $seen)"
}

function Set-Thumbprint([string]$Value) {
    $text = Get-Content $config -Raw
    $text = $text -replace '(?m)^thumbprint = .*$', "thumbprint = `"$Value`""
    Set-Content -Path $config -Value $text -Encoding utf8NoBOM
}

# STARTTLS on port 587; asserts the server presents the certificate with this thumbprint.
function Test-StartTls([string]$Thumbprint, [string]$Subject) {
    $env:EXPECT_THUMBPRINT = $Thumbprint
    $env:MAIL_SUBJECT = $Subject
    @'
import hashlib, os, smtplib, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with smtplib.SMTP("127.0.0.1", 587, timeout=30) as s:
    s.ehlo("ci.example.test")
    s.starttls(context=ctx)
    der = s.sock.getpeercert(binary_form=True)
    got = hashlib.sha1(der).hexdigest().upper()
    print(f"{s.sock.version()} {s.sock.cipher()[0]} certificate {got}")
    assert got == os.environ["EXPECT_THUMBPRINT"], f"expected {os.environ['EXPECT_THUMBPRINT']}"
    s.ehlo("ci.example.test")
    subject = os.environ["MAIL_SUBJECT"]
    s.sendmail("app@example.test", ["tls@example.test"],
               f"From: app@example.test\r\nTo: tls@example.test\r\nSubject: {subject}\r\n\r\nhello\r\n")
'@ | python -
    if ($LASTEXITCODE -ne 0) { Fail "STARTTLS with certificate $Thumbprint failed" }
}

function Wait-Drop([int]$Count) {
    $drop = Join-Path $data 'drop'
    $deadline = (Get-Date).AddSeconds(45)
    do {
        Start-Sleep -Seconds 1
        $files = @(Get-ChildItem $drop -Filter *.eml -ErrorAction SilentlyContinue)
    } while ($files.Count -lt $Count -and (Get-Date) -lt $deadline)
    if ($files.Count -lt $Count) { Fail "expected $Count delivered messages in Drop, found $($files.Count)" }
    return ($files | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
}

# The pipeline runs this once per installer on the same runner: start from a clean slate.
if (Test-Path $data) { Remove-Item -Recurse -Force $data }

Step "Installing $Installer"
if ($isMsi) {
    $p = Start-Process msiexec.exe -ArgumentList '/i', "`"$Installer`"", '/qn', '/norestart', '/l*v', 'msi-install.log', 'HOSTNAME=Smoke.Example.Test', 'START_SERVICE=0' -Wait -PassThru
} else {
    $p = Start-Process $Installer -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/TASKS="service,!service\start,path"', '/LOG=install.log' -Wait -PassThru
}
if ($p.ExitCode -ne 0) { Fail "installer exit code $($p.ExitCode)" }
if (-not (Test-Path $exe)) { Fail "promailer.exe not installed" }
if (-not (Test-Path $config)) { Fail "default configuration not created" }
if (-not (Get-Service Promailer -ErrorAction SilentlyContinue)) { Fail "service not registered" }
if ((Get-Service Promailer).Status -ne 'Stopped') { Fail "service started although it was asked not to" }
$messageFile = (Get-ItemProperty $sourceKey -ErrorAction SilentlyContinue).EventMessageFile
if ($messageFile -ne $exe) { Fail "Event Log source not registered for $exe (EventMessageFile: '$messageFile')" }
if ($isMsi -and -not (Select-String -Path $config -Pattern '^hostname = "smoke.example.test"' -Quiet)) {
    Fail "MSI did not personalise the configuration with HOSTNAME"
}
& $exe --version

Step "Service configuration"
$qc = (sc.exe qc Promailer) -join "`n"
$qfailure = (sc.exe qfailure Promailer) -join "`n"
$qflag = (sc.exe qfailureflag Promailer) -join "`n"
Write-Host $qc; Write-Host $qfailure; Write-Host $qflag
if ($qc -notmatch 'AUTO_START\s+\(DELAYED\)') { Fail "service is not delayed auto-start" }
if ($qc -notmatch 'service run --config') { Fail "unexpected service command line" }
if (([regex]::Matches($qfailure, 'RESTART')).Count -lt 3) { Fail "service recovery actions are not configured" }
if ($qflag -notmatch 'TRUE') { Fail "recovery actions do not apply to non-crash failures" }

Step "Creating test certificates in LocalMachine\My"
$rsa = New-SelfSignedCertificate -DnsName 'smoke.example.test' -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -FriendlyName 'Promailer smoke RSA'
$ec = New-SelfSignedCertificate -DnsName 'smoke.example.test' -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyAlgorithm ECDSA_nistP256 -KeyExportPolicy NonExportable -FriendlyName 'Promailer smoke ECDSA'
$createdCerts += $rsa, $ec
Write-Host "RSA   $($rsa.Thumbprint)`nECDSA $($ec.Thumbprint)"
$list = (& $exe cert list) -join "`n"
Write-Host $list
foreach ($c in $rsa, $ec) {
    if ($list -notmatch "$($c.Thumbprint)\s+\S+\s+valid\s+yes") { Fail "cert list does not show $($c.Thumbprint) as valid with a usable key" }
}

Step "Configuring local test domain and TLS"
$text = Get-Content $config -Raw
$text = $text -replace 'local_domains = \[\]', 'local_domains = ["example.test"]'
$text = $text -replace 'hostname = "[^"]*"', 'hostname = "smoke.example.test"'
# Submission listener with STARTTLS (inserted before the existing [[listener]] entries).
$submission = "[[listener]]`r`nname = `"submission`"`r`nbind = `"127.0.0.1:587`"`r`ntls = `"starttls`"`r`n`r`n"
$text = ([regex]'(?m)^\[\[listener\]\]').Replace($text, $submission + '[[listener]]', 1)
# Paste the thumbprint the way certlm.msc copies it: invisible U+200E, lower case, spaced pairs.
$pasted = [char]0x200E + (($rsa.Thumbprint.ToLower() -split '(..)' | Where-Object { $_ }) -join ' ')
$text += "`r`n[tls]`r`nthumbprint = `"$pasted`"`r`n"
Set-Content -Path $config -Value $text -Encoding utf8NoBOM
$check = (& $exe config check --config $config) -join "`n"
Write-Host $check
if ($LASTEXITCODE -ne 0) { Fail "config check failed" }
if ($check -notmatch $rsa.Thumbprint) { Fail "config check does not report the store certificate" }

Step "Starting service"
& $exe service start
if ($LASTEXITCODE -ne 0) { Fail "service failed to start" }
if ((Get-Service Promailer).Status -ne 'Running') { Fail "service not running" }
Expect-Event 1000 'Promailer started' | Out-Null

Step "Sending via SMTP, STARTTLS and Pickup"
@'
import smtplib
with smtplib.SMTP("127.0.0.1", 25, timeout=30) as s:
    s.ehlo("ci.example.test")
    s.sendmail("app@example.test", ["smtp@example.test"],
               "From: app@example.test\r\nTo: smtp@example.test\r\nSubject: smoke smtp\r\n\r\nhello\r\n")
print("SMTP accepted")
'@ | python -
if ($LASTEXITCODE -ne 0) { Fail "SMTP submission failed" }
Test-StartTls $rsa.Thumbprint 'smoke tls rsa'
$pickup = Join-Path $data 'pickup\smoke.eml'
"X-Sender: app@example.test`r`nX-Receiver: pickup@example.test`r`nFrom: app@example.test`r`nTo: pickup@example.test`r`nSubject: smoke pickup`r`n`r`nhello`r`n" |
    Set-Content -Path $pickup -NoNewline -Encoding ascii
$all = Wait-Drop 3
foreach ($s in 'smoke smtp', 'smoke pickup', 'smoke tls rsa') {
    if ($all -notmatch $s) { Fail "message '$s' not delivered" }
}
if ($all -notmatch 'by smoke.example.test \(Promailer\)') { Fail "Received header missing" }

Step "Hot reload to an ECDSA certificate"
Set-Thumbprint $ec.Thumbprint
& $exe service reload
Expect-Event 1002 'configuration reloaded' | Out-Null
Expect-Event 1012 $ec.Thumbprint | Out-Null
Test-StartTls $ec.Thumbprint 'smoke tls ecdsa'
Wait-Drop 4 | Out-Null

Step "Legacy CryptoAPI key"
# Certificates imported years ago often keep their key in a legacy CSP rather than a CNG
# key storage provider; CNG opens those keys too (TLS 1.3 / RSA-PSS included).
$csp = New-SelfSignedCertificate -DnsName 'smoke.example.test' -CertStoreLocation 'Cert:\LocalMachine\My' `
    -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable `
    -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -FriendlyName 'Promailer smoke CSP'
$createdCerts += $csp
Set-Thumbprint $csp.Thumbprint
& $exe service reload
Expect-Event 1012 $csp.Thumbprint | Out-Null
Test-StartTls $csp.Thumbprint 'smoke tls csp'
Wait-Drop 5 | Out-Null

Step "Stopping service"
& $exe service stop
if ($LASTEXITCODE -ne 0) { Fail "service failed to stop" }
Expect-Event 1001 'Promailer stopped' | Out-Null

Step "Start-up failure is reported to the Event Log"
$good = Get-Content $config -Raw
Set-Content -Path $config -Value ($good + "`r`nthis is not valid toml`r`n") -Encoding utf8NoBOM -NoNewline
& $exe service start 2>&1 | Out-Host
if ($LASTEXITCODE -eq 0) { Fail "service started with an invalid configuration" }
Expect-Event 1004 'could not start' | Out-Null
Set-Content -Path $config -Value $good -Encoding utf8NoBOM -NoNewline

Step "Uninstalling"
if ($isMsi) {
    $p = Start-Process msiexec.exe -ArgumentList '/x', "`"$Installer`"", '/qn', '/norestart', '/l*v', 'msi-uninstall.log' -Wait -PassThru
} else {
    $p = Start-Process (Join-Path $app 'unins000.exe') -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
}
if ($p.ExitCode -ne 0) { Fail "uninstaller exit code $($p.ExitCode)" }
Start-Sleep -Seconds 3
if (Get-Service Promailer -ErrorAction SilentlyContinue) { Fail "service still registered after uninstall" }
if (-not (Test-Path $config)) { Fail "configuration was removed by uninstall (must be kept)" }
if (Test-Path $sourceKey) { Fail "Event Log source still registered after uninstall" }
$createdCerts | ForEach-Object { Remove-Item "Cert:\LocalMachine\My\$($_.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue }

Write-Host "`nSMOKE TEST PASSED ($([IO.Path]::GetFileName($Installer)))" -ForegroundColor Green
# Explicit: the Actions pwsh wrapper would otherwise exit with the last native exit code
# (the deliberately failed `service start` above).
exit 0
