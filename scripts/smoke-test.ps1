# End-to-end smoke test of a built installer on a clean Windows machine (used by the release pipeline).
# Installs the setup silently, configures a local domain, starts the service, sends mail via SMTP
# and the Pickup directory, verifies Drop-directory delivery, exercises reload, then uninstalls.
param([Parameter(Mandatory = $true)][string]$Installer)

$ErrorActionPreference = 'Stop'
$app = Join-Path $env:ProgramFiles 'Promailer'
$exe = Join-Path $app 'promailer.exe'
$data = Join-Path $env:ProgramData 'Promailer'
$config = Join-Path $data 'promailer.toml'

function Step($msg) { Write-Host "`n=== $msg" -ForegroundColor Cyan }
function Fail($msg) {
    Write-Host "SMOKE TEST FAILED: $msg" -ForegroundColor Red
    Get-ChildItem (Join-Path $data 'logs') -Filter *.log -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "--- $($_.Name)"; Get-Content $_.FullName -Tail 40
    }
    $svcErr = Join-Path $env:TEMP 'promailer-service-error.log'
    if (Test-Path $svcErr) { Get-Content $svcErr }
    if (Test-Path install.log) { Get-Content install.log -Tail 60 }
    exit 1
}

Step "Installing $Installer"
$p = Start-Process $Installer -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/TASKS="service,!service\start,path"', '/LOG=install.log' -Wait -PassThru
if ($p.ExitCode -ne 0) { Fail "installer exit code $($p.ExitCode)" }
if (-not (Test-Path $exe)) { Fail "promailer.exe not installed" }
if (-not (Test-Path $config)) { Fail "default configuration not created" }
if (-not (Get-Service Promailer -ErrorAction SilentlyContinue)) { Fail "service not registered" }
& $exe --version

Step "Configuring local test domain"
$text = Get-Content $config -Raw
$text = $text -replace 'local_domains = \[\]', 'local_domains = ["example.test"]'
$text = $text -replace 'hostname = "[^"]*"', 'hostname = "smoke.example.test"'
Set-Content -Path $config -Value $text -Encoding ascii
& $exe config check --config $config
if ($LASTEXITCODE -ne 0) { Fail "config check failed" }

Step "Starting service"
& $exe service start
if ($LASTEXITCODE -ne 0) { Fail "service failed to start" }
if ((Get-Service Promailer).Status -ne 'Running') { Fail "service not running" }

Step "Sending via SMTP and Pickup"
$py = @'
import smtplib
with smtplib.SMTP("127.0.0.1", 25, timeout=30) as s:
    s.ehlo("ci.example.test")
    s.sendmail("app@example.test", ["smtp@example.test"],
               "From: app@example.test\r\nTo: smtp@example.test\r\nSubject: smoke smtp\r\n\r\nhello\r\n")
print("SMTP accepted")
'@
$py | python -
if ($LASTEXITCODE -ne 0) { Fail "SMTP submission failed" }
$pickup = Join-Path $data 'pickup\smoke.eml'
"X-Sender: app@example.test`r`nX-Receiver: pickup@example.test`r`nFrom: app@example.test`r`nTo: pickup@example.test`r`nSubject: smoke pickup`r`n`r`nhello`r`n" |
    Set-Content -Path $pickup -NoNewline -Encoding ascii

$drop = Join-Path $data 'drop'
$deadline = (Get-Date).AddSeconds(45)
do {
    Start-Sleep -Seconds 1
    $files = @(Get-ChildItem $drop -Filter *.eml -ErrorAction SilentlyContinue)
} while ($files.Count -lt 2 -and (Get-Date) -lt $deadline)
if ($files.Count -lt 2) { Fail "expected 2 delivered messages in Drop, found $($files.Count)" }
$all = ($files | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
if ($all -notmatch 'smoke smtp' -or $all -notmatch 'smoke pickup') { Fail "delivered messages have unexpected content" }
if ($all -notmatch 'by smoke.example.test \(Promailer\)') { Fail "Received header missing" }
Write-Host "Delivered: $($files.Name -join ', ')"

Step "Hot reload"
& $exe service reload
Start-Sleep -Seconds 2
$log = Get-ChildItem (Join-Path $data 'logs') -Filter 'promailer*.log' | Sort-Object LastWriteTime | Select-Object -Last 1
if (-not (Select-String -Path $log.FullName -Pattern 'configuration reloaded' -Quiet)) { Fail "reload not observed in log" }

Step "Uninstalling"
$p = Start-Process (Join-Path $app 'unins000.exe') -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART' -Wait -PassThru
Start-Sleep -Seconds 3
if (Get-Service Promailer -ErrorAction SilentlyContinue) { Fail "service still registered after uninstall" }
if (-not (Test-Path $config)) { Fail "configuration was removed by uninstall (must be kept)" }

Write-Host "`nSMOKE TEST PASSED" -ForegroundColor Green
