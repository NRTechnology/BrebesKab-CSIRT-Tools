$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python      = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Script      = Join-Path $ProjectRoot "scripts\reconnaissance\directory.py"
$LogDir      = Join-Path $ProjectRoot ".runtime\logs"
$PidFile     = Join-Path $LogDir "directory-discover.pid"

if (-not (Test-Path $Python)) {
    throw "Python venv tidak ditemukan: $Python"
}

if (-not (Test-Path $Script)) {
    throw "directory.py tidak ditemukan: $Script"
}

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$StdoutLog = Join-Path $LogDir "directory-discover-$Timestamp.log"
$StderrLog = Join-Path $LogDir "directory-discover-$Timestamp-error.log"

$Arguments = @(
    $Script
    "discover"
)

$Process = Start-Process `
    -FilePath $Python `
    -ArgumentList $Arguments `
    -WorkingDirectory $ProjectRoot `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError $StderrLog `
    -WindowStyle Hidden `
    -PassThru

$Process.Id | Set-Content -Path $PidFile -Encoding ASCII

Write-Host ""
Write-Host "[PASS] Directory discovery dijalankan di background."
Write-Host "PID    : $($Process.Id)"
Write-Host "LOG    : $StdoutLog"
Write-Host "ERROR  : $StderrLog"
Write-Host "PIDFILE: $PidFile"
Write-Host ""
Write-Host "Monitor:"
Write-Host "  Get-Content '$StdoutLog' -Wait"
Write-Host ""
Write-Host "Check process:"
Write-Host "  Get-Process -Id $($Process.Id)"
Write-Host ""