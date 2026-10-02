$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python      = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Script      = Join-Path $ProjectRoot "scripts\reconnaissance\directory.py"
$LogDir      = Join-Path $ProjectRoot ".runtime\logs"
$PidFile     = Join-Path $LogDir "directory-discover.pid"

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

if (Test-Path $PidFile) {
    $ExistingPid = Get-Content $PidFile -ErrorAction SilentlyContinue

    if ($ExistingPid -and (Get-Process -Id $ExistingPid -ErrorAction SilentlyContinue)) {
        Write-Host "Directory discovery masih berjalan. PID: $ExistingPid"
        exit 1
    }

    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$StdoutLog = Join-Path $LogDir "directory-discover-$Timestamp.log"
$StderrLog = Join-Path $LogDir "directory-discover-$Timestamp-error.log"

# Quote the Python script path so paths containing spaces are handled correctly.
$Arguments = @(
    "`"$Script`""
    "discover"
    "--wordlist-id"
    "common"
    "--max-requests"
    "28512"
)

$Process = Start-Process `
    -FilePath $Python `
    -ArgumentList $Arguments `
    -WorkingDirectory $ProjectRoot `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError $StderrLog `
    -WindowStyle Hidden `
    -PassThru

$Process.Id | Set-Content $PidFile -Encoding ascii

Write-Host ""
Write-Host "Directory discovery started."
Write-Host "PID     : $($Process.Id)"
Write-Host "Wordlist: common"
Write-Host "Budget  : 28512 requests"
Write-Host "Log     : $StdoutLog"
Write-Host "Error   : $StderrLog"
Write-Host ""
Write-Host "Monitor PID:"
Write-Host "  Get-Process -Id $($Process.Id)"
Write-Host ""
Write-Host "Follow log:"
Write-Host "  Get-Content `"$StdoutLog`" -Wait"
Write-Host ""
Write-Host "Follow error log:"
Write-Host "  Get-Content `"$StderrLog`" -Wait"
Write-Host ""