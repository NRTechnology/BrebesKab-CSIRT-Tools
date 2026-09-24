#requires -Version 5.1
<#
.SYNOPSIS
    Health check untuk BrebesKab-CSIRT-Tools.

.DESCRIPTION
    Memeriksa kesiapan runtime, Python project, security tools, OWASP ZAP,
    struktur repository, dan artefak installer tanpa melakukan perubahan
    pada sistem.

    Doctor TIDAK:
      - menginstall software
      - mengubah PATH
      - mengubah registry
      - menjalankan pentest terhadap target
      - menjalankan Nmap/Nuclei/ffuf/ZAP scan
      - membuat atau menghapus artefak project, kecuali file log sementara di .runtime\logs

.PARAMETER Quiet
    Hanya menampilkan ringkasan hasil akhir.

.PARAMETER Json
    Menampilkan hasil dalam JSON ke stdout.

.PARAMETER SkipStructure
    Lewati pemeriksaan struktur repository.

.PARAMETER SkipZAP
    Lewati pemeriksaan OWASP ZAP.

.EXAMPLE
    .\doctor.ps1

.EXAMPLE
    .\doctor.ps1 -Json

.EXAMPLE
    .\doctor.ps1 -Quiet
#>

[CmdletBinding()]
param(
    [switch]$Quiet,
    [switch]$Json,
    [switch]$SkipStructure,
    [switch]$SkipZAP
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.1.4'
$ExpectedPythonMajorMinor = '3.14'
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$LogDirectory = Join-Path $RepositoryRoot '.runtime\logs'
$LogPath = Join-Path $LogDirectory 'doctor.log'

$Results = New-Object System.Collections.Generic.List[object]
$StartedAt = Get-Date

# Persistent log directory is created by Doctor itself when needed.
if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Name,
        [ValidateSet('PASS','FAIL','WARN','SKIP')]
        [string]$Status,
        [string]$Message,
        [string]$Path = ''
    )

    $Results.Add([pscustomobject]@{
        Category = $Category
        Name     = $Name
        Status   = $Status
        Message  = $Message
        Path     = $Path
    }) | Out-Null
}

function Write-Doctor {
    param(
        [string]$Message,
        [ValidateSet('INFO','PASS','FAIL','WARN','STEP','SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $logLine = "[$timestamp] [$Level] $Message"

    try {
        Add-Content -LiteralPath $LogPath -Value $logLine -Encoding UTF8
    }
    catch {
        # Logging must not make the health check fail.
    }

    if ($Quiet -or $Json) {
        return
    }

    switch ($Level) {
        'PASS'    { Write-Host "[PASS] $Message" -ForegroundColor Green }
        'FAIL'    { Write-Host "[FAIL] $Message" -ForegroundColor Red }
        'WARN'    { Write-Host "[WARN] $Message" -ForegroundColor Yellow }
        'STEP'    { Write-Host "`n$Message" -ForegroundColor Cyan }
        'SUCCESS' { Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
        default   { Write-Host "[INFO] $Message" }
    }
}

function Get-CommandPath {
    param([string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    return $null
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory=$true)][string]$Executable,
        [string[]]$Arguments = @()
    )

    $stdoutFile = Join-Path $LogDirectory ("doctor-stdout-" + [guid]::NewGuid().ToString('N') + ".tmp")
    $stderrFile = Join-Path $LogDirectory ("doctor-stderr-" + [guid]::NewGuid().ToString('N') + ".tmp")

    try {
        # PowerShell 5.1 / Start-Process treats an ArgumentList array as a
        # single command-line string. Each argument therefore needs explicit
        # Windows command-line quoting; otherwise paths containing spaces are
        # truncated (for example: C:\Users\wawan\OneDrive\Open Source Projects...).
        $quotedArguments = @()
        foreach ($argument in @($Arguments)) {
            if ($null -eq $argument) {
                $quotedArguments += '""'
                continue
            }

            $text = [string]$argument
            $escaped = $text -replace '(\\*)"', '$1$1\\"'
            $escaped = $escaped -replace '(\\+)$', '$1$1'
            $quotedArguments += '"' + $escaped + '"'
        }

        $argumentList = ($quotedArguments -join ' ')

        $process = Start-Process `
            -FilePath $Executable `
            -ArgumentList $argumentList `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile `
            -ErrorAction Stop

        $stdout = ''
        $stderr = ''

        if (Test-Path -LiteralPath $stdoutFile) {
            $stdoutValue = Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue
            if ($null -ne $stdoutValue) { $stdout = [string]$stdoutValue }
        }

        if (Test-Path -LiteralPath $stderrFile) {
            $stderrValue = Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue
            if ($null -ne $stderrValue) { $stderr = [string]$stderrValue }
        }

        $combined = (($stdout + "`r`n" + $stderr).Trim())

        return [pscustomobject]@{
            Success  = ($process.ExitCode -eq 0)
            ExitCode = $process.ExitCode
            Output   = $combined
            StdOut   = $stdout.Trim()
            StdErr   = $stderr.Trim()
        }
    }
    catch {
        return [pscustomobject]@{
            Success  = $false
            ExitCode = -1
            Output   = $_.Exception.Message
            StdOut   = ''
            StdErr   = $_.Exception.Message
        }
    }
    finally {
        Remove-Item -LiteralPath $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-NativeVersion {
    param(
        [string]$Executable,
        [string[]]$Arguments = @('--version')
    )

    return Invoke-NativeCapture -Executable $Executable -Arguments $Arguments
}

function Find-ExistingPath {
    param([string[]]$Candidates)

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    return $null
}

function Test-Directory {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path -PathType Container) {
        Add-Result $Category $Name 'PASS' 'Directory tersedia.' $Path
        Write-Doctor "$Name -> $Path" 'PASS'
        return $true
    }

    Add-Result $Category $Name 'FAIL' 'Directory tidak ditemukan.' $Path
    Write-Doctor "$Name tidak ditemukan: $Path" 'FAIL'
    return $false
}

function Test-File {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Path
    )

    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Add-Result $Category $Name 'PASS' 'File tersedia.' $Path
        Write-Doctor "$Name -> $Path" 'PASS'
        return $true
    }

    Add-Result $Category $Name 'FAIL' 'File tidak ditemukan.' $Path
    Write-Doctor "$Name tidak ditemukan: $Path" 'FAIL'
    return $false
}

function Test-PythonProject {
    $venvPython = Join-Path $RepositoryRoot '.venv\Scripts\python.exe'

    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        Add-Result 'Runtime' 'Project Python' 'FAIL' 'Python .venv tidak ditemukan.' $venvPython
        Write-Doctor "Project Python tidak ditemukan: $venvPython" 'FAIL'
        return
    }

    $versionResult = Invoke-NativeVersion -Executable $venvPython -Arguments @('--version')

    if (-not $versionResult.Success) {
        Add-Result 'Runtime' 'Project Python' 'FAIL' "Python gagal dijalankan. ExitCode=$($versionResult.ExitCode). $($versionResult.Output)" $venvPython
        Write-Doctor "Project Python gagal dijalankan." 'FAIL'
        return
    }

    $version = $versionResult.Output.Trim()

    if ($version -notmatch '^Python\s+3\.14(\.\d+)?') {
        Add-Result 'Runtime' 'Project Python' 'FAIL' "Versi Python tidak sesuai: $version" $venvPython
        Write-Doctor "Project Python: $version (expected $ExpectedPythonMajorMinor.x)" 'FAIL'
        return
    }

    Add-Result 'Runtime' 'Project Python' 'PASS' $version $venvPython
    Write-Doctor "Project Python: $version" 'PASS'

    $code = @'
import os
import sys

print("executable=" + sys.executable)
print("prefix=" + sys.prefix)
print("base_prefix=" + sys.base_prefix)
print("venv=" + str(sys.prefix != sys.base_prefix))
'@

    $codeFile = Join-Path $LogDirectory ("doctor-python-" + [guid]::NewGuid().ToString('N') + '.py')

    try {
        Set-Content -LiteralPath $codeFile -Value $code -Encoding UTF8
        $integrity = Invoke-NativeCapture -Executable $venvPython -Arguments @($codeFile)

        if (-not $integrity.Success) {
            Add-Result 'Runtime' 'Python venv integrity' 'FAIL' "ExitCode=$($integrity.ExitCode). $($integrity.Output)" $venvPython
            Write-Doctor 'Python venv integrity gagal diverifikasi.' 'FAIL'
            return
        }

        if ($integrity.Output -notmatch 'venv=True') {
            Add-Result 'Runtime' 'Python venv integrity' 'FAIL' "Interpreter tidak terdeteksi sebagai virtual environment. Output: $($integrity.Output)" $venvPython
            Write-Doctor 'Interpreter bukan virtual environment.' 'FAIL'
            return
        }

        Add-Result 'Runtime' 'Python venv integrity' 'PASS' 'sys.prefix berbeda dari sys.base_prefix.' $venvPython
        Write-Doctor 'Python venv integrity OK.' 'PASS'
    }
    catch {
        Add-Result 'Runtime' 'Python venv integrity' 'FAIL' $_.Exception.Message $venvPython
        Write-Doctor 'Python venv integrity gagal.' 'FAIL'
    }
    finally {
        Remove-Item -LiteralPath $codeFile -Force -ErrorAction SilentlyContinue
    }
}

function Test-PythonPackage {
    param(
        [string]$Package,
        [string]$ImportName = $Package
    )

    $venvPython = Join-Path $RepositoryRoot '.venv\Scripts\python.exe'

    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        Add-Result 'Python Packages' $Package 'FAIL' 'Project Python tidak tersedia.' $venvPython
        return
    }

    $codeFile = Join-Path $LogDirectory ("doctor-package-" + [guid]::NewGuid().ToString('N') + '.py')
    $code = "import importlib.util; import sys; sys.exit(0 if importlib.util.find_spec('$ImportName') else 1)"

    try {
        Set-Content -LiteralPath $codeFile -Value $code -Encoding UTF8
        $packageCheck = Invoke-NativeCapture -Executable $venvPython -Arguments @($codeFile)
        $exitCode = $packageCheck.ExitCode

        if ($exitCode -eq 0) {
            Add-Result 'Python Packages' $Package 'PASS' 'Python module tersedia.' $venvPython
            Write-Doctor "Python package: $Package" 'PASS'
        }
        else {
            Add-Result 'Python Packages' $Package 'FAIL' 'Python module tidak ditemukan.' $venvPython
            Write-Doctor "Python package tidak ditemukan: $Package" 'FAIL'
        }
    }
    catch {
        Add-Result 'Python Packages' $Package 'FAIL' $_.Exception.Message $venvPython
        Write-Doctor "Python package gagal diperiksa: $Package" 'FAIL'
    }
    finally {
        Remove-Item -LiteralPath $codeFile -Force -ErrorAction SilentlyContinue
    }
}

function Test-Tool {
    param(
        [string]$Name,
        [string]$DisplayName,
        [string]$Executable,
        [string[]]$VersionArguments = @('--version')
    )

    if ([string]::IsNullOrWhiteSpace($Executable)) {
        Add-Result 'Security Tools' $DisplayName 'FAIL' 'Executable tidak ditemukan.' ''
        Write-Doctor "$DisplayName tidak ditemukan." 'FAIL'
        return
    }

    $result = Invoke-NativeVersion -Executable $Executable -Arguments $VersionArguments

    if ($result.Success) {
        $firstLine = ($result.Output -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
        if ([string]::IsNullOrWhiteSpace($firstLine)) {
            $firstLine = 'Version command berhasil.'
        }

        Add-Result 'Security Tools' $DisplayName 'PASS' $firstLine $Executable
        Write-Doctor "$DisplayName OK: $firstLine" 'PASS'
    }
    else {
        Add-Result 'Security Tools' $DisplayName 'FAIL' "ExitCode=$($result.ExitCode). $($result.Output)" $Executable
        Write-Doctor "$DisplayName gagal diverifikasi." 'FAIL'
    }
}

function Find-Zap {
    $candidates = @(
        'C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe',
        'C:\Program Files (x86)\ZAP\Zed Attack Proxy\ZAP.exe'
    )

    $cmd = Get-CommandPath 'ZAP.exe'
    if ($cmd) {
        $candidates += $cmd
    }

    $found = Find-ExistingPath -Candidates $candidates

    if ($found) {
        return $found
    }

    $registryRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($root in $registryRoots) {
        try {
            $items = Get-ItemProperty $root -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -and $_.DisplayName -match 'OWASP ZAP|Zed Attack Proxy'
                }

            foreach ($item in $items) {
                if ($item.InstallLocation) {
                    $candidate = Join-Path $item.InstallLocation 'ZAP.exe'
                    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                        return (Resolve-Path -LiteralPath $candidate).Path
                    }
                }
            }
        }
        catch {
            # Registry detection is optional; continue with other candidates.
        }
    }

    return $null
}

function Test-ZAP {
    if ($SkipZAP) {
        Add-Result 'Security Tools' 'OWASP ZAP' 'SKIP' 'Pemeriksaan ZAP dilewati oleh parameter.'
        Write-Doctor 'OWASP ZAP dilewati.' 'WARN'
        return
    }

    $zap = Find-Zap

    if (-not $zap) {
        Add-Result 'Security Tools' 'OWASP ZAP' 'FAIL' 'ZAP.exe tidak ditemukan.'
        Write-Doctor 'OWASP ZAP tidak ditemukan.' 'FAIL'
        return
    }

    try {
        $fileVersion = (Get-Item -LiteralPath $zap -ErrorAction Stop).VersionInfo.FileVersion
        $productVersion = (Get-Item -LiteralPath $zap -ErrorAction Stop).VersionInfo.ProductVersion

        if ([string]::IsNullOrWhiteSpace($fileVersion) -and [string]::IsNullOrWhiteSpace($productVersion)) {
            Add-Result 'Security Tools' 'OWASP ZAP' 'PASS' 'ZAP.exe ditemukan. Versi file tidak tersedia pada metadata executable.' $zap
            Write-Doctor "OWASP ZAP executable ditemukan: $zap" 'PASS'
            return
        }

        $versionText = if (-not [string]::IsNullOrWhiteSpace($productVersion)) { $productVersion } else { $fileVersion }
        Add-Result 'Security Tools' 'OWASP ZAP' 'PASS' "ZAP.exe ditemukan. Version=$versionText" $zap
        Write-Doctor "OWASP ZAP OK: Version=$versionText" 'PASS'
    }
    catch {
        Add-Result 'Security Tools' 'OWASP ZAP' 'FAIL' "ZAP.exe ditemukan tetapi metadata executable gagal dibaca: $($_.Exception.Message)" $zap
        Write-Doctor 'OWASP ZAP ditemukan tetapi metadata verification gagal.' 'FAIL'
    }
}

function Test-Structure {
    if ($SkipStructure) {
        Add-Result 'Project Structure' 'Repository structure' 'SKIP' 'Pemeriksaan struktur dilewati oleh parameter.'
        Write-Doctor 'Pemeriksaan struktur repository dilewati.' 'WARN'
        return
    }

    $directories = @(
        @{ Name = 'scripts/'; Path = (Join-Path $RepositoryRoot 'scripts') },
        @{ Name = 'tools/'; Path = (Join-Path $RepositoryRoot 'tools') },
        @{ Name = 'tools/api/'; Path = (Join-Path $RepositoryRoot 'tools\api') },
        @{ Name = 'tools/infrastructure/'; Path = (Join-Path $RepositoryRoot 'tools\infrastructure') },
        @{ Name = 'tools/recon/'; Path = (Join-Path $RepositoryRoot 'tools\recon') },
        @{ Name = 'tools/reporting/'; Path = (Join-Path $RepositoryRoot 'tools\reporting') },
        @{ Name = 'tools/tls/'; Path = (Join-Path $RepositoryRoot 'tools\tls') },
        @{ Name = 'tools/web/'; Path = (Join-Path $RepositoryRoot 'tools\web') },
        @{ Name = 'profiles/'; Path = (Join-Path $RepositoryRoot 'profiles') },
        @{ Name = 'evidence/'; Path = (Join-Path $RepositoryRoot 'evidence') },
        @{ Name = 'reports/'; Path = (Join-Path $RepositoryRoot 'reports') },
        @{ Name = 'projects/'; Path = (Join-Path $RepositoryRoot 'projects') }
    )

    foreach ($item in $directories) {
        [void](Test-Directory -Category 'Project Structure' -Name $item.Name -Path $item.Path)
    }

    $requiredFiles = @(
        'README.md',
        'LICENSE',
        'SECURITY.md',
        'CONTRIBUTING.md',
        'scripts\install-requirements.ps1',
        'scripts\doctor.ps1',
        'scripts\pentest.ps1',
        'scripts\update.ps1'
    )

    foreach ($relative in $requiredFiles) {
        $path = Join-Path $RepositoryRoot $relative
        $display = $relative -replace '\\','/'
        [void](Test-File -Category 'Project Structure' -Name $display -Path $path)
    }
}

function Test-InstallerState {
    $statePath = Join-Path $RepositoryRoot '.runtime\state\install-state.json'

    if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
        Add-Result 'Installer State' 'Install state' 'WARN' 'install-state.json belum ditemukan. Jalankan installer jika dependency belum pernah disiapkan.' $statePath
        Write-Doctor 'Installer state belum ditemukan.' 'WARN'
        return
    }

    try {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json

        if ($state.schema_version) {
            Add-Result 'Installer State' 'Install state' 'PASS' "schema_version=$($state.schema_version)" $statePath
            Write-Doctor "Installer state OK: schema_version=$($state.schema_version)" 'PASS'
        }
        else {
            Add-Result 'Installer State' 'Install state' 'WARN' 'install-state.json ada tetapi schema_version tidak ditemukan.' $statePath
            Write-Doctor 'Installer state ada tetapi schema_version tidak ditemukan.' 'WARN'
        }
    }
    catch {
        Add-Result 'Installer State' 'Install state' 'FAIL' "JSON tidak valid: $($_.Exception.Message)" $statePath
        Write-Doctor 'install-state.json tidak valid.' 'FAIL'
    }
}

function Test-PATHVisibility {
    param(
        [string]$Name,
        [string]$ExpectedPath
    )

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $effectivePath = "$userPath;$machinePath"

    $normalizedExpected = $ExpectedPath.TrimEnd('\')

    $found = $false
    foreach ($part in ($effectivePath -split ';')) {
        if ($part.TrimEnd('\') -ieq $normalizedExpected) {
            $found = $true
            break
        }
    }

    if ($found) {
        Add-Result 'Environment' $Name 'PASS' 'Directory terdaftar pada User/Machine PATH.' $ExpectedPath
        Write-Doctor "$Name PATH OK." 'PASS'
    }
    else {
        Add-Result 'Environment' $Name 'WARN' 'Directory tidak ditemukan pada User/Machine PATH. Tool tetap dapat digunakan melalui path project.' $ExpectedPath
        Write-Doctor "$Name tidak ada di PATH. Ini bukan failure karena tool disimpan secara lokal di repository." 'WARN'
    }
}

function Print-Summary {
    $passCount = @($Results | Where-Object { $_.Status -eq 'PASS' }).Count
    $failCount = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warnCount = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
    $skipCount = @($Results | Where-Object { $_.Status -eq 'SKIP' }).Count

    $duration = (Get-Date) - $StartedAt

    if ($Json) {
        $summary = [pscustomobject]@{
            tool = 'BrebesKab-CSIRT-Tools Doctor'
            version = $ScriptVersion
            repository = $RepositoryRoot
            log_path = $LogPath
            started_at = $StartedAt.ToString('o')
            duration_seconds = [math]::Round($duration.TotalSeconds, 2)
            result = if ($failCount -eq 0) { 'PASS' } else { 'FAIL' }
            counts = [pscustomobject]@{
                pass = $passCount
                fail = $failCount
                warn = $warnCount
                skip = $skipCount
            }
            checks = @($Results)
        }

        $summary | ConvertTo-Json -Depth 6
        Write-Doctor "SUMMARY PASS=$passCount FAIL=$failCount WARN=$warnCount SKIP=$skipCount Duration=$([math]::Round($duration.TotalSeconds, 2))s" 'INFO'
        if ($failCount -eq 0) {
            Write-Doctor 'RESULT: PASS' 'SUCCESS'
        }
        else {
            Write-Doctor 'RESULT: FAIL' 'FAIL'
        }
        return
    }

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host 'BrebesKab-CSIRT-Tools Doctor Summary' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host "PASS : $passCount" -ForegroundColor Green
    Write-Host "FAIL : $failCount" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "WARN : $warnCount" -ForegroundColor $(if ($warnCount -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host "SKIP : $skipCount"
    Write-Host ("Duration: {0:N2}s" -f $duration.TotalSeconds)
    Write-Host "Log     : $LogPath"

    if ($failCount -eq 0) {
        Write-Host ''
        Write-Host 'RESULT: PASS' -ForegroundColor Green
    }
    else {
        Write-Host ''
        Write-Host 'RESULT: FAIL' -ForegroundColor Red
        Write-Host ''
        Write-Host 'Failed checks:' -ForegroundColor Red

        foreach ($item in @($Results | Where-Object { $_.Status -eq 'FAIL' })) {
            Write-Host "  - $($item.Name): $($item.Message)" -ForegroundColor Red
        }
    }

    Write-Doctor "SUMMARY PASS=$passCount FAIL=$failCount WARN=$warnCount SKIP=$skipCount Duration=$([math]::Round($duration.TotalSeconds, 2))s" 'INFO'

    if ($failCount -eq 0) {
        Write-Doctor 'RESULT: PASS' 'SUCCESS'
    }
    else {
        Write-Doctor 'RESULT: FAIL' 'FAIL'
    }
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

try {
    Write-Doctor "============================================================" 'INFO'
    Write-Doctor "BrebesKab-CSIRT-Tools Doctor v$ScriptVersion" 'INFO'
    Write-Doctor "Repository: $RepositoryRoot" 'INFO'
    Write-Doctor "PowerShell: $($PSVersionTable.PSVersion)" 'INFO'
    Write-Doctor "Started: $($StartedAt.ToString('o'))" 'INFO'
    Write-Doctor "============================================================" 'INFO'

    if (-not $Quiet -and -not $Json) {
        Write-Host ''
        Write-Host '============================================================' -ForegroundColor Cyan
        Write-Host "BrebesKab-CSIRT-Tools Doctor v$ScriptVersion" -ForegroundColor Cyan
        Write-Host '============================================================' -ForegroundColor Cyan
        Write-Host "Repository : $RepositoryRoot"
        Write-Host "PowerShell : $($PSVersionTable.PSVersion)"
        Write-Host "Started    : $($StartedAt.ToString('yyyy-MM-ddTHH:mm:ssK'))"
        Write-Host "Log        : $LogPath"
    }

    Write-Doctor 'Runtime' 'STEP'

    # PowerShell version.
    if ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -ge 1) {
        Add-Result 'Runtime' 'PowerShell' 'PASS' "PowerShell $($PSVersionTable.PSVersion)"
        Write-Doctor "PowerShell $($PSVersionTable.PSVersion)" 'PASS'
    }
    else {
        Add-Result 'Runtime' 'PowerShell' 'FAIL' "PowerShell $($PSVersionTable.PSVersion) tidak didukung. Minimum 5.1."
        Write-Doctor "PowerShell $($PSVersionTable.PSVersion) tidak sesuai." 'FAIL'
    }

    # Repository root.
    if (Test-Path -LiteralPath $RepositoryRoot -PathType Container) {
        Add-Result 'Runtime' 'Repository root' 'PASS' 'Repository root tersedia.' $RepositoryRoot
        Write-Doctor "Repository root OK: $RepositoryRoot" 'PASS'
    }
    else {
        Add-Result 'Runtime' 'Repository root' 'FAIL' 'Repository root tidak ditemukan.' $RepositoryRoot
        Write-Doctor 'Repository root tidak ditemukan.' 'FAIL'
    }

    Test-PythonProject

    Write-Doctor 'Python Packages' 'STEP'

    $packages = @(
        @{ Package = 'typer'; Import = 'typer' },
        @{ Package = 'rich'; Import = 'rich' },
        @{ Package = 'httpx'; Import = 'httpx' },
        @{ Package = 'requests'; Import = 'requests' },
        @{ Package = 'PyYAML'; Import = 'yaml' },
        @{ Package = 'pydantic'; Import = 'pydantic' },
        @{ Package = 'python-dateutil'; Import = 'dateutil' },
        @{ Package = 'beautifulsoup4'; Import = 'bs4' },
        @{ Package = 'lxml'; Import = 'lxml' },
        @{ Package = 'playwright'; Import = 'playwright' },
        @{ Package = 'Jinja2'; Import = 'jinja2' },
        @{ Package = 'python-docx'; Import = 'docx' }
    )

    foreach ($package in $packages) {
        Test-PythonPackage -Package $package.Package -ImportName $package.Import
    }

    # Playwright CLI/package verification.
    $venvPython = Join-Path $RepositoryRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
        try {
            $playwrightCheck = Invoke-NativeCapture -Executable $venvPython -Arguments @('-m', 'playwright', '--version')
            $playwrightVersion = $playwrightCheck.Output
            $playwrightExit = $playwrightCheck.ExitCode

            if ($playwrightExit -eq 0) {
                Add-Result 'Python Packages' 'Playwright CLI' 'PASS' $playwrightVersion.Trim() $venvPython
                Write-Doctor "Playwright CLI: $($playwrightVersion.Trim())" 'PASS'
            }
            else {
                Add-Result 'Python Packages' 'Playwright CLI' 'FAIL' "ExitCode=$playwrightExit. $($playwrightVersion.Trim())" $venvPython
                Write-Doctor 'Playwright CLI gagal.' 'FAIL'
            }
        }
        catch {
            Add-Result 'Python Packages' 'Playwright CLI' 'FAIL' $_.Exception.Message $venvPython
            Write-Doctor 'Playwright CLI gagal diperiksa.' 'FAIL'
        }
    }

    Write-Doctor 'Security Tools' 'STEP'

    Test-Tool -Name 'git' -DisplayName 'Git' -Executable (Get-CommandPath 'git.exe') -VersionArguments @('--version')

    $nmapPath = Get-CommandPath 'nmap.exe'
    if (-not $nmapPath) {
        $nmapPath = Find-ExistingPath @(
            'C:\Program Files\Nmap\nmap.exe',
            'C:\Program Files (x86)\Nmap\nmap.exe'
        )
    }
    Test-Tool -Name 'nmap' -DisplayName 'Nmap' -Executable $nmapPath -VersionArguments @('--version')

    $ffufPath = Get-CommandPath 'ffuf.exe'
    if (-not $ffufPath) {
        $ffufPath = Find-ExistingPath @(
            (Join-Path $RepositoryRoot 'tools\ffuf\ffuf.exe')
        )
    }
    Test-Tool -Name 'ffuf' -DisplayName 'ffuf' -Executable $ffufPath -VersionArguments @('-V')

    $nucleiPath = Find-ExistingPath @(
        (Join-Path $RepositoryRoot 'tools\nuclei\nuclei.exe'),
        (Join-Path $RepositoryRoot 'tools\nuclei.exe')
    )
    if (-not $nucleiPath) {
        $nucleiPath = Get-CommandPath 'nuclei.exe'
    }
    Test-Tool -Name 'nuclei' -DisplayName 'Nuclei' -Executable $nucleiPath -VersionArguments @('-version')

    $httpxPath = Find-ExistingPath @(
        (Join-Path $RepositoryRoot 'tools\httpx\httpx.exe'),
        (Join-Path $RepositoryRoot 'tools\httpx.exe')
    )
    if (-not $httpxPath) {
        $httpxPath = Get-CommandPath 'httpx.exe'
    }
    Test-Tool -Name 'httpx' -DisplayName 'ProjectDiscovery httpx' -Executable $httpxPath -VersionArguments @('-version')

    Test-ZAP

    Write-Doctor 'Environment' 'STEP'

    Test-PATHVisibility -Name 'Nuclei' -ExpectedPath (Join-Path $RepositoryRoot 'tools\nuclei')
    Test-PATHVisibility -Name 'ProjectDiscovery httpx' -ExpectedPath (Join-Path $RepositoryRoot 'tools\httpx')

    Write-Doctor 'Project Structure' 'STEP'
    Test-Structure

    Write-Doctor 'Installer State' 'STEP'
    Test-InstallerState

    Print-Summary

    $failed = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count

    if ($failed -gt 0) {
        exit 1
    }

    exit 0
}
catch {
    Write-Doctor "Doctor terminated unexpectedly: $($_.Exception.Message)" 'FAIL'

    if (-not $Json) {
        Write-Host ''
        Write-Host "[FAIL] Doctor terminated unexpectedly: $($_.Exception.Message)" -ForegroundColor Red
    }

    exit 2
}
