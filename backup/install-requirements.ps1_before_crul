#requires -Version 5.1
# BrebesKab-CSIRT-Tools install-requirements.ps1 v2.16
# CLI version verification is based on executable availability and non-empty version output.
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SkipRollback,
    [switch]$SkipZAP,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$RuntimeRoot = Join-Path $RepoRoot '.runtime'
$LogRoot = Join-Path $RuntimeRoot 'logs'
$StateRoot = Join-Path $RuntimeRoot 'state'
$DownloadRoot = Join-Path $RuntimeRoot 'downloads'
$ToolsRoot = Join-Path $RepoRoot 'tools'
$LogFile = Join-Path $LogRoot 'install-requirements.log'
$StateFile = Join-Path $StateRoot 'install-state.json'
$NucleiDir = Join-Path $ToolsRoot 'nuclei'
$HttpxDir = Join-Path $ToolsRoot 'httpx'
$VenvDir = Join-Path $RepoRoot '.venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
$VenvScripts = Join-Path $VenvDir 'Scripts'

$WinGetPackages = @(
    [pscustomobject]@{ Name='Python'; Id='Python.Python.3.14' },
    [pscustomobject]@{ Name='Git'; Id='Git.Git' },
    [pscustomobject]@{ Name='Nmap'; Id='Insecure.Nmap' },
    [pscustomobject]@{ Name='ffuf'; Id='ffuf.ffuf' }
)

$PythonPackages = @(
    'typer','rich','httpx','requests','PyYAML','pydantic',
    'python-dateutil','beautifulsoup4','lxml','playwright','Jinja2','python-docx',
    'cryptography'
)

# Package-to-module mapping used for dependency import verification.
# The PyPI distribution name is not always identical to the Python import name.
$PythonImportChecks = @(
    [pscustomobject]@{ Package='typer'; Module='typer' },
    [pscustomobject]@{ Package='rich'; Module='rich' },
    [pscustomobject]@{ Package='httpx'; Module='httpx' },
    [pscustomobject]@{ Package='requests'; Module='requests' },
    [pscustomobject]@{ Package='PyYAML'; Module='yaml' },
    [pscustomobject]@{ Package='pydantic'; Module='pydantic' },
    [pscustomobject]@{ Package='python-dateutil'; Module='dateutil' },
    [pscustomobject]@{ Package='beautifulsoup4'; Module='bs4' },
    [pscustomobject]@{ Package='lxml'; Module='lxml' },
    [pscustomobject]@{ Package='playwright'; Module='playwright' },
    [pscustomobject]@{ Package='Jinja2'; Module='jinja2' },
    [pscustomobject]@{ Package='python-docx'; Module='docx' },
    [pscustomobject]@{ Package='cryptography'; Module='cryptography' }
)

$GitHubHeaders = @{
    Accept='application/vnd.github+json'
    'X-GitHub-Api-Version'='2022-11-28'
    'User-Agent'='BrebesKab-CSIRT-Tools-install-requirements'
}

$script:State = [ordered]@{
    schema_version=2.16
    started_at=(Get-Date).ToString('o')
    repo_root=$RepoRoot
    dry_run=[bool]$DryRun
    installed_by_script=@()
    venv_created_by_script=$false
    python_reference=$null
    python_base=$null
    completed=$false
}

function Write-Log {
    param([string]$Message,[ValidateSet('INFO','WARN','ERROR','OK','STEP','DRYRUN')][string]$Level='INFO')
    $line="[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    $color = switch ($Level) { ERROR {'Red'} WARN {'Yellow'} OK {'Green'} STEP {'Cyan'} DRYRUN {'Magenta'} default {'Gray'} }
    Write-Host $line -ForegroundColor $color
    if (-not (Test-Path $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Save-State {
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    $script:State | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFile -Encoding UTF8
}

function Add-InstalledComponent {
    param([string]$Type,[string]$Name,[string]$Id,[string]$Version,[string]$Path)
    $script:State.installed_by_script += [ordered]@{
        type=$Type; name=$Name; id=$Id; version=$Version; path=$Path; installed_at=(Get-Date).ToString('o')
    }
    Save-State
}

function Test-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Administrator {
    if (Test-Administrator) {
        return
    }

    Write-Log 'PowerShell belum berjalan sebagai Administrator. Meminta akses Administrator melalui UAC...' 'WARN'

    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        throw 'Path install-requirements.ps1 tidak dapat ditentukan untuk proses elevation.'
    }

    $elevatedArguments = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        "`"$scriptPath`""
    )

    if ($DryRun) { $elevatedArguments += '-DryRun' }
    if ($SkipRollback) { $elevatedArguments += '-SkipRollback' }
    if ($SkipZAP) { $elevatedArguments += '-SkipZAP' }
    if ($Force) { $elevatedArguments += '-Force' }

    try {
        $process = Start-Process `
            -FilePath 'powershell.exe' `
            -ArgumentList $elevatedArguments `
            -Verb RunAs `
            -Wait `
            -PassThru `
            -ErrorAction Stop
    }
    catch {
        throw "Permintaan akses Administrator gagal atau dibatalkan oleh user: $($_.Exception.Message)"
    }

    $childExitCode = $process.ExitCode

    if ($childExitCode -ne 0) {
        # The elevated child already performed its own error handling and
        # rollback. Do not let the parent re-enter the installer catch/rollback
        # path and hide the real child failure behind an elevation error.
        Write-Log "Proses Administrator selesai dengan exit code $childExitCode." 'ERROR'
        Write-Log "Detail proses elevated tersedia pada: $LogFile" 'ERROR'
        exit $childExitCode
    }

    Write-Log 'Proses Administrator selesai dengan sukses.' 'OK'
    exit 0
}

function Refresh-Path {
    $env:Path=@(
        [Environment]::GetEnvironmentVariable('Path','Machine'),
        [Environment]::GetEnvironmentVariable('Path','User')
    ) -join ';'
}

function Find-Command {
    param([string]$Name)
    try { (Get-Command $Name -ErrorAction Stop).Source } catch { $null }
}

function Invoke-NativeChecked {
    param([string]$FilePath,[string[]]$Arguments=@())
    Write-Log "EXEC: $FilePath $($Arguments -join ' ')"
    if ($DryRun) { Write-Log 'DryRun: command tidak dijalankan.' 'DRYRUN'; return }
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command gagal, exit code $LASTEXITCODE`: $FilePath" }
}

function Get-WinGetInstalled {
    param([string]$Id)
    try {
        $out=& winget list --id $Id --exact --source winget --accept-source-agreements 2>$null | Out-String
        return ($out -match [regex]::Escape($Id))
    } catch { return $false }
}

function Get-WinGetSearchExact {
    param([string]$Id)
    try {
        $out=& winget search --id $Id --exact --source winget --accept-source-agreements 2>$null | Out-String
        return ($out -match [regex]::Escape($Id))
    } catch { return $false }
}

function Install-WinGetPackage {
    param([string]$Name,[string]$Id)

    if (Get-WinGetInstalled $Id) {
        Write-Log "$Name sudah terpasang: $Id" 'OK'
        return
    }

    if (-not (Get-WinGetSearchExact $Id)) {
        throw "Paket WinGet tidak ditemukan: $Id"
    }

    if ($DryRun) {
        Write-Log "DryRun: install WinGet $Id (scope machine)" 'DRYRUN'
        return
    }

    Write-Log "Install $Name via WinGet: $Id (scope machine)" 'STEP'
    & winget install `
        --id $Id `
        --exact `
        --source winget `
        --scope machine `
        --silent `
        --accept-package-agreements `
        --accept-source-agreements

    if ($LASTEXITCODE -ne 0) {
        throw "WinGet gagal menginstall $Id. Exit code: $LASTEXITCODE"
    }

    Refresh-Path

    if (-not (Get-WinGetInstalled $Id)) {
        throw "Package tidak terdeteksi setelah install: $Id"
    }

    Add-InstalledComponent 'winget' $Name $Id '' ''
    Write-Log "$Name berhasil diinstall." 'OK'
}

function Get-PythonBaseExecutable {
    <#
        Resolve Python installed by WinGet/Python Launcher.
        Never trust the WindowsApps python.exe App Execution Alias.
        The project .venv is created from this real interpreter.
    #>
    if (Find-Command 'py') {
        try {
            $candidate = (& py -3 -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
            if ($candidate) {
                $candidate = [string]$candidate
                if ((Test-Path $candidate) -and ($candidate -notmatch '\\WindowsApps\\')) {
                    $version = (& $candidate --version 2>&1 | Out-String).Trim()
                    if ($version -match '^Python\s+3\.14(\.\d+)?$') {
                        return $candidate
                    }
                }
            }
        } catch {}
    }

    $candidates = @(
        (Join-Path $env:ProgramFiles 'Python314\python.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Python314\python.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python314\python.exe')
    )

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            try {
                $version = (& $candidate --version 2>&1 | Out-String).Trim()
                if ($version -match '^Python\s+3\.14(\.\d+)?$') {
                    return $candidate
                }
            } catch {}
        }
    }

    $null
}

function Test-ProjectPython {
    param([string]$PythonExe)

    if (-not (Test-Path $PythonExe)) {
        return $false
    }

    try {
        $version = (& $PythonExe --version 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { return $false }
        if ($version -notmatch '^Python\s+3\.14(\.\d+)?$') { return $false }

        $prefix = (& $PythonExe -c "import sys; print(sys.prefix)" 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { return $false }

        return ([IO.Path]::GetFullPath($prefix).TrimEnd('\') -ieq
            [IO.Path]::GetFullPath($VenvDir).TrimEnd('\'))
    }
    catch {
        return $false
    }
}

function Ensure-Venv {
    if ($DryRun) {
        $basePython = Join-Path $env:ProgramFiles 'Python314\python.exe'
        Write-Log "DryRun: Python base reference -> $basePython" 'DRYRUN'
    }
    else {
        $basePython = Get-PythonBaseExecutable
        if (-not $basePython) {
            throw 'Python 3.14 dari instalasi resmi tidak ditemukan. Pastikan paket Python.Python.3.14 berhasil diinstall.'
        }

        Write-Log "Python referensi sistem: $basePython" 'INFO'
    }

    if (Test-ProjectPython $VenvPython) {
        $version = (& $VenvPython --version 2>&1 | Out-String).Trim()
        Write-Log "Python project sudah tersedia di .venv: $version" 'OK'
        Write-Log "Python reference: $VenvPython" 'OK'
        return $VenvPython
    }

    if (Test-Path $VenvDir) {
        if ($Force) {
            if ($DryRun) {
                Write-Log "DryRun: recreate $VenvDir karena -Force." 'DRYRUN'
            }
            else {
                Write-Log "Venv existing tidak valid. Menghapus dan membuat ulang: $VenvDir" 'WARN'
                Remove-Item $VenvDir -Recurse -Force
            }
        }
        elseif (-not $DryRun) {
            Write-Log "Venv existing tidak valid. Menghapus dan membuat ulang: $VenvDir" 'WARN'
            Remove-Item $VenvDir -Recurse -Force
        }
    }

    if ($DryRun) {
        Write-Log "DryRun: membuat Python project runtime di $VenvDir menggunakan $basePython" 'DRYRUN'
        return $VenvPython
    }

    Write-Log 'Membuat Python virtual environment project...' 'STEP'
    Invoke-NativeChecked $basePython @('-m','venv',$VenvDir)

    if (-not (Test-ProjectPython $VenvPython)) {
        throw "Python project gagal dibuat atau versinya bukan Python 3.14: $VenvPython"
    }

    $script:State.venv_created_by_script=$true
    $script:State.python_reference=$VenvPython
    $script:State.python_base=$basePython
    Save-State

    Write-Log "Python project berhasil dibuat: $VenvPython" 'OK'
    Write-Log 'Seluruh dependency Python BrebesKab-CSIRT-Tools akan menggunakan interpreter .venv ini.' 'OK'

    $VenvPython
}

function Install-PythonPackages {
    param([string]$VenvPython)

    if ($DryRun) {
        Write-Log "DryRun: pip install $($PythonPackages -join ', ')" 'DRYRUN'
        return
    }

    Write-Log 'Upgrade pip/setuptools/wheel...' 'STEP'
    Invoke-NativeChecked $VenvPython @('-m','pip','install','--upgrade','pip','setuptools','wheel')

    Write-Log 'Install Python dependencies...' 'STEP'
    Invoke-NativeChecked $VenvPython (@('-m','pip','install','--upgrade')+$PythonPackages)

    Write-Log 'Python packages berhasil diinstall.' 'OK'
}

function Install-PlaywrightChromium {
    param([string]$VenvPython)

    if ($DryRun) {
        Write-Log 'DryRun: playwright install chromium' 'DRYRUN'
        return
    }

    Invoke-NativeChecked $VenvPython @('-m','playwright','install','chromium')
    Write-Log 'Playwright Chromium berhasil diinstall.' 'OK'
}

function Get-GitHubLatestRelease {
    param([string]$Repo)
    Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $GitHubHeaders -Method Get
}

function Get-WindowsAmd64Asset {
    param($Release,[string]$ToolName)

    $patterns=switch($ToolName) {
        nuclei {@('^nuclei_.*_windows_amd64\.zip$','^nuclei_.*_windows_x64\.zip$')}
        httpx {@('^httpx_.*_windows_amd64\.zip$','^httpx_.*_windows_x64\.zip$')}
        default { throw "Tool tidak didukung: $ToolName" }
    }

    foreach($pattern in $patterns) {
        $a=@($Release.assets | Where-Object {$_.name -match $pattern} | Select-Object -First 1)
        if($a.Count -gt 0){return $a[0]}
    }

    throw "Asset Windows AMD64 $ToolName tidak ditemukan pada $($Release.tag_name)."
}

function Install-GitHubZipTool {
    param([string]$ToolName,[string]$Repo,[string]$InstallDir,[string]$ExecutableName)

    $existing=Join-Path $InstallDir $ExecutableName

    if((Test-Path $existing) -and -not $Force){
        Write-Log "$ToolName sudah tersedia: $existing" 'OK'
        return
    }

    $release=Get-GitHubLatestRelease $Repo
    $asset=Get-WindowsAmd64Asset $release $ToolName
    $zip=Join-Path $DownloadRoot $asset.name

    if($DryRun){
        Write-Log "DryRun: resolve/download official release $Repo -> $existing" 'DRYRUN'
        return
    }

    New-Item -ItemType Directory -Path $DownloadRoot,$InstallDir -Force | Out-Null
    Write-Log "Download $ToolName $($release.tag_name): $($asset.name)" 'STEP'

    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -Headers $GitHubHeaders

    if($asset.digest -and $asset.digest -match '^sha256:([0-9a-fA-F]{64})$'){
        $expected=$Matches[1].ToLowerInvariant()
        $actual=(Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()

        if($actual -ne $expected){
            throw "$ToolName checksum mismatch. Expected $expected, got $actual"
        }

        Write-Log "$ToolName SHA-256 checksum OK." 'OK'
    }
    else {
        Write-Log "$ToolName release tidak menyediakan digest SHA-256 via GitHub API; lanjut dengan official release asset." 'WARN'
    }

    if(Test-Path $InstallDir){
        Get-ChildItem $InstallDir -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force

    $exe=Get-ChildItem $InstallDir -Filter $ExecutableName -File -Recurse |
        Select-Object -First 1

    if(-not $exe){
        throw "$ToolName executable tidak ditemukan setelah extraction: $ExecutableName"
    }

    if($exe.FullName -ne $existing){
        Copy-Item $exe.FullName $existing -Force
    }

    Add-InstalledComponent 'github-binary' $ToolName $Repo $release.tag_name $InstallDir
    Write-Log "$ToolName $($release.tag_name) berhasil diinstall: $existing" 'OK'
}

function Add-UserPath {
    param([string]$PathToAdd)

    $current=[Environment]::GetEnvironmentVariable('Path','User')
    $parts=@()

    if($current){
        $parts=$current -split ';' | Where-Object {$_ -and $_.Trim()}
    }

    $target=[IO.Path]::GetFullPath($PathToAdd).TrimEnd('\')

    $exists=$parts | Where-Object {
        try {
            [IO.Path]::GetFullPath($_).TrimEnd('\') -ieq $target
        }
        catch {
            $_.TrimEnd('\') -ieq $target
        }
    }

    if(-not $exists){
        if($DryRun){
            Write-Log "DryRun: tambah User PATH $PathToAdd" 'DRYRUN'
        }
        else{
            [Environment]::SetEnvironmentVariable('Path',(($parts+$PathToAdd)-join ';'),'User')
            Write-Log "User PATH ditambahkan: $PathToAdd" 'OK'
        }
    }

    Refresh-Path
}

function Get-ZapUninstallEntries {
    $roots=@(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $entries=@()

    foreach($root in $roots){
        try{
            $entries += Get-ItemProperty $root -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -and
                    ($_.DisplayName -match 'Zed Attack Proxy' -or $_.DisplayName -match '^OWASP ZAP')
                }
        }
        catch{}
    }

    $entries
}

function Get-ZapExecutableCandidates {
    param([string]$Version)

    $candidates = @(
        (Join-Path $env:ProgramFiles 'ZAP\ZAP.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'ZAP\ZAP.exe'),
        (Join-Path $env:ProgramFiles "ZAP\ZAP_$Version\ZAP.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "ZAP\ZAP_$Version\ZAP.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\ZAP\ZAP.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\OWASP ZAP\ZAP.exe")
    )

    $candidates | Where-Object {
        $_ -and (Test-Path $_)
    } | Select-Object -Unique
}

function Find-ZapExecutable {
    param([string]$Version)

    $candidates = @(Get-ZapExecutableCandidates $Version)

    if($candidates.Count -gt 0){
        return $candidates[0]
    }

    $roots = @(
        (Join-Path $env:ProgramFiles 'ZAP'),
        (Join-Path ${env:ProgramFiles(x86)} 'ZAP'),
        (Join-Path $env:LOCALAPPDATA 'Programs\ZAP'),
        (Join-Path $env:LOCALAPPDATA 'Programs\OWASP ZAP')
    )

    foreach($root in $roots){
        if(Test-Path $root){
            $found = Get-ChildItem -Path $root -Filter 'ZAP.exe' -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1

            if($found){
                return $found.FullName
            }
        }
    }

    $null
}

function Get-ZapUninstallCommand {
    param($Entry)

    if(-not $Entry){ return $null }

    if($Entry.QuietUninstallString){
        return [string]$Entry.QuietUninstallString
    }

    if($Entry.UninstallString){
        return [string]$Entry.UninstallString
    }

    $null
}

function Install-ZAP {
    if($SkipZAP){
        Write-Log 'OWASP ZAP dilewati (-SkipZAP).' 'WARN'
        return
    }

    $existingEntry = @(Get-ZapUninstallEntries) | Select-Object -First 1
    $existingExe = Find-ZapExecutable ''

    if($existingEntry -or $existingExe){
        if($existingExe){
            Write-Log "OWASP ZAP sudah terpasang: $existingExe" 'OK'
        }
        else{
            Write-Log "OWASP ZAP sudah terpasang berdasarkan registry: $($existingEntry.DisplayName)" 'OK'
        }
        return
    }

    if($DryRun){
        Write-Log 'DryRun: ZAP diambil dari manifest resmi zaproxy/zap-admin.' 'DRYRUN'
        return
    }

    $manifest=Invoke-RestMethod `
        -Uri 'https://raw.githubusercontent.com/zaproxy/zap-admin/master/ZapVersions.xml' `
        -Method Get

    $version=[string]$manifest.ZAP.core.version
    $url=[string]$manifest.ZAP.core.windows.url
    $file=[string]$manifest.ZAP.core.windows.file
    $hash=[string]$manifest.ZAP.core.windows.hash

    if(
        [string]::IsNullOrWhiteSpace($version) -or
        [string]::IsNullOrWhiteSpace($url) -or
        [string]::IsNullOrWhiteSpace($hash)
    ){
        throw 'Manifest ZAP tidak lengkap.'
    }

    $expected=$hash -replace '^SHA-256:',''
    $installer=Join-Path $DownloadRoot $file

    New-Item -ItemType Directory -Path $DownloadRoot -Force | Out-Null

    Write-Log "Download OWASP ZAP $version..." 'STEP'
    Invoke-WebRequest $url -OutFile $installer

    $actual=(Get-FileHash $installer -Algorithm SHA256).Hash

    if($actual -ine $expected){
        throw "OWASP ZAP SHA-256 mismatch. Expected $expected, got $actual"
    }

    Write-Log 'OWASP ZAP SHA-256 checksum OK.' 'OK'

    $before=@(Get-ZapUninstallEntries | ForEach-Object {
        "$($_.DisplayName)|$($_.DisplayVersion)|$($_.UninstallString)"
    })

    $beforeExe = Find-ZapExecutable $version

    Write-Log "Menjalankan installer OWASP ZAP $version..." 'STEP'
    $p=Start-Process -FilePath $installer -ArgumentList '-q' -Wait -PassThru

    if($p.ExitCode -ne 0){
        throw "Installer OWASP ZAP gagal. Exit code: $($p.ExitCode)"
    }

    $after=@(Get-ZapUninstallEntries)
    $zapExe=Find-ZapExecutable $version

    if(-not $zapExe -and $after.Count -eq 0){
        throw 'Installer OWASP ZAP selesai tetapi instalasi tidak dapat diverifikasi melalui executable maupun registry.'
    }

    $entry = $null

    if($after.Count -gt 0){
        $entry=$after |
            Where-Object {
                $before -notcontains "$($_.DisplayName)|$($_.DisplayVersion)|$($_.UninstallString)"
            } |
            Select-Object -First 1

        if(-not $entry){
            $entry=$after | Select-Object -First 1
        }
    }

    $uninstallCommand = Get-ZapUninstallCommand $entry

    Add-InstalledComponent `
        'upstream-installer' `
        'OWASP ZAP' `
        'zaproxy/zaproxy' `
        $version `
        $uninstallCommand

    if($zapExe){
        Write-Log "OWASP ZAP executable terdeteksi: $zapExe" 'OK'
    }

    if($entry){
        Write-Log "OWASP ZAP registry entry terdeteksi: $($entry.DisplayName) $($entry.DisplayVersion)" 'OK'
    }

    if($beforeExe -and -not $zapExe){
        Write-Log 'Catatan: executable ZAP sebelum instalasi ada tetapi setelah instalasi tidak ditemukan pada kandidat lokasi.' 'WARN'
    }

    Write-Log "OWASP ZAP $version berhasil diinstall dan diverifikasi." 'OK'
}

function Find-ToolExecutable {
    param([string]$Name)

    $cmd=Find-Command $Name
    if($cmd){return $cmd}

    $candidate=switch($Name){
        nuclei {Join-Path $NucleiDir 'nuclei.exe'}
        httpx {Join-Path $HttpxDir 'httpx.exe'}
        default {$null}
    }

    if($candidate -and (Test-Path $candidate)){return $candidate}
    $null
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [string[]]$Arguments=@()
    )

    if(-not (Test-Path $FilePath)){
        throw "Executable tidak ditemukan: $FilePath"
    }

    $stdoutFile = Join-Path $DownloadRoot ("verify-" + [Guid]::NewGuid().ToString('N') + ".stdout")
    $stderrFile = Join-Path $DownloadRoot ("verify-" + [Guid]::NewGuid().ToString('N') + ".stderr")

    try {
        # Native tools may write informational/version output to stderr.
        # In Windows PowerShell 5.1, keep native stderr from becoming a
        # terminating error while we capture stdout/stderr to files.
        $previousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            # Use the PowerShell call operator instead of Start-Process -ArgumentList.
            # Start-Process joins an argument array into a single command-line string,
            # which can break arguments containing newlines/quotes such as Python -c code.
            # The call operator preserves the argument array as discrete native arguments.
            & $FilePath @Arguments 1> $stdoutFile 2> $stderrFile
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }

        $stdout = if(Test-Path $stdoutFile){ Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue } else { '' }
        $stderr = if(Test-Path $stderrFile){ Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue } else { '' }

        [pscustomobject]@{
            ExitCode = $exitCode
            StdOut   = [string]$stdout
            StdErr   = [string]$stderr
        }
    }
    finally {
        Remove-Item $stdoutFile,$stderrFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-VerificationOutput {
    param($Result)

    $output = (($Result.StdOut + "`r`n" + $Result.StdErr).Trim())
    if($output.Length -gt 2000){
        $output = $output.Substring(0,2000) + '...'
    }

    $output
}

function Verify-Command {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string[]]$Arguments=@('--version')
    )

    if($DryRun){
        Write-Log "DryRun: verification dilewati untuk $Name." 'DRYRUN'
        return
    }

    $path=Find-ToolExecutable $Name

    if(-not $path){
        throw "Tool tidak ditemukan: $Name"
    }

    Write-Log "VERIFY $Name -> $path"

    $result = Invoke-NativeCapture -FilePath $path -Arguments $Arguments
    $output = Get-VerificationOutput $result

    # Verification criterion for version-capable CLI tools is intentionally simple:
    # executable exists and the requested version command returns non-empty output.
    # Do not reject a valid version banner only because the tool uses a non-zero
    # exit code or writes informational text to stderr on Windows.
    if([string]::IsNullOrWhiteSpace($output)){
        throw "Verifikasi gagal untuk ${Name}: command tidak mengembalikan output."
    }

    Write-Log "$Name OK: $output" 'OK'
}

function Verify-Nuclei {
    if($DryRun){
        Write-Log 'DryRun: verification dilewati untuk nuclei.' 'DRYRUN'
        return
    }

    $path = Find-ToolExecutable 'nuclei'

    if(-not $path){
        throw 'Tool tidak ditemukan: nuclei'
    }

    Write-Log "VERIFY nuclei -> $path"

    # Nuclei writes its version banner to stderr on this Windows environment.
    # Windows PowerShell 5.1 can treat native stderr as a terminating error when
    # $ErrorActionPreference is Stop. Temporarily use Continue only for this
    # native command so stderr becomes captured output instead of aborting.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = (& $path '-version' 2>&1 | Out-String).Trim()
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    # Verification criterion is intentionally simple:
    # executable exists and -version returns any non-empty output.
    if([string]::IsNullOrWhiteSpace($output)){
        throw 'Verifikasi Nuclei gagal: command -version tidak mengembalikan output.'
    }

    if($output.Length -gt 4000){
        $output = $output.Substring(0,4000) + '...'
    }

    Write-Log "nuclei OK: $output" 'OK'
}

function Verify-PythonEnvironment {
    param([string]$VenvPython)

    if($DryRun){
        Write-Log 'DryRun: verifikasi Python environment dilewati.' 'DRYRUN'
        return
    }

    if(-not(Test-Path $VenvPython)){
        throw "Venv Python tidak ditemukan: $VenvPython"
    }

    $pythonResult = Invoke-NativeCapture -FilePath $VenvPython -Arguments @('--version')
    if($pythonResult.ExitCode -ne 0){
        throw "Python project verification gagal. Exit code: $($pythonResult.ExitCode)"
    }

    $pythonVersion = ($pythonResult.StdOut + "`r`n" + $pythonResult.StdErr).Trim()
    Write-Log "Venv Python OK: $pythonVersion" 'OK'

    foreach($pkg in $PythonPackages){
        $result = Invoke-NativeCapture `
            -FilePath $VenvPython `
            -Arguments @('-m','pip','show',$pkg)

        if($result.ExitCode -ne 0){
            throw "Python package belum terpasang: $pkg"
        }

        Write-Log "Python package OK: $pkg" 'OK'
    }

    foreach($check in $PythonImportChecks){
        $pythonCode = @"
import importlib
import sys

module_name = sys.argv[1]
try:
    importlib.import_module(module_name)
except Exception as exc:
    print(type(exc).__name__, exc, file=sys.stderr)
    raise SystemExit(1)
print(module_name)
"@

        $importCheck = Invoke-NativeCapture `
            -FilePath $VenvPython `
            -Arguments @('-c',$pythonCode,$check.Module)

        if($importCheck.ExitCode -ne 0){
            $details = (($importCheck.StdOut + "`r`n" + $importCheck.StdErr).Trim())
            if($details.Length -gt 2000){
                $details = $details.Substring(0,2000) + '...'
            }

            throw "Python module tidak dapat diimport: $($check.Module) (package: $($check.Package)). Output: $details"
        }

        Write-Log "Python module OK: $($check.Module) [$($check.Package)]" 'OK'
    }

    $cryptographyVersion = Invoke-NativeCapture `
        -FilePath $VenvPython `
        -Arguments @('-c','import cryptography; print(cryptography.__version__)')

    if($cryptographyVersion.ExitCode -ne 0){
        throw "Cryptography import verification gagal."
    }

    Write-Log "cryptography runtime OK: $(($cryptographyVersion.StdOut + "`r`n" + $cryptographyVersion.StdErr).Trim())" 'OK'

    $playwright = Invoke-NativeCapture `
        -FilePath $VenvPython `
        -Arguments @('-m','playwright','--version')

    if($playwright.ExitCode -ne 0){
        $details = (($playwright.StdOut + "`r`n" + $playwright.StdErr).Trim())
        throw "Playwright verification gagal. Exit code: $($playwright.ExitCode). Output: $details"
    }

    $playwrightVersion = ($playwright.StdOut + "`r`n" + $playwright.StdErr).Trim()
    Write-Log "Playwright OK: $playwrightVersion" 'OK'
    Write-Log 'Semua Python packages dan Playwright terverifikasi.' 'OK'
}

function Rollback {
    if($DryRun){
        Write-Log 'DryRun: rollback tidak diperlukan.' 'DRYRUN'
        return
    }

    Write-Log 'Memulai rollback komponen yang dipasang oleh script...' 'STEP'

    foreach($c in @($script:State.installed_by_script)){
        try{
            switch($c.type){
                'winget' {
                    if($c.id -and (Find-Command 'winget')){
                        Write-Log "Rollback WinGet: $($c.id)"
                        & winget uninstall `
                            --id $c.id `
                            --exact `
                            --scope machine `
                            --silent `
                            --accept-source-agreements `
                            2>&1 | Add-Content $LogFile

                        if($LASTEXITCODE -eq 0){
                            Write-Log "Rollback WinGet berhasil: $($c.id)" 'OK'
                        }
                        else{
                            Write-Log "Rollback WinGet gagal [$($c.id)], exit code: $LASTEXITCODE" 'WARN'
                        }
                    }
                }

                'github-binary' {
                    if($c.path -and (Test-Path $c.path)){
                        Write-Log "Rollback binary: $($c.path)"
                        Remove-Item $c.path -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }

                'upstream-installer' {
                    $u=$c.path

                    if($u){
                        if($u -match '^\s*"([^"]+)"(.*)$'){
                            $exe=$Matches[1]
                            $args=$Matches[2].Trim()
                        }
                        elseif($u -match '^\s*(\S+)(.*)$'){
                            $exe=$Matches[1]
                            $args=$Matches[2].Trim()
                        }
                        else{
                            $exe=$null
                            $args=$null
                        }

                        if($exe -and (Test-Path $exe)){
                            Write-Log "Rollback upstream installer: $exe"
                            $p=Start-Process $exe -ArgumentList $args -Wait -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue

                            if($p -and $p.ExitCode -eq 0){
                                Write-Log "Rollback upstream installer berhasil." 'OK'
                            }
                            else{
                                Write-Log "Rollback upstream installer gagal atau exit code bukan 0." 'WARN'
                            }
                        }
                        else{
                            Write-Log "Uninstaller tidak ditemukan: $u" 'WARN'
                        }
                    }
                }
            }
        }
        catch{
            Write-Log "Rollback error [$($c.name)]: $($_.Exception.Message)" 'WARN'
        }
    }

    if(
        $script:State.venv_created_by_script -and
        (Test-Path $VenvDir)
    ){
        try{
            Remove-Item $VenvDir -Recurse -Force
            Write-Log "Rollback venv: $VenvDir" 'OK'
        }
        catch{
            Write-Log "Gagal menghapus venv: $($_.Exception.Message)" 'WARN'
        }
    }

    Refresh-Path
    Write-Log 'Rollback selesai.' 'OK'
}

try{
    New-Item -ItemType Directory `
        -Path $RuntimeRoot,$LogRoot,$StateRoot,$DownloadRoot,$ToolsRoot `
        -Force | Out-Null

    Write-Log '============================================================' 'STEP'
    Write-Log 'BrebesKab-CSIRT-Tools install-requirements.ps1 v2.16' 'STEP'
    Write-Log '============================================================' 'STEP'

    Request-Administrator

    if(-not(Test-Administrator)){
        throw 'Installer v2.16 tidak berjalan sebagai Administrator setelah proses elevation.'
    }

    if(-not [Environment]::Is64BitOperatingSystem){
        throw 'Installer v2.16 membutuhkan Windows 64-bit.'
    }

    if(-not(Find-Command 'winget')){
        throw 'WinGet tidak ditemukan. Install/update Microsoft App Installer terlebih dahulu.'
    }

    Write-Log "WinGet: $((& winget --version 2>&1|Out-String).Trim())" 'OK'
    Refresh-Path

    foreach($p in $WinGetPackages){
        Install-WinGetPackage $p.Name $p.Id
    }

    Refresh-Path

    $venvPython=Ensure-Venv
    Install-PythonPackages $venvPython
    Install-PlaywrightChromium $venvPython

    Install-GitHubZipTool 'nuclei' 'projectdiscovery/nuclei' $NucleiDir 'nuclei.exe'
    Install-GitHubZipTool 'httpx' 'projectdiscovery/httpx' $HttpxDir 'httpx.exe'

    Add-UserPath $NucleiDir
    Add-UserPath $HttpxDir
    Refresh-Path

    Install-ZAP

    Write-Log 'Memulai verification...' 'STEP'

    Verify-Command 'git' @('--version')
    Verify-Command 'nmap' @('--version')
    Verify-Command 'ffuf' @('-V')
    Verify-Nuclei
    Verify-Command 'httpx' @('-version')

    if (-not $DryRun) {
        if (-not (Test-ProjectPython $venvPython)) {
            throw "Python reference BrebesKab-CSIRT-Tools tidak valid: $venvPython"
        }

        $projectPythonVersion = (& $venvPython --version 2>&1 | Out-String).Trim()
        Write-Log "VERIFY project Python -> $venvPython" 'INFO'
        Write-Log "Project Python OK: $projectPythonVersion" 'OK'
    }
    else {
        Write-Log 'DryRun: verification dilewati untuk project Python.' 'DRYRUN'
    }

    Verify-PythonEnvironment $venvPython

    if(-not $SkipZAP -and -not $DryRun){
        $zapVerified = @(Get-ZapUninstallEntries).Count -gt 0 -or [bool](Find-ZapExecutable '')

        if(-not $zapVerified){
            throw 'OWASP ZAP tidak terdeteksi setelah installation.'
        }

        Write-Log 'OWASP ZAP verification OK.' 'OK'
    }

    $script:State.completed=$true
    $script:State.completed_at=(Get-Date).ToString('o')
    Save-State

    Write-Log 'Semua dependency berhasil diinstall dan diverifikasi.' 'OK'

    if($DryRun){
        Write-Log 'DryRun selesai dengan sukses. Tidak ada software atau konfigurasi sistem yang diubah.' 'OK'
    }

    exit 0
}
catch{
    Write-Log "INSTALL FAILED: $($_.Exception.Message)" 'ERROR'

    if(-not $SkipRollback){
        Rollback
    }
    else{
        Write-Log 'Rollback dilewati karena -SkipRollback.' 'WARN'
    }

    $script:State.completed=$false
    $script:State.failed_at=(Get-Date).ToString('o')
    $script:State.error=$_.Exception.Message
    Save-State

    exit 1
}
