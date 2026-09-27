#requires -Version 5.1
# BrebesKab-CSIRT-Tools install-requirements.ps1 v2.20
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
$GobusterDir = Join-Path $ToolsRoot 'gobuster'
$GobusterExe = Join-Path $GobusterDir 'gobuster.exe'

# Wordlists used by RECON directory discovery.
# Source-oriented layout keeps upstream data traceable while allowing
# directory.py to build technology-aware composite wordlists later.
$WordlistsRoot = Join-Path $RepoRoot 'config\dictionaries\directory'
$SecListsWordlistsDir = Join-Path $WordlistsRoot 'generic\seclists'
$AssetnoteAutomatedDir = Join-Path $WordlistsRoot 'generic\assetnote'
$AssetnoteTechnologyDir = Join-Path $WordlistsRoot 'technology\assetnote'
$WordlistManifest = Join-Path $WordlistsRoot 'manifest.json'
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
    schema_version=2.19
    started_at=(Get-Date).ToString('o')
    repo_root=$RepoRoot
    dry_run=[bool]$DryRun
    installed_by_script=@()
    venv_created_by_script=$false
    python_reference=$null
    python_base=$null
    curl_reference=$null
    openssl_reference=$null
    gobuster_reference=$null
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

function Find-CurlExecutable {
    # Use curl.exe explicitly so the Windows PowerShell "curl" alias
    # (Invoke-WebRequest) is never mistaken for the native cURL executable.
    try {
        $command = Get-Command 'curl.exe' -CommandType Application -ErrorAction Stop |
            Select-Object -First 1

        if ($command -and $command.Source) {
            $source = [string]$command.Source
            if (Test-Path $source) {
                return $source
            }
        }
    }
    catch {}

    $null
}

function Ensure-Curl {
    $existing = Find-CurlExecutable

    if ($existing) {
        Write-Log "curl sudah tersedia: $existing" 'OK'
        return $existing
    }

    if ($DryRun) {
        Write-Log 'DryRun: curl.exe tidak ditemukan; install cURL via WinGet: cURL.cURL' 'DRYRUN'
        return $null
    }

    Write-Log 'curl.exe tidak ditemukan. Menginstall cURL via WinGet: cURL.cURL' 'STEP'
    Install-WinGetPackage 'curl' 'cURL.cURL'
    Refresh-Path

    $installed = Find-CurlExecutable
    if (-not $installed) {
        throw 'curl.exe tidak ditemukan setelah instalasi cURL.cURL.'
    }

    Write-Log "curl berhasil diinstall: $installed" 'OK'
    return $installed
}

function Find-OpenSSLExecutable {
    <#
        Resolve a real native openssl.exe executable.

        Priority:
        1. Native openssl.exe available in PATH.
        2. Common OpenSSL installation locations on Windows.

        This intentionally accepts an already-installed OpenSSL from another
        trusted installation (for example a developer toolchain) and does not
        reinstall or replace it.
    #>
    try {
        $command = Get-Command 'openssl.exe' -CommandType Application -ErrorAction Stop |
            Select-Object -First 1

        if ($command -and $command.Source) {
            $source = [string]$command.Source
            if (Test-Path $source) {
                return $source
            }
        }
    }
    catch {}

    $candidates = @(
        (Join-Path $env:ProgramFiles 'OpenSSL-Win64\bin\openssl.exe'),
        (Join-Path $env:ProgramFiles 'OpenSSL-Win32\bin\openssl.exe'),
        (Join-Path $env:ProgramFiles 'OpenSSL\bin\openssl.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'OpenSSL-Win32\bin\openssl.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'OpenSSL\bin\openssl.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\OpenSSL\bin\openssl.exe')
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    $null
}

function Ensure-OpenSSL {
    $existing = Find-OpenSSLExecutable

    if ($existing) {
        $binDir = Split-Path -Parent $existing

        Write-Log "OpenSSL sudah tersedia: $existing" 'OK'

        # Make an existing installation consistently available to child
        # processes used by the toolkit, without reinstalling or replacing it.
        Add-UserPath $binDir

        Refresh-Path
        $resolved = Find-OpenSSLExecutable

        if ($resolved) {
            Write-Log "OpenSSL reference: $resolved" 'OK'
            return $resolved
        }

        Write-Log "OpenSSL ditemukan tetapi PATH belum dapat direfresh otomatis: $existing" 'WARN'
        return $existing
    }

    if ($DryRun) {
        Write-Log 'DryRun: OpenSSL tidak ditemukan; install via WinGet: ShiningLight.OpenSSL.Light' 'DRYRUN'
        return $null
    }

    Write-Log 'OpenSSL tidak ditemukan. Menginstall OpenSSL Light via WinGet: ShiningLight.OpenSSL.Light' 'STEP'
    Install-WinGetPackage 'OpenSSL Light' 'ShiningLight.OpenSSL.Light'
    Refresh-Path

    $installed = Find-OpenSSLExecutable

    if (-not $installed) {
        throw 'openssl.exe tidak ditemukan setelah instalasi ShiningLight.OpenSSL.Light.'
    }

    $binDir = Split-Path -Parent $installed
    Add-UserPath $binDir
    Refresh-Path

    $resolved = Find-OpenSSLExecutable
    if (-not $resolved) {
        throw "OpenSSL terpasang tetapi executable tidak dapat di-resolve: $installed"
    }

    Write-Log "OpenSSL berhasil diinstall: $resolved" 'OK'
    return $resolved
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


function Get-LatestAssetnoteWordlist {
    param(
        [Parameter(Mandatory=$true)][string]$MetadataUrl,
        [Parameter(Mandatory=$true)][string]$FilePrefix
    )

    try{
        $metadata = Invoke-RestMethod -Uri $MetadataUrl -Method Get
        $matches = @($metadata.data | Where-Object {
            $_.Filename -like "$FilePrefix*.txt" -and
            $_.Download
        })
    }
    catch{
        Write-Log "Gagal mengambil metadata Assetnote [$FilePrefix]: $($_.Exception.Message). Wordlist dilewati." 'WARN'
        return $null
    }

    if($matches.Count -eq 0){
        Write-Log "Assetnote wordlist tidak ditemukan pada metadata [$FilePrefix]. Wordlist dilewati." 'WARN'
        return $null
    }

    # Metadata is generated from the current Assetnote dataset. Prefer the
    # newest timestamp rather than hard-coding a monthly filename.
    $selected = $matches |
        Sort-Object { [double]$_.Date } -Descending |
        Select-Object -First 1

    $downloadHtml=[string]$selected.Download
    $downloadUrl=$null
    if($downloadHtml -match 'href=["'']([^"'']+)["'']'){
        $downloadUrl=$Matches[1]
    }
    if([string]::IsNullOrWhiteSpace($downloadUrl)){
        Write-Log "URL download Assetnote tidak dapat diparse [$($selected.Filename)]. Wordlist dilewati." 'WARN'
        return $null
    }

    [pscustomobject]@{
        Filename = [string]$selected.Filename
        Url      = $downloadUrl
        LineCount = [int64]$selected.'Line Count'
        FileSize = [string]$selected.'File Size'
    }
}

function Get-RepoRelativePath {
    param([Parameter(Mandatory=$true)][string]$Path)

    $full=[IO.Path]::GetFullPath($Path)
    $root=[IO.Path]::GetFullPath($RepoRoot).TrimEnd('\') + '\'

    if($full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){
        return $full.Substring($root.Length).Replace('\','/')
    }

    return $full.Replace('\','/')
}

function Download-Wordlist {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Destination,
        [string]$Source='unknown',
        [string]$Version='',
        [string]$ExpectedSha256=''
    )

    if(Test-Path $Destination){
        Write-Log "Wordlist sudah tersedia: $Destination" 'OK'
        return $false
    }

    if($DryRun){
        Write-Log "DryRun: download wordlist [$Source] $Name -> $Destination" 'DRYRUN'
        return $false
    }

    $temp = "$Destination.download"
    try{
        New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
        Write-Log "Download wordlist [$Source] $Name..." 'STEP'
        Invoke-WebRequest -Uri $Url -OutFile $temp -UseBasicParsing

        if(-not (Test-Path $temp)){
            throw "File hasil download tidak ditemukan: $temp"
        }

        if($ExpectedSha256){
            $actual=(Get-FileHash $temp -Algorithm SHA256).Hash.ToLowerInvariant()
            if($actual -ne $ExpectedSha256.ToLowerInvariant()){
                throw "Wordlist SHA-256 mismatch [$Name]. Expected $ExpectedSha256, got $actual"
            }
        }

        Move-Item $temp $Destination -Force
        Write-Log "Wordlist berhasil disimpan: $Destination" 'OK'
        return $true
    }
    catch{
        Remove-Item $temp -Force -ErrorAction SilentlyContinue
        Write-Log "Gagal download wordlist [$Source] $Name dari ${Url}: $($_.Exception.Message). Wordlist dilewati." 'WARN'
        return $false
    }
}

function Add-WordlistManifestEntry {
    param(
        [Parameter(Mandatory=$true)][System.Collections.IList]$Manifest,
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Source,
        [string]$Url='',
        [string]$Version='',
        [int64]$LineCount=0,
        [string]$FileSize=''
    )

    $Manifest.Add([ordered]@{
        category=$Category
        name=$Name
        path=$Path
        source=$Source
        url=$Url
        version=$Version
        line_count=$LineCount
        file_size=$FileSize
    }) | Out-Null
}

function Install-Gobuster {
    $existing = Find-ToolExecutable 'gobuster'

    if($existing -and -not $Force){
        Write-Log "Gobuster sudah tersedia: $existing" 'OK'
        return $existing
    }

    if($DryRun){
        Write-Log 'DryRun: resolve/download official Gobuster Windows AMD64 release dari OJ/gobuster.' 'DRYRUN'
        return $GobusterExe
    }

    $release = Get-GitHubLatestRelease 'OJ/gobuster'

    $patterns = @(
        '^gobuster_.*_Windows_x86_64\.zip$',
        '^gobuster_.*_windows_amd64\.zip$',
        '^gobuster_.*_Windows_amd64\.zip$',
        '^gobuster_.*_windows_x86_64\.zip$',
        '^gobuster-windows-amd64\.zip$',
        '^gobuster.*windows.*(amd64|x86_64).*\.zip$'
    )

    $asset = $null
    foreach($pattern in $patterns){
        $asset = @($release.assets |
            Where-Object { $_.name -match $pattern } |
            Select-Object -First 1)
        if($asset.Count -gt 0){
            $asset=$asset[0]
            break
        }
    }

    if(-not $asset){
        throw "Asset Gobuster Windows AMD64 tidak ditemukan pada release $($release.tag_name)."
    }

    $zip = Join-Path $DownloadRoot $asset.name
    New-Item -ItemType Directory -Path $DownloadRoot,$GobusterDir -Force | Out-Null

    Write-Log "Download Gobuster $($release.tag_name): $($asset.name)" 'STEP'
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -Headers $GitHubHeaders

    if($asset.digest -and $asset.digest -match '^sha256:([0-9a-fA-F]{64})$'){
        $expected=$Matches[1].ToLowerInvariant()
        $actual=(Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()

        if($actual -ne $expected){
            throw "Gobuster checksum mismatch. Expected $expected, got $actual"
        }

        Write-Log 'Gobuster SHA-256 checksum OK.' 'OK'
    }
    else{
        Write-Log 'Gobuster release tidak menyediakan digest SHA-256 via GitHub API; lanjut dengan official release asset.' 'WARN'
    }

    if(Test-Path $GobusterDir){
        Get-ChildItem $GobusterDir -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    New-Item -ItemType Directory -Path $GobusterDir -Force | Out-Null
    Expand-Archive -Path $zip -DestinationPath $GobusterDir -Force

    $exe=Get-ChildItem $GobusterDir -Filter 'gobuster.exe' -File -Recurse |
        Select-Object -First 1

    if(-not $exe){
        throw "Gobuster executable tidak ditemukan setelah extraction."
    }

    if($exe.FullName -ne $GobusterExe){
        Copy-Item $exe.FullName $GobusterExe -Force
    }

    Add-InstalledComponent 'github-binary' 'Gobuster' 'OJ/gobuster' $release.tag_name $GobusterDir
    Add-UserPath $GobusterDir
    Refresh-Path

    Write-Log "Gobuster $($release.tag_name) berhasil diinstall: $GobusterExe" 'OK'
    return $GobusterExe
}

function Install-Wordlists {
    if($DryRun){
        Write-Log 'DryRun: wordlist installation akan menggunakan layout generic/technology dan manifest.json.' 'DRYRUN'
    }

    New-Item -ItemType Directory -Path `
        $SecListsWordlistsDir,
        $AssetnoteAutomatedDir,
        $AssetnoteTechnologyDir `
        -Force | Out-Null

    $manifest = New-Object System.Collections.ArrayList

    # SecLists: compact-to-broad directory discovery tiers.
    # Wordlist download failures are non-fatal; failed URLs are logged and skipped.
    $secLists = @(
        [pscustomobject]@{
            Name='common'
            Category='generic/seclists'
            File='common.txt'
        },
        [pscustomobject]@{
            Name='quickhits'
            Category='generic/seclists'
            File='quickhits.txt'
        },
        [pscustomobject]@{
            Name='raft-small-directories'
            Category='generic/seclists'
            File='raft-small-directories.txt'
        },
        [pscustomobject]@{
            Name='raft-medium-directories'
            Category='generic/seclists'
            File='raft-medium-directories.txt'
        },
        [pscustomobject]@{
            Name='raft-large-directories'
            Category='generic/seclists'
            File='raft-large-directories.txt'
        }
    )

    foreach($item in $secLists){
        $url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/$($item.File)"
        $destination=Join-Path $SecListsWordlistsDir $item.File

        Download-Wordlist `
            -Name $item.Name `
            -Url $url `
            -Destination $destination `
            -Source 'SecLists'

        if(Test-Path $destination){
            Add-WordlistManifestEntry `
                -Manifest $manifest `
                -Category $item.Category `
                -Name $item.Name `
                -Path (Get-RepoRelativePath $destination) `
                -Source 'danielmiessler/SecLists' `
                -Url $url
        }
    }

    # Assetnote metadata is used instead of hard-coding monthly filenames.
    # This keeps the installer aligned with the latest published dataset.
    $automatedMetadataUrl='https://raw.githubusercontent.com/assetnote/wordlists/master/data/automated.json'
    $technologyMetadataUrl='https://raw.githubusercontent.com/assetnote/wordlists/master/data/technologies.json'

    $assetnoteAutomated = @(
        [pscustomobject]@{
            Name='httparchive-directories-1m'
            Prefix='httparchive_directories_1m_'
            Category='generic/assetnote'
        },
        [pscustomobject]@{
            Name='httparchive-php'
            Prefix='httparchive_php_'
            Category='technology/assetnote'
        },
        [pscustomobject]@{
            Name='httparchive-jsp-jspa-do-action'
            Prefix='httparchive_jsp_jspa_do_action_'
            Category='technology/assetnote'
        },
        [pscustomobject]@{
            Name='httparchive-aspx-asp-cfm-svc-ashx-asmx'
            Prefix='httparchive_aspx_asp_cfm_svc_ashx_asmx_'
            Category='technology/assetnote'
        }
    )

    foreach($item in $assetnoteAutomated){
        $meta=Get-LatestAssetnoteWordlist -MetadataUrl $automatedMetadataUrl -FilePrefix $item.Prefix
        if(-not $meta){
            continue
        }

        $destinationRoot = if($item.Category -eq 'generic/assetnote'){
            $AssetnoteAutomatedDir
        }
        else{
            $AssetnoteTechnologyDir
        }

        $destination=Join-Path $destinationRoot $meta.Filename

        Download-Wordlist `
            -Name $item.Name `
            -Url $meta.Url `
            -Destination $destination `
            -Source 'Assetnote' `
            -Version $meta.Filename

        if(Test-Path $destination){
            Add-WordlistManifestEntry `
                -Manifest $manifest `
                -Category $item.Category `
                -Name $item.Name `
                -Path (Get-RepoRelativePath $destination) `
                -Source 'assetnote/wordlists' `
                -Url $meta.Url `
                -Version $meta.Filename `
                -LineCount $meta.LineCount `
                -FileSize $meta.FileSize
        }
    }

    # Technology-specific Assetnote lists. These are selected because they
    # map directly to the technology-aware discovery design. We intentionally
    # skip extremely large lists such as Nginx (>100 MB in current metadata);
    # directory.py can add them later as an explicit deep-scan profile.
    $technologyLists = @(
        'apache',
        'django',
        'express',
        'flask',
        'laravel',
        'rails',
        'spring',
        'symfony',
        'tomcat',
        'yii',
        'zend',
        'coldfusion'
    )

    foreach($technology in $technologyLists){
        $meta=Get-LatestAssetnoteWordlist `
            -MetadataUrl $technologyMetadataUrl `
            -FilePrefix "httparchive_${technology}_"

        if(-not $meta){
            continue
        }

        if($meta.LineCount -eq 0){
            Write-Log "Assetnote technology wordlist kosong; dilewati: $technology" 'WARN'
            continue
        }

        $destination=Join-Path $AssetnoteTechnologyDir $meta.Filename

        Download-Wordlist `
            -Name "assetnote-$technology" `
            -Url $meta.Url `
            -Destination $destination `
            -Source 'Assetnote' `
            -Version $meta.Filename

        if(Test-Path $destination){
            Add-WordlistManifestEntry `
                -Manifest $manifest `
                -Category 'technology/assetnote' `
                -Name "assetnote-$technology" `
                -Path (Get-RepoRelativePath $destination) `
                -Source 'assetnote/wordlists' `
                -Url $meta.Url `
                -Version $meta.Filename `
                -LineCount $meta.LineCount `
                -FileSize $meta.FileSize
        }
    }

    $manifestDocument=[ordered]@{
        schema_version=1
        generated_at=(Get-Date).ToString('o')
        root=(Get-RepoRelativePath $WordlistsRoot)
        sources=@(
            [ordered]@{
                name='SecLists'
                repository='danielmiessler/SecLists'
                license='MIT'
                purpose='Generic web-content discovery'
            },
            [ordered]@{
                name='Assetnote Wordlists'
                repository='assetnote/wordlists'
                license='Apache-2.0'
                purpose='HTTP Archive generic and technology-specific content discovery'
            }
        )
        wordlists=$manifest
    }

    if(-not $DryRun){
        $manifestDocument | ConvertTo-Json -Depth 10 |
            Set-Content -Path $WordlistManifest -Encoding UTF8

        Write-Log "Wordlist manifest berhasil dibuat: $WordlistManifest" 'OK'
    }
    else{
        Write-Log "DryRun: manifest akan dibuat di $WordlistManifest" 'DRYRUN'
    }
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
        gobuster {$GobusterExe}
        'curl.exe' {Find-CurlExecutable}
        'curl' {Find-CurlExecutable}
        'openssl.exe' {Find-OpenSSLExecutable}
        'openssl' {Find-OpenSSLExecutable}
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
    Write-Log 'BrebesKab-CSIRT-Tools install-requirements.ps1 v2.20' 'STEP'
    Write-Log '============================================================' 'STEP'

    Request-Administrator

    if(-not(Test-Administrator)){
        throw 'Installer v2.19 tidak berjalan sebagai Administrator setelah proses elevation.'
    }

    if(-not [Environment]::Is64BitOperatingSystem){
        throw 'Installer v2.19 membutuhkan Windows 64-bit.'
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

    # cURL is handled separately from the standard WinGet package list.
    # Existing curl.exe installations are reused; WinGet is only invoked
    # when no native curl.exe executable is available.
    $curlPath = Ensure-Curl
    Refresh-Path

    # OpenSSL is handled separately from the standard WinGet package list.
    # Existing native openssl.exe installations are reused; WinGet is only
    # invoked when no usable OpenSSL executable can be located.
    $opensslPath = Ensure-OpenSSL
    Refresh-Path

    $venvPython=Ensure-Venv
    Install-PythonPackages $venvPython
    Install-PlaywrightChromium $venvPython

    Install-GitHubZipTool 'nuclei' 'projectdiscovery/nuclei' $NucleiDir 'nuclei.exe'
    Install-GitHubZipTool 'httpx' 'projectdiscovery/httpx' $HttpxDir 'httpx.exe'
    Install-Gobuster

    Add-UserPath $NucleiDir
    Add-UserPath $HttpxDir
    Add-UserPath $GobusterDir
    Refresh-Path

    Install-Wordlists

    Install-ZAP

    Write-Log 'Memulai verification...' 'STEP'

    Verify-Command 'git' @('--version')
    Verify-Command 'nmap' @('--version')
    Verify-Command 'ffuf' @('-V')
    Verify-Nuclei
    Verify-Command 'httpx' @('-version')
    Verify-Command 'gobuster' @('version')
    Verify-Command 'curl.exe' @('--version')
    Verify-Command 'openssl.exe' @('version')

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

    $script:State.curl_reference = $curlPath
    $script:State.openssl_reference = $opensslPath
    $script:State.gobuster_reference = $GobusterExe
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
