#requires -Version 5.1
# BrebesKab-CSIRT-Tools install-requirements.ps1 v2.30
# WinGet/App Installer is upgraded and re-verified before package installation.
# CLI version verification is based on executable availability and non-empty version output.
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SkipRollback,
    [switch]$SkipZAP,
    [switch]$Force,
    [switch]$UpdateWordlists,
    [switch]$ApproveSecurityChanges,
    [switch]$SkipWinGetUpgrade
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
$JavaReference = $null

# Assetnote metadata/CDN checks are deliberately bounded so a degraded CDN
# cannot stall the installer for a long time. Other wordlist sources keep
# the default timeout used by Download-Wordlist.
$AssetnoteTimeoutSec = 20
$script:AssetnoteMetadataCache = @{}

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
    schema_version=2.30
    installer_version='2.30'
    started_at=(Get-Date).ToString('o')
    repo_root=$RepoRoot
    dry_run=[bool]$DryRun
    update_wordlists=[bool]$UpdateWordlists
    installed_by_script=@()
    venv_created_by_script=$false
    python_reference=$null
    python_base=$null
    curl_reference=$null
    openssl_reference=$null
    gobuster_reference=$null
    security_preflight=$null
    security_changes_approved=[bool]$ApproveSecurityChanges
    winget_upgrade=[ordered]@{
        attempted=$false
        skipped=[bool]$SkipWinGetUpgrade
        before_version=$null
        after_version=$null
        before_appinstaller_version=$null
        after_appinstaller_version=$null
        update_available=$null
        exit_code=$null
        result='not-run'
        error=''
    }
    security_state=[ordered]@{
        captured=$false
        defender_detected=$false
        defender_rtp_initial=$null
        defender_rtp_changed=$false
        defender_restored=$false
        third_party_products=@()
        firewall_profiles=@()
        restoration_attempted=$false
        restoration_completed=$false
    }
    completed=$false
}

function Write-Log {
    param([string]$Message,[ValidateSet('INFO','WARN','ERROR','OK','STEP','DRYRUN','SECURITY')][string]$Level='INFO')
    $line="[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    $color = switch ($Level) { ERROR {'Red'} WARN {'Yellow'} OK {'Green'} STEP {'Cyan'} DRYRUN {'Magenta'} SECURITY {'Yellow'} default {'Gray'} }
    Write-Host $line -ForegroundColor $color
    if (-not (Test-Path $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null }
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::AppendAllText($LogFile, $line + [Environment]::NewLine, $utf8NoBom)
}

function Write-Utf8NoBom {
    <#
    .SYNOPSIS
        Write text as UTF-8 without BOM.

    .DESCRIPTION
        Windows PowerShell 5.1's Set-Content -Encoding UTF8 writes a UTF-8 BOM.
        The repository standard is UTF-8 without BOM for JSON and YAML.
        This helper uses .NET directly so the output is deterministic on
        Windows PowerShell 5.1 and PowerShell 7+.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Content
    )

    $parent = Split-Path -Parent $Path
    if ($parent) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
}

function Write-JsonUtf8NoBom {
    <#
    .SYNOPSIS
        Serialize an object as UTF-8 JSON without BOM.

    .NOTES
        The serialized JSON is then written with UTF8Encoding($false), so the
        resulting file has no UTF-8 BOM.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object]$InputObject,

        [Parameter(Mandatory=$true)]
        [string]$Path,

        [int]$Depth = 10
    )

    $json = $InputObject | ConvertTo-Json -Depth $Depth
    Write-Utf8NoBom -Path $Path -Content $json
}

function Write-YamlUtf8NoBom {
    <#
    .SYNOPSIS
        Write YAML as UTF-8 without BOM.

    .DESCRIPTION
        The current installer does not generate YAML directly, but this helper
        establishes the same repository encoding contract for any YAML output
        added to the installer later.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Content
    )

    Write-Utf8NoBom -Path $Path -Content $Content
}

function Save-State {
    New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
    Write-JsonUtf8NoBom -InputObject $script:State -Path $StateFile -Depth 10
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
    if ($UpdateWordlists) { $elevatedArguments += '-UpdateWordlists' }
    if ($ApproveSecurityChanges) { $elevatedArguments += '-ApproveSecurityChanges' }

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


function Get-EndpointSecurityStatus {
    <#
    .SYNOPSIS
        Collect endpoint-security state without changing it.
    #>
    $result = [ordered]@{
        checked_at = (Get-Date).ToString('o')
        defender = [ordered]@{
            available = $false
            antivirus_enabled = $null
            real_time_protection_enabled = $null
            behavior_monitor_enabled = $null
            ioav_protection_enabled = $null
            network_inspection_enabled = $null
            status = 'UNKNOWN'
            error = ''
        }
        antivirus_products = @()
        firewall_profiles = @()
    }

    Write-Log 'Memeriksa status security endpoint...' 'SECURITY'

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $result.defender.available = $true
        $result.defender.antivirus_enabled = [bool]$status.AntivirusEnabled
        $result.defender.real_time_protection_enabled = [bool]$status.RealTimeProtectionEnabled
        $result.defender.behavior_monitor_enabled = [bool]$status.BehaviorMonitorEnabled
        $result.defender.ioav_protection_enabled = [bool]$status.IoavProtectionEnabled
        $result.defender.network_inspection_enabled = [bool]$status.NISEnabled
        $result.defender.status = if(
            $status.AntivirusEnabled -or
            $status.RealTimeProtectionEnabled
        ) { 'ACTIVE' } else { 'INACTIVE' }

        Write-Log ("Microsoft Defender        : {0}" -f $result.defender.status) 'SECURITY'
        Write-Log ("Real-Time Protection      : {0}" -f $(if($status.RealTimeProtectionEnabled){'ACTIVE'}else{'INACTIVE'})) 'SECURITY'
        Write-Log ("Behavior Monitor          : {0}" -f $(if($status.BehaviorMonitorEnabled){'ACTIVE'}else{'INACTIVE'})) 'SECURITY'
        Write-Log ("IOAV Protection           : {0}" -f $(if($status.IoavProtectionEnabled){'ACTIVE'}else{'INACTIVE'})) 'SECURITY'
        Write-Log ("Network Inspection       : {0}" -f $(if($status.NISEnabled){'ACTIVE'}else{'INACTIVE'})) 'SECURITY'
    }
    catch {
        $result.defender.error = $_.Exception.Message
        Write-Log 'Tidak dapat membaca status Microsoft Defender.' 'WARN'
        Write-Log "Defender status detail: $($_.Exception.Message)" 'WARN'
    }

    try {
        $products = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop)
        foreach($product in $products) {
            $displayName = [string]$product.displayName
            if([string]::IsNullOrWhiteSpace($displayName)) { continue }

            $result.antivirus_products += [ordered]@{
                display_name = $displayName
                product_state = [string]$product.productState
                path = [string]$product.pathToSignedProductExe
            }
        }

        if($result.antivirus_products.Count -gt 0) {
            foreach($product in $result.antivirus_products) {
                Write-Log "Endpoint AV/EDR terdeteksi: $($product.display_name)" 'SECURITY'
            }
        }
        else {
            Write-Log 'Tidak ada produk antivirus yang dapat dibaca dari SecurityCenter2.' 'WARN'
        }
    }
    catch {
        Write-Log "Daftar antivirus/EDR pihak ketiga tidak dapat diverifikasi: $($_.Exception.Message)" 'WARN'
    }

    try {
        if(Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
            foreach($profile in $profiles) {
                $result.firewall_profiles += [ordered]@{
                    name = [string]$profile.Name
                    enabled = [bool]$profile.Enabled
                }
                Write-Log "Windows Firewall [$($profile.Name)] : $(if($profile.Enabled){'ACTIVE'}else{'INACTIVE'})" 'SECURITY'
            }
        }
        else {
            Write-Log 'Get-NetFirewallProfile tidak tersedia; status Windows Firewall tidak diverifikasi.' 'WARN'
        }
    }
    catch {
        Write-Log "Status Windows Firewall tidak dapat diverifikasi: $($_.Exception.Message)" 'WARN'
    }

    return [pscustomobject]$result
}

function Request-SecurityChangeApproval {
    param(
        [Parameter(Mandatory=$true)]
        [pscustomobject]$SecurityStatus
    )

    $rtpActive = $false
    if($SecurityStatus.defender.available) {
        $rtpActive = [bool]$SecurityStatus.defender.real_time_protection_enabled
    }

    if(-not $rtpActive) {
        Write-Log 'Real-Time Protection tidak aktif; tidak diperlukan persetujuan untuk menonaktifkannya.' 'SECURITY'
        return $false
    }

    if($DryRun) {
        Write-Log 'DryRun: security mitigation tidak akan dilakukan.' 'DRYRUN'
        return $false
    }

    if($ApproveSecurityChanges) {
        Write-Log 'Persetujuan security mitigation diberikan melalui -ApproveSecurityChanges.' 'SECURITY'
        return $true
    }

    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Yellow
    Write-Host ' PERSETUJUAN SECURITY MITIGATION' -ForegroundColor Yellow
    Write-Host '============================================================' -ForegroundColor Yellow
    Write-Host 'Microsoft Defender Real-Time Protection saat ini AKTIF.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Installer dapat menonaktifkan Real-Time Protection sementara' -ForegroundColor Yellow
    Write-Host 'selama proses instalasi BrebesKab-CSIRT-Tools.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'PERHATIAN:' -ForegroundColor Red
    Write-Host '- Tindakan ini hanya ditujukan untuk VM/lab khusus project.' -ForegroundColor Red
    Write-Host '- Installer tidak otomatis menonaktifkan antivirus/EDR pihak ketiga.' -ForegroundColor Red
    Write-Host '- Windows Firewall, SmartScreen, App Control, dan EDR lain tidak' -ForegroundColor Red
    Write-Host '  diubah otomatis karena mekanisme restoration berbeda-beda.' -ForegroundColor Red
    Write-Host '- Defender akan dipulihkan ke kondisi awal setelah installer selesai.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Ketik YES untuk memberikan persetujuan.' -ForegroundColor Cyan

    $answer = Read-Host 'Persetujuan'
    if($answer -ceq 'YES') {
        Write-Log 'Operator menyetujui temporary Defender Real-Time Protection mitigation.' 'SECURITY'
        return $true
    }

    Write-Log 'Operator tidak menyetujui security mitigation. Defender tetap aktif.' 'WARN'
    return $false
}

function Disable-DefenderTemporarily {
    param(
        [Parameter(Mandatory=$true)]
        [pscustomobject]$SecurityStatus
    )

    if(-not $SecurityStatus.defender.available) {
        Write-Log 'Defender tidak dapat diverifikasi; tidak ada perubahan Defender yang dilakukan.' 'WARN'
        return
    }

    if(-not [bool]$SecurityStatus.defender.real_time_protection_enabled) {
        Write-Log 'Defender Real-Time Protection sudah INACTIVE; tidak ada perubahan.' 'SECURITY'
        return
    }

    if(-not $SecurityStatus.defender.antivirus_enabled) {
        Write-Log 'Microsoft Defender Antivirus tidak aktif; tidak ada perubahan.' 'SECURITY'
        return
    }

    $script:State.security_state.captured = $true
    $script:State.security_state.defender_detected = $true
    $script:State.security_state.defender_rtp_initial = [bool]$SecurityStatus.defender.real_time_protection_enabled
    Save-State

    Write-Log 'Menonaktifkan Microsoft Defender Real-Time Protection sementara sesuai persetujuan operator...' 'SECURITY'

    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop

        # Mark the state as changed immediately after Set-MpPreference succeeds.
        # If verification fails, restoration must still be attempted conservatively.
        $script:State.security_state.defender_rtp_changed = $true
        Save-State
    }
    catch {
        Write-Log "Gagal mengubah Defender Real-Time Protection: $($_.Exception.Message)" 'WARN'
        Write-Log 'Kemungkinan Tamper Protection, policy organisasi, atau security control lain mencegah perubahan.' 'WARN'
        return
    }

    Start-Sleep -Seconds 2

    try {
        $after = Get-MpComputerStatus -ErrorAction Stop
        if([bool]$after.RealTimeProtectionEnabled) {
            Write-Log 'Defender Real-Time Protection masih ACTIVE setelah permintaan disable. Security control mungkin menolak perubahan.' 'WARN'
            return
        }

        Write-Log 'Defender Real-Time Protection berhasil dinonaktifkan sementara.' 'SECURITY'
    }
    catch {
        Write-Log "Tidak dapat memverifikasi perubahan Defender: $($_.Exception.Message)" 'WARN'
        Write-Log 'State perubahan tetap dianggap aktif agar restoration tetap dicoba.' 'WARN'
    }
}

function Restore-EndpointSecurity {
    if($DryRun) {
        return
    }

    $securityState = $script:State.security_state
    if($null -eq $securityState) {
        return
    }

    $securityState.restoration_attempted = $true
    Save-State

    if(
        [bool]$securityState.defender_rtp_changed -and
        [bool]$securityState.defender_rtp_initial
    ) {
        Write-Log 'Memulihkan Microsoft Defender Real-Time Protection ke kondisi awal...' 'SECURITY'

        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Start-Sleep -Seconds 2

            $after = Get-MpComputerStatus -ErrorAction Stop
            if([bool]$after.RealTimeProtectionEnabled) {
                $securityState.defender_restored = $true
                Write-Log 'Defender Real-Time Protection berhasil dipulihkan ke ACTIVE.' 'OK'
            }
            else {
                Write-Log 'Defender Real-Time Protection belum kembali ACTIVE setelah restoration.' 'ERROR'
            }
        }
        catch {
            Write-Log "GAGAL memulihkan Defender Real-Time Protection: $($_.Exception.Message)" 'ERROR'
            Write-Log 'Operator harus memeriksa dan memulihkan Microsoft Defender secara manual.' 'ERROR'
        }
    }
    elseif([bool]$securityState.defender_detected) {
        Write-Log 'Defender terdeteksi tetapi tidak diubah oleh installer; tidak ada restoration yang diperlukan.' 'SECURITY'
    }

    $securityState.restoration_completed = $true
    $securityState.restoration_completed_at = (Get-Date).ToString('o')
    Save-State
}

function Write-SecurityWarning {
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Yellow
    Write-Host ' PERINGATAN KEAMANAN' -ForegroundColor Yellow
    Write-Host '============================================================' -ForegroundColor Yellow
    Write-Host 'install-requirements.ps1 ditujukan untuk VM/lab khusus BrebesKab-CSIRT-Tools.' -ForegroundColor Yellow
    Write-Host 'JANGAN menjalankan installer ini pada workstation atau server production.' -ForegroundColor Red
    Write-Host ''
    Write-Host 'Tool security dapat memicu Microsoft Defender, antivirus/EDR,' -ForegroundColor Yellow
    Write-Host 'SmartScreen, firewall, atau application-control selama download/install/execute.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'Installer tidak menonaktifkan security control secara diam-diam.' -ForegroundColor Cyan
    Write-Host 'Perubahan Defender hanya dilakukan setelah persetujuan operator dan' -ForegroundColor Cyan
    Write-Host 'kondisi awal disimpan untuk restoration.' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Antivirus/EDR pihak ketiga, firewall, SmartScreen, dan application' -ForegroundColor Yellow
    Write-Host 'control tidak dinonaktifkan otomatis karena restoration-nya bergantung' -ForegroundColor Yellow
    Write-Host 'pada vendor/policy masing-masing.' -ForegroundColor Yellow
    Write-Host '============================================================' -ForegroundColor Yellow
    Write-Host ''
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

function Get-AppInstallerVersion {
    <#
    .SYNOPSIS
        Return the installed Microsoft App Installer version, which provides WinGet.
    #>
    try {
        $packages = @(Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction Stop)
        if($packages.Count -eq 0) { return $null }
        $package = $packages | Sort-Object Version -Descending | Select-Object -First 1
        if($null -eq $package.Version) { return $null }
        return [version]$package.Version
    }
    catch {
        return $null
    }
}

function Get-WinGetVersion {
    try {
        $path = Find-Command 'winget'
        if([string]::IsNullOrWhiteSpace($path)) { return $null }
        $output = & $path --version 2>&1 | Out-String
        $value = $output.Trim()
        if([string]::IsNullOrWhiteSpace($value)) { return $null }
        return $value
    }
    catch {
        return $null
    }
}

function Update-WinGet {
    <#
    .SYNOPSIS
        Upgrade Microsoft App Installer / WinGet before installing dependencies.

    .DESCRIPTION
        WinGet is delivered as part of Microsoft App Installer. The installer
        first records both the WinGet CLI version and the App Installer package
        version, then asks WinGet to upgrade Microsoft.AppInstaller. A failure
        to find an available upgrade is not treated as an error. A real upgrade
        failure is logged and the existing WinGet installation is re-verified.

        This function never uses `winget upgrade --all`; it only targets the
        WinGet/App Installer package so unrelated applications are not changed.
    #>
    if($SkipWinGetUpgrade) {
        Write-Log 'Upgrade WinGet dilewati karena -SkipWinGetUpgrade.' 'WARN'
        $script:State.winget_upgrade.result = 'skipped'
        Save-State
        return
    }

    $wingetPath = Find-Command 'winget'
    if([string]::IsNullOrWhiteSpace($wingetPath)) {
        throw 'WinGet tidak ditemukan sebelum proses upgrade. Installer tidak dapat melakukan bootstrap WinGet secara otomatis.'
    }

    $beforeWinGet = Get-WinGetVersion
    $beforeAppInstaller = Get-AppInstallerVersion

    $script:State.winget_upgrade.attempted = $true
    $script:State.winget_upgrade.before_version = $beforeWinGet
    $script:State.winget_upgrade.before_appinstaller_version = if($beforeAppInstaller){$beforeAppInstaller.ToString()}else{$null}
    Save-State

    Write-Log "WinGet sebelum upgrade : $(if($beforeWinGet){$beforeWinGet}else{'UNKNOWN'})" 'SECURITY'
    Write-Log "App Installer sebelum upgrade : $(if($beforeAppInstaller){$beforeAppInstaller}else{'UNKNOWN'})" 'SECURITY'

    if($DryRun) {
        Write-Log 'DryRun: akan menjalankan upgrade Microsoft.AppInstaller/WinGet, tetapi command tidak dijalankan.' 'DRYRUN'
        $script:State.winget_upgrade.result = 'dry-run'
        Save-State
        return
    }

    Write-Log 'Memeriksa update Microsoft App Installer / WinGet...' 'STEP'

    $upgradeOutput = ''
    $exitCode = 0
    try {
        $upgradeOutput = & $wingetPath upgrade `
            --id Microsoft.AppInstaller `
            --exact `
            --silent `
            --accept-package-agreements `
            --accept-source-agreements 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
    }
    catch {
        $exitCode = -1
        $script:State.winget_upgrade.error = $_.Exception.Message
        Write-Log "Exception saat upgrade WinGet/App Installer: $($_.Exception.Message)" 'WARN'
    }

    $script:State.winget_upgrade.exit_code = $exitCode
    if(-not [string]::IsNullOrWhiteSpace($upgradeOutput)) {
        $cleanOutput = $upgradeOutput.Trim()
        Write-Log "WinGet upgrade output: $cleanOutput" 'INFO'
    }

    # WinGet may report that no upgrade is applicable while returning a
    # non-zero code depending on the installed/source state. Verify the actual
    # App Installer package and CLI after the command instead of relying only
    # on the exit code.
    Start-Sleep -Seconds 3
    Refresh-Path

    $newWingetPath = Find-Command 'winget'
    $afterWinGet = Get-WinGetVersion
    $afterAppInstaller = Get-AppInstallerVersion

    $script:State.winget_upgrade.after_version = $afterWinGet
    $script:State.winget_upgrade.after_appinstaller_version = if($afterAppInstaller){$afterAppInstaller.ToString()}else{$null}

    if($beforeAppInstaller -and $afterAppInstaller) {
        $script:State.winget_upgrade.update_available = ($afterAppInstaller -gt $beforeAppInstaller)
    }
    else {
        $script:State.winget_upgrade.update_available = $null
    }

    if([string]::IsNullOrWhiteSpace($newWingetPath) -or [string]::IsNullOrWhiteSpace($afterWinGet)) {
        $script:State.winget_upgrade.result = 'failed'
        Save-State
        throw 'WinGet/App Installer tidak dapat diverifikasi setelah proses upgrade.'
    }

    if($exitCode -eq 0) {
        if($script:State.winget_upgrade.update_available -eq $true) {
            $script:State.winget_upgrade.result = 'upgraded'
            Write-Log "WinGet/App Installer berhasil di-upgrade: $beforeAppInstaller -> $afterAppInstaller" 'OK'
        }
        else {
            $script:State.winget_upgrade.result = 'already-current'
            Write-Log 'WinGet/App Installer sudah versi terbaru atau tidak ada upgrade yang tersedia.' 'OK'
        }
    }
    else {
        # If the CLI and App Installer are still healthy, do not break the
        # installation solely because the upgrade command returned a source- or
        # package-specific code. Record the condition for auditability.
        $script:State.winget_upgrade.result = 'verified-current-after-nonzero'
        Write-Log "WinGet upgrade command exit code $exitCode, tetapi WinGet tetap dapat diverifikasi: $afterWinGet" 'WARN'
        Write-Log 'Installer melanjutkan menggunakan WinGet yang terverifikasi.' 'WARN'
    }

    Save-State
    Write-Log "WinGet setelah upgrade : $afterWinGet" 'OK'
    Write-Log "App Installer setelah upgrade : $(if($afterAppInstaller){$afterAppInstaller}else{'UNKNOWN'})" 'OK'
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

function Find-JavaExecutable {
    # Resolve a real java.exe executable. Prefer PATH, then common JRE/JDK
    # installation locations. Ignore the WindowsApps execution alias.
    try {
        $command = Get-Command 'java.exe' -CommandType Application -ErrorAction Stop |
            Select-Object -First 1
        if ($command -and $command.Source) {
            $source = [string]$command.Source
            if ($source -notmatch '\\WindowsApps\\' -and (Test-Path $source)) {
                return $source
            }
        }
    } catch {}

    $patterns = @(
        (Join-Path $env:ProgramFiles 'Microsoft\jdk-*\bin\java.exe'),
        (Join-Path $env:ProgramFiles 'Eclipse Adoptium\jre-*\bin\java.exe'),
        (Join-Path $env:ProgramFiles 'Eclipse Adoptium\jdk-*\bin\java.exe'),
        (Join-Path $env:ProgramFiles 'Java\jre*\bin\java.exe'),
        (Join-Path $env:ProgramFiles 'Java\jdk*\bin\java.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Java\jre*\bin\java.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Java\jdk*\bin\java.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Microsoft\jdk-*\bin\java.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Eclipse Adoptium\jre-*\bin\java.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Eclipse Adoptium\jdk-*\bin\java.exe')
    )

    foreach ($pattern in $patterns) {
        $matches = @(Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue)
        if ($matches.Count -gt 0) {
            return ($matches | Sort-Object FullName | Select-Object -First 1).FullName
        }
    }
    return $null
}

function Ensure-Java {
    $existing = Find-JavaExecutable
    if ($existing) {
        Write-Log "Java sudah tersedia: $existing" 'OK'
        $script:JavaReference = $existing
        return $existing
    }

    if ($DryRun) {
        Write-Log 'DryRun: Java Runtime belum ditemukan; install Microsoft OpenJDK 21 via WinGet.' 'DRYRUN'
        return $null
    }

    $javaId = 'Microsoft.OpenJDK.21'
    if (-not (Get-WinGetSearchExact $javaId)) {
        throw "Java Runtime tidak ditemukan dan paket WinGet tidak tersedia: $javaId"
    }

    Write-Log "Java Runtime tidak ditemukan. Menginstall Microsoft OpenJDK 21 via WinGet: $javaId" 'STEP'

    # Do not force --scope machine. This follows the WinGet behavior that
    # successfully installed Nmap on the current VM.
    & winget install `
        --id $javaId `
        --exact `
        --source winget `
        --silent `
        --accept-package-agreements `
        --accept-source-agreements

    if ($LASTEXITCODE -ne 0) {
        throw "WinGet gagal menginstall Java Runtime $javaId. Exit code: $LASTEXITCODE"
    }

    Refresh-Path
    $installed = Find-JavaExecutable
    if (-not $installed) {
        throw 'Java Runtime berhasil dilaporkan oleh WinGet tetapi java.exe tidak ditemukan setelah instalasi.'
    }

    $script:JavaReference = $installed
    Add-InstalledComponent 'winget' 'Java Runtime' $javaId '' $installed
    Write-Log "Java Runtime berhasil diinstall: $installed" 'OK'
    return $installed
}

function Verify-Java {
    param([string]$JavaPath)
    if ($DryRun) {
        Write-Log 'DryRun: verification Java dilewati.' 'DRYRUN'
        return
    }
    if ([string]::IsNullOrWhiteSpace($JavaPath) -or -not (Test-Path $JavaPath)) {
        throw "Java executable tidak ditemukan untuk verification: $JavaPath"
    }
    $result = Invoke-NativeCapture -FilePath $JavaPath -Arguments @('-version')
    $output = ($result.StdOut + "`r`n" + $result.StdErr).Trim()
    if ($result.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($output)) {
        throw "Java verification gagal. Exit code: $($result.ExitCode). Output: $output"
    }
    Write-Log "Java OK: $output" 'OK'
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
        [Parameter(Mandatory=$true)][string]$FilePrefix,
        [int]$TimeoutSec=$AssetnoteTimeoutSec
    )

    try{
        if($script:AssetnoteMetadataCache.ContainsKey($MetadataUrl)){
            $metadata = $script:AssetnoteMetadataCache[$MetadataUrl]
        }
        else{
            Write-Log "Mengambil metadata Assetnote: $MetadataUrl" 'INFO'
            $metadata = Invoke-RestMethod -Uri $MetadataUrl -Method Get -TimeoutSec $TimeoutSec
            $script:AssetnoteMetadataCache[$MetadataUrl] = $metadata
        }

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

    # Assetnote publishes the dataset identity in the metadata table.
    # The installer selects the newest Date entry for the requested filename
    # prefix instead of hard-coding a monthly filename.
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
        Filename  = [string]$selected.Filename
        Url       = $downloadUrl
        LineCount = [int64]$selected.'Line Count'
        FileSize  = [string]$selected.'File Size'
        Date      = [string]$selected.Date
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
        [string]$ExpectedSha256='',
        [int]$TimeoutSec=60,
        [switch]$AllowReplaceExisting
    )

    if((Test-Path $Destination) -and -not $AllowReplaceExisting){
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
        Invoke-WebRequest -Uri $Url -OutFile $temp -UseBasicParsing -TimeoutSec $TimeoutSec

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
        [string]$FileSize='',
        [string]$SourceId='',
        [string]$SourceSha='',
        [string]$MetadataDate='',
        [string]$ETag='',
        [string]$LastModified=''
    )

    $sha256=''
    if(Test-Path $Path){
        try { $sha256=(Get-FileHash $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
        catch { Write-Log "Gagal menghitung SHA-256 wordlist [$Name]: $($_.Exception.Message)" 'WARN' }
    }

    $Manifest.Add([ordered]@{
        category=$Category
        name=$Name
        path=$Path
        source=$Source
        url=$Url
        version=$Version
        line_count=$LineCount
        file_size=$FileSize
        source_id=$SourceId
        source_sha=$SourceSha
        metadata_date=$MetadataDate
        sha256=$sha256
        etag=$ETag
        last_modified=$LastModified
        checked_at=(Get-Date).ToString('o')
    }) | Out-Null
}


function Test-Utf8Bom {
    param([Parameter(Mandatory=$true)][string]$Path)
    if(-not (Test-Path $Path)){ return $false }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        return ($bytes.Length -ge 3 -and
            $bytes[0] -eq 0xEF -and
            $bytes[1] -eq 0xBB -and
            $bytes[2] -eq 0xBF)
    }
    catch {
        Write-Log "Tidak dapat memeriksa BOM: $Path : $($_.Exception.Message)" 'WARN'
        return $false
    }
}

function Read-WordlistManifest {
    if(-not (Test-Path $WordlistManifest)){
        return @()
    }

    try{
        $doc=Get-Content -Path $WordlistManifest -Raw -Encoding UTF8 | ConvertFrom-Json

        if(Test-Utf8Bom -Path $WordlistManifest){
            Write-Log 'manifest.json menggunakan UTF-8 BOM; menormalisasi ke UTF-8 tanpa BOM.' 'WARN'
            Write-JsonUtf8NoBom -InputObject $doc -Path $WordlistManifest -Depth 10
        }

        if($doc.wordlists){ return @($doc.wordlists) }
        return @()
    }
    catch{
        Write-Log "Manifest wordlist lama tidak dapat dibaca: $($_.Exception.Message). Installer akan membangun manifest baru." 'WARN'
        return @()
    }
}

function Get-PreviousWordlistEntry {
    param(
        [Parameter(Mandatory=$true)][object[]]$PreviousManifest,
        [Parameter(Mandatory=$true)][string]$Name
    )

    $match=@(
        $PreviousManifest |
            Where-Object {
                $entryName=[string](Get-SafeObjectProperty -Object $_ -Name 'name')
                $entryName -eq $Name
            } |
            Select-Object -First 1
    )

    if($match.Count -eq 0){
        return $null
    }

    return $match[0]
}

function Get-GitHubFileMetadata {
    param(
        [Parameter(Mandatory=$true)][string]$Repository,
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$Ref='master'
    )

    $encodedParts=@($Path -split '/' | ForEach-Object { [uri]::EscapeDataString($_) })
    $encodedPath=$encodedParts -join '/'
    $apiUrl="https://api.github.com/repos/$Repository/contents/${encodedPath}?ref=${Ref}"

    try{
        $response=Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $GitHubHeaders
        return [pscustomobject]@{
            Url=$apiUrl
            Sha=[string]$response.sha
            Size=[int64]$response.size
            Name=[string]$response.name
        }
    }
    catch{
        Write-Log "Gagal mengambil metadata GitHub [$Repository/$Path]: $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Get-SafeObjectProperty {
    param(
        [Parameter(Mandatory=$true)][object]$Object,
        [Parameter(Mandatory=$true)][string]$Name
    )

    if($null -eq $Object){ return $null }
    $property=$Object.PSObject.Properties[$Name]
    if($null -eq $property){ return $null }
    return $property.Value
}

function Test-WordlistCurrent {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Destination,
        [Parameter(Mandatory=$true)][string]$Source,
        [string]$Version='',
        [string]$SourceId='',
        [string]$SourceSha='',
        [int64]$RemoteSize=0,
        [int64]$LineCount=0,
        [string]$FileSize='',
        [object]$PreviousEntry=$null,
        [int]$TimeoutSec=60,
        [switch]$ForceRemoteCheck
    )

    if(-not (Test-Path $Destination)){ return $false }

    if($PreviousEntry -and -not $ForceRemoteCheck){
        $previousSourceSha = [string](Get-SafeObjectProperty -Object $PreviousEntry -Name 'source_sha')
        $previousVersion   = [string](Get-SafeObjectProperty -Object $PreviousEntry -Name 'version')
        $previousLineCount = [int64](Get-SafeObjectProperty -Object $PreviousEntry -Name 'line_count')
        $previousFileSize  = [string](Get-SafeObjectProperty -Object $PreviousEntry -Name 'file_size')

        if($SourceSha -and $previousSourceSha){
            if($SourceSha -eq $previousSourceSha){
                Write-Log "Source metadata tidak berubah: $Name (GitHub source SHA cocok)." 'OK'
                return $true
            }
            return $false
        }

        if($Version -and $previousVersion){
            if($Version -eq $previousVersion){
                if($Source -eq 'Assetnote'){
                    # Assetnote equality is based on the metadata identity used by the
                    # manifest: filename + line count + file size. Date is informational
                    # because the filename already carries the published dataset date.
                    $lineCountMatches = ($LineCount -le 0 -or $previousLineCount -le 0 -or $LineCount -eq $previousLineCount)
                    $fileSizeMatches  = ([string]::IsNullOrWhiteSpace($FileSize) -or [string]::IsNullOrWhiteSpace($previousFileSize) -or $FileSize -eq $previousFileSize)

                    if($lineCountMatches -and $fileSizeMatches){
                        Write-Log "Assetnote metadata sama: $Name (filename=$Version; line_count=$LineCount; file_size=$FileSize). Date metadata dicatat sebagai informasi, bukan kriteria equality." 'OK'
                        return $true
                    }

                    Write-Log "Assetnote metadata berubah: $Name (filename sama=$Version; line_count $previousLineCount -> $LineCount; file_size $previousFileSize -> $FileSize)." 'INFO'
                    return $false
                }

                if($RemoteSize -gt 0 -and (Get-Item $Destination).Length -eq $RemoteSize){
                    Write-Log "Source metadata sama: $Name ($Version; remote size cocok)." 'OK'
                    return $true
                }

                if(-not $RemoteSize){
                    Write-Log "Source version sama: $Name ($Version)." 'OK'
                    return $true
                }
            }
            elseif($Version -ne $previousVersion){
                return $false
            }
        }
    }

    # A legacy manifest or a forced remote check may not provide enough source
    # metadata. Perform a bounded content comparison. The live wordlist is
    # never replaced unless the new content is successfully downloaded.
    if($DryRun){
        Write-Log "DryRun: wordlist perlu diverifikasi/di-update: $Name" 'DRYRUN'
        return $true
    }

    $temp="$Destination.check"
    try{
        Write-Log "Memeriksa perubahan wordlist [$Source] $Name..." 'STEP'
        Invoke-WebRequest -Uri $Url -OutFile $temp -UseBasicParsing -TimeoutSec $TimeoutSec
        if(-not (Test-Path $temp)){ throw "File hasil check tidak ditemukan: $temp" }

        $localHash=(Get-FileHash $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
        $remoteHash=(Get-FileHash $temp -Algorithm SHA256).Hash.ToLowerInvariant()

        if($localHash -eq $remoteHash){
            Write-Log "Konten wordlist sama: $Name (SHA-256 cocok)." 'OK'
            Remove-Item $temp -Force -ErrorAction SilentlyContinue
            return $true
        }

        Write-Log "Perubahan konten wordlist terdeteksi: $Name (SHA-256 berbeda)." 'INFO'
        Remove-Item $temp -Force -ErrorAction SilentlyContinue
        return $false
    }
    catch{
        Remove-Item $temp -Force -ErrorAction SilentlyContinue
        Write-Log "Tidak dapat memastikan update [$Name]: $($_.Exception.Message). Wordlist lama dipertahankan." 'WARN'
        return $true
    }
}

function Sync-Wordlist {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$Destination,
        [Parameter(Mandatory=$true)][string]$Source,
        [string]$Category='generic',
        [string]$Version='',
        [string]$SourceId='',
        [string]$SourceSha='',
        [int64]$RemoteSize=0,
        [int64]$LineCount=0,
        [string]$FileSize='',
        [object]$PreviousEntry=$null,
        [int]$TimeoutSec=60,
        [switch]$ForceRemoteCheck
    )

    $needsDownload = -not (Test-Path $Destination)

    if(-not $needsDownload){
        $current=Test-WordlistCurrent `
            -Name $Name -Url $Url -Destination $Destination -Source $Source `
            -Version $Version -SourceId $SourceId -SourceSha $SourceSha `
            -RemoteSize $RemoteSize `
            -LineCount $LineCount -FileSize $FileSize `
            -PreviousEntry $PreviousEntry -TimeoutSec $TimeoutSec -ForceRemoteCheck:$ForceRemoteCheck
        $needsDownload = -not $current
    }

    if($needsDownload){
        $updated=Download-Wordlist `
            -Name $Name -Url $Url -Destination $Destination `
            -Source $Source -Version $Version `
            -TimeoutSec $TimeoutSec `
            -AllowReplaceExisting
        if(-not (Test-Path $Destination)){
            return $false
        }
        if($updated){
            Write-Log "Wordlist diperbarui/diinstall: $Name" 'OK'

            $previousEntryPath = [string](Get-SafeObjectProperty -Object $PreviousEntry -Name 'path')
            if($previousEntryPath){
                $previousPath=Join-Path $RepoRoot ($previousEntryPath -replace '/', '\')
                $currentPath=[IO.Path]::GetFullPath($Destination)
                if((Test-Path $previousPath) -and ([IO.Path]::GetFullPath($previousPath) -ne $currentPath)){
                    Remove-Item $previousPath -Force -ErrorAction SilentlyContinue
                    Write-Log "Wordlist versi lama dihapus setelah update: $previousPath" 'INFO'
                }
            }
        }
    }

    return (Test-Path $Destination)
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
        Write-Log 'DryRun: wordlist installation/update akan menggunakan layout generic/technology dan manifest.json.' 'DRYRUN'
    }

    New-Item -ItemType Directory -Path `
        $SecListsWordlistsDir,
        $AssetnoteAutomatedDir,
        $AssetnoteTechnologyDir `
        -Force | Out-Null

    $previousManifest=Read-WordlistManifest
    $manifest = New-Object System.Collections.ArrayList

    if($UpdateWordlists){
        Write-Log 'Mode UpdateWordlists aktif: memeriksa seluruh wordlist yang dikelola installer.' 'STEP'
    }
    else{
        Write-Log 'Memeriksa wordlist: file yang sudah ada juga akan dicek terhadap source terbaru.' 'STEP'
    }

    # SecLists: use the GitHub Contents API SHA as a lightweight source
    # fingerprint. If the API is unavailable, the existing wordlist is kept.
    $secLists = @(
        [pscustomobject]@{ Name='common'; Category='generic/seclists'; File='common.txt' },
        [pscustomobject]@{ Name='quickhits'; Category='generic/seclists'; File='quickhits.txt' },
        [pscustomobject]@{ Name='raft-small-directories'; Category='generic/seclists'; File='raft-small-directories.txt' },
        [pscustomobject]@{ Name='raft-medium-directories'; Category='generic/seclists'; File='raft-medium-directories.txt' },
        [pscustomobject]@{ Name='raft-large-directories'; Category='generic/seclists'; File='raft-large-directories.txt' }
    )

    foreach($item in $secLists){
        $url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/$($item.File)"
        $destination=Join-Path $SecListsWordlistsDir $item.File
        $previous=Get-PreviousWordlistEntry -PreviousManifest $previousManifest -Name $item.Name
        $sourceMeta=Get-GitHubFileMetadata -Repository 'danielmiessler/SecLists' -Path "Discovery/Web-Content/$($item.File)" -Ref 'master'

        $sourceSha=if($sourceMeta){ [string]$sourceMeta.Sha } else { '' }
        $sourceSize=if($sourceMeta){ [int64]$sourceMeta.Size } else { 0 }
        $available=Sync-Wordlist `
            -Name $item.Name -Url $url -Destination $destination `
            -Source 'SecLists' -Category $item.Category `
            -SourceId "danielmiessler/SecLists:Discovery/Web-Content/$($item.File)" `
            -SourceSha $sourceSha -RemoteSize $sourceSize `
            -PreviousEntry $previous -TimeoutSec 60 `
            -ForceRemoteCheck:$UpdateWordlists

        if($available){
            Add-WordlistManifestEntry `
                -Manifest $manifest `
                -Category $item.Category `
                -Name $item.Name `
                -Path (Get-RepoRelativePath $destination) `
                -Source 'danielmiessler/SecLists' `
                -Url $url `
                -SourceId "danielmiessler/SecLists:Discovery/Web-Content/$($item.File)" `
                -SourceSha $sourceSha
        }
    }

    $automatedMetadataUrl='https://raw.githubusercontent.com/assetnote/wordlists/master/data/automated.json'
    $technologyMetadataUrl='https://raw.githubusercontent.com/assetnote/wordlists/master/data/technologies.json'

    $assetnoteAutomated = @(
        [pscustomobject]@{ Name='httparchive-directories-1m'; Prefix='httparchive_directories_1m_'; Category='generic/assetnote' },
        [pscustomobject]@{ Name='httparchive-php'; Prefix='httparchive_php_'; Category='technology/assetnote' },
        [pscustomobject]@{ Name='httparchive-jsp-jspa-do-action'; Prefix='httparchive_jsp_jspa_do_action_'; Category='technology/assetnote' },
        [pscustomobject]@{ Name='httparchive-aspx-asp-cfm-svc-ashx-asmx'; Prefix='httparchive_aspx_asp_cfm_svc_ashx_asmx_'; Category='technology/assetnote' }
    )

    foreach($item in $assetnoteAutomated){
        $meta=Get-LatestAssetnoteWordlist -MetadataUrl $automatedMetadataUrl -FilePrefix $item.Prefix -TimeoutSec $AssetnoteTimeoutSec
        if(-not $meta){ continue }

        $destinationRoot=if($item.Category -eq 'generic/assetnote'){ $AssetnoteAutomatedDir } else { $AssetnoteTechnologyDir }
        $destination=Join-Path $destinationRoot $meta.Filename
        $previous=Get-PreviousWordlistEntry -PreviousManifest $previousManifest -Name $item.Name
        $sourceId="assetnote/wordlists:$($meta.Filename)"

        $available=Sync-Wordlist `
            -Name $item.Name -Url $meta.Url -Destination $destination `
            -Source 'Assetnote' -Category $item.Category `
            -Version $meta.Filename -SourceId $sourceId `
            -LineCount $meta.LineCount -FileSize $meta.FileSize `
            -PreviousEntry $previous -TimeoutSec $AssetnoteTimeoutSec `
            -ForceRemoteCheck:$UpdateWordlists

        if($available){
            Add-WordlistManifestEntry `
                -Manifest $manifest `
                -Category $item.Category `
                -Name $item.Name `
                -Path (Get-RepoRelativePath $destination) `
                -Source 'assetnote/wordlists' `
                -Url $meta.Url `
                -Version $meta.Filename `
                -LineCount $meta.LineCount `
                -FileSize $meta.FileSize `
                -MetadataDate $meta.Date `
                -SourceId $sourceId
        }
    }

    $technologyLists=@(
        'apache','django','express','flask','laravel','rails',
        'spring','symfony','tomcat','yii','zend','coldfusion'
    )

    foreach($technology in $technologyLists){
        $meta=Get-LatestAssetnoteWordlist `
            -MetadataUrl $technologyMetadataUrl `
            -FilePrefix "httparchive_${technology}_" `
            -TimeoutSec $AssetnoteTimeoutSec

        if(-not $meta){ continue }
        if($meta.LineCount -eq 0){
            Write-Log "Assetnote technology wordlist kosong; dilewati: $technology" 'WARN'
            continue
        }

        $destination=Join-Path $AssetnoteTechnologyDir $meta.Filename
        $name="assetnote-$technology"
        $previous=Get-PreviousWordlistEntry -PreviousManifest $previousManifest -Name $name
        $sourceId="assetnote/wordlists:$($meta.Filename)"

        $available=Sync-Wordlist `
            -Name $name -Url $meta.Url -Destination $destination `
            -Source 'Assetnote' -Category 'technology/assetnote' `
            -Version $meta.Filename -SourceId $sourceId `
            -LineCount $meta.LineCount -FileSize $meta.FileSize `
            -PreviousEntry $previous -TimeoutSec $AssetnoteTimeoutSec `
            -ForceRemoteCheck:$UpdateWordlists

        if($available){
            Add-WordlistManifestEntry `
                -Manifest $manifest `
                -Category 'technology/assetnote' `
                -Name $name `
                -Path (Get-RepoRelativePath $destination) `
                -Source 'assetnote/wordlists' `
                -Url $meta.Url `
                -Version $meta.Filename `
                -LineCount $meta.LineCount `
                -FileSize $meta.FileSize `
                -MetadataDate $meta.Date `
                -SourceId $sourceId
        }
    }

    $manifestDocument=[ordered]@{
        schema_version=2
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
        Write-JsonUtf8NoBom `
            -InputObject $manifestDocument `
            -Path $WordlistManifest `
            -Depth 10
        Write-Log "Wordlist manifest berhasil dibuat/diperbarui (UTF-8 tanpa BOM): $WordlistManifest" 'OK'
    }
    else{
        Write-Log "DryRun: manifest akan dibuat/diperbarui di $WordlistManifest" 'DRYRUN'
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

function Invoke-VersionCapture {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [string[]]$Arguments=@()
    )

    if(-not (Test-Path $FilePath)){
        throw "Executable tidak ditemukan: $FilePath"
    }

    $stdoutFile = Join-Path $DownloadRoot ("version-" + [Guid]::NewGuid().ToString('N') + ".stdout")
    $stderrFile = Join-Path $DownloadRoot ("version-" + [Guid]::NewGuid().ToString('N') + ".stderr")

    try{
        $argumentString = ($Arguments | ForEach-Object {
            if($_ -match '[\s"]') { '"' + ($_.Replace('"','\"')) + '"' } else { $_ }
        }) -join ' '

        $process = Start-Process `
            -FilePath $FilePath `
            -ArgumentList $argumentString `
            -RedirectStandardOutput $stdoutFile `
            -RedirectStandardError $stderrFile `
            -WindowStyle Hidden `
            -Wait `
            -PassThru `
            -ErrorAction Stop

        $stdout = if(Test-Path $stdoutFile){ Get-Content $stdoutFile -Raw -ErrorAction SilentlyContinue } else { '' }
        $stderr = if(Test-Path $stderrFile){ Get-Content $stderrFile -Raw -ErrorAction SilentlyContinue } else { '' }

        [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut   = [string]$stdout
            StdErr   = [string]$stderr
        }
    }
    finally{
        Remove-Item $stdoutFile,$stderrFile -Force -ErrorAction SilentlyContinue
    }
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

    # Use Start-Process redirection for CLI version checks. This keeps native
    # stderr out of the Windows PowerShell error stream, eliminating the
    # misleading NativeCommandError noise produced by some Go CLIs.
    $result = Invoke-VersionCapture -FilePath $path -Arguments $Arguments
    $output = Get-VerificationOutput $result

    if([string]::IsNullOrWhiteSpace($output)){
        throw "Verifikasi gagal untuk ${Name}: command tidak mengembalikan output. Exit code: $($result.ExitCode)."
    }

    Write-Log "$Name OK: $output" 'OK'
}

function Verify-Gobuster {
    if($DryRun){
        Write-Log 'DryRun: verification dilewati untuk gobuster.' 'DRYRUN'
        return
    }

    $path = Find-ToolExecutable 'gobuster'

    if(-not $path){
        throw 'Tool tidak ditemukan: gobuster'
    }

    Write-Log "VERIFY gobuster -> $path"

    # Gobuster does not expose a stable `version` subcommand in the
    # installed CLI. Read the Windows executable version metadata instead,
    # keeping verification consistent with the other binary checks without
    # producing a misleading "No help topic for 'version'" message.
    $versionInfo = (Get-Item -LiteralPath $path -ErrorAction Stop).VersionInfo
    $version = [string]$versionInfo.ProductVersion

    if([string]::IsNullOrWhiteSpace($version)){
        $version = [string]$versionInfo.FileVersion
    }

    if(-not [string]::IsNullOrWhiteSpace($version)){
        $displayVersion = $version.Trim()
        if($displayVersion -notmatch '^v'){
            $displayVersion = "v$displayVersion"
        }

        Write-Log "gobuster OK: $displayVersion (executable metadata)" 'OK'
        return
    }

    # Fallback: verify that the executable itself responds to --help when
    # version metadata is unavailable.
    $result = Invoke-VersionCapture -FilePath $path -Arguments @('--help')
    $output = Get-VerificationOutput $result

    if([string]::IsNullOrWhiteSpace($output)){
        throw "Verifikasi Gobuster gagal: executable tidak memiliki version metadata dan command --help tidak mengembalikan output. Exit code: $($result.ExitCode)."
    }

    Write-Log 'gobuster OK: executable merespons --help (version metadata tidak tersedia).' 'OK'
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

    $result = Invoke-VersionCapture -FilePath $path -Arguments @('-version')
    $output = Get-VerificationOutput $result

    if([string]::IsNullOrWhiteSpace($output)){
        throw "Verifikasi Nuclei gagal: command -version tidak mengembalikan output. Exit code: $($result.ExitCode)."
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
                            2>&1 | Out-String | ForEach-Object {
                                $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
                                [System.IO.File]::AppendAllText($LogFile, $_, $utf8NoBom)
                            }

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
    Write-Log 'BrebesKab-CSIRT-Tools install-requirements.ps1 v2.30' 'STEP'
    Write-Log '============================================================' 'STEP'

    Request-Administrator

    if(-not(Test-Administrator)){
        throw 'Installer v2.30 tidak berjalan sebagai Administrator setelah proses elevation.'
    }

    if(-not [Environment]::Is64BitOperatingSystem){
        throw 'Installer v2.30 membutuhkan Windows 64-bit.'
    }

    if(-not(Find-Command 'winget')){
        throw 'WinGet tidak ditemukan. Install/update Microsoft App Installer terlebih dahulu.'
    }

    Update-WinGet
    Refresh-Path

    $verifiedWingetVersion = Get-WinGetVersion
    if([string]::IsNullOrWhiteSpace($verifiedWingetVersion)){
        throw 'WinGet tidak dapat diverifikasi setelah proses upgrade.'
    }
    Write-Log "WinGet verified: $verifiedWingetVersion" 'OK'

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

    $javaPath = Ensure-Java
    Refresh-Path

    Install-ZAP

    Write-Log 'Memulai verification...' 'STEP'

    Verify-Command 'git' @('--version')
    Verify-Command 'nmap' @('--version')
    Verify-Command 'ffuf' @('-V')
    Verify-Nuclei
    Verify-Command 'httpx' @('-version')
    Verify-Gobuster
    Verify-Command 'curl.exe' @('--version')
    Verify-Command 'openssl.exe' @('version')
    Verify-Java $javaPath

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
    $script:State.java_reference = $javaPath
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
finally {
    try {
        Restore-EndpointSecurity
    }
    catch {
        Write-Log "Security restoration handler gagal: $($_.Exception.Message)" 'ERROR'
    }
}
