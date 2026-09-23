#requires -Version 5.1

<#
.SYNOPSIS
    Fix and standardize BrebesKab-CSIRT-Tools repository structure.

.DESCRIPTION
    This script prepares the repository structure for the
    BrebesKab-CSIRT-Tools project.

    IMPORTANT:
    - Does NOT create Python source code.
    - Does NOT create pyproject.toml.
    - Does NOT create requirements.txt.
    - Does NOT create a Python virtual environment.
    - Does NOT install any software.
    - Does NOT overwrite existing documentation files.

    The script uses the directory containing this script
    as the repository root.

.NOTES
    Target:
        Windows 11 Pro

    Project:
        BrebesKab-CSIRT-Tools
#>

$ErrorActionPreference = "Stop"

# ============================================================
# Repository Root
# ============================================================

$RepoPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " BrebesKab-CSIRT-Tools" -ForegroundColor Cyan
Write-Host " Repository Structure Fixer" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Repository root:" -ForegroundColor Cyan
Write-Host "  $RepoPath"
Write-Host ""

# ============================================================
# Validate repository
# ============================================================

if (-not (Test-Path -LiteralPath $RepoPath -PathType Container)) {
    Write-Host "[ERROR] Repository root tidak ditemukan." -ForegroundColor Red
    exit 1
}

$ReadmePath = Join-Path $RepoPath "README.md"

if (-not (Test-Path -LiteralPath $ReadmePath -PathType Leaf)) {
    Write-Host "[ERROR] README.md tidak ditemukan." -ForegroundColor Red
    Write-Host ""
    Write-Host "Script harus berada di root repository:"
    Write-Host ""
    Write-Host "BrebesKab-CSIRT-Tools\fix-brebeskab-csirt-structure.ps1"
    Write-Host ""
    exit 1
}

# ============================================================
# Helper Functions
# ============================================================

function Ensure-Directory {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $FullPath = Join-Path $RepoPath $RelativePath

    if (-not (Test-Path -LiteralPath $FullPath -PathType Container)) {
        New-Item -ItemType Directory -Path $FullPath -Force | Out-Null
        Write-Host "[CREATE DIR ] $RelativePath" -ForegroundColor Green
    }
    else {
        Write-Host "[EXISTS DIR ] $RelativePath" -ForegroundColor DarkGray
    }
}

function Ensure-File {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RelativePath,

        [string]$Content = ""
    )

    $FullPath = Join-Path $RepoPath $RelativePath

    if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) {
        Set-Content `
            -LiteralPath $FullPath `
            -Value $Content `
            -Encoding UTF8

        Write-Host "[CREATE FILE] $RelativePath" -ForegroundColor Green
    }
    else {
        Write-Host "[EXISTS FILE] $RelativePath" -ForegroundColor DarkGray
    }
}

function Remove-DirectoryIfExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $FullPath = Join-Path $RepoPath $RelativePath

    if (Test-Path -LiteralPath $FullPath -PathType Container) {
        Write-Host "[REMOVE DIR ] $RelativePath" -ForegroundColor Yellow
        Remove-Item -LiteralPath $FullPath -Recurse -Force
    }
}

function Remove-FileIfExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $FullPath = Join-Path $RepoPath $RelativePath

    if (Test-Path -LiteralPath $FullPath -PathType Leaf) {
        Write-Host "[REMOVE FILE] $RelativePath" -ForegroundColor Yellow
        Remove-Item -LiteralPath $FullPath -Force
    }
}

# ============================================================
# Remove obsolete structure
# ============================================================

Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Removing obsolete structure"
Write-Host "------------------------------------------------------------"

$ObsoleteDirectories = @(
    "tools\brebeskab_csirt",
    "tools\recon",
    "tools\web",
    "tools\api",
    "tools\tls",
    "tools\infrastructure",
    "tools\reporting",
    "tools\common"
)

foreach ($Directory in $ObsoleteDirectories) {
    Remove-DirectoryIfExists $Directory
}

# ============================================================
# Remove Python project files
# ============================================================

Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Removing Python project artifacts"
Write-Host "------------------------------------------------------------"

Remove-FileIfExists "pyproject.toml"
Remove-FileIfExists "requirements.txt"

# ============================================================
# Remove accidental bootstrap script
# ============================================================

Remove-FileIfExists "create-brebeskab-csirt-tools.ps1"

# ============================================================
# Create documentation structure
# ============================================================

Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Creating documentation structure"
Write-Host "------------------------------------------------------------"

$Directories = @(

    # Documentation
    "docs",
    "docs\methodology",
    "docs\standards",
    "docs\templates",

    # Checklists
    "checklists",
    "checklists\web",
    "checklists\api",
    "checklists\infrastructure",
    "checklists\pre-production",

    # Profiles
    "profiles",

    # Configuration
    "config",

    # External tool integration
    "tools",
    "tools\recon",
    "tools\web",
    "tools\api",
    "tools\tls",
    "tools\infrastructure",
    "tools\reporting",

    # Reporting
    "reports",
    "reports\templates",
    "reports\examples",

    # Runtime
    "evidence",
    "projects",

    # Windows scripts
    "scripts",

    # Testing
    "tests"
)

foreach ($Directory in $Directories) {
    Ensure-Directory $Directory
}

# ============================================================
# Methodology files
# ============================================================

Write-Host ""
Write-Host "Creating methodology files..." -ForegroundColor Cyan

$Files = @(
    "docs\methodology\pentest-methodology.md",
    "docs\methodology\rules-of-engagement.md",
    "docs\methodology\reconnaissance.md",
    "docs\methodology\vulnerability-assessment.md",
    "docs\methodology\web-application-testing.md",
    "docs\methodology\api-security-testing.md",
    "docs\methodology\authentication-testing.md",
    "docs\methodology\authorization-testing.md",
    "docs\methodology\business-logic-testing.md",
    "docs\methodology\retest.md",

    # Standards
    "docs\standards\severity.md",
    "docs\standards\evidence-standard.md",
    "docs\standards\finding-standard.md",
    "docs\standards\report-standard.md",

    # Templates
    "docs\templates\ROE.md",
    "docs\templates\PENTEST-PLAN.md",
    "docs\templates\FINDING.md",
    "docs\templates\RETEST.md",
    "docs\templates\FINAL-REPORT.md",

    # Web checklists
    "checklists\web\web-pentest-checklist.md",
    "checklists\web\authentication.md",
    "checklists\web\authorization.md",
    "checklists\web\session-management.md",
    "checklists\web\input-validation.md",
    "checklists\web\file-upload.md",
    "checklists\web\business-logic.md",
    "checklists\web\security-headers.md",

    # API
    "checklists\api\api-pentest-checklist.md",

    # Infrastructure
    "checklists\infrastructure\network-checklist.md",
    "checklists\infrastructure\tls-checklist.md",
    "checklists\infrastructure\web-server-checklist.md",

    # Pre-production
    "checklists\pre-production\dc-readiness-checklist.md",

    # Profiles
    "profiles\web-basic.yaml",
    "profiles\web-full.yaml",
    "profiles\api-full.yaml",
    "profiles\pre-production.yaml",

    # Configuration
    "config\defaults.yaml",
    "config\severity.yaml",
    "config\tools.yaml"
)

foreach ($File in $Files) {
    Ensure-File $File
}

# ============================================================
# Git placeholders
# ============================================================

Write-Host ""
Write-Host "Creating Git placeholders..." -ForegroundColor Cyan

Ensure-File "reports\templates\.gitkeep"
Ensure-File "reports\examples\.gitkeep"
Ensure-File "evidence\.gitkeep"
Ensure-File "projects\.gitkeep"
Ensure-File "tests\.gitkeep"

# ============================================================
# Windows management scripts
# ============================================================

Write-Host ""
Write-Host "Creating Windows management scripts..." -ForegroundColor Cyan

$ScriptFiles = @(
    "scripts\install.ps1",
    "scripts\update.ps1",
    "scripts\doctor.ps1",
    "scripts\pentest.ps1"
)

foreach ($File in $ScriptFiles) {
    Ensure-File $File
}

# ============================================================
# Root documentation placeholders
# ============================================================

Write-Host ""
Write-Host "Checking root documentation..." -ForegroundColor Cyan

Ensure-File "CHANGELOG.md"
Ensure-File "CONTRIBUTING.md"
Ensure-File "SECURITY.md"

# ============================================================
# .gitignore
# ============================================================

Write-Host ""
Write-Host "Updating .gitignore..." -ForegroundColor Cyan

$Gitignore = @'
# ============================================================
# Python
# ============================================================

__pycache__/
*.py[cod]
*.pyo
*.pyd

.venv/
venv/
env/
ENV/

.pytest_cache/
.mypy_cache/
.ruff_cache/

*.egg-info/
dist/
build/

# ============================================================
# Windows
# ============================================================

Thumbs.db
Desktop.ini

# ============================================================
# IDE / Editor
# ============================================================

.vscode/
.idea/
*.code-workspace

# ============================================================
# Secrets
# ============================================================

.env
.env.*
*.key
*.pem
*.pfx
*.p12

secrets/
credentials/

# ============================================================
# Pentest Runtime Data
# ============================================================

projects/*/
evidence/*

reports/generated/
reports/output/

!projects/.gitkeep
!evidence/.gitkeep

# ============================================================
# Temporary Scan Results
# ============================================================

*.pcap
*.pcapng
*.har

# ============================================================
# Screenshots / Evidence
# ============================================================

*.png
*.jpg
*.jpeg
*.webp

# ============================================================
# Archives
# ============================================================

*.zip
*.7z
*.rar
*.tar
*.gz

# ============================================================
# Logs
# ============================================================

*.log
logs/

# ============================================================
# Temporary Files
# ============================================================

*.tmp
*.temp
*.bak
*.swp
*.swo
'@

Set-Content `
    -LiteralPath (Join-Path $RepoPath ".gitignore") `
    -Value $Gitignore `
    -Encoding UTF8

Write-Host "[UPDATED] .gitignore" -ForegroundColor Green

# ============================================================
# Verify Python has NOT been created
# ============================================================

Write-Host ""
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "Verifying Python implementation"
Write-Host "------------------------------------------------------------"

$PythonFiles = Get-ChildItem `
    -LiteralPath $RepoPath `
    -Recurse `
    -File `
    -Filter "*.py" `
    -ErrorAction SilentlyContinue

if ($PythonFiles.Count -eq 0) {

    Write-Host "[OK] Tidak ada file Python." -ForegroundColor Green

}
else {

    Write-Host ""
    Write-Host "[WARNING] File Python ditemukan:" -ForegroundColor Yellow

    foreach ($File in $PythonFiles) {
        Write-Host "  $($File.FullName)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Script tidak menghapus file Python yang sudah ada." -ForegroundColor Yellow
}

# ============================================================
# Verify Python project files do not exist
# ============================================================

Write-Host ""
Write-Host "Checking Python project metadata..." -ForegroundColor Cyan

$PythonMetadata = @(
    "pyproject.toml",
    "requirements.txt"
)

foreach ($File in $PythonMetadata) {

    if (Test-Path -LiteralPath (Join-Path $RepoPath $File)) {

        Write-Host "[WARNING] $File masih ada." -ForegroundColor Yellow

    }
    else {

        Write-Host "[OK] $File belum dibuat." -ForegroundColor Green

    }
}

# ============================================================
# Final tree
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Final Repository Structure" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

tree $RepoPath /F

# ============================================================
# Git status
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Git Status" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

git -C $RepoPath status --short

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Struktur repository selesai diperbaiki." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Python implementation BELUM dibuat." -ForegroundColor Cyan
Write-Host "Silakan review struktur terlebih dahulu di VS Code." -ForegroundColor Cyan
Write-Host ""