<#
.SYNOPSIS
    Mengaktifkan Python virtual environment untuk BrebesKab-CSIRT-Tools.

.DESCRIPTION
    Script ini harus di-dot-source dari PowerShell agar aktivasi .venv
    tetap berlaku pada terminal yang sedang digunakan.

    Script:
      - Memastikan .venv tersedia.
      - Mengaktifkan .venv\Scripts\Activate.ps1.
      - Menambahkan repository root dan scripts/ ke PYTHONPATH.
      - Menampilkan interpreter dan versi Python yang aktif.
      - Menampilkan file Python yang tersedia di scripts/.
      - Tidak gagal hanya karena scripts/ belum memiliki file Python.

    Penggunaan:
      . .\scripts\activate-venv.ps1

    Setelah aktif:
      python --version
      python scripts/project.py list
#>

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepositoryRoot = Split-Path -Parent $ScriptDirectory
$VenvPath = Join-Path $RepositoryRoot '.venv'
$VenvActivate = Join-Path $VenvPath 'Scripts\Activate.ps1'
$ScriptsPath = Join-Path $RepositoryRoot 'scripts'

Write-Host ''
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host ' BrebesKab-CSIRT-Tools - Python Environment' -ForegroundColor DarkCyan
Write-Host '============================================================' -ForegroundColor DarkCyan
Write-Host "Repository : $RepositoryRoot"
Write-Host "Venv       : $VenvPath"
Write-Host ''

if (-not (Test-Path -LiteralPath $VenvActivate -PathType Leaf)) {
    Write-Host '[ERROR] Python virtual environment tidak ditemukan.' -ForegroundColor Red
    Write-Host ''
    Write-Host "Expected: $VenvActivate"
    Write-Host ''
    Write-Host 'Buat/rebuild .venv terlebih dahulu menggunakan installer project.'
    return
}

# Activate the project virtual environment in the CURRENT PowerShell session.
. $VenvActivate

# Keep repository root and scripts/ importable by Python.
$PythonPaths = @(
    $RepositoryRoot
    $ScriptsPath
)

$ExistingPythonPath = [Environment]::GetEnvironmentVariable('PYTHONPATH', 'Process')

$PathEntries = New-Object System.Collections.Generic.List[string]

foreach ($Path in $PythonPaths) {
    if (-not $PathEntries.Contains($Path)) {
        [void]$PathEntries.Add($Path)
    }
}

if (-not [string]::IsNullOrWhiteSpace($ExistingPythonPath)) {
    foreach ($Entry in ($ExistingPythonPath -split ';')) {
        if (-not [string]::IsNullOrWhiteSpace($Entry) -and
            -not $PathEntries.Contains($Entry)) {
            [void]$PathEntries.Add($Entry)
        }
    }
}

$env:PYTHONPATH = $PathEntries -join ';'

Write-Host '[PASS] Python virtual environment aktif.' -ForegroundColor Green
Write-Host "Python     : $((Get-Command python).Source)"
Write-Host "Python ver : $(& python --version 2>&1)"
Write-Host "PYTHONPATH : $env:PYTHONPATH"
Write-Host ''

Write-Host 'Python scripts yang tersedia:' -ForegroundColor Yellow

# Force array semantics so Count is always available in PowerShell 5.1,
# including when there are zero or one .py files.
$PythonScripts = @(
    Get-ChildItem -LiteralPath $ScriptsPath -Filter '*.py' -File |
        Sort-Object Name
)

if ($PythonScripts.Count -eq 0) {
    Write-Host '  [INFO] Belum ada file .py di scripts/.' -ForegroundColor DarkYellow
}
else {
    foreach ($PythonScript in $PythonScripts) {
        Write-Host "  - $($PythonScript.Name)"
    }
}

Write-Host ''
Write-Host '[PASS] Python environment siap digunakan.' -ForegroundColor Green
Write-Host ''
Write-Host 'Contoh:' -ForegroundColor Yellow
Write-Host '  python --version'
Write-Host '  python scripts/project.py list'
Write-Host ''
