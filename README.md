# BrebesKab-CSIRT-Tools

**BrebesKab-CSIRT-Tools** adalah toolkit dan orchestrator pentest untuk
kebutuhan **CSIRT Kabupaten Brebes**.

Project ini dirancang untuk membantu pelaksanaan penetration testing
secara terstruktur, terdokumentasi, dapat ditelusuri, dan mengikuti alur
assessment yang konsisten.

> **Catatan penting:** Tool ini ditujukan untuk assessment yang memiliki
> otorisasi dan scope yang sah. Jangan menjalankan pengujian terhadap
> sistem yang tidak termasuk scope atau tanpa izin.

## Repository

Repository resmi:

``` text
https://github.com/NRTechnology/BrebesKab-CSIRT-Tools.git
```

urlGitHub
Repositoryhttps://github.com/NRTechnology/BrebesKab-CSIRT-Tools.git

------------------------------------------------------------------------

## Tujuan

BrebesKab-CSIRT-Tools dibuat sebagai framework/orchestrator, bukan
sekadar kumpulan exploit.

Fokus utama:

-   standardisasi proses penetration testing;
-   pemisahan setiap fase assessment;
-   pencatatan activity/timeline;
-   pengelolaan project pentest;
-   pengelolaan authorization, scope, RoE, contacts, test account, dan
    backup/recovery;
-   reconnaissance yang terstruktur;
-   pengumpulan evidence;
-   traceability dari checklist sampai finding dan retest;
-   penyusunan report secara konsisten.

Alur assessment:

``` text
PLAN
  ↓
RECON
  ↓
TEST
  ↓
VERIFY
  ↓
FINDING
  ↓
REPORT
  ↓
REMEDIATION
  ↓
RETEST
  ↓
CLOSE
```

------------------------------------------------------------------------

# 1. Prasyarat

Environment pengembangan/penggunaan saat ini ditujukan untuk **Windows
11 + Python**.

Komponen utama:

-   Python 3.14
-   Git
-   Nmap
-   ffuf
-   ProjectDiscovery Nuclei
-   ProjectDiscovery httpx
-   OWASP ZAP
-   Playwright + Chromium

Python packages utama:

``` text
typer
rich
httpx
requests
PyYAML
pydantic
python-dateutil
beautifulsoup4
lxml
playwright
Jinja2
python-docx
```

Versi tools dapat berbeda tergantung environment. Gunakan
`scripts/install-requirements.ps1` untuk proses instalasi yang
disediakan project.

------------------------------------------------------------------------

# 2. Download dari GitHub

Clone repository:

``` powershell
git clone https://github.com/NRTechnology/BrebesKab-CSIRT-Tools.git
```

Masuk ke directory:

``` powershell
cd BrebesKab-CSIRT-Tools
```

Untuk mengambil perubahan terbaru:

``` powershell
git pull --ff-only origin main
```

`git pull --ff-only` digunakan agar update tidak membuat merge commit
otomatis ketika branch lokal sudah memiliki divergence.

------------------------------------------------------------------------

# 3. Virtual Environment

Buat virtual environment:

``` powershell
python -m venv .venv
```

Aktifkan:

``` powershell
. .\scripts\activate-venv.ps1
```

Setelah aktif, prompt PowerShell akan menunjukkan:

``` text
(.venv)
```

Script aktivasi project juga membantu menyiapkan `PYTHONPATH` agar modul
internal seperti `context.py` dan `activity.py` dapat digunakan.

------------------------------------------------------------------------

# 4. Instalasi Requirements

Jalankan PowerShell sebagai Administrator jika diperlukan oleh proses
instalasi tools:

``` powershell
Set-ExecutionPolicy -Scope Process Bypass
```

Kemudian:

``` powershell
.\scripts\install-requirements.ps1
```

Dry run:

``` powershell
.\scripts\install-requirements.ps1 -DryRun
```

Jika script meminta elevation, jalankan kembali dari PowerShell
Administrator.

------------------------------------------------------------------------

# 5. Struktur Repository

Struktur utama project:

``` text
BrebesKab-CSIRT-Tools/
├── .gitignore
├── CHANGELOG.md
├── COMMERCIAL-LICENSE
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
├── checklists/
├── config/
├── docs/
├── evidence/
├── profiles/
├── projects/
├── reports/
├── tests/
├── scripts/
│   ├── activate-venv.ps1
│   ├── activity.py
│   ├── context.py
│   ├── doctor.ps1
│   ├── install.ps1
│   ├── install-requirements.ps1
│   ├── new-pentest-project.ps1
│   ├── pentest.ps1
│   ├── project.py
│   ├── update.ps1
│   ├── preparation/
│   │   ├── authorization.py
│   │   ├── scope.py
│   │   ├── roe.py
│   │   ├── contacts.py
│   │   ├── account.py
│   │   └── backup.py
│   └── reconnaissance/
│       ├── __init__.py
│       ├── target.py
│       ├── dns.py
│       ├── network.py
│       ├── technology.py
│       ├── http.py
│       ├── endpoint.py
│       └── summary.py
└── tools/
    ├── api/
    ├── infrastructure/
    ├── recon/
    ├── reporting/
    ├── tls/
    ├── web/
    ├── httpx/
    └── nuclei/
```

------------------------------------------------------------------------

# 6. Project Management

Project harus dibuat sebelum menjalankan preparation atau
reconnaissance.

## Membuat project

``` powershell
.\scripts\new-pentest-project.ps1
```

Project akan dibuat di:

``` text
projects/<PROJECT-ID>/
```

Contoh:

``` text
projects/
└── PENTEST-2026-002/
```

## Melihat project

``` powershell
python scripts/project.py list
```

## Memilih active project

``` powershell
python scripts/project.py use PENTEST-2026-002
```

## Melihat status active project

``` powershell
python scripts/project.py status
```

## Menghapus active project context

``` powershell
python scripts/project.py clear
```

Active project disimpan pada:

``` text
.runtime/active-project.yaml
```

------------------------------------------------------------------------

# 7. Activity / Timeline

Semua aktivitas penting assessment dicatat ke:

``` text
projects/<PROJECT-ID>/timeline/activity.log
```

Format activity:

``` text
ACT-ID | Timestamp | Phase | Checklist Item | Action | Status
```

Contoh:

``` text
ACT-0001 | 2026-09-24T16:39:55+07:00 | 01-preparation | 01-004 | Contact recorded: C-001 (tester) | completed
```

Traceability yang digunakan:

``` text
Checklist Item
      ↓
Activity ID
      ↓
Tool / Command
      ↓
Result
      ↓
Evidence ID
      ↓
Finding ID
      ↓
Retest ID
```

------------------------------------------------------------------------

# 8. Preparation

Preparation adalah fase pertama dan harus selesai sebelum masuk
Reconnaissance.

Checklist:

``` text
01-001 Authorization
01-002 Scope
01-003 Rules of Engagement
01-004 Contacts
01-005 Test Account
01-006 Backup / Recovery
```

------------------------------------------------------------------------

## 8.1 Authorization

Script:

``` text
scripts/preparation/authorization.py
```

Command:

``` powershell
python scripts/preparation/authorization.py init
python scripts/preparation/authorization.py add
python scripts/preparation/authorization.py status
python scripts/preparation/authorization.py verify
python scripts/preparation/authorization.py attach <FILE>
python scripts/preparation/authorization.py reject
python scripts/preparation/authorization.py version
```

### Argumen

`attach` membutuhkan path file evidence:

``` powershell
python scripts/preparation/authorization.py attach D:\pentest\permohonan.pdf
```

`reject` meminta alasan rejection secara interactive.

Authorization menyimpan data pada:

``` text
projects/<PROJECT-ID>/01-preparation/authorization/authorization.yaml
```

Evidence:

``` text
projects/<PROJECT-ID>/01-preparation/authorization/evidence/
```

Credential, password, token, API key, dan secret tidak boleh disimpan di
file authorization.

------------------------------------------------------------------------

## 8.2 Scope

Script:

``` text
scripts/preparation/scope.py
```

Command:

``` powershell
python scripts/preparation/scope.py init
python scripts/preparation/scope.py add-in
python scripts/preparation/scope.py add-out
python scripts/preparation/scope.py list
python scripts/preparation/scope.py show <ID>
python scripts/preparation/scope.py verify <ID>
python scripts/preparation/scope.py status
python scripts/preparation/scope.py remove <ID>
python scripts/preparation/scope.py version
```

`add-in` dan `add-out` sengaja dipertahankan karena scope memiliki dua
jenis objek:

``` text
IN-SCOPE
OUT-OF-SCOPE
```

Contoh:

``` powershell
python scripts/preparation/scope.py show IN-001
```

ID scope menggunakan format seperti:

``` text
IN-001
OUT-001
```

------------------------------------------------------------------------

## 8.3 Rules of Engagement

Script:

``` text
scripts/preparation/roe.py
```

Command standar:

``` powershell
python scripts/preparation/roe.py init
python scripts/preparation/roe.py add
python scripts/preparation/roe.py list
python scripts/preparation/roe.py show
python scripts/preparation/roe.py verify
python scripts/preparation/roe.py status
python scripts/preparation/roe.py remove
python scripts/preparation/roe.py version
```

Command khusus RoE:

``` powershell
python scripts/preparation/roe.py set-status <STATUS>
python scripts/preparation/roe.py set <FIELD> <VALUE>
python scripts/preparation/roe.py schedule --start <DATE> --end <DATE> [--timezone <TZ>]
python scripts/preparation/roe.py window <testing|blackout> --start <DATETIME> --end <DATETIME> [--reason <TEXT>]
python scripts/preparation/roe.py rule <allowed|prohibited|conditional> --action <ACTION> --description <DESCRIPTION> [--condition <TEXT>]
python scripts/preparation/roe.py safety [OPTIONS]
python scripts/preparation/roe.py communication [OPTIONS]
python scripts/preparation/roe.py stop-trigger <TRIGGER>
python scripts/preparation/roe.py stop [OPTIONS]
python scripts/preparation/roe.py deviation <DESCRIPTION> [OPTIONS]
python scripts/preparation/roe.py approve --approved-by <NAME> --approved-date <DATE> [OPTIONS]
python scripts/preparation/roe.py add-rule
```

Status RoE:

``` text
not-started
draft
pending-approval
approved
active
suspended
closed
```

Contoh:

``` powershell
python scripts/preparation/roe.py set-status approved
```

> `verify` melakukan validasi kesiapan RoE. Verification tidak otomatis
> berarti RoE telah mendapatkan approval administratif.

------------------------------------------------------------------------

## 8.4 Contacts

Script:

``` text
scripts/preparation/contacts.py
```

Command:

``` powershell
python scripts/preparation/contacts.py init
python scripts/preparation/contacts.py add
python scripts/preparation/contacts.py list
python scripts/preparation/contacts.py show <ID>
python scripts/preparation/contacts.py verify <ID>
python scripts/preparation/contacts.py status
python scripts/preparation/contacts.py remove <ID>
python scripts/preparation/contacts.py version
```

Contoh:

``` powershell
python scripts/preparation/contacts.py show C-001
python scripts/preparation/contacts.py verify C-001
```

ID contact:

``` text
C-001
C-002
C-003
```

------------------------------------------------------------------------

## 8.5 Test Account

Script:

``` text
scripts/preparation/account.py
```

Command:

``` powershell
python scripts/preparation/account.py init
python scripts/preparation/account.py add
python scripts/preparation/account.py list
python scripts/preparation/account.py show <ID>
python scripts/preparation/account.py verify <ID>
python scripts/preparation/account.py status
python scripts/preparation/account.py remove <ID>
python scripts/preparation/account.py version
```

Contoh:

``` powershell
python scripts/preparation/account.py show TA-002
python scripts/preparation/account.py verify TA-002
```

ID test account:

``` text
TA-001
TA-002
TA-003
```

**Password, token, API key, dan secret tidak disimpan oleh script ini.**

------------------------------------------------------------------------

## 8.6 Backup / Recovery

Script:

``` text
scripts/preparation/backup.py
```

Command:

``` powershell
python scripts/preparation/backup.py init
python scripts/preparation/backup.py add
python scripts/preparation/backup.py list
python scripts/preparation/backup.py show <ID>
python scripts/preparation/backup.py verify <ID>
python scripts/preparation/backup.py status
python scripts/preparation/backup.py remove <ID>
python scripts/preparation/backup.py version
```

Contoh:

``` powershell
python scripts/preparation/backup.py show BK-001
python scripts/preparation/backup.py verify BK-001
```

ID backup:

``` text
BK-001
BK-002
BK-003
```

Script ini **mencatat kesiapan backup/recovery**. Script tidak melakukan
backup atau restore secara otomatis.

------------------------------------------------------------------------

# 9. Reconnaissance

Setelah Preparation selesai, assessment masuk ke:

``` text
02 Reconnaissance
```

Struktur:

``` text
02-001 Target Identification
02-002 DNS / Domain
02-003 IP / Network
02-004 Technology Identification
02-005 HTTP / HTTPS
02-006 Endpoint Discovery
02-007 Recon Summary
```

Script:

``` text
scripts/reconnaissance/
├── target.py
├── dns.py
├── network.py
├── technology.py
├── http.py
├── endpoint.py
└── summary.py
```

------------------------------------------------------------------------

## 9.1 Target Identification

Script:

``` text
scripts/reconnaissance/target.py
```

Command standar:

``` powershell
python scripts/reconnaissance/target.py init
python scripts/reconnaissance/target.py add
python scripts/reconnaissance/target.py list
python scripts/reconnaissance/target.py show
python scripts/reconnaissance/target.py verify
python scripts/reconnaissance/target.py status
python scripts/reconnaissance/target.py remove
python scripts/reconnaissance/target.py version
```

Fungsi:

-   mencatat application;
-   mencatat target URL;
-   mengambil hostname dari URL;
-   menentukan scheme;
-   menentukan port default berdasarkan scheme;
-   mencatat environment;
-   mencatat assessment type;
-   menghubungkan target dengan scope.

`target.py` **tidak melakukan network request atau scanning**.

------------------------------------------------------------------------

## 9.2 DNS / Domain

Script yang disiapkan:

``` text
scripts/reconnaissance/dns.py
```

Checklist:

``` text
02-002 DNS / Domain
```

Implementasi command akan mengikuti standard CLI project.

------------------------------------------------------------------------

## 9.3 IP / Network

Script:

``` text
scripts/reconnaissance/network.py
```

Checklist:

``` text
02-003 IP / Network
```

------------------------------------------------------------------------

## 9.4 Technology Identification

Script:

``` text
scripts/reconnaissance/technology.py
```

Checklist:

``` text
02-004 Technology Identification
```

------------------------------------------------------------------------

## 9.5 HTTP / HTTPS

Script:

``` text
scripts/reconnaissance/http.py
```

Checklist:

``` text
02-005 HTTP / HTTPS
```

------------------------------------------------------------------------

## 9.6 Endpoint Discovery

Script:

``` text
scripts/reconnaissance/endpoint.py
```

Checklist:

``` text
02-006 Endpoint Discovery
```

------------------------------------------------------------------------

## 9.7 Recon Summary

Script:

``` text
scripts/reconnaissance/summary.py
```

Checklist:

``` text
02-007 Recon Summary
```

Summary akan menggabungkan hasil reconnaissance yang telah dikumpulkan
sebelumnya.

------------------------------------------------------------------------

# 10. Standard CLI Contract

Untuk script yang menggunakan model multi-record, command dasar yang
digunakan:

``` text
init
add
list
show <ID>
verify <ID>
status
remove <ID>
version
```

Contoh:

``` powershell
python scripts/preparation/account.py add
python scripts/preparation/account.py list
python scripts/preparation/account.py show TA-002
python scripts/preparation/account.py verify TA-002
python scripts/preparation/account.py status
python scripts/preparation/account.py remove TA-002
python scripts/preparation/account.py version
```

Tidak semua script dipaksa identik.

Command khusus dipertahankan jika memang mewakili domain yang berbeda,
misalnya:

``` text
scope.py
  add-in
  add-out

authorization.py
  attach
  reject

roe.py
  schedule
  window
  rule
  safety
  communication
  stop-trigger
  stop
  deviation
  approve
```

Prinsipnya:

> **Standardisasi interface tanpa menghilangkan makna domain.**

------------------------------------------------------------------------

# 11. Project Status

Project menggunakan lifecycle:

``` text
01 Preparation
02 Reconnaissance
03 Infrastructure
04 Web Server Configuration
05 Security Headers
06 Authentication
07 Authorization
08 Session Management
09 Input Validation
10 File Upload
11 Client-Side Security
12 CSRF
13 CORS
14 SSRF
15 Sensitive Data
16 Business Logic
17 API
18 Dependency & Component
19 Logging & Monitoring
20 Evidence Validation
21 Finding Review
22 Retest
23 Final Sign-Off
```

Assessment tidak boleh melompat fase tanpa alasan dan dokumentasi yang
jelas.

------------------------------------------------------------------------

# 12. Evidence

Evidence harus dapat ditelusuri kembali ke aktivitas assessment.

Prinsip evidence:

-   memiliki Evidence ID;
-   request/response disimpan jika relevan;
-   screenshot digunakan jika diperlukan;
-   timestamp tersedia;
-   data sensitif disanitasi;
-   credential dan token tidak disimpan;
-   PII disimpan seminimal mungkin;
-   evidence dapat direproduksi.

Struktur umum project:

``` text
projects/
└── PENTEST-YYYY-NNN/
    ├── 01-preparation/
    ├── 02-reconnaissance/
    ├── ...
    ├── evidence/
    ├── findings/
    ├── retest/
    ├── report/
    └── timeline/
```

------------------------------------------------------------------------

# 13. Finding Traceability

Setiap finding harus memiliki hubungan dengan evidence dan aktivitas.

``` text
Checklist Item
      ↓
Activity ID
      ↓
Tool / Command
      ↓
Result
      ↓
Evidence ID
      ↓
Finding ID
      ↓
Retest ID
```

AI atau automation dapat membantu melakukan parsing dan penyusunan
kandidat finding, tetapi keputusan akhir finding tetap melalui proses
verification/manual review.

------------------------------------------------------------------------

# 14. Contoh Quick Start

Clone:

``` powershell
git clone https://github.com/NRTechnology/BrebesKab-CSIRT-Tools.git
cd BrebesKab-CSIRT-Tools
```

Buat environment:

``` powershell
python -m venv .venv
. .\scripts\activate-venv.ps1
```

Install requirements:

``` powershell
.\scripts\install-requirements.ps1
```

Buat project:

``` powershell
.\scripts\new-pentest-project.ps1
```

Pilih project:

``` powershell
python scripts/project.py list
python scripts/project.py use PENTEST-2026-002
python scripts/project.py status
```

Setelah Preparation selesai, mulai Reconnaissance:

``` powershell
python scripts/reconnaissance/target.py init
python scripts/reconnaissance/target.py add
python scripts/reconnaissance/target.py list
python scripts/reconnaissance/target.py verify
python scripts/reconnaissance/target.py status
```

------------------------------------------------------------------------

# 15. Development Principle

Project ini dikembangkan dengan prinsip:

1.  **Authorized testing only**
2.  **Scope first**
3.  **Preparation before testing**
4.  **Checklist-driven assessment**
5.  **Activity traceability**
6.  **Evidence-based findings**
7.  **Manual verification of findings**
8.  **No credentials/secrets in project data**
9.  **One phase at a time**
10. **Standard CLI where it makes sense**
11. **Domain-specific commands are preserved when necessary**
12. **AI assists analysis; human reviewer remains responsible for final
    finding validation**

------------------------------------------------------------------------

# 16. Status Pengembangan

Status saat ini:

``` text
Preparation
├── Authorization      ✅
├── Scope              ✅
├── Rules of Engagement ✅
├── Contacts           ✅
├── Test Account       ✅
└── Backup / Recovery  ✅

Reconnaissance
├── Target Identification     🔄
├── DNS / Domain              ⏳
├── IP / Network              ⏳
├── Technology Identification ⏳
├── HTTP / HTTPS              ⏳
├── Endpoint Discovery        ⏳
└── Recon Summary             ⏳
```

Development dilakukan bertahap:

``` text
Implement
   ↓
Test
   ↓
Validate
   ↓
Document
   ↓
Continue
```

------------------------------------------------------------------------

# 17. License

Lihat:

``` text
LICENSE
COMMERCIAL-LICENSE
```

untuk ketentuan penggunaan project.

------------------------------------------------------------------------

# 18. Security

Untuk melaporkan masalah keamanan pada project, lihat:

``` text
SECURITY.md
```

Jangan memasukkan password, token, API key, credential, atau data
sensitif ke issue, commit, atau repository.
