# BrebesKab-CSIRT-Tools

**BrebesKab-CSIRT-Tools** adalah toolkit dan orchestrator *penetration testing* untuk membantu pelaksanaan asesmen keamanan yang berotorisasi. Proyek ini mengorganisasi persiapan, reconnaissance, pengujian berbasis checklist, pencatatan aktivitas, pengelolaan evidence, dan penyusunan laporan agar prosesnya lebih konsisten dan dapat ditelusuri.

Tool ini bukan pengganti penilaian teknis reviewer. Output otomatis, evidence mentah, rekomendasi berbantuan AI, dan finding yang telah dikonfirmasi harus diperlakukan sebagai hal yang berbeda.

> **Peringatan:** gunakan tool hanya terhadap aset yang tercantum dalam scope dan dengan otorisasi yang sah. Patuhi Rules of Engagement (RoE), batas request, jadwal, dan prosedur penghentian pengujian.

## Repository

- Repository: <https://github.com/NRTechnology/BrebesKab-CSIRT-Tools>
- Clone URL: `https://github.com/NRTechnology/BrebesKab-CSIRT-Tools.git`

## Tujuan dan alur asesmen

Fokus proyek:

- mengelola project asesmen dan project aktif;
- mendokumentasikan authorization, scope, RoE, kontak, test account, dan kesiapan backup/recovery;
- menjalankan modul reconnaissance dan checklist pengujian;
- mencatat aktivitas/timeline serta menghubungkan aktivitas, hasil, evidence, finding, dan retest;
- menghasilkan laporan dari data yang tersedia tanpa mengarang metadata atau temuan;
- membedakan status pelaksanaan checklist dari kelengkapan hasilnya.

Alur konseptual:

```text
PLAN → RECON → TEST → VERIFY → FINDING → REPORT
                                      ↓
                         REMEDIATION → RETEST → CLOSE
```

## 1. Prasyarat

Environment yang tercermin pada repository saat ini adalah **Windows 11 dengan Python 3.14**. Versi dan lokasi tool eksternal dapat berbeda sesuai environment.

Komponen yang digunakan oleh instalasi dan modul tertentu antara lain:

- Python dan Git;
- Nmap;
- Gobuster;
- ProjectDiscovery Nuclei dan httpx;
- OWASP ZAP;
- Playwright dan Chromium;
- paket Python yang digunakan project, termasuk Typer, Rich, HTTPX, Requests, PyYAML, Pydantic, python-dateutil, BeautifulSoup, lxml, Playwright, Jinja2, dan python-docx.

Tidak semua modul memerlukan semua tool di atas. Periksa konfigurasi dan pesan dari pemeriksaan instalasi untuk mengetahui kebutuhan yang berlaku pada environment Anda.

## 2. Instalasi

Clone repository:

```powershell
git clone https://github.com/NRTechnology/BrebesKab-CSIRT-Tools.git
cd BrebesKab-CSIRT-Tools
```

Buat virtual environment dan aktifkan:

```powershell
python -m venv .venv
. .\scripts\activate-venv.ps1
```

Jalankan instalasi requirements:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install-requirements.ps1
```

Untuk melihat tindakan yang akan dilakukan tanpa menjalankan instalasi:

```powershell
.\scripts\install-requirements.ps1 -DryRun
```

Jika diperlukan, jalankan PowerShell dengan hak Administrator ketika script meminta akses tersebut. Hindari menjalankan seluruh tool sebagai Administrator secara default; gunakan hak akses minimum yang diperlukan.

Pemeriksaan environment:

```powershell
.\scripts\doctor.ps1
```

Perintah update yang tersedia pada repository:

```powershell
.\scripts\update.ps1
```

Periksa opsi script sebelum menjalankannya pada environment yang sudah digunakan untuk asesmen.

## 3. Struktur repository

Ringkasan berikut menggambarkan direktori dan file utama yang terlihat pada tree repository. File runtime, virtual environment, project asesmen aktual, log, dan hasil pengujian tidak ditampilkan seluruhnya.

```text
BrebesKab-CSIRT-Tools/
├── .gitignore
├── CHANGELOG.md
├── COMMERCIAL-LICENSE
├── CONTRIBUTING.md
├── LICENSE
├── README.md
├── SECURITY.md
├── backup/                    # salinan kerja/versi sebelum perubahan
├── checklists/
│   ├── api/
│   ├── infrastructure/
│   ├── pre-production/
│   └── web/
├── config/
│   ├── defaults.yaml
│   ├── severity.yaml
│   ├── tools.yaml
│   ├── dictionaries/
│   └── fingerprints/
├── docs/
│   ├── methodology/
│   ├── standards/
│   └── templates/
├── evidence/
├── profiles/
│   ├── api-full.yaml
│   ├── pre-production.yaml
│   ├── web-basic.yaml
│   └── web-full.yaml
├── projects/
├── reports/
│   ├── examples/
│   └── templates/
├── scripts/
│   ├── activate-venv.ps1
│   ├── activity.py
│   ├── context.py
│   ├── doctor.ps1
│   ├── evidence.py
│   ├── install-requirements.ps1
│   ├── pentest.ps1
│   ├── project.py
│   ├── report.py
│   ├── run-directory-discover.ps1
│   ├── secrets.py
│   ├── authentication/
│   ├── authorization/
│   ├── fileupload/
│   ├── httpheader/
│   ├── infrastructure/
│   ├── inputvalidation/
│   ├── preparation/
│   ├── reconnaissance/
│   └── webserver/
├── tests/
└── tools/
    ├── api/
    ├── gobuster/
    ├── httpx/
    ├── infrastructure/
    ├── nuclei/
    ├── recon/
    ├── reporting/
    ├── tls/
    └── web/
```

**Catatan:** direktori `backup/` berisi salinan sebelum perubahan dan bukan tempat penyimpanan backup target asesmen. Direktori `.runtime/` dan `.venv/` merupakan data lokal/runtime; jangan memasukkan secret, key enkripsi, log sensitif, atau evidence asesmen ke commit publik. Periksa `.gitignore` dan status Git sebelum melakukan commit.

## 4. Project management

Buat project asesmen:

```powershell
.\scripts\new-pentest-project.ps1
```

Lihat project dan status:

```powershell
python scripts/project.py list
python scripts/project.py status
```

Pilih project aktif dengan ID yang benar-benar ada:

```powershell
python scripts/project.py use <PROJECT-ID>
```

Contoh placeholder `<PROJECT-ID>` harus diganti dengan ID project Anda, misalnya `PENTEST-YYYY-NNN`. Untuk menghapus konteks project aktif:

```powershell
python scripts/project.py clear
```

Konteks project aktif disimpan secara lokal pada `.runtime/active-project.yaml`. Pastikan project yang aktif benar sebelum menjalankan command yang membuat atau mengubah data asesmen.

## 5. Preparation

Preparation mendokumentasikan kesiapan dan batasan asesmen sebelum pengujian. Modul yang tersedia di `scripts/preparation/`:

| Modul | Kegunaan |
|---|---|
| `authorization.py` | Mencatat dan memeriksa informasi otorisasi serta evidence pendukungnya. |
| `scope.py` | Mengelola aset in-scope dan out-of-scope. |
| `roe.py` | Mendokumentasikan jadwal, aturan, kondisi, komunikasi, dan penghentian pengujian. |
| `contacts.py` | Mencatat kontak yang relevan untuk asesmen. |
| `account.py` | Mencatat metadata akun pengujian; bukan tempat menyimpan password/token. |
| `backup.py` | Mencatat kesiapan backup/recovery; bukan menjalankan backup atau restore target secara otomatis. |

Contoh pola pemanggilan:

```powershell
python scripts/preparation/scope.py --help
python scripts/preparation/authorization.py --help
python scripts/preparation/roe.py --help
```

Lihat bantuan CLI masing-masing modul sebelum menjalankan subcommand. Command dapat memiliki argumen atau kebutuhan interaktif yang berbeda. `verify` adalah pemeriksaan data/kesiapan dan tidak otomatis menggantikan approval administratif.

## 6. Reconnaissance

Direktori `scripts/reconnaissance/` saat ini berisi modul:

- `target.py` — pengelolaan identitas target dan metadata URL;
- `dns.py` — kegiatan terkait DNS/domain;
- `network.py` — pemeriksaan terkait IP/network;
- `technology.py` — identifikasi teknologi;
- `http.py` — pemeriksaan HTTP/HTTPS;
- `endpoint.py` — penemuan endpoint;
- `subdomain.py` — kegiatan terkait subdomain;
- `directory.py` — directory discovery;
- `api.py` — reconnaissance API;
- `attack.py` — fungsi terkait aktivitas/permukaan pengujian;
- `summary.py` — ringkasan reconnaissance.

Keberadaan file tidak dengan sendirinya membuktikan bahwa setiap fungsi atau command sudah lengkap. Periksa bantuan CLI dan implementasi versi yang sedang digunakan:

```powershell
python scripts/reconnaissance/target.py --help
python scripts/reconnaissance/dns.py --help
python scripts/reconnaissance/directory.py --help
```

Jalankan hanya modul yang sesuai dengan scope dan RoE yang disetujui.

## 7. Modul pengujian

Direktori `scripts/` mengelompokkan modul pengujian menurut area:

| Direktori | Cakupan umum |
|---|---|
| `authentication/` | Login, brute force yang diizinkan, MFA, password, recovery, session, dan ringkasan. |
| `authorization/` | Access control, endpoint, IDOR, ownership, privilege, role, dan ringkasan. |
| `fileupload/` | Discovery upload, ekstensi, nama file, overwrite, ukuran, storage, validasi, dan ringkasan. |
| `httpheader/` | Content type, CSP, frame, HSTS, permissions policy, referrer policy, dan ringkasan. |
| `infrastructure/` | Admin exposure, sertifikat, exposure, HTTP/HTTPS, IPv6, service, TLS, dan ringkasan. |
| `inputvalidation/` | Command injection, injection, parameter, SQLi, traversal, XSS, dan ringkasan. |
| `webserver/` | Backup, konfigurasi, debug, default files, directory listing, environment, error handling, Git exposure, HTTP methods, versi, dan ringkasan. |

Nama direktori menjelaskan pengelompokan kode, bukan jaminan bahwa semua skenario telah diuji atau seluruh hasil telah tervalidasi. Gunakan checklist, profil, konfigurasi tool, serta evidence untuk menentukan cakupan aktual.

## 8. CLI utama

Script tingkat atas yang tersedia:

| Script | Peran |
|---|---|
| `scripts/pentest.ps1` | Entry point workflow pentest berbasis PowerShell. |
| `scripts/project.py` | Pengelolaan project dan konteks project aktif. |
| `scripts/activity.py` | Pencatatan aktivitas/timeline. |
| `scripts/evidence.py` | Fungsi terkait pengelolaan evidence. |
| `scripts/secrets.py` | Fungsi terkait pengelolaan secret. |
| `scripts/report.py` | Penyusunan laporan dari data asesmen yang tersedia. |
| `scripts/run-directory-discover.ps1` | Entry point PowerShell untuk directory discovery. |
| `scripts/doctor.ps1` | Pemeriksaan environment. |

Mulai dengan opsi bantuan yang disediakan oleh script:

```powershell
python scripts/project.py --help
python scripts/report.py --help
python scripts/evidence.py --help
python scripts/secrets.py --help
.\scripts\pentest.ps1 -?
.\scripts\run-directory-discover.ps1 -?
```

Jika bentuk bantuan suatu script berbeda, gunakan dokumentasi dan implementasi aktualnya. Jangan mengasumsikan semua script memakai kontrak CLI yang sama.

## 9. Activity, evidence, dan traceability

Aktivitas asesmen perlu dapat ditelusuri ke hasil dan evidence yang mendukungnya. Bentuk relasi konseptual:

```text
Checklist Item
    ↓
Activity / Timeline
    ↓
Tool atau Command
    ↓
Result
    ↓
Evidence ID
    ↓
Finding ID
    ↓
Retest
```

Prinsip evidence:

- gunakan identitas evidence yang konsisten;
- simpan request/response atau screenshot bila relevan dan diizinkan;
- catat waktu dan konteks pengujian;
- sanitasi credential, token, secret, dan data sensitif;
- minimalkan penyimpanan data pribadi;
- dokumentasikan keterbatasan dan langkah reproduksi;
- batasi akses serta retensi evidence sesuai kebijakan asesmen.

Jangan menganggap file yang tersimpan otomatis merupakan bukti kerentanan. Evidence harus ditinjau dalam konteks request, response, perilaku aplikasi, scope, dan kemungkinan penjelasan alternatif.

## 10. Pelaporan dan interpretasi hasil

`report.py` menyusun laporan berdasarkan data asesmen, metadata, checklist, dan evidence yang tersedia. Kelengkapan serta ketepatan laporan bergantung pada input dan aturan pemrosesan versi tool yang digunakan.

Prinsip interpretasi:

- **Evidence bukan otomatis finding.** Respons HTTP `200` atau `303`, refleksi payload, penerimaan upload, versi komponen yang terlihat, metode HTTP yang diterima, atau perilaku replay tidak dengan sendirinya membuktikan kerentanan.
- **Finding terkonfirmasi memerlukan validasi.** Indikator teknis harus diperiksa terhadap bukti dan konteks sebelum dinyatakan sebagai kerentanan.
- **Item review bukan otomatis finding atau kondisi aman.** Tandai sebagai kebutuhan tinjauan sampai ada kesimpulan yang didukung bukti.
- **Status pelaksanaan berbeda dari status hasil.** Checklist dapat sudah dijalankan meskipun hasilnya `partial`. Ringkasan pelaksanaan perlu menghitung penyelesaian proses berdasarkan kriteria yang eksplisit tanpa mengubah status hasil atau evidence asli.
- **Tidak adanya finding record bukan jaminan target aman.** Periksa cakupan, item review, kualitas evidence, serta pengujian yang belum dilakukan.
- **Rekomendasi AI bersifat pendukung.** Rekomendasi dari berkas tinjauan berbantuan AI bukan finding terkonfirmasi dan tidak boleh mengubah status evidence dengan sendirinya. Reviewer manusia bertanggung jawab atas validasi dan kesimpulan akhir.

Pada konfigurasi pengujian yang didokumentasikan, batas teknisnya adalah maksimal **100 request untuk setiap pengujian**, di luar proses **Directory Discovery** yang menggunakan mekanisme tersendiri. Verifikasi konfigurasi dan implementasi versi yang digunakan sebelum asesmen; jangan menganggap angka ini sebagai batas total seluruh asesmen.

Alur otomatis juga dapat terhambat oleh interaksi manusia seperti OTP atau *Human Verification Challenge*. Kode status HTTP perlu ditafsirkan bersama request/response, alur aplikasi, dan evidence pendukung, bukan sebagai dasar tunggal untuk menetapkan kerentanan.

## 11. Checklist, profil, konfigurasi, dan dokumentasi

Direktori pendukung yang tersedia:

- `checklists/` — checklist untuk area web, API, infrastruktur, dan pre-production;
- `profiles/` — profil `web-basic`, `web-full`, `api-full`, dan `pre-production`;
- `config/` — default, severity, konfigurasi tool, dictionary, dan fingerprint teknologi;
- `docs/methodology/` — dokumentasi metodologi pengujian;
- `docs/standards/` — standar evidence, finding, laporan, dan severity;
- `docs/templates/` — template rencana pentest, RoE, finding, retest, dan laporan;
- `reports/templates/` — template dokumen laporan/checklist.

Gunakan checklist dan profil yang sesuai dengan jenis asesmen. Jangan menyimpulkan suatu area telah diuji hanya karena tersedia checklist atau modul untuk area tersebut.

## 12. Quick start

Urutan awal yang disarankan:

```powershell
git clone https://github.com/NRTechnology/BrebesKab-CSIRT-Tools.git
cd BrebesKab-CSIRT-Tools

python -m venv .venv
. .\scripts\activate-venv.ps1

.\scripts\install-requirements.ps1
.\scripts\doctor.ps1

.\scripts\new-pentest-project.ps1
python scripts/project.py list
python scripts/project.py status
```

Sebelum reconnaissance atau pengujian, pastikan project yang aktif benar, otorisasi tersedia, scope telah diverifikasi, RoE disepakati, kontak darurat tersedia, dan persyaratan backup/recovery sudah dipahami. Kemudian ikuti workflow dan checklist yang berlaku pada versi repository tersebut.

## 13. Prinsip pengembangan

1. Authorized testing only.
2. Scope first.
3. Preparation before testing.
4. Checklist-driven assessment.
5. Activity and evidence traceability.
6. Evidence-based findings.
7. Manual verification of findings.
8. No credentials or secrets in source control.
9. Distinguish execution status from result completeness.
10. Standardize interfaces where appropriate without removing domain-specific behavior.
11. Test and validate changes before documenting them.
12. AI assists analysis; human reviewer remains responsible for final finding validation.

## 14. Status pengembangan

Repository berisi modul preparation, reconnaissance, pengujian per area, pengelolaan evidence/secret, konfigurasi, checklist, profil, dokumentasi, serta generator laporan. Tingkat kesiapan setiap fitur dapat berbeda dan berubah antarversi.

Daftar file pada README ini disusun berdasarkan tree repository yang diperiksa. Tree hanya menunjukkan keberadaan file dan direktori; tree tidak membuktikan bahwa setiap fungsi telah selesai, lolos pengujian, atau siap digunakan untuk semua skenario. Untuk memastikan status suatu fitur, periksa implementasi, bantuan CLI, hasil pengujian, dan dokumentasi versi yang sedang digunakan.

Siklus pengembangan:

```text
Implement → Test → Validate → Document → Continue
```

## 15. License

Baca `LICENSE` dan `COMMERCIAL-LICENSE` untuk memahami ketentuan penggunaan, modifikasi, distribusi, dan penggunaan komersial.

## 16. Security

Untuk melaporkan masalah keamanan pada proyek ini, ikuti petunjuk di `SECURITY.md`.

Jangan memasukkan password, token, API key, credential, encryption key, atau data asesmen sensitif ke issue publik, commit, maupun repository publik. Tinjau perubahan dan status Git sebelum melakukan commit.
