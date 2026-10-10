#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Project Manager

Usage:
    python scripts/project.py create PENTEST-2026-003
    python scripts/project.py init-secrets PENTEST-2026-002
    python scripts/project.py list
    python scripts/project.py use PENTEST-2026-002
    python scripts/project.py status
    python scripts/project.py start PENTEST-2026-002
    python scripts/project.py complete PENTEST-2026-002
    python scripts/project.py clear

The `create` command replaces the former new-pentest-project.ps1 bootstrap
workflow while preserving the existing project context lifecycle.
"""

from __future__ import annotations

import argparse
import base64
import re
import os
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML belum terinstall.")
    print("       Jalankan: python -m pip install PyYAML")
    sys.exit(1)


SCRIPT_VERSION = "1.5.5"
PROJECT_ID_PATTERN = re.compile(r"^PENTEST-[0-9]{4}-[0-9]{3,}$")
ALLOWED_ENVIRONMENTS = ("Production", "Staging", "Pre-Production")
ALLOWED_ASSESSMENT_TYPES = ("Black Box", "Grey Box", "White Box")

PHASE_DEFINITIONS: tuple[dict[str, str], ...] = (
    {"number": "01", "name": "Preparation", "slug": "preparation"},
    {"number": "02", "name": "Reconnaissance", "slug": "reconnaissance"},
    {"number": "03", "name": "Infrastructure", "slug": "infrastructure"},
    {"number": "04", "name": "Web Server Configuration", "slug": "web-server-configuration"},
    {"number": "05", "name": "Security Headers", "slug": "security-headers"},
    {"number": "06", "name": "Authentication", "slug": "authentication"},
    {"number": "07", "name": "Authorization", "slug": "authorization"},
    {"number": "08", "name": "Session Management", "slug": "session-management"},
    {"number": "09", "name": "Input Validation", "slug": "input-validation"},
    {"number": "10", "name": "File Upload", "slug": "file-upload"},
    {"number": "11", "name": "Client-Side Security", "slug": "client-side-security"},
    {"number": "12", "name": "CSRF", "slug": "csrf"},
    {"number": "13", "name": "CORS", "slug": "cors"},
    {"number": "14", "name": "SSRF", "slug": "ssrf"},
    {"number": "15", "name": "Sensitive Data", "slug": "sensitive-data"},
    {"number": "16", "name": "Business Logic", "slug": "business-logic"},
    {"number": "17", "name": "API", "slug": "api"},
    {"number": "18", "name": "Dependency & Component", "slug": "dependency-component"},
    {"number": "19", "name": "Logging & Monitoring", "slug": "logging-monitoring"},
    {"number": "20", "name": "Evidence Validation", "slug": "evidence-validation"},
    {"number": "21", "name": "Finding Review", "slug": "finding-review"},
    {"number": "22", "name": "Retest", "slug": "retest"},
    {"number": "23", "name": "Final Sign-Off", "slug": "final-sign-off"},
)

# Wordlist/fuzzy scoring model.
# Wordlist source files remain centrally managed by install-requirements.ps1.
# Project workspaces store references, configuration, baselines, results,
# feedback and score history only.
SCORING_SCHEMA_VERSION = "1.0"
CANONICAL_WORDLIST_MANIFEST = "config/dictionaries/directory/manifest.json"

WORDLIST_SCORING_CONFIG = """schema_version: '1.0'
model: 'fuzzy-wordlist-adaptive'
enabled: true

wordlist_source:
  mode: 'global-manifest'
  local_copy: false
  manifest: 'config/dictionaries/directory/manifest.json'

ranking:
  enabled: true
  initial_score_range: [0.0, 1.0]
  tiers:
    - name: 'Primary'
      min_score: 0.80
      max_score: 1.00
    - name: 'Secondary'
      min_score: 0.50
      max_score: 0.79
    - name: 'Exploration'
      min_score: 0.20
      max_score: 0.49

exploration:
  enabled: true
  minimum_score: 0.20
  low_rank_access: true

fuzzy:
  enabled: true
  similarity_recording: true
  baseline_required: true

request_budget:
  enabled: true
  mode: 'per-run'
  max_requests: null

feedback:
  enabled: true
  formula: 'new_score = initial_score + evidence_gain + discovery_yield - noise_penalty'
  signals:
    - 'evidence_gain'
    - 'discovery_yield'
    - 'noise_penalty'
  score_clamp:
    minimum: 0.0
    maximum: 1.0

traceability:
  required_fields:
    - 'project_id'
    - 'run_id'
    - 'wordlist_id'
    - 'wordlist_source'
    - 'initial_score'
    - 'final_score'
    - 'tier'
    - 'request_count'
    - 'evidence_gain'
    - 'discovery_yield'
    - 'noise_penalty'
    - 'timestamp'
"""

WORDLIST_SELECTION_TEMPLATE = """schema_version: '1.0'
project_id: '{project_id}'

# Referensi wordlist dikelola oleh manifest global.
# Jangan menyalin source wordlist ke dalam project.
wordlists: []

# Contoh item:
# - wordlist_id: 'seclists-common'
#   source: 'SecLists'
#   manifest_path: 'config/dictionaries/directory/manifest.json'
#   enabled: true
#   initial_score: 0.80
#   tier: 'Primary'
#   notes: ''

runs: []
"""

SCORING_README = """# Fuzzy & Wordlist Scoring

Workspace ini menyimpan state dan artefak model adaptive fuzzy-wordlist scoring.

## Prinsip

Wordlist source tidak disalin ke dalam project. Source dikelola secara terpusat
oleh installer/wordlist manifest. Project menyimpan referensi wordlist yang
dipilih dan hasil eksekusinya.

## Alur

Wordlist -> Initial Score -> Fuzzy Ranking -> Request Budget -> Enumeration
-> Feedback -> Updated Score -> Ranking berikutnya

## Feedback

Model feedback menggunakan:

`new_score = initial_score + evidence_gain + discovery_yield - noise_penalty`

Score harus dibatasi pada rentang 0.0 sampai 1.0.

## Tier

- Primary: 0.80 - 1.00
- Secondary: 0.50 - 0.79
- Exploration: 0.20 - 0.49

Exploration tetap diberi kesempatan dan tidak langsung dibuang hanya karena
ranking awal rendah.

## Direktori

- `config/`    konfigurasi model.
- `baseline/`  baseline response/fuzzy comparison.
- `results/`   hasil scoring/ranking per run.
- `feedback/`  feedback evidence/discovery/noise.
- `history/`   histori perubahan score dan ranking.

Setiap run harus dapat ditelusuri kembali ke project, wordlist, request,
evidence, dan timestamp.
"""

WORDLISTS_README = """# Wordlists

Project menyimpan **referensi dan metadata pemakaian wordlist**, bukan salinan
source wordlist.

Source wordlist dikelola oleh wordlist manifest global yang dipelihara oleh
`install-requirements.ps1`.

## Direktori

- `selected/` referensi wordlist yang dipilih untuk project.
- `runs/` metadata/artefak pemakaian wordlist per run.

Raw hasil request tetap disimpan pada `../scans/ffuf/` atau repository scan
yang sesuai.
"""

ACTIVITY_LOG_HEADER = (
    "# BrebesKab-CSIRT-Tools Activity Log\n"
    "# timestamp | activity_id | phase | item | action | status | operator\n"
)


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def projects_root() -> Path:
    return repository_root() / "projects"


def runtime_root() -> Path:
    return repository_root() / ".runtime"


def active_project_file() -> Path:
    return runtime_root() / "active-project.yaml"


def secrets_root() -> Path:
    """Return the repository-local runtime secrets directory."""
    return runtime_root() / "secrets"


def project_secrets_dir(project_id: str) -> Path:
    """Return the runtime secrets directory for a project."""
    return secrets_root() / project_id


def encryption_key_file(project_id: str) -> Path:
    """Return the Fernet-compatible encryption key path for a project."""
    return project_secrets_dir(project_id) / "encryption.key"


def generate_encryption_key() -> bytes:
    """Generate a Fernet-compatible 32-byte URL-safe base64 key."""
    return base64.urlsafe_b64encode(os.urandom(32))


def is_valid_encryption_key(key: bytes) -> bool:
    """Validate the expected Fernet-compatible key representation."""
    key = key.strip()
    if len(key) != 44:
        return False

    try:
        decoded = base64.urlsafe_b64decode(key)
    except Exception:
        return False

    return len(decoded) == 32


def initialize_project_secrets(project_id: str) -> tuple[Path, bool]:
    """
    Ensure a project encryption key exists.

    Returns:
        (key_path, created)
    """
    project_id = normalize_project_id(project_id)
    key_path = encryption_key_file(project_id)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        if not key_path.is_file():
            raise ValueError(f"Encryption key path bukan file: {key_path}")

        existing_key = key_path.read_bytes().strip()
        if not is_valid_encryption_key(existing_key):
            raise ValueError(
                f"Encryption key tidak valid atau rusak: {key_path}"
            )

        return key_path, False

    key = generate_encryption_key()

    try:
        with key_path.open("xb") as handle:
            handle.write(key + b"\n")
    except FileExistsError:
        # Another process initialized the same project concurrently.
        existing_key = key_path.read_bytes().strip()
        if not is_valid_encryption_key(existing_key):
            raise ValueError(
                f"Encryption key tidak valid atau rusak: {key_path}"
            )
        return key_path, False

    # Restrict permissions on POSIX systems. On Windows, filesystem ACLs
    # remain responsible for access control.
    try:
        key_path.chmod(0o600)
    except OSError:
        pass

    return key_path, True


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}

    try:
        with path.open("r", encoding="utf-8-sig") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        return {}

    return data if isinstance(data, dict) else {}


def get_active_project_id() -> str | None:
    data = load_yaml(active_project_file())
    project_id = data.get("project_id")

    if not isinstance(project_id, str):
        return None

    project_id = project_id.strip()
    return project_id or None


def load_project(project_id: str) -> tuple[Path, dict[str, Any]]:
    project_dir = projects_root() / project_id

    if not project_dir.is_dir():
        raise ValueError(f"Project tidak ditemukan: {project_id}")

    assessment_file = project_dir / "assessment.yaml"

    if not assessment_file.is_file():
        raise ValueError(f"assessment.yaml tidak ditemukan pada project: {project_id}")

    assessment = load_yaml(assessment_file)

    if not assessment:
        raise ValueError(
            f"assessment.yaml tidak dapat dibaca atau kosong: {assessment_file}"
        )

    return project_dir, assessment


def write_text_if_missing(path: Path, content: str) -> bool:
    """Create a text file only when it does not already exist."""
    if path.exists():
        return False

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def ensure_directory(path: Path) -> bool:
    """Create a directory when missing and return True when created."""
    if path.is_dir():
        return False

    path.mkdir(parents=True, exist_ok=True)
    return True


def yaml_quote(value: str | None) -> str:
    if value is None:
        return "''"
    return "'" + value.replace("'", "''") + "'"


def normalize_project_id(project_id: str) -> str:
    project_id = project_id.strip()
    if not PROJECT_ID_PATTERN.fullmatch(project_id):
        raise ValueError(
            f"ProjectId tidak valid: '{project_id}'. "
            "Format yang digunakan adalah PENTEST-YYYY-NNN, contoh: PENTEST-2026-001."
        )
    return project_id


def write_initial_activity_log(
    project_dir: Path,
    *,
    project_id: str,
    operator: str,
    timestamp: str,
) -> bool:
    """Create the canonical activity log used by activity.py."""
    activity_path = project_dir / "timeline" / "activity.log"
    activity_line = (
        f"{timestamp} | ACT-0001 | 00-project | 00-001 | "
        f"Project workspace initialized | completed | {operator}\n"
    )
    return write_text_if_missing(
        activity_path,
        ACTIVITY_LOG_HEADER + "\n" + activity_line,
    )


def append_activity_record(
    project_dir: Path,
    *,
    phase: str,
    item: str,
    action: str,
    status: str,
    operator: str,
) -> str:
    """Append a canonical activity record and return its activity ID."""
    activity_path = project_dir / "timeline" / "activity.log"
    activity_path.parent.mkdir(parents=True, exist_ok=True)

    highest = 0
    if activity_path.is_file():
        for line in activity_path.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue

            parts = [part.strip() for part in line.split("|")]
            if len(parts) != 7:
                continue

            activity_id = parts[1].upper()
            if activity_id.startswith("ACT-") and activity_id[4:].isdigit():
                highest = max(highest, int(activity_id[4:]))

    activity_id = f"ACT-{highest + 1:04d}"
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    fields = (
        timestamp,
        activity_id,
        phase.strip(),
        item.strip(),
        action.strip(),
        status.strip().lower(),
        operator.strip(),
    )

    sanitized = [
        str(value).replace("\r", " ").replace("\n", " ").replace("|", "/")
        for value in fields
    ]

    if not activity_path.exists():
        activity_path.write_text(
            ACTIVITY_LOG_HEADER + "\n",
            encoding="utf-8",
            newline="\n",
        )

    with activity_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(" | ".join(sanitized) + "\n")

    return activity_id


def init_secrets(project_id: str) -> int:
    try:
        project_id = normalize_project_id(project_id)
        project_dir, _assessment = load_project(project_id)
        key_path, created = initialize_project_secrets(project_id)
    except (ValueError, OSError) as exc:
        print(f"[ERROR] Gagal menyiapkan encryption key: {exc}")
        return 1

    try:
        activity_id = append_activity_record(
            project_dir,
            phase="00-project",
            item="00-002",
            action=(
                "Project encryption key initialized"
                if created
                else "Project encryption key verified"
            ),
            status="completed",
            operator="project.py",
        )
    except OSError as exc:
        print(f"[ERROR] Encryption key siap, tetapi activity log gagal ditulis: {exc}")
        return 1

    print()
    print("=" * 60)
    print(" BrebesKab-CSIRT-Tools - Project Secrets")
    print("=" * 60)
    print(f"Project ID : {project_id}")
    print(f"Key path   : {key_path}")

    if created:
        print("[PASS] Encryption key berhasil dibuat.")
    else:
        print("[PASS] Encryption key sudah tersedia dan valid.")

    print(f"Activity   : {activity_id}")
    print()
    print("[INFO] Key tidak ditampilkan dan tidak dicatat ke activity log.")
    print()

    return 0



def atomic_write_text(path: Path, content: str) -> None:
    """Atomically replace a text configuration file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.migration.tmp")
    try:
        temp_path.write_text(content, encoding="utf-8", newline="\n")
        temp_path.replace(path)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def migrate_scoring_config(path: Path) -> bool:
    """
    Migrate legacy scoring wordlist manifest configuration to the canonical
    global manifest reference.

    Only scoring configuration is migrated. Assessment metadata, evidence,
    activity logs, and runtime encryption keys are never touched here.
    """
    if not path.is_file():
        return False

    original = path.read_text(encoding="utf-8-sig")
    updated = original

    # Legacy block:
    # manifest_candidates:
    #   - 'wordlists/manifest.json'
    #   - '.runtime/wordlists/manifest.json'
    legacy_block = re.compile(
        r"(?m)^([ \t]*)manifest_candidates:\s*\n"
        r"(?:\1[ \t]*-[^\n]*\n)+"
    )
    updated, block_count = legacy_block.subn(
        lambda m: (
            f"{m.group(1)}manifest: "
            f"'{CANONICAL_WORDLIST_MANIFEST}'\n"
        ),
        updated,
    )

    # Defensive migration for a legacy single manifest field.
    updated = re.sub(
        r'(?m)^([ \t]*)manifest:\s*[\'"](?:wordlists/manifest\.json|\.runtime/wordlists/manifest\.json)[\'"]\s*$',
        lambda m: (
            f"{m.group(1)}manifest: "
            f"'{CANONICAL_WORDLIST_MANIFEST}'"
        ),
        updated,
    )

    # Normalize legacy manifest paths everywhere else in the YAML as well,
    # including comments and example blocks. This keeps the file internally
    # consistent without changing any unrelated configuration.
    updated = re.sub(
        r'(?<![A-Za-z0-9_.-])(?:wordlists/manifest\.json|\.runtime/wordlists/manifest\.json)',
        CANONICAL_WORDLIST_MANIFEST,
        updated,
    )

    if updated == original:
        return False

    atomic_write_text(path, updated)
    return True


def migrate_selection_config(path: Path) -> bool:
    """
    Migrate legacy manifest_path references in selection.yaml.

    This changes only the project wordlist reference metadata; it never copies
    or modifies the actual global wordlist source files.
    """
    if not path.is_file():
        return False

    original = path.read_text(encoding="utf-8-sig")
    updated = original

    updated = re.sub(
        r"(?m)^([ \t]*manifest_path:\s*)['\"](?:wordlists/manifest\.json|\.runtime/wordlists/manifest\.json)['\"]\s*$",
        lambda m: (
            f"{m.group(1)}'{CANONICAL_WORDLIST_MANIFEST}'"
        ),
        updated,
    )

    # Normalize legacy manifest paths everywhere else in the YAML too,
    # including comments and examples.
    updated = re.sub(
        r'(?<![A-Za-z0-9_.-])(?:wordlists/manifest\.json|\.runtime/wordlists/manifest\.json)',
        CANONICAL_WORDLIST_MANIFEST,
        updated,
    )

    if updated == original:
        return False

    atomic_write_text(path, updated)
    return True


def migrate_project_scoring_configuration(project_dir: Path) -> tuple[bool, bool]:
    """
    Migrate existing scoring/selection configuration to the canonical
    global wordlist manifest.

    Returns:
        (scoring_migrated, selection_migrated)
    """
    scoring_path = project_dir / "scoring" / "config" / "scoring.yaml"
    selection_path = project_dir / "wordlists" / "selected" / "selection.yaml"

    scoring_migrated = migrate_scoring_config(scoring_path)
    selection_migrated = migrate_selection_config(selection_path)

    return scoring_migrated, selection_migrated

def create_project(
    *,
    project_id: str,
    application: str,
    target: str,
    tester: str,
    reviewer: str,
    environment: str,
    assessment_type: str,
    force: bool,
) -> int:
    try:
        project_id = normalize_project_id(project_id)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 1

    application = application.strip()
    target = target.strip()
    tester = tester.strip()
    reviewer = reviewer.strip()
    environment = environment.strip()
    assessment_type = assessment_type.strip()

    if environment not in ALLOWED_ENVIRONMENTS:
        print(
            f"[ERROR] Environment tidak valid: {environment!r}. "
            f"Gunakan: {', '.join(ALLOWED_ENVIRONMENTS)}"
        )
        return 1

    if assessment_type not in ALLOWED_ASSESSMENT_TYPES:
        print(
            f"[ERROR] Assessment type tidak valid: {assessment_type!r}. "
            f"Gunakan: {', '.join(ALLOWED_ASSESSMENT_TYPES)}"
        )
        return 1

    root = projects_root()
    project_dir = root / project_id
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

    print()
    print("=" * 60)
    print(" BrebesKab-CSIRT-Tools - New Pentest Project")
    print("=" * 60)
    print(f"Version    : {SCRIPT_VERSION}")
    print(f"Project ID : {project_id}")
    print(f"Repository : {repository_root()}")
    print(f"Project    : {project_dir}")
    print()

    root.mkdir(parents=True, exist_ok=True)

    if project_dir.is_file():
        print(f"[ERROR] Project path exists as a file: {project_dir}")
        return 1

    already_exists = project_dir.is_dir()
    if already_exists and not force:
        print(f"[ERROR] Project already exists: {project_dir}")
        print("        Gunakan --force jika ingin melengkapi item yang belum ada.")
        print("        File yang sudah ada tidak akan dihapus atau ditimpa.")
        return 1

    if already_exists:
        print("[WARN] Project sudah ada. Mode --force: hanya membuat item yang belum ada.")
    else:
        project_dir.mkdir(parents=True, exist_ok=True)
        print("[PASS] Project directory dibuat.")

    try:
        key_path, key_created = initialize_project_secrets(project_id)
    except (ValueError, OSError) as exc:
        print(f"[ERROR] Gagal menyiapkan encryption key: {exc}")
        return 1

    root_directories = (
        "evidence",
        "findings",
        "retest",
        "report",
        "report/draft",
        "report/final",
        "scans",
        "scans/nmap",
        "scans/httpx",
        "scans/nuclei",
        "scans/ffuf",
        "scans/zap",
        "wordlists",
        "wordlists/selected",
        "wordlists/runs",
        "scoring",
        "scoring/config",
        "scoring/baseline",
        "scoring/results",
        "scoring/feedback",
        "scoring/history",
        "timeline",
    )

    for relative_path in root_directories:
        ensure_directory(project_dir / relative_path)

    for phase in PHASE_DEFINITIONS:
        phase_dir = project_dir / f"{phase['number']}-{phase['slug']}"
        ensure_directory(phase_dir)

        phase_readme = f"""# {phase['number']}. {phase['name']}\n\n**Project:** {project_id}\n\n## Purpose\n\nWorkspace untuk seluruh aktivitas pada phase **{phase['number']}. {phase['name']}**.\n\n## Activities\n\nCatat aktivitas assessment yang dilakukan pada phase ini pada `timeline/activity.log`\ndan hubungkan dengan Activity ID.\n\n## Evidence\n\nEvidence disimpan pada:\n\n`../evidence/`\n\n## Findings\n\nFinding yang dihasilkan dari phase ini disimpan pada:\n\n`../findings/`\n\n## Notes\n\n- Jangan menyimpan password, token, API key, atau credential aktif di repository.\n- Raw output tool disimpan pada `../scans/` sesuai tool.\n- Evidence yang dipilih untuk mendukung finding harus mempunyai Evidence ID.\n"""
        write_text_if_missing(phase_dir / "README.md", phase_readme)

    readme = f"""# {project_id}\n\n## Web Application Penetration Testing Assessment\n\n| Item | Value |\n|---|---|\n| Project ID | {project_id} |\n| Application | {application} |\n| Target | {target} |\n| Tester | {tester} |\n| Reviewer | {reviewer} |\n| Environment | {environment} |\n| Assessment Type | {assessment_type} |\n| Created | {timestamp} |\n\n## Assessment Phases\n\nAssessment menggunakan 23 phase yang didefinisikan dalam\nframework assessment keamanan aplikasi web.\n\n""" + "\n".join(
        f"{idx}. {phase['name']}" for idx, phase in enumerate(PHASE_DEFINITIONS, start=1)
    ) + f"""\n\n## Repository Structure\n\n- `01-preparation/` sampai `23-final-sign-off/`\n  - Workspace berdasarkan phase assessment.\n- `timeline/`\n  - Jejak aktivitas assessment.\n- `scans/`\n  - Raw output dari security tools.\n- `wordlists/`\n  - Referensi wordlist yang dipilih dan metadata pemakaian; source wordlist tidak dicopy.\n- `scoring/`\n  - Konfigurasi, baseline, hasil ranking, feedback, dan history fuzzy-wordlist scoring.\n- `evidence/`\n  - Evidence yang dipilih dan direferensikan oleh assessment.\n- `findings/`\n  - Security findings.\n- `retest/`\n  - Evidence dan catatan retest.\n- `report/draft/`\n  - Draft report.\n- `report/final/`\n  - Final report.\n\n## Traceability\n\nSetiap aktivitas sebaiknya mempunyai:\n\n- Activity ID (`ACT-xxxx`)\n- Phase\n- Item\n- Timestamp\n- Action\n- Status\n- Operator\n- Evidence ID jika diperlukan\n- Finding ID jika menghasilkan finding\n- Scoring Run ID jika aktivitas menggunakan fuzzy/wordlist scoring\n- Wordlist ID dan source manifest jika menggunakan wordlist\n\n## Security\n\nJangan menyimpan:\n\n- Password\n- API key\n- Access token\n- Session cookie aktif\n- Private key\n- Credential lain\n\nSanitasi evidence sebelum dimasukkan ke repository.\n"""
    write_text_if_missing(project_dir / "README.md", readme)

    assessment_lines = [
        "schema_version: '1.0'",
        f"project_id: {yaml_quote(project_id)}",
        f"application: {yaml_quote(application)}",
        f"target: {yaml_quote(target)}",
        f"tester: {yaml_quote(tester)}",
        f"reviewer: {yaml_quote(reviewer)}",
        f"environment: {yaml_quote(environment)}",
        f"assessment_type: {yaml_quote(assessment_type)}",
        "status: 'not-started'",
        f"created_at: '{timestamp}'",
        "started_at: null",
        "completed_at: null",
        "",
        "phases:",
    ]
    for phase in PHASE_DEFINITIONS:
        assessment_lines.extend(
            [
                f"  - id: '{phase['number']}'",
                f"    name: {yaml_quote(phase['name'])}",
                f"    slug: '{phase['slug']}'",
                "    status: 'not-started'",
            ]
        )
    write_text_if_missing(
        project_dir / "assessment.yaml",
        "\n".join(assessment_lines) + "\n",
    )

    evidence_readme = "\n".join(
        [
            "# Evidence",
            "",
            f"Evidence repository untuk **{project_id}**.",
            "",
            "Gunakan format:",
            "",
            "`E-0001`, `E-0002`, `E-0003`, ...",
            "",
            "Setiap evidence sebaiknya memiliki metadata yang mencatat:",
            "",
            "- Evidence ID",
            "- Activity ID",
            "- Phase",
            "- Timestamp",
            "- Target",
            "- Tool",
            "- Description",
            "- Hash bila diperlukan",
            "- Sanitization status",
        ]
    ) + "\n"
    findings_readme = "\n".join(
        [
            "# Findings",
            "",
            f"Security findings untuk **{project_id}**.",
            "",
            "Gunakan format:",
            "",
            "`F-0001`, `F-0002`, `F-0003`, ...",
            "",
            "Setiap finding harus dapat ditelusuri ke:",
            "",
            "Finding -> Evidence -> Activity -> Phase",
        ]
    ) + "\n"
    retest_readme = "\n".join(
        [
            "# Retest",
            "",
            f"Retest records untuk **{project_id}**.",
            "",
            "Gunakan format:",
            "",
            "`RT-0001`, `RT-0002`, `RT-0003`, ...",
            "",
            "Retest harus mengacu pada Finding ID dan menyimpan evidence hasil verifikasi.",
        ]
    ) + "\n"
    report_readme = "\n".join(
        [
            "# Reports",
            "",
            "## Draft",
            "",
            "Simpan draft assessment report pada:",
            "",
            "`draft/`",
            "",
            "## Final",
            "",
            "Simpan final signed-off report pada:",
            "",
            "`final/`",
        ]
    ) + "\n"

    write_text_if_missing(project_dir / "evidence" / "README.md", evidence_readme)
    write_text_if_missing(project_dir / "findings" / "README.md", findings_readme)
    write_text_if_missing(project_dir / "retest" / "README.md", retest_readme)
    write_text_if_missing(project_dir / "report" / "README.md", report_readme)

    scan_readme = "\n".join(
        [
            "# Scans",
            "",
            "Raw output security tools.",
            "",
            "## Directories",
            "",
            "- `nmap/`",
            "- `httpx/`",
            "- `nuclei/`",
            "- `ffuf/`",
            "- `zap/`",
            "",
            "Raw scan output harus mempertahankan timestamp dan nama file yang dapat",
            "dikaitkan dengan Activity ID.",
        ]
    ) + "\n"
    write_text_if_missing(project_dir / "scans" / "README.md", scan_readme)
    write_text_if_missing(project_dir / "wordlists" / "README.md", WORDLISTS_README)
    write_text_if_missing(project_dir / "scoring" / "README.md", SCORING_README)

    scoring_config_path = project_dir / "scoring" / "config" / "scoring.yaml"
    selection_config_path = project_dir / "wordlists" / "selected" / "selection.yaml"

    scoring_created = write_text_if_missing(
        scoring_config_path,
        WORDLIST_SCORING_CONFIG,
    )
    selection_created = write_text_if_missing(
        selection_config_path,
        WORDLIST_SELECTION_TEMPLATE.format(project_id=project_id),
    )

    scoring_migrated = False
    selection_migrated = False

    # --force is intentionally allowed to migrate only these two configuration
    # files. Existing assessment/evidence/activity/key data remain untouched.
    if already_exists and force:
        try:
            scoring_migrated, selection_migrated = (
                migrate_project_scoring_configuration(project_dir)
            )
        except OSError as exc:
            print(f"[ERROR] Migrasi konfigurasi scoring/wordlist gagal: {exc}")
            return 1

    activity_created = write_initial_activity_log(
        project_dir,
        project_id=project_id,
        operator=tester or "project.py",
        timestamp=timestamp,
    )

    key_activity_created = False
    if key_created and activity_created:
        append_activity_record(
            project_dir,
            phase="00-project",
            item="00-002",
            action="Project encryption key initialized",
            status="completed",
            operator=tester or "project.py",
        )
        key_activity_created = True

    print()
    print("=" * 60)
    print(" Project structure ready")
    print("=" * 60)
    print(f"Project : {project_dir}")
    print()
    print("[PASS] 23 assessment phase directories tersedia.")
    print("[PASS] Evidence repository tersedia.")
    print("[PASS] Findings repository tersedia.")
    print("[PASS] Retest repository tersedia.")
    print("[PASS] Scan repositories tersedia.")
    print("[PASS] Wordlist workspace tersedia.")
    print("[PASS] Fuzzy/scoring workspace tersedia.")
    print("[PASS] Report repository tersedia.")
    print("[PASS] Timeline tersedia.")
    print("[PASS] assessment.yaml tersedia.")
    print("[PASS] README.md tersedia.")

    if scoring_created:
        print("[PASS] scoring/config/scoring.yaml dibuat.")
    elif scoring_migrated:
        print("[PASS] scoring/config/scoring.yaml dimigrasikan ke manifest global.")
    else:
        print("[INFO] scoring/config/scoring.yaml sudah ada; tidak ditimpa.")

    if selection_created:
        print("[PASS] wordlists/selected/selection.yaml dibuat.")
    elif selection_migrated:
        print("[PASS] wordlists/selected/selection.yaml dimigrasikan ke manifest global.")
    else:
        print("[INFO] wordlists/selected/selection.yaml sudah ada; tidak ditimpa.")

    print(f"[PASS] Global wordlist manifest: {CANONICAL_WORDLIST_MANIFEST}")
    print("[PASS] Source wordlist tidak disalin ke dalam project.")

    if activity_created:
        print("[PASS] Activity log canonical tersedia.")
    else:
        print("[INFO] Activity log sudah ada; tidak ditimpa.")

    if key_created:
        print("[PASS] Encryption key runtime berhasil dibuat.")
    else:
        print("[INFO] Encryption key runtime sudah tersedia dan valid.")
    print(f"        Key path: {key_path}")
    if key_activity_created:
        print("[PASS] Activity key initialization tercatat.")

    print()
    print("Next step:")
    print("  1. Verifikasi assessment.yaml / metadata project.")
    print("  2. Mulai dari 01-preparation.")
    print("  3. Catat setiap aktivitas melalui scripts/activity.py.")
    print("  4. Simpan raw scan pada scans/.")
    print("  5. Simpan evidence terpilih pada evidence/.")
    print("  6. Gunakan wordlists/selected/selection.yaml untuk referensi wordlist project.")
    print("  7. Gunakan scoring/config/scoring.yaml sebagai konfigurasi model scoring.")
    print("  8. Simpan baseline, result, feedback, dan history pada scoring/.")
    print("  9. Buat finding pada findings/ jika ada.")
    print()

    return 0


def validate_generated_report(project_dir: Path, started_at: Any) -> tuple[bool, str]:
    """
    Require a successfully generated report.py DOCX before assessment completion.

    report.py defaults to:
      <project>/23-final-sign-off/penetration-test-report.docx

    A valid DOCX container is required, and the report must not predate the
    current assessment start timestamp.
    """
    report_path = (
        project_dir
        / "23-final-sign-off"
        / "penetration-test-report.docx"
    )

    if not report_path.is_file():
        return False, f"Laporan belum ditemukan: {report_path}"

    try:
        if report_path.stat().st_size == 0 or not zipfile.is_zipfile(report_path):
            return False, f"File laporan bukan DOCX yang valid: {report_path}"
        with zipfile.ZipFile(report_path) as archive:
            names = set(archive.namelist())
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                return False, f"Struktur DOCX tidak lengkap: {report_path}"
    except (OSError, zipfile.BadZipFile) as exc:
        return False, f"Laporan tidak dapat diverifikasi ({report_path}): {exc}"

    if started_at:
        try:
            started_dt = datetime.fromisoformat(str(started_at))
            report_dt = datetime.fromtimestamp(
                report_path.stat().st_mtime, tz=started_dt.tzinfo
            )
            if report_dt < started_dt:
                return False, (
                    "Laporan ditemukan, tetapi waktu modifikasinya lebih lama "
                    "daripada started_at assessment saat ini."
                )
        except (TypeError, ValueError, OSError):
            return False, (
                "started_at tidak dapat diverifikasi; periksa assessment.yaml "
                "sebelum menyelesaikan assessment."
            )

    return True, str(report_path)


def update_assessment_lifecycle(project_id: str, action: str) -> int:
    """Set assessment start/completion timestamps without rewriting unrelated YAML."""
    try:
        project_id = normalize_project_id(project_id)
        project_dir, assessment = load_project(project_id)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 1

    assessment_path = project_dir / "assessment.yaml"
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    current_status = str(assessment.get("status", "not-started")).strip().lower()
    started_at = assessment.get("started_at")
    completed_at = assessment.get("completed_at")

    if action == "start":
        if current_status == "completed" or completed_at:
            print("[ERROR] Assessment sudah berstatus completed.")
            print("        Tidak ada perubahan yang dilakukan.")
            return 1
        if started_at:
            print(f"[INFO] Assessment sudah dimulai pada: {started_at}")
            print("[INFO] started_at tidak diubah.")
            if current_status != "in-progress":
                _replace_assessment_root_values(
                    assessment_path,
                    {"status": "in-progress"},
                )
        else:
            _replace_assessment_root_values(
                assessment_path,
                {"status": "in-progress", "started_at": now},
            )
            print(f"[PASS] started_at: {now}")
        activity_action = "Assessment started"
        activity_status = "in-progress"

    elif action == "complete":
        if completed_at:
            print(f"[INFO] Assessment sudah selesai pada: {completed_at}")
            print("[INFO] completed_at tidak diubah.")
            return 0

        if not started_at:
            print("[ERROR] Assessment belum dimulai.")
            print("        Jalankan: python scripts/project.py start <PROJECT-ID>")
            print("        completed_at tidak diubah.")
            return 1

        report_ok, report_message = validate_generated_report(project_dir, started_at)
        if not report_ok:
            print("[ERROR] Assessment belum dapat diselesaikan.")
            print(f"        {report_message}")
            print("        Jalankan scripts/report.py sampai muncul [PASS] Word report generated.")
            print("        completed_at tidak diubah.")
            return 1

        print(f"[PASS] Report terverifikasi: {report_message}")
        updates = {"status": "completed", "completed_at": now}
        _replace_assessment_root_values(assessment_path, updates)
        print(f"[PASS] completed_at: {now}")
        activity_action = "Assessment completed"
        activity_status = "completed"
    else:
        print(f"[ERROR] Aksi lifecycle tidak dikenal: {action}")
        return 2

    try:
        activity_id = append_activity_record(
            project_dir,
            phase="00-project",
            item="00-003" if action == "start" else "00-004",
            action=activity_action,
            status=activity_status,
            operator="project.py",
        )
    except OSError as exc:
        print(f"[WARN] assessment.yaml diperbarui, tetapi activity log gagal ditulis: {exc}")
    else:
        print(f"[PASS] Activity log: {activity_id}")

    print(f"Project    : {project_id}")
    print(f"Assessment : {assessment_path}")
    print()
    return 0


def _replace_assessment_root_values(path: Path, updates: dict[str, str]) -> None:
    """Replace selected top-level scalar fields while preserving the rest of the YAML."""
    content = path.read_text(encoding="utf-8-sig")
    for key, value in updates.items():
        if key not in {"status", "started_at", "completed_at"}:
            raise ValueError(f"Field assessment tidak diizinkan: {key}")
        if key == "status":
            replacement = f"status: {yaml_quote(value)}"
        else:
            replacement = f"{key}: {yaml_quote(value)}"
        pattern = re.compile(rf"(?m)^{re.escape(key)}:[^\n]*$")
        content, count = pattern.subn(lambda _match, line=replacement: line, content, count=1)
        if count != 1:
            raise ValueError(f"Field top-level '{key}' tidak ditemukan di {path}")
    atomic_write_text(path, content)


def list_projects() -> int:
    root = projects_root()

    if not root.is_dir():
        print("[INFO] Directory projects belum tersedia.")
        return 0

    project_dirs = sorted(
        [
            path
            for path in root.iterdir()
            if path.is_dir() and path.name.startswith("PENTEST-")
        ],
        key=lambda p: p.name.lower(),
    )

    active_id = get_active_project_id()

    print()
    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Pentest Projects")
    print("=" * 72)
    print(f"Version      : {SCRIPT_VERSION}")
    print(f"Repository   : {repository_root()}")
    print(f"Projects     : {root}")
    print()

    if not project_dirs:
        print("[INFO] Belum ada pentest project.")
        print()
        return 0

    print(f"{'':2}{'Project ID':<24} {'Application':<24} {'Status':<15}")
    print("-" * 72)

    for project_dir in project_dirs:
        project_id = project_dir.name
        assessment = load_yaml(project_dir / "assessment.yaml")

        application = assessment.get("application", "-")
        status = assessment.get("status", "unknown")

        if not isinstance(application, str):
            application = str(application)

        if not isinstance(status, str):
            status = str(status)

        marker = "*" if project_id == active_id else " "

        print(
            f"{marker} "
            f"{project_id:<24} "
            f"{application:<24} "
            f"{status:<15}"
        )

    print()
    if active_id:
        print(f"Active project: {active_id}")
    else:
        print("Active project: [none]")

    print()
    print("Keterangan:")
    print("  * = active project")
    print()
    return 0


def use_project(project_id: str) -> int:
    project_id = project_id.strip()

    if not project_id:
        print("[ERROR] Project ID tidak boleh kosong.")
        return 1

    try:
        project_dir, assessment = load_project(project_id)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 1

    application = assessment.get("application", "[Application Name]")
    target = assessment.get("target", "[Target URL]")
    environment = assessment.get("environment", "unknown")
    assessment_type = assessment.get("assessment_type", "unknown")

    active_file = active_project_file()
    active_file.parent.mkdir(parents=True, exist_ok=True)

    activated_at = datetime.now().astimezone().isoformat(timespec="seconds")

    active_data = {
        "schema_version": "1.0",
        "project_id": project_id,
        "project_path": project_dir.relative_to(repository_root()).as_posix(),
        "application": application,
        "target": target,
        "environment": environment,
        "assessment_type": assessment_type,
        "activated_at": activated_at,
    }

    with active_file.open("w", encoding="utf-8", newline="\n") as fh:
        yaml.safe_dump(
            active_data,
            fh,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )

    print()
    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Active Project")
    print("=" * 72)
    print("[PASS] Active project berhasil diubah.")
    print()
    print(f"Project ID  : {project_id}")
    print(f"Application : {application}")
    print(f"Target      : {target}")
    print(f"Environment : {environment}")
    print(f"Type        : {assessment_type}")
    print(f"Activated   : {activated_at}")
    print()
    print(f"Context     : {active_file}")
    print()

    return 0


def status_project() -> int:
    active_file = active_project_file()

    if not active_file.is_file():
        print()
        print("=" * 72)
        print(" BrebesKab-CSIRT-Tools - Active Project Status")
        print("=" * 72)
        print("[INFO] Tidak ada active project.")
        print()
        return 0

    data = load_yaml(active_file)

    if not data:
        print("[ERROR] active-project.yaml tidak dapat dibaca atau kosong.")
        print(f"Context: {active_file}")
        return 1

    project_id = data.get("project_id")

    if not isinstance(project_id, str) or not project_id.strip():
        print("[ERROR] active-project.yaml tidak memiliki project_id yang valid.")
        print(f"Context: {active_file}")
        return 1

    project_id = project_id.strip()

    try:
        project_dir, assessment = load_project(project_id)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        print(f"Context: {active_file}")
        return 1

    application = data.get("application", assessment.get("application", "-"))
    target = data.get("target", assessment.get("target", "-"))
    environment = data.get("environment", assessment.get("environment", "-"))
    assessment_type = data.get(
        "assessment_type",
        assessment.get("assessment_type", "-"),
    )
    activated_at = data.get("activated_at", "-")

    print()
    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Active Project Status")
    print("=" * 72)
    print(f"Project ID  : {project_id}")
    print(f"Application : {application}")
    print(f"Target      : {target}")
    print(f"Environment : {environment}")
    print(f"Type        : {assessment_type}")
    print(f"Activated   : {activated_at}")
    print(f"Project     : {project_dir}")
    print(f"Context     : {active_file}")
    print()

    return 0


def clear_project() -> int:
    active_file = active_project_file()

    if not active_file.exists():
        print()
        print("[INFO] Tidak ada active project yang perlu di-clear.")
        print()
        return 0

    if not active_file.is_file():
        print(f"[ERROR] Context path bukan file: {active_file}")
        return 1

    active_file.unlink()

    print()
    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Active Project")
    print("=" * 72)
    print("[PASS] Active project telah di-clear.")
    print(f"Context   : {active_file}")
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="project.py",
        description="BrebesKab-CSIRT-Tools Project Manager",
    )
    parser.add_argument(
        "command",
        choices=(
            "create", "init-secrets", "list", "use", "status",
            "start", "start-at", "complete", "completed-at", "clear",
        ),
        help="Project lifecycle command.",
    )
    parser.add_argument(
        "project_id",
        nargs="?",
        help="Project ID for create/use/init-secrets.",
    )
    parser.add_argument("--application", default="[Application Name]")
    parser.add_argument("--target", default="[Target URL]")
    parser.add_argument("--tester", default="[Tester]")
    parser.add_argument("--reviewer", default="[Reviewer]")
    parser.add_argument("--environment", choices=ALLOWED_ENVIRONMENTS, default="Production")
    parser.add_argument(
        "--assessment-type",
        choices=ALLOWED_ASSESSMENT_TYPES,
        default="Black Box",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Lengkapi project existing tanpa menimpa data assessment/evidence/activity/key; migrasikan konfigurasi scoring/wordlist legacy.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "create":
        if not args.project_id:
            parser.error("command 'create' membutuhkan <PROJECT-ID>.")
        return create_project(
            project_id=args.project_id,
            application=args.application,
            target=args.target,
            tester=args.tester,
            reviewer=args.reviewer,
            environment=args.environment,
            assessment_type=args.assessment_type,
            force=args.force,
        )

    if args.command == "init-secrets":
        if not args.project_id:
            parser.error("command 'init-secrets' membutuhkan <PROJECT-ID>.")
        return init_secrets(args.project_id)

    if args.command == "use":
        if not args.project_id:
            parser.error("command 'use' membutuhkan <PROJECT-ID>.")
        if any(
            value is not None
            for value in (
                args.application,
                args.target,
                args.tester,
                args.reviewer,
            )
        ):
            # argparse supplies defaults, so project-management commands ignore
            # create-only metadata silently rather than changing existing behavior.
            pass
        return use_project(args.project_id)

    if args.command == "list":
        return list_projects()

    if args.command == "status":
        return status_project()

    if args.command in ("start", "start-at"):
        if not args.project_id:
            parser.error(f"command '{args.command}' membutuhkan <PROJECT-ID>.")
        return update_assessment_lifecycle(args.project_id, "start")

    if args.command in ("complete", "completed-at"):
        if not args.project_id:
            parser.error(f"command '{args.command}' membutuhkan <PROJECT-ID>.")
        return update_assessment_lifecycle(args.project_id, "complete")

    if args.command == "clear":
        return clear_project()

    parser.error(f"Command tidak dikenal: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
