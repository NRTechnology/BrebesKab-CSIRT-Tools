#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Project Manager

Usage:
    python scripts/project.py create PENTEST-2026-003
    python scripts/project.py list
    python scripts/project.py use PENTEST-2026-002
    python scripts/project.py status
    python scripts/project.py clear

The `create` command replaces the former new-pentest-project.ps1 bootstrap
workflow while preserving the existing project context lifecycle.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML belum terinstall.")
    print("       Jalankan: python -m pip install PyYAML")
    sys.exit(1)


SCRIPT_VERSION = "1.3.0"
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
        "timeline",
    )

    for relative_path in root_directories:
        ensure_directory(project_dir / relative_path)

    for phase in PHASE_DEFINITIONS:
        phase_dir = project_dir / f"{phase['number']}-{phase['slug']}"
        ensure_directory(phase_dir)

        phase_readme = f"""# {phase['number']}. {phase['name']}\n\n**Project:** {project_id}\n\n## Purpose\n\nWorkspace untuk seluruh aktivitas pada phase **{phase['number']}. {phase['name']}**.\n\n## Activities\n\nCatat aktivitas assessment yang dilakukan pada phase ini pada `timeline/activity.log`\ndan hubungkan dengan Activity ID.\n\n## Evidence\n\nEvidence disimpan pada:\n\n`../evidence/`\n\n## Findings\n\nFinding yang dihasilkan dari phase ini disimpan pada:\n\n`../findings/`\n\n## Notes\n\n- Jangan menyimpan password, token, API key, atau credential aktif di repository.\n- Raw output tool disimpan pada `../scans/` sesuai tool.\n- Evidence yang dipilih untuk mendukung finding harus mempunyai Evidence ID.\n"""
        write_text_if_missing(phase_dir / "README.md", phase_readme)

    readme = f"""# {project_id}\n\n## Web Application Penetration Testing Assessment\n\n| Item | Value |\n|---|---|\n| Project ID | {project_id} |\n| Application | {application} |\n| Target | {target} |\n| Tester | {tester} |\n| Reviewer | {reviewer} |\n| Environment | {environment} |\n| Assessment Type | {assessment_type} |\n| Created | {timestamp} |\n\n## Assessment Phases\n\nAssessment menggunakan 23 phase yang didefinisikan dalam\nBrebesKab-CSIRT Web Application Penetration Testing Checklist.\n\n""" + "\n".join(
        f"{idx}. {phase['name']}" for idx, phase in enumerate(PHASE_DEFINITIONS, start=1)
    ) + f"""\n\n## Repository Structure\n\n- `01-preparation/` sampai `23-final-sign-off/`\n  - Workspace berdasarkan phase assessment.\n- `timeline/`\n  - Jejak aktivitas assessment.\n- `scans/`\n  - Raw output dari security tools.\n- `evidence/`\n  - Evidence yang dipilih dan direferensikan oleh assessment.\n- `findings/`\n  - Security findings.\n- `retest/`\n  - Evidence dan catatan retest.\n- `report/draft/`\n  - Draft report.\n- `report/final/`\n  - Final report.\n\n## Traceability\n\nSetiap aktivitas sebaiknya mempunyai:\n\n- Activity ID (`ACT-xxxx`)\n- Phase\n- Item\n- Timestamp\n- Action\n- Status\n- Operator\n- Evidence ID jika diperlukan\n- Finding ID jika menghasilkan finding\n\n## Security\n\nJangan menyimpan:\n\n- Password\n- API key\n- Access token\n- Session cookie aktif\n- Private key\n- Credential lain\n\nSanitasi evidence sebelum dimasukkan ke repository.\n"""
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

    checklist_lines = [
        "schema_version: '1.0'",
        f"project_id: {yaml_quote(project_id)}",
        "",
        "# Status values:",
        "# not-started | in-progress | completed | not-applicable",
        "",
        "items:",
    ]
    for phase in PHASE_DEFINITIONS:
        checklist_lines.extend(
            [
                f"  - phase_id: '{phase['number']}'",
                f"    phase: {yaml_quote(phase['name'])}",
                "    status: 'not-started'",
                "    activities: []",
                "    evidence: []",
                "    findings: []",
            ]
        )
    write_text_if_missing(
        project_dir / "checklist.yaml",
        "\n".join(checklist_lines) + "\n",
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

    activity_created = write_initial_activity_log(
        project_dir,
        project_id=project_id,
        operator=tester or "project.py",
        timestamp=timestamp,
    )

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
    print("[PASS] Report repository tersedia.")
    print("[PASS] Timeline tersedia.")
    print("[PASS] assessment.yaml tersedia.")
    print("[PASS] checklist.yaml tersedia.")
    print("[PASS] README.md tersedia.")
    if activity_created:
        print("[PASS] Activity log canonical tersedia.")
    else:
        print("[INFO] Activity log sudah ada; tidak ditimpa.")

    print()
    print("Next step:")
    print("  1. Verifikasi assessment.yaml / metadata project.")
    print("  2. Mulai dari 01-preparation.")
    print("  3. Catat setiap aktivitas melalui scripts/activity.py.")
    print("  4. Simpan raw scan pada scans/.")
    print("  5. Simpan evidence terpilih pada evidence/.")
    print("  6. Buat finding pada findings/ jika ada.")
    print()

    return 0


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
        choices=("create", "list", "use", "status", "clear"),
        help="Project lifecycle command.",
    )
    parser.add_argument("project_id", nargs="?", help="Project ID for create/use.")
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
        help="Lengkapi project yang sudah ada tanpa menimpa file yang sudah ada.",
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

    if args.command == "clear":
        return clear_project()

    parser.error(f"Command tidak dikenal: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
