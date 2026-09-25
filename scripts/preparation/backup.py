#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Preparation - Backup / Recovery

Version: 1.0.0

Manage backup and recovery readiness records for a pentest project.

Backup data is stored at:
    projects/<PROJECT-ID>/01-preparation/backup/backups.yaml

The active project is resolved through context.py.
No --project argument is required.

This module records backup/recovery readiness only. It does not execute
backup, restore, or recovery operations against the target environment.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from activity import ActivityError, record_activity
from context import ContextError, ProjectContext, require_active_project


SCRIPT_VERSION = "1.0.0"

BACKUP_DIR_NAME = "backup"
BACKUP_FILE_NAME = "backups.yaml"

VALID_STATUSES = {
    "planned",
    "available",
    "verified",
    "unavailable",
    "unknown",
}


class BackupError(RuntimeError):
    """Raised when backup/recovery data cannot be created or modified."""


def backup_dir(context: ProjectContext) -> Path:
    """Return the backup/recovery directory."""
    return context.project_path / "01-preparation" / BACKUP_DIR_NAME


def backup_file(context: ProjectContext) -> Path:
    """Return the backups YAML path."""
    return backup_dir(context) / BACKUP_FILE_NAME


def _now() -> str:
    """Return current local timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    """Return the initial backup/recovery document."""
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "backups": [],
        "notes": "",
    }


def _load(context: ProjectContext) -> dict[str, Any]:
    """Load and validate backups.yaml."""
    path = backup_file(context)

    if not path.is_file():
        return _empty_document(context)

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise BackupError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise BackupError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise BackupError("Format backups.yaml harus berupa mapping/object.")

    if data.get("project_id") != context.project_id:
        raise BackupError(
            "Project ID pada backups.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    backups = data.get("backups", [])

    if not isinstance(backups, list):
        raise BackupError("Field 'backups' harus berupa list.")

    data["backups"] = backups
    data["notes"] = str(data.get("notes", ""))

    return data


def _save(context: ProjectContext, data: dict[str, Any]) -> Path:
    """Save backups.yaml."""
    directory = backup_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = backup_file(context)

    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump(
                data,
                handle,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except OSError as exc:
        raise BackupError(f"Gagal menulis: {path}\n{exc}") from exc

    return path


def initialize(*, context: Optional[ProjectContext] = None) -> Path:
    """Create backups.yaml if it does not exist."""
    if context is None:
        context = require_active_project()

    path = backup_file(context)

    if path.is_file():
        return path

    return _save(context, _empty_document(context))


def _validate_status(status: str) -> str:
    """Validate and normalize backup status."""
    value = status.strip().lower()

    if value not in VALID_STATUSES:
        allowed = ", ".join(sorted(VALID_STATUSES))
        raise BackupError(
            f"Status backup tidak valid: {status!r}. Gunakan: {allowed}"
        )

    return value


def _next_backup_id(backups: list[dict[str, Any]]) -> str:
    """Generate the next sequential backup record ID."""
    highest = 0

    for backup in backups:
        if not isinstance(backup, dict):
            continue

        value = str(backup.get("backup_id", "")).upper()

        if value.startswith("BK-"):
            number = value[3:]
            if number.isdigit():
                highest = max(highest, int(number))

    return f"BK-{highest + 1:03d}"


def add_backup(
    *,
    name: str,
    scope: str = "",
    location: str = "",
    frequency: str = "",
    restore_tested: bool = False,
    rto: str = "",
    rpo: str = "",
    status: str = "planned",
    notes: str = "",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Add one backup/recovery readiness record."""
    if context is None:
        context = require_active_project()

    name = name.strip()
    scope = scope.strip()
    location = location.strip()
    frequency = frequency.strip()
    rto = rto.strip()
    rpo = rpo.strip()
    notes = notes.strip()
    status = _validate_status(status)

    if not name:
        raise BackupError("Nama backup/recovery wajib diisi.")

    data = _load(context)
    backups = data["backups"]

    backup = {
        "backup_id": _next_backup_id(backups),
        "name": name,
        "scope": scope,
        "location": location,
        "frequency": frequency,
        "restore_tested": restore_tested,
        "rto": rto,
        "rpo": rpo,
        "status": status,
        "created_at": _now(),
        "notes": notes,
    }

    backups.append(backup)
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-006",
        action=(
            f"Backup/recovery record recorded: "
            f"{backup['backup_id']} ({name})"
        ),
        status="completed",
        context=context,
    )

    return backup


def list_backups(*, context: Optional[ProjectContext] = None) -> list[dict[str, Any]]:
    """Return all backup/recovery records."""
    if context is None:
        context = require_active_project()

    return list(_load(context)["backups"])


def get_backup(
    backup_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> Optional[dict[str, Any]]:
    """Find one backup/recovery record by ID."""
    if context is None:
        context = require_active_project()

    wanted = backup_id.strip().upper()

    for backup in _load(context)["backups"]:
        if not isinstance(backup, dict):
            continue

        if str(backup.get("backup_id", "")).upper() == wanted:
            return backup

    return None


def remove_backup(
    backup_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Remove one backup/recovery record."""
    if context is None:
        context = require_active_project()

    wanted = backup_id.strip().upper()
    data = _load(context)
    backups = data["backups"]

    for index, backup in enumerate(backups):
        if not isinstance(backup, dict):
            continue

        current_id = str(backup.get("backup_id", "")).upper()

        if current_id == wanted:
            backups.pop(index)
            _save(context, data)

            record_activity(
                phase="01-preparation",
                item="01-006",
                action=f"Backup/recovery record removed: {wanted}",
                status="completed",
                context=context,
            )

            return True

    return False


def verify_backup(
    backup_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Mark a backup/recovery record as verified."""
    if context is None:
        context = require_active_project()

    wanted = backup_id.strip().upper()
    data = _load(context)

    for backup in data["backups"]:
        if not isinstance(backup, dict):
            continue

        current_id = str(backup.get("backup_id", "")).upper()

        if current_id != wanted:
            continue

        backup["status"] = "verified"
        backup["verified_at"] = _now()

        _save(context, data)

        record_activity(
            phase="01-preparation",
            item="01-006",
            action=f"Backup/recovery verified: {wanted}",
            status="completed",
            context=context,
        )

        return True

    return False


def set_notes(
    notes: str,
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Set general backup/recovery notes."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    data["notes"] = notes.strip()
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-006",
        action="Backup/recovery notes updated",
        status="completed",
        context=context,
    )


def print_backups(*, context: Optional[ProjectContext] = None) -> None:
    """Print backup/recovery information."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    backups = data["backups"]

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Backup / Recovery")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"File       : {backup_file(context)}")
    print()

    if not backups:
        print("[none]")
    else:
        for backup in backups:
            print(
                f"[{backup.get('backup_id', '-')}] "
                f"{backup.get('name', '')}"
            )
            print(f"  Scope          : {backup.get('scope', '')}")
            print(f"  Location       : {backup.get('location', '')}")
            print(f"  Frequency      : {backup.get('frequency', '')}")
            print(f"  Restore Tested : {backup.get('restore_tested', False)}")
            print(f"  RTO            : {backup.get('rto', '')}")
            print(f"  RPO            : {backup.get('rpo', '')}")
            print(f"  Status         : {backup.get('status', '')}")
            print(f"  Created        : {backup.get('created_at', '')}")

            if backup.get("verified_at"):
                print(f"  Verified       : {backup.get('verified_at')}")

            if backup.get("notes"):
                print(f"  Notes          : {backup.get('notes')}")

            print()

    print("NOTES")
    print("-" * 72)
    print(data.get("notes", "") or "[none]")


def print_backup(
    backup_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Print one backup/recovery record."""
    if context is None:
        context = require_active_project()

    backup = get_backup(backup_id, context=context)

    if backup is None:
        print(f"[INFO] Backup/recovery record tidak ditemukan: {backup_id}")
        return False

    print("=" * 72)
    print(" Backup / Recovery Record")
    print("=" * 72)

    for key, value in backup.items():
        print(f"{key:16}: {value}")

    return True


def print_status(*, context: Optional[ProjectContext] = None) -> None:
    """Print backup/recovery preparation status."""
    if context is None:
        context = require_active_project()

    backups = _load(context)["backups"]

    verified = 0
    available = 0
    planned = 0
    unavailable = 0
    unknown = 0

    for backup in backups:
        if not isinstance(backup, dict):
            continue

        status = str(backup.get("status", "")).lower()

        if status == "verified":
            verified += 1
        elif status == "available":
            available += 1
        elif status == "planned":
            planned += 1
        elif status == "unavailable":
            unavailable += 1
        elif status == "unknown":
            unknown += 1

    print("=" * 72)
    print(" Backup / Recovery Status")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()
    print(f"Total      : {len(backups)}")
    print(f"Verified   : {verified}")
    print(f"Available  : {available}")
    print(f"Planned    : {planned}")
    print(f"Unavailable: {unavailable}")
    print(f"Unknown    : {unknown}")
    print()

    if verified > 0:
        print("[PASS] Minimal backup/recovery record terverifikasi tersedia.")
    elif available > 0:
        print("[WARN] Backup tersedia tetapi belum diverifikasi.")
    elif planned > 0:
        print("[WARN] Backup/recovery sudah dicatat tetapi belum diverifikasi.")
    else:
        print("[WARN] Belum ada record backup/recovery.")


def _prompt(label: str, required: bool = False) -> str:
    """Read one interactive value."""
    while True:
        value = input(f"{label}: ").strip()

        if value or not required:
            return value

        print("[ERROR] Nilai wajib diisi.")


def _prompt_bool(label: str, default: bool = False) -> bool:
    """Read a yes/no value."""
    default_text = "Y/n" if default else "y/N"

    while True:
        value = input(f"{label} [{default_text}]: ").strip().lower()

        if not value:
            return default

        if value in {"y", "yes", "ya", "yakin"}:
            return True

        if value in {"n", "no", "tidak", "t"}:
            return False

        print("[ERROR] Masukkan y/yes/ya atau n/no/tidak.")


def interactive_add(*, context: Optional[ProjectContext] = None) -> dict[str, Any]:
    """Interactively add one backup/recovery record."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" Add Backup / Recovery Record")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()
    print("CATATAN: Jangan mengarang RTO/RPO. Jika belum diketahui,")
    print("         biarkan kosong dan dokumentasikan status sebenarnya.")
    print()

    name = _prompt("Name", required=True)
    scope = _prompt("Scope")
    location = _prompt("Location")
    frequency = _prompt("Frequency")
    restore_tested = _prompt_bool("Restore already tested", default=False)
    rto = _prompt("RTO")
    rpo = _prompt("RPO")
    status = _prompt("Status (planned/available/verified/unavailable/unknown)")

    if not status:
        status = "planned"

    notes = _prompt("Notes")

    backup = add_backup(
        name=name,
        scope=scope,
        location=location,
        frequency=frequency,
        restore_tested=restore_tested,
        rto=rto,
        rpo=rpo,
        status=status,
        notes=notes,
        context=context,
    )

    print()
    print(
        f"[PASS] Backup/recovery {backup['backup_id']} berhasil disimpan."
    )
    print(f"File: {backup_file(context)}")

    return backup


def print_help() -> None:
    """Print CLI help."""
    print(
        "Preparation Backup / Recovery\n"
        "\n"
        "Usage:\n"
        "  python scripts/preparation/backup.py init\n"
        "  python scripts/preparation/backup.py add\n"
        "  python scripts/preparation/backup.py list\n"
        "  python scripts/preparation/backup.py show BK-001\n"
        "  python scripts/preparation/backup.py verify BK-001\n"
        "  python scripts/preparation/backup.py status\n"
        "  python scripts/preparation/backup.py remove BK-001\n"
        "  python scripts/preparation/backup.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
        "\n"
        "This module records backup/recovery readiness only.\n"
        "It does not execute backup or restore operations.\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    """Command-line entry point."""
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = args[0].lower()

    try:
        context = require_active_project()

        if command == "init":
            path = initialize(context=context)
            print(f"[PASS] Backup/recovery structure siap: {path}")
            return 0

        if command == "add":
            interactive_add(context=context)
            return 0

        if command == "list":
            print_backups(context=context)
            return 0

        if command == "show":
            if len(args) != 2:
                print("[ERROR] Gunakan: backup.py show BK-001")
                return 2

            found = print_backup(args[1], context=context)
            return 0 if found else 1

        if command == "verify":
            if len(args) != 2:
                print("[ERROR] Gunakan: backup.py verify BK-001")
                return 2

            verified = verify_backup(args[1], context=context)

            if not verified:
                print(
                    f"[INFO] Backup/recovery record tidak ditemukan: {args[1]}"
                )
                return 1

            print(
                f"[PASS] Backup/recovery {args[1].upper()} telah diverifikasi."
            )
            return 0

        if command == "status":
            print_status(context=context)
            return 0

        if command == "remove":
            if len(args) != 2:
                print("[ERROR] Gunakan: backup.py remove BK-001")
                return 2

            removed = remove_backup(args[1], context=context)

            if not removed:
                print(
                    f"[INFO] Backup/recovery record tidak ditemukan: {args[1]}"
                )
                return 1

            print(
                f"[PASS] Backup/recovery {args[1].upper()} telah dihapus."
            )
            return 0

        if command == "version":
            print(
                "BrebesKab-CSIRT-Tools "
                f"backup.py v{SCRIPT_VERSION}"
            )
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (ContextError, BackupError, ActivityError) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
