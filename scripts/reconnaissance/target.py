#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Target Identification

Version: 1.0.0

Record and review the target identity for the active pentest project.

The active project is resolved through context.py.
No --project argument is required.

Storage:
    projects/<PROJECT-ID>/02-reconnaissance/target/target.yaml

Checklist mapping:
    02-001 - Target Identification

This module records the target baseline only. It does not perform
network requests or technical security testing.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from activity import ActivityError, record_activity
from context import ContextError, ProjectContext, require_active_project


SCRIPT_VERSION = "1.0.0"

RECON_DIR_NAME = "02-reconnaissance"
TARGET_DIR_NAME = "target"
TARGET_FILE_NAME = "target.yaml"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
}


class TargetError(RuntimeError):
    """Raised when target data cannot be created or modified."""


def target_dir(context: ProjectContext) -> Path:
    """Return the target identification directory."""
    return context.project_path / RECON_DIR_NAME / TARGET_DIR_NAME


def target_file(context: ProjectContext) -> Path:
    """Return the target YAML path."""
    return target_dir(context) / TARGET_FILE_NAME


def _now() -> str:
    """Return current local timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    """Return the initial target identification document."""
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "target": {
            "status": "not-started",
            "application": context.application,
            "target_url": context.target,
            "hostname": "",
            "scheme": "",
            "port": "",
            "environment": context.environment,
            "assessment_type": context.assessment_type,
            "scope_reference": "01-preparation/scope/scope.yaml",
            "notes": "",
        },
    }


def _load(context: ProjectContext) -> dict[str, Any]:
    """Load and validate target.yaml."""
    path = target_file(context)

    if not path.is_file():
        return _empty_document(context)

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise TargetError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise TargetError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise TargetError("Format target.yaml harus berupa mapping/object.")

    if data.get("project_id") != context.project_id:
        raise TargetError(
            "Project ID pada target.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    target = data.get("target")
    if not isinstance(target, dict):
        raise TargetError("Field 'target' harus berupa mapping/object.")

    defaults = _empty_document(context)["target"]
    for key, value in defaults.items():
        target.setdefault(key, value)

    status = str(target.get("status", "not-started")).strip().lower()
    if status not in VALID_STATUSES:
        raise TargetError(
            f"Status target tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data["target"] = target
    return data


def _save(context: ProjectContext, data: dict[str, Any]) -> Path:
    """Save target.yaml."""
    directory = target_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = target_file(context)

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
        raise TargetError(f"Gagal menulis: {path}\n{exc}") from exc

    return path


def initialize(*, context: Optional[ProjectContext] = None) -> Path:
    """Create target.yaml if it does not exist."""
    if context is None:
        context = require_active_project()

    path = target_file(context)

    if path.is_file():
        return path

    return _save(context, _empty_document(context))


def _normalize_target_url(target_url: str) -> str:
    """Validate and normalize the target URL."""
    value = target_url.strip()

    if not value:
        raise TargetError("Target URL tidak boleh kosong.")

    parsed = urlparse(value)

    if parsed.scheme not in {"http", "https"}:
        raise TargetError(
            "Target URL harus menggunakan protocol http atau https."
        )

    if not parsed.hostname:
        raise TargetError("Hostname pada target URL tidak ditemukan.")

    return value


def _derive_target_fields(target_url: str) -> dict[str, str]:
    """Derive scheme, hostname, and effective port from the target URL."""
    parsed = urlparse(target_url)

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""

    if parsed.port is not None:
        port = str(parsed.port)
    elif scheme == "https":
        port = "443"
    else:
        port = "80"

    return {
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
    }


def set_target(
    *,
    target_url: str,
    application: Optional[str] = None,
    environment: Optional[str] = None,
    assessment_type: Optional[str] = None,
    scope_reference: Optional[str] = None,
    notes: Optional[str] = None,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Record the target identification baseline."""
    if context is None:
        context = require_active_project()

    normalized_url = _normalize_target_url(target_url)
    derived = _derive_target_fields(normalized_url)

    data = _load(context)
    target = data["target"]

    target["target_url"] = normalized_url
    target["hostname"] = derived["hostname"]
    target["scheme"] = derived["scheme"]
    target["port"] = derived["port"]

    if application is not None:
        target["application"] = application.strip()

    if environment is not None:
        target["environment"] = environment.strip()

    if assessment_type is not None:
        target["assessment_type"] = assessment_type.strip()

    if scope_reference is not None:
        target["scope_reference"] = scope_reference.strip()

    if notes is not None:
        target["notes"] = notes.strip()

    target["status"] = "in-progress"

    _save(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-001",
            action=f"Target identification recorded: {derived['hostname']}",
            status="in-progress",
            context=context,
        )
    except ActivityError as exc:
        raise TargetError(
            f"Target berhasil disimpan, tetapi activity gagal dicatat.\n{exc}"
        ) from exc

    return data


def get_target(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Return the current target identification document."""
    if context is None:
        context = require_active_project()

    return _load(context)


def validate(
    *,
    context: Optional[ProjectContext] = None,
) -> list[str]:
    """Validate the minimum target identification information."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    target = data["target"]
    errors: list[str] = []

    required_fields = {
        "application": target.get("application"),
        "target_url": target.get("target_url"),
        "hostname": target.get("hostname"),
        "scheme": target.get("scheme"),
        "port": target.get("port"),
        "environment": target.get("environment"),
        "assessment_type": target.get("assessment_type"),
        "scope_reference": target.get("scope_reference"),
    }

    for field, value in required_fields.items():
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} belum diisi.")

    if target.get("scheme") not in {"http", "https"}:
        errors.append("scheme harus berupa http atau https.")

    if not str(target.get("port", "")).isdigit():
        errors.append("port harus berupa angka.")

    return errors


def verify(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Verify the target identification and mark it completed."""
    if context is None:
        context = require_active_project()

    errors = validate(context=context)

    if errors:
        raise TargetError(
            "Target identification belum lengkap:\n"
            + "\n".join(f"- {error}" for error in errors)
        )

    data = _load(context)
    data["target"]["status"] = "completed"
    _save(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-001",
            action="Target identification verified",
            status="completed",
            context=context,
        )
    except ActivityError as exc:
        raise TargetError(
            f"Target berhasil diverifikasi, tetapi activity gagal dicatat.\n{exc}"
        ) from exc

    return data


def set_status(
    status: str,
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Set target identification lifecycle status."""
    if context is None:
        context = require_active_project()

    normalized = status.strip().lower()

    if normalized not in VALID_STATUSES:
        raise TargetError(
            f"Status tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data = _load(context)
    data["target"]["status"] = normalized
    _save(context, data)

    record_activity(
        phase="02-reconnaissance",
        item="02-001",
        action=f"Target identification status changed to {normalized}",
        status="completed" if normalized == "completed" else "in-progress",
        context=context,
    )


def remove(
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Remove the target identification file."""
    if context is None:
        context = require_active_project()

    path = target_file(context)

    if not path.is_file():
        return False

    try:
        path.unlink()
    except OSError as exc:
        raise TargetError(f"Gagal menghapus: {path}\n{exc}") from exc

    record_activity(
        phase="02-reconnaissance",
        item="02-001",
        action="Target identification removed",
        status="completed",
        context=context,
    )

    return True


def print_summary(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print a concise target identification summary."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    target = data["target"]

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Reconnaissance Target")
    print("=" * 72)
    print(f"Project ID       : {context.project_id}")
    print(f"Status           : {target.get('status', '')}")
    print(f"Application      : {target.get('application', '')}")
    print(f"Target URL       : {target.get('target_url', '')}")
    print(f"Hostname         : {target.get('hostname', '')}")
    print(f"Scheme           : {target.get('scheme', '')}")
    print(f"Port             : {target.get('port', '')}")
    print(f"Environment      : {target.get('environment', '')}")
    print(f"Assessment Type  : {target.get('assessment_type', '')}")
    print(f"Scope Reference  : {target.get('scope_reference', '')}")
    print(f"File             : {target_file(context)}")


def print_full(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print the complete target document."""
    if context is None:
        context = require_active_project()

    data = _load(context)

    print(f"PROJECT: {context.project_id}")
    print(f"FILE   : {target_file(context)}")
    print()
    _print_value(data["target"])


def _print_value(value: Any, indent: int = 0) -> None:
    """Print nested YAML-like values."""
    prefix = " " * indent

    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print(f"{prefix}{key}:")
                _print_value(item, indent + 2)
            else:
                print(f"{prefix}{key}: {item}")
    elif isinstance(value, list):
        if not value:
            print(f"{prefix}[none]")
        else:
            for item in value:
                if isinstance(item, dict):
                    print(f"{prefix}-")
                    _print_value(item, indent + 2)
                else:
                    print(f"{prefix}- {item}")
    else:
        print(f"{prefix}{value}")


def interactive_add(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Interactively record the target identification baseline."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    target = data["target"]

    print("=" * 72)
    print(" Add Reconnaissance Target")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()

    current_url = str(target.get("target_url", "")).strip()
    current_application = str(target.get("application", "")).strip()
    current_environment = str(target.get("environment", "")).strip()
    current_assessment_type = str(target.get("assessment_type", "")).strip()

    target_url = input(
        f"Target URL [{current_url}]: "
    ).strip() or current_url

    if not target_url:
        raise TargetError("Target URL wajib diisi.")

    application = input(
        f"Application [{current_application}]: "
    ).strip() or current_application

    environment = input(
        f"Environment [{current_environment}]: "
    ).strip() or current_environment

    assessment_type = input(
        f"Assessment Type [{current_assessment_type}]: "
    ).strip() or current_assessment_type

    return set_target(
        target_url=target_url,
        application=application,
        environment=environment,
        assessment_type=assessment_type,
        context=context,
    )


def print_help() -> None:
    """Print CLI help."""
    print(
        "Reconnaissance Target Identification\n"
        "\n"
        "Usage:\n"
        "  python scripts/reconnaissance/target.py init\n"
        "  python scripts/reconnaissance/target.py add\n"
        "  python scripts/reconnaissance/target.py list\n"
        "  python scripts/reconnaissance/target.py show\n"
        "  python scripts/reconnaissance/target.py verify\n"
        "  python scripts/reconnaissance/target.py status\n"
        "  python scripts/reconnaissance/target.py remove\n"
        "  python scripts/reconnaissance/target.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    """Command-line entry point."""
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = args[0].lower()

    # version should work even without an active project.
    if command == "version":
        print(f"BrebesKab-CSIRT-Tools target.py v{SCRIPT_VERSION}")
        return 0

    try:
        context = require_active_project()

        if command == "init":
            path = initialize(context=context)
            print(f"[PASS] Target structure siap: {path}")
            return 0

        if command == "add":
            data = interactive_add(context=context)
            print()
            print("[PASS] Target identification berhasil disimpan.")
            print(f"File: {target_file(context)}")
            return 0

        if command == "list":
            print_summary(context=context)
            return 0

        if command == "show":
            print_full(context=context)
            return 0

        if command == "verify":
            verify(context=context)
            print("[PASS] Target identification memenuhi validasi.")
            print("[PASS] Status: completed")
            return 0

        if command == "status":
            data = get_target(context=context)
            print(f"Project ID : {context.project_id}")
            print(f"Status     : {data['target'].get('status', '')}")
            return 0

        if command == "remove":
            removed = remove(context=context)
            if not removed:
                print("[INFO] Target identification belum ada.")
                return 1

            print("[PASS] Target identification telah dihapus.")
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (ContextError, TargetError, ActivityError) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
