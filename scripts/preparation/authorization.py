#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Preparation - Authorization

Version: 1.0.0

Record and review authorization for an authorized pentest project.

The active project is resolved through context.py.
No --project argument is required.

Authorization data is stored at:
    projects/<PROJECT-ID>/01-preparation/authorization/authorization.yaml

Evidence files, when provided, belong under:
    projects/<PROJECT-ID>/01-preparation/authorization/evidence/

This module records the administrative authorization state. It does not
perform any technical security testing.
"""

from __future__ import annotations

import shutil
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

AUTHORIZATION_DIR_NAME = "authorization"
AUTHORIZATION_FILE_NAME = "authorization.yaml"
EVIDENCE_DIR_NAME = "evidence"

VALID_STATUSES = {
    "not-started",
    "pending",
    "verified",
    "rejected",
    "expired",
}


class AuthorizationError(RuntimeError):
    """Raised when authorization data cannot be created or modified."""


def authorization_dir(context: ProjectContext) -> Path:
    """Return the authorization directory."""
    return context.project_path / "01-preparation" / AUTHORIZATION_DIR_NAME


def authorization_file(context: ProjectContext) -> Path:
    """Return the authorization YAML path."""
    return authorization_dir(context) / AUTHORIZATION_FILE_NAME


def authorization_evidence_dir(context: ProjectContext) -> Path:
    """Return the authorization evidence directory."""
    return authorization_dir(context) / EVIDENCE_DIR_NAME


def _now() -> str:
    """Return current local timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    """Return the initial authorization document."""
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "status": "not-started",
        "authorization": {
            "reference": "",
            "document": "",
            "authorized_by": "",
            "authorized_date": "",
            "valid_from": "",
            "valid_until": "",
            "verification_notes": "",
        },
        "updated_at": _now(),
    }


def _load(context: ProjectContext) -> dict[str, Any]:
    """Load and validate authorization.yaml."""
    path = authorization_file(context)

    if not path.is_file():
        return _empty_document(context)

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise AuthorizationError(
            f"YAML tidak valid: {path}\n{exc}"
        ) from exc
    except OSError as exc:
        raise AuthorizationError(
            f"Gagal membaca: {path}\n{exc}"
        ) from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise AuthorizationError(
            "Format authorization.yaml harus berupa mapping/object."
        )

    if data.get("project_id") != context.project_id:
        raise AuthorizationError(
            "Project ID pada authorization.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    status = str(data.get("status", "not-started")).strip().lower()

    if status not in VALID_STATUSES:
        raise AuthorizationError(
            f"Status authorization tidak valid: {status!r}"
        )

    authorization = data.get("authorization")

    if not isinstance(authorization, dict):
        raise AuthorizationError(
            "Field 'authorization' harus berupa mapping/object."
        )

    data["authorization"] = authorization
    data["status"] = status

    return data


def _save(context: ProjectContext, data: dict[str, Any]) -> Path:
    """Save authorization.yaml."""
    directory = authorization_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = authorization_file(context)

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
        raise AuthorizationError(
            f"Gagal menulis: {path}\n{exc}"
        ) from exc

    return path


def initialize(
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    """Create authorization.yaml and evidence directory if absent."""
    if context is None:
        context = require_active_project()

    authorization_evidence_dir(context).mkdir(
        parents=True,
        exist_ok=True,
    )

    path = authorization_file(context)

    if path.is_file():
        return path

    return _save(context, _empty_document(context))


def set_authorization(
    *,
    reference: str,
    document: str = "",
    authorized_by: str = "",
    authorized_date: str = "",
    valid_from: str = "",
    valid_until: str = "",
    verification_notes: str = "",
    status: str = "pending",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """
    Record authorization metadata.

    This function does not claim that authorization is verified merely
    because metadata was entered. Use verify() after the authorization
    has actually been reviewed.
    """
    if context is None:
        context = require_active_project()

    reference = reference.strip()
    document = document.strip()
    authorized_by = authorized_by.strip()
    authorized_date = authorized_date.strip()
    valid_from = valid_from.strip()
    valid_until = valid_until.strip()
    verification_notes = verification_notes.strip()
    status = status.strip().lower()

    if not reference:
        raise AuthorizationError("Authorization reference tidak boleh kosong.")

    if status not in VALID_STATUSES:
        allowed = ", ".join(sorted(VALID_STATUSES))
        raise AuthorizationError(
            f"Status tidak valid: {status!r}. Gunakan: {allowed}"
        )

    data = _load(context)

    data["status"] = status
    data["authorization"] = {
        "reference": reference,
        "document": document,
        "authorized_by": authorized_by,
        "authorized_date": authorized_date,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "verification_notes": verification_notes,
    }

    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-001",
        action=f"Authorization metadata recorded: {reference}",
        status="completed",
        context=context,
    )

    return data


def verify(
    *,
    verification_notes: str = "",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """
    Mark an existing authorization record as verified.

    Verification means the tester/reviewer has actually reviewed the
    authorization record and confirmed it is suitable for the assessment.
    """
    if context is None:
        context = require_active_project()

    data = _load(context)
    authorization = data["authorization"]

    required_fields = {
        "reference": authorization.get("reference"),
        "authorized_by": authorization.get("authorized_by"),
        "authorized_date": authorization.get("authorized_date"),
    }

    missing = [
        field
        for field, value in required_fields.items()
        if not isinstance(value, str) or not value.strip()
    ]

    if missing:
        raise AuthorizationError(
            "Authorization belum lengkap. Field wajib kosong: "
            + ", ".join(missing)
        )

    notes = verification_notes.strip()

    if notes:
        authorization["verification_notes"] = notes

    data["status"] = "verified"
    data["authorization"] = authorization

    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-001",
        action="Authorization verified",
        status="completed",
        context=context,
    )

    return data


def reject(
    *,
    reason: str,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Mark the authorization as rejected."""
    if context is None:
        context = require_active_project()

    reason = reason.strip()

    if not reason:
        raise AuthorizationError("Alasan rejection wajib diisi.")

    data = _load(context)
    data["status"] = "rejected"
    data["authorization"]["verification_notes"] = reason

    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-001",
        action="Authorization rejected",
        status="failed",
        context=context,
    )

    return data


def attach_evidence(
    source: str,
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    """
    Copy an authorization evidence file into the project evidence directory.

    The source file is copied; the original is not modified.
    """
    if context is None:
        context = require_active_project()

    source_path = Path(source).expanduser().resolve()

    if not source_path.is_file():
        raise AuthorizationError(
            f"Evidence source tidak ditemukan: {source_path}"
        )

    destination_dir = authorization_evidence_dir(context)
    destination_dir.mkdir(parents=True, exist_ok=True)

    destination = destination_dir / source_path.name

    if destination.exists():
        raise AuthorizationError(
            f"Evidence dengan nama yang sama sudah ada: {destination}"
        )

    try:
        shutil.copy2(source_path, destination)
    except OSError as exc:
        raise AuthorizationError(
            f"Gagal menyalin evidence ke project:\n{exc}"
        ) from exc

    record_activity(
        phase="01-preparation",
        item="01-001",
        action=f"Authorization evidence attached: {destination.name}",
        status="completed",
        context=context,
    )

    return destination


def get_authorization(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Return the authorization document."""
    if context is None:
        context = require_active_project()

    return _load(context)


def print_status(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print authorization status."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    authorization = data["authorization"]

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Preparation Authorization")
    print("=" * 72)
    print(f"Project ID       : {context.project_id}")
    print(f"Status           : {data['status']}")
    print(f"Reference        : {authorization.get('reference', '')}")
    print(f"Document         : {authorization.get('document', '')}")
    print(f"Authorized by    : {authorization.get('authorized_by', '')}")
    print(f"Authorized date  : {authorization.get('authorized_date', '')}")
    print(f"Valid from       : {authorization.get('valid_from', '')}")
    print(f"Valid until      : {authorization.get('valid_until', '')}")
    print(f"Verification    : {authorization.get('verification_notes', '')}")
    print(f"File             : {authorization_file(context)}")
    print(f"Evidence         : {authorization_evidence_dir(context)}")


def _prompt(label: str, required: bool = False) -> str:
    """Read one value interactively."""
    while True:
        value = input(f"{label}: ").strip()

        if value or not required:
            return value

        print("[ERROR] Nilai wajib diisi.")


def interactive_record(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Interactively collect authorization metadata."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" Record Pentest Authorization")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()

    reference = _prompt(
        "Authorization Reference",
        required=True,
    )
    document = _prompt(
        "Authorization Document / Filename",
    )
    authorized_by = _prompt(
        "Authorized By",
        required=True,
    )
    authorized_date = _prompt(
        "Authorized Date (YYYY-MM-DD)",
        required=True,
    )
    valid_from = _prompt(
        "Valid From (YYYY-MM-DD)",
    )
    valid_until = _prompt(
        "Valid Until (YYYY-MM-DD)",
    )
    verification_notes = _prompt(
        "Verification Notes",
    )

    data = set_authorization(
        reference=reference,
        document=document,
        authorized_by=authorized_by,
        authorized_date=authorized_date,
        valid_from=valid_from,
        valid_until=valid_until,
        verification_notes=verification_notes,
        status="pending",
        context=context,
    )

    print()
    print("[PASS] Authorization metadata berhasil disimpan.")
    print(f"File: {authorization_file(context)}")
    print()
    print(
        "Status saat ini: pending.\n"
        "Gunakan 'verify' setelah authorization benar-benar diperiksa."
    )

    return data


def interactive_verify(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Interactively verify the current authorization."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" Verify Pentest Authorization")
    print("=" * 72)

    data = _load(context)

    print(f"Project ID : {context.project_id}")
    print(f"Reference  : {data['authorization'].get('reference', '')}")
    print(f"Authorized : {data['authorization'].get('authorized_by', '')}")
    print()

    notes = _prompt("Verification Notes")

    data = verify(
        verification_notes=notes,
        context=context,
    )

    print()
    print("[PASS] Authorization berstatus VERIFIED.")
    print(f"File: {authorization_file(context)}")

    return data


def print_help() -> None:
    """Print CLI help."""
    print(
        "Preparation Authorization\n"
        "\n"
        "Usage:\n"
        "  python scripts/preparation/authorization.py init\n"
        "  python scripts/preparation/authorization.py add\n"
        "  python scripts/preparation/authorization.py status\n"
        "  python scripts/preparation/authorization.py verify\n"
        "  python scripts/preparation/authorization.py attach <FILE>\n"
        "  python scripts/preparation/authorization.py reject\n"
        "  python scripts/preparation/authorization.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
        "\n"
        "Important:\n"
        "  'add' records authorization metadata as pending.\n"
        "  'verify' is a separate explicit verification step.\n"
        "  Do not store passwords, tokens, API keys, or other secrets here.\n"
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
            print(f"[PASS] Authorization structure siap: {path}")
            print(
                f"Evidence   : {authorization_evidence_dir(context)}"
            )
            return 0

        if command == "add":
            interactive_record(context=context)
            return 0

        if command == "status":
            print_status(context=context)
            return 0

        if command == "verify":
            interactive_verify(context=context)
            return 0

        if command == "attach":
            if len(args) != 2:
                print(
                    "[ERROR] Gunakan: "
                    "authorization.py attach <FILE>"
                )
                return 2

            destination = attach_evidence(
                args[1],
                context=context,
            )

            print(f"[PASS] Authorization evidence attached: {destination}")
            return 0

        if command == "reject":
            reason = _prompt("Reason", required=True)
            reject(reason=reason, context=context)
            print("[PASS] Authorization berstatus REJECTED.")
            return 0

        if command == "version":
            print(
                "BrebesKab-CSIRT-Tools "
                f"authorization.py v{SCRIPT_VERSION}"
            )
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (ContextError, AuthorizationError, ActivityError) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
