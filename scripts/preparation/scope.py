#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Preparation - Scope

Version: 1.0.0

Manage the authorized scope of a pentest project.

Scope is stored at:
    projects/<PROJECT-ID>/01-preparation/scope/scope.yaml

The active project is resolved through context.py.
No --project argument is required.

The scope defines:
- in-scope targets
- out-of-scope targets
- scope notes

This module does not perform technical scanning. It records the
assessment boundary that later tools can consume.
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

SCOPE_DIR_NAME = "scope"
SCOPE_FILE_NAME = "scope.yaml"

VALID_SCOPE_TYPES = {
    "domain",
    "url",
    "ip",
    "cidr",
    "application",
    "api",
    "service",
    "other",
}


class ScopeError(RuntimeError):
    """Raised when scope data cannot be created or modified."""


def scope_dir(context: ProjectContext) -> Path:
    """Return the scope directory."""
    return context.project_path / "01-preparation" / SCOPE_DIR_NAME


def scope_file(context: ProjectContext) -> Path:
    """Return the scope YAML path."""
    return scope_dir(context) / SCOPE_FILE_NAME


def _now() -> str:
    """Return current local timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    """Return the initial scope document."""
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "scope": {
            "in_scope": [],
            "out_of_scope": [],
            "notes": "",
        },
    }


def _load(context: ProjectContext) -> dict[str, Any]:
    """Load and validate scope.yaml."""
    path = scope_file(context)

    if not path.is_file():
        return _empty_document(context)

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ScopeError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise ScopeError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise ScopeError(
            "Format scope.yaml harus berupa mapping/object."
        )

    if data.get("project_id") != context.project_id:
        raise ScopeError(
            "Project ID pada scope.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    scope = data.get("scope")

    if not isinstance(scope, dict):
        raise ScopeError(
            "Field 'scope' harus berupa mapping/object."
        )

    in_scope = scope.get("in_scope", [])
    out_of_scope = scope.get("out_of_scope", [])

    if not isinstance(in_scope, list):
        raise ScopeError("Field 'in_scope' harus berupa list.")

    if not isinstance(out_of_scope, list):
        raise ScopeError("Field 'out_of_scope' harus berupa list.")

    scope["in_scope"] = in_scope
    scope["out_of_scope"] = out_of_scope
    scope["notes"] = str(scope.get("notes", ""))

    data["scope"] = scope

    return data


def _save(context: ProjectContext, data: dict[str, Any]) -> Path:
    """Save scope.yaml."""
    directory = scope_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = scope_file(context)

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
        raise ScopeError(f"Gagal menulis: {path}\n{exc}") from exc

    return path


def initialize(
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    """Create scope.yaml if it does not exist."""
    if context is None:
        context = require_active_project()

    path = scope_file(context)

    if path.is_file():
        return path

    return _save(context, _empty_document(context))


def _validate_type(scope_type: str) -> str:
    """Validate and normalize a scope item type."""
    value = scope_type.strip().lower()

    if value not in VALID_SCOPE_TYPES:
        allowed = ", ".join(sorted(VALID_SCOPE_TYPES))
        raise ScopeError(
            f"Scope type tidak valid: {scope_type!r}. "
            f"Gunakan: {allowed}"
        )

    return value


def _next_scope_id(items: list[dict[str, Any]], prefix: str) -> str:
    """Generate the next sequential scope item ID."""
    highest = 0

    for item in items:
        if not isinstance(item, dict):
            continue

        value = str(item.get("scope_id", "")).upper()

        if value.startswith(prefix) and value[len(prefix):].isdigit():
            highest = max(
                highest,
                int(value[len(prefix):]),
            )

    return f"{prefix}{highest + 1:03d}"


def add_in_scope(
    *,
    scope_type: str,
    value: str,
    description: str = "",
    ports: Optional[list[int]] = None,
    protocols: Optional[list[str]] = None,
    notes: str = "",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Add one authorized in-scope target."""
    if context is None:
        context = require_active_project()

    scope_type = _validate_type(scope_type)
    value = value.strip()
    description = description.strip()
    notes = notes.strip()

    if not value:
        raise ScopeError("Scope value tidak boleh kosong.")

    data = _load(context)
    items = data["scope"]["in_scope"]

    item = {
        "scope_id": _next_scope_id(items, "IN-"),
        "type": scope_type,
        "value": value,
        "description": description,
        "ports": ports or [],
        "protocols": protocols or [],
        "notes": notes,
    }

    items.append(item)
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-002",
        action=f"In-scope target recorded: {item['scope_id']} ({value})",
        status="completed",
        context=context,
    )

    return item


def add_out_of_scope(
    *,
    scope_type: str,
    value: str,
    reason: str,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Add one explicitly out-of-scope target."""
    if context is None:
        context = require_active_project()

    scope_type = _validate_type(scope_type)
    value = value.strip()
    reason = reason.strip()

    if not value:
        raise ScopeError("Out-of-scope value tidak boleh kosong.")

    if not reason:
        raise ScopeError("Alasan out-of-scope wajib diisi.")

    data = _load(context)
    items = data["scope"]["out_of_scope"]

    item = {
        "scope_id": _next_scope_id(items, "OUT-"),
        "type": scope_type,
        "value": value,
        "reason": reason,
    }

    items.append(item)
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-002",
        action=f"Out-of-scope target recorded: {item['scope_id']} ({value})",
        status="completed",
        context=context,
    )

    return item


def set_notes(
    notes: str,
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Set general scope notes."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    data["scope"]["notes"] = notes.strip()
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-002",
        action="Scope notes updated",
        status="completed",
        context=context,
    )


def list_scope(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, list[dict[str, Any]]]:
    """Return in-scope and out-of-scope items."""
    if context is None:
        context = require_active_project()

    scope = _load(context)["scope"]

    return {
        "in_scope": list(scope["in_scope"]),
        "out_of_scope": list(scope["out_of_scope"]),
    }


def get_scope_item(
    scope_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> Optional[dict[str, Any]]:
    """Find one scope item by IN-xxx or OUT-xxx."""
    if context is None:
        context = require_active_project()

    wanted = scope_id.strip().upper()
    data = _load(context)["scope"]

    for item in data["in_scope"] + data["out_of_scope"]:
        if str(item.get("scope_id", "")).upper() == wanted:
            return item

    return None


def remove_scope_item(
    scope_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Remove a scope item."""
    if context is None:
        context = require_active_project()

    wanted = scope_id.strip().upper()
    data = _load(context)
    scope = data["scope"]

    for field in ("in_scope", "out_of_scope"):
        items = scope[field]

        for index, item in enumerate(items):
            if str(item.get("scope_id", "")).upper() == wanted:
                items.pop(index)
                _save(context, data)

                record_activity(
                    phase="01-preparation",
                    item="01-002",
                    action=f"Scope item removed: {wanted}",
                    status="completed",
                    context=context,
                )

                return True

    return False


def print_scope(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print scope information."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    scope = data["scope"]

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Preparation Scope")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"File       : {scope_file(context)}")
    print()

    print("IN-SCOPE")
    print("-" * 72)

    if not scope["in_scope"]:
        print("[none]")
    else:
        for item in scope["in_scope"]:
            print(
                f"[{item.get('scope_id', '-')}] "
                f"{item.get('type', '')}: "
                f"{item.get('value', '')}"
            )
            if item.get("description"):
                print(f"  Description : {item['description']}")
            if item.get("ports"):
                print(f"  Ports       : {', '.join(map(str, item['ports']))}")
            if item.get("protocols"):
                print(f"  Protocols   : {', '.join(map(str, item['protocols']))}")
            if item.get("notes"):
                print(f"  Notes       : {item['notes']}")

    print()
    print("OUT-OF-SCOPE")
    print("-" * 72)

    if not scope["out_of_scope"]:
        print("[none]")
    else:
        for item in scope["out_of_scope"]:
            print(
                f"[{item.get('scope_id', '-')}] "
                f"{item.get('type', '')}: "
                f"{item.get('value', '')}"
            )
            print(f"  Reason      : {item.get('reason', '')}")

    print()
    print("NOTES")
    print("-" * 72)
    print(scope.get("notes", "") or "[none]")


def _prompt(label: str, required: bool = False) -> str:
    """Read one interactive value."""
    while True:
        value = input(f"{label}: ").strip()

        if value or not required:
            return value

        print("[ERROR] Nilai wajib diisi.")


def _parse_csv(value: str) -> list[str]:
    """Parse comma-separated values."""
    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def _parse_ports(value: str) -> list[int]:
    """Parse comma-separated TCP/UDP port numbers."""
    if not value.strip():
        return []

    ports: list[int] = []

    for part in value.split(","):
        part = part.strip()

        if not part:
            continue

        try:
            port = int(part)
        except ValueError as exc:
            raise ScopeError(
                f"Port tidak valid: {part!r}"
            ) from exc

        if not 1 <= port <= 65535:
            raise ScopeError(
                f"Port di luar rentang 1-65535: {port}"
            )

        ports.append(port)

    return ports


def interactive_add_in_scope(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Interactively add an in-scope target."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" Add In-Scope Target")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()

    scope_type = _prompt(
        "Type (domain/url/ip/cidr/application/api/service/other)",
        required=True,
    )
    value = _prompt("Value", required=True)
    description = _prompt("Description")
    ports = _parse_ports(_prompt("Ports (comma-separated)"))
    protocols = _parse_csv(_prompt("Protocols (comma-separated)"))
    notes = _prompt("Notes")

    item = add_in_scope(
        scope_type=scope_type,
        value=value,
        description=description,
        ports=ports,
        protocols=protocols,
        notes=notes,
        context=context,
    )

    print()
    print(f"[PASS] In-scope {item['scope_id']} berhasil disimpan.")
    print(f"File: {scope_file(context)}")

    return item


def interactive_add_out_of_scope(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Interactively add an out-of-scope target."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" Add Out-of-Scope Target")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()

    scope_type = _prompt(
        "Type (domain/url/ip/cidr/application/api/service/other)",
        required=True,
    )
    value = _prompt("Value", required=True)
    reason = _prompt("Reason", required=True)

    item = add_out_of_scope(
        scope_type=scope_type,
        value=value,
        reason=reason,
        context=context,
    )

    print()
    print(f"[PASS] Out-of-scope {item['scope_id']} berhasil disimpan.")
    print(f"File: {scope_file(context)}")

    return item


def print_help() -> None:
    """Print CLI help."""
    print(
        "Preparation Scope\n"
        "\n"
        "Usage:\n"
        "  python scripts/preparation/scope.py init\n"
        "  python scripts/preparation/scope.py add-in\n"
        "  python scripts/preparation/scope.py add-out\n"
        "  python scripts/preparation/scope.py list\n"
        "  python scripts/preparation/scope.py show IN-001\n"
        "  python scripts/preparation/scope.py remove IN-001\n"
        "  python scripts/preparation/scope.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
        "\n"
        "Scope types:\n"
        "  domain, url, ip, cidr, application, api, service, other\n"
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
            print(f"[PASS] Scope structure siap: {path}")
            return 0

        if command == "add-in":
            interactive_add_in_scope(context=context)
            return 0

        if command == "add-out":
            interactive_add_out_of_scope(context=context)
            return 0

        if command == "list":
            print_scope(context=context)
            return 0

        if command == "show":
            if len(args) != 2:
                print("[ERROR] Gunakan: scope.py show IN-001")
                return 2

            item = get_scope_item(args[1], context=context)

            if item is None:
                print(f"[INFO] Scope item tidak ditemukan: {args[1]}")
                return 1

            for key, value in item.items():
                print(f"{key:14}: {value}")

            return 0

        if command == "remove":
            if len(args) != 2:
                print("[ERROR] Gunakan: scope.py remove IN-001")
                return 2

            removed = remove_scope_item(
                args[1],
                context=context,
            )

            if not removed:
                print(f"[INFO] Scope item tidak ditemukan: {args[1]}")
                return 1

            print(f"[PASS] Scope item {args[1].upper()} telah dihapus.")
            return 0

        if command == "version":
            print(
                "BrebesKab-CSIRT-Tools "
                f"scope.py v{SCRIPT_VERSION}"
            )
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (ContextError, ScopeError, ActivityError) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
