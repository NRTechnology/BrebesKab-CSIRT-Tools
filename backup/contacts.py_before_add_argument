#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Preparation - Contacts

Version: 1.0.0

Manage contact information for the active pentest project.

Contacts are stored at:
    projects/<PROJECT-ID>/01-preparation/contacts/contacts.yaml

The active project is resolved through context.py.
No --project argument is required.

Typical contacts:
- Project PIC
- Application/System Owner
- Tester
- Reviewer
- Emergency Contact

This module intentionally stores only contact information needed for the
assessment workflow. Avoid storing passwords, API keys, tokens, or other
authentication secrets here.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

# Make scripts/ importable when this file is executed directly.
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from context import ContextError, ProjectContext, require_active_project
from activity import ActivityError, record_activity


SCRIPT_VERSION = "1.0.0"

CONTACTS_DIR_NAME = "contacts"
CONTACTS_FILE_NAME = "contacts.yaml"

DEFAULT_ROLES = (
    "project-pic",
    "application-owner",
    "tester",
    "reviewer",
    "emergency-contact",
)


class ContactsError(RuntimeError):
    """Raised when contact data cannot be created or modified."""


def contacts_dir(context: ProjectContext) -> Path:
    """Return the contacts directory for the active project."""
    return context.project_path / "01-preparation" / CONTACTS_DIR_NAME


def contacts_file(context: ProjectContext) -> Path:
    """Return the contacts YAML file for the active project."""
    return contacts_dir(context) / CONTACTS_FILE_NAME


def _now() -> str:
    """Return current local timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    """Return the initial contacts YAML structure."""
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "contacts": [],
    }


def _load_contacts(context: ProjectContext) -> dict[str, Any]:
    """Load and validate the contacts YAML document."""
    path = contacts_file(context)

    if not path.is_file():
        return _empty_document(context)

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ContactsError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise ContactsError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise ContactsError("Format contacts.yaml harus berupa mapping/object.")

    if data.get("project_id") != context.project_id:
        raise ContactsError(
            "Project ID pada contacts.yaml tidak sesuai dengan active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    contacts = data.get("contacts", [])

    if not isinstance(contacts, list):
        raise ContactsError("Field 'contacts' harus berupa list.")

    data["contacts"] = contacts
    return data


def _save_contacts(context: ProjectContext, data: dict[str, Any]) -> Path:
    """Save contacts YAML for the active project."""
    directory = contacts_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = contacts_file(context)

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
        raise ContactsError(f"Gagal menulis: {path}\n{exc}") from exc

    return path


def initialize_contacts(
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    """
    Create the contacts file if it does not exist.

    Returns the contacts file path.
    """
    if context is None:
        context = require_active_project()

    path = contacts_file(context)

    if path.is_file():
        return path

    return _save_contacts(context, _empty_document(context))


def _next_contact_id(data: dict[str, Any]) -> str:
    """Generate the next sequential contact ID."""
    highest = 0

    for contact in data.get("contacts", []):
        if not isinstance(contact, dict):
            continue

        value = str(contact.get("contact_id", "")).upper()

        if value.startswith("C-") and value[2:].isdigit():
            highest = max(highest, int(value[2:]))

    return f"C-{highest + 1:03d}"


def add_contact(
    *,
    role: str,
    name: str,
    organization: str = "",
    email: str = "",
    phone: str = "",
    availability: str = "",
    notes: str = "",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Add one contact to the active project."""
    if context is None:
        context = require_active_project()

    role = role.strip()
    name = name.strip()
    organization = organization.strip()
    email = email.strip()
    phone = phone.strip()
    availability = availability.strip()
    notes = notes.strip()

    if not role:
        raise ContactsError("Role tidak boleh kosong.")

    if not name:
        raise ContactsError("Nama contact tidak boleh kosong.")

    data = _load_contacts(context)

    contact = {
        "contact_id": _next_contact_id(data),
        "role": role,
        "name": name,
        "organization": organization,
        "email": email,
        "phone": phone,
        "availability": availability,
        "notes": notes,
    }

    data["contacts"].append(contact)
    _save_contacts(context, data)

    try:
        record_activity(
            phase="01-preparation",
            item="01-004",
            action=f"Contact recorded: {contact['contact_id']} ({role})",
            status="completed",
            context=context,
        )
    except ActivityError as exc:
        raise ContactsError(
            f"Contact berhasil disimpan, tetapi activity gagal dicatat.\n{exc}"
        ) from exc

    return contact


def list_contacts(
    *,
    context: Optional[ProjectContext] = None,
) -> list[dict[str, Any]]:
    """Return all contacts for the active project."""
    if context is None:
        context = require_active_project()

    return list(_load_contacts(context).get("contacts", []))


def get_contact(
    contact_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> Optional[dict[str, Any]]:
    """Return one contact by contact ID."""
    if context is None:
        context = require_active_project()

    wanted = contact_id.strip().upper()

    for contact in list_contacts(context=context):
        if str(contact.get("contact_id", "")).upper() == wanted:
            return contact

    return None


def remove_contact(
    contact_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Remove one contact from the active project."""
    if context is None:
        context = require_active_project()

    wanted = contact_id.strip().upper()
    data = _load_contacts(context)
    contacts = data.get("contacts", [])

    remaining = [
        contact
        for contact in contacts
        if str(contact.get("contact_id", "")).upper() != wanted
    ]

    if len(remaining) == len(contacts):
        return False

    data["contacts"] = remaining
    _save_contacts(context, data)

    record_activity(
        phase="01-preparation",
        item="01-004",
        action=f"Contact removed: {wanted}",
        status="completed",
        context=context,
    )

    return True


def print_contacts(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print contacts in a readable table-like format."""
    if context is None:
        context = require_active_project()

    contacts = list_contacts(context=context)

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Preparation Contacts")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"File       : {contacts_file(context)}")
    print()

    if not contacts:
        print("[INFO] Belum ada contact.")
        return

    for contact in contacts:
        print(f"[{contact.get('contact_id', '-')}]")
        print(f"  Role         : {contact.get('role', '')}")
        print(f"  Name         : {contact.get('name', '')}")
        print(f"  Organization : {contact.get('organization', '')}")
        print(f"  Email        : {contact.get('email', '')}")
        print(f"  Phone        : {contact.get('phone', '')}")
        print(f"  Availability : {contact.get('availability', '')}")
        print(f"  Notes        : {contact.get('notes', '')}")
        print()


def _prompt(label: str, required: bool = False) -> str:
    """Read one value interactively."""
    while True:
        value = input(f"{label}: ").strip()

        if value or not required:
            return value

        print("[ERROR] Nilai wajib diisi.")


def interactive_add(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Interactively collect and add one contact."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" Add Preparation Contact")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()

    role = _prompt(
        "Role (contoh: project-pic, application-owner, tester, reviewer, emergency-contact)",
        required=True,
    )
    name = _prompt("Name", required=True)
    organization = _prompt("Organization")
    email = _prompt("Email")
    phone = _prompt("Phone")
    availability = _prompt("Availability")
    notes = _prompt("Notes")

    contact = add_contact(
        role=role,
        name=name,
        organization=organization,
        email=email,
        phone=phone,
        availability=availability,
        notes=notes,
        context=context,
    )

    print()
    print(f"[PASS] Contact {contact['contact_id']} berhasil disimpan.")
    print(f"File: {contacts_file(context)}")

    return contact


def print_help() -> None:
    """Print CLI help."""
    print(
        "Preparation Contacts\n"
        "\n"
        "Usage:\n"
        "  python scripts/preparation/contacts.py init\n"
        "  python scripts/preparation/contacts.py add\n"
        "  python scripts/preparation/contacts.py list\n"
        "  python scripts/preparation/contacts.py show C-001\n"
        "  python scripts/preparation/contacts.py remove C-001\n"
        "  python scripts/preparation/contacts.py version\n"
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

    try:
        context = require_active_project()

        if command == "init":
            path = initialize_contacts(context=context)
            print(f"[PASS] Contacts file siap: {path}")
            return 0

        if command == "add":
            interactive_add(context=context)
            return 0

        if command == "list":
            print_contacts(context=context)
            return 0

        if command == "show":
            if len(args) != 2:
                print("[ERROR] Gunakan: contacts.py show C-001")
                return 2

            contact = get_contact(args[1], context=context)

            if contact is None:
                print(f"[INFO] Contact tidak ditemukan: {args[1]}")
                return 1

            for key, value in contact.items():
                print(f"{key:14}: {value}")

            return 0

        if command == "remove":
            if len(args) != 2:
                print("[ERROR] Gunakan: contacts.py remove C-001")
                return 2

            removed = remove_contact(args[1], context=context)

            if not removed:
                print(f"[INFO] Contact tidak ditemukan: {args[1]}")
                return 1

            print(f"[PASS] Contact {args[1].upper()} telah dihapus.")
            return 0

        if command == "version":
            print(f"BrebesKab-CSIRT-Tools contacts.py v{SCRIPT_VERSION}")
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (ContextError, ContactsError, ActivityError) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
