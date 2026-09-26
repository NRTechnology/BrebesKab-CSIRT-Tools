#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Preparation - Test Account

Version: 1.3.0

Manage authorized test accounts for a pentest project.

Account data is stored at:
    projects/<PROJECT-ID>/01-preparation/account/accounts.yaml

The active project is resolved through context.py.
No --project argument is required.

Credential values are accepted only in encrypted form and are stored
as Fernet ciphertext in accounts.yaml. Plaintext credentials are kept
only in memory when explicitly decrypted for an authorized caller.
"""

from __future__ import annotations

import sys
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Any, Optional

import yaml


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from activity import ActivityError, record_activity
from context import ContextError, ProjectContext, require_active_project
from secrets import SecretsError, decrypt, encrypt, load_key


SCRIPT_VERSION = "1.3.0"

ACCOUNT_DIR_NAME = "account"
ACCOUNT_FILE_NAME = "accounts.yaml"
ACCOUNT_SCHEMA_VERSION = "2.0"

VALID_ROLES = {
    "tester",
    "reviewer",
    "admin",
    "user",
    "operator",
    "other",
}

VALID_STATUSES = {
    "planned",
    "active",
    "disabled",
    "revoked",
}


class AccountError(RuntimeError):
    """Raised when account data cannot be created or modified."""


def account_dir(context: ProjectContext) -> Path:
    """Return the account directory."""
    return context.project_path / "01-preparation" / ACCOUNT_DIR_NAME


def account_file(context: ProjectContext) -> Path:
    """Return the accounts YAML path."""
    return account_dir(context) / ACCOUNT_FILE_NAME


def _now() -> str:
    """Return current local timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    """Return the initial account document."""
    return {
        "schema_version": ACCOUNT_SCHEMA_VERSION,
        "project_id": context.project_id,
        "updated_at": _now(),
        "accounts": [],
        "notes": "",
    }


def _load(context: ProjectContext) -> dict[str, Any]:
    """Load and validate accounts.yaml."""
    path = account_file(context)

    if not path.is_file():
        return _empty_document(context)

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise AccountError(
            f"YAML tidak valid: {path}\n{exc}"
        ) from exc
    except OSError as exc:
        raise AccountError(
            f"Gagal membaca: {path}\n{exc}"
        ) from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise AccountError(
            "Format accounts.yaml harus berupa mapping/object."
        )

    if data.get("project_id") != context.project_id:
        raise AccountError(
            "Project ID pada accounts.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    schema_version = str(data.get("schema_version", "")).strip()
    if schema_version != ACCOUNT_SCHEMA_VERSION:
        raise AccountError(
            "Schema accounts.yaml tidak didukung oleh account.py versi ini.\n"
            f"  Ditemukan : {schema_version or '[kosong]'}\n"
            f"  Didukung  : {ACCOUNT_SCHEMA_VERSION}\n"
            "Gunakan account.py versi yang sesuai atau lakukan migrasi "
            "account terlebih dahulu."
        )

    accounts = data.get("accounts", [])

    if not isinstance(accounts, list):
        raise AccountError(
            "Field 'accounts' harus berupa list."
        )

    data["accounts"] = accounts
    data["notes"] = str(data.get("notes", ""))

    return data


def _save(
    context: ProjectContext,
    data: dict[str, Any],
) -> Path:
    """Save accounts.yaml."""
    directory = account_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = ACCOUNT_SCHEMA_VERSION
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = account_file(context)

    try:
        with path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            yaml.safe_dump(
                data,
                handle,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except OSError as exc:
        raise AccountError(
            f"Gagal menulis: {path}\n{exc}"
        ) from exc

    return path


def initialize(
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    """Create accounts.yaml if it does not exist."""
    if context is None:
        context = require_active_project()

    path = account_file(context)

    if path.is_file():
        return path

    return _save(
        context,
        _empty_document(context),
    )


def _validate_role(role: str) -> str:
    """Validate and normalize account role."""
    value = role.strip().lower()

    if value not in VALID_ROLES:
        allowed = ", ".join(sorted(VALID_ROLES))
        raise AccountError(
            f"Role account tidak valid: {role!r}. "
            f"Gunakan: {allowed}"
        )

    return value


def _validate_status(status: str) -> str:
    """Validate and normalize account status."""
    value = status.strip().lower()

    if value not in VALID_STATUSES:
        allowed = ", ".join(sorted(VALID_STATUSES))
        raise AccountError(
            f"Status account tidak valid: {status!r}. "
            f"Gunakan: {allowed}"
        )

    return value


def _next_account_id(
    accounts: list[dict[str, Any]],
) -> str:
    """Generate the next sequential account ID."""
    highest = 0

    for account in accounts:
        if not isinstance(account, dict):
            continue

        value = str(
            account.get("account_id", "")
        ).upper()

        if value.startswith("TA-"):
            number = value[3:]

            if number.isdigit():
                highest = max(
                    highest,
                    int(number),
                )

    return f"TA-{highest + 1:03d}"


def _validate_encrypted_credential(
    value: str,
    field_name: str,
) -> str:
    """
    Validate an encrypted credential token without exposing plaintext.

    The ciphertext must be decryptable by the active project's encryption
    key and the resulting plaintext must not be empty.
    """
    token = str(value or "").strip()

    if not token:
        raise AccountError(
            f"Credential terenkripsi '{field_name}' wajib diisi."
        )

    try:
        plaintext = decrypt(token)
    except SecretsError as exc:
        raise AccountError(
            f"Credential terenkripsi '{field_name}' tidak valid atau "
            "tidak sesuai encryption key project."
        ) from exc

    if not plaintext:
        raise AccountError(
            f"Credential terenkripsi '{field_name}' menghasilkan nilai kosong."
        )

    return token


def _credentials(account: dict[str, Any]) -> dict[str, str]:
    """Return encrypted credential fields from an account record."""
    raw = account.get("credentials")

    if not isinstance(raw, dict):
        raise AccountError(
            "Field 'credentials' pada test account tidak valid."
        )

    username = raw.get("username")
    password = raw.get("password")

    if not isinstance(username, str) or not username.strip():
        raise AccountError(
            "Credential username terenkripsi tidak tersedia."
        )

    if not isinstance(password, str) or not password.strip():
        raise AccountError(
            "Credential password terenkripsi tidak tersedia."
        )

    return {
        "username": username.strip(),
        "password": password.strip(),
    }


def get_account_credentials(
    account_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, str]:
    """
    Decrypt and return one account's username/password in memory.

    This is the only account.py API intended for a caller that actually needs
    the plaintext credentials. The values are never written to accounts.yaml
    and are never included in activity records or normal account output.
    """
    if context is None:
        context = require_active_project()

    account = get_account(account_id, context=context)
    if account is None:
        raise AccountError(
            f"Test account tidak ditemukan: {account_id}"
        )

    encrypted = _credentials(account)

    try:
        username = decrypt(encrypted["username"])
        password = decrypt(encrypted["password"])
    except SecretsError as exc:
        raise AccountError(
            f"Credential test account {account_id.upper()} "
            "tidak dapat didecrypt dengan project encryption key."
        ) from exc

    if not username:
        raise AccountError(
            f"Username test account {account_id.upper()} hasil decrypt kosong."
        )

    if not password:
        raise AccountError(
            f"Password test account {account_id.upper()} hasil decrypt kosong."
        )

    return {
        "username": username,
        "password": password,
    }


def _username_for_comparison(
    account: dict[str, Any],
) -> Optional[str]:
    """Decrypt an account username for duplicate detection only."""
    raw = account.get("credentials")

    if not isinstance(raw, dict):
        return None

    token = raw.get("username")

    if not isinstance(token, str) or not token.strip():
        return None

    try:
        return decrypt(token)
    except SecretsError:
        return None


def add_account(
    *,
    role: str,
    name: str,
    username_encrypted: str,
    password_encrypted: str,
    purpose: str = "",
    access: str = "",
    status: str = "planned",
    notes: str = "",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """
    Add one test account record using encrypted username/password.

    The caller must provide Fernet ciphertext generated with the active
    project's encryption key. Plaintext credentials are not accepted.
    """
    if context is None:
        context = require_active_project()

    # Fail early with a clear error when the project key is unavailable.
    try:
        load_key()
    except SecretsError as exc:
        raise AccountError(
            "Encryption key project belum tersedia atau tidak valid."
        ) from exc

    role = _validate_role(role)
    status = _validate_status(status)

    name = name.strip()
    purpose = purpose.strip()
    access = access.strip()
    notes = notes.strip()

    if not name:
        raise AccountError(
            "Nama pemegang account wajib diisi."
        )

    encrypted_username = _validate_encrypted_credential(
        username_encrypted,
        "username",
    )
    encrypted_password = _validate_encrypted_credential(
        password_encrypted,
        "password",
    )

    try:
        decrypted_username = decrypt(encrypted_username)
    except SecretsError as exc:
        raise AccountError(
            "Username terenkripsi tidak dapat didecrypt."
        ) from exc

    data = _load(context)
    accounts = data["accounts"]

    for existing in accounts:
        if not isinstance(existing, dict):
            continue

        existing_username = _username_for_comparison(existing)

        if (
            existing_username is not None
            and existing_username.strip().lower()
            == decrypted_username.strip().lower()
        ):
            raise AccountError(
                "Username account sudah terdaftar."
            )

    account = {
        "account_id": _next_account_id(accounts),
        "role": role,
        "name": name,
        "credentials": {
            "username": encrypted_username,
            "password": encrypted_password,
        },
        "purpose": purpose,
        "access": access,
        "status": status,
        "created_at": _now(),
        "notes": notes,
    }

    accounts.append(account)

    _save(
        context,
        data,
    )

    record_activity(
        phase="01-preparation",
        item="01-005",
        action=(
            f"Test account recorded: "
            f"{account['account_id']}"
        ),
        status="completed",
        context=context,
    )

    return account

def list_accounts(
    *,
    context: Optional[ProjectContext] = None,
) -> list[dict[str, Any]]:
    """Return all test account records."""
    if context is None:
        context = require_active_project()

    return list(
        _load(context)["accounts"]
    )


def get_account(
    account_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> Optional[dict[str, Any]]:
    """Find one account by account ID."""
    if context is None:
        context = require_active_project()

    wanted = account_id.strip().upper()

    for account in _load(context)["accounts"]:
        if not isinstance(account, dict):
            continue

        if (
            str(account.get("account_id", "")).upper()
            == wanted
        ):
            return account

    return None


def remove_account(
    account_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Remove one test account record."""
    if context is None:
        context = require_active_project()

    wanted = account_id.strip().upper()

    data = _load(context)
    accounts = data["accounts"]

    for index, account in enumerate(accounts):
        if not isinstance(account, dict):
            continue

        current_id = str(
            account.get("account_id", "")
        ).upper()

        if current_id == wanted:
            removed = accounts.pop(index)

            _save(
                context,
                data,
            )

            record_activity(
                phase="01-preparation",
                item="01-005",
                action=(
                    f"Test account removed: "
                    f"{wanted}"
                ),
                status="completed",
                context=context,
            )

            return True

    return False


def verify_account(
    account_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """
    Mark an account as active after manual verification.

    This command does not perform authentication against the target.
    """
    if context is None:
        context = require_active_project()

    wanted = account_id.strip().upper()

    data = _load(context)
    accounts = data["accounts"]

    for account in accounts:
        if not isinstance(account, dict):
            continue

        current_id = str(
            account.get("account_id", "")
        ).upper()

        if current_id != wanted:
            continue

        account["status"] = "active"
        account["verified_at"] = _now()

        _save(
            context,
            data,
        )

        record_activity(
            phase="01-preparation",
            item="01-005",
            action=(
                f"Test account verified: "
                f"{wanted}"
            ),
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
    """Set general account notes."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    data["notes"] = notes.strip()

    _save(
        context,
        data,
    )

    record_activity(
        phase="01-preparation",
        item="01-005",
        action="Test account notes updated",
        status="completed",
        context=context,
    )


def print_accounts(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print test account metadata without exposing credentials."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    accounts = data["accounts"]

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Test Accounts")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"File       : {account_file(context)}")
    print()

    if not accounts:
        print("[none]")
    else:
        for account in accounts:
            print(
                f"[{account.get('account_id', '-')}] "
                f"Credential: [encrypted]"
            )

            print(
                f"  Name    : "
                f"{account.get('name', '')}"
            )

            print(
                f"  Role    : "
                f"{account.get('role', '')}"
            )

            print(
                f"  Purpose : "
                f"{account.get('purpose', '')}"
            )

            print(
                f"  Access  : "
                f"{account.get('access', '')}"
            )

            print(
                f"  Status  : "
                f"{account.get('status', '')}"
            )

            if account.get("created_at"):
                print(
                    f"  Created : "
                    f"{account.get('created_at')}"
                )

            if account.get("verified_at"):
                print(
                    f"  Verified: "
                    f"{account.get('verified_at')}"
                )

            if account.get("notes"):
                print(
                    f"  Notes   : "
                    f"{account.get('notes')}"
                )

            print()

    print("NOTES")
    print("-" * 72)
    print(
        data.get("notes", "")
        or "[none]"
    )

def print_account(
    account_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Print one complete test account, including decrypted credentials."""
    if context is None:
        context = require_active_project()

    account = get_account(
        account_id,
        context=context,
    )

    if account is None:
        print(
            f"[INFO] Test account tidak ditemukan: "
            f"{account_id}"
        )
        return False

    credentials = get_account_credentials(
        account_id,
        context=context,
    )

    print("=" * 72)
    print(" Test Account")
    print("=" * 72)
    print(f"account_id    : {account.get('account_id', '')}")
    print(f"name          : {account.get('name', '')}")
    print(f"role          : {account.get('role', '')}")
    print(f"username      : {credentials['username']}")
    print(f"password      : {credentials['password']}")
    print(f"purpose       : {account.get('purpose', '')}")
    print(f"access        : {account.get('access', '')}")
    print(f"status        : {account.get('status', '')}")

    if account.get("created_at"):
        print(f"created_at    : {account.get('created_at')}")

    if account.get("verified_at"):
        print(f"verified_at   : {account.get('verified_at')}")

    if account.get("notes"):
        print(f"notes         : {account.get('notes')}")

    print()
    print("WARNING       : username dan password ditampilkan dalam plaintext.")

    return True

def print_status(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print test account preparation status."""
    if context is None:
        context = require_active_project()

    data = _load(context)
    accounts = data["accounts"]

    active = 0
    planned = 0
    disabled = 0
    revoked = 0

    for account in accounts:
        if not isinstance(account, dict):
            continue

        status = str(
            account.get("status", "")
        ).lower()

        if status == "active":
            active += 1
        elif status == "planned":
            planned += 1
        elif status == "disabled":
            disabled += 1
        elif status == "revoked":
            revoked += 1

    print("=" * 72)
    print(" Test Account Status")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()
    print(f"Total      : {len(accounts)}")
    print(f"Active     : {active}")
    print(f"Planned    : {planned}")
    print(f"Disabled   : {disabled}")
    print(f"Revoked    : {revoked}")
    print()

    if active > 0:
        print("[PASS] Minimal test account aktif tersedia.")
    elif planned > 0:
        print(
            "[WARN] Test account tersedia "
            "tetapi belum diverifikasi aktif."
        )
    else:
        print(
            "[WARN] Belum ada test account."
        )


def _prompt(
    label: str,
    required: bool = False,
) -> str:
    """Read one interactive value."""
    while True:
        value = input(
            f"{label}: "
        ).strip()

        if value or not required:
            return value

        print(
            "[ERROR] Nilai wajib diisi."
        )


def interactive_add(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Interactively add one test account using plaintext input in memory.

    The username is read as normal text and the password is read without
    echo. Both values are encrypted immediately with the active project's
    Fernet key before they are passed to add_account(). Plaintext values are
    never written to accounts.yaml or activity.log.
    """
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" Add Test Account")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()
    print(
        "CATATAN: Username dan password akan dienkripsi otomatis "
        "dengan project encryption key sebelum disimpan."
    )
    print()

    role = _prompt(
        "Role (tester/reviewer/admin/user/operator/other)",
        required=True,
    )

    name = _prompt(
        "Name",
        required=True,
    )

    username_plaintext = _prompt(
        "Username",
        required=True,
    )

    while True:
        password_plaintext = getpass(
            "Password: "
        )

        if password_plaintext:
            break

        print("[ERROR] Nilai wajib diisi.")

    try:
        username_encrypted = encrypt(username_plaintext)
        password_encrypted = encrypt(password_plaintext)
    except SecretsError as exc:
        raise AccountError(
            "Gagal mengenkripsi credential dengan project encryption key."
        ) from exc
    finally:
        # Remove local references as soon as possible. Python strings are
        # immutable, so this is best-effort cleanup only.
        username_plaintext = ""
        password_plaintext = ""

    purpose = _prompt(
        "Purpose",
    )

    access = _prompt(
        "Access / privilege",
    )

    status = _prompt(
        "Status (planned/active/disabled/revoked)",
    )

    if not status:
        status = "planned"

    notes = _prompt(
        "Notes",
    )

    account = add_account(
        role=role,
        name=name,
        username_encrypted=username_encrypted,
        password_encrypted=password_encrypted,
        purpose=purpose,
        access=access,
        status=status,
        notes=notes,
        context=context,
    )

    print()
    print(
        f"[PASS] Test account "
        f"{account['account_id']} berhasil disimpan."
    )
    print(
        f"File: {account_file(context)}"
    )

    return account


def interactive_add_encrypted(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Interactively add an account from pre-encrypted Fernet values."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" Add Test Account (Encrypted)")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print()
    print(
        "CATATAN: Username dan password harus berupa ciphertext Fernet "
        "yang dibuat menggunakan encryption key project aktif."
    )
    print()

    role = _prompt(
        "Role (tester/reviewer/admin/user/operator/other)",
        required=True,
    )

    name = _prompt(
        "Name",
        required=True,
    )

    username_encrypted = _prompt(
        "Username (encrypted)",
        required=True,
    )

    while True:
        password_encrypted = getpass(
            "Password (encrypted): "
        ).strip()

        if password_encrypted:
            break

        print("[ERROR] Nilai wajib diisi.")

    purpose = _prompt("Purpose")
    access = _prompt("Access / privilege")
    status = _prompt("Status (planned/active/disabled/revoked)")

    if not status:
        status = "planned"

    notes = _prompt("Notes")

    account = add_account(
        role=role,
        name=name,
        username_encrypted=username_encrypted,
        password_encrypted=password_encrypted,
        purpose=purpose,
        access=access,
        status=status,
        notes=notes,
        context=context,
    )

    print()
    print(
        f"[PASS] Test account "
        f"{account['account_id']} berhasil disimpan."
    )
    print(
        f"File: {account_file(context)}"
    )

    return account

def print_credentials(
    account_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """
    Decrypt and print credentials for an explicit credential-retrieval command.

    This command is intentionally explicit because it exposes plaintext
    credentials to the terminal.
    """
    if context is None:
        context = require_active_project()

    credentials = get_account_credentials(
        account_id,
        context=context,
    )

    print("=" * 72)
    print(" Test Account Credentials")
    print("=" * 72)
    print(f"Account ID : {account_id.upper()}")
    print("WARNING: plaintext credentials akan ditampilkan ke terminal.")
    print()
    print(f"Username   : {credentials['username']}")
    print(f"Password   : {credentials['password']}")
    return True



def print_help() -> None:
    """Print CLI help."""
    print(
        "Preparation Test Account\n"
        "\n"
        "Usage:\n"
        "  python scripts/preparation/account.py init\n"
        "  python scripts/preparation/account.py add\n"
        "  python scripts/preparation/account.py add-encrypted\n"
        "  python scripts/preparation/account.py list\n"
        "  python scripts/preparation/account.py show TA-001\n"
        "  python scripts/preparation/account.py verify TA-001\n"
        "  python scripts/preparation/account.py status\n"
        "  python scripts/preparation/account.py remove TA-001\n"
        "  python scripts/preparation/account.py credentials TA-001\n"
        "  python scripts/preparation/account.py version\n"
        "\n"
        "The active project is resolved automatically through "
        "context.py.\n"
        "No --project argument is required.\n"
        "\n"
        "CREDENTIAL SECURITY:\n"
        "  Command 'add' menerima username/password biasa dan mengenkripsinya\n"
        "  otomatis menggunakan encryption key project aktif.\n"
        "  Command 'add-encrypted' menerima ciphertext Fernet secara langsung.\n"
        "  Plaintext credential tidak disimpan di accounts.yaml.\n"
        "  Command 'show' dan 'credentials' secara eksplisit menampilkan plaintext.\n"
    )


def main(
    argv: Optional[list[str]] = None,
) -> int:
    """Command-line entry point."""
    args = list(
        sys.argv[1:]
        if argv is None
        else argv
    )

    if not args or args[0] in (
        "-h",
        "--help",
        "help",
    ):
        print_help()
        return 0

    command = args[0].lower()

    try:
        context = require_active_project()

        if command == "init":
            path = initialize(
                context=context
            )

            print(
                f"[PASS] Account structure siap: "
                f"{path}"
            )

            return 0

        if command == "add":
            interactive_add(
                context=context
            )

            return 0

        if command == "add-encrypted":
            interactive_add_encrypted(
                context=context
            )

            return 0

        if command == "list":
            print_accounts(
                context=context
            )

            return 0

        if command == "show":
            if len(args) != 2:
                print(
                    "[ERROR] Gunakan: "
                    "account.py show TA-001"
                )
                return 2

            found = print_account(
                args[1],
                context=context,
            )

            return 0 if found else 1

        if command == "verify":
            if len(args) != 2:
                print(
                    "[ERROR] Gunakan: "
                    "account.py verify TA-001"
                )
                return 2

            verified = verify_account(
                args[1],
                context=context,
            )

            if not verified:
                print(
                    f"[INFO] Test account tidak ditemukan: "
                    f"{args[1]}"
                )
                return 1

            print(
                f"[PASS] Test account "
                f"{args[1].upper()} telah diverifikasi aktif."
            )

            return 0

        if command == "credentials":
            if len(args) != 2:
                print(
                    "[ERROR] Gunakan: "
                    "account.py credentials TA-001"
                )
                return 2

            found = print_credentials(
                args[1],
                context=context,
            )

            return 0 if found else 1

        if command == "status":
            print_status(
                context=context
            )

            return 0

        if command == "remove":
            if len(args) != 2:
                print(
                    "[ERROR] Gunakan: "
                    "account.py remove TA-001"
                )
                return 2

            removed = remove_account(
                args[1],
                context=context,
            )

            if not removed:
                print(
                    f"[INFO] Test account tidak ditemukan: "
                    f"{args[1]}"
                )
                return 1

            print(
                f"[PASS] Test account "
                f"{args[1].upper()} telah dihapus."
            )

            return 0

        if command == "version":
            print(
                "BrebesKab-CSIRT-Tools "
                f"account.py v{SCRIPT_VERSION}"
            )

            return 0

        print(
            f"[ERROR] Command tidak dikenal: "
            f"{args[0]}"
        )

        print()
        print_help()

        return 2

    except (
        ContextError,
        AccountError,
        ActivityError,
        SecretsError,
    ) as exc:
        print(
            f"[ERROR] {exc}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )