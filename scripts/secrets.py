#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Project Secret Management

Secure local secret handling for pentest projects.

Responsibilities:
    - Resolve the runtime secret directory for a project.
    - Generate and validate the project encryption key.
    - Load the project encryption key.
    - Encrypt/decrypt small secrets such as test-account passwords.
    - Provide safe diagnostic commands without printing secret material.

Storage convention:
    .runtime/
    └── secrets/
        └── <PROJECT-ID>/
            └── encryption.key

Security rules:
    - Encryption keys never belong in the project repository.
    - The key is never printed by this module.
    - encrypt()/decrypt() operate in memory.
    - A missing key is an error; encrypt()/decrypt() never auto-create one.
    - Existing keys are never overwritten unless overwrite=True is explicitly
      requested through generate_key().

The project lifecycle (create/init-secrets) is owned by project.py.
This module provides the cryptographic/runtime secret abstraction used by
other tools such as test_account.py.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Optional, Union

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("[ERROR] cryptography belum terinstall.")
    print("        Jalankan: python -m pip install cryptography")
    raise SystemExit(1)

try:
    from .context import ProjectContext, require_active_project, runtime_root
except ImportError:
    from context import ProjectContext, require_active_project, runtime_root


SCRIPT_VERSION = "1.0.0"
PROJECT_ID_PATTERN = re.compile(r"^PENTEST-[0-9]{4}-[0-9]{3,}$")
SECRET_ROOT_NAME = "secrets"
KEY_FILENAME = "encryption.key"

BytesLike = Union[bytes, bytearray]


class SecretsError(RuntimeError):
    """Raised when project secret handling fails."""


# ---------------------------------------------------------------------------
# Project / path resolution
# ---------------------------------------------------------------------------


def repository_root() -> Path:
    """Return the repository root."""
    return Path(__file__).resolve().parent.parent


def secrets_root() -> Path:
    """Return the repository-wide runtime secrets directory."""
    return runtime_root() / SECRET_ROOT_NAME


def validate_project_id(project_id: str) -> str:
    """Validate and normalize a pentest project ID."""
    normalized = project_id.strip()

    if not PROJECT_ID_PATTERN.fullmatch(normalized):
        raise SecretsError(
            f"Project ID tidak valid: {project_id!r}. "
            "Format: PENTEST-YYYY-NNN."
        )

    return normalized


def get_project_context(
    project_id: Optional[str] = None,
) -> Optional[ProjectContext]:
    """
    Return the active ProjectContext when no explicit project_id is supplied.

    For an explicit project ID, no active-project switch is performed and
    None is returned because the caller only needs the validated ID/path.
    """
    if project_id is None:
        return require_active_project()
    return None


def get_secret_directory(project_id: Optional[str] = None) -> Path:
    """
    Return the runtime secrets directory for a project.

    When project_id is omitted, the active project from context.py is used.
    """
    if project_id is None:
        context = require_active_project()
        project_id = context.project_id
    else:
        project_id = validate_project_id(project_id)

    return secrets_root() / project_id


def get_encryption_key_path(project_id: Optional[str] = None) -> Path:
    """Return the encryption key path for a project."""
    return get_secret_directory(project_id) / KEY_FILENAME


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


def _validate_key_bytes(key: bytes) -> bytes:
    """Validate that bytes represent a valid Fernet key."""
    if not isinstance(key, bytes):
        raise SecretsError("Encryption key harus berupa bytes.")

    stripped = key.strip()

    if not stripped:
        raise SecretsError("Encryption key kosong.")

    try:
        Fernet(stripped)
    except (ValueError, TypeError) as exc:
        raise SecretsError("Encryption key tidak valid.") from exc

    return stripped


def generate_key(
    project_id: Optional[str] = None,
    *,
    overwrite: bool = False,
) -> Path:
    """
    Generate a Fernet encryption key for a project.

    The generated key is written as ASCII text with a trailing newline to
    remain consistent with the current project.py key file convention.

    By default an existing key is never replaced.
    """
    key_path = get_encryption_key_path(project_id)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        if not key_path.is_file():
            raise SecretsError(f"Key path bukan file: {key_path}")

        existing_key = load_key(project_id)
        if overwrite:
            # Explicit overwrite is intentionally allowed only here.
            # project.py should normally use the non-overwriting path.
            del existing_key
        else:
            return key_path

    key = Fernet.generate_key()
    key_path.write_text(key.decode("ascii") + "\n", encoding="ascii", newline="\n")
    _restrict_file_permissions(key_path)

    # Verify the file after writing, but never print the key.
    load_key(project_id)
    return key_path


def load_key(project_id: Optional[str] = None) -> bytes:
    """Load and validate a project's encryption key."""
    key_path = get_encryption_key_path(project_id)

    if not key_path.is_file():
        raise SecretsError(
            "Encryption key tidak ditemukan:\n"
            f"  {key_path}\n"
            "Gunakan project.py init-secrets untuk menginisialisasi key."
        )

    try:
        raw = key_path.read_bytes()
    except OSError as exc:
        raise SecretsError(
            f"Gagal membaca encryption key: {key_path}\n{exc}"
        ) from exc

    return _validate_key_bytes(raw)


def verify_key(project_id: Optional[str] = None) -> Path:
    """Validate the existing encryption key without exposing it."""
    key_path = get_encryption_key_path(project_id)
    load_key(project_id)
    return key_path


# ---------------------------------------------------------------------------
# File permission handling
# ---------------------------------------------------------------------------


def _restrict_file_permissions(path: Path) -> None:
    """
    Restrict key-file permissions where the platform supports POSIX mode bits.

    Windows ACL handling is intentionally not attempted here because the
    repository currently targets Windows as a primary development platform.
    """
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            # Do not hide a successfully written key because chmod is not
            # supported by the underlying filesystem.
            pass


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------


def encrypt_bytes(
    plaintext: BytesLike,
    *,
    project_id: Optional[str] = None,
) -> bytes:
    """
    Encrypt bytes using the project's encryption key.

    The key is loaded but never created automatically.
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise SecretsError("encrypt_bytes() membutuhkan bytes/bytearray.")

    key = load_key(project_id)

    try:
        return Fernet(key).encrypt(bytes(plaintext))
    except Exception as exc:
        raise SecretsError(f"Gagal mengenkripsi secret: {exc}") from exc


def decrypt_bytes(
    ciphertext: BytesLike,
    *,
    project_id: Optional[str] = None,
) -> bytes:
    """
    Decrypt bytes using the project's encryption key.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise SecretsError("decrypt_bytes() membutuhkan bytes/bytearray.")

    key = load_key(project_id)

    try:
        return Fernet(key).decrypt(bytes(ciphertext))
    except InvalidToken as exc:
        raise SecretsError(
            "Ciphertext tidak dapat didecrypt dengan project encryption key. "
            "Pastikan project/key sesuai."
        ) from exc
    except Exception as exc:
        raise SecretsError(f"Gagal mendekripsi secret: {exc}") from exc


def encrypt(
    plaintext: str,
    *,
    project_id: Optional[str] = None,
) -> str:
    """
    Encrypt a UTF-8 string and return a Fernet token as text.

    This is the main API intended for test_account.py.
    """
    if not isinstance(plaintext, str):
        raise SecretsError("encrypt() membutuhkan plaintext bertipe str.")

    return encrypt_bytes(
        plaintext.encode("utf-8"),
        project_id=project_id,
    ).decode("ascii")


def decrypt(
    ciphertext: str,
    *,
    project_id: Optional[str] = None,
) -> str:
    """
    Decrypt a Fernet token and return the original UTF-8 string.

    The plaintext exists only in memory and is not written by this module.
    """
    if not isinstance(ciphertext, str):
        raise SecretsError("decrypt() membutuhkan ciphertext bertipe str.")

    try:
        plaintext = decrypt_bytes(
            ciphertext.encode("ascii"),
            project_id=project_id,
        )
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretsError("Plaintext hasil decrypt bukan UTF-8 yang valid.") from exc


# ---------------------------------------------------------------------------
# Diagnostic CLI
# ---------------------------------------------------------------------------


def _resolve_display_project_id(project_id: Optional[str]) -> str:
    """Resolve a project ID for CLI messages without exposing secrets."""
    if project_id:
        return validate_project_id(project_id)
    return require_active_project().project_id


def command_path(project_id: Optional[str]) -> int:
    try:
        resolved = _resolve_display_project_id(project_id)
        print(f"Project ID : {resolved}")
        print(f"Secrets    : {get_secret_directory(resolved)}")
        print(f"Key path   : {get_encryption_key_path(resolved)}")
        return 0
    except SecretsError as exc:
        print(f"[ERROR] {exc}")
        return 1


def command_verify(project_id: Optional[str]) -> int:
    try:
        resolved = _resolve_display_project_id(project_id)
        key_path = verify_key(resolved)
        print()
        print("=" * 72)
        print(" BrebesKab-CSIRT-Tools - Secret Verification")
        print("=" * 72)
        print(f"Project ID : {resolved}")
        print(f"Key path   : {key_path}")
        print("[PASS] Encryption key tersedia dan valid.")
        print("[INFO] Key tidak ditampilkan.")
        return 0
    except SecretsError as exc:
        print(f"[ERROR] {exc}")
        return 1


def command_init(project_id: Optional[str]) -> int:
    try:
        resolved = _resolve_display_project_id(project_id)
        key_path = get_encryption_key_path(resolved)

        if key_path.exists():
            verify_key(resolved)
            print()
            print("=" * 72)
            print(" BrebesKab-CSIRT-Tools - Secret Initialization")
            print("=" * 72)
            print(f"Project ID : {resolved}")
            print(f"Key path   : {key_path}")
            print("[PASS] Encryption key sudah tersedia dan valid.")
            print("[INFO] Key tidak ditampilkan.")
            return 0

        generated_path = generate_key(resolved)
        print()
        print("=" * 72)
        print(" BrebesKab-CSIRT-Tools - Secret Initialization")
        print("=" * 72)
        print(f"Project ID : {resolved}")
        print(f"Key path   : {generated_path}")
        print("[PASS] Encryption key berhasil dibuat.")
        print("[INFO] Key tidak ditampilkan.")
        return 0
    except SecretsError as exc:
        print(f"[ERROR] {exc}")
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secrets.py",
        description="BrebesKab-CSIRT-Tools Project Secret Management",
    )

    parser.add_argument(
        "command",
        choices=("path", "init", "verify", "version"),
        help="Secret management command.",
    )
    parser.add_argument(
        "project_id",
        nargs="?",
        help="Project ID. Omit to use the active project.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "path":
            if args.project_id is None:
                return command_path(None)
            return command_path(args.project_id)

        if args.command == "init":
            return command_init(args.project_id)

        if args.command == "verify":
            return command_verify(args.project_id)

        if args.command == "version":
            print(f"BrebesKab-CSIRT-Tools secrets.py v{SCRIPT_VERSION}")
            return 0

        parser.error(f"Command tidak dikenal: {args.command}")
        return 2
    except KeyboardInterrupt:
        print("[ERROR] Operasi dibatalkan oleh pengguna.")
        return 130


__all__ = [
    "SCRIPT_VERSION",
    "SecretsError",
    "secrets_root",
    "get_secret_directory",
    "get_encryption_key_path",
    "generate_key",
    "load_key",
    "verify_key",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt",
    "decrypt",
]


if __name__ == "__main__":
    raise SystemExit(main())
