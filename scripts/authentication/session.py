#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Authentication Session Management

Checklist: 5-002 Session Management
Schema: 1.0

Purpose:
    Securely store and assess an authorized authenticated session.

Security model:
    - Session secrets are encrypted at rest with the same project Fernet
      encryption API used by preparation/account.py.
    - The project encryption key is never created by this script.
    - Plaintext session values are never written to YAML, JSON evidence,
      activity logs, or normal stdout.
    - Explicit --debug-login is an interactive debugging mode only. It may
      display cookie/session values in the console for the authorized test
      session, but never persists those debug values to artifacts/evidence.
    - Only explicitly authorized test accounts/sessions are supported.
    - No session brute force, hijacking of third-party sessions, CAPTCHA/
      Turnstile bypass, or mass session testing is performed.

Typical workflow:
    python scripts/authentication/session.py version
    python scripts/authentication/session.py init
    python scripts/authentication/session.py add --account-id TA-002
    python scripts/authentication/session.py add --account-id TA-002 --debug-login
    python scripts/authentication/session.py list
    python scripts/authentication/session.py show S-001
    python scripts/authentication/session.py analyze --session-id S-001 --url /dashboard
    python scripts/authentication/session.py verify

The "add" command obtains an authorized authenticated session automatically
when possible. If the login page requires human interaction, a visible
Playwright browser is used and the human completes the challenge/login.
Turnstile/CAPTCHA is never bypassed. If no valid username/password is
available, the artifact remains valid with an explicit not-tested status.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from getpass import getpass
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urljoin, urlparse

try:
    import requests
except ImportError:
    print("[ERROR] requests belum terinstall.")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML belum terinstall.")
    sys.exit(1)


SCRIPT_VERSION = "1.1.8"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "5-002"
CHECKLIST_NAME = "Session Management"
PHASE_NAME = "05 Authentication"
PHASE_DIR = "05-authentication"
SESSION_DIR = "session"
SESSION_FILE = "session.yaml"
EVIDENCE_DIR = "evidence"
EVIDENCE_FILE = "session-probes.json"

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_BODY_BYTES = 262144
BODY_SAMPLE_CHARS = 4000

SESSION_ID_RE = re.compile(r"^S-[0-9]{3,}$", re.IGNORECASE)

# The same API names used by preparation/account.py and preparation/secrets.py.
try:
    SCRIPTS_DIR = Path(__file__).resolve().parents[1]
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))

    # Account credentials are read directly from the canonical
    # 01-preparation/account/accounts.yaml artifact.  session.py deliberately
    # does not depend on preparation.account.py for credential retrieval.
    from context import (
        ProjectContext,
        get_active_project_path,
        load_active_context,
    )
    from secrets import (
        SecretsError,
        decrypt,
        encrypt,
        verify_key,
    )
except ImportError as exc:
    print(f"[ERROR] Modul preparation tidak dapat dimuat: {exc}")
    sys.exit(1)


class SessionError(RuntimeError):
    """Raised for session management errors."""


# ---------------------------------------------------------------------------
# Context and paths
# ---------------------------------------------------------------------------

def active_context() -> ProjectContext:
    try:
        return load_active_context()
    except Exception as exc:
        raise SessionError(
            f"Active project context tidak valid: {exc}"
        ) from exc


def project_root() -> Path:
    try:
        return Path(get_active_project_path())
    except Exception as exc:
        raise SessionError(
            f"Gagal menentukan active project path: {exc}"
        ) from exc


def session_dir() -> Path:
    return project_root() / PHASE_DIR / SESSION_DIR


def session_file() -> Path:
    return session_dir() / SESSION_FILE


def evidence_dir() -> Path:
    return session_dir() / EVIDENCE_DIR


def evidence_file() -> Path:
    return evidence_dir() / EVIDENCE_FILE


# ---------------------------------------------------------------------------
# Time / serialization helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump(
                data,
                handle,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                explicit_start=False,
            )
    except OSError as exc:
        raise SessionError(f"Gagal menulis YAML: {path}\n{exc}") from exc


def load_yaml(path: Path, label: str = "YAML") -> dict[str, Any]:
    if not path.exists():
        raise SessionError(f"{label} tidak ditemukan: {path}")

    try:
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raise SessionError(
                f"{label} menggunakan UTF-8 BOM, sedangkan canonical artifact "
                "wajib UTF-8 tanpa BOM."
            )
        text = raw.decode("utf-8")
        data = yaml.safe_load(text) or {}
    except UnicodeDecodeError as exc:
        raise SessionError(f"{label} bukan UTF-8 valid: {path}") from exc
    except yaml.YAMLError as exc:
        raise SessionError(f"YAML {label} tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise SessionError(f"Gagal membaca {label}: {path}\n{exc}") from exc

    if not isinstance(data, dict):
        raise SessionError(f"Root {label} harus berupa mapping/object.")

    return data


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                data,
                handle,
                ensure_ascii=False,
                indent=2,
            )
            handle.write("\n")
    except OSError as exc:
        raise SessionError(f"Gagal menulis evidence JSON: {path}") from exc


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact_secret(value: Any) -> str:
    if value is None:
        return "[REDACTED]"
    return "[REDACTED]"


def mask_identifier(value: str) -> str:
    value = str(value or "")
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * max(1, len(value) - 4) + value[-2:]


# ---------------------------------------------------------------------------
# Canonical artifact
# ---------------------------------------------------------------------------

def canonical_empty_artifact(context: ProjectContext) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": context.project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "session.py",
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "focus": (
                "Authenticated session lifecycle, cookie security attributes, "
                "session reuse, rotation, and invalidation assessment."
            ),
            "status": "initialized",
        },
        "target": {
            "application": context.project_id,
            "hostname": "",
            "url": "",
            "environment": "",
            "assessment_type": "",
            "scope_id": "",
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": [80, 443],
        },
        "methodology": {
            "description": (
                "Controlled session assessment using explicitly authorized "
                "test-account sessions."
            ),
            "authorized_test_account_only": True,
            "session_secret_encryption": "project Fernet key via preparation.secrets",
            "session_value_plaintext_in_artifact": False,
            "session_bruteforce": False,
            "session_hijacking_third_party": False,
            "captcha_turnstile_bypass": False,
            "mass_session_testing": False,
            "redirect_following": False,
            "authentication_outcome_engine": True,
            "authentication_outcomes": [
                "SUCCESS",
                "FAILED",
                "UNCONFIRMED",
            ],
            "automatic_finding": False,
            "debug_login_persist_session": False,
        },
        "baseline": {
            "account_source": "01-preparation/account/accounts.yaml",
            "scope_source": "01-preparation/scope/scope.yaml",
            "encryption_key_source": (
                ".runtime/secrets/<PROJECT-ID>/encryption.key"
            ),
        },
        "toolchain": {
            "mandatory": [
                "Python",
                "requests",
                "PyYAML",
                "BeautifulSoup",
                "accounts.yaml",
                "preparation.secrets",
                "preparation.context",
            ],
            "optional": [
                "Playwright",
                "curl.exe",
            ],
            "not_required": [
                "Nmap",
                "ffuf",
                "Gobuster",
                "Nuclei",
                "Hydra",
                "ZAP",
            ],
        },
        "probe": {
            "timeout_seconds": DEFAULT_TIMEOUT,
            "allow_redirects": False,
            "max_body_bytes": DEFAULT_MAX_BODY_BYTES,
            "body_sample_chars": BODY_SAMPLE_CHARS,
        },
        "source_status": {
            "scope": "not-tested",
            "account": "not-tested",
            "encryption_key": "not-tested",
            "authentication": "not-tested",
        },
        "results": {
            "sessions_selected": 0,
            "sessions": [],
            "cookie_security": [],
            "rotation": [],
            "reuse": [],
            "invalidation": [],
        },
        "summary": {
            "sessions_selected": 0,
            "cookie_attributes_observed": 0,
            "rotation_tested": 0,
            "reuse_tested": 0,
            "invalidation_tested": 0,
            "authenticated_access_observed": 0,
            "authentication_attempted": False,
            "authentication_mode": "not-tested",
            "human_interaction_required": False,
            "valid_credentials_available": None,
            "requires_review": False,
            "finding": False,
        },
        "cve_correlation": {
            "source": "04-web-server-configuration/version/version.yaml",
            "source_checklist": "4-001",
            "status": "not-tested",
            "candidate_count": 0,
            "candidates": [],
            "assessment_note": (
                "CVE correlation is secondary triage evidence; version match "
                "does not establish exploitability or a vulnerability."
            ),
        },
        "assessment": {
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
            "note": "",
        },
        "evidence": {
            "session_probes": (
                "05-authentication/session/evidence/session-probes.json"
            ),
        },
        "errors": [],
        "notes": [
            "Only explicitly authorized test accounts/sessions are used.",
            "Session values are encrypted at rest using the project Fernet key.",
            "Session plaintext is never written to YAML, JSON evidence, stdout, or logs.",
            "Cloudflare Turnstile/CAPTCHA is not bypassed.",
            "HTTP authentication is attempted once with the authorized test account; "
            "human interaction falls back to a visible Playwright browser.",
            "Explicit --debug-login is interactive-only and does not persist debug "
            "cookie/session values to artifact or evidence.",
            "Missing/invalid test credentials do not make canonical verify fail; "
            "the authentication assessment remains not-tested.",
            "Session brute force and third-party session hijacking are not performed.",
            "Raw evidence is retained; report-layer redaction remains separate.",
        ],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
    }


def load_artifact() -> dict[str, Any]:
    return load_yaml(session_file(), "session.yaml")


def save_artifact(data: dict[str, Any]) -> None:
    data["updated_at"] = utc_now()
    save_yaml(session_file(), data)


def ensure_project_match(data: dict[str, Any]) -> ProjectContext:
    context = active_context()
    actual = str(data.get("project_id", "")).strip()
    if actual != context.project_id:
        raise SessionError(
            "project_id pada session.yaml tidak sesuai active project. "
            f"Expected: {context.project_id}; Found: {actual or '-'}"
        )
    return context


# ---------------------------------------------------------------------------
# Scope / account validation
# ---------------------------------------------------------------------------

def load_scope_baseline() -> dict[str, Any]:
    path = project_root() / "01-preparation" / "scope" / "scope.yaml"
    data = load_yaml(path, "scope.yaml")

    if str(data.get("project_id", "")).strip() != active_context().project_id:
        raise SessionError("project_id scope.yaml tidak sesuai active project.")

    return data


def scope_target(scope_data: dict[str, Any]) -> dict[str, Any]:
    scope = scope_data.get("scope")
    if not isinstance(scope, dict):
        raise SessionError("scope.yaml: field 'scope' tidak valid.")

    in_scope = scope.get("in_scope")
    if not isinstance(in_scope, list) or not in_scope:
        raise SessionError("scope.yaml: scope.in_scope tidak tersedia.")

    # Canonical scope.yaml uses:
    #   type: domain
    #   value: <hostname>
    #   ports: [80, 443]
    # A dedicated hostname/domain/url/target field is not required.
    for item in in_scope:
        if not isinstance(item, dict):
            continue

        scope_type = str(item.get("type", "")).strip().lower()
        value = str(item.get("value", "")).strip()

        # Prefer the canonical domain entry. Keep support for the older
        # hostname/domain/host/url/target aliases for compatibility.
        if scope_type == "domain" and value:
            return item

        for key in ("hostname", "domain", "host", "url", "target"):
            candidate = str(item.get(key, "")).strip()
            if candidate:
                return item

    return in_scope[0] if isinstance(in_scope[0], dict) else {}


def normalize_url(url: str, base: str = "") -> str:
    value = str(url or "").strip()
    if not value:
        raise SessionError("URL tidak boleh kosong.")

    if base:
        value = urljoin(base.rstrip("/") + "/", value)

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise SessionError(
            f"URL tidak valid atau bukan HTTP/HTTPS: {value}"
        )

    return value


def target_from_context() -> tuple[str, str]:
    data = load_scope_baseline()
    item = scope_target(data)

    hostname = ""

    # Canonical scope.yaml stores the domain/host in `value`.
    scope_type = str(item.get("type", "")).strip().lower()
    if scope_type == "domain":
        candidate = str(item.get("value", "")).strip()
        if candidate:
            hostname = candidate

    # Compatibility with older/non-canonical scope entries.
    if not hostname:
        for key in ("hostname", "domain", "host"):
            candidate = str(item.get(key, "")).strip()
            if candidate:
                hostname = candidate
                break

    # scope.yaml canonical format stores a domain/host plus authorized ports.
    # It does not require a dedicated url/target field. Build the base URL from
    # the authorized HTTP/HTTPS ports when url/target is absent.
    url = ""
    for key in ("url", "target"):
        candidate = str(item.get(key, "")).strip()
        if candidate:
            url = candidate
            break

    ports = item.get("ports")
    if not isinstance(ports, list):
        ports = []

    normalized_ports: list[int] = []
    for port in ports:
        try:
            normalized_ports.append(int(port))
        except (TypeError, ValueError):
            continue

    if not hostname and url:
        hostname = urlparse(url).hostname or ""

    if not hostname:
        raise SessionError(
            "Hostname/domain pada scope.yaml tidak dapat ditentukan."
        )

    # Prefer an explicit URL if the scope provides one. Otherwise select HTTPS
    # when port 443 is authorized, then HTTP when port 80 is authorized.
    if not url:
        if 443 in normalized_ports:
            url = f"https://{hostname}"
        elif 80 in normalized_ports:
            url = f"http://{hostname}"

    if not url:
        raise SessionError(
            "Target HTTP/HTTPS pada scope.yaml tidak dapat ditentukan. "
            "Pastikan scope.in_scope memiliki hostname/domain dan port 80 atau 443."
        )

    return hostname, normalize_url(url)


def validate_target_url(url: str) -> str:
    hostname, base_url = target_from_context()
    normalized = normalize_url(url, base_url)

    target_host = (urlparse(normalized).hostname or "").lower()
    if target_host != hostname.lower():
        raise SessionError(
            "URL berada di luar hostname scope aktif. "
            f"Expected: {hostname}; Found: {target_host or '-'}"
        )

    return normalized


def account_file() -> Path:
    """Return the canonical authorized test-account YAML path."""
    return project_root() / "01-preparation" / "account" / "accounts.yaml"


def load_account_baseline() -> dict[str, Any]:
    """Load the canonical account artifact for the active project."""
    path = account_file()
    data = load_yaml(path, "accounts.yaml")

    if str(data.get("project_id", "")).strip() != active_context().project_id:
        raise SessionError(
            "project_id accounts.yaml tidak sesuai active project."
        )

    schema_version = str(data.get("schema_version", "")).strip()
    if schema_version != "2.0":
        raise SessionError(
            f"schema_version accounts.yaml tidak didukung: {schema_version or '-'}"
        )

    accounts = data.get("accounts")
    if not isinstance(accounts, list):
        raise SessionError("Field 'accounts' pada accounts.yaml harus berupa list.")

    return data


def validate_account(account_id: str) -> dict[str, Any]:
    """Read one authorized account record without exposing credential plaintext."""
    account_id = str(account_id or "").strip()
    if not account_id:
        raise SessionError("account_id wajib diisi.")

    data = load_account_baseline()

    for item in data["accounts"]:
        if not isinstance(item, dict):
            continue
        if str(item.get("account_id", "")).strip().lower() != account_id.lower():
            continue

        if str(item.get("status", "")).strip().lower() != "active":
            raise SessionError(f"Test account {account_id} tidak active.")

        credentials = item.get("credentials")
        if not isinstance(credentials, dict):
            raise SessionError(
                f"Test account {account_id} tidak memiliki blok credentials."
            )

        if not str(credentials.get("username", "")).strip():
            raise SessionError(
                f"Test account {account_id} tidak memiliki encrypted username."
            )

        if not str(credentials.get("password", "")).strip():
            raise SessionError(
                f"Test account {account_id} tidak memiliki encrypted password."
            )

        return item

    raise SessionError(
        f"Test account {account_id} tidak ditemukan pada {account_file()}."
    )


# ---------------------------------------------------------------------------
# Session secret helpers
# ---------------------------------------------------------------------------

def encrypt_session_value(value: str) -> str:
    value = str(value or "")
    if not value:
        raise SessionError("Session value tidak boleh kosong.")

    try:
        return encrypt(
            value,
            project_id=active_context().project_id,
        )
    except SecretsError as exc:
        raise SessionError(
            f"Gagal mengenkripsi session value: {exc}"
        ) from exc


def decrypt_session_value(ciphertext: str) -> str:
    if not ciphertext:
        raise SessionError("Encrypted session value kosong.")

    try:
        return decrypt(
            ciphertext,
            project_id=active_context().project_id,
        )
    except SecretsError as exc:
        raise SessionError(
            f"Gagal mendekripsi session value: {exc}"
        ) from exc


def verify_encryption_key() -> None:
    try:
        verify_key(active_context().project_id)
    except SecretsError as exc:
        raise SessionError(
            f"Project encryption key tidak valid: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Session records
# ---------------------------------------------------------------------------

def session_records(data: dict[str, Any]) -> list[dict[str, Any]]:
    value = data.get("sessions")
    if value is None:
        data["sessions"] = []
        return data["sessions"]

    if not isinstance(value, list):
        raise SessionError("Field 'sessions' pada session.yaml harus berupa list.")

    records: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            records.append(item)
    return records


def next_session_id(records: list[dict[str, Any]]) -> str:
    highest = 0
    for item in records:
        match = SESSION_ID_RE.match(str(item.get("session_id", "")))
        if match:
            try:
                highest = max(highest, int(str(item["session_id"])[2:]))
            except ValueError:
                pass
    return f"S-{highest + 1:03d}"


def find_session(data: dict[str, Any], session_id: str) -> dict[str, Any]:
    wanted = str(session_id or "").strip().upper()
    for item in session_records(data):
        if str(item.get("session_id", "")).upper() == wanted:
            return item
    raise SessionError(f"Session {session_id} tidak ditemukan.")


def public_session_record(record: dict[str, Any]) -> dict[str, Any]:
    result = dict(record)
    auth = dict(result.get("authentication") or {})
    if "value_encrypted" in auth:
        auth["value_encrypted"] = "[ENCRYPTED]"
    result["authentication"] = auth
    return result


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def response_body_info(response: requests.Response) -> dict[str, Any]:
    raw = response.content[:DEFAULT_MAX_BODY_BYTES]
    try:
        text = raw.decode(response.encoding or "utf-8", errors="replace")
    except Exception:
        text = raw.decode("utf-8", errors="replace")

    return {
        "body_length_bytes": len(response.content),
        "body_truncated": len(response.content) > DEFAULT_MAX_BODY_BYTES,
        "body_sha256": hashlib.sha256(response.content).hexdigest(),
        "body_sample": text[:BODY_SAMPLE_CHARS],
    }


def safe_headers(response: requests.Response) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in response.headers.items():
        lower = key.lower()
        if lower in {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
        }:
            result[key] = "[REDACTED]"
        else:
            result[key] = str(value)
    return result


def cookie_attributes_from_response(
    response: requests.Response,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    # get_all() preserves multiple Set-Cookie values where available.
    raw_values: list[str] = []
    try:
        raw_values = response.raw.headers.get_all("Set-Cookie") or []
    except Exception:
        raw = response.headers.get("Set-Cookie")
        if raw:
            raw_values = [raw]

    for raw_value in raw_values:
        cookie = SimpleCookie()
        try:
            cookie.load(raw_value)
        except Exception:
            records.append({
                "parse_error": True,
                "raw": "[REDACTED]",
            })
            continue

        for name, morsel in cookie.items():
            records.append({
                "name": name,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or None,
                "path": morsel["path"] or None,
                "domain": morsel["domain"] or None,
                "max_age_present": bool(morsel["max-age"]),
                "expires_present": bool(morsel["expires"]),
                "value": "[REDACTED]",
            })

    return records


def build_cookie_session(record: dict[str, Any]) -> requests.Session:
    auth = record.get("authentication")
    if not isinstance(auth, dict):
        raise SessionError("Authentication metadata session tidak valid.")

    name = str(auth.get("name", "")).strip()
    encrypted = str(auth.get("value_encrypted", "")).strip()

    if not name or not encrypted:
        raise SessionError(
            "Session cookie/token belum memiliki name dan encrypted value."
        )

    value = decrypt_session_value(encrypted)

    session = requests.Session()
    cookie_type = str(auth.get("type", "cookie")).lower()

    if cookie_type == "cookie":
        session.cookies.set(
            name,
            value,
            domain=urlparse(str(record.get("target", {}).get("url", ""))).hostname
            or None,
            path=str(auth.get("path") or "/"),
        )
    else:
        # Generic token mode. The header name is explicitly stored in metadata.
        header_name = str(auth.get("header_name") or "Authorization")
        session.headers.update({header_name: value})

    # Do not keep the plaintext value in the record.
    value = ""
    return session



# ---------------------------------------------------------------------------
# Authentication / browser-assisted session capture
# ---------------------------------------------------------------------------

KNOWN_SESSION_COOKIE_NAMES = {
    "phpsessid",
    "laravel_session",
    "ci_session",
    "session",
    "sid",
    "jsessionid",
}
HUMAN_CHALLENGE_MARKERS = (
    "cloudflare turnstile",
    "cf-turnstile",
    "challenges.cloudflare.com",
    "g-recaptcha",
    "recaptcha",
    "hcaptcha",
    "captcha",
    "human verification",
    "human verification required",
    "verify you are human",
    "checking your browser",
    "challenge-platform",
)
USERNAME_FIELD_NAMES = (
    "username",
    "user",
    "userid",
    "user_id",
    "email",
    "login",
)
PASSWORD_FIELD_NAMES = ("password", "pass", "passwd")
DEFAULT_LOGIN_PATHS = ("/login", "/loginuser")


def html_human_interaction_info(html: str) -> dict[str, Any]:
    """Classify obvious human-interaction challenges without bypassing them."""
    lower = str(html or "").lower()
    matches: list[str] = []
    for marker in HUMAN_CHALLENGE_MARKERS:
        if marker in lower and marker not in matches:
            matches.append(marker)

    return {
        "detected": bool(matches),
        "classification": (
            "human-interaction-required" if matches else "no-human-interaction-detected"
        ),
        "markers": matches,
    }


def login_url_from_target(base_url: str) -> str:
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"
    return urljoin(root.rstrip("/") + "/", "login")


def parse_login_form(html: str, page_url: str) -> dict[str, Any]:
    """Extract a normal username/password form without submitting it."""
    try:
        from bs4 import BeautifulSoup
    except ImportError as exc:
        raise SessionError(
            "BeautifulSoup belum terinstall; diperlukan untuk parsing login form."
        ) from exc

    soup = BeautifulSoup(html, "html.parser")
    password_input = soup.find("input", attrs={"type": re.compile("^password$", re.I)})
    if password_input is None:
        raise SessionError("Form login tidak memiliki input password.")

    form = password_input.find_parent("form")
    if form is None:
        forms = soup.find_all("form")
        form = forms[0] if forms else None
    if form is None:
        raise SessionError("Form login tidak ditemukan.")

    def attr_name(element: Any) -> str:
        return str(element.get("name") or element.get("id") or "").strip()

    password_name = attr_name(password_input)
    if not password_name:
        raise SessionError("Input password tidak memiliki name/id yang dapat digunakan.")

    username_input = None
    inputs = form.find_all("input")
    for item in inputs:
        input_type = str(item.get("type") or "text").lower()
        name = attr_name(item).lower()
        autocomplete = str(item.get("autocomplete") or "").lower()
        if input_type in {"hidden", "password", "submit", "button", "checkbox", "radio", "file"}:
            continue
        if name in USERNAME_FIELD_NAMES or "username" in name or "email" in name:
            username_input = item
            break
        if autocomplete in {"username", "email"}:
            username_input = item
            break

    if username_input is None:
        for item in inputs:
            input_type = str(item.get("type") or "text").lower()
            if input_type in {"text", "email"} and attr_name(item):
                username_input = item
                break

    if username_input is None:
        raise SessionError("Input username/email pada form login tidak ditemukan.")

    username_name = attr_name(username_input)
    action = urljoin(page_url, str(form.get("action") or page_url))
    method = str(form.get("method") or "post").lower()

    fields: dict[str, str] = {}
    for item in inputs:
        input_type = str(item.get("type") or "text").lower()
        name = attr_name(item)
        if not name or input_type in {"submit", "button", "file", "image"}:
            continue
        if input_type in {"checkbox", "radio"} and not item.has_attr("checked"):
            continue
        fields[name] = str(item.get("value") or "")

    return {
        "action": action,
        "method": method,
        "username_name": username_name,
        "password_name": password_name,
        "fields": fields,
        "human_interaction": html_human_interaction_info(html),
    }


def session_cookie_from_cookies(
    cookies: list[dict[str, Any]],
    preferred_name: str = "",
) -> Optional[dict[str, Any]]:
    """Select a session cookie from Playwright/normalized cookie metadata."""
    preferred = str(preferred_name or "").strip().lower()

    ranked: list[tuple[int, dict[str, Any]]] = []
    for item in cookies:
        name = str(item.get("name") or "").strip()
        lower = name.lower()
        if not name:
            continue

        score = 0
        if preferred and lower == preferred:
            score += 1000
        if lower in KNOWN_SESSION_COOKIE_NAMES:
            score += 500
        if "session" in lower:
            score += 250
        if lower.endswith("_session") or lower.endswith("-session"):
            score += 100
        if item.get("httpOnly") or item.get("httponly"):
            score += 25
        if item.get("secure"):
            score += 10

        if score > 0:
            ranked.append((score, item))

    if not ranked:
        return None

    ranked.sort(key=lambda pair: pair[0], reverse=True)
    return ranked[0][1]


def normalized_cookie_metadata(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize browser cookie metadata and redact all values."""
    result: list[dict[str, Any]] = []
    for item in cookies:
        result.append({
            "name": item.get("name"),
            "domain": item.get("domain"),
            "path": item.get("path"),
            "secure": bool(item.get("secure")),
            "httponly": bool(item.get("httpOnly", item.get("httponly", False))),
            "samesite": item.get("sameSite", item.get("samesite")),
            "expires_present": item.get("expires") not in (None, -1, 0),
            "value": "[REDACTED]",
        })
    return result


def get_authorized_credentials(account_id: str) -> tuple[str, str]:
    """
    Read encrypted credentials directly from accounts.yaml and decrypt them
    through preparation.secrets. Plaintext exists only in memory.
    """
    account = validate_account(account_id)
    credentials = account.get("credentials") or {}

    encrypted_username = str(credentials.get("username") or "").strip()
    encrypted_password = str(credentials.get("password") or "").strip()

    if not encrypted_username or not encrypted_password:
        raise SessionError(
            f"Credential test account {account_id} tidak lengkap."
        )

    try:
        username = decrypt(
            encrypted_username,
            project_id=active_context().project_id,
        )
        password = decrypt(
            encrypted_password,
            project_id=active_context().project_id,
        )
    except SecretsError as exc:
        raise SessionError(
            f"Gagal mendekripsi credential test account {account_id}: {exc}"
        ) from exc

    if not username or not password:
        raise SessionError(
            f"Credential test account {account_id} hasil decrypt kosong."
        )

    return username, password


def find_login_form_with_requests(
    login_url: str,
    timeout: int,
) -> tuple[requests.Session, requests.Response, dict[str, Any]]:
    session = requests.Session()
    response = session.get(
        login_url,
        timeout=timeout,
        allow_redirects=False,
    )
    if response.status_code >= 500:
        raise SessionError(
            f"GET login mengembalikan HTTP {response.status_code}; "
            "automatic authentication tidak dilanjutkan."
        )

    form = parse_login_form(response.text, response.url or login_url)
    return session, response, form



AUTH_OUTCOME_SUCCESS = "SUCCESS"
AUTH_OUTCOME_FAILED = "FAILED"
AUTH_OUTCOME_UNCONFIRMED = "UNCONFIRMED"

AUTH_REJECTION_STATUSES = {400, 401, 403, 422, 429}
AUTH_FAILURE_MARKERS = (
    "invalid username",
    "invalid password",
    "invalid credentials",
    "incorrect password",
    "incorrect username",
    "wrong password",
    "wrong username",
    "authentication failed",
    "login failed",
    "login gagal",
    "username atau password",
    "username or password",
    "password salah",
    "akun tidak ditemukan",
    "account not found",
    "credentials are incorrect",
    "credential is incorrect",
    "unauthorized",
)
AUTHENTICATED_STATE_MARKERS = (
    "logout",
    "log out",
    "sign out",
    "signout",
    "dashboard",
    "my account",
    "profile",
    "welcome",
)

def _normalized_path(value: str) -> str:
    parsed = urlparse(str(value or ""))
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/").lower() or "/"

def _auth_url(value: str, base: str = "") -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return urljoin(base, raw) if base else raw
    except Exception:
        return raw

def _auth_login_paths(login_url: str, login_action_url: str = "") -> set[str]:
    paths = {
        _normalized_path(login_url),
        _normalized_path(login_action_url),
        "/login",
    }
    return {item for item in paths if item}

def _body_has_login_form(html: str) -> bool:
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(str(html or ""), "html.parser")
        password = soup.find(
            "input",
            attrs={"type": re.compile("^password$", re.I)},
        )
        return password is not None
    except Exception:
        return False

def _authentication_failure_reasons(html: str) -> list[str]:
    lower = re.sub(r"\s+", " ", str(html or "").lower())
    return [marker for marker in AUTH_FAILURE_MARKERS if marker in lower]

def _authenticated_state_signals(html: str) -> list[str]:
    lower = re.sub(r"\s+", " ", str(html or "").lower())
    return [marker for marker in AUTHENTICATED_STATE_MARKERS if marker in lower]

def authentication_outcome_engine(
    *,
    login_url: str,
    login_action_url: str = "",
    post_captured: bool,
    post_status: Optional[int],
    location: str = "",
    current_url: str = "",
    session_cookie_present: bool,
    response_body: str = "",
) -> dict[str, Any]:
    """
    Decide authentication outcome from multiple independent signals.

    Rules:
      - HTTP rejection or explicit login failure -> FAILED.
      - Missing POST capture -> UNCONFIRMED.
      - Redirect/navigation back to a login endpoint -> FAILED.
      - A pre-existing session cookie is never sufficient evidence.
      - SUCCESS requires: captured POST, non-rejection response, navigation
        away from login, a usable session cookie, no login form/failure
        indicators on the resulting page.
      - If evidence is insufficient -> UNCONFIRMED.
    """
    reasons: list[str] = []
    normalized_login_paths = _auth_login_paths(
        login_url,
        login_action_url,
    )
    resolved_location = _auth_url(location, login_url)
    resolved_current = _auth_url(current_url, login_url)

    destination = resolved_location or resolved_current
    destination_path = _normalized_path(destination)
    failure_markers = _authentication_failure_reasons(response_body)
    login_form_present = _body_has_login_form(response_body)
    state_signals = _authenticated_state_signals(response_body)

    if post_status in AUTH_REJECTION_STATUSES:
        reasons.append(f"authentication response HTTP {post_status} indicates rejection")

    if failure_markers:
        reasons.append(
            "explicit login failure indicator: " + ", ".join(failure_markers[:5])
        )

    destination_is_login = (
        destination_path in normalized_login_paths
        or destination_path == "/login"
    )

    if destination_is_login:
        reasons.append("redirect/navigation kembali ke login endpoint")

    if not post_captured:
        reasons.append("authentication POST tidak tertangkap")

    if not session_cookie_present:
        reasons.append("usable session cookie tidak tersedia")

    if login_form_present:
        reasons.append("halaman hasil masih memiliki login form")

    if (
        post_captured
        and post_status not in AUTH_REJECTION_STATUSES
        and not destination_is_login
        and session_cookie_present
        and not failure_markers
        and not login_form_present
        and destination_path not in {"", "/"}
    ):
        # A login-form-free page reached through the authentication flow,
        # together with the authenticated session cookie, is the automatic
        # authenticated-state confirmation. Explicit markers strengthen the
        # evidence but are not mandatory because applications vary.
        outcome = AUTH_OUTCOME_SUCCESS
        reasons.append("post-login page reached without login form/failure indicators")
    elif (
        post_captured
        and (
            destination_is_login
            or post_status in AUTH_REJECTION_STATUSES
            or failure_markers
            or login_form_present
        )
    ):
        outcome = AUTH_OUTCOME_FAILED
    else:
        outcome = AUTH_OUTCOME_UNCONFIRMED

    return {
        "outcome": outcome,
        "success": outcome == AUTH_OUTCOME_SUCCESS,
        "authentication_outcome": outcome,
        "destination_url": destination,
        "destination_path": destination_path,
        "redirect_away_from_login": bool(
            destination_path and destination_path not in normalized_login_paths
        ),
        "login_form_present": login_form_present,
        "failure_markers": failure_markers,
        "authenticated_state_signals": state_signals,
        "session_cookie_present": session_cookie_present,
        "post_captured": post_captured,
        "post_status": post_status,
        "location": location,
        "reasons": reasons,
        "requires_review": outcome == AUTH_OUTCOME_UNCONFIRMED,
    }

def _post_login_http_verification(
    session: requests.Session,
    destination_url: str,
    login_url: str,
    timeout: int,
) -> dict[str, Any]:
    if not destination_url:
        return {
            "verified": False,
            "status": None,
            "url": "",
            "body": "",
            "reason": "Tidak ada destination URL untuk post-login verification.",
        }

    try:
        response = session.get(
            destination_url,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return {
            "verified": False,
            "status": None,
            "url": destination_url,
            "body": "",
            "reason": f"Post-login verification request gagal: {exc}",
        }

    body = response.text[:DEFAULT_MAX_BODY_BYTES]
    final_path = _normalized_path(response.url or destination_url)
    login_path = _normalized_path(login_url)

    verified = (
        response.status_code < 400
        and final_path != login_path
        and not _body_has_login_form(body)
        and not _authentication_failure_reasons(body)
    )

    return {
        "verified": verified,
        "status": response.status_code,
        "url": response.url or destination_url,
        "body": body,
        "body_info": response_body_info(response),
        "headers": safe_headers(response),
        "login_form_present": _body_has_login_form(body),
        "failure_markers": _authentication_failure_reasons(body),
        "authenticated_state_signals": _authenticated_state_signals(body),
        "reason": (
            "Post-login page tidak kembali ke login dan tidak menunjukkan "
            "login form/failure indicator."
            if verified
            else "Post-login page belum memberikan bukti authenticated state yang cukup."
        ),
    }

def automatic_http_authentication(
    login_url: str,
    username: str,
    password: str,
    preferred_cookie_name: str,
    timeout: int,
) -> dict[str, Any]:
    """Perform one bounded authorized login attempt with outcome verification."""
    session, response, form = find_login_form_with_requests(login_url, timeout)

    challenge = form.get("human_interaction") or {}
    if challenge.get("detected"):
        return {
            "success": False,
            "authentication_outcome": AUTH_OUTCOME_UNCONFIRMED,
            "mode": "browser-required",
            "human_interaction_required": True,
            "human_interaction": challenge,
            "reason": "Human interaction challenge detected on login page.",
        }

    fields = dict(form.get("fields") or {})
    fields[str(form["username_name"])] = username
    fields[str(form["password_name"])] = password

    method = str(form.get("method") or "post").upper()
    if method != "POST":
        return {
            "success": False,
            "authentication_outcome": AUTH_OUTCOME_UNCONFIRMED,
            "mode": "http",
            "human_interaction_required": False,
            "reason": f"Login form method {method} tidak didukung untuk automatic POST.",
            "login_get_status": response.status_code,
        }

    try:
        login_response = session.post(
            str(form["action"]),
            data=fields,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return {
            "success": False,
            "authentication_outcome": AUTH_OUTCOME_UNCONFIRMED,
            "mode": "http",
            "human_interaction_required": False,
            "reason": f"HTTP authentication request gagal: {exc}",
        }

    post_challenge = html_human_interaction_info(login_response.text)
    if post_challenge.get("detected"):
        return {
            "success": False,
            "authentication_outcome": AUTH_OUTCOME_UNCONFIRMED,
            "mode": "browser-required",
            "human_interaction_required": True,
            "human_interaction": post_challenge,
            "reason": "Human interaction challenge detected after login submission.",
            "login_status": login_response.status_code,
        }

    cookies: list[dict[str, Any]] = []
    for cookie in session.cookies:
        cookies.append({
            "name": cookie.name,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": bool(cookie.secure),
            "httponly": False,
            "samesite": None,
            "value": cookie.value,
        })

    selected = session_cookie_from_cookies(cookies, preferred_cookie_name)
    location = str(login_response.headers.get("Location") or "")
    destination = urljoin(
        str(response.url or login_url),
        location,
    ) if location else ""

    verification = _post_login_http_verification(
        session,
        destination,
        login_url,
        timeout,
    ) if destination and _normalized_path(destination) not in _auth_login_paths(
        login_url,
        str(form.get("action") or ""),
    ) else {
        "verified": False,
        "status": None,
        "url": destination,
        "body": "",
        "reason": "Authentication redirect kembali ke login; post-login verification tidak dilakukan.",
    }

    body = str(verification.get("body") or "")
    engine = authentication_outcome_engine(
        login_url=login_url,
        login_action_url=str(form.get("action") or ""),
        post_captured=True,
        post_status=login_response.status_code,
        location=location,
        current_url=str(verification.get("url") or destination),
        session_cookie_present=bool(selected),
        response_body=body,
    )

    if engine["outcome"] == AUTH_OUTCOME_SUCCESS and not verification.get("verified"):
        engine["outcome"] = AUTH_OUTCOME_UNCONFIRMED
        engine["success"] = False
        engine["authentication_outcome"] = AUTH_OUTCOME_UNCONFIRMED
        engine["requires_review"] = True
        engine["reasons"].append(
            "post-login verification tidak mengonfirmasi authenticated state"
        )

    return {
        "success": bool(engine["success"]),
        "authentication_outcome": engine["outcome"],
        "mode": "http",
        "human_interaction_required": False,
        "login_get_status": response.status_code,
        "login_status": login_response.status_code,
        "location": location,
        "post_login_url": str(verification.get("url") or destination or ""),
        "cookies": normalized_cookie_metadata(cookies),
        "selected_cookie": (
            {**selected, "value": "[REDACTED]"} if selected else None
        ),
        "session_value": selected.get("value") if selected else "",
        "post_login_verification": {
            key: value for key, value in verification.items() if key != "body"
        },
        "authentication_engine": engine,
        "requires_review": bool(engine["requires_review"]),
        "reason": (
            "Authorized HTTP login berhasil dan post-login authenticated state "
            "terverifikasi."
            if engine["success"]
            else "Authentication outcome "
            + str(engine["outcome"])
            + ": "
            + "; ".join(engine["reasons"])
        ),
    }


def browser_authentication(
    login_url: str,
    username: str,
    password: str,
    preferred_cookie_name: str,
    timeout: int,
    browser_wait: int,
) -> dict[str, Any]:
    """
    Use a visible Playwright browser when human interaction is required.

    Normal browser authentication uses the same capture baseline as
    --debug-login:
      - discover the rendered login form action before authentication;
      - capture cookies before login;
      - capture the actual authentication POST;
      - capture the POST response and navigation/redirect;
      - capture cookies after login;
      - compare the preferred session cookie before/after authentication;
      - return the authenticated session value for encrypted persistence.

    Unlike --debug-login, normal mode:
      - never prints plaintext cookie/session values;
      - keeps the existing automatic-submit behavior when no challenge exists;
      - persists the selected authenticated session through cmd_add().
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SessionError(
            "Playwright belum terinstall; browser emulator diperlukan karena "
            "login membutuhkan human interaction."
        ) from exc

    timeout_ms = max(5, int(timeout)) * 1000
    wait_seconds = max(30, int(browser_wait))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(timeout_ms)

        login_post_request: Optional[Any] = None
        login_post_response: Optional[Any] = None
        post_data: str = ""
        navigation_urls: list[str] = []
        login_action_url = ""
        login_method = ""

        def on_request(request: Any) -> None:
            nonlocal login_post_request, post_data

            try:
                if request.method.upper() != "POST":
                    return

                if login_post_request is not None:
                    return

                request_url = str(request.url)
                normalized_request = request_url.rstrip("/")
                normalized_action = login_action_url.rstrip("/")

                # Match the actual rendered form action. Do not assume that
                # /login is also the authentication POST endpoint.
                if normalized_action and normalized_request == normalized_action:
                    login_post_request = request
                    try:
                        post_data = request.post_data or ""
                    except Exception:
                        post_data = ""
            except Exception:
                return

        def on_response(response: Any) -> None:
            nonlocal login_post_response

            try:
                request = response.request
                if (
                    login_post_request is not None
                    and request is login_post_request
                ):
                    login_post_response = response
            except Exception:
                return

        def on_navigation(frame: Any) -> None:
            try:
                if frame == page.main_frame:
                    current = str(frame.url)
                    if current and (
                        not navigation_urls or navigation_urls[-1] != current
                    ):
                        navigation_urls.append(current)
            except Exception:
                return

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("framenavigated", on_navigation)

        try:
            page.goto(
                login_url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
            navigation_urls.append(page.url)

            page_html = page.content()
            before_cookies = context.cookies()
            challenge = html_human_interaction_info(page_html)

            # Synchronize normal mode with the debug baseline: discover the
            # actual POST action from the rendered login form before the user
            # can submit the form.
            try:
                browser_form = parse_login_form(page_html, page.url)
                login_action_url = str(
                    browser_form.get("action") or ""
                ).strip()
                login_method = str(
                    browser_form.get("method") or "post"
                ).upper()
            except SessionError as exc:
                raise SessionError(
                    f"Browser: form login tidak dapat dianalisis: {exc}"
                ) from exc

            password_locator = page.locator('input[type="password"]').first
            if password_locator.count() == 0:
                raise SessionError(
                    "Browser: input password tidak ditemukan."
                )

            username_locator = None
            for selector in (
                'input[name="username"]',
                'input[name="email"]',
                'input[name="user"]',
                'input[autocomplete="username"]',
                'input[type="email"]',
                'input[type="text"]',
            ):
                candidate = page.locator(selector).first
                if candidate.count() > 0:
                    username_locator = candidate
                    break

            if username_locator is None:
                raise SessionError(
                    "Browser: input username/email tidak ditemukan."
                )

            username_locator.fill(username)
            password_locator.fill(password)

            print(f"[STEP] Login page      : {page.url}")
            print(f"[STEP] Login method    : {login_method}")
            print(
                f"[STEP] Login POST URL  : "
                f"{login_action_url or '-'}"
            )
            print(
                f"[STEP] HTTP challenge  : "
                f"{challenge.get('classification')}"
            )

            if challenge.get("markers"):
                print(
                    "[INFO] Challenge markers: "
                    + ", ".join(
                        str(x) for x in challenge["markers"]
                    )
                )

            if challenge.get("detected"):
                print(
                    "[INFO] Human interaction diperlukan. "
                    "Selesaikan challenge/login pada browser yang dibuka."
                )
                print(
                    f"[INFO] Browser akan menunggu maksimal "
                    f"{wait_seconds} detik."
                )
            else:
                # Preserve the existing normal-mode behavior:
                # if there is no human challenge, submit automatically.
                submit = page.locator(
                    'button[type="submit"], input[type="submit"]'
                ).first

                if submit.count() > 0:
                    submit.click()
                else:
                    password_locator.press("Enter")

            # Baseline debug waits for the actual authentication POST.
            deadline = __import__("time").monotonic() + wait_seconds
            while (
                __import__("time").monotonic() < deadline
                and login_post_request is None
            ):
                page.wait_for_timeout(250)

            # Preserve a useful authenticated-cookie fallback if an
            # application submits through an endpoint that Playwright cannot
            # associate with the discovered form action. However, when the
            # actual POST is captured, the captured POST remains authoritative.
            if login_post_request is None:
                after_timeout = context.cookies()
                selected = session_cookie_from_cookies(
                    after_timeout,
                    preferred_cookie_name,
                )
                engine = authentication_outcome_engine(
                    login_url=login_url,
                    login_action_url=login_action_url,
                    post_captured=False,
                    post_status=None,
                    location="",
                    current_url=page.url,
                    session_cookie_present=bool(selected),
                    response_body=page.content(),
                )
                return {
                    "success": False,
                    "authentication_outcome": engine["outcome"],
                    "mode": "browser",
                    "human_interaction_required": bool(
                        challenge.get("detected")
                    ),
                    "human_interaction": challenge,
                    "post_captured": False,
                    "login_method": login_method,
                    "login_action_url": login_action_url,
                    "login_status": None,
                    "location": "",
                    "post_login_url": page.url,
                    "navigation_urls": navigation_urls,
                    "url_after_login": page.url,
                    "cookie_before": normalized_cookie_metadata(
                        before_cookies
                    ),
                    "cookie_after": normalized_cookie_metadata(
                        after_timeout
                    ),
                    "cookie_comparison": _debug_print_cookie_comparison(
                        before_cookies,
                        after_timeout,
                        preferred_cookie_name,
                    ),
                    "reason": (
                        "Browser login selesai/timeout tetapi POST login "
                        "yang sesuai dengan form action tidak tertangkap."
                    ),
                    "cookies": normalized_cookie_metadata(after_timeout),
                    "selected_cookie": (
                        {**selected, "value": "[REDACTED]"}
                        if selected
                        else None
                    ),
                    "session_value": (
                        str(selected.get("value") or "")
                        if selected
                        else ""
                    ),
                }

            # Wait briefly for the response/navigation associated with the
            # captured authentication POST. The response may already be
            # available immediately for 303/302 authentication flows.
            response_deadline = __import__("time").monotonic() + min(
                10,
                max(2, int(browser_wait)),
            )
            while (
                __import__("time").monotonic() < response_deadline
                and login_post_response is None
            ):
                page.wait_for_timeout(100)

            after_cookies = context.cookies()

            selected = session_cookie_from_cookies(
                after_cookies,
                preferred_cookie_name,
            )

            comparison = _debug_print_cookie_comparison(
                before_cookies,
                after_cookies,
                preferred_cookie_name,
            )

            login_status: Optional[int] = None
            location = ""
            if login_post_response is not None:
                try:
                    login_status = int(login_post_response.status)
                except Exception:
                    login_status = None

                try:
                    location = str(
                        login_post_response.headers.get("location") or ""
                    )
                except Exception:
                    location = ""

            response_body = ""
            try:
                response_body = page.content()
            except Exception:
                response_body = ""

            engine = authentication_outcome_engine(
                login_url=login_url,
                login_action_url=login_action_url,
                post_captured=login_post_request is not None,
                post_status=login_status,
                location=location,
                current_url=page.url,
                session_cookie_present=bool(selected),
                response_body=response_body,
            )

            authenticated_indication = bool(engine["success"])
            preferred_changed = bool(comparison.get("preferred_changed"))
            potential_session_hijacking = bool(
                authenticated_indication
                and preferred_cookie_name
                and not preferred_changed
                and comparison.get("preferred_before") is not None
                and comparison.get("preferred_after") is not None
            )

            if login_post_request is not None:
                print()
                print("=" * 72)
                print(" LOGIN POST REQUEST")
                print("=" * 72)
                print(f"Method       : {login_post_request.method}")
                print(f"URL          : {login_post_request.url}")

                request_headers: dict[str, str] = {}
                try:
                    for key, value in (
                        login_post_request.all_headers().items()
                    ):
                        lower = key.lower()
                        if lower in {
                            "cookie",
                            "authorization",
                            "proxy-authorization",
                        }:
                            request_headers[key] = "[REDACTED]"
                        else:
                            request_headers[key] = str(value)
                except Exception:
                    request_headers = {}

                if request_headers:
                    print("Headers:")
                    for key, value in sorted(request_headers.items()):
                        print(f"  {key}: {value}")

                print("POST fields:")
                safe_fields = _debug_safe_post_fields(post_data)
                if safe_fields:
                    for field in safe_fields:
                        print(
                            f"  {field['name']} = "
                            f"{field['value']}"
                        )
                else:
                    print(
                        "  [body tidak dapat diparse "
                        "sebagai form-urlencoded]"
                    )

            print()
            print("=" * 72)
            print(" LOGIN POST RESPONSE")
            print("=" * 72)

            if login_post_response is not None:
                print(f"Status       : {login_status}")
                print(
                    f"Location     : "
                    f"{location or '-'}"
                )
            else:
                print("Status       : [NOT CAPTURED]")
                print("Location     : -")

            print()
            print("=" * 72)
            print(" NAVIGATION")
            print("=" * 72)
            if navigation_urls:
                for item in navigation_urls:
                    print(f"  {item}")
            else:
                print("  [none]")

            # Do not print cookie values in normal mode. The comparison helper
            # intentionally prints names/status only; its returned before/after
            # records contain raw values, so they must never be persisted.
            print()
            print("=" * 72)
            print(" COOKIE / SESSION COMPARISON")
            print("=" * 72)
            print(f"Cookies sebelum : {len(before_cookies)}")
            print(f"Cookies sesudah : {len(after_cookies)}")
            print(
                "Cookie baru     : "
                + (
                    ", ".join(comparison.get("added") or [])
                    or "-"
                )
            )
            print(
                "Cookie hilang   : "
                + (
                    ", ".join(comparison.get("removed") or [])
                    or "-"
                )
            )
            print(
                "Cookie berubah  : "
                + (
                    ", ".join(comparison.get("changed") or [])
                    or "-"
                )
            )
            print(
                "Cookie tetap    : "
                + (
                    ", ".join(comparison.get("unchanged") or [])
                    or "-"
                )
            )

            if preferred_cookie_name:
                print()
                print(
                    f"Preferred cookie: "
                    f"{preferred_cookie_name}"
                )
                print(
                    "Status          : "
                    + (
                        "BERUBAH/DITERBITKAN ULANG"
                        if preferred_changed
                        else "TIDAK BERUBAH"
                    )
                )

            print()
            print("BROWSER LOGIN ASSESSMENT")
            print(
                f"POST captured          : "
                f"{'YES' if login_post_request is not None else 'NO'}"
            )
            print(
                f"POST response          : "
                f"{login_status if login_status is not None else '-'}"
            )
            print(
                f"Redirect/navigation    : "
                f"{'YES' if len(navigation_urls) > 1 else 'NO'}"
            )
            print(
                f"Preferred cookie change: "
                f"{'YES' if preferred_changed else 'NO'}"
            )
            print(
                f"Authentication outcome : {engine['outcome']}"
            )
            print(
                f"Post-login verification: "
                f"{'PASS' if engine['success'] else 'REVIEW/FAIL'}"
            )
            if engine.get("authenticated_state_signals"):
                print(
                    "Authenticated signals : "
                    + ", ".join(engine["authenticated_state_signals"])
                )
            if engine.get("failure_markers"):
                print(
                    "Failure indicators    : "
                    + ", ".join(engine["failure_markers"])
                )


            if potential_session_hijacking:
                print(
                    "Potential session hijacking: "
                    "REVIEW - session identifier tidak berubah "
                    "setelah login"
                )
                print(
                    "[REVIEW] Session/cookie yang sama sebelum dan "
                    "sesudah authentication berpotensi dapat direplay "
                    "jika diperoleh pihak lain. Lakukan controlled "
                    "session-replay test untuk mengonfirmasi; ini "
                    "BUKAN finding otomatis."
                )

            return {
                "success": authenticated_indication,
                "authentication_outcome": engine["outcome"],
                "mode": "browser",
                "human_interaction_required": bool(
                    challenge.get("detected")
                ),
                "human_interaction": challenge,
                "post_captured": login_post_request is not None,
                "login_method": login_method,
                "login_action_url": login_action_url,
                "login_status": login_status,
                "location": location,
                "post_login_url": (
                    urljoin(login_action_url or login_url, location)
                    if location
                    else str(page.url or "")
                ),
                "navigation_urls": navigation_urls,
                "url_after_login": page.url,
                "cookie_before": normalized_cookie_metadata(
                    before_cookies
                ),
                "cookie_after": normalized_cookie_metadata(
                    after_cookies
                ),
                "cookie_comparison": comparison,
                "preferred_cookie_changed": preferred_changed,
                "potential_session_hijacking": potential_session_hijacking,
                "authentication_engine": engine,
                "requires_review": bool(engine.get("requires_review")),
                "reason": (
                    "Authorized browser login completed and authenticated "
                    "state verified."
                    if authenticated_indication
                    else (
                        "Authentication outcome "
                        + str(engine.get("outcome"))
                        + ": "
                        + "; ".join(engine.get("reasons") or [])
                    )
                ),
                "cookies": normalized_cookie_metadata(after_cookies),
                "selected_cookie": (
                    {**selected, "value": "[REDACTED]"}
                    if selected
                    else None
                ),
                "session_value": (
                    str(selected.get("value") or "")
                    if selected
                    else ""
                ),
            }
        finally:
            browser.close()

def _debug_cookie_key(cookie: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(cookie.get("name") or ""),
        str(cookie.get("domain") or ""),
        str(cookie.get("path") or "/"),
    )


def _debug_cookie_map(cookies: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    return {_debug_cookie_key(item): item for item in cookies}


def _debug_safe_post_fields(post_data: str) -> list[dict[str, str]]:
    """Parse POST form data while keeping passwords/tokens/cookies redacted."""
    if not post_data:
        return []

    sensitive_tokens = (
        "password",
        "passwd",
        "pass",
        "pwd",
        "csrf",
        "xsrf",
        "token",
        "secret",
        "authorization",
        "cookie",
        "session",
    )

    fields: list[dict[str, str]] = []
    try:
        parsed = parse_qsl(post_data, keep_blank_values=True)
    except Exception:
        return [{"name": "[UNPARSED_BODY]", "value": "[REDACTED]"}]

    for name, value in parsed:
        lower = str(name).strip().lower()
        sensitive = any(token in lower for token in sensitive_tokens)
        fields.append({
            "name": str(name),
            "value": "[REDACTED]" if sensitive else str(value),
        })

    return fields


def _debug_print_cookies(
    title: str,
    cookies: list[dict[str, Any]],
) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)

    if not cookies:
        print("(tidak ada cookie)")
        return

    for cookie in cookies:
        print(f"Name       : {cookie.get('name', '-')}")
        print(f"Value      : {cookie.get('value', '')}")
        print(f"Domain     : {cookie.get('domain', '-')}")
        print(f"Path       : {cookie.get('path', '-')}")
        print(f"HttpOnly   : {bool(cookie.get('httpOnly', cookie.get('httponly', False)))}")
        print(f"Secure     : {bool(cookie.get('secure', False))}")
        print(f"SameSite   : {cookie.get('sameSite', cookie.get('samesite')) or '-'}")
        print(f"Expires    : {cookie.get('expires', '-')}")
        print("-" * 72)


def _debug_print_cookie_comparison(
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    preferred_name: str = "",
) -> dict[str, Any]:
    before_map = _debug_cookie_map(before)
    after_map = _debug_cookie_map(after)

    before_names = {str(item.get("name") or "") for item in before}
    after_names = {str(item.get("name") or "") for item in after}

    added = sorted(after_names - before_names)
    removed = sorted(before_names - after_names)
    changed: list[str] = []
    unchanged: list[str] = []

    for key in sorted(set(before_map) & set(after_map)):
        old_value = str(before_map[key].get("value") or "")
        new_value = str(after_map[key].get("value") or "")
        name = str(key[0])

        if old_value != new_value:
            changed.append(name)
        else:
            unchanged.append(name)

    preferred_changed = False
    preferred_before = None
    preferred_after = None
    if preferred_name:
        wanted = preferred_name.lower()
        for key, item in before_map.items():
            if str(key[0]).lower() == wanted:
                preferred_before = item
                break
        for key, item in after_map.items():
            if str(key[0]).lower() == wanted:
                preferred_after = item
                break

        if preferred_before is None and preferred_after is not None:
            preferred_changed = True
        elif preferred_before is not None and preferred_after is None:
            preferred_changed = True
        elif preferred_before is not None and preferred_after is not None:
            preferred_changed = (
                str(preferred_before.get("value") or "")
                != str(preferred_after.get("value") or "")
            )

    print()
    print("=" * 72)
    print(" COOKIE / SESSION COMPARISON")
    print("=" * 72)
    print(f"Cookies sebelum : {len(before)}")
    print(f"Cookies sesudah : {len(after)}")
    print(f"Cookie baru     : {', '.join(added) if added else '-'}")
    print(f"Cookie hilang   : {', '.join(removed) if removed else '-'}")
    print(f"Cookie berubah  : {', '.join(sorted(set(changed))) if changed else '-'}")
    print(
        f"Cookie tetap    : "
        f"{', '.join(sorted(set(unchanged))) if unchanged else '-'}"
    )

    if preferred_name:
        print()
        print(f"Preferred cookie: {preferred_name}")
        print(
            "Status          : "
            + ("BERUBAH/DITERBITKAN ULANG" if preferred_changed else "TIDAK BERUBAH")
        )

    return {
        "added": added,
        "removed": removed,
        "changed": sorted(set(changed)),
        "unchanged": sorted(set(unchanged)),
        "preferred_name": preferred_name,
        "preferred_changed": preferred_changed,
        "preferred_before": preferred_before,
        "preferred_after": preferred_after,
    }


def debug_login_browser(
    login_url: str,
    username: str,
    password: str,
    preferred_cookie_name: str,
    timeout: int,
    browser_wait: int,
) -> dict[str, Any]:
    """
    Explicit interactive debug mode.

    Important:
      - Opens the real login page in a visible browser.
      - Captures and displays the initial cookie/session state.
      - Fills the authorized username/password automatically.
      - NEVER clicks the login button automatically.
      - Waits for the user to perform human interaction and click Login.
      - Captures the actual POST request and response/redirect.
      - Captures and displays cookie/session state after the POST.
      - Does not save a session record or debug cookie values to any artifact.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SessionError(
            "Playwright belum terinstall; --debug-login membutuhkan browser."
        ) from exc

    timeout_ms = max(5, int(timeout)) * 1000
    wait_seconds = max(30, int(browser_wait))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        page.set_default_timeout(timeout_ms)

        login_post_request: Optional[Any] = None
        login_post_response: Optional[Any] = None
        post_data: str = ""
        navigation_urls: list[str] = []
        login_action_url = ""

        def on_request(request: Any) -> None:
            nonlocal login_post_request, post_data
            try:
                if request.method.upper() != "POST":
                    return

                if login_post_request is not None:
                    return

                request_url = str(request.url)
                normalized_request = request_url.rstrip("/")
                normalized_action = login_action_url.rstrip("/")

                # The application login form may POST to a different endpoint
                # than /login (for Bangsaku this is /loginuser). Match the
                # actual form action discovered from the rendered page instead
                # of assuming the GET login URL is also the POST endpoint.
                if normalized_action and normalized_request == normalized_action:
                    login_post_request = request
                    try:
                        post_data = request.post_data or ""
                    except Exception:
                        post_data = ""
            except Exception:
                return

        def on_response(response: Any) -> None:
            nonlocal login_post_response
            try:
                request = response.request
                if (
                    login_post_request is not None
                    and request is login_post_request
                ):
                    login_post_response = response
            except Exception:
                return

        def on_navigation(frame: Any) -> None:
            try:
                if frame == page.main_frame:
                    current = str(frame.url)
                    if current and (
                        not navigation_urls or navigation_urls[-1] != current
                    ):
                        navigation_urls.append(current)
            except Exception:
                return

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("framenavigated", on_navigation)

        try:
            print()
            print("=" * 72)
            print(" DEBUG LOGIN - INTERACTIVE SESSION TRACE")
            print("=" * 72)
            print("[INFO] Browser dibuka dalam mode visible.")
            print("[INFO] Tidak ada bypass Turnstile/CAPTCHA.")
            print("[INFO] Login button TIDAK akan diklik otomatis.")
            print("[INFO] Username/password hanya diisi otomatis.")
            print()

            page.goto(
                login_url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
            navigation_urls.append(page.url)

            page_html = page.content()
            before_cookies = context.cookies()
            challenge = html_human_interaction_info(page_html)

            # Discover the actual POST target from the rendered login form.
            # This is intentionally done before the user clicks Login so the
            # request listener can capture the real authentication POST.
            try:
                debug_form = parse_login_form(page_html, page.url)
                login_action_url = str(debug_form.get("action") or "").strip()
                login_method = str(debug_form.get("method") or "post").upper()
            except SessionError as exc:
                raise SessionError(
                    f"Browser debug: form login tidak dapat dianalisis: {exc}"
                ) from exc

            print(f"[STEP] Login page      : {page.url}")
            print(f"[STEP] Login method    : {login_method}")
            print(f"[STEP] Login POST URL  : {login_action_url or '-'}")
            print(f"[STEP] HTTP challenge  : {challenge.get('classification')}")
            if challenge.get("markers"):
                print(
                    "[INFO] Challenge markers: "
                    + ", ".join(str(x) for x in challenge["markers"])
                )

            _debug_print_cookies(
                " COOKIE / SESSION BEFORE LOGIN",
                before_cookies,
            )

            password_locator = page.locator('input[type="password"]').first
            if password_locator.count() == 0:
                raise SessionError(
                    "Browser debug: input password tidak ditemukan."
                )

            username_locator = None
            for selector in (
                'input[name="username"]',
                'input[name="email"]',
                'input[name="user"]',
                'input[autocomplete="username"]',
                'input[type="email"]',
                'input[type="text"]',
            ):
                candidate = page.locator(selector).first
                if candidate.count() > 0:
                    username_locator = candidate
                    break

            if username_locator is None:
                raise SessionError(
                    "Browser debug: input username/email tidak ditemukan."
                )

            username_locator.fill(username)
            password_locator.fill(password)

            print()
            print("[PASS] Username otomatis diisi.")
            print("[PASS] Password otomatis diisi.")
            print()
            print("[ACTION] Silakan lakukan langkah berikut pada browser:")
            print("         1. Selesaikan Turnstile/human interaction jika ada.")
            print("         2. Klik tombol Login.")
            print("         3. Jangan tutup browser sebelum hasil POST tampil.")
            print()
            print(
                f"[INFO] Menunggu POST login maksimal {wait_seconds} detik..."
            )

            deadline = __import__("time").monotonic() + wait_seconds
            while (
                __import__("time").monotonic() < deadline
                and login_post_request is None
            ):
                page.wait_for_timeout(250)

            if login_post_request is None:
                after_timeout = context.cookies()
                print()
                print("[WARN] POST login belum tertangkap.")
                print("[INFO] Kemungkinan Anda belum klik Login atau login form")
                print("       menggunakan endpoint/request yang berbeda.")
                _debug_print_cookies(
                    " COOKIE / SESSION AT TIMEOUT",
                    after_timeout,
                )
                comparison = _debug_print_cookie_comparison(
                    before_cookies,
                    after_timeout,
                    preferred_cookie_name,
                )
                return {
                    "success": False,
                    "mode": "debug-browser",
                    "debug_only": True,
                    "post_captured": False,
                    "human_interaction_required": bool(
                        challenge.get("detected")
                    ),
                    "cookie_before": before_cookies,
                    "cookie_after": after_timeout,
                    "cookie_comparison": comparison,
                    "reason": "POST login belum tertangkap dalam waktu tunggu.",
                }

            print()
            print("=" * 72)
            print(" LOGIN POST REQUEST")
            print("=" * 72)
            print(f"Method       : {login_post_request.method}")
            print(f"URL          : {login_post_request.url}")
            print(
                f"Resource type: "
                f"{getattr(login_post_request, 'resource_type', 'unknown')}"
            )

            request_headers = {}
            try:
                for key, value in login_post_request.all_headers().items():
                    lower = key.lower()
                    if lower in {
                        "cookie",
                        "authorization",
                        "proxy-authorization",
                    }:
                        request_headers[key] = "[REDACTED]"
                    else:
                        request_headers[key] = str(value)
            except Exception:
                request_headers = {}

            if request_headers:
                print("Headers:")
                for key, value in sorted(request_headers.items()):
                    print(f"  {key}: {value}")

            print("POST fields:")
            safe_fields = _debug_safe_post_fields(post_data)
            if safe_fields:
                for field in safe_fields:
                    print(f"  {field['name']} = {field['value']}")
            else:
                print("  [body tidak dapat diparse sebagai form-urlencoded]")

            response_deadline = __import__("time").monotonic() + max(
                10, min(wait_seconds, 30)
            )
            while (
                login_post_response is None
                and __import__("time").monotonic() < response_deadline
            ):
                page.wait_for_timeout(100)

            if login_post_response is not None:
                print()
                print("=" * 72)
                print(" LOGIN POST RESPONSE")
                print("=" * 72)
                print(f"Status       : {login_post_response.status}")
                print(f"Status text  : {login_post_response.status_text}")
                print(f"Response URL : {login_post_response.url}")
                location = login_post_response.headers.get("location", "")
                print(f"Location     : {location or '-'}")
            else:
                print()
                print("[WARN] Response untuk POST login belum tertangkap.")

            # Allow redirect/navigation and Set-Cookie processing to settle.
            page.wait_for_timeout(1500)

            after_cookies = context.cookies()

            print()
            print("=" * 72)
            print(" NAVIGATION AFTER LOGIN POST")
            print("=" * 72)
            print(f"Current URL   : {page.url}")
            if navigation_urls:
                for index, url in enumerate(navigation_urls, start=1):
                    print(f"{index:02d}. {url}")
            else:
                print("(tidak ada navigation event tambahan)")

            _debug_print_cookies(
                " COOKIE / SESSION AFTER LOGIN",
                after_cookies,
            )

            comparison = _debug_print_cookie_comparison(
                before_cookies,
                after_cookies,
                preferred_cookie_name,
            )

            post_status = (
                login_post_response.status
                if login_post_response is not None
                else None
            )
            location = (
                login_post_response.headers.get("location", "")
                if login_post_response is not None
                else ""
            )

            debug_body = ""
            try:
                debug_body = page.content()
            except Exception:
                debug_body = ""

            debug_engine = authentication_outcome_engine(
                login_url=login_url,
                login_action_url=login_action_url,
                post_captured=login_post_response is not None,
                post_status=post_status,
                location=location,
                current_url=page.url,
                session_cookie_present=bool(
                    session_cookie_from_cookies(
                        after_cookies,
                        preferred_cookie_name,
                    )
                ),
                response_body=debug_body,
            )
            apparent_success = bool(debug_engine["success"])
            redirect_away_from_login = bool(
                debug_engine["redirect_away_from_login"]
            )

            # A session identifier that remains identical across the
            # authentication boundary is not, by itself, proof of session
            # hijacking or session fixation.  It is, however, a material
            # condition that warrants controlled session-replay testing.
            potential_session_hijacking = bool(
                apparent_success
                and comparison["preferred_name"]
                and not comparison["preferred_changed"]
                and comparison["preferred_before"]
                and comparison["preferred_after"]
            )

            print()
            print("=" * 72)
            print(" DEBUG LOGIN ASSESSMENT")
            print("=" * 72)
            print(f"POST captured          : YES")
            print(f"POST response          : {post_status or 'unknown'}")
            print(
                "Redirect/navigation    : "
                + ("YES" if redirect_away_from_login or location else "NO")
            )
            print(
                "Preferred cookie change: "
                + (
                    "YES"
                    if comparison["preferred_changed"]
                    else "NO"
                )
            )
            print(
                "Authentication outcome : "
                + str(debug_engine["outcome"])
            )
            print(
                "Post-login verification: "
                + ("PASS" if debug_engine["success"] else "FAIL/REVIEW")
            )
            if debug_engine.get("failure_markers"):
                print(
                    "Failure indicators      : "
                    + ", ".join(debug_engine["failure_markers"])
                )
            print(
                "Potential session hijacking: "
                + (
                    "REVIEW - session identifier tidak berubah setelah login"
                    if potential_session_hijacking
                    else "NOT OBSERVED"
                )
            )
            if potential_session_hijacking:
                print(
                    "[REVIEW] Session/cookie yang sama sebelum dan sesudah "
                    "authentication berpotensi dapat direplay jika diperoleh "
                    "oleh pihak lain. Lakukan controlled session-replay test "
                    "untuk mengonfirmasi; ini BUKAN finding otomatis."
                )
            print()
            print(
                "[INFO] POST ditangkap berdasarkan action form login yang dirender "
                "oleh aplikasi; bukan asumsi endpoint /login."
            )
            print(
                "[INFO] Authentication outcome berasal dari outcome engine "
                "multi-signal; mode debug tidak membuat session record."
            )
            print(
                "[INFO] Tidak ada session yang disimpan ke session.yaml "
                "dalam mode --debug-login."
            )

            return {
                "success": apparent_success,
                "authentication_outcome": debug_engine["outcome"],
                "mode": "debug-browser",
                "debug_only": True,
                "post_captured": True,
                "potential_session_hijacking": potential_session_hijacking,
                "requires_review": bool(
                    potential_session_hijacking or debug_engine.get("requires_review")
                ),
                "authentication_engine": debug_engine,
                "human_interaction_required": bool(challenge.get("detected")),
                "human_interaction": challenge,
                "login_post": {
                    "method": login_post_request.method,
                    "url": login_post_request.url,
                    "post_fields": safe_fields,
                    "status": post_status,
                    "location": location,
                    "response_url": (
                        login_post_response.url
                        if login_post_response is not None
                        else ""
                    ),
                },
                "navigation": navigation_urls,
                "current_url": page.url,
                "cookie_before": before_cookies,
                "cookie_after": after_cookies,
                "cookie_comparison": comparison,
                "reason": (
                    "Authentication outcome SUCCESS dan post-login state "
                    "terverifikasi."
                    if apparent_success
                    else (
                        "Authentication outcome "
                        + str(debug_engine.get("outcome"))
                        + ": "
                        + "; ".join(debug_engine.get("reasons") or [])
                    )
                ),
            }
        finally:
            browser.close()


def capture_authorized_session(
    base_url: str,
    username: str,
    password: str,
    preferred_cookie_name: str,
    timeout: int,
    browser_wait: int,
) -> dict[str, Any]:
    """HTTP-first authentication; visible browser only when human interaction is required."""
    login_url = login_url_from_target(base_url)

    print(f"[STEP] Login URL        : {login_url}")
    print("[STEP] Authentication  : HTTP automatic-first")

    result = automatic_http_authentication(
        login_url=login_url,
        username=username,
        password=password,
        preferred_cookie_name=preferred_cookie_name,
        timeout=timeout,
    )

    if result.get("success"):
        print(
            "[PASS] Login otomatis berhasil; "
            "authentication outcome = SUCCESS."
        )
        return result

    if result.get("human_interaction_required"):
        print("[INFO] Human interaction terdeteksi; berpindah ke Playwright browser.")
        return browser_authentication(
            login_url=login_url,
            username=username,
            password=password,
            preferred_cookie_name=preferred_cookie_name,
            timeout=timeout,
            browser_wait=browser_wait,
        )

    return result


def record_authentication_state(
    data: dict[str, Any],
    *,
    attempted: bool,
    mode: str,
    human_required: bool,
    credentials_available: Optional[bool],
    reason: str,
) -> None:
    summary = data.setdefault("summary", {})
    source_status = data.setdefault("source_status", {})

    summary["authentication_attempted"] = bool(attempted)
    summary["authentication_mode"] = mode
    summary["human_interaction_required"] = bool(human_required)
    summary["valid_credentials_available"] = credentials_available
    source_status["authentication"] = "completed" if attempted else "not-tested"

    if reason:
        assessment = data.setdefault("assessment", {})
        existing = str(assessment.get("note") or "").strip()
        assessment["note"] = (
            f"{existing} {reason}".strip()
            if existing
            else reason
        )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_version(_: argparse.Namespace) -> int:
    print(f"BrebesKab-CSIRT-Tools session.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print(
        "Method   : authentication outcome engine + authorized session + "
        "cookie/security attribute + bounded reuse/invalidation assessment"
    )
    print(
        "Storage  : encrypted session value using project Fernet key"
    )
    print(
        "Mode     : HTTP automatic-first; Playwright browser when human interaction is required"
    )
    print(
        "Debug    : --debug-login traces POST/redirect/cookie before-after without saving"
    )
    print(
        "CVE      : secondary correlation only; version match != vulnerability"
    )
    return 0


def cmd_init(_: argparse.Namespace) -> int:
    context = active_context()
    verify_encryption_key()

    hostname, base_url = target_from_context()

    path = session_file()
    if path.exists():
        data = load_artifact()
        ensure_project_match(data)

        # Non-destructive schema-compatible refresh for an existing artifact.
        # This keeps existing sessions intact while bringing tool metadata and
        # newly introduced authentication status fields to the current script.
        data.setdefault("tool", {})["version"] = SCRIPT_VERSION
        # Keep the canonical toolchain synchronized for existing artifacts.
        # This is non-destructive and does not alter stored session records.
        toolchain = data.setdefault("toolchain", {})
        mandatory = toolchain.setdefault("mandatory", [])
        if "preparation.account" in mandatory:
            mandatory.remove("preparation.account")
        if "BeautifulSoup" not in mandatory:
            mandatory.append("BeautifulSoup")
        if "accounts.yaml" not in mandatory:
            mandatory.append("accounts.yaml")

        source_status = data.setdefault("source_status", {})
        source_status.setdefault("authentication", "not-tested")
        summary = data.setdefault("summary", {})
        summary.setdefault("authentication_attempted", False)
        summary.setdefault("authentication_mode", "not-tested")
        summary.setdefault("human_interaction_required", False)
        summary.setdefault("valid_credentials_available", None)

        save_artifact(data)

        print("[PASS] Authentication Session Management sudah diinisialisasi.")
        print(f"PROJECT : {context.project_id}")
        print(f"TARGET  : {hostname}")
        print(f"FILE    : {path}")
        return 0

    data = canonical_empty_artifact(context)
    data["target"].update({
        "hostname": hostname,
        "url": base_url,
        "environment": str(
            (load_scope_baseline().get("scope") or {}).get(
                "environment", ""
            )
        ),
        "assessment_type": str(
            (load_scope_baseline().get("scope") or {}).get(
                "assessment_type", ""
            )
        ),
        "scope_id": str(
            ((load_scope_baseline().get("scope") or {}).get("in_scope") or [{}])[0].get(
                "scope_id", ""
            )
            if isinstance(
                ((load_scope_baseline().get("scope") or {}).get("in_scope") or [{}])[0],
                dict,
            )
            else ""
        ),
    })
    data["source_status"] = {
        "scope": "completed",
        "account": "not-tested",
        "encryption_key": "completed",
    }
    save_artifact(data)

    print("[PASS] Authentication Session Management berhasil diinisialisasi.")
    print(f"PROJECT : {context.project_id}")
    print(f"TARGET  : {hostname}")
    print(f"FILE    : {path}")
    return 0


def discover_session_cookie_names(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Discover cookie names from an in-scope unauthenticated HTTP response.

    This is discovery only: it never authenticates, never bypasses a challenge,
    and never logs cookie values. A CSRF/remember/tracking cookie is not treated
    as an authenticated session merely because it is present.
    """
    response_meta: dict[str, Any] = {
        "url": base_url,
        "method": "GET",
        "status_code": None,
        "human_interaction_required": False,
        "cookies": [],
    }

    try:
        response = requests.get(
            base_url,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise SessionError(
            f"Auto discovery session cookie gagal: {exc}"
        ) from exc

    response_meta["status_code"] = response.status_code
    response_meta["headers"] = safe_headers(response)
    response_meta["body"] = response_body_info(response)

    cookies = cookie_attributes_from_response(response)
    response_meta["cookies"] = cookies

    csrf_tokens = (
        "csrf", "xsrf", "csrf_token", "csrf-cookie", "token"
    )
    non_session_names = (
        "remember", "tracking", "analytics", "cookieconsent",
        "consent", "locale", "language", "theme"
    )

    candidates: list[dict[str, Any]] = []
    for item in cookies:
        name = str(item.get("name", "")).strip()
        lower = name.lower()
        if not name:
            continue

        score = 0
        reasons: list[str] = []
        if any(token in lower for token in csrf_tokens):
            score -= 100
            reasons.append("csrf-or-token-like")
        if any(token in lower for token in non_session_names):
            score -= 50
            reasons.append("non-session-like")
        if lower in {"phpsessid", "laravel_session", "ci_session", "session", "sid", "jsessionid"}:
            score += 100
            reasons.append("known-session-name")
        if "session" in lower:
            score += 40
            reasons.append("contains-session")
        if lower.endswith("_session") or lower.endswith("-session"):
            score += 30
            reasons.append("session-suffix")
        if item.get("httponly"):
            score += 10
            reasons.append("httponly")
        if item.get("secure"):
            score += 5
            reasons.append("secure")

        candidate = dict(item)
        candidate["score"] = score
        candidate["reasons"] = reasons
        candidate["classification"] = (
            "session-candidate" if score > 0 else "non-session-cookie"
        )
        candidates.append(candidate)

    candidates.sort(key=lambda x: (x.get("score", -999), x.get("name", "")), reverse=True)
    return candidates, response_meta


def cmd_add(args: argparse.Namespace) -> int:
    context = active_context()
    verify_encryption_key()

    account = validate_account(args.account_id)
    account_id = str(account.get("account_id", args.account_id))

    data = load_artifact()
    ensure_project_match(data)
    records = session_records(data)

    session_type = args.type.lower()
    if session_type not in {"cookie", "header"}:
        raise SessionError("Session type harus 'cookie' atau 'header'.")

    hostname, base_url = target_from_context()
    name = str(args.name or "").strip()

    print("=" * 72)
    print(" Add Authorized Session")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"Account ID : {account_id}")
    print(f"Target     : {base_url}")
    print(f"Type       : {session_type}")
    print()

    # If no valid credentials are available, do not fabricate a session and do
    # not fail the checklist artifact. The assessment remains not-tested.
    try:
        username, password = get_authorized_credentials(account_id)
        credentials_available = True
    except SessionError as exc:
        credentials_available = False
        record_authentication_state(
            data,
            attempted=False,
            mode="not-tested",
            human_required=False,
            credentials_available=False,
            reason=(
                "Valid username/password tidak tersedia untuk test account. "
                "Authenticated session acquisition tidak dilakukan; "
                "assessment tetap not-tested."
            ),
        )
        data["source_status"]["account"] = "not-available"
        data["checklist"]["status"] = "completed"
        save_artifact(data)

        print("[WARN] Credential valid tidak tersedia.")
        print(f"[WARN] {exc}")
        print(
            "[PASS] Session Management artifact tetap valid; "
            "authenticated session assessment berstatus not-tested."
        )
        print(f"FILE     : {session_file()}")
        return 0

    # Explicit interactive debug mode:
    # - does not perform automatic HTTP POST;
    # - does not click Login;
    # - fills the authorized credentials;
    # - waits for the human to complete challenge/click Login;
    # - captures the actual POST, response, navigation and cookie changes;
    # - never persists the debug session value to session.yaml/evidence.
    if args.debug_login:
        preferred_name = name
        if not preferred_name and session_type == "cookie":
            candidates, _ = discover_session_cookie_names(
                base_url,
                args.timeout,
            )
            session_candidates = [
                item
                for item in candidates
                if item.get("classification") == "session-candidate"
            ]
            if session_candidates:
                preferred_name = str(
                    session_candidates[0].get("name") or ""
                )
                print(
                    f"[PASS] Auto discovery menemukan kandidat session cookie: "
                    f"{preferred_name}"
                )

        try:
            debug_result = debug_login_browser(
                login_url=login_url_from_target(base_url),
                username=username,
                password=password,
                preferred_cookie_name=preferred_name,
                timeout=args.timeout,
                browser_wait=args.browser_wait,
            )
        finally:
            username = ""
            password = ""

        print()
        print("[PASS] Debug login trace selesai.")
        print("[INFO] Tidak ada session S-xxx yang dibuat.")
        print("[INFO] session.yaml tidak diubah oleh mode --debug-login.")
        return 0

    preferred_name = name
    if not preferred_name and session_type == "cookie":
        candidates, discovery_meta = discover_session_cookie_names(
            base_url,
            args.timeout,
        )
        session_candidates = [
            item for item in candidates
            if item.get("classification") == "session-candidate"
        ]
        if session_candidates:
            preferred_name = str(session_candidates[0].get("name") or "")
            print(
                f"[PASS] Auto discovery menemukan kandidat session cookie: "
                f"{preferred_name}"
            )
        else:
            print(
                "[INFO] Belum ada session cookie pada GET awal; "
                "nama cookie akan dideteksi setelah authentication."
            )

    result = capture_authorized_session(
        base_url=base_url,
        username=username,
        password=password,
        preferred_cookie_name=preferred_name,
        timeout=args.timeout,
        browser_wait=args.browser_wait,
    )

    # Never retain credential plaintext beyond this point.
    username = ""
    password = ""

    record_authentication_state(
        data,
        attempted=True,
        mode=str(result.get("mode") or "unknown"),
        human_required=bool(result.get("human_interaction_required")),
        credentials_available=credentials_available,
        reason=str(result.get("reason") or ""),
    )

    if not result.get("success"):
        data["source_status"]["account"] = "completed"
        data["checklist"]["status"] = "completed"
        outcome = str(
            result.get("authentication_outcome")
            or (result.get("authentication_engine") or {}).get("outcome")
            or AUTH_OUTCOME_UNCONFIRMED
        )
        requires_review = outcome == AUTH_OUTCOME_UNCONFIRMED
        data["assessment"] = {
            "result": "review" if requires_review else "not-tested",
            "finding": False,
            "requires_review": requires_review,
            "note": (
                f"Authentication outcome: {outcome}. "
                "Authenticated session tidak disimpan. "
                "Ini bukan bukti authentication/session vulnerability."
            ),
        }
        data["summary"]["requires_review"] = requires_review
        data["summary"]["finding"] = False
        save_artifact(data)

        print("[WARN] Authenticated session belum berhasil diperoleh.")
        print(
            "Authentication outcome : "
            + str(
                result.get("authentication_outcome")
                or (result.get("authentication_engine") or {}).get("outcome")
                or AUTH_OUTCOME_UNCONFIRMED
            )
        )
        print(f"[INFO] Reason   : {result.get('reason', '-')}")
        print("[INFO] Session record tidak dibuat.")
        print(f"FILE       : {session_file()}")
        return 0

    selected = result.get("selected_cookie") or {}
    session_value = str(result.get("session_value") or "")
    if session_type == "cookie":
        if not session_value:
            raise SessionError(
                "Authentication berhasil tetapi nilai session cookie tidak tersedia."
            )
        detected_name = str(selected.get("name") or preferred_name).strip()
        if not detected_name:
            raise SessionError(
                "Authentication berhasil tetapi nama session cookie tidak dapat ditentukan."
            )
        name = detected_name
    else:
        # Header mode remains supported as an explicit/manual mode. Browser/HTTP
        # capture is cookie-oriented because authenticated web sessions are
        # normally represented by cookies.
        raise SessionError(
            "Automatic/browser session capture saat ini menghasilkan cookie. "
            "Gunakan --type cookie untuk authenticated web session."
        )

    encrypted = encrypt_session_value(session_value)
    session_value = ""

    session_id = next_session_id(records)
    auth: dict[str, Any] = {
        "type": "cookie",
        "name": name,
        "value_encrypted": encrypted,
        "path": str(selected.get("path") or args.path or "/"),
        "domain": str(selected.get("domain") or args.domain or hostname),
        "secure": bool(selected.get("secure")),
        "httponly": bool(
            selected.get("httpOnly", selected.get("httponly", False))
        ),
        "samesite": selected.get("sameSite", selected.get("samesite")),
    }

    record = {
        "session_id": session_id,
        "account_id": account_id,
        "status": "active",
        "target": {
            "hostname": hostname,
            "url": base_url,
        },
        "authentication": {
            **auth,
            "outcome": str(
                result.get("authentication_outcome")
                or (result.get("authentication_engine") or {}).get("outcome")
                or AUTH_OUTCOME_SUCCESS
            ),
            "post_login_url": str(
                result.get("post_login_url")
                or result.get("url_after_login")
                or ""
            ),
        },
        "source": {
            "method": (
                "authorized-browser"
                if result.get("mode") == "browser"
                else "authorized-automation"
            ),
            "human_interaction": bool(
                result.get("human_interaction_required")
            ),
            "discovery": {
                "mode": str(result.get("mode") or "unknown"),
                "selected_name": name,
                "url": login_url_from_target(base_url),
                "human_interaction": result.get("human_interaction") or {},
            },
        },
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }

    records.append(record)
    data["sessions"] = records
    data["source_status"]["account"] = "completed"
    data["source_status"]["encryption_key"] = "completed"
    data["checklist"]["status"] = "completed"
    potential_session_hijacking = bool(
        result.get("potential_session_hijacking")
    )
    requires_review = bool(
        result.get("requires_review")
        or potential_session_hijacking
    )

    data["assessment"] = {
        "result": "review" if requires_review else "pass",
        "finding": False,
        "requires_review": requires_review,
        "note": (
            "Authorized authenticated session captured successfully. "
            "Session value is encrypted at rest."
            + (
                " Session identifier tidak berubah setelah authentication; "
                "controlled session-replay diperlukan untuk konfirmasi."
                if potential_session_hijacking
                else ""
            )
        ),
    }
    data["summary"]["requires_review"] = requires_review
    data["summary"]["finding"] = False
    data["summary"]["sessions_selected"] = len(records)
    save_artifact(data)

    print()
    print(f"[PASS] Session {session_id} berhasil ditangkap dan disimpan.")
    print(f"TYPE     : cookie")
    print(f"NAME     : {name}")
    print("VALUE    : [ENCRYPTED]")
    print(f"MODE     : {result.get('mode', '-')}")
    print(
        "HUMAN    : "
        f"{bool(result.get('human_interaction_required'))}"
    )
    print(f"FILE     : {session_file()}")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    data = load_artifact()
    ensure_project_match(data)

    records = session_records(data)

    print("=" * 72)
    print(" Authentication Sessions")
    print("=" * 72)
    print(f"Project ID : {active_context().project_id}")
    print(f"Total      : {len(records)}")
    print()

    if not records:
        print("[INFO] Belum ada session.")
        return 0

    for record in records:
        auth = record.get("authentication") or {}
        print(
            f"{record.get('session_id', '-'):8} "
            f"{record.get('account_id', '-'):10} "
            f"{auth.get('type', '-'):8} "
            f"{auth.get('name', '-'):20} "
            f"{record.get('status', '-')}"
        )

    return 0


def cmd_show(args: argparse.Namespace) -> int:
    data = load_artifact()
    ensure_project_match(data)
    record = find_session(data, args.session_id)

    public = public_session_record(record)

    print("=" * 72)
    print(" Authentication Session")
    print("=" * 72)
    print(f"Session ID : {public.get('session_id', '-')}")
    print(f"Account ID : {public.get('account_id', '-')}")
    print(f"Status     : {public.get('status', '-')}")
    print()
    print("Authentication:")
    for key, value in (public.get("authentication") or {}).items():
        if key == "value_encrypted":
            print(f"  {key:16}: [ENCRYPTED]")
        else:
            print(f"  {key:16}: {value}")

    print()
    print(f"Created    : {public.get('created_at', '-')}")
    print(f"Updated    : {public.get('updated_at', '-')}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    data = load_artifact()
    ensure_project_match(data)
    record = find_session(data, args.session_id)

    target_url = validate_target_url(args.url)

    hostname = str(
        (record.get("target") or {}).get("hostname")
        or urlparse(target_url).hostname
        or ""
    )

    print("[STEP] Session Management analysis...")
    print(f"PROJECT : {active_context().project_id}")
    print(f"SESSION : {record.get('session_id')}")
    print(f"ACCOUNT : {record.get('account_id')}")
    print(f"TARGET  : {target_url}")
    print()

    auth = record.get("authentication") or {}
    if not auth.get("value_encrypted"):
        raise SessionError("Session value terenkripsi belum tersedia.")

    session = build_cookie_session(record)

    try:
        response = session.get(
            target_url,
            timeout=args.timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        raise SessionError(
            f"Authenticated session request gagal: {exc}"
        ) from exc

    body = response_body_info(response)

    reuse_result = {
        "session_id": record.get("session_id"),
        "account_id": record.get("account_id"),
        "url": target_url,
        "status_code": response.status_code,
        "location": response.headers.get("Location", ""),
        "authenticated_indication": response.status_code not in {401, 403},
        "headers": safe_headers(response),
        **body,
        "session_value_logged": False,
        "timestamp": utc_now(),
    }

    # Cookie attributes are observed from a fresh response as well as
    # metadata captured by add/capture workflows.
    cookie_results = cookie_attributes_from_response(response)

    data["results"]["sessions_selected"] = 1
    data["results"]["reuse"] = [reuse_result]
    data["results"]["cookie_security"] = cookie_results
    data["summary"]["sessions_selected"] = 1
    data["summary"]["reuse_tested"] = 1
    data["summary"]["authenticated_access_observed"] = (
        1 if reuse_result["authenticated_indication"] else 0
    )
    data["summary"]["requires_review"] = False
    data["summary"]["finding"] = False

    data["assessment"] = {
        "result": "pass" if reuse_result["authenticated_indication"] else "not-authenticated",
        "finding": False,
        "requires_review": False,
        "note": (
            "Session reuse tested against an authorized target URL. "
            "A non-401/403 response is evidence of access, not proof that "
            "authorization controls are correct."
        ),
    }

    data["target"]["hostname"] = hostname
    data["target"]["url"] = target_url
    data["checklist"]["status"] = "completed"

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "project_id": active_context().project_id,
        "checklist": CHECKLIST_ID,
        "generated_at": utc_now(),
        "session_reuse": reuse_result,
        "cookie_security": cookie_results,
        "errors": [],
    }

    save_json(evidence_file(), evidence)
    save_artifact(data)

    print("[PASS] Session Management analysis completed.")
    print(f"STATUS          : {response.status_code}")
    print(
        "AUTHENTICATED   : "
        f"{reuse_result['authenticated_indication']}"
    )
    print("SESSION LOGGED  : False")
    print(f"FILE            : {session_file()}")
    print(f"EVIDENCE        : {evidence_file()}")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    data = load_artifact()
    ensure_project_match(data)
    records = session_records(data)

    active = sum(
        1 for item in records
        if str(item.get("status", "")).lower() == "active"
    )
    revoked = sum(
        1 for item in records
        if str(item.get("status", "")).lower() == "revoked"
    )

    print("=" * 72)
    print(" Authentication Session Status")
    print("=" * 72)
    print(f"Project ID : {active_context().project_id}")
    print(f"Total      : {len(records)}")
    print(f"Active     : {active}")
    print(f"Revoked    : {revoked}")

    if active:
        print("[PASS] Authorized session tersedia.")
    else:
        print("[WARN] Belum ada authorized session aktif.")

    return 0


def cmd_verify(_: argparse.Namespace) -> int:
    path = session_file()
    data = load_artifact()
    context = ensure_project_match(data)

    if str(data.get("schema_version")) != SCHEMA_VERSION:
        raise SessionError(
            f"schema_version harus {SCHEMA_VERSION}; "
            f"found {data.get('schema_version')}"
        )

    tool = data.get("tool") or {}
    if tool.get("script") != "session.py":
        raise SessionError("tool.script harus session.py.")
    if tool.get("version") != SCRIPT_VERSION:
        raise SessionError(
            f"tool.version tidak sesuai script. "
            f"Expected {SCRIPT_VERSION}; Found {tool.get('version')}"
        )

    checklist = data.get("checklist") or {}
    if checklist.get("id") != CHECKLIST_ID:
        raise SessionError("checklist.id tidak sesuai.")
    if checklist.get("name") != CHECKLIST_NAME:
        raise SessionError("checklist.name tidak sesuai.")
    if checklist.get("phase") != PHASE_NAME:
        raise SessionError("checklist.phase tidak sesuai.")

    target = data.get("target") or {}
    if target.get("scope_reference") != "01-preparation/scope/scope.yaml":
        raise SessionError("target.scope_reference tidak canonical.")
    if target.get("authorized_ports") != [80, 443]:
        raise SessionError("target.authorized_ports harus [80, 443].")

    methodology = data.get("methodology") or {}
    if methodology.get("session_value_plaintext_in_artifact") is not False:
        raise SessionError(
            "methodology.session_value_plaintext_in_artifact harus false."
        )
    if methodology.get("session_secret_encryption") != (
        "project Fernet key via preparation.secrets"
    ):
        raise SessionError("Metode enkripsi session tidak canonical.")

    baseline = data.get("baseline") or {}
    if not baseline.get("account_source"):
        raise SessionError("baseline.account_source wajib ada.")
    if not baseline.get("encryption_key_source"):
        raise SessionError("baseline.encryption_key_source wajib ada.")

    toolchain = data.get("toolchain") or {}
    mandatory = toolchain.get("mandatory") or []
    for required in (
        "Python",
        "requests",
        "PyYAML",
        "accounts.yaml",
        "preparation.secrets",
        "preparation.context",
        "BeautifulSoup",
    ):
        if required not in mandatory:
            raise SessionError(
                f"toolchain.mandatory tidak memuat {required}."
            )

    summary = data.get("summary") or {}
    authentication_status = str(
        data.get("source_status", {}).get("authentication", "not-tested")
    )
    if authentication_status not in {"not-tested", "completed"}:
        raise SessionError(
            "source_status.authentication harus not-tested atau completed."
        )

    records = session_records(data)
    if authentication_status == "not-tested" and not records:
        # No valid credential/session is an allowed not-tested state. This is
        # not a schema failure and must not make verify fail.
        summary.setdefault("authentication_attempted", False)
        summary.setdefault("valid_credentials_available", None)
        data["assessment"] = {
            **(data.get("assessment") or {}),
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
        }
    for record in records:
        sid = str(record.get("session_id", ""))
        if not SESSION_ID_RE.match(sid):
            raise SessionError(f"session_id tidak valid: {sid}")

        if not record.get("account_id"):
            raise SessionError(f"{sid}: account_id wajib ada.")

        auth = record.get("authentication")
        if not isinstance(auth, dict):
            raise SessionError(f"{sid}: authentication wajib mapping.")

        if not auth.get("name"):
            raise SessionError(f"{sid}: authentication.name wajib ada.")

        encrypted = auth.get("value_encrypted")
        if not isinstance(encrypted, str) or not encrypted:
            raise SessionError(
                f"{sid}: value_encrypted wajib berisi ciphertext."
            )

        if encrypted == "[REDACTED]":
            raise SessionError(
                f"{sid}: value_encrypted tidak boleh berupa [REDACTED]."
            )

        # Verify the ciphertext without exposing plaintext.
        try:
            plaintext = decrypt_session_value(encrypted)
            if not plaintext:
                raise SessionError(f"{sid}: ciphertext mendekripsi ke nilai kosong.")
            plaintext = ""
        except SessionError:
            raise

    evidence = data.get("evidence") or {}
    if evidence.get("session_probes") != (
        "05-authentication/session/evidence/session-probes.json"
    ):
        raise SessionError("evidence.session_probes tidak canonical.")

    if not isinstance(data.get("errors"), list):
        raise SessionError("errors harus berupa list.")

    notes = data.get("notes")
    if not isinstance(notes, list):
        raise SessionError("notes harus berupa list.")

    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SessionError("session.yaml menggunakan UTF-8 BOM.")
    raw.decode("utf-8")

    verify_encryption_key()

    print("[PASS] Session Management memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {context.project_id}")
    print(f"[PASS] File      : {path}")
    print(f"[PASS] Sessions  : {len(records)}")
    if not records:
        print(
            "[PASS] Authenticated session: belum tersedia; "
            "status assessment = not-tested."
        )
        print(
            "[PASS] Valid credential requirement: tidak menjadi syarat "
            "untuk verify canonical artifact."
        )
    else:
        print("[PASS] Session values: encrypted and decryptable.")
    print("[PASS] Encoding  : UTF-8 tanpa BOM")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    data = load_artifact()
    ensure_project_match(data)
    records = session_records(data)

    wanted = args.session_id.upper()
    found = False
    new_records: list[dict[str, Any]] = []

    for record in records:
        if str(record.get("session_id", "")).upper() == wanted:
            found = True
            continue
        new_records.append(record)

    if not found:
        raise SessionError(f"Session {args.session_id} tidak ditemukan.")

    data["sessions"] = new_records
    save_artifact(data)

    print(f"[PASS] Session {args.session_id.upper()} dihapus dari artifact.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools - Authentication Session Management"
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version", help="Tampilkan versi dan metodologi.")

    sub.add_parser("init", help="Inisialisasi canonical session.yaml.")

    add = sub.add_parser(
        "add",
        help="Simpan authorized session value secara terenkripsi.",
    )
    add.add_argument("--account-id", required=True)
    add.add_argument(
        "--type",
        choices=("cookie", "header"),
        default="cookie",
    )
    add.add_argument(
        "--name",
        default="",
        help=(
            "Nama session cookie/header. Jika tidak diberikan, session.py "
            "melakukan auto discovery terhadap cookie pada response GET target."
        ),
    )
    add.add_argument("--path", default="/")
    add.add_argument("--domain", default="")
    add.add_argument(
        "--header-name",
        default="Authorization",
    )
    add.add_argument(
        "--source-method",
        choices=("manual-login", "authorized-automation"),
        default="manual-login",
    )
    add.add_argument(
        "--human-interaction",
        action="store_true",
        help="Tandai session diperoleh setelah human interaction.",
    )
    add.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Timeout request/login HTTP dalam detik.",
    )
    add.add_argument(
        "--browser-wait",
        type=int,
        default=300,
        help=(
            "Maksimum waktu browser menunggu human interaction/login "
            "(default 300 detik)."
        ),
    )
    add.add_argument(
        "--debug-login",
        action="store_true",
        help=(
            "Mode debug interaktif: buka login, tampilkan cookie sebelum "
            "login, isi credential otomatis, jangan klik Login otomatis, "
            "tangkap POST/response/redirect, lalu tampilkan cookie sesudah "
            "login. Tidak menyimpan session ke artifact."
        ),
    )

    sub.add_parser("list", help="Daftar session tanpa menampilkan secret.")

    show = sub.add_parser("show", help="Tampilkan metadata session.")
    show.add_argument("session_id")

    analyze = sub.add_parser(
        "analyze",
        help="Uji bounded reuse authenticated session.",
    )
    analyze.add_argument("--session-id", required=True)
    analyze.add_argument(
        "--url",
        required=True,
        help="Protected URL dalam scope yang ingin diuji.",
    )
    analyze.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
    )

    sub.add_parser("status", help="Tampilkan status session.")

    sub.add_parser(
        "verify",
        help="Validasi canonical artifact dan decryptability ciphertext.",
    )

    remove = sub.add_parser(
        "remove",
        help="Hapus session record dari artifact.",
    )
    remove.add_argument("session_id")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        command = args.command
        if command == "version":
            return cmd_version(args)
        if command == "init":
            return cmd_init(args)
        if command == "add":
            return cmd_add(args)
        if command == "list":
            return cmd_list(args)
        if command == "show":
            return cmd_show(args)
        if command == "analyze":
            return cmd_analyze(args)
        if command == "status":
            return cmd_status(args)
        if command == "verify":
            return cmd_verify(args)
        if command == "remove":
            return cmd_remove(args)

        parser.error(f"Command tidak dikenal: {command}")
        return 2

    except KeyboardInterrupt:
        print("\n[WARN] Dibatalkan oleh pengguna.")
        return 130
    except SessionError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] SESSION ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
