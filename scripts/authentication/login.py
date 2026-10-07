#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Authentication Login

Checklist: 7-002 Authentication Login

Purpose
-------
Controlled authentication testing using explicitly authorized test accounts.
The script supports:
  * discovery of the login form with requests/BeautifulSoup;
  * detection of human-interaction challenges such as Cloudflare Turnstile;
  * one valid-login attempt using a password supplied interactively at runtime;
  * a bounded failed-login sequence (default: 5 attempts) using one authorized
    account and a generated wrong password;
  * evidence collection without writing passwords to logs/artifacts;
  * conservative assessment of anti-automation controls.

Important boundary
------------------
This is NOT an unrestricted brute-force/password-cracking tool. It never uses
large password lists and never enumerates arbitrary usernames. Failed attempts
are limited to the explicitly selected authorized test account.

If the login flow requires human interaction (for example Cloudflare Turnstile
checkbox/challenge), the automated login-attempt test stops. No bypass is
attempted. For the anti-automation portion, human interaction is treated as a
PASS under the agreed assessment rule.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import string
import sys
import time
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

try:
    import requests
    import yaml
    from bs4 import BeautifulSoup
except ImportError as exc:  # pragma: no cover
    print(f"[FAIL] Dependency tidak tersedia: {exc}")
    raise SystemExit(1)

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:  # pragma: no cover
    sync_playwright = None
    PlaywrightTimeoutError = Exception


SCRIPT_VERSION = "1.0.8"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "7-002"
CHECKLIST_NAME = "Authentication Login"
PHASE = "07 Authentication"
DEFAULT_LOGIN_PATH = "/login"
DEFAULT_FAILED_ATTEMPTS = 5
DEFAULT_TIMEOUT = 15
MAX_FAILED_ATTEMPTS = 5
MAX_BODY_BYTES = 262144
BODY_SAMPLE_CHARS = 4000
USER_AGENT = "BrebesKab-CSIRT-Tools/7-002"

# Preparation account.py is the authoritative owner of the test-account
# registry and credential decryption. Do not duplicate its YAML/encryption
# interpretation here.
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

try:
    from preparation.account import (
        AccountError,
        get_account,
        list_accounts,
        get_account_credentials,
    )
except ImportError as exc:  # pragma: no cover
    print(f"[FAIL] Modul preparation.account tidak tersedia: {exc}")
    raise SystemExit(1)

STATUS_SUCCESS = "success"
STATUS_FAILED = "failed"
STATUS_BLOCKED = "blocked_by_human_interaction"
STATUS_NOT_TESTED = "not_tested"


class LoginError(RuntimeError):
    """Controlled login assessment error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_yaml(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(str(path))
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def dump_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            data,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def dump_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)


def project_root_from_script() -> Path:
    return Path(__file__).resolve().parents[2]


def runtime_context(repo_root: Path) -> dict[str, Any]:
    """Load canonical .runtime/active-project.yaml context."""
    active = repo_root / ".runtime" / "active-project.yaml"
    data = load_yaml(active)
    if not isinstance(data, dict):
        raise LoginError("Active project context bukan object YAML.")

    project_id = str(data.get("project_id") or data.get("id") or "").strip()
    raw_path = str(data.get("project_path") or "").strip()
    assessment_type = str(data.get("assessment_type") or "").strip()
    if not project_id:
        raise LoginError("project_id tidak ditemukan pada active-project.yaml.")
    if not raw_path:
        raise LoginError("project_path tidak ditemukan pada active-project.yaml.")
    if not assessment_type:
        raise LoginError("assessment_type tidak ditemukan pada active-project.yaml.")

    project_path = Path(raw_path)
    if not project_path.is_absolute():
        project_path = repo_root / project_path
    project_path = project_path.resolve()

    if not project_path.exists():
        raise LoginError(f"Project aktif tidak ditemukan: {project_path}")

    assessment = project_path / "assessment.yaml"
    if not assessment.exists():
        raise LoginError(f"assessment.yaml tidak ditemukan: {assessment}")

    assessment_data = load_yaml(assessment)
    if isinstance(assessment_data, dict):
        assessment_project_id = str(
            assessment_data.get("project_id")
            or assessment_data.get("id")
            or ""
        ).strip()
        if assessment_project_id and assessment_project_id != project_id:
            raise LoginError(
                "project_id active context tidak sama dengan assessment.yaml: "
                f"{project_id} != {assessment_project_id}"
            )

    return {
        "project_id": project_id,
        "project_path": project_path,
        "assessment_type": assessment_type,
        "active_context": active,
        "assessment": assessment,
        "assessment_data": assessment_data,
    }


def locate_scope(project_path: Path) -> Path:
    candidates = [
        project_path / "01-preparation" / "scope" / "scope.yaml",
        project_path / "01-preparation" / "scope" / "scope.yml",
    ]
    for path in candidates:
        if path.exists():
            return path
    raise LoginError("scope.yaml tidak ditemukan pada project aktif.")


def extract_scope(scope: dict[str, Any]) -> list[dict[str, Any]]:
    section = scope.get("scope", {})
    if isinstance(section, dict):
        items = section.get("in_scope", [])
    else:
        items = scope.get("in_scope", [])
    return items if isinstance(items, list) else []


def target_from_scope(scope: dict[str, Any]) -> dict[str, Any]:
    items = extract_scope(scope)
    for item in items:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or item.get("hostname") or "").strip()
        scope_type = str(item.get("type") or "").lower()
        if value and scope_type in {"domain", "hostname", "url"}:
            ports = item.get("ports") or item.get("authorized_ports") or [80, 443]
            ports = [int(p) for p in ports if str(p).isdigit()]
            if not ports:
                ports = [80, 443]
            if value.startswith("http://") or value.startswith("https://"):
                base_url = value.rstrip("/")
                hostname = urlparse(base_url).hostname or value
            else:
                hostname = value
                base_url = f"https://{value}"
            return {
                "scope_id": str(item.get("scope_id") or "IN-001"),
                "type": scope_type,
                "value": value,
                "hostname": hostname,
                "url": base_url,
                "authorized_ports": ports,
            }
    raise LoginError("Tidak ada domain/hostname in-scope yang dapat digunakan.")


def account_file(project_path: Path) -> Path:
    return project_path / "01-preparation" / "account" / "accounts.yaml"


def artifact_dir(project_path: Path) -> Path:
    return project_path / "07-authentication" / "login"


def artifact_file(project_path: Path) -> Path:
    return artifact_dir(project_path) / "login.yaml"


def evidence_file(project_path: Path) -> Path:
    return artifact_dir(project_path) / "evidence" / "login-probes.json"


def account_items(data: Any) -> list[dict[str, Any]]:
    """Compatibility helper for the canonical preparation account schema.

    The authoritative schema is owned by preparation/account.py:
      accounts:
        - account_id: TA-001
          credentials:
            username: <Fernet ciphertext>
            password: <Fernet ciphertext>

    This helper intentionally does not attempt to interpret encrypted
    credentials. Runtime credential resolution is delegated to account.py.
    """
    if not isinstance(data, dict):
        return []

    accounts = data.get("accounts", [])
    if not isinstance(accounts, list):
        return []

    return [item for item in accounts if isinstance(item, dict)]


def find_account_by_id(data: Any, requested_id: str) -> dict[str, Any] | None:
    """Find one account in the canonical accounts list."""
    requested = str(requested_id or "").strip().upper()
    if not requested:
        return None

    for item in account_items(data):
        if account_id(item).upper() == requested:
            return item

    return None


def account_id(item: dict[str, Any]) -> str:
    return str(item.get("account_id") or "").strip()


def account_role(item: dict[str, Any]) -> str:
    return str(item.get("role") or "other").strip().lower()


def account_status(item: dict[str, Any]) -> str:
    return str(item.get("status") or "").strip().lower()


def account_username(item: dict[str, Any]) -> str:
    """Return the runtime username resolved by preparation/account.py."""
    return str(item.get("_resolved_username") or "").strip()


def redact_username(username: str) -> str:
    if not username:
        return ""
    if len(username) <= 4:
        return "*" * len(username)
    return username[:2] + "*" * max(2, len(username) - 4) + username[-2:]


def select_accounts(
    project_path: Path,
    requested_id: str | None = None,
) -> list[dict[str, Any]]:
    """Select active accounts using preparation/account.py as source of truth.

    No YAML shape, credential field, or encryption key is guessed here.
    account.py owns:
      * accounts.yaml loading/validation;
      * account_id lookup;
      * active-status handling;
      * Fernet decryption via secrets.py.
    """
    del project_path  # Active project is already resolved by account.py.

    try:
        raw_accounts = list_accounts()
    except AccountError as exc:
        raise LoginError(f"Gagal membaca test account melalui account.py: {exc}") from exc

    if not raw_accounts:
        raise LoginError("Tidak ada test account pada accounts.yaml.")

    if requested_id:
        requested = str(requested_id).strip().upper()
        selected_raw = None

        for item in raw_accounts:
            if not isinstance(item, dict):
                continue
            if account_id(item).upper() == requested:
                selected_raw = item
                break

        if selected_raw is None:
            known_ids = [
                account_id(item)
                for item in raw_accounts
                if isinstance(item, dict) and account_id(item)
            ]
            known_text = ", ".join(known_ids[:20]) if known_ids else "-"
            raise LoginError(
                f"Account {requested_id} tidak ditemukan pada registry account.py. "
                f"Account IDs terdeteksi: {known_text}"
            )

        if account_status(selected_raw) != "active":
            raise LoginError(
                f"Account {requested_id} ditemukan tetapi statusnya "
                f"'{account_status(selected_raw) or '[kosong]'}', bukan active."
            )

        selected = [selected_raw]
    else:
        selected = [
            item
            for item in raw_accounts
            if isinstance(item, dict) and account_status(item) == "active"
        ]

    if not selected:
        raise LoginError("Tidak ada test account dengan status active.")

    resolved: list[dict[str, Any]] = []

    for item in selected:
        aid = account_id(item)
        if not aid:
            raise LoginError("Ada record test account tanpa account_id.")

        try:
            credentials = get_account_credentials(aid)
        except AccountError as exc:
            raise LoginError(
                f"Credential account {aid} tidak dapat dibaca/decrypt "
                f"melalui account.py: {exc}"
            ) from exc

        username = str(credentials.get("username") or "").strip()
        if not username:
            raise LoginError(
                f"Username account {aid} hasil decrypt kosong."
            )

        # Keep the canonical account metadata and attach the decrypted
        # username only in memory. Password is intentionally not attached.
        runtime_item = dict(item)
        runtime_item["_resolved_username"] = username
        resolved.append(runtime_item)

    return resolved


def resolve_account_credentials(account: dict[str, Any]) -> tuple[str, str]:
    """Resolve username/password through preparation/account.py only."""
    aid = account_id(account)
    if not aid:
        raise LoginError("Test account tidak memiliki account_id.")

    try:
        credentials = get_account_credentials(aid)
    except AccountError as exc:
        raise LoginError(
            f"Credential account {aid} tidak dapat dibaca/decrypt "
            f"melalui account.py: {exc}"
        ) from exc

    username = str(credentials.get("username") or "").strip()
    password = str(credentials.get("password") or "")

    if not username:
        raise LoginError(f"Username account {aid} hasil decrypt kosong.")
    if not password:
        raise LoginError(f"Password account {aid} hasil decrypt kosong.")

    return username, password


def random_wrong_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*_-+="
    return "PENTEST-INVALID-" + "".join(secrets.choice(alphabet) for _ in range(length))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def body_sample(response: requests.Response) -> tuple[str, bool]:
    raw = response.content[:MAX_BODY_BYTES]
    truncated = len(response.content) > MAX_BODY_BYTES
    text = raw.decode(response.encoding or "utf-8", errors="replace")
    return text[:BODY_SAMPLE_CHARS], truncated


def header_subset(headers: Any) -> dict[str, Any]:
    interesting = {
        "location",
        "content-type",
        "content-length",
        "server",
        "x-powered-by",
        "retry-after",
        "cf-ray",
        "cf-mitigated",
        "set-cookie",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    }
    result: dict[str, Any] = {}
    for key, value in headers.items():
        if key.lower() in interesting:
            if key.lower() == "set-cookie":
                result[key] = "[present]"
            else:
                result[key] = str(value)[:1000]
    return result


def response_fingerprint(response: requests.Response, body: str) -> str:
    normalized = "\n".join(
        [
            str(response.status_code),
            str(response.headers.get("Content-Type", "")),
            str(response.headers.get("Location", "")),
            str(len(response.content)),
            body[:4000],
        ]
    )
    return sha256_text(normalized)


def text_indicators(text: str) -> dict[str, bool]:
    lower = text.lower()
    return {
        "cloudflare_turnstile": bool(
            re.search(r"turnstile|challenges\.cloudflare\.com|cf-turnstile", lower)
        ),
        "captcha": bool(re.search(r"captcha|verify you are human", lower)),
        "login_error": bool(
            re.search(
                r"invalid|incorrect|salah|tidak valid|gagal login|password.*salah|username.*salah",
                lower,
            )
        ),
        "lockout": bool(
            re.search(r"locked|lockout|terkunci|akun.*blokir|account.*blocked", lower)
        ),
        "rate_limit": bool(
            re.search(r"too many|rate limit|terlalu banyak|coba lagi nanti", lower)
        ),
        "authenticated_marker": bool(
            re.search(r"logout|dashboard|sign out|selamat datang|welcome", lower)
        ),
    }


def detect_turnstile_html(html: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    scripts = [str(tag.get("src") or "") for tag in soup.find_all("script")]
    iframes = [str(tag.get("src") or "") for tag in soup.find_all("iframe")]
    classes = " ".join(str(tag.get("class") or "") for tag in soup.find_all(True))
    text = soup.get_text(" ", strip=True)
    joined = "\n".join(scripts + iframes + [classes, text, html[:200000]])
    indicators = text_indicators(joined)
    turnstile = indicators["cloudflare_turnstile"]
    human = turnstile or indicators["captcha"]
    return {
        "human_interaction_detected": human,
        "cloudflare_turnstile_detected": turnstile,
        "captcha_detected": indicators["captcha"],
        "iframe_count": len(iframes),
        "turnstile_script_detected": any("turnstile" in x.lower() for x in scripts),
        "turnstile_iframe_detected": any("cloudflare" in x.lower() for x in iframes),
    }


def discover_form(html: str, base_url: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        raise LoginError("Form login tidak ditemukan pada halaman login.")

    selected = None
    for form in forms:
        password = form.find("input", attrs={"type": re.compile("^password$", re.I)})
        if password:
            selected = form
            break
    selected = selected or forms[0]

    action = urljoin(base_url, str(selected.get("action") or base_url))
    method = str(selected.get("method") or "post").lower()
    fields: list[dict[str, Any]] = []
    for element in selected.find_all(["input", "button", "textarea", "select"]):
        name = str(element.get("name") or "").strip()
        if not name:
            continue
        field_type = str(element.get("type") or element.name).lower()
        fields.append(
            {
                "name": name,
                "type": field_type,
                "value_present": bool(element.get("value")),
            }
        )

    password_fields = [x for x in fields if x["type"] == "password"]
    text_fields = [
        x
        for x in fields
        if x["type"] in {"text", "email", "tel", "number"}
    ]
    csrf_fields = [
        x
        for x in fields
        if re.search(r"csrf|token|xsrf", x["name"], re.I)
    ]

    username_field = None
    if text_fields:
        preferred = [
            x for x in text_fields if re.search(r"user|login|email|phone|username|no.?hp", x["name"], re.I)
        ]
        username_field = (preferred or text_fields)[0]["name"]
    password_field = password_fields[0]["name"] if password_fields else None

    return {
        "action": action,
        "method": method,
        "field_count": len(fields),
        "fields": fields,
        "username_field": username_field,
        "password_field": password_field,
        "csrf_field_names": [x["name"] for x in csrf_fields],
    }


def redact_request_body(body: Any, sensitive_names: set[str]) -> str:
    """Redact sensitive form values while preserving actual field names/order."""
    if body is None:
        return ""

    if isinstance(body, bytes):
        text = body.decode("utf-8", errors="replace")
    else:
        text = str(body)

    # requests normally uses application/x-www-form-urlencoded for this form.
    # Preserve field names and structure while replacing sensitive values.
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
    except Exception:
        return "[REDACTED BODY]"

    redacted_pairs: list[tuple[str, str]] = []
    for name, value in pairs:
        if name.lower() in {x.lower() for x in sensitive_names}:
            redacted_pairs.append((name, "[REDACTED]"))
        else:
            redacted_pairs.append((name, value))

    return urlencode(redacted_pairs, doseq=True)


def request_audit(
    prepared: requests.PreparedRequest,
    data: dict[str, str],
    form: dict[str, Any],
) -> dict[str, Any]:
    """Build a safe audit record proving field mapping without exposing secrets."""
    username_field = str(form.get("username_field") or "")
    password_field = str(form.get("password_field") or "")
    csrf_fields = [
        str(x)
        for x in (form.get("csrf_field_names") or [])
        if str(x)
    ]

    sensitive_names = set(csrf_fields)
    if password_field:
        sensitive_names.add(password_field)

    # CSRF and password values are redacted. Username is retained for direct
    # mapping verification; this is not a password/secret.
    safe_fields: list[dict[str, Any]] = []
    for name, value in data.items():
        if name == password_field or name in sensitive_names:
            safe_value = "[REDACTED]"
        else:
            safe_value = str(value)
        source = "form-username-mapping" if name == username_field else (
            "form-password-mapping" if name == password_field else (
                "csrf-form-field" if name in csrf_fields else "form-field"
            )
        )
        safe_fields.append({
            "name": name,
            "value": safe_value,
            "source": source,
        })

    return {
        "method": prepared.method,
        "url": prepared.url,
        "content_type": prepared.headers.get("Content-Type", ""),
        "username_field": username_field,
        "password_field": password_field,
        "csrf_field_names": csrf_fields,
        "fields": safe_fields,
        "prepared_body_redacted": redact_request_body(
            prepared.body,
            sensitive_names | {password_field},
        ),
        "password_value_logged": False,
        "csrf_value_logged": False,
    }


def perform_request_audit_only(
    session: requests.Session,
    form: dict[str, Any],
    username: str,
    password: str,
    page_url: str,
    timeout: int,
    debug_request: bool = True,
) -> dict[str, Any]:
    """Prepare the login request for audit without sending the authentication POST.

    This intentionally mirrors the request construction used by request_login():
    it performs a fresh GET to obtain the current hidden fields/CSRF value, maps
    the discovered username/password fields, prepares the exact requests request,
    and stops before session.send(). No authentication attempt is made.
    """
    if not form.get("username_field") or not form.get("password_field"):
        raise LoginError(
            "Field username/password tidak dapat diidentifikasi secara aman."
        )

    response_get = session.get(
        page_url,
        allow_redirects=False,
        timeout=timeout,
    )
    soup = BeautifulSoup(response_get.text, "html.parser")
    forms = soup.find_all("form")

    selected = None
    for candidate in forms:
        if candidate.find(
            "input",
            attrs={"type": re.compile("^password$", re.I)},
        ):
            selected = candidate
            break

    if selected is None:
        selected = forms[0] if forms else None

    if selected is None:
        raise LoginError("Form login tidak ditemukan saat menyiapkan request audit.")

    data: dict[str, str] = {}

    # Keep this construction identical to request_login(): hidden/submit
    # values are copied from the current form, then username/password are
    # mapped to the discovered field names.
    for element in selected.find_all("input"):
        name = str(element.get("name") or "").strip()
        if not name:
            continue

        typ = str(element.get("type") or "text").lower()
        if typ in {"hidden", "submit"}:
            value = element.get("value")
            if value is not None:
                data[name] = str(value)

    data[form["username_field"]] = username
    data[form["password_field"]] = password

    if form["method"] == "get":
        prepared_request = requests.Request(
            "GET",
            form["action"],
            params=data,
        )
    else:
        prepared_request = requests.Request(
            "POST",
            form["action"],
            data=data,
        )

    prepared = session.prepare_request(prepared_request)
    audit = request_audit(prepared, data, form)

    # Explicit safety marker: this function never calls session.send(),
    # session.post(), or session.get() against the form action.
    audit["request_sent"] = False
    audit["authentication_attempt"] = False
    audit["audit_only"] = True
    audit["page_get_status"] = response_get.status_code
    audit["page_get_url"] = response_get.url

    if debug_request:
        print("[DEBUG] REQUEST AUDIT ONLY")
        print("  NO LOGIN REQUEST SENT")
        print(f"  PAGE GET STATUS : {response_get.status_code}")
        print(f"  METHOD          : {audit['method']}")
        print(f"  URL             : {audit['url']}")
        print(f"  CONTENT-TYPE    : {audit['content_type']}")
        print(f"  USERNAME FIELD  : {audit['username_field']}")
        print(f"  PASSWORD FIELD  : {audit['password_field']}")
        print(
            "  CSRF FIELDS     : "
            + (", ".join(audit["csrf_field_names"]) or "-")
        )
        print("  FORM FIELDS:")
        for field in audit["fields"]:
            print(
                f"    {field['name']} = {field['value']} "
                f"[{field['source']}]"
            )
        print(f"  PREPARED BODY   : {audit['prepared_body_redacted']}")
        print("  REQUEST SENT    : NO")
        print("  AUTH ATTEMPT    : NO")
        print("  PASSWORD LOGGED : NO")
        print("  CSRF LOGGED     : NO")

    return audit


def request_login(
    session: requests.Session,
    form: dict[str, Any],
    username: str,
    password: str,
    page_url: str,
    timeout: int,
    debug_request: bool = False,
) -> dict[str, Any]:
    if not form.get("username_field") or not form.get("password_field"):
        raise LoginError("Field username/password tidak dapat diidentifikasi secara aman.")

    data: dict[str, str] = {}
    # Preserve hidden fields and submit values discovered from the login form.
    for field in form["fields"]:
        if field["type"] in {"hidden", "submit"} and field.get("value_present"):
            # The actual value is intentionally not stored by discover_form.
            # Re-fetch the form to preserve hidden CSRF data in the caller.
            pass

    response_get = session.get(page_url, allow_redirects=False, timeout=timeout)
    soup = BeautifulSoup(response_get.text, "html.parser")
    forms = soup.find_all("form")
    selected = None
    for candidate in forms:
        if candidate.find("input", attrs={"type": re.compile("^password$", re.I)}):
            selected = candidate
            break
    if selected is None:
        selected = forms[0] if forms else None
    if selected is None:
        raise LoginError("Form login tidak ditemukan saat menyiapkan POST.")

    for element in selected.find_all("input"):
        name = str(element.get("name") or "").strip()
        if not name:
            continue
        typ = str(element.get("type") or "text").lower()
        if typ in {"hidden", "submit"}:
            value = element.get("value")
            if value is not None:
                data[name] = str(value)

    data[form["username_field"]] = username
    data[form["password_field"]] = password

    request_audit_data: dict[str, Any] | None = None
    started = time.perf_counter()
    try:
        # Prepare the exact request first so --debug-request can prove the
        # actual field mapping that requests is about to transmit.
        if form["method"] == "get":
            prepared_request = requests.Request(
                "GET",
                form["action"],
                params=data,
            )
        else:
            prepared_request = requests.Request(
                "POST",
                form["action"],
                data=data,
            )

        prepared = session.prepare_request(prepared_request)
        request_audit_data = request_audit(prepared, data, form)

        if debug_request:
            print("[DEBUG] LOGIN REQUEST")
            print(f"  METHOD          : {request_audit_data['method']}")
            print(f"  URL             : {request_audit_data['url']}")
            print(f"  CONTENT-TYPE    : {request_audit_data['content_type']}")
            print(f"  USERNAME FIELD  : {request_audit_data['username_field']}")
            print(f"  PASSWORD FIELD  : {request_audit_data['password_field']}")
            print(
                "  CSRF FIELDS     : "
                + (", ".join(request_audit_data["csrf_field_names"]) or "-")
            )
            print("  FORM FIELDS:")
            for field in request_audit_data["fields"]:
                print(
                    f"    {field['name']} = {field['value']} "
                    f"[{field['source']}]"
                )
            print(
                "  PREPARED BODY   : "
                f"{request_audit_data['prepared_body_redacted']}"
            )
            print("  PASSWORD LOGGED : NO")
            print("  CSRF LOGGED     : NO")

        response = session.send(
            prepared,
            allow_redirects=False,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return {
            "status": None,
            "classification": "probe-error",
            "error": str(exc),
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "request_audit": request_audit_data,
        }

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    body, truncated = body_sample(response)
    indicators = text_indicators(body)
    return {
        "status": response.status_code,
        "reason": response.reason,
        "location": response.headers.get("Location", ""),
        "content_type": response.headers.get("Content-Type", ""),
        "content_length": len(response.content),
        "body_sha256": sha256_text(response.text),
        "body_sample": body,
        "body_truncated": truncated,
        "response_fingerprint": response_fingerprint(response, body),
        "headers": header_subset(response.headers),
        "indicators": indicators,
        "duration_ms": duration_ms,
        "classification": classify_login_response(response, body, indicators),
        "error": "",
    }


def classify_login_response(
    response: requests.Response,
    body: str,
    indicators: dict[str, bool],
) -> str:
    status = response.status_code
    location = str(response.headers.get("Location", ""))
    lower_location = location.lower()

    if status == 429 or indicators["rate_limit"]:
        return "rate-limited"
    if indicators["lockout"]:
        return "account-lockout-indicated"
    if indicators["authenticated_marker"] or (300 <= status < 400 and any(x in lower_location for x in ("dashboard", "home", "logout"))):
        return "authenticated-or-success-indicated"
    if status in {401, 403} or indicators["login_error"]:
        return "authentication-rejected"
    if 300 <= status < 400:
        return "redirected"
    if 200 <= status < 300:
        return "application-response"
    if 500 <= status < 600:
        return "server-error"
    return "other"



def correlate_cves(project_path: Path) -> dict[str, Any]:
    """Carry forward only authentication-relevant CVE candidates from 4-001.

    A candidate is traceability evidence only. It is never converted into a
    finding by this script.
    """
    version_path = project_path / "04-web-server-configuration" / "version" / "version.yaml"
    result: dict[str, Any] = {
        "source": "04-web-server-configuration/version/version.yaml",
        "source_checklist": "4-001",
        "candidate_count": 0,
        "candidates": [],
        "assessment_note": "Only authentication-relevant candidates are inherited; version match is not a vulnerability.",
    }
    if not version_path.exists():
        result["assessment_note"] = (
            "4-001 version artifact tidak tersedia; authentication CVE correlation tidak dilakukan. "
            "Version match is not a vulnerability."
        )
        return result

    try:
        data = load_yaml(version_path)
    except Exception as exc:
        result["assessment_note"] = f"Gagal membaca 4-001 CVE source: {exc}"
        return result

    products = data.get("cve_correlation", {}).get("products", []) if isinstance(data, dict) else []
    if not isinstance(products, list):
        products = []

    keywords = re.compile(
        r"authentication|authorization|login|credential|password|session|auth|access control",
        re.I,
    )
    candidates: list[dict[str, Any]] = []
    for product in products:
        if not isinstance(product, dict):
            continue
        for cve in product.get("cves", []) or []:
            if not isinstance(cve, dict):
                continue
            description = str(cve.get("description") or "")
            if not keywords.search(description):
                continue
            candidates.append(
                {
                    "cve": str(cve.get("cve") or ""),
                    "product": str(product.get("product") or cve.get("product") or ""),
                    "version": str(product.get("version") or cve.get("version") or ""),
                    "severity": cve.get("severity"),
                    "cvss": cve.get("cvss"),
                    "description": description[:2000],
                    "classification": "authentication-relevant-candidate",
                    "requires_validation": True,
                    "finding": False,
                    "correlation_basis": "4-001 version/CPE candidate filtered for authentication-relevant terminology",
                }
            )

    result["candidate_count"] = len(candidates)
    result["candidates"] = candidates
    return result

def initial_artifact(context: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": context["project_id"],
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "login.py",
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE,
            "focus": "Controlled authentication login and bounded failed-login attempt assessment.",
            "status": "initialized",
        },
        "target": {
            "application": context["project_id"],
            "hostname": target["hostname"],
            "url": target["url"],
            "environment": "Production",
            "assessment_type": context["assessment_type"],
            "scope_id": target["scope_id"],
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": target["authorized_ports"],
            "login_path": DEFAULT_LOGIN_PATH,
        },
        "methodology": {
            "description": "Controlled login testing with explicitly authorized test accounts.",
            "valid_login_attempts_per_account": 1,
            "controlled_failed_attempts_per_account": DEFAULT_FAILED_ATTEMPTS,
            "max_failed_attempts": MAX_FAILED_ATTEMPTS,
            "failed_attempt_strategy": "single authorized account, generated wrong password, no wordlist",
            "human_interaction_policy": "stop automated testing; do not bypass; anti-automation assessment PASS",
            "redirect_following": False,
            "mutation": True,
            "brute_force_unrestricted": False,
            "password_cracking": False,
            "credential_spraying": False,
            "bypass_cloudflare": False,
            "automatic_finding": False,
        },
        "baseline": {
            "account_source": "01-preparation/account/accounts.yaml",
            "scope_source": "01-preparation/scope/scope.yaml",
        },
        "toolchain": {
            "mandatory": ["Python", "requests", "PyYAML", "BeautifulSoup"],
            "optional": ["Playwright", "curl.exe"],
            "nmap": "not-required",
            "ffuf": "not-required",
            "nuclei": "not-required",
            "zap": "not-required for baseline",
        },
        "probe": {
            "timeout_seconds": DEFAULT_TIMEOUT,
            "allow_redirects": False,
            "max_body_bytes": MAX_BODY_BYTES,
            "body_sample_chars": BODY_SAMPLE_CHARS,
            "browser": "Playwright for human-interaction detection and browser-emulator handoff",
        },
        "source_status": {
            "scope": "pending",
            "account": "pending",
        },
        "results": {
            "accounts_selected": 0,
            "accounts": [],
            "login_page": None,
            "valid_login": [],
            "controlled_failed_attempts": [],
            "human_interaction": None,
            "probe_count": 0,
        },
        "summary": {
            "accounts_selected": 0,
            "valid_login_tested": 0,
            "valid_login_success": 0,
            "failed_attempts_executed": 0,
            "failed_attempts_blocked": 0,
            "rate_limited": 0,
            "lockout_indicated": 0,
            "human_interaction_required": False,
            "requires_review": False,
            "finding": False,
        },
        "cve_correlation": {
            "source": "04-web-server-configuration/version/version.yaml",
            "source_checklist": "4-001",
            "candidate_count": 0,
            "candidates": [],
            "assessment_note": "Authentication login CVE correlation is secondary; version match is not a vulnerability.",
        },
        "assessment": {
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
            "note": "No authentication finding is asserted automatically.",
        },
        "evidence": {
            "login_probes": "07-authentication/login/evidence/login-probes.json",
        },
        "errors": [],
        "notes": [
            "Only explicitly authorized test accounts are used.",
            "Passwords are never written to YAML, JSON, stdout, or evidence.",
            "Failed-login testing is bounded to a maximum of five attempts per selected account.",
            "No unrestricted brute force, password cracking, credential spraying, or username enumeration is performed.",
            "Cloudflare Turnstile/CAPTCHA human interaction is not bypassed.",
            "If human interaction is required, automated failed-login testing stops and the anti-automation control is assessed as PASS under the agreed rule.",
            "Raw evidence is retained; credential/secret redaction is performed during report generation.",
            "CVE correlation is triage evidence only and does not establish exploitability.",
        ],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
    }


def cmd_version() -> int:
    print(f"BrebesKab-CSIRT-Tools login.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : authorized test account + bounded failed-login attempts")
    print("Browser  : Playwright Chromium emulator handoff on human interaction; no bypass")
    print("Prefill  : authorized test username/password auto-filled in browser; secrets never logged")
    print("Limit    : maximum 5 failed attempts per account")
    print("Debug    : --debug-request shows safe prepared request mapping; secrets redacted")
    print("Audit    : --request-audit-only prepares request without sending authentication")
    print("CVE      : secondary correlation only; version match != vulnerability")
    return 0


def cmd_init() -> int:
    repo = project_root_from_script()
    context = runtime_context(repo)
    scope_path = locate_scope(context["project_path"])
    scope = load_yaml(scope_path)
    target = target_from_scope(scope)
    path = artifact_file(context["project_path"])
    write = initial_artifact(context, target)
    write["source_status"]["scope"] = "completed"
    write["source_status"]["account"] = "completed" if account_file(context["project_path"]).exists() else "missing"
    dump_yaml(path, write)

    print("[PASS] Authentication Login berhasil diinisialisasi.")
    print(f"PROJECT : {context['project_id']}")
    print(f"TARGET  : {target['hostname']}")
    print(f"LOGIN   : {target['url']}{DEFAULT_LOGIN_PATH}")
    print(f"FILE    : {path}")
    return 0


def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    return session


def get_login_page(session: requests.Session, login_url: str, timeout: int) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response = session.get(login_url, allow_redirects=False, timeout=timeout)
    except requests.RequestException as exc:
        return {
            "status": None,
            "classification": "probe-error",
            "error": str(exc),
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "url": login_url,
        }

    body, truncated = body_sample(response)
    challenge = detect_turnstile_html(response.text)
    form = None
    form_error = ""
    if response.ok:
        try:
            form = discover_form(response.text, response.url)
        except LoginError as exc:
            form_error = str(exc)

    return {
        "status": response.status_code,
        "reason": response.reason,
        "url": response.url,
        "location": response.headers.get("Location", ""),
        "content_type": response.headers.get("Content-Type", ""),
        "content_length": len(response.content),
        "body_sha256": sha256_text(response.text),
        "body_sample": body,
        "body_truncated": truncated,
        "response_fingerprint": response_fingerprint(response, body),
        "headers": header_subset(response.headers),
        "human_interaction": challenge,
        "form": form,
        "form_error": form_error,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "classification": "login-page" if response.ok else "login-page-error",
        "error": "",
    }


def _xpath_literal(value: str) -> str:
    """Return a safe XPath string literal for arbitrary field names."""
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    parts = value.split("'")
    return "concat(" + ", \"'\", ".join(f"'{part}'" for part in parts) + ")"


def _browser_fill_field(page: Any, field_name: str, value: str) -> bool:
    """Fill one input field by its HTML name without logging the value."""
    name = str(field_name or "").strip()
    if not name:
        return False

    try:
        locator = page.locator(f"//input[@name={_xpath_literal(name)}]").first
        if locator.count() == 0 or not locator.is_visible():
            return False
        locator.fill(value)
        return True
    except Exception:
        return False


def _prefill_browser_credentials(
    page: Any,
    form: dict[str, Any] | None,
    username: str,
    password: str,
) -> dict[str, Any]:
    """Prefill authorized credentials in the browser only.

    The credentials remain in memory and are never returned in the result,
    printed, or written to evidence.
    """
    form = form or {}
    username_field = str(form.get("username_field") or "").strip()
    password_field = str(form.get("password_field") or "").strip()

    username_filled = _browser_fill_field(page, username_field, username)
    password_filled = _browser_fill_field(page, password_field, password)

    # Conservative fallbacks for pages where the discovered form metadata
    # is incomplete but the DOM still exposes standard input types.
    if not username_filled:
        try:
            candidates = page.locator(
                'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
            )
            for index in range(candidates.count()):
                candidate = candidates.nth(index)
                if candidate.is_visible() and candidate.is_editable():
                    candidate.fill(username)
                    username_filled = True
                    break
        except Exception:
            pass

    if not password_filled:
        try:
            candidate = page.locator('input[type="password"]').first
            if candidate.count() > 0 and candidate.is_visible() and candidate.is_editable():
                candidate.fill(password)
                password_filled = True
        except Exception:
            pass

    return {
        "username_field": username_field,
        "password_field": password_field,
        "username_prefilled": username_filled,
        "password_prefilled": password_filled,
        "credentials_prefilled": bool(username_filled and password_filled),
        "credential_values_logged": False,
    }


def playwright_human_interaction(
    login_url: str,
    timeout: int,
    interactive: bool = False,
    form: dict[str, Any] | None = None,
    username: str = "",
    password: str = "",
    account_id_value: str = "",
) -> dict[str, Any]:
    """Detect/render human interaction without solving or bypassing it.

    When a human-interaction challenge is detected, Chromium is opened in
    headed/emulated-browser mode. Authorized username/password values are
    automatically prefilled into the login form, but the challenge itself is
    never solved or bypassed programmatically.

    The browser remains open until the assessor presses ENTER in the terminal.
    No credential values are returned, printed, or written to evidence.
    """
    if sync_playwright is None:
        return {
            "available": False,
            "human_interaction_required": None,
            "classification": "playwright-unavailable",
            "browser_mode": "unavailable",
            "credentials_prefilled": False,
            "error": "Playwright tidak tersedia.",
        }

    result: dict[str, Any] = {
        "available": True,
        "human_interaction_required": False,
        "turnstile_detected": False,
        "captcha_detected": False,
        "challenge_visible": False,
        "classification": "no-human-challenge-observed",
        "browser_mode": "headless-detection",
        "manual_interaction": False,
        "credentials_prefilled": False,
        "username_prefilled": False,
        "password_prefilled": False,
        "credential_values_logged": False,
        "account_id": str(account_id_value or ""),
        "error": "",
    }

    browser = None
    try:
        with sync_playwright() as pw:
            # If requests already detected the challenge, go directly to the
            # visible browser handoff. Otherwise perform a headless detection
            # first and only open a visible browser when a challenge appears.
            browser = pw.chromium.launch(headless=not interactive)
            page = browser.new_page(
                viewport={"width": 1366, "height": 900},
                user_agent=USER_AGENT,
            )
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout * 1000)
            page.wait_for_timeout(1000)

            html = page.content()
            detected = detect_turnstile_html(html)
            result.update(
                {
                    "human_interaction_required": detected["human_interaction_detected"],
                    "turnstile_detected": detected["cloudflare_turnstile_detected"],
                    "captcha_detected": detected["captcha_detected"],
                }
            )

            selectors = [
                'iframe[src*="challenges.cloudflare.com"]',
                'iframe[src*="turnstile"]',
                '[name="cf-turnstile-response"]',
                ".cf-turnstile",
                "[data-sitekey]",
            ]
            visible = False
            for selector in selectors:
                try:
                    locator = page.locator(selector)
                    if locator.count() > 0 and locator.first.is_visible():
                        visible = True
                        break
                except Exception:
                    continue

            result["challenge_visible"] = visible
            challenge = bool(result["human_interaction_required"] or visible)

            if challenge:
                result["human_interaction_required"] = True
                result["classification"] = "human-interaction-required"

                if not interactive:
                    # The first browser was headless. Close it and hand off to
                    # a visible Chromium emulator only after challenge detection.
                    browser.close()
                    browser = pw.chromium.launch(headless=False)
                    page = browser.new_page(
                        viewport={"width": 1366, "height": 900},
                        user_agent=USER_AGENT,
                    )
                    page.goto(
                        login_url,
                        wait_until="domcontentloaded",
                        timeout=timeout * 1000,
                    )
                    page.wait_for_timeout(1000)

                    # Re-check the visible browser DOM because the challenge
                    # may be dynamically rendered by Cloudflare/JavaScript.
                    html = page.content()
                    detected = detect_turnstile_html(html)
                    result.update(
                        {
                            "human_interaction_required": (
                                detected["human_interaction_detected"]
                                or result["human_interaction_required"]
                            ),
                            "turnstile_detected": (
                                detected["cloudflare_turnstile_detected"]
                                or result["turnstile_detected"]
                            ),
                            "captcha_detected": (
                                detected["captcha_detected"]
                                or result["captcha_detected"]
                            ),
                        }
                    )
                    result["browser_mode"] = "headed-browser-emulator"
                else:
                    result["browser_mode"] = "headed-browser-emulator"

                # Prefill only the explicitly authorized account credentials.
                # This is form filling, not challenge solving or bypass.
                prefill = _prefill_browser_credentials(
                    page,
                    form,
                    username,
                    password,
                )
                result.update(prefill)

                print("[INFO] Human interaction terdeteksi.")
                print("[INFO] Berpindah ke browser emulator Chromium.")
                if result["credentials_prefilled"]:
                    print("[INFO] Username dan password test account otomatis dimasukkan.")
                else:
                    print("[WARN] Username/password belum seluruhnya dapat dipetakan ke form browser.")
                print("[INFO] Challenge tidak dibypass atau diselesaikan secara otomatis.")
                print("[INFO] Silakan lakukan interaksi yang diperlukan secara manual.")
                print("[INFO] Setelah selesai, kembali ke terminal lalu tekan ENTER.")

                result["manual_interaction"] = True
                try:
                    input()
                except EOFError:
                    pass
                result["manual_interaction_completed"] = True

            browser.close()
            browser = None

    except Exception as exc:
        result["classification"] = "browser-probe-error"
        result["error"] = f"{type(exc).__name__}: {exc}"
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass

    # Never expose the actual credential values through the returned object.
    return result


def summarize_assessment(
    login_page: dict[str, Any],
    browser: dict[str, Any],
    valid_results: list[dict[str, Any]],
    failed_results: list[dict[str, Any]],
) -> tuple[str, bool, bool, str]:
    human = bool(
        login_page.get("human_interaction", {}).get("human_interaction_detected")
        or browser.get("human_interaction_required")
    )
    if human:
        return (
            "pass",
            False,
            False,
            "Human interaction/challenge detected; automated login-attempt testing stopped. No bypass attempted. Anti-automation control assessed PASS under agreed rule.",
        )

    if not valid_results and not failed_results:
        return (
            "not-tested",
            False,
            False,
            "Tidak ada login attempt yang dapat dieksekusi.",
        )

    errors = [x for x in valid_results + failed_results if x.get("classification") == "probe-error"]
    if errors:
        return (
            "probe-error",
            False,
            True,
            "Satu atau lebih login probe mengalami error; hasil memerlukan review.",
        )

    rate_limited = any(x.get("classification") == "rate-limited" for x in failed_results)
    locked = any(x.get("classification") == "account-lockout-indicated" for x in failed_results)
    if rate_limited or locked:
        return (
            "protected",
            False,
            False,
            "Controlled failed-login attempts menunjukkan kontrol rate-limit/lockout.",
        )

    if failed_results and len(failed_results) >= DEFAULT_FAILED_ATTEMPTS:
        return (
            "requires-review",
            False,
            True,
            "Seluruh bounded failed-login attempts dapat dieksekusi tanpa indikasi rate-limit/lockout; konfigurasi kontrol login memerlukan review.",
        )

    return (
        "observed",
        False,
        True,
        "Hasil login teramati tetapi belum cukup untuk menyimpulkan kontrol authentication secara menyeluruh.",
    )


def cmd_analyze(account_id_value: str | None, failed_attempts: int, timeout: int, debug_request: bool = False, request_audit_only: bool = False) -> int:
    repo = project_root_from_script()
    context = runtime_context(repo)
    project = context["project_path"]
    scope = load_yaml(locate_scope(project))
    target = target_from_scope(scope)
    login_url = target["url"].rstrip("/") + DEFAULT_LOGIN_PATH

    if failed_attempts < 0 or failed_attempts > MAX_FAILED_ATTEMPTS:
        raise LoginError(f"failed_attempts harus 0-{MAX_FAILED_ATTEMPTS}.")

    accounts = select_accounts(project, account_id_value)
    path = artifact_file(project)
    if not path.exists():
        raise LoginError("login.yaml belum ada. Jalankan command init terlebih dahulu.")
    artifact = load_yaml(path)
    if not isinstance(artifact, dict):
        raise LoginError("login.yaml bukan object YAML.")

    print("[STEP] Authentication Login analysis...")
    print(f"PROJECT : {context['project_id']}")
    print(f"TARGET  : {target['hostname']}")
    print(f"LOGIN   : {login_url}")
    print(f"ACCOUNTS: {len(accounts)}")
    print(f"FAILED ATTEMPTS/ACCOUNT: {failed_attempts}")
    print(f"DEBUG REQUEST: {debug_request}")
    print(f"REQUEST AUDIT ONLY: {request_audit_only}")

    session = build_session()
    login_page = get_login_page(session, login_url, timeout)

    # Resolve the first selected authorized account in memory so that if the
    # browser-side probe discovers a dynamically rendered challenge, the
    # visible Chromium handoff can still prefill the same authorized account.
    # The password is cleared immediately after the browser handoff.
    browser_account = accounts[0]
    browser_account_id = account_id(browser_account)
    browser_username, browser_password = resolve_account_credentials(browser_account)

    browser = playwright_human_interaction(
        login_url,
        timeout,
        interactive=bool(
            login_page.get("human_interaction", {}).get("human_interaction_detected")
        ),
        form=login_page.get("form") or {},
        username=browser_username,
        password=browser_password,
        account_id_value=browser_account_id,
    )
    browser_password = ""

    evidence: list[dict[str, Any]] = [
        {
            "type": "login-page",
            "timestamp": utc_now(),
            **login_page,
        },
        {
            "type": "browser-human-interaction-detection",
            "timestamp": utc_now(),
            **browser,
        },
    ]

    valid_results: list[dict[str, Any]] = []
    failed_results: list[dict[str, Any]] = []

    if login_page.get("status") is None:
        raise LoginError(f"Login page probe gagal: {login_page.get('error')}")

    human_required = bool(
        login_page.get("human_interaction", {}).get("human_interaction_detected")
        or browser.get("human_interaction_required")
    )

    if request_audit_only:
        print("[STEP] Request audit-only mode: tidak ada POST login yang dikirim.")

        for account in accounts:
            aid = account_id(account)
            resolved_username, audit_password = resolve_account_credentials(account)
            safe_user = redact_username(resolved_username)
            print(f"[STEP] Request audit: {aid} ({safe_user})")

            audit_result = perform_request_audit_only(
                build_session(),
                login_page.get("form") or {},
                resolved_username,
                audit_password,
                login_url,
                timeout,
                debug_request=True,
            )
            audit_password = ""

            audit_result.update(
                {
                    "account_id": aid,
                    "username": safe_user,
                    "credential_type": "valid",
                    "timestamp": utc_now(),
                }
            )
            evidence.append(
                {
                    "type": "login-request-audit-only",
                    **audit_result,
                }
            )

        # Audit-only is an observation/verification operation, not an
        # authentication attempt. It must not be classified as a login finding.
        artifact["checklist"]["status"] = "completed"
        artifact["cve_correlation"] = correlate_cves(project)
        artifact["target"]["url"] = target["url"]
        artifact["target"]["hostname"] = target["hostname"]
        artifact["target"]["assessment_type"] = context["assessment_type"]
        artifact["target"]["login_path"] = DEFAULT_LOGIN_PATH
        artifact["source_status"] = {
            "scope": "completed",
            "account": "completed",
        }
        artifact["results"] = {
            "accounts_selected": len(accounts),
            "accounts": [
                {
                    "account_id": account_id(x),
                    "role": account_role(x),
                    "username": redact_username(account_username(x)),
                    "status": account_status(x),
                }
                for x in accounts
            ],
            "login_page": {
                key: value
                for key, value in login_page.items()
                if key not in {"body_sample"}
            },
            "controlled_failed_attempts": [],
            "valid_login": [],
            "human_interaction": browser,
            "request_audit_only": [
                item
                for item in evidence
                if item.get("type") == "login-request-audit-only"
            ],
            "probe_count": len(evidence),
        }
        artifact["summary"] = {
            "accounts_selected": len(accounts),
            "valid_login_tested": 0,
            "valid_login_success": 0,
            "failed_attempts_executed": 0,
            "failed_attempts_blocked": 0,
            "rate_limited": 0,
            "lockout_indicated": 0,
            "human_interaction_required": human_required,
            "requires_review": False,
            "finding": False,
            "request_audit_only": True,
        }
        artifact["assessment"] = {
            "result": "request-audit-only",
            "finding": False,
            "requires_review": False,
            "note": (
                "Login request dipersiapkan dan diaudit tanpa dikirim. "
                "Mode ini bukan authentication attempt."
            ),
        }
        artifact["updated_at"] = utc_now()

        dump_json(evidence_file(project), evidence)
        dump_yaml(path, artifact)

        print("[PASS] Request audit-only completed.")
        print("POST LOGIN SENT : False")
        print("AUTH ATTEMPT    : False")
        print(f"ACCOUNTS AUDITED: {len(accounts)}")
        print(f"FILE            : {path}")
        print(f"EVIDENCE        : {evidence_file(project)}")
        return 0

    if human_required:
        print("[PASS] Human interaction/challenge terdeteksi.")
        print("[PASS] Automated login-attempt testing dihentikan; bypass tidak dilakukan.")
    else:
        for account in accounts:
            aid = account_id(account)
            username = account_username(account)
            safe_user = redact_username(username)
            print(f"[STEP] Valid login test: {aid} ({safe_user})")
            resolved_username, valid_password = resolve_account_credentials(account)
            # Use the authoritative decrypted username as well as the password.
            username = resolved_username
            safe_user = redact_username(username)
            result = request_login(
                build_session(),
                login_page.get("form") or {},
                username,
                valid_password,
                login_url,
                timeout,
                debug_request=debug_request,
            )
            valid_password = ""
            result.update(
                {
                    "account_id": aid,
                    "username": safe_user,
                    "credential_type": "valid",
                    "attempt": 1,
                    "timestamp": utc_now(),
                }
            )
            valid_results.append(result)
            evidence.append({"type": "login-attempt", **result})

            if failed_attempts <= 0:
                continue

            print(f"[STEP] Controlled failed-login test: {aid} ({failed_attempts} attempts)")
            for attempt in range(1, failed_attempts + 1):
                # A fresh Session keeps each attempt independent while remaining bounded.
                result = request_login(
                    build_session(),
                    login_page.get("form") or {},
                    username,
                    random_wrong_password(),
                    login_url,
                    timeout,
                    debug_request=debug_request,
                )
                result.update(
                    {
                        "account_id": aid,
                        "username": safe_user,
                        "credential_type": "invalid-generated",
                        "attempt": attempt,
                        "timestamp": utc_now(),
                    }
                )
                failed_results.append(result)
                evidence.append({"type": "login-attempt", **result})
                print(
                    f"  attempt {attempt}/{failed_attempts}: "
                    f"status={result.get('status')} classification={result.get('classification')}"
                )

                if result.get("classification") in {
                    "rate-limited",
                    "account-lockout-indicated",
                }:
                    print("[PASS] Login protection terdeteksi; controlled attempts dihentikan.")
                    break

    assessment_result, finding, requires_review, assessment_note = summarize_assessment(
        login_page,
        browser,
        valid_results,
        failed_results,
    )

    artifact["checklist"]["status"] = "completed"
    artifact["cve_correlation"] = correlate_cves(project)
    artifact["target"]["url"] = target["url"]
    artifact["target"]["hostname"] = target["hostname"]
    artifact["target"]["assessment_type"] = context["assessment_type"]
    artifact["target"]["login_path"] = DEFAULT_LOGIN_PATH
    artifact["source_status"] = {
        "scope": "completed",
        "account": "completed",
    }
    artifact["results"] = {
        "accounts_selected": len(accounts),
        "accounts": [
            {
                "account_id": account_id(x),
                "role": account_role(x),
                "username": redact_username(account_username(x)),
                "status": account_status(x),
            }
            for x in accounts
        ],
        "login_page": {
            key: value
            for key, value in login_page.items()
            if key not in {"body_sample"}
        },
        "controlled_failed_attempts": failed_results,
        "valid_login": valid_results,
        "human_interaction": browser,
        "probe_count": len(evidence),
    }
    artifact["summary"] = {
        "accounts_selected": len(accounts),
        "valid_login_tested": len(valid_results),
        "valid_login_success": sum(
            1 for x in valid_results if x.get("classification") == "authenticated-or-success-indicated"
        ),
        "failed_attempts_executed": len(failed_results),
        "failed_attempts_blocked": (
            len(accounts) * failed_attempts if human_required else 0
        ),
        "rate_limited": sum(1 for x in failed_results if x.get("classification") == "rate-limited"),
        "lockout_indicated": sum(1 for x in failed_results if x.get("classification") == "account-lockout-indicated"),
        "human_interaction_required": human_required,
        "requires_review": requires_review,
        "finding": finding,
    }
    artifact["assessment"] = {
        "result": assessment_result,
        "finding": finding,
        "requires_review": requires_review,
        "note": assessment_note,
    }
    artifact["updated_at"] = utc_now()

    dump_json(evidence_file(project), evidence)
    dump_yaml(path, artifact)

    print(f"[PASS] Authentication Login analysis completed.")
    print(f"RESULT          : {assessment_result}")
    print(f"VALID LOGIN     : {len(valid_results)}")
    print(f"FAILED ATTEMPTS : {len(failed_results)}")
    print(f"HUMAN CHALLENGE : {human_required}")
    print(f"REQUIRES REVIEW : {requires_review}")
    print(f"FINDING         : {finding}")
    print(f"FILE            : {path}")
    print(f"EVIDENCE        : {evidence_file(project)}")
    return 0


def cmd_list() -> int:
    repo = project_root_from_script()
    context = runtime_context(repo)
    path = artifact_file(context["project_path"])
    if not path.exists():
        print(f"[INFO] Artifact belum ada: {path}")
        return 0
    artifact = load_yaml(path)
    summary = artifact.get("summary", {})
    target = artifact.get("target", {})
    assessment = artifact.get("assessment", {})
    print(f"PROJECT: {context['project_id']}")
    print(f"STATUS : {artifact.get('checklist', {}).get('status', '-')}")
    print(f"TARGET : {target.get('hostname', '-')}")
    print(f"RESULT : {assessment.get('result', '-')}")
    print()
    print("ACCOUNT / LOGIN")
    print("-" * 88)
    print(
        f"Accounts={summary.get('accounts_selected', 0)} "
        f"ValidLogin={summary.get('valid_login_tested', 0)} "
        f"FailedAttempts={summary.get('failed_attempts_executed', 0)} "
        f"HumanChallenge={summary.get('human_interaction_required', False)}"
    )
    print(
        f"RateLimited={summary.get('rate_limited', 0)} "
        f"Lockout={summary.get('lockout_indicated', 0)} "
        f"Review={summary.get('requires_review', False)} "
        f"Finding={summary.get('finding', False)}"
    )
    return 0


def cmd_show() -> int:
    repo = project_root_from_script()
    context = runtime_context(repo)
    path = artifact_file(context["project_path"])
    if not path.exists():
        print(f"[INFO] Artifact belum ada: {path}")
        return 0
    print(f"PROJECT: {context['project_id']}")
    print(f"FILE   : {path}")
    print()
    with path.open("r", encoding="utf-8") as handle:
        print(handle.read(), end="")
    return 0


def cmd_status() -> int:
    repo = project_root_from_script()
    context = runtime_context(repo)
    path = artifact_file(context["project_path"])
    if not path.exists():
        print(f"PROJECT          : {context['project_id']}")
        print("STATUS           : -")
        print(f"CHECKLIST        : {CHECKLIST_ID}")
        print("RESULT           : -")
        print("ACCOUNTS         : 0")
        print("VALID LOGIN      : 0")
        print("FAILED ATTEMPTS  : 0")
        print("HUMAN CHALLENGE  : False")
        print("REQUIRES REVIEW  : False")
        print("FINDING          : False")
        return 0

    artifact = load_yaml(path)
    summary = artifact.get("summary", {})
    assessment = artifact.get("assessment", {})
    print(f"PROJECT          : {context['project_id']}")
    print(f"STATUS           : {artifact.get('checklist', {}).get('status', '-')}")
    print(f"CHECKLIST        : {CHECKLIST_ID}")
    print(f"TARGET           : {artifact.get('target', {}).get('hostname', '-')}")
    print(f"RESULT           : {assessment.get('result', '-')}")
    print(f"ACCOUNTS         : {summary.get('accounts_selected', 0)}")
    print(f"VALID LOGIN      : {summary.get('valid_login_tested', 0)}")
    print(f"FAILED ATTEMPTS  : {summary.get('failed_attempts_executed', 0)}")
    print(f"RATE LIMITED     : {summary.get('rate_limited', 0)}")
    print(f"LOCKOUT          : {summary.get('lockout_indicated', 0)}")
    print(f"HUMAN CHALLENGE  : {summary.get('human_interaction_required', False)}")
    print(f"REQUIRES REVIEW  : {summary.get('requires_review', False)}")
    print(f"FINDING          : {summary.get('finding', False)}")
    print(f"UPDATED          : {artifact.get('updated_at', '-')}")
    return 0


def cmd_verify() -> int:
    repo = project_root_from_script()
    context = runtime_context(repo)
    project = context["project_path"]
    path = artifact_file(project)
    errors: list[str] = []

    if not path.exists():
        errors.append(f"Artifact tidak ditemukan: {path}")
    else:
        artifact = load_yaml(path)
        if artifact.get("schema_version") != SCHEMA_VERSION:
            errors.append("schema_version tidak sesuai.")
        if artifact.get("project_id") != context["project_id"]:
            errors.append("project_id artifact tidak sesuai active project.")
        checklist = artifact.get("checklist", {})
        if checklist.get("id") != CHECKLIST_ID:
            errors.append("checklist.id tidak sesuai.")
        if checklist.get("name") != CHECKLIST_NAME:
            errors.append("checklist.name tidak sesuai.")
        if checklist.get("phase") != PHASE:
            errors.append("checklist.phase tidak sesuai.")
        target = artifact.get("target", {})
        if not target.get("hostname"):
            errors.append("target.hostname kosong.")
        results = artifact.get("results", {})
        if "controlled_failed_attempts" not in results:
            errors.append("results.controlled_failed_attempts tidak tersedia.")
        summary = artifact.get("summary", {})
        if bool(summary.get("finding", False)) is not bool(artifact.get("assessment", {}).get("finding", False)):
            errors.append("summary.finding dan assessment.finding tidak konsisten.")

        failed = results.get("controlled_failed_attempts", [])
        if isinstance(failed, list) and len(failed) > MAX_FAILED_ATTEMPTS * max(1, int(results.get("accounts_selected", 1))):
            errors.append("Jumlah failed-login attempts melebihi batas maksimum.")

        evidence = evidence_file(project)
        if not evidence.exists():
            errors.append(f"Evidence tidak ditemukan: {evidence}")

    if errors:
        print("[FAIL] Authentication Login belum memenuhi validasi.")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("[PASS] Authentication Login memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {context['project_id']}")
    print(f"[PASS] File      : {path}")
    return 0


def cmd_remove() -> int:
    import shutil

    repo = project_root_from_script()
    context = runtime_context(repo)
    path = artifact_dir(context["project_path"])
    if not path.exists():
        print("[INFO] Authentication Login belum ada.")
        return 0
    confirm = input("Hapus seluruh data Authentication Login untuk project aktif? [y/N]: ").strip().lower()
    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0
    shutil.rmtree(path)
    print("[PASS] Authentication Login berhasil dihapus.")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Authentication Login\n"
        "\n"
        "Checklist:\n"
        "  7-002 Authentication Login\n"
        "\n"
        "Usage:\n"
        "  python scripts/authentication/login.py version\n"
        "  python scripts/authentication/login.py init\n"
        "  python scripts/authentication/login.py analyze\n"
        "  python scripts/authentication/login.py analyze --account-id TA-001\n"
        "  python scripts/authentication/login.py analyze --failed-attempts 5\n"
        "  python scripts/authentication/login.py analyze --account-id TA-001 --debug-request\n"
        "  python scripts/authentication/login.py analyze --account-id TA-001 --request-audit-only --debug-request\n"
        "  python scripts/authentication/login.py list\n"
        "  python scripts/authentication/login.py show\n"
        "  python scripts/authentication/login.py status\n"
        "  python scripts/authentication/login.py verify\n"
        "  python scripts/authentication/login.py remove\n"
        "\n"
        "Design:\n"
        "  - Uses only active authorized accounts from 01-preparation/account/accounts.yaml.\n"
        "  - Valid password is resolved through preparation/account.py and never stored.\n"
        "  - Failed-login testing uses one generated wrong password and max 5 attempts/account.\n"
        "  - No password wordlist, password spraying, username enumeration, or unrestricted brute force.\n"
        "  - Cloudflare Turnstile/CAPTCHA is detected but never bypassed; when detected, Chromium browser emulator is opened for manual interaction.\n"
        "  - The selected authorized test account username/password is auto-filled in the browser; credential values are never logged or persisted.\n"
        "  - Human interaction requirement stops automated login testing and is PASS for anti-automation.\n"
        "  - --request-audit-only prepares the login request but never sends the authentication request.\n"
        "  - Raw evidence is retained without passwords; report redaction remains a separate layer.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "command",
        nargs="?",
        default="help",
        choices=("version", "init", "analyze", "list", "show", "status", "verify", "remove", "help"),
    )
    parser.add_argument("--account-id", dest="account_id", default=None)
    parser.add_argument("--failed-attempts", dest="failed_attempts", type=int, default=DEFAULT_FAILED_ATTEMPTS)
    parser.add_argument("--timeout", dest="timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--debug-request",
        dest="debug_request",
        action="store_true",
        help="Tampilkan mapping request login yang sudah disanitasi; password/CSRF tidak pernah ditampilkan.",
    )
    parser.add_argument(
        "--request-audit-only",
        dest="request_audit_only",
        action="store_true",
        help="Siapkan dan audit request login tanpa mengirim POST/authentication attempt.",
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "help":
            print_help()
            return 0
        if args.command == "version":
            return cmd_version()
        if args.command == "init":
            return cmd_init()
        if args.command == "analyze":
            return cmd_analyze(args.account_id, args.failed_attempts, args.timeout, args.debug_request, args.request_audit_only)
        if args.command == "list":
            return cmd_list()
        if args.command == "show":
            return cmd_show()
        if args.command == "status":
            return cmd_status()
        if args.command == "verify":
            return cmd_verify()
        if args.command == "remove":
            return cmd_remove()
        raise LoginError(f"Command tidak dikenal: {args.command}")
    except LoginError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Dibatalkan oleh pengguna.")
        return 130
    except Exception as exc:
        print(f"[FAIL] Unexpected error: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
