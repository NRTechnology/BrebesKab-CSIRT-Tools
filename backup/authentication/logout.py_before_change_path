#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Authentication Logout / Session Invalidation

Checklist: 5-003 Logout / Session Invalidation
Schema: 1.0

Purpose:
    Verify that an authorized authenticated session is actually invalidated by
    logout and that the old authenticated session cannot be reused afterward.

Security model:
    - Uses only an explicitly authorized SUCCESS session from 5-002.
    - Decrypts the session value only in memory using the canonical project secrets API.
    - Never stores or prints plaintext session values.
    - Performs one bounded authenticated request, one logout request, and one
      bounded old-session validation request.
    - Does not brute force, enumerate accounts, bypass CAPTCHA/Turnstile,
      hijack third-party sessions, crawl the application, or mass-test logout.
    - HTTP 200, /webapp, Dashboard, Profile, or Login modal visibility alone are never considered proof of authenticated state.
    - A confirmed old-session reuse after logout is REVIEW, not an automatic
      vulnerability finding.
    - CVE correlation is secondary triage only; version match is not a finding.

Typical workflow:
    python scripts/authentication/logout.py version
    python scripts/authentication/logout.py init
    python scripts/authentication/logout.py run --session-id S-006
    python scripts/authentication/logout.py run --session-id S-006 --url /logout
    python scripts/authentication/logout.py show
    python scripts/authentication/logout.py verify
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("[ERROR] requests belum terinstall.")
    raise SystemExit(1)

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML belum terinstall.")
    raise SystemExit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[ERROR] BeautifulSoup belum terinstall.")
    raise SystemExit(1)


SCRIPT_VERSION = "1.0.4"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "5-003"
CHECKLIST_NAME = "Logout / Session Invalidation"
PHASE_NAME = "05 Authentication"
PHASE_DIR = "05-authentication"
LOGOUT_DIR = "logout"
LOGOUT_FILE = "logout.yaml"
EVIDENCE_DIR = "evidence"
EVIDENCE_FILE = "logout-probes.json"
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_BODY_BYTES = 262144
BODY_SAMPLE_CHARS = 4000
SESSION_ID_RE = re.compile(r"^S-[0-9]{3,}$", re.IGNORECASE)

LOGOUT_PATH_HINTS = (
    "/logout",
    "/signout",
    "/sign-out",
    "/auth/logout",
    "/user/logout",
)
LOGIN_PATHS = {"/login", "/loginuser", "/signin", "/sign-in"}
# Authentication-state strategy v1:
#   - AUTHENTICATED  : logout link/action is present and login link/action is absent
#   - UNAUTHENTICATED: login link/action is present and logout link/action is absent
#   - AMBIGUOUS      : both are present
#   - UNCONFIRMED    : neither is present
#
# This is intentionally a generic link/action strategy. It is not hard-coded
# to one application's exact URL. The observed Bangsaku target currently uses
# /login and /logoutuser, but future applications may expose different paths.
LOGIN_ACTION_HINTS = (
    "/login",
    "/loginuser",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/user/login",
)
LOGOUT_ACTION_HINTS = LOGOUT_PATH_HINTS
LOGIN_TEXT_HINTS = (
    "login",
    "log in",
    "sign in",
    "signin",
    "masuk",
)
LOGOUT_TEXT_HINTS = (
    "logout",
    "log out",
    "sign out",
    "signout",
    "keluar",
)
FAILURE_MARKERS = (
    "invalid username",
    "invalid password",
    "invalid credentials",
    "login failed",
    "login gagal",
    "unauthorized",
    "please login",
    "please log in",
    "session expired",
)

try:
    SCRIPTS_DIR = Path(__file__).resolve().parents[1]
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    from context import ProjectContext, load_active_context
    from secrets import SecretsError, decrypt
except Exception as exc:
    print(f"[ERROR] Modul project tidak dapat dimuat: {exc}")
    raise SystemExit(1)


class LogoutError(RuntimeError):
    """Controlled logout assessment error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def active_context() -> ProjectContext:
    try:
        return load_active_context()
    except Exception as exc:
        raise LogoutError(f"Active project context tidak valid: {exc}") from exc


def project_root() -> Path:
    return active_context().project_path


def logout_dir() -> Path:
    return project_root() / PHASE_DIR / LOGOUT_DIR


def logout_file() -> Path:
    return logout_dir() / LOGOUT_FILE


def evidence_dir() -> Path:
    return logout_dir() / EVIDENCE_DIR


def evidence_file() -> Path:
    return evidence_dir() / EVIDENCE_FILE


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise LogoutError(f"File tidak ditemukan: {path}")
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise LogoutError(f"{path.name} menggunakan UTF-8 BOM.")
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise LogoutError(f"YAML tidak dapat dibaca: {path}") from exc
    if not isinstance(data, dict):
        raise LogoutError(f"Root {path.name} harus berupa mapping.")
    return data


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": SCHEMA_VERSION,
            "project_id": active_context().project_id,
            "checklist": CHECKLIST_ID,
            "logout_probes": [],
            "errors": [],
        }
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise LogoutError(f"{path.name} menggunakan UTF-8 BOM.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LogoutError(f"Evidence JSON tidak dapat dibaca: {path}") from exc
    if not isinstance(data, dict):
        raise LogoutError("Root evidence JSON harus berupa mapping.")
    return data


def empty_artifact() -> dict[str, Any]:
    context = active_context()
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": context.project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "logout.py",
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "focus": (
                "Logout endpoint execution, authenticated session invalidation, "
                "cookie behavior, and controlled old-session reuse assessment."
            ),
            "status": "initialized",
        },
        "target": {
            "application": context.project_id,
            "hostname": "",
            "url": "",
            "environment": "",
            "assessment_type": "",
            "scope_id": "IN-001",
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": [80, 443],
        },
        "methodology": {
            "description": (
                "Controlled logout and session-invalidation assessment using "
                "an explicitly authorized SUCCESS session from 5-002."
            ),
            "authorized_test_session_only": True,
            "session_secret_encryption": "project Fernet key via scripts/secrets.py",
            "session_value_plaintext_in_artifact": False,
            "single_logout_attempt": True,
            "single_old_session_reuse_check": True,
            "redirect_following": False,
            "automatic_finding": False,
            "captcha_turnstile_bypass": False,
            "mass_session_testing": False,
            "third_party_session_hijacking": False,
            "authentication_state_strategy": "link_action",
            "authentication_state_rules": {
                "authenticated": "logout link/action present and login link/action absent",
                "unauthenticated": "login link/action present and logout link/action absent",
                "ambiguous": "login and logout link/action both present",
                "unconfirmed": "neither login nor logout link/action present",
            },
        },
        "baseline": {
            "session_source": "05-authentication/session/session.yaml",
            "scope_source": "01-preparation/scope/scope.yaml",
            "encryption_key_source": ".runtime/secrets/<PROJECT-ID>/encryption.key",
            "authentication_source_checklist": "5-002 Session Management",
        },
        "toolchain": {
            "mandatory": [
                "Python",
                "requests",
                "PyYAML",
                "BeautifulSoup",
                "session.yaml",
                "scripts.secrets",
                "scripts.context",
            ],
            "optional": ["curl.exe", "Playwright"],
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
            "authentication_state_strategy": "link_action",
            "authentication_state_strategy_version": "1.0",
        },
        "source_status": {
            "scope": "completed",
            "session": "not-tested",
        },
        "results": {
            "sessions_selected": 0,
            "logout_candidates": [],
            "authenticated_before_logout": [],
            "logout": [],
            "post_logout_reuse": [],
            "cookie_invalidation": [],
        },
        "summary": {
            "sessions_selected": 0,
            "logout_endpoint_found": False,
            "logout_attempted": False,
            "logout_completed": False,
            "old_session_reuse_tested": False,
            "old_session_replay_confirmed": False,
            "session_invalidated": False,
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
                "CVE correlation is secondary triage evidence; version match does "
                "not establish exploitability or a vulnerability."
            ),
        },
        "assessment": {
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
            "note": "Logout assessment belum dijalankan.",
        },
        "evidence": {
            "logout_probes": "05-authentication/logout/evidence/logout-probes.json",
        },
        "errors": [],
        "notes": [
            "Only explicitly authorized authenticated sessions are used.",
            "Old-session reuse after logout is tested once and is not third-party hijacking.",
            "Authentication state baseline uses Login/Logout link or action markers; generic HTTP 200, /webapp, Dashboard, Profile, or Login modal visibility are not authentication proof.",
        ],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
    }


def load_artifact() -> dict[str, Any]:
    return load_yaml(logout_file())


def ensure_artifact_metadata(
    data: dict[str, Any],
    *,
    persist: bool = False,
) -> tuple[dict[str, Any], bool]:
    """
    Ensure metadata and security-policy fields introduced by the link_action authentication-state strategy
    exists on artifacts created by older logout.py versions.

    This is a metadata/schema migration only. It never changes assessment
    results, session evidence, probe results, or CVE data.

    Returns:
        (data, changed)
    """
    changed = False

    methodology = data.setdefault("methodology", {})
    if not isinstance(methodology, dict):
        raise LogoutError("methodology pada logout.yaml harus berupa mapping.")

    if methodology.get("authentication_state_strategy") != "link_action":
        methodology["authentication_state_strategy"] = "link_action"
        changed = True

    rules = {
        "authenticated": "logout link/action present and login link/action absent",
        "unauthenticated": "login link/action present and logout link/action absent",
        "ambiguous": "login and logout link/action both present",
        "unconfirmed": "neither login nor logout link/action present",
    }
    if methodology.get("authentication_state_rules") != rules:
        methodology["authentication_state_rules"] = rules
        changed = True

    probe = data.setdefault("probe", {})
    if not isinstance(probe, dict):
        raise LogoutError("probe pada logout.yaml harus berupa mapping.")

    if probe.get("authentication_state_strategy") != "link_action":
        probe["authentication_state_strategy"] = "link_action"
        changed = True

    if probe.get("authentication_state_strategy_version") != "1.0":
        probe["authentication_state_strategy_version"] = "1.0"
        changed = True

    # Keep the canonical tool metadata synchronized with this script version.
    tool = data.setdefault("tool", {})
    if not isinstance(tool, dict):
        raise LogoutError("tool pada logout.yaml harus berupa mapping.")

    if tool.get("script") != "logout.py":
        raise LogoutError("tool.script harus logout.py.")

    if tool.get("version") != SCRIPT_VERSION:
        tool["version"] = SCRIPT_VERSION
        changed = True

    # Migrate legacy toolchain metadata without changing assessment results.
    toolchain = data.setdefault("toolchain", {})
    if not isinstance(toolchain, dict):
        raise LogoutError("toolchain pada logout.yaml harus berupa mapping.")

    mandatory = toolchain.setdefault("mandatory", [])
    if not isinstance(mandatory, list):
        raise LogoutError("toolchain.mandatory pada logout.yaml harus berupa list.")

    # Older artifacts used preparation.context. The canonical project context
    # module is scripts.context. Keep the migration metadata-only.
    if "preparation.context" in mandatory:
        mandatory[:] = [
            "scripts.context" if item == "preparation.context" else item
            for item in mandatory
        ]
        changed = True

    if "scripts.context" not in mandatory:
        mandatory.append("scripts.context")
        changed = True

    if "scripts.secrets" not in mandatory:
        mandatory.append("scripts.secrets")
        changed = True

    # Migrate legacy post_logout_reuse records so the artifact explicitly
    # records that plaintext session material was neither logged nor persisted.
    # This is metadata/policy normalization only; it never changes the
    # authentication result, HTTP evidence, or assessment outcome.
    results = data.setdefault("results", {})
    if not isinstance(results, dict):
        raise LogoutError("results pada logout.yaml harus berupa mapping.")

    post_logout_reuse = results.setdefault("post_logout_reuse", [])
    if not isinstance(post_logout_reuse, list):
        raise LogoutError("results.post_logout_reuse pada logout.yaml harus berupa list.")

    for item in post_logout_reuse:
        if not isinstance(item, dict):
            raise LogoutError("Setiap results.post_logout_reuse harus berupa mapping.")
        if item.get("session_value_logged") is not False:
            item["session_value_logged"] = False
            changed = True
        if item.get("plaintext_session_persisted") is not False:
            item["plaintext_session_persisted"] = False
            changed = True

    if persist and changed:
        data["updated_at"] = utc_now()
        save_yaml(logout_file(), data)

    return data, changed


def ensure_project_match(data: dict[str, Any]) -> ProjectContext:
    context = active_context()
    actual = str(data.get("project_id", "")).strip()
    if actual != context.project_id:
        raise LogoutError(
            f"project_id tidak sesuai active project. Expected: {context.project_id}; Found: {actual or '-'}"
        )
    return context


def load_session_artifact() -> dict[str, Any]:
    path = project_root() / PHASE_DIR / "session" / "session.yaml"
    if not path.exists():
        raise LogoutError(f"Session artifact 5-002 tidak ditemukan: {path}")
    raw = load_yaml(path)
    if raw.get("project_id") != active_context().project_id:
        raise LogoutError("project_id pada session.yaml tidak sesuai active project.")
    return raw


def find_session(data: dict[str, Any], session_id: str) -> dict[str, Any]:
    wanted = str(session_id or "").strip().upper()
    records = (data.get("sessions") or [])
    if not isinstance(records, list):
        raise LogoutError("sessions pada session.yaml harus berupa list.")
    for item in records:
        if str(item.get("session_id", "")).upper() == wanted:
            return item
    raise LogoutError(f"Session {session_id} tidak ditemukan.")


def validate_session_record(record: dict[str, Any]) -> None:
    sid = str(record.get("session_id", "")).upper()
    if not SESSION_ID_RE.match(sid):
        raise LogoutError(f"session_id tidak valid: {sid}")
    if str(record.get("status", "")).lower() != "active":
        raise LogoutError(f"Session {sid} tidak active.")
    auth = record.get("authentication") or {}
    if str(auth.get("outcome", "")).upper() != "SUCCESS":
        raise LogoutError(
            f"Session {sid} harus memiliki authentication.outcome=SUCCESS."
        )
    if str(auth.get("type", "cookie")).lower() != "cookie":
        raise LogoutError("logout.py v1.0.0 saat ini hanya mendukung session type cookie.")
    if not auth.get("name") or not auth.get("value_encrypted"):
        raise LogoutError("Session tidak memiliki encrypted cookie value yang lengkap.")
    target = record.get("target") or {}
    if not target.get("hostname"):
        raise LogoutError("Session target hostname kosong.")


def decrypt_session_value(ciphertext: str) -> str:
    try:
        return decrypt(ciphertext, project_id=active_context().project_id)
    except SecretsError as exc:
        raise LogoutError(f"Gagal mendekripsi session value: {exc}") from exc


def target_base(record: dict[str, Any]) -> str:
    target = record.get("target") or {}
    base = str(target.get("url") or "").strip()
    if not base:
        raise LogoutError("Session target.url kosong.")
    parsed = urlparse(base)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LogoutError("Session target.url bukan URL HTTP(S) yang valid.")
    return f"{parsed.scheme}://{parsed.netloc}"


def target_url(record: dict[str, Any]) -> str:
    auth = record.get("authentication") or {}
    post_login = str(auth.get("post_login_url") or "").strip()
    if post_login:
        return post_login if post_login.startswith("http") else urljoin(target_base(record) + "/", post_login.lstrip("/"))
    return str((record.get("target") or {}).get("url") or "")


def ensure_in_scope(url: str, record: dict[str, Any]) -> None:
    parsed = urlparse(url)
    base = urlparse(target_base(record))
    if parsed.scheme not in {"http", "https"}:
        raise LogoutError("Target harus HTTP/HTTPS.")
    if parsed.hostname != base.hostname:
        raise LogoutError(
            f"Target di luar scope hostname: {parsed.hostname or '-'} != {base.hostname}"
        )
    if parsed.port and parsed.port not in {80, 443}:
        raise LogoutError(f"Target menggunakan port di luar authorized ports: {parsed.port}")


def build_session(record: dict[str, Any]) -> requests.Session:
    auth = record["authentication"]
    value = decrypt_session_value(str(auth["value_encrypted"]))
    s = requests.Session()
    s.headers.update({"User-Agent": "BrebesKab-CSIRT-Tools/5-003"})
    hostname = str((record.get("target") or {}).get("hostname") or "")
    s.cookies.set(
        str(auth["name"]),
        value,
        domain=hostname or None,
        path=str(auth.get("path") or "/"),
    )
    value = ""
    return s


def normalize_path(url: str) -> str:
    return (urlparse(url).path or "/").lower().rstrip("/") or "/"


def is_login_url(url: str) -> bool:
    path = normalize_path(url)
    return path in LOGIN_PATHS or any(path.startswith(p + "/") for p in LOGIN_PATHS)


def _action_matches_login(url: str, text: str) -> bool:
    """Return True when an HTML link/form action is a login-state indicator."""
    path = normalize_path(url)
    haystack = f"{url} {text}".lower()
    if path in LOGIN_PATHS or any(path.startswith(p + "/") for p in LOGIN_PATHS):
        return True
    if any(hint in path for hint in LOGIN_ACTION_HINTS):
        return True
    return any(token in haystack for token in LOGIN_TEXT_HINTS)


def _action_matches_logout(url: str, text: str) -> bool:
    """Return True when an HTML link/form action is a logout-state indicator."""
    path = normalize_path(url)
    haystack = f"{url} {text}".lower()
    if any(hint in path for hint in LOGOUT_ACTION_HINTS):
        return True
    return any(token in haystack for token in LOGOUT_TEXT_HINTS)


def discover_auth_state_markers(response: requests.Response, base: str) -> dict[str, Any]:
    """
    Detect authentication state using Login/Logout link or form-action markers.

    This deliberately does not treat HTTP 200, /webapp, Dashboard, Profile,
    generic navigation text, or a password modal as proof of authentication.

    The result is application-agnostic at the engine level. Applications can
    later provide additional strategies without changing this baseline strategy.
    """
    body = response.text[:DEFAULT_MAX_BODY_BYTES]
    soup = BeautifulSoup(body, "html.parser")

    login_matches: list[dict[str, Any]] = []
    logout_matches: list[dict[str, Any]] = []
    seen_login: set[tuple[str, str]] = set()
    seen_logout: set[tuple[str, str]] = set()

    for tag in soup.find_all(["a", "form", "button"]):
        if tag.name == "a":
            raw_url = str(tag.get("href") or "").strip()
            action = urljoin(response.url, raw_url) if raw_url else ""
        elif tag.name == "form":
            raw_url = str(tag.get("action") or "").strip()
            action = urljoin(response.url, raw_url or response.url)
        else:
            raw_url = str(
                tag.get("formaction")
                or tag.get("href")
                or ""
            ).strip()
            action = urljoin(response.url, raw_url) if raw_url else ""

        text = tag.get_text(" ", strip=True)
        aria = str(tag.get("aria-label") or "").strip()
        title = str(tag.get("title") or "").strip()
        marker_text = " ".join(x for x in (raw_url, text, aria, title) if x)

        if action:
            parsed = urlparse(action)
            response_host = urlparse(response.url).hostname
            base_host = urlparse(base).hostname
            if parsed.hostname and parsed.hostname not in {response_host, base_host}:
                continue

        if _action_matches_login(action, marker_text):
            key = (tag.name, action or marker_text[:200])
            if key not in seen_login:
                seen_login.add(key)
                login_matches.append({
                    "element": tag.name,
                    "url": action,
                    "text": text[:200],
                    "marker": "login",
                })

        if _action_matches_logout(action, marker_text):
            key = (tag.name, action or marker_text[:200])
            if key not in seen_logout:
                seen_logout.add(key)
                logout_matches.append({
                    "element": tag.name,
                    "url": action,
                    "text": text[:200],
                    "marker": "logout",
                })

    has_login = bool(login_matches)
    has_logout = bool(logout_matches)

    if has_logout and not has_login:
        state = "AUTHENTICATED"
        confidence = "strong"
        reason = "Logout link/action ditemukan dan Login link/action tidak ditemukan."
    elif has_login and not has_logout:
        state = "UNAUTHENTICATED"
        confidence = "strong"
        reason = "Login link/action ditemukan dan Logout link/action tidak ditemukan."
    elif has_login and has_logout:
        state = "AMBIGUOUS"
        confidence = "none"
        reason = "Login dan Logout link/action sama-sama ditemukan."
    else:
        state = "UNCONFIRMED"
        confidence = "none"
        reason = "Login maupun Logout link/action tidak ditemukan."

    return {
        "strategy": "link_action",
        "state": state,
        "confidence": confidence,
        "reason": reason,
        "login": {
            "found": has_login,
            "matches": login_matches,
        },
        "logout": {
            "found": has_logout,
            "matches": logout_matches,
        },
    }


def body_flags(text: str) -> dict[str, Any]:
    body = text[:DEFAULT_MAX_BODY_BYTES]
    normalized = re.sub(r"\s+", " ", body.lower())
    soup = BeautifulSoup(body, "html.parser")
    forms = soup.find_all("form")
    login_form = False
    for form in forms:
        names = {
            str(x.get("name") or "").lower()
            for x in form.find_all(["input", "button"])
        }
        types = {
            str(x.get("type") or "").lower()
            for x in form.find_all("input")
        }
        if "password" in types or "password" in names:
            login_form = True
            break
    failures = [m for m in FAILURE_MARKERS if m in normalized]
    return {
        "login_form_present": login_form,
        "failure_markers": failures,
        "body_length": len(body),
        "body_sample": re.sub(r"\s+", " ", body)[:BODY_SAMPLE_CHARS],
    }


def authenticated_indication(response: requests.Response, base: str) -> dict[str, Any]:
    flags = body_flags(response.text)
    state = discover_auth_state_markers(response, base)
    location = response.headers.get("Location", "")
    destination = urljoin(response.url, location) if location else response.url
    login_redirect = is_login_url(destination)

    authenticated = (
        state["state"] == "AUTHENTICATED"
        and not login_redirect
        and response.status_code not in {401, 403}
    )

    return {
        "authenticated": authenticated,
        "login_redirect": login_redirect,
        "status_code": response.status_code,
        "url": response.url,
        "location": location,
        "destination_url": destination,
        "authentication_state": state,
        "authenticated_state_markers": [
            "logout_link_or_action"
        ] if state["logout"]["found"] and not state["login"]["found"] else [],
        **flags,
    }


def discover_logout(response: requests.Response, base: str) -> list[dict[str, Any]]:
    soup = BeautifulSoup(response.text[:DEFAULT_MAX_BODY_BYTES], "html.parser")
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for tag in soup.find_all(["a", "form"]):
        if tag.name == "a":
            raw_url = str(tag.get("href") or "").strip()
            text = tag.get_text(" ", strip=True).lower()
            action = urljoin(response.url, raw_url) if raw_url else ""
            method = "GET"
            fields: list[dict[str, str]] = []
            score_text = f"{raw_url} {text}".lower()
        else:
            raw_url = str(tag.get("action") or "").strip()
            action = urljoin(response.url, raw_url or response.url)
            method = str(tag.get("method") or "GET").upper()
            text = tag.get_text(" ", strip=True).lower()
            fields = []
            for inp in tag.find_all("input"):
                name = str(inp.get("name") or "").strip()
                if not name:
                    continue
                input_type = str(inp.get("type") or "text").lower()
                if input_type in {"submit", "button", "hidden"}:
                    fields.append({
                        "name": name,
                        "value": str(inp.get("value") or ""),
                        "type": input_type,
                    })
            score_text = f"{raw_url} {text}".lower()

        path = normalize_path(action)
        if not action or path == "/":
            continue
        if urlparse(action).hostname != urlparse(base).hostname:
            continue
        if any(hint in score_text for hint in LOGOUT_PATH_HINTS):
            score = 100
        elif any(word in score_text for word in ("logout", "log out", "sign out", "signout")):
            score = 90
        else:
            continue
        key = (method, action)
        if key in seen:
            continue
        seen.add(key)
        candidates.append({
            "method": method,
            "url": action,
            "score": score,
            "text": text[:200],
            "fields": fields,
        })

    candidates.sort(key=lambda x: (-x["score"], x["url"]))
    return candidates


def build_logout_request(session: requests.Session, candidate: dict[str, Any], referer: str, timeout: int) -> requests.Response:
    method = candidate["method"]
    url = candidate["url"]
    fields = candidate.get("fields") or []
    data = {x["name"]: x["value"] for x in fields if x.get("name")}
    session.headers.update({"Referer": referer})
    if method == "POST":
        return session.post(url, data=data, timeout=timeout, allow_redirects=False)
    if method == "DELETE":
        return session.delete(url, timeout=timeout, allow_redirects=False)
    return session.get(url, timeout=timeout, allow_redirects=False)


def classify_logout(
    response: requests.Response,
    old_session: requests.Session,
    base: str,
) -> dict[str, Any]:
    flags = body_flags(response.text)
    state = discover_auth_state_markers(response, base)
    location = response.headers.get("Location", "")
    destination = urljoin(response.url, location) if location else response.url
    cookie_changes = []
    for cookie in response.cookies:
        cookie_changes.append({
            "name": cookie.name,
            "value": "[REDACTED]",
            "expires": cookie.expires,
            "max_age": cookie._rest.get("max-age"),
            "secure": cookie.secure,
            "httponly": cookie._rest.get("HttpOnly") is not None,
            "samesite": cookie._rest.get("SameSite"),
        })
    login_destination = is_login_url(destination)
    logout_indication = bool(
        login_destination
        or response.status_code in {401, 403}
        or any(
            x in flags["failure_markers"]
            for x in ("session expired", "please login", "please log in")
        )
    )
    return {
        "status_code": response.status_code,
        "url": response.url,
        "location": location,
        "destination_url": destination,
        "login_redirect": login_destination,
        "login_form_present": flags["login_form_present"],
        "authenticated_state_markers": (
            ["logout_link_or_action"]
            if state["logout"]["found"] and not state["login"]["found"]
            else []
        ),
        "authentication_state": state,
        "failure_markers": flags["failure_markers"],
        "logout_indication": logout_indication,
        "set_cookie": cookie_changes,
    }


def test_old_session_reuse(
    record: dict[str, Any],
    protected_url: str,
    base: str,
    timeout: int,
) -> dict[str, Any]:
    session = build_session(record)
    try:
        response = session.get(protected_url, timeout=timeout, allow_redirects=False)
        state = authenticated_indication(response, base)
    except requests.RequestException as exc:
        return {
            "result": "ERROR",
            "reason": f"Post-logout old-session request gagal: {exc}",
            "authenticated": False,
            "session_value_logged": False,
            "plaintext_session_persisted": False,
        }

    if state["authenticated"]:
        return {
            "result": "CONFIRMED",
            "reason": (
                "Old session setelah logout masih memperoleh authenticated-state "
                "evidence: Logout link/action ditemukan tanpa Login link/action."
            ),
            **state,
            "session_value_logged": False,
            "plaintext_session_persisted": False,
        }

    if (
        state["authentication_state"]["state"] == "UNAUTHENTICATED"
        or state["login_redirect"]
        or state["status_code"] in {401, 403}
    ):
        return {
            "result": "REJECTED",
            "reason": (
                "Old session setelah logout tidak lagi memperoleh authenticated "
                "state; Login link/action ditemukan atau akses ditolak."
            ),
            **state,
            "session_value_logged": False,
            "plaintext_session_persisted": False,
        }

    return {
        "result": "REVIEW",
        "reason": (
            "Response post-logout ambigu; Login/Logout link-action state tidak "
            "cukup untuk memastikan authenticated state."
        ),
        **state,
        "session_value_logged": False,
        "plaintext_session_persisted": False,
    }


def cmd_version(_: argparse.Namespace) -> int:
    print(f"BrebesKab-CSIRT-Tools logout.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : authorized logout + link/action auth-state detection + bounded old-session reuse")
    print("Storage  : logout.yaml + logout-probes.json; session value never persisted plaintext")
    print("Client   : requests.Session; one bounded logout and one old-session validation")
    print("Schema   : backward-compatible metadata migration for older logout.yaml artifacts")
    print("CVE      : secondary correlation only; version match != vulnerability")
    return 0


def cmd_init(_: argparse.Namespace) -> int:
    path = logout_file()
    if path.exists():
        raise LogoutError(f"Artifact sudah ada: {path}")
    data = empty_artifact()
    save_yaml(path, data)
    save_json(evidence_file(), {
        "schema_version": SCHEMA_VERSION,
        "project_id": active_context().project_id,
        "checklist": CHECKLIST_ID,
        "generated_at": utc_now(),
        "logout_probes": [],
        "errors": [],
    })
    print("[PASS] Logout artifact initialized.")
    print(f"FILE     : {path}")
    print(f"EVIDENCE : {evidence_file()}")
    return 0


def cmd_show(_: argparse.Namespace) -> int:
    data = load_artifact()
    ensure_project_match(data)
    print(yaml.safe_dump(data, allow_unicode=True, sort_keys=False))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    data = load_artifact()
    ensure_project_match(data)
    data, migrated = ensure_artifact_metadata(data, persist=True)
    if migrated:
        print("[INFO] Metadata artifact logout dimigrasikan ke schema metadata v1.0.4 tanpa mengubah evidence/assessment.")
    session_data = load_session_artifact()
    record = find_session(session_data, args.session_id)
    validate_session_record(record)

    protected_url = args.protected_url or target_url(record)
    ensure_in_scope(protected_url, record)
    timeout = max(1, int(args.timeout))

    base = target_base(record)
    auth_session = build_session(record)

    print("=" * 72)
    print(" Controlled Logout / Session Invalidation Verification")
    print("=" * 72)
    print(f"Project ID : {active_context().project_id}")
    print(f"Session ID : {record['session_id']}")
    print(f"Account ID : {record.get('account_id', '-')}")
    print(f"Protected  : {protected_url}")
    print("Client     : independent requests.Session")
    print()
    print("[PASS] Session record ditemukan.")
    print("[PASS] Authentication outcome : SUCCESS")
    print("[PASS] Session status          : active")
    print("[PASS] Session type            : cookie")
    print("[PASS] Target berada dalam scope.")
    print()

    print("[STEP] Confirming authenticated state before logout...")
    try:
        before_response = auth_session.get(protected_url, timeout=timeout, allow_redirects=False)
    except requests.RequestException as exc:
        raise LogoutError(f"Pre-logout authenticated request gagal: {exc}") from exc
    before_state = authenticated_indication(before_response, base)
    print(f"Status       : {before_state['status_code']}")
    print(f"Login redirect: {'YES' if before_state['login_redirect'] else 'NO'}")
    print(f"Login form   : {'YES' if before_state['login_form_present'] else 'NO'}")
    print(f"Auth state   : {before_state['authentication_state']['state']}")
    print(f"Login action : {'FOUND' if before_state['authentication_state']['login']['found'] else 'NOT FOUND'}")
    print(f"Logout action: {'FOUND' if before_state['authentication_state']['logout']['found'] else 'NOT FOUND'}")
    if not before_state["authenticated"]:
        raise LogoutError("Pre-logout session belum dapat dikonfirmasi authenticated; logout test dibatalkan.")
    print("[PASS] Authenticated state sebelum logout terkonfirmasi.")
    print()

    print("[STEP] Discovering logout endpoint from authenticated page...")
    candidates = discover_logout(before_response, base)
    if args.url:
        explicit = urljoin(base + "/", args.url.lstrip("/"))
        ensure_in_scope(explicit, record)
        candidates = [{"method": args.method.upper(), "url": explicit, "score": 100, "text": "explicit", "fields": []}]
    if not candidates:
        data["source_status"]["session"] = "completed"
        data["summary"]["sessions_selected"] = 1
        data["summary"]["logout_endpoint_found"] = False
        data["summary"]["requires_review"] = True
        data["assessment"] = {
            "result": "review",
            "finding": False,
            "requires_review": True,
            "note": "Logout endpoint tidak ditemukan secara aman dari authenticated page.",
        }
        data["results"]["sessions_selected"] = 1
        data["results"]["logout_candidates"] = []
        save_yaml(logout_file(), data)
        print("[REVIEW] Logout endpoint tidak ditemukan.")
        print(f"FILE     : {logout_file()}")
        print(f"EVIDENCE : {evidence_file()}")
        return 0

    candidate = candidates[0]
    print(f"[PASS] Logout candidate : {candidate['method']} {candidate['url']}")
    print()
    print("[STEP] Sending one bounded logout request...")
    try:
        logout_response = build_logout_request(
            auth_session,
            candidate,
            protected_url,
            timeout,
        )
    except requests.RequestException as exc:
        raise LogoutError(f"Logout request gagal: {exc}") from exc
    logout_state = classify_logout(logout_response, auth_session, base)
    print(f"Status       : {logout_state['status_code']}")
    print(f"Location     : {logout_state['location'] or '-'}")
    print(f"Login redirect: {'YES' if logout_state['login_redirect'] else 'NO'}")
    print(f"Set-Cookie   : {len(logout_state['set_cookie'])} cookie update(s)")
    print()

    print("[STEP] Reusing old session once after logout...")
    reuse = test_old_session_reuse(record, protected_url, base, timeout)
    print(f"Status       : {reuse.get('status_code', '-')}")
    print(f"Login redirect: {'YES' if reuse.get('login_redirect') else 'NO'}")
    print(f"Login form   : {'YES' if reuse.get('login_form_present') else 'NO'}")
    state_after = reuse.get('authentication_state') or {}
    print(f"Auth state   : {state_after.get('state', 'UNCONFIRMED')}")
    print(f"Login action : {'FOUND' if (state_after.get('login') or {}).get('found') else 'NOT FOUND'}")
    print(f"Logout action: {'FOUND' if (state_after.get('logout') or {}).get('found') else 'NOT FOUND'}")
    print(f"Old session  : {reuse['result']}")

    if reuse["result"] == "CONFIRMED":
        assessment_result = "review"
        requires_review = True
        finding = False
        note = (
            "Logout request berhasil dijalankan tetapi old authenticated session "
            "masih memperoleh authenticated-state evidence. Session invalidation "
            "failure terindikasi kuat; finding tidak dibuat otomatis."
        )
    elif reuse["result"] == "REJECTED":
        assessment_result = "pass"
        requires_review = False
        finding = False
        note = "Old authenticated session ditolak setelah logout; session invalidation terkonfirmasi."
    else:
        assessment_result = "review"
        requires_review = True
        finding = False
        note = "Post-logout old-session response ambigu; invalidation belum dapat dipastikan otomatis."

    result = {
        "session_id": record["session_id"],
        "account_id": record.get("account_id", ""),
        "protected_url": protected_url,
        "logout_candidate": {
            "method": candidate["method"],
            "url": candidate["url"],
            "score": candidate.get("score"),
        },
        "authenticated_before_logout": before_state,
        "logout": logout_state,
        "post_logout_reuse": reuse,
        "session_value_logged": False,
        "plaintext_session_persisted": False,
        "timestamp": utc_now(),
    }

    results = data.setdefault("results", {})
    results["sessions_selected"] = 1
    results["logout_candidates"] = candidates
    results["authenticated_before_logout"] = [before_state]
    results["logout"] = [logout_state]
    results["post_logout_reuse"] = [reuse]
    results["cookie_invalidation"] = logout_state.get("set_cookie", [])

    summary = data.setdefault("summary", {})
    summary.update({
        "sessions_selected": 1,
        "logout_endpoint_found": True,
        "logout_attempted": True,
        "logout_completed": bool(logout_state.get("logout_indication") or reuse["result"] == "REJECTED"),
        "old_session_reuse_tested": True,
        "old_session_replay_confirmed": reuse["result"] == "CONFIRMED",
        "session_invalidated": reuse["result"] == "REJECTED",
        "requires_review": requires_review,
        "finding": finding,
    })
    data["source_status"]["session"] = "completed"
    data["checklist"]["status"] = "completed"
    data["target"]["hostname"] = urlparse(protected_url).hostname or record["target"]["hostname"]
    data["target"]["url"] = protected_url
    data["assessment"] = {
        "result": assessment_result,
        "finding": finding,
        "requires_review": requires_review,
        "note": note,
    }

    evidence = load_json(evidence_file())
    evidence["schema_version"] = SCHEMA_VERSION
    evidence["project_id"] = active_context().project_id
    evidence["checklist"] = CHECKLIST_ID
    evidence["generated_at"] = utc_now()
    evidence.setdefault("logout_probes", []).append(result)
    evidence["errors"] = []
    save_json(evidence_file(), evidence)
    save_yaml(logout_file(), data)

    print()
    print("LOGOUT / SESSION INVALIDATION ASSESSMENT")
    print(f"Result               : {assessment_result.upper()}")
    print(f"Logout completed     : {'YES' if summary['logout_completed'] else 'NO/UNCONFIRMED'}")
    print(f"Old session reuse    : {reuse['result']}")
    print(f"Session invalidated  : {'YES' if summary['session_invalidated'] else 'NO/UNCONFIRMED'}")
    print(f"Finding              : {'REVIEW' if finding is False and requires_review else 'FALSE'}")
    print(f"Reason               : {note}")
    if reuse["result"] == "CONFIRMED":
        print("[REVIEW] Old session masih authenticated setelah logout. Lakukan assessment session invalidation/fixation; finding tidak dibuat otomatis.")
    elif reuse["result"] == "REJECTED":
        print("[PASS] Old authenticated session tidak dapat digunakan kembali setelah logout.")
    else:
        print("[REVIEW] Invalidation belum dapat dipastikan secara otomatis.")
    print(f"FILE     : {logout_file()}")
    print(f"EVIDENCE : {evidence_file()}")
    return 0


def cmd_verify(_: argparse.Namespace) -> int:
    data = load_artifact()
    ensure_project_match(data)

    # Backward-compatible metadata repair for artifacts generated by v1.0.2
    # or earlier. Only canonical metadata fields are added/updated; assessment
    # results and raw evidence remain untouched.
    data, migrated = ensure_artifact_metadata(data, persist=True)
    if migrated:
        print("[INFO] Metadata artifact lama diperbarui untuk verify; evidence dan hasil assessment tidak diubah.")

    if data.get("schema_version") != SCHEMA_VERSION:
        raise LogoutError("schema_version tidak sesuai.")
    tool = data.get("tool") or {}
    if tool.get("script") != "logout.py":
        raise LogoutError("tool.script harus logout.py.")
    if tool.get("version") != SCRIPT_VERSION:
        raise LogoutError(
            f"tool.version tidak sesuai script. Expected {SCRIPT_VERSION}; Found {tool.get('version')}"
        )
    checklist = data.get("checklist") or {}
    if checklist.get("id") != CHECKLIST_ID or checklist.get("name") != CHECKLIST_NAME:
        raise LogoutError("Metadata checklist tidak sesuai canonical schema.")
    if checklist.get("phase") != PHASE_NAME:
        raise LogoutError("checklist.phase tidak sesuai.")
    target = data.get("target") or {}
    if target.get("scope_reference") != "01-preparation/scope/scope.yaml":
        raise LogoutError("target.scope_reference tidak canonical.")
    if target.get("authorized_ports") != [80, 443]:
        raise LogoutError("target.authorized_ports harus [80, 443].")
    probe = data.get("probe") or {}
    if probe.get("authentication_state_strategy") != "link_action":
        raise LogoutError("probe.authentication_state_strategy harus link_action.")
    methodology = data.get("methodology") or {}
    if methodology.get("authentication_state_strategy") != "link_action":
        raise LogoutError("authentication_state_strategy harus link_action.")
    if methodology.get("session_value_plaintext_in_artifact") is not False:
        raise LogoutError("Plaintext session artifact policy harus false.")
    if methodology.get("automatic_finding") is not False:
        raise LogoutError("automatic_finding harus false.")
    toolchain = data.get("toolchain") or {}
    mandatory = toolchain.get("mandatory") or []
    for item in ("Python", "requests", "PyYAML", "BeautifulSoup", "session.yaml", "scripts.secrets", "scripts.context"):
        if item not in mandatory:
            raise LogoutError(f"toolchain.mandatory tidak memuat {item}.")
    results = data.get("results") or {}
    for key in ("logout_candidates", "authenticated_before_logout", "logout", "post_logout_reuse", "cookie_invalidation"):
        if not isinstance(results.get(key, []), list):
            raise LogoutError(f"results.{key} harus berupa list.")
    for item in results.get("post_logout_reuse", []):
        if item.get("session_value_logged") is not False and item.get("session_value_logged") is not None:
            raise LogoutError("post_logout_reuse session_value_logged harus false.")
        if item.get("plaintext_session_persisted") is not False:
            raise LogoutError("post_logout_reuse plaintext_session_persisted harus false.")
    evidence = load_json(evidence_file())
    if evidence.get("project_id") not in {None, "", active_context().project_id}:
        raise LogoutError("project_id evidence tidak sesuai active project.")
    for item in evidence.get("logout_probes", []):
        if item.get("plaintext_session_persisted") is not False:
            raise LogoutError("Evidence plaintext_session_persisted harus false.")
    print("[PASS] Logout / Session Invalidation memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {active_context().project_id}")
    print(f"[PASS] File      : {logout_file()}")
    print(f"[PASS] Probes    : {len(evidence.get('logout_probes', []))}")
    print("[PASS] Encoding  : UTF-8 tanpa BOM")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools - Logout / Session Invalidation"
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("version")
    sub.add_parser("init")
    run = sub.add_parser("run", help="Run one bounded logout/invalidation assessment.")
    run.add_argument("--session-id", required=True)
    run.add_argument(
        "--url",
        default="",
        help="Logout endpoint. Jika tidak diberikan, discover dari authenticated page.",
    )
    run.add_argument(
        "--method",
        default="GET",
        choices=("GET", "POST", "DELETE"),
        help="HTTP method untuk explicit --url (default GET).",
    )
    run.add_argument(
        "--protected-url",
        default="",
        help="Protected URL untuk pre/post logout validation. Default: authentication.post_login_url.",
    )
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    sub.add_parser("show")
    sub.add_parser("verify")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1
    try:
        if args.command == "version":
            return cmd_version(args)
        if args.command == "init":
            return cmd_init(args)
        if args.command == "run":
            return cmd_run(args)
        if args.command == "show":
            return cmd_show(args)
        if args.command == "verify":
            return cmd_verify(args)
        parser.error(f"Command tidak dikenal: {args.command}")
        return 2
    except KeyboardInterrupt:
        print("\n[WARN] Dibatalkan oleh pengguna.")
        return 130
    except LogoutError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] LOGOUT ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
