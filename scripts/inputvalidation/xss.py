#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Cross-Site Scripting (XSS) Assessment

Checklist: 7-002 XSS
Schema: 1.0

Purpose:
    Crawl same-origin pages from the authorized target, identify GET query
    parameters and GET-form inputs, and perform bounded, non-destructive XSS
    probes using an explicitly authorized authenticated session.

Security / assessment model:
    - Black Box assessment.
    - Target and ports are taken from the active project/scope artifacts.
    - Only same-origin HTTP(S) URLs are crawled.
    - Authentication is provided by an existing SUCCESS session; this script
      never logs in.
    - Session plaintext exists only in memory and is never written to YAML,
      JSON evidence, stdout, or logs.
    - The default probe engine uses GET only. It does not submit POST forms,
      create accounts, upload files, change application data, or bypass WAF/
      CAPTCHA challenges.
    - Payloads are bounded and non-destructive. No cookie/session exfiltration,
      credential theft, external callback, persistence, or data extraction is
      attempted.
    - Reflection is a signal, not proof of XSS.
    - A browser execution marker is stronger evidence, but automatic finding
      remains conservative; context and response evidence are retained for
      manual verification.
    - Raw forensic detail is preserved so apparently minor signals are not
      discarded during later review.

Typical workflow:
    python scripts/inputvalidation/xss.py version
    python scripts/inputvalidation/xss.py init
    python scripts/inputvalidation/xss.py crawl
    python scripts/inputvalidation/xss.py analyze
    python scripts/inputvalidation/xss.py show
    python scripts/inputvalidation/xss.py verify
    python scripts/inputvalidation/xss.py status

    Or run the complete bounded workflow:
    python scripts/inputvalidation/xss.py analyze

The script writes only its own artifacts:
    07-input-validation/xss/xss.yaml
    07-input-validation/xss/evidence/xss-probes.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

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

SCRIPT_VERSION = "1.0.2"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "7-002"
CHECKLIST_NAME = "Cross-Site Scripting (XSS)"
PHASE_NAME = "07 Input Validation"
PHASE_DIR = "07-input-validation"
CHECKLIST_DIR = "xss"
ARTIFACT_FILE = "xss.yaml"
EVIDENCE_FILE = "xss-probes.json"

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_LINKS = 0
DEFAULT_MAX_CANDIDATES = 200
DEFAULT_MAX_PARAMS_PER_URL = 5
DEFAULT_MAX_BODY_BYTES = 262144
DEFAULT_DELAY_MS = 150
DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_PROBES_PER_PARAM = 6
DEFAULT_BROWSER_TIMEOUT = 12

# Reflection payloads are deliberately unique and non-destructive.
# The execution payload only sets a window property in the target browser.
PAYLOAD_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("html-marker", "BREBESXSS_{token}"),
    ("html-tag-marker", "<x-brebes-xss data-token=\"BREBESXSS_{token}\">"),
    (
        "attribute-break-execution",
        '" autofocus onfocus="window.__BREBES_XSS__=\'BREBESXSS_{token}\'" x="',
    ),
    (
        "svg-execution",
        '<svg/onload="window.__BREBES_XSS__=\'BREBESXSS_{token}\'">',
    ),
    # Passive HTML rendering probes; no JavaScript execution.
    (
        "html-bold-render",
        "<b>BREBESXSS_{token}</b>",
    ),
    (
        "html-link-render",
        '<a href="#BREBESXSS_{token}">BREBESXSS_{token}</a>',
    ),
)

CHALLENGE_PATTERNS: tuple[str, ...] = (
    "cloudflare turnstile",
    "cf-turnstile",
    "challenges.cloudflare.com",
    "recaptcha",
    "hcaptcha",
    "captcha",
    "human verification",
    "verify you are human",
    "access denied",
)

STATE_CHANGING_PATH_PATTERNS: tuple[str, ...] = (
    r"/logout(?:/|$)",
    r"/sign[-_]?out(?:/|$)",
    r"/delete(?:/|$)",
    r"/remove(?:/|$)",
    r"/destroy(?:/|$)",
    r"/checkout(?:/|$)",
    r"/payment(?:/|$)",
    r"/confirm(?:/|$)",
    r"/submit(?:/|$)",
)

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

try:
    from context import load_active_context, get_active_project_path
    from secrets import SecretsError, decrypt, verify_key
except ImportError as exc:
    print(f"[ERROR] Gagal memuat scripts.context/scripts.secrets: {exc}")
    raise SystemExit(1)


class XSSError(RuntimeError):
    pass


class LinkParser(HTMLParser):
    """Stdlib-only HTML parser for links and GET forms."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: Optional[dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        data = {str(k).lower(): v for k, v in attrs}
        tag = tag.lower()

        if tag == "a":
            href = data.get("href")
            if href:
                self.links.append(str(href))

        if tag == "form":
            self._current_form = {
                "action": str(data.get("action") or ""),
                "method": str(data.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._current_form)

        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = data.get("name")
            if name:
                self._current_form["inputs"].append(str(name))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def project_path() -> Path:
    return Path(get_active_project_path())


def checklist_root() -> Path:
    return project_path() / PHASE_DIR / CHECKLIST_DIR


def artifact_path() -> Path:
    return checklist_root() / ARTIFACT_FILE


def evidence_path() -> Path:
    return checklist_root() / "evidence" / EVIDENCE_FILE


def load_yaml(path: Path) -> Any:
    if not path.exists():
        raise XSSError(f"Artifact tidak ditemukan: {path}")
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise XSSError(f"File menggunakan UTF-8 BOM: {path}")
    raw.decode("utf-8")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False, default_flow_style=False)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def active_context() -> Any:
    context = load_active_context()
    if str(context.assessment_type or "").strip().lower() != "black box":
        raise XSSError(
            "Assessment type active project bukan Black Box. "
            f"Nilai saat ini: {context.assessment_type!r}"
        )
    return context


def load_scope_target() -> dict[str, Any]:
    """Read authoritative IN-001 scope item; never infer target from DNS."""
    context = active_context()
    scope_file = project_path() / "01-preparation" / "scope" / "scope.yaml"
    data = load_yaml(scope_file)
    if not isinstance(data, dict):
        raise XSSError("scope.yaml tidak valid.")
    section = data.get("scope") if isinstance(data.get("scope"), dict) else data
    items = section.get("in_scope", []) if isinstance(section, dict) else []
    if not isinstance(items, list):
        raise XSSError("scope.yaml field in_scope tidak valid.")

    for item in items:
        if not isinstance(item, dict):
            continue
        scope_id = str(item.get("scope_id") or item.get("id") or "").strip()
        value = str(item.get("value") or item.get("hostname") or item.get("url") or "").strip()
        scope_type = str(item.get("type") or "").strip().lower()
        ports = item.get("ports") or []
        if scope_id != "IN-001" or not value or scope_type not in {"domain", "hostname", "url"}:
            continue
        numeric_ports = sorted(int(p) for p in ports if str(p).isdigit())
        if numeric_ports != [80, 443]:
            raise XSSError(f"IN-001 authorized ports tidak sesuai: {ports!r}")
        target = value if scope_type == "url" else f"https://{value}"
        return {
            "scope_id": scope_id,
            "hostname": urlsplit(target).hostname or value,
            "url": target.rstrip("/"),
            "ports": [80, 443],
        }
    raise XSSError("IN-001 domain/hostname tidak ditemukan pada scope.yaml.")


def initial_artifact() -> dict[str, Any]:
    context = active_context()
    scope_target = load_scope_target()
    now = now_iso()
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": context.project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "xss.py",
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "focus": (
                "Controlled XSS assessment of discovered same-origin GET query "
                "parameters and GET-form inputs using an authorized authenticated session."
            ),
            "status": "initialized",
        },
        "target": {
            "application": context.project_id,
            "hostname": scope_target["hostname"],
            "url": scope_target["url"],
            "environment": getattr(context, "environment", "") or "",
            "assessment_type": str(context.assessment_type),
            "scope_id": scope_target["scope_id"],
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": scope_target["ports"],
        },
        "methodology": {
            "description": (
                "Same-origin crawl followed by bounded non-destructive XSS probes "
                "against GET query parameters and GET forms, with optional browser verification."
            ),
            "authenticated_session_required": True,
            "session_source": "05-authentication/session/session.yaml",
            "logout_cross_check": "05-authentication/logout/logout.yaml",
            "session_secret_encryption": "project Fernet key via scripts/secrets.py",
            "plaintext_session_persisted": False,
            "same_origin_only": True,
            "redirect_following": False,
            "get_only_probe_engine": True,
            "non_destructive_payloads_only": True,
            "stored_xss_write_testing": False,
            "post_forms": False,
            "cookie_exfiltration": False,
            "external_callbacks": False,
            "captcha_turnstile_bypass": False,
            "automatic_finding": False,
            "browser_execution_verification": "optional_if_playwright_available",
            "html_rendering_verification": {
                "enabled": True,
                "tags": ["b", "a"],
                "error_response_follow_up": True,
                "javascript_execution": False,
            },
            "forensic_detail": {
                "response_fingerprint": True,
                "response_timing": True,
                "reflection_location": True,
                "html_context": True,
                "encoding_observation": True,
                "challenge_detail": True,
                "browser_console_events": True,
                "browser_execution_marker": True,
            },
        },
        "baseline": {
            "active_project": ".runtime/active-project.yaml",
            "scope_source": "01-preparation/scope/scope.yaml",
            "session_source": "05-authentication/session/session.yaml",
            "logout_source": "05-authentication/logout/logout.yaml",
            "encryption_key_source": ".runtime/secrets/<PROJECT-ID>/encryption.key",
        },
        "toolchain": {
            "mandatory": [
                "Python",
                "requests",
                "PyYAML",
                "scripts.context",
                "scripts.secrets",
                "session.yaml",
            ],
            "optional": ["Playwright", "Chromium"],
            "not_required": ["Nmap", "ffuf", "Gobuster", "sqlmap", "ZAP", "Hydra"],
        },
        "probe": {
            "engine": "requests.Session",
            "crawl": {
                "max_links": DEFAULT_MAX_LINKS,
                "max_depth": DEFAULT_MAX_DEPTH,
                "max_candidates": DEFAULT_MAX_CANDIDATES,
                "max_params_per_url": DEFAULT_MAX_PARAMS_PER_URL,
            },
            "payloads": [name for name, _ in PAYLOAD_TEMPLATES],
            "delay_ms": DEFAULT_DELAY_MS,
            "max_probes_per_param": DEFAULT_MAX_PROBES_PER_PARAM,
            "browser": {
                "enabled": False,
                "timeout_seconds": DEFAULT_BROWSER_TIMEOUT,
                "playwright_required": False,
            },
        },
        "source_status": {
            "active_project": "completed",
            "scope": "completed",
            "session": "pending",
            "logout_cross_check": "pending",
        },
        "results": {
            "links_discovered": 0,
            "same_origin_links": 0,
            "query_parameter_candidates": 0,
            "get_form_candidates": 0,
            "tested_parameters": 0,
            "probes_sent": 0,
            "baseline_requests": 0,
            "reflected_payload_signals": 0,
            "encoded_payload_signals": 0,
            "html_context_signals": 0,
            "attribute_context_signals": 0,
            "script_context_signals": 0,
            "challenge_stops": 0,
            "browser_execution_signals": 0,
            "html_rendering_signals": 0,
            "browser_html_rendering_signals": 0,
            "error_response_probes": 0,
            "request_errors": 0,
            "candidates": [],
            "probes": [],
        },
        "summary": {
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
            "note": "Belum dilakukan assessment.",
        },
        "assessment": {
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
            "note": "Belum dilakukan assessment.",
        },
        "evidence": {
            "xss_probes": f"{PHASE_DIR}/{CHECKLIST_DIR}/evidence/{EVIDENCE_FILE}",
        },
        "errors": [],
        "notes": [
            "Raw evidence is preserved; report redaction is a separate layer.",
            "Payload reflection alone is not a finding.",
            "HTML/attribute/script context is retained because context determines exploitability.",
            "Passive HTML rendering probes (<b> and <a>) are retained separately from execution probes.",
            "If a probe produces an HTTP error response, passive HTML rendering probes are still tested against that error/debug response.",
            "Encoded reflection is retained as evidence and is not silently discarded.",
            "Only authorized session S-xxx with SUCCESS outcome may be used.",
            "Browser execution marker only sets a local window property; no data is exfiltrated.",
            "Challenge responses are recorded and stop probing for that candidate.",
            "This script never modifies session.yaml or logout.yaml.",
        ],
        "generated_at": now,
        "updated_at": now,
    }


def init_artifact() -> dict[str, Any]:
    path = artifact_path()
    if path.exists():
        data = load_yaml(path)
        if not isinstance(data, dict):
            raise XSSError("xss.yaml memiliki format yang tidak valid.")
        return data
    data = initial_artifact()
    save_yaml(path, data)
    return data


def load_artifact() -> dict[str, Any]:
    data = load_yaml(artifact_path())
    if not isinstance(data, dict):
        raise XSSError("xss.yaml harus berupa mapping/object YAML.")
    return data


def project_match(data: dict[str, Any]) -> None:
    context = active_context()
    if str(data.get("project_id")) != str(context.project_id):
        raise XSSError("project_id pada xss.yaml tidak sesuai active project.")


def normalized_path(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    return path if path.startswith("/") else "/" + path


def target_origin(target_url: str) -> tuple[str, str, int]:
    parsed = urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise XSSError(f"Target URL tidak valid: {target_url}")
    return (
        parsed.scheme.lower(),
        parsed.hostname.lower(),
        parsed.port or (443 if parsed.scheme == "https" else 80),
    )


def is_in_scope_url(url: str, target_url: str) -> bool:
    try:
        scheme, host, port = target_origin(target_url)
        parsed = urlsplit(url)
        if parsed.scheme.lower() != scheme:
            return False
        if (parsed.hostname or "").lower() != host:
            return False
        candidate_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return candidate_port == port
    except ValueError:
        return False


def canonical_url(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))


def body_fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def safe_headers(response: requests.Response) -> dict[str, str]:
    secret_headers = {"authorization", "cookie", "set-cookie", "proxy-authorization"}
    result: dict[str, str] = {}
    for key, value in response.headers.items():
        if key.lower() in secret_headers:
            result[key] = "[REDACTED]"
        else:
            result[key] = str(value)[:1000]
    return result


def safe_response(response: requests.Response, body: str) -> dict[str, Any]:
    elapsed_ms = None
    try:
        elapsed_ms = round(response.elapsed.total_seconds() * 1000, 2)
    except Exception:
        pass
    return {
        "status": response.status_code,
        "url": response.url,
        "headers": safe_headers(response),
        "content_type": response.headers.get("Content-Type", ""),
        "content_length": len(body),
        "body_sha256": body_fingerprint(body),
        "body_sample": body[:4000],
        "elapsed_ms": elapsed_ms,
    }


def detect_challenge(text: str) -> list[str]:
    sample = text.lower()
    return [marker for marker in CHALLENGE_PATTERNS if marker in sample]


def decrypt_session_value(ciphertext: str, project_id: str) -> str:
    if not ciphertext:
        raise XSSError("Encrypted session value kosong.")
    try:
        return decrypt(ciphertext, project_id=project_id)
    except SecretsError as exc:
        raise XSSError(f"Gagal decrypt session value: {exc}") from exc


def recursive_find_session_ids(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in {"session_id", "session"} and isinstance(item, str):
                if re.fullmatch(r"S-\d{3,}", item.strip(), re.IGNORECASE):
                    found.add(item.strip().upper())
            found.update(recursive_find_session_ids(item))
    elif isinstance(value, list):
        for item in value:
            found.update(recursive_find_session_ids(item))
    return found


def logout_marks_session_invalidated(data: Any, session_id: str) -> bool:
    if not isinstance(data, dict):
        return False
    if session_id.upper() not in recursive_find_session_ids(data):
        return False

    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in {"session_invalidated", "invalidated", "logout_completed"} and item is True:
                    return True
                if walk(item):
                    return True
        elif isinstance(value, list):
            return any(walk(item) for item in value)
        return False

    return walk(data)


def load_usable_session() -> dict[str, Any]:
    context = active_context()
    session_file = project_path() / "05-authentication" / "session" / "session.yaml"
    logout_file = project_path() / "05-authentication" / "logout" / "logout.yaml"
    data = load_yaml(session_file)
    if not isinstance(data, dict):
        raise XSSError("session.yaml tidak valid.")
    sessions = data.get("sessions")
    if not isinstance(sessions, list):
        raise XSSError("session.yaml field 'sessions' tidak valid.")

    logout_data: Any = None
    if logout_file.exists():
        logout_data = load_yaml(logout_file)

    usable: list[dict[str, Any]] = []
    for record in sessions:
        if not isinstance(record, dict):
            continue
        session_id = str(record.get("session_id") or "").strip().upper()
        if not re.fullmatch(r"S-\d{3,}", session_id):
            continue
        if str(record.get("status") or "").lower() != "active":
            continue
        authentication = record.get("authentication")
        if not isinstance(authentication, dict):
            continue
        if str(authentication.get("outcome") or "").upper() != "SUCCESS":
            continue
        if str(authentication.get("type") or "cookie").lower() != "cookie":
            continue
        ciphertext = str(authentication.get("value_encrypted") or authentication.get("encrypted_value") or "").strip()
        name = str(authentication.get("name") or "").strip()
        if not ciphertext or not name:
            continue
        if logout_marks_session_invalidated(logout_data, session_id):
            continue
        usable.append(record)

    if not usable:
        raise XSSError(
            "Tidak ada authenticated SUCCESS session yang usable. "
            "Acquire a new session dengan session.py add --account-id TA-002."
        )

    usable.sort(key=lambda item: str(item.get("updated_at") or item.get("created_at") or ""), reverse=True)
    record = usable[0]
    authentication = record["authentication"]
    plaintext = decrypt_session_value(
        str(authentication.get("value_encrypted") or authentication.get("encrypted_value")),
        context.project_id,
    )
    if not plaintext:
        raise XSSError("Session value berhasil didecrypt tetapi kosong.")
    try:
        verify_key(context.project_id)
    except SecretsError as exc:
        raise XSSError(f"Project encryption key tidak valid: {exc}") from exc

    return {
        "session_id": str(record.get("session_id")),
        "account_id": str(record.get("account_id") or ""),
        "cookie_name": str(authentication.get("name")),
        "cookie_value": plaintext,
        "domain": str(authentication.get("domain") or ""),
        "path": str(authentication.get("path") or "/"),
    }


def build_session(base_url: str, session_info: dict[str, Any]) -> requests.Session:
    session = requests.Session()
    session.trust_env = True
    session.headers.update({
        "User-Agent": "BrebesKab-CSIRT-Tools/xss.py",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    })
    session.cookies.set(
        session_info["cookie_name"],
        session_info["cookie_value"],
        domain=session_info["domain"] or (urlsplit(base_url).hostname or ""),
        path=session_info["path"] or "/",
    )
    return session


def request_no_redirect(session: requests.Session, url: str, timeout: int) -> tuple[requests.Response, str]:
    response = session.get(url, timeout=timeout, allow_redirects=False, stream=True)
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = DEFAULT_MAX_BODY_BYTES - total
            if remaining <= 0:
                break
            piece = chunk[:remaining]
            chunks.append(piece)
            total += len(piece)
            if total >= DEFAULT_MAX_BODY_BYTES:
                break
    finally:
        response.close()
    raw = b"".join(chunks)
    body = raw.decode(response.encoding or "utf-8", errors="replace")
    return response, body


def is_safe_crawl_url(url: str) -> bool:
    path = normalized_path(url).lower()
    return not any(re.search(pattern, path) for pattern in STATE_CHANGING_PATH_PATTERNS)


def discover_links(
    session: requests.Session,
    target_url: str,
    timeout: int,
    max_links: int,
    max_depth: int,
    delay_ms: int,
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    start = canonical_url(target_url)
    queue: list[tuple[str, int]] = [(start, 0)]
    visited: set[str] = set()
    discovered: set[str] = set()
    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []

    while queue:
        current, depth = queue.pop(0)
        current = canonical_url(current)
        if current in visited or not is_in_scope_url(current, target_url) or not is_safe_crawl_url(current):
            continue
        if max_links and len(visited) >= max_links:
            break
        visited.add(current)
        try:
            response, body = request_no_redirect(session, current, timeout)
        except requests.RequestException as exc:
            pages.append({"url": current, "depth": depth, "status": None, "error": str(exc)})
            continue

        challenge = detect_challenge(body)
        parser = LinkParser()
        content_type = response.headers.get("Content-Type", "")
        if "html" in content_type.lower() or "text" in content_type.lower():
            try:
                parser.feed(body)
            except Exception:
                pass

        pages.append({
            "url": current,
            "depth": depth,
            "status": response.status_code,
            "content_type": content_type,
            "body_sha256": body_fingerprint(body),
            "body_length": len(body),
            "challenge_markers": challenge,
        })

        for href in parser.links:
            absolute = canonical_url(urljoin(current, href))
            if is_in_scope_url(absolute, target_url) and is_safe_crawl_url(absolute):
                discovered.add(absolute)
                if absolute not in visited and depth < max_depth:
                    queue.append((absolute, depth + 1))

        for form in parser.forms:
            action = canonical_url(urljoin(current, str(form.get("action") or current)))
            if not is_in_scope_url(action, target_url) or not is_safe_crawl_url(action):
                continue
            if str(form.get("method") or "get").lower() == "get":
                forms.append({
                    "page": current,
                    "action": action,
                    "method": "GET",
                    "inputs": list(form.get("inputs") or []),
                })
                discovered.add(action)

        if delay_ms:
            time.sleep(max(0, delay_ms) / 1000.0)

    urls = sorted({start, *visited, *discovered})
    return urls, pages, forms


def candidate_parameters(urls: list[str], forms: list[dict[str, Any]], max_params: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for url in urls:
        parsed = urlsplit(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in params[:max_params]:
            key = (canonical_url(url), name, "GET")
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "source": "link",
                "url": canonical_url(url),
                "parameter": name,
                "original_value": value,
                "value_profile": (
                    "numeric" if re.fullmatch(r"-?\d+(?:\.\d+)?", value or "")
                    else "uuid" if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", value or "")
                    else "text_or_unknown"
                ),
                "method": "GET",
            })

    for form in forms:
        for name in list(form.get("inputs") or [])[:max_params]:
            action = canonical_url(str(form.get("action") or ""))
            key = (action, name, "GET")
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "source": "get-form",
                "url": action,
                "page": str(form.get("page") or ""),
                "parameter": str(name),
                "original_value": "",
                "value_profile": "empty_form_value",
                "method": "GET",
            })
    return candidates


def mutate_query(url: str, parameter: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    output: list[tuple[str, str]] = []
    for name, old in pairs:
        if name == parameter and not replaced:
            output.append((name, value))
            replaced = True
        else:
            output.append((name, old))
    if not replaced:
        output.append((parameter, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(output), ""))


def build_candidate_url(candidate: dict[str, Any], value: str) -> str:
    return mutate_query(str(candidate["url"]), str(candidate["parameter"]), value)


def make_token(candidate_index: int, probe_index: int) -> str:
    seed = f"{candidate_index}:{probe_index}:{time.time_ns()}"
    return hashlib.sha256(seed.encode()).hexdigest()[:12].upper()


def render_payload(template: str, token: str) -> str:
    return template.format(token=token)


def baseline_for_candidate(session: requests.Session, candidate: dict[str, Any], timeout: int) -> dict[str, Any]:
    original = str(candidate.get("original_value") or "")
    url = build_candidate_url(candidate, original)
    response, body = request_no_redirect(session, url, timeout)
    return {
        "url": url,
        "response": safe_response(response, body),
        "challenge_markers": detect_challenge(body),
    }


def find_contexts(body: str, marker: str, limit: int = 8, context_chars: int = 220) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    if not marker:
        return contexts
    for match in re.finditer(re.escape(marker), body, flags=re.IGNORECASE):
        start = max(0, match.start() - context_chars)
        end = min(len(body), match.end() + context_chars)
        excerpt = body[start:end]
        before = body[max(0, match.start() - 120):match.start()]
        after = body[match.end():min(len(body), match.end() + 120)]
        contexts.append({
            "offset": match.start(),
            "excerpt": excerpt,
            "before": before,
            "after": after,
        })
        if len(contexts) >= limit:
            break
    return contexts


def classify_context(body: str, marker: str) -> dict[str, Any]:
    contexts = find_contexts(body, marker)
    html_context = False
    attribute_context = False
    script_context = False
    encoded = False

    for item in contexts:
        excerpt = str(item.get("excerpt") or "")
        before = str(item.get("before") or "")
        after = str(item.get("after") or "")
        if re.search(r"<script\b[^>]*>[^<]{0,400}$", before, re.I | re.S) or re.search(r"^.{0,400}</script>", after, re.I | re.S):
            script_context = True
        if re.search(r"\b(?:href|src|action|value|title|alt|data-[\w-]+)\s*=\s*[\"'][^\"']*$", before, re.I | re.S):
            attribute_context = True
        if re.search(r"<[^>]+$", before) or re.search(r"^.*?>", after, re.S):
            html_context = True
        if marker not in excerpt:
            encoded = True

    # Explicit encoded forms are evidence even when parser context is unclear.
    if re.search(r"(?:&lt;|&gt;|&quot;|&#x?27;|&#x?22;)", body, re.I):
        encoded = encoded or bool(contexts)

    return {
        "reflected": bool(contexts),
        "contexts": contexts,
        "html_context": html_context,
        "attribute_context": attribute_context,
        "script_context": script_context,
        "encoded_or_transformed": encoded,
    }


def is_error_response(probe: dict[str, Any]) -> bool:
    """Return True for HTTP 4xx/5xx responses."""
    response = probe.get("response") or {}
    try:
        status = int(response.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    return 400 <= status <= 599


def html_render_payload_names() -> set[str]:
    return {"html-bold-render", "html-link-render"}


def passive_html_render_signal(body: str, token: str) -> dict[str, Any]:
    """Detect raw passive HTML tag reflection; this is not browser proof."""
    token = str(token or "")
    if not token:
        return {
            "tag_reflected": False,
            "bold_tag_reflected": False,
            "link_tag_reflected": False,
            "html_entities_reflected": False,
        }

    bold = bool(re.search(
        rf"<b\b[^>]*>\s*BREBESXSS_{re.escape(token)}\s*</b\s*>",
        body, re.I | re.S,
    ))
    link = bool(re.search(
        rf"<a\b[^>]*>\s*BREBESXSS_{re.escape(token)}\s*</a\s*>",
        body, re.I | re.S,
    ))
    entities = bool(re.search(
        rf"(?:&lt;b\b|&lt;a\b)[^<]{{0,500}}BREBESXSS_{re.escape(token)}",
        body, re.I | re.S,
    ))
    return {
        "tag_reflected": bold or link,
        "bold_tag_reflected": bold,
        "link_tag_reflected": link,
        "html_entities_reflected": entities,
    }


def browser_verify_html_rendering(
    session_info: dict[str, Any],
    target_url: str,
    probe: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Verify whether <b>/<a> becomes a real DOM element in Chromium."""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except ImportError:
        return {"available": False, "rendered": False, "reason": "playwright_not_installed"}

    payload = str((probe.get("payload") or {}).get("value") or "")
    token = str((probe.get("payload") or {}).get("token") or "")
    url = str((probe.get("request") or {}).get("url") or "")
    if not payload or not token:
        return {"available": True, "rendered": False, "reason": "missing_payload_token"}
    if not url or not is_in_scope_url(url, target_url):
        return {"available": True, "rendered": False, "reason": "out_of_scope_url"}

    marker = f"BREBESXSS_{token}"
    console_events: list[str] = []
    page_errors: list[str] = []
    matching_elements: list[dict[str, Any]] = []
    rendered = False
    rendered_tag = ""

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            cookie = {
                "name": session_info["cookie_name"],
                "value": session_info["cookie_value"],
                "path": session_info.get("path") or "/",
            }
            domain = session_info.get("domain") or urlsplit(target_url).hostname or ""
            if domain:
                cookie["domain"] = domain
            context.add_cookies([cookie])
            page = context.new_page()
            page.on("console", lambda msg: console_events.append(str(msg.text)[:500]))
            page.on("pageerror", lambda exc: page_errors.append(str(exc)[:500]))
            try:
                page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=max(1000, timeout_seconds * 1000),
                )
            except PlaywrightTimeoutError:
                pass
            try:
                page.wait_for_timeout(500)
            except Exception:
                pass

            try:
                matching_elements = page.evaluate(
                    """(marker) => {
                        const out = [];
                        const root = document.body || document.documentElement;
                        const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
                        let node;
                        while ((node = walker.nextNode())) {
                            if (!(node.textContent || "").includes(marker)) continue;
                            const tag = node.tagName.toLowerCase();
                            if (tag === "b" || tag === "a") {
                                out.push({
                                    tag: tag,
                                    text: (node.textContent || "").slice(0, 500),
                                    href: tag === "a" ? (node.getAttribute("href") || "") : ""
                                });
                            }
                        }
                        return out.slice(0, 20);
                    }""",
                    marker,
                )
                tags = [
                    str(x.get("tag") or "").lower()
                    for x in matching_elements
                    if isinstance(x, dict)
                ]
                if "b" in tags:
                    rendered = True
                    rendered_tag = "b"
                elif "a" in tags:
                    rendered = True
                    rendered_tag = "a"
            except Exception:
                pass

            final_url = page.url
            title = page.title()
            browser.close()
    except Exception as exc:
        return {
            "available": True,
            "rendered": False,
            "reason": f"browser_error: {exc}",
            "console_events": console_events[:20],
            "page_errors": page_errors[:20],
        }

    return {
        "available": True,
        "rendered": rendered,
        "rendered_tag": rendered_tag,
        "marker": marker,
        "matching_elements": matching_elements,
        "final_url": final_url,
        "title": title,
        "console_events": console_events[:20],
        "page_errors": page_errors[:20],
    }


def probe_candidate(
    session: requests.Session,
    candidate: dict[str, Any],
    baseline: dict[str, Any],
    timeout: int,
    delay_ms: int,
    candidate_index: int,
    max_probes_per_param: int,
) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    baseline_hash = str((baseline["response"] or {}).get("body_sha256") or "")
    baseline_status = int((baseline["response"] or {}).get("status") or -1)
    baseline_len = int((baseline["response"] or {}).get("content_length") or 0)

    limit = max(1, min(int(max_probes_per_param), len(PAYLOAD_TEMPLATES)))
    for probe_index, (payload_name, template) in enumerate(PAYLOAD_TEMPLATES[:limit], start=1):
        token = make_token(candidate_index, probe_index)
        payload = render_payload(template, token)
        url = build_candidate_url(candidate, str(candidate.get("original_value") or "") + payload)
        record: dict[str, Any] = {
            "candidate": {
                "source": candidate.get("source"),
                "url": candidate.get("url"),
                "parameter": candidate.get("parameter"),
                "method": candidate.get("method"),
            },
            "payload": {
                "name": payload_name,
                "value": payload,
                "token": token,
                "execution_marker": f"BREBESXSS_{token}",
            },
            "request": {
                "method": "GET",
                "url": url,
                "redirect_following": False,
            },
        }

        try:
            response, body = request_no_redirect(session, url, timeout)
        except requests.RequestException as exc:
            record["error"] = str(exc)
            probes.append(record)
            if delay_ms:
                time.sleep(max(0, delay_ms) / 1000.0)
            continue

        marker = f"BREBESXSS_{token}"
        ctx = classify_context(body, marker)
        passive_html = passive_html_render_signal(body, token)
        challenges = detect_challenge(body)
        response_hash = body_fingerprint(body)
        body_len = len(body)
        record["response"] = safe_response(response, body)
        record["html_rendering"] = {
            "probe_type": payload_name if payload_name in html_render_payload_names() else None,
            **passive_html,
            "browser_verification": None,
        }
        record["signals"] = {
            "payload_reflected": bool(ctx["reflected"]),
            "reflection_count": len(ctx["contexts"]),
            "reflection_contexts": ctx["contexts"],
            "html_context": bool(ctx["html_context"]),
            "attribute_context": bool(ctx["attribute_context"]),
            "script_context": bool(ctx["script_context"]),
            "encoded_or_transformed": bool(ctx["encoded_or_transformed"]),
            "challenge_markers": challenges,
            "passive_html_tag_reflected": bool(passive_html["tag_reflected"]),
            "passive_html_bold_reflected": bool(passive_html["bold_tag_reflected"]),
            "passive_html_link_reflected": bool(passive_html["link_tag_reflected"]),
            "passive_html_entities_reflected": bool(passive_html["html_entities_reflected"]),
            "error_response": 400 <= int(response.status_code) <= 599,
            "body_hash_changed": response_hash != baseline_hash,
            "status_changed": int(response.status_code) != baseline_status,
            "body_length_delta": abs(body_len - baseline_len),
        }
        probes.append(record)

        # Preserve challenge-stop behavior for existing execution probes.
        # HTTP error/debug pages still receive the bounded passive HTML probes.
        if challenges and payload_name not in html_render_payload_names():
            if not is_error_response(record):
                break
        if delay_ms:
            time.sleep(max(0, delay_ms) / 1000.0)

    return probes


def try_browser_verify(
    session_info: dict[str, Any],
    target_url: str,
    candidate: dict[str, Any],
    probe: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    """Optional Playwright verification. No external callbacks and no storage writes."""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except ImportError:
        return {"available": False, "executed": False, "reason": "playwright_not_installed"}

    payload = str((probe.get("payload") or {}).get("value") or "")
    token = str((probe.get("payload") or {}).get("token") or "")
    if not payload or not token:
        return {"available": True, "executed": False, "reason": "missing_payload_token"}

    url = str((probe.get("request") or {}).get("url") or "")
    if not url or not is_in_scope_url(url, target_url):
        return {"available": True, "executed": False, "reason": "out_of_scope_url"}

    marker = f"BREBESXSS_{token}"
    console_events: list[str] = []
    page_errors: list[str] = []
    execution = False
    final_url = url
    title = ""

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            cookie = {
                "name": session_info["cookie_name"],
                "value": session_info["cookie_value"],
                "path": session_info.get("path") or "/",
            }
            domain = session_info.get("domain") or urlsplit(target_url).hostname or ""
            if domain:
                cookie["domain"] = domain
            context.add_cookies([cookie])
            page = context.new_page()

            page.on("console", lambda msg: console_events.append(str(msg.text)[:500]))
            page.on("pageerror", lambda exc: page_errors.append(str(exc)[:500]))
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=max(1000, timeout_seconds * 1000))
            except PlaywrightTimeoutError:
                pass
            try:
                page.wait_for_timeout(500)
            except Exception:
                pass

            try:
                value = page.evaluate("window.__BREBES_XSS__ || ''")
                execution = str(value) == marker
            except Exception:
                execution = False
            final_url = page.url
            title = page.title()
            browser.close()
    except Exception as exc:
        return {
            "available": True,
            "executed": False,
            "reason": f"browser_error: {exc}",
            "console_events": console_events,
            "page_errors": page_errors,
        }

    return {
        "available": True,
        "executed": execution,
        "marker": marker,
        "final_url": final_url,
        "title": title,
        "console_events": console_events[:20],
        "page_errors": page_errors[:20],
    }


def assess_candidate(candidate: dict[str, Any], baseline: dict[str, Any], probes: list[dict[str, Any]]) -> dict[str, Any]:
    reflected = False
    html_context = False
    attribute_context = False
    script_context = False
    encoded = False
    challenge = bool(baseline.get("challenge_markers"))
    browser_executed = False
    html_rendered = False
    html_rendered_tag = ""

    for probe in probes:
        signals = probe.get("signals") or {}
        reflected = reflected or bool(signals.get("payload_reflected"))
        html_context = html_context or bool(signals.get("html_context"))
        attribute_context = attribute_context or bool(signals.get("attribute_context"))
        script_context = script_context or bool(signals.get("script_context"))
        encoded = encoded or bool(signals.get("encoded_or_transformed"))
        challenge = challenge or bool(signals.get("challenge_markers"))
        browser = probe.get("browser_verification") or {}
        browser_executed = browser_executed or bool(browser.get("executed"))
        if bool(browser.get("html_rendered")):
            html_rendered = True
            html_rendered_tag = str(browser.get("rendered_tag") or html_rendered_tag)

    if browser_executed:
        result = "confirmed"
        finding = True
        requires_review = False
        note = "Browser execution marker confirmed controlled JavaScript execution in the target context."
    elif challenge:
        result = "requires_review"
        finding = False
        requires_review = True
        note = "Human-interaction/challenge response detected; probing stopped for this candidate."
    elif reflected and (html_context or attribute_context or script_context):
        result = "requires_review"
        finding = False
        requires_review = True
        note = "Payload reflection occurred in an HTML/attribute/script context; browser execution was not confirmed."
    elif html_rendered:
        result = "requires_review"
        finding = False
        requires_review = True
        note = (
            f"Passive HTML rendering confirmed in browser as <{html_rendered_tag}>; "
            "JavaScript execution was not confirmed."
        )
    elif reflected:
        result = "not_confirmed"
        finding = False
        requires_review = False
        note = "Payload reflection observed without confirmed executable context."
    else:
        result = "pass"
        finding = False
        requires_review = False
        note = "No controlled payload reflection observed in bounded probes."

    return {
        "result": result,
        "finding": finding,
        "requires_review": requires_review,
        "payload_reflected": reflected,
        "html_context": html_context,
        "attribute_context": attribute_context,
        "script_context": script_context,
        "encoded_or_transformed": encoded,
        "browser_execution_confirmed": browser_executed,
        "html_rendered_in_browser": html_rendered,
        "html_rendered_tag": html_rendered_tag,
        "note": note,
    }


def update_result_counts(data: dict[str, Any], candidates: list[dict[str, Any]], probes: list[dict[str, Any]]) -> None:
    results = data.setdefault("results", {})
    results["tested_parameters"] = len(candidates)
    results["probes_sent"] = len(probes)
    results["baseline_requests"] = sum(1 for c in candidates if c.get("baseline"))
    results["reflected_payload_signals"] = sum(
        1 for p in probes if (p.get("signals") or {}).get("payload_reflected")
    )
    results["encoded_payload_signals"] = sum(
        1 for p in probes if (p.get("signals") or {}).get("encoded_or_transformed")
    )
    results["html_context_signals"] = sum(1 for p in probes if (p.get("signals") or {}).get("html_context"))
    results["attribute_context_signals"] = sum(1 for p in probes if (p.get("signals") or {}).get("attribute_context"))
    results["script_context_signals"] = sum(1 for p in probes if (p.get("signals") or {}).get("script_context"))
    results["challenge_stops"] = sum(1 for p in probes if (p.get("signals") or {}).get("challenge_markers"))
    results["browser_execution_signals"] = sum(
        1 for p in probes if (p.get("browser_verification") or {}).get("executed")
    )
    results["html_rendering_signals"] = sum(
        1 for p in probes if (p.get("signals") or {}).get("passive_html_tag_reflected")
    )
    results["browser_html_rendering_signals"] = sum(
        1 for p in probes if (p.get("browser_verification") or {}).get("html_rendered")
    )
    results["error_response_probes"] = sum(
        1 for p in probes if (p.get("signals") or {}).get("error_response")
    )
    results["request_errors"] = sum(1 for p in probes if p.get("error"))


def aggregate_summary(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    findings = [c for c in candidates if (c.get("assessment") or {}).get("finding")]
    reviews = [c for c in candidates if (c.get("assessment") or {}).get("requires_review")]
    if findings:
        return {
            "result": "confirmed",
            "finding": True,
            "requires_review": bool(reviews),
            "note": "At least one candidate has controlled browser execution evidence; review preserved evidence before reporting.",
        }
    if reviews:
        return {
            "result": "requires_review",
            "finding": False,
            "requires_review": True,
            "note": "No automatically confirmed XSS unless browser execution was observed; review candidates with reflection/context signals.",
        }
    if candidates:
        return {
            "result": "pass",
            "finding": False,
            "requires_review": False,
            "note": "No XSS execution or strong reflection/context evidence observed in bounded probes.",
        }
    return {
        "result": "not-tested",
        "finding": False,
        "requires_review": False,
        "note": "Tidak ada candidate yang diuji.",
    }


def cmd_version(_: argparse.Namespace) -> int:
    print(f"BrebesKab-CSIRT-Tools XSS {SCRIPT_VERSION}")
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema    : {SCHEMA_VERSION}")
    return 0


def cmd_init(_: argparse.Namespace) -> int:
    data = init_artifact()
    print("[PASS] XSS artifact siap.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {data.get('project_id')}")
    print(f"[PASS] File      : {artifact_path()}")
    return 0


def cmd_crawl(args: argparse.Namespace) -> int:
    data = init_artifact()
    project_match(data)
    target = load_scope_target()
    session_info = load_usable_session()
    data["source_status"]["session"] = "completed"
    data["source_status"]["logout_cross_check"] = "completed"
    session = build_session(target["url"], session_info)

    urls, pages, forms = discover_links(
        session,
        target["url"],
        args.timeout,
        args.max_links,
        args.max_depth,
        args.delay_ms,
    )
    candidates = candidate_parameters(urls, forms, args.max_params_per_url)
    if args.max_candidates and len(candidates) > args.max_candidates:
        candidates = candidates[:args.max_candidates]

    data["crawl"] = {
        "pages": pages,
        "forms": forms,
        "urls": urls,
    }
    data["results"]["links_discovered"] = len(urls)
    data["results"]["same_origin_links"] = len([u for u in urls if is_in_scope_url(u, target["url"])])
    data["results"]["query_parameter_candidates"] = len([c for c in candidates if c.get("source") == "link"])
    data["results"]["get_form_candidates"] = len([c for c in candidates if c.get("source") == "get-form"])
    data["candidates"] = candidates
    data["checklist"]["status"] = "crawled"
    data["updated_at"] = now_iso()
    save_yaml(artifact_path(), data)

    print("[PASS] XSS crawl selesai.")
    print(f"[PASS] Links     : {len(urls)}")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(f"[PASS] GET forms : {len([c for c in candidates if c.get('source') == 'get-form'])}")
    print(f"[PASS] File      : {artifact_path()}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    data = init_artifact()
    project_match(data)
    target = load_scope_target()
    session_info = load_usable_session()
    data["source_status"]["session"] = "completed"
    data["source_status"]["logout_cross_check"] = "completed"
    session = build_session(target["url"], session_info)

    urls, pages, forms = discover_links(
        session,
        target["url"],
        args.timeout,
        args.max_links,
        args.max_depth,
        args.delay_ms,
    )
    candidates = candidate_parameters(urls, forms, args.max_params_per_url)
    if args.max_candidates and len(candidates) > args.max_candidates:
        candidates = candidates[:args.max_candidates]

    all_probes: list[dict[str, Any]] = []
    assessed_candidates: list[dict[str, Any]] = []
    browser_requested = bool(args.browser)
    browser_available = None

    if browser_requested:
        try:
            import playwright  # noqa: F401
            browser_available = True
        except ImportError:
            browser_available = False

        print("[STEP] Browser verification")
        print("[INFO] Engine     : Playwright / Chromium")
        print("[INFO] Mode       : Headless")
        print("[INFO] Purpose    : Verify reflected HTML rendering and JavaScript execution")
        print(f"[INFO] Candidates : {len(candidates)}")
        print(
            "[INFO] Payloads   : "
            "html-tag-marker, html-bold-render, html-link-render, "
            "attribute-break-execution, svg-execution"
        )
        print(f"[INFO] Available  : {'YES' if browser_available else 'NO'}")
        if not browser_available:
            print("[WARN] Playwright tidak tersedia; browser verification dilewati.")
        print()

    for index, candidate in enumerate(candidates, start=1):
        try:
            baseline = baseline_for_candidate(session, candidate, args.timeout)
        except requests.RequestException as exc:
            assessed_candidates.append({
                **candidate,
                "baseline": {"error": str(exc)},
                "probes": [],
                "assessment": {
                    "result": "request_error",
                    "finding": False,
                    "requires_review": True,
                    "note": "Baseline request failed; candidate requires manual review.",
                },
            })
            continue

        probes = probe_candidate(
            session,
            candidate,
            baseline,
            args.timeout,
            args.delay_ms,
            index,
            args.max_probes_per_param,
        )

        for probe in probes:
            if args.browser and not probe.get("error"):
                payload_name = str((probe.get("payload") or {}).get("name") or "")
                if payload_name in html_render_payload_names():
                    browser = browser_verify_html_rendering(
                        session_info,
                        target["url"],
                        probe,
                        args.browser_timeout,
                    )
                    probe["browser_verification"] = {
                        "available": browser.get("available"),
                        "executed": False,
                        "html_rendered": bool(browser.get("rendered")),
                        "rendered_tag": browser.get("rendered_tag"),
                        "marker": browser.get("marker"),
                        "matching_elements": browser.get("matching_elements", []),
                        "final_url": browser.get("final_url"),
                        "title": browser.get("title"),
                        "console_events": browser.get("console_events", []),
                        "page_errors": browser.get("page_errors", []),
                        "reason": browser.get("reason"),
                    }
                    probe.setdefault("html_rendering", {})["browser_verification"] = probe["browser_verification"]
                else:
                    browser = try_browser_verify(
                        session_info,
                        target["url"],
                        candidate,
                        probe,
                        args.browser_timeout,
                    )
                    probe["browser_verification"] = browser

                if browser_requested:
                    response = probe.get("response") or {}
                    signals = probe.get("signals") or {}
                    payload_name = str((probe.get("payload") or {}).get("name") or "")
                    status = response.get("status", "-")
                    reflected = "YES" if signals.get("payload_reflected") else "NO"
                    browser_result = probe.get("browser_verification") or {}
                    available = bool(browser_result.get("available"))

                    if not available:
                        browser_state = "SKIPPED"
                    elif bool(browser_result.get("executed")):
                        browser_state = "EXECUTED"
                    elif bool(browser_result.get("html_rendered")):
                        browser_state = "REVIEW"
                    else:
                        browser_state = "PASS"

                    print(f"[TEST] [{index}/{len(candidates)}] {candidate.get('url')}")
                    print(f"       Parameter: {candidate.get('parameter')}")
                    print(f"       Payload  : {payload_name}")
                    print(f"       Status   : HTTP {status}")
                    print(f"       Reflected: {reflected}")

                    if payload_name in html_render_payload_names():
                        if bool(browser_result.get("html_rendered")):
                            rendered_tag = str(browser_result.get("rendered_tag") or "?")
                            html_state = f"RENDERED <{rendered_tag}>"
                        else:
                            html_state = "NOT RENDERED"
                        print(f"       HTML     : {html_state}")
                        print(f"       Browser  : {browser_state}")
                    else:
                        js_state = "EXECUTED" if bool(browser_result.get("executed")) else "NOT EXECUTED"
                        print(f"       JavaScript: {js_state}")
                        print(f"       Browser   : {browser_state}")
                    print()

        assessment = assess_candidate(candidate, baseline, probes)
        candidate_record = {
            **candidate,
            "baseline": baseline,
            "probes": probes,
            "assessment": assessment,
        }
        assessed_candidates.append(candidate_record)
        all_probes.extend(probes)

        if any((p.get("signals") or {}).get("challenge_markers") for p in probes):
            # Challenge response is already preserved; do not hammer it.
            pass

    data["crawl"] = {"pages": pages, "forms": forms, "urls": urls}
    data["candidates"] = assessed_candidates
    data["results"]["links_discovered"] = len(urls)
    data["results"]["same_origin_links"] = len([u for u in urls if is_in_scope_url(u, target["url"])])
    data["results"]["query_parameter_candidates"] = len([c for c in assessed_candidates if c.get("source") == "link"])
    data["results"]["get_form_candidates"] = len([c for c in assessed_candidates if c.get("source") == "get-form"])
    data["probe"]["browser"]["enabled"] = browser_requested
    data["probe"]["browser"]["playwright_required"] = browser_requested
    data["probe"]["browser"]["available"] = browser_available
    update_result_counts(data, assessed_candidates, all_probes)
    summary = aggregate_summary(assessed_candidates)
    data["summary"] = summary
    data["assessment"] = dict(summary)
    data["checklist"]["status"] = "completed"
    data["updated_at"] = now_iso()

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "BrebesKab-CSIRT-Tools", "script": "xss.py", "version": SCRIPT_VERSION},
        "checklist": {"id": CHECKLIST_ID, "name": CHECKLIST_NAME},
        "project_id": data.get("project_id"),
        "target": data.get("target"),
        "browser": data["probe"]["browser"],
        "generated_at": now_iso(),
        "candidates": assessed_candidates,
    }
    save_json(evidence_path(), evidence)
    data["results"]["probes"] = all_probes
    save_yaml(artifact_path(), data)

    print(f"[PASS] XSS analysis selesai: {summary['result']}")
    print(f"[INFO] Candidates: {len(assessed_candidates)}")
    print(f"[INFO] Probes    : {len(all_probes)}")
    print(f"[INFO] Finding   : {summary['finding']}")
    print(f"[INFO] Review    : {summary['requires_review']}")
    if browser_requested:
        browser_rendered = sum(
            1 for p in all_probes
            if (p.get("browser_verification") or {}).get("html_rendered")
        )
        browser_executed = sum(
            1 for p in all_probes
            if (p.get("browser_verification") or {}).get("executed")
        )
        print("[RESULT] Browser verification completed")
        print(f"[INFO] HTML rendered : {browser_rendered}")
        print(f"[INFO] JS executed   : {browser_executed}")
    print(f"[PASS] Artifact  : {artifact_path()}")
    print(f"[PASS] Evidence  : {evidence_path()}")
    return 0


def cmd_show(_: argparse.Namespace) -> int:
    data = load_artifact()
    project_match(data)
    print(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False))
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    data = load_artifact()
    project_match(data)
    checklist = data.get("checklist") or {}
    summary = data.get("summary") or {}
    results = data.get("results") or {}
    print(f"Checklist : {checklist.get('id')} {checklist.get('name')}")
    print(f"Status    : {checklist.get('status')}")
    print(f"Result    : {summary.get('result')}")
    print(f"Finding   : {summary.get('finding')}")
    print(f"Review    : {summary.get('requires_review')}")
    print(f"Candidates: {results.get('tested_parameters', 0)}")
    print(f"Probes    : {results.get('probes_sent', 0)}")
    print(f"Artifact  : {artifact_path()}")
    return 0


def cmd_verify(_: argparse.Namespace) -> int:
    data = load_artifact()
    project_match(data)
    errors: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai")
    if str((data.get("tool") or {}).get("script")) != "xss.py":
        errors.append("tool.script bukan xss.py")
    if str((data.get("tool") or {}).get("version")) != SCRIPT_VERSION:
        errors.append("tool.version tidak sesuai")
    checklist = data.get("checklist") or {}
    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist.id bukan 7-002")
    results = data.get("results") or {}
    candidates = data.get("candidates") or []
    probes = results.get("probes") or []
    if not isinstance(candidates, list):
        errors.append("candidates bukan list")
    if not isinstance(probes, list):
        errors.append("results.probes bukan list")
    if int(results.get("tested_parameters", -1)) != len(candidates):
        errors.append("tested_parameters tidak sama dengan jumlah candidates")
    if int(results.get("probes_sent", -1)) != len(probes):
        errors.append("probes_sent tidak sama dengan jumlah probes")
    if not evidence_path().exists():
        errors.append(f"evidence tidak ditemukan: {evidence_path()}")
    else:
        raw = evidence_path().read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            errors.append("evidence menggunakan UTF-8 BOM")
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append("evidence bukan UTF-8 valid")

    # Verify each probe remains bounded and GET-only.
    for idx, probe in enumerate(probes, start=1):
        request = probe.get("request") or {}
        if str(request.get("method") or "").upper() != "GET":
            errors.append(f"probe #{idx} bukan GET")
        url = str(request.get("url") or "")
        if url and not is_in_scope_url(url, str((data.get("target") or {}).get("url") or "")):
            errors.append(f"probe #{idx} berada di luar scope")
        if "cookie" in json.dumps(request).lower():
            errors.append(f"probe #{idx} mengandung kata cookie pada request evidence")

    if errors:
        print("[FAIL] XSS tidak memenuhi validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    encoding_ok = True
    artifact_raw = artifact_path().read_bytes()
    if artifact_raw.startswith(b"\xef\xbb\xbf"):
        encoding_ok = False
    try:
        artifact_raw.decode("utf-8")
    except UnicodeDecodeError:
        encoding_ok = False

    print("[PASS] XSS memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {data.get('project_id')}")
    print(f"[PASS] File      : {artifact_path()}")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(f"[PASS] Probes    : {len(probes)}")
    print(f"[PASS] Encoding  : {'UTF-8 tanpa BOM' if encoding_ok else 'INVALID'}")
    return 0


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-links", type=int, default=DEFAULT_MAX_LINKS)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    parser.add_argument("--max-params-per-url", type=int, default=DEFAULT_MAX_PARAMS_PER_URL)
    parser.add_argument("--delay-ms", type=int, default=DEFAULT_DELAY_MS)
    parser.add_argument("--max-probes-per-param", type=int, default=DEFAULT_MAX_PROBES_PER_PARAM)
    parser.add_argument("--browser", action="store_true", help="Aktifkan Playwright browser execution verification.")
    parser.add_argument("--browser-timeout", type=int, default=DEFAULT_BROWSER_TIMEOUT)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools XSS assessment (checklist 7-002)."
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version", help="Tampilkan versi tool.")
    sub.add_parser("init", help="Buat artifact xss.yaml.")

    for command, help_text in [
        ("crawl", "Crawl same-origin dan identifikasi candidate input."),
        ("analyze", "Crawl + bounded XSS assessment."),
    ]:
        p = sub.add_parser(command, help=help_text)
        add_common(p)

    sub.add_parser("show", help="Tampilkan xss.yaml.")
    sub.add_parser("status", help="Tampilkan status checklist.")
    sub.add_parser("verify", help="Validasi artifact dan evidence.")
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
        if args.command == "crawl":
            return cmd_crawl(args)
        if args.command == "analyze":
            return cmd_analyze(args)
        if args.command == "show":
            return cmd_show(args)
        if args.command == "status":
            return cmd_status(args)
        if args.command == "verify":
            return cmd_verify(args)
        parser.error(f"Command tidak dikenal: {args.command}")
        return 2
    except KeyboardInterrupt:
        print("\n[WARN] Assessment dibatalkan oleh pengguna.")
        return 130
    except XSSError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except requests.RequestException as exc:
        print(f"[FAIL] Request error: {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] XSS ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
