#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - SQL Injection Assessment

Checklist: 7-001 SQL Injection
Schema: 1.0

Purpose:
    Crawl same-origin links from the authorized target, identify URLs that
    contain injectable query parameters, and perform bounded, non-destructive
    SQL injection probes using an explicitly authorized authenticated session.

Security / assessment model:
    - Black Box assessment.
    - Target and ports are taken from the active project/scope artifacts.
    - Only same-origin HTTP(S) URLs are crawled.
    - Authentication is provided by an existing SUCCESS session from
      05-authentication/session/session.yaml; this script never logs in.
    - logout.yaml is cross-checked when it contains an explicit matching
      session identifier. logout.py is never modified.
    - Session plaintext exists only in memory and is never written to YAML,
      JSON evidence, stdout, or logs.
    - Only GET requests are used by the default SQLi probe engine. No INSERT,
      UPDATE, DELETE, DROP, ALTER, stacked-query, UNION data extraction, or
      database dumping payloads are used.
    - No unrestricted sqlmap, brute force, credential testing, or WAF/CAPTCHA
      bypass is performed.
    - A response difference, SQL error marker, or reflected payload is only a
      candidate signal. It is not automatically a vulnerability finding.
    - Finding is true only when the controlled differential evidence is strong
      enough to support confirmation; otherwise the result is pass,
      not_confirmed, or requires_review.

Typical workflow:
    python scripts/inputvalidation/sqli.py version
    python scripts/inputvalidation/sqli.py init
    python scripts/inputvalidation/sqli.py crawl
    python scripts/inputvalidation/sqli.py analyze
    python scripts/inputvalidation/sqli.py show
    python scripts/inputvalidation/sqli.py verify
    python scripts/inputvalidation/sqli.py status

    Or run the complete bounded workflow:
    python scripts/inputvalidation/sqli.py analyze

The script writes only its own artifacts:
    07-input-validation/sqli/sqli.yaml
    07-input-validation/sqli/evidence/sqli-probes.json
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
CHECKLIST_ID = "7-001"
CHECKLIST_NAME = "SQL Injection"
PHASE_NAME = "07 Input Validation"
PHASE_DIR = "07-input-validation"
CHECKLIST_DIR = "sqli"
ARTIFACT_FILE = "sqli.yaml"
EVIDENCE_FILE = "sqli-probes.json"

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_LINKS = 0  # 0 = all same-origin links discovered within crawl scope.
DEFAULT_MAX_CANDIDATES = 200
DEFAULT_MAX_PARAMS_PER_URL = 5
DEFAULT_MAX_BODY_BYTES = 262144
DEFAULT_DELAY_MS = 150
DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_PROBES_PER_PARAM = 3

# Deliberately small and non-destructive. These payloads are intended to
# produce syntax/boolean differential signals, not to extract or modify data.
SQLI_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("quote-single", "'"),
    ("boolean-true", "' AND 1=1-- "),
    ("boolean-false", "' AND 1=2-- "),
)

SQL_ERROR_PATTERNS: tuple[tuple[str, str], ...] = (
    ("mysql", r"(?:mysql|mysqli|pdo_mysql).*?(?:syntax|sql|query|error)"),
    ("mariadb", r"mariadb.*?(?:syntax|sql|query|error)"),
    ("postgresql", r"(?:postgresql|postgres|pg_query).*?(?:syntax|error)"),
    ("mssql", r"(?:sql server|microsoft sql|odbc sql server).*?(?:error|syntax)"),
    ("oracle", r"(?:ora-\d{5}|oracle).*?(?:error|syntax)"),
    ("sqlite", r"(?:sqlite|sqlite3).*?(?:error|syntax)"),
    ("generic-sql", r"(?:sql syntax|sqlstate|database query failed|database error)"),
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
)

STATE_CHANGING_PATH_PATTERNS: tuple[str, ...] = (
    r"/logout(?:/|$)",
    r"/sign[-_]?out(?:/|$)",
    r"/delete(?:/|$)",
    r"/remove(?:/|$)",
    r"/destroy(?:/|$)",
    r"/checkout(?:/|$)",
    r"/payment(?:/|$)",
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


class SQLiError(RuntimeError):
    pass


class LinkParser(HTMLParser):
    """Small stdlib-only HTML link extractor; no JavaScript execution."""

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


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


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
        raise SQLiError(f"Artifact tidak ditemukan: {path}")
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SQLiError(f"File menggunakan UTF-8 BOM: {path}")
    raw.decode("utf-8")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(
            data,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def active_context() -> Any:
    context = load_active_context()
    if str(context.assessment_type or "").strip().lower() != "black box":
        raise SQLiError(
            "Assessment type active project bukan Black Box. "
            f"Nilai saat ini: {context.assessment_type!r}"
        )
    return context


def load_scope_target() -> dict[str, Any]:
    """Read the authoritative IN-001 scope item; never infer the target from DNS."""
    context = active_context()
    scope_file = project_path() / "01-preparation" / "scope" / "scope.yaml"
    data = load_yaml(scope_file)
    if not isinstance(data, dict):
        raise SQLiError("scope.yaml tidak valid.")
    section = data.get("scope") if isinstance(data.get("scope"), dict) else data
    items = section.get("in_scope", []) if isinstance(section, dict) else []
    if not isinstance(items, list):
        raise SQLiError("scope.yaml field in_scope tidak valid.")
    for item in items:
        if not isinstance(item, dict):
            continue
        scope_id = str(item.get("scope_id") or item.get("id") or "").strip()
        value = str(item.get("value") or item.get("hostname") or item.get("url") or "").strip()
        scope_type = str(item.get("type") or "").strip().lower()
        ports = item.get("ports") or []
        if scope_id == "IN-001" and value and scope_type in {"domain", "hostname", "url"}:
            if isinstance(ports, list) and sorted(int(p) for p in ports if str(p).isdigit()) != [80, 443]:
                raise SQLiError(f"IN-001 authorized ports tidak sesuai: {ports!r}")
            if scope_type == "url":
                target = value
            else:
                target = f"https://{value}"
            return {
                "scope_id": scope_id,
                "hostname": urlsplit(target).hostname or value,
                "url": target.rstrip("/"),
                "ports": [80, 443],
            }
    raise SQLiError("IN-001 domain/hostname tidak ditemukan pada scope.yaml.")


def initial_artifact() -> dict[str, Any]:
    context = active_context()
    scope_target = load_scope_target()
    target = scope_target["url"]
    hostname = scope_target["hostname"]

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": context.project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "sqli.py",
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "focus": (
                "Controlled SQL injection assessment of discovered same-origin "
                "URL query parameters using an authorized authenticated session."
            ),
            "status": "initialized",
        },
        "target": {
            "application": context.project_id,
            "hostname": hostname,
            "url": str(target),
            "environment": getattr(context, "environment", "") or "",
            "assessment_type": str(context.assessment_type),
            "scope_id": scope_target["scope_id"],
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": scope_target["ports"],
        },
        "methodology": {
            "description": (
                "Same-origin crawl followed by bounded SQLi differential probes "
                "against URL query parameters."
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
            "data_extraction": False,
            "stacked_queries": False,
            "write_queries": False,
            "mass_fuzzing": False,
            "captcha_turnstile_bypass": False,
            "automatic_finding": False,
            "forensic_detail": {
                "response_fingerprint": True,
                "response_timing": True,
                "sql_error_context": True,
                "true_false_differential_detail": True,
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
            "optional": ["curl", "Playwright", "sqlmap"],
            "not_required": ["Nmap", "ffuf", "Gobuster", "ZAP", "Hydra"],
        },
        "probe": {
            "engine": "requests.Session",
            "crawl": {
                "max_links": DEFAULT_MAX_LINKS,
                "max_depth": DEFAULT_MAX_DEPTH,
                "max_candidates": DEFAULT_MAX_CANDIDATES,
                "max_params_per_url": DEFAULT_MAX_PARAMS_PER_URL,
            },
            "payloads": [name for name, _ in SQLI_PAYLOADS],
            "delay_ms": DEFAULT_DELAY_MS,
            "max_probes_per_param": DEFAULT_MAX_PROBES_PER_PARAM,
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
            "tested_parameters": 0,
            "probes_sent": 0,
            "baseline_requests": 0,
            "sql_error_signals": 0,
            "differential_signals": 0,
            "reflected_payload_signals": 0,
            "challenge_stops": 0,
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
        "cve_correlation": {
            "status": "not-tested",
            "candidate_count": 0,
            "candidates": [],
            "assessment_note": (
                "CVE correlation is secondary triage evidence; version match does "
                "not establish SQL injection exploitability or vulnerability."
            ),
        },
        "assessment": {
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
            "note": "Belum dilakukan assessment.",
        },
        "evidence": {
            "sqli_probes": f"{PHASE_DIR}/{CHECKLIST_DIR}/evidence/{EVIDENCE_FILE}",
        },
        "errors": [],
        "notes": [
            "Raw evidence is preserved; report redaction is a separate layer.",
            "HTTP 200, reflected payload, or generic error alone is not a finding.",
            "Only authorized session S-xxx with SUCCESS outcome may be used.",
            "Detailed response metadata is retained for assessment; authentication secrets remain protected.",
            "SQL error context is evidence, not automatic proof; challenge responses are recorded and stop probing for that candidate.",
            "This script never modifies session.yaml or logout.yaml.",
        ],
        "generated_at": now_iso(),
        "updated_at": now_iso(),
    }


def init_artifact() -> dict[str, Any]:
    path = artifact_path()
    if path.exists():
        data = load_yaml(path)
        if not isinstance(data, dict):
            raise SQLiError("sqli.yaml memiliki format yang tidak valid.")
        return data
    data = initial_artifact()
    save_yaml(path, data)
    return data


def load_artifact() -> dict[str, Any]:
    data = load_yaml(artifact_path())
    if not isinstance(data, dict):
        raise SQLiError("sqli.yaml harus berupa mapping/object YAML.")
    return data


def project_match(data: dict[str, Any]) -> None:
    context = active_context()
    if str(data.get("project_id")) != str(context.project_id):
        raise SQLiError("project_id pada sqli.yaml tidak sesuai active project.")


def normalized_path(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def target_origin(target_url: str) -> tuple[str, str, int]:
    parsed = urlsplit(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SQLiError(f"Target URL tidak valid: {target_url}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme.lower(), parsed.hostname.lower(), port


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


def similarity_score(a: str, b: str) -> float:
    """Cheap normalized length similarity; not used as proof by itself."""
    if not a and not b:
        return 1.0
    max_len = max(len(a), len(b), 1)
    return 1.0 - (abs(len(a) - len(b)) / max_len)


def find_sql_errors(text: str) -> list[str]:
    sample = text[:DEFAULT_MAX_BODY_BYTES].lower()
    found: list[str] = []
    for name, pattern in SQL_ERROR_PATTERNS:
        if re.search(pattern, sample, flags=re.IGNORECASE | re.DOTALL):
            found.append(name)
    return found


def sql_error_contexts(text: str, limit_per_marker: int = 3, context_chars: int = 180) -> dict[str, list[str]]:
    """Return short local excerpts around SQL error markers for forensic detail."""
    sample = text[:DEFAULT_MAX_BODY_BYTES]
    contexts: dict[str, list[str]] = {}
    for name, pattern in SQL_ERROR_PATTERNS:
        matches = list(re.finditer(pattern, sample, flags=re.IGNORECASE | re.DOTALL))
        if not matches:
            continue
        excerpts: list[str] = []
        for match in matches[:limit_per_marker]:
            start = max(0, match.start() - context_chars)
            end = min(len(sample), match.end() + context_chars)
            excerpts.append(sample[start:end])
        contexts[name] = excerpts
    return contexts


def detect_challenge(text: str) -> list[str]:
    sample = text.lower()
    return [marker for marker in CHALLENGE_PATTERNS if marker in sample]


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


def decrypt_session_value(ciphertext: str, project_id: str) -> str:
    if not ciphertext:
        raise SQLiError("Encrypted session value kosong.")
    try:
        return decrypt(ciphertext, project_id=project_id)
    except SecretsError as exc:
        raise SQLiError(f"Gagal decrypt session value: {exc}") from exc


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
    """Only block when logout evidence explicitly names this session and invalidates it."""
    if not isinstance(data, dict):
        return False

    explicit_ids = recursive_find_session_ids(data)
    if session_id.upper() not in explicit_ids:
        return False

    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                key_l = str(key).lower()
                if key_l in {
                    "session_invalidated",
                    "invalidated",
                    "logout_completed",
                } and item is True:
                    return True
                if key_l in {
                    "old_session_replay_confirmed",
                    "replay_confirmed",
                } and item is False:
                    # False replay alone does not mean invalidated; keep walking.
                    pass
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
        raise SQLiError("session.yaml tidak valid.")

    sessions = data.get("sessions")
    if not isinstance(sessions, list):
        raise SQLiError("session.yaml field 'sessions' tidak valid.")

    logout_data: Any = None
    if logout_file.exists():
        try:
            logout_data = load_yaml(logout_file)
        except Exception as exc:
            raise SQLiError(f"Gagal membaca logout.yaml: {exc}") from exc

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
        ciphertext = str(
            authentication.get("value_encrypted")
            or authentication.get("encrypted_value")
            or ""
        ).strip()
        name = str(authentication.get("name") or "").strip()
        if not ciphertext or not name:
            continue
        if logout_marks_session_invalidated(logout_data, session_id):
            continue
        usable.append(record)

    if not usable:
        raise SQLiError(
            "Tidak ada authenticated SUCCESS session yang usable. "
            "Acquire a new session dengan session.py add --account-id TA-002."
        )

    # Prefer the newest S-xxx record without revealing its value.
    usable.sort(key=lambda item: str(item.get("updated_at") or item.get("created_at") or ""), reverse=True)
    record = usable[0]
    authentication = record["authentication"]
    plaintext = decrypt_session_value(
        str(authentication.get("value_encrypted") or authentication.get("encrypted_value")),
        context.project_id,
    )
    if not plaintext:
        raise SQLiError("Session value berhasil didecrypt tetapi kosong.")

    try:
        verify_key(context.project_id)
    except SecretsError as exc:
        raise SQLiError(f"Project encryption key tidak valid: {exc}") from exc

    return {
        "session_id": str(record.get("session_id")),
        "account_id": str(record.get("account_id") or ""),
        "cookie_name": str(authentication.get("name")),
        "cookie_value": plaintext,
        "domain": str(authentication.get("domain") or ""),
        "path": str(authentication.get("path") or "/"),
        "post_login_url": str(authentication.get("post_login_url") or ""),
    }


def build_session(base_url: str, session_info: dict[str, Any]) -> requests.Session:
    session = requests.Session()
    session.trust_env = True
    session.headers.update({
        "User-Agent": "BrebesKab-CSIRT-Tools/sqli.py",
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


def request_no_redirect(
    session: requests.Session,
    url: str,
    timeout: int,
) -> tuple[requests.Response, str]:
    response = session.get(
        url,
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    )
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
    encoding = response.encoding or "utf-8"
    body = raw.decode(encoding, errors="replace")
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
        if current in visited:
            continue
        if not is_in_scope_url(current, target_url):
            continue
        if not is_safe_crawl_url(current):
            continue
        if max_links and len(visited) >= max_links:
            break
        visited.add(current)

        try:
            response, body = request_no_redirect(session, current, timeout)
        except requests.RequestException as exc:
            pages.append({
                "url": current,
                "depth": depth,
                "status": None,
                "error": str(exc),
            })
            continue

        challenge = detect_challenge(body)
        parser = LinkParser()
        content_type = response.headers.get("Content-Type", "")
        if "html" in content_type.lower() or "text" in content_type.lower():
            try:
                parser.feed(body)
            except Exception:
                pass

        page_record = {
            "url": current,
            "depth": depth,
            "status": response.status_code,
            "content_type": content_type,
            "body_sha256": body_fingerprint(body),
            "challenge_markers": challenge,
            "title_or_html": True,
        }
        pages.append(page_record)

        for href in parser.links:
            absolute = canonical_url(urljoin(current, href))
            if not is_in_scope_url(absolute, target_url):
                continue
            if not is_safe_crawl_url(absolute):
                continue
            discovered.add(absolute)
            if absolute not in visited and depth < max_depth:
                queue.append((absolute, depth + 1))

        for form in parser.forms:
            action = canonical_url(urljoin(current, str(form.get("action") or current)))
            if not is_in_scope_url(action, target_url):
                continue
            if str(form.get("method") or "get").lower() == "get":
                forms.append({
                    "page": current,
                    "action": action,
                    "method": "get",
                    "inputs": list(form.get("inputs") or []),
                })
                discovered.add(action)

        if delay_ms:
            time.sleep(max(0, delay_ms) / 1000.0)

    urls = sorted({start, *visited, *discovered})
    return urls, pages, forms


def candidate_parameters(urls: list[str], forms: list[dict[str, Any]], max_params: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for url in urls:
        parsed = urlsplit(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in params[:max_params]:
            key = (canonical_url(url), name)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "source": "link",
                "url": canonical_url(url),
                "parameter": name,
                "original_value": value,
                "value_profile": (
                    "numeric" if re.fullmatch(r"-?\\d+(?:\\.\\d+)?", value or "")
                    else "uuid" if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", value or "")
                    else "text_or_unknown"
                ),
                "method": "GET",
            })

    for form in forms:
        for name in list(form.get("inputs") or [])[:max_params]:
            key = (canonical_url(str(form.get("action") or "")), name)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "source": "get-form",
                "url": canonical_url(str(form.get("action") or "")),
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
    return mutate_query(
        str(candidate["url"]),
        str(candidate["parameter"]),
        value,
    )


def baseline_for_candidate(
    session: requests.Session,
    candidate: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    original = str(candidate.get("original_value") or "")
    url = build_candidate_url(candidate, original)
    response, body = request_no_redirect(session, url, timeout)
    return {
        "url": url,
        "response": safe_response(response, body),
        "sql_errors": find_sql_errors(body),
        "sql_error_contexts": sql_error_contexts(body),
        "challenge_markers": detect_challenge(body),
    }


def probe_candidate(
    session: requests.Session,
    candidate: dict[str, Any],
    baseline: dict[str, Any],
    timeout: int,
    delay_ms: int,
    max_probes_per_param: int = DEFAULT_MAX_PROBES_PER_PARAM,
) -> list[dict[str, Any]]:
    probes: list[dict[str, Any]] = []
    baseline_body_hash = str((baseline["response"] or {}).get("body_sha256") or "")
    baseline_len = int((baseline["response"] or {}).get("content_length") or 0)

    probe_limit = max(1, min(int(max_probes_per_param), len(SQLI_PAYLOADS)))
    for payload_name, payload in SQLI_PAYLOADS[:probe_limit]:
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
            },
            "request": {
                "method": "GET",
                "url": url,
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

        sql_errors = find_sql_errors(body)
        error_contexts = sql_error_contexts(body)
        challenges = detect_challenge(body)
        reflected = payload in body
        body_hash = body_fingerprint(body)
        body_len = len(body)
        status_changed = int(response.status_code) != int((baseline["response"] or {}).get("status") or -1)
        length_delta = abs(body_len - baseline_len)
        similarity = similarity_score(
            str((baseline["response"] or {}).get("body_sample") or ""),
            body[:4000],
        )

        record["response"] = safe_response(response, body)
        record["signals"] = {
            "sql_error_markers": sql_errors,
            "sql_error_contexts": error_contexts,
            "challenge_markers": challenges,
            "payload_reflected": reflected,
            "body_hash_changed": body_hash != baseline_body_hash,
            "status_changed": status_changed,
            "body_length_delta": length_delta,
            "body_similarity": round(similarity, 6),
        }
        probes.append(record)

        if challenges:
            break
        if delay_ms:
            time.sleep(max(0, delay_ms) / 1000.0)

    return probes


def assess_candidate(candidate: dict[str, Any], baseline: dict[str, Any], probes: list[dict[str, Any]]) -> dict[str, Any]:
    baseline_errors = set(baseline.get("sql_errors") or [])
    challenge = bool(baseline.get("challenge_markers"))
    errors_after: set[str] = set()
    differential = False
    reflected_only = False

    for probe in probes:
        signals = probe.get("signals") or {}
        if signals.get("challenge_markers"):
            challenge = True
        errors_after.update(str(x) for x in signals.get("sql_error_markers") or [])
        if signals.get("payload_reflected"):
            reflected_only = True
        if signals.get("status_changed") and not signals.get("challenge_markers"):
            differential = True

    new_sql_errors = sorted(errors_after - baseline_errors)
    true_probe = next((p for p in probes if (p.get("payload", {}).get("name") == "boolean-true")), None)
    false_probe = next((p for p in probes if (p.get("payload", {}).get("name") == "boolean-false")), None)

    boolean_differential = False
    differential_detail: dict[str, Any] = {
        "available": False,
        "true_status": None,
        "false_status": None,
        "true_body_sha256": None,
        "false_body_sha256": None,
        "true_body_length": None,
        "false_body_length": None,
        "true_vs_false_status_changed": False,
        "true_vs_false_body_changed": False,
        "true_vs_false_body_length_delta": None,
    }
    if true_probe and false_probe:
        ts = true_probe.get("signals") or {}
        fs = false_probe.get("signals") or {}
        if not ts.get("challenge_markers") and not fs.get("challenge_markers"):
            true_response = true_probe.get("response") or {}
            false_response = false_probe.get("response") or {}
            true_status = true_response.get("status")
            false_status = false_response.get("status")
            true_hash = true_response.get("body_sha256")
            false_hash = false_response.get("body_sha256")
            true_len = true_response.get("content_length")
            false_len = false_response.get("content_length")
            differential_detail.update({
                "available": True,
                "true_status": true_status,
                "false_status": false_status,
                "true_body_sha256": true_hash,
                "false_body_sha256": false_hash,
                "true_body_length": true_len,
                "false_body_length": false_len,
                "true_vs_false_status_changed": true_status != false_status,
                "true_vs_false_body_changed": true_hash != false_hash,
                "true_vs_false_body_length_delta": (
                    abs(int(true_len) - int(false_len))
                    if true_len is not None and false_len is not None else None
                ),
            })
            boolean_differential = (
                true_status != false_status
                or true_hash != false_hash
            )

    if challenge:
        result = "requires_review"
        finding = False
        requires_review = True
        note = "Human-interaction/challenge response detected; SQLi probes stopped for this candidate."
    elif new_sql_errors and boolean_differential:
        result = "confirmed"
        finding = True
        requires_review = False
        note = "New SQL error markers plus controlled true/false differential observed."
    elif new_sql_errors or boolean_differential:
        result = "requires_review"
        finding = False
        requires_review = True
        note = "SQL-related or differential signal observed, but evidence is insufficient for automatic confirmation."
    elif reflected_only:
        result = "not_confirmed"
        finding = False
        requires_review = False
        note = "Payload reflection observed without SQL-specific differential evidence."
    else:
        result = "pass"
        finding = False
        requires_review = False
        note = "No SQL-specific differential/error evidence observed in bounded probes."

    return {
        "result": result,
        "finding": finding,
        "requires_review": requires_review,
        "new_sql_error_markers": new_sql_errors,
        "boolean_differential": boolean_differential,
        "differential_detail": differential_detail,
        "reflected_only": reflected_only,
        "note": note,
    }


def cmd_version(_: argparse.Namespace) -> int:
    print("BrebesKab-CSIRT-Tools sqli.py v" + SCRIPT_VERSION)
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : same-origin crawl + bounded GET SQLi differential probes")
    print("Session  : existing SUCCESS session from session.yaml; no login")
    print("Payloads : quote + boolean true/false; no data extraction/write")
    print("Detail   : response fingerprint, timing, SQL-error context, differential detail")
    print("Scope    : active project, same-origin, authorized ports 80/443")
    print("CVE      : secondary correlation only; version match != vulnerability")
    return 0


def cmd_init(_: argparse.Namespace) -> int:
    data = init_artifact()
    project_match(data)
    print("=" * 72)
    print(" Initialize SQL Injection Assessment")
    print("=" * 72)
    print(f"Project ID : {data.get('project_id')}")
    print(f"Checklist  : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"File       : {artifact_path()}")
    print("[PASS] Canonical artifact siap.")
    return 0


def cmd_crawl(args: argparse.Namespace) -> int:
    data = init_artifact()
    project_match(data)
    context = active_context()
    target_url = str(data["target"]["url"])
    session_info = load_usable_session()
    session = build_session(target_url, session_info)

    print("=" * 72)
    print(" SQL Injection Candidate Discovery")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"Session    : {session_info['session_id']}")
    print(f"Target     : {target_url}")
    print("Session value: [ENCRYPTED AT REST / PLAINTEXT IN MEMORY ONLY]")

    urls, pages, forms = discover_links(
        session,
        target_url,
        args.timeout,
        args.max_links,
        args.max_depth,
        args.delay_ms,
    )
    candidates = candidate_parameters(urls, forms, args.max_params_per_url)
    if args.max_candidates and len(candidates) > args.max_candidates:
        candidates = candidates[:args.max_candidates]

    data["source_status"]["session"] = "completed"
    data["source_status"]["logout_cross_check"] = "completed"
    data["checklist"]["status"] = "completed"
    data["probe"]["crawl"] = {
        "max_links": args.max_links,
        "max_depth": args.max_depth,
        "max_candidates": args.max_candidates,
        "max_params_per_url": args.max_params_per_url,
        "max_probes_per_param": args.max_probes_per_param,
    }
    data["results"]["links_discovered"] = len(urls)
    data["results"]["same_origin_links"] = len(urls)
    data["results"]["query_parameter_candidates"] = len(candidates)
    data["results"]["candidates"] = [
        {
            "source": c["source"],
            "url": c["url"],
            "parameter": c["parameter"],
            "method": c["method"],
        }
        for c in candidates
    ]
    data["summary"] = {
        "result": "not-tested",
        "finding": False,
        "requires_review": False,
        "note": "Candidate discovery completed; SQLi probes not yet executed.",
    }
    data["assessment"] = dict(data["summary"])
    data["updated_at"] = now_iso()
    save_yaml(artifact_path(), data)

    save_json(
        evidence_path(),
        {
            "schema_version": SCHEMA_VERSION,
            "project_id": context.project_id,
            "session_id": session_info["session_id"],
            "crawl": {
                "pages": pages,
                "forms": forms,
                "urls": urls,
                "candidate_count": len(candidates),
            },
            "session_secret_persisted": False,
            "generated_at": now_iso(),
        },
    )

    print(f"[PASS] Links discovered       : {len(urls)}")
    print(f"[PASS] GET forms discovered   : {len(forms)}")
    print(f"[PASS] SQLi candidates        : {len(candidates)}")
    print(f"[PASS] Evidence               : {evidence_path()}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    data = init_artifact()
    project_match(data)
    context = active_context()
    target_url = str(data["target"]["url"])
    session_info = load_usable_session()
    session = build_session(target_url, session_info)

    print("=" * 72)
    print(" SQL Injection Controlled Assessment")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"Session    : {session_info['session_id']}")
    print(f"Target     : {target_url}")
    print(f"Max links  : {'ALL' if not args.max_links else args.max_links}")
    print(f"Max cand.  : {args.max_candidates or 'UNLIMITED'}")
    print(f"Payloads   : {', '.join(name for name, _ in SQLI_PAYLOADS[:max(1, min(args.max_probes_per_param, len(SQLI_PAYLOADS)))])}")
    print(f"Probes/param: {args.max_probes_per_param}")
    print()

    urls, pages, forms = discover_links(
        session,
        target_url,
        args.timeout,
        args.max_links,
        args.max_depth,
        args.delay_ms,
    )
    candidates = candidate_parameters(urls, forms, args.max_params_per_url)
    if args.max_candidates and len(candidates) > args.max_candidates:
        candidates = candidates[:args.max_candidates]

    all_probe_records: list[dict[str, Any]] = []
    candidate_results: list[dict[str, Any]] = []
    total_baselines = 0
    total_probes = 0
    total_errors = 0
    total_sql_errors = 0
    total_differential = 0
    total_reflected = 0
    total_challenges = 0
    overall_review = False
    overall_finding = False
    confirmed: list[str] = []

    for index, candidate in enumerate(candidates, start=1):
        print(
            f"[TEST {index}/{len(candidates)}] "
            f"{candidate['parameter']} @ {candidate['url']}"
        )
        try:
            baseline = baseline_for_candidate(session, candidate, args.timeout)
            total_baselines += 1
            if baseline.get("challenge_markers"):
                total_challenges += 1
                result = {
                    "result": "requires_review",
                    "finding": False,
                    "requires_review": True,
                    "note": "Challenge detected during baseline; probes stopped.",
                    "new_sql_error_markers": [],
                    "boolean_differential": False,
                }
                probes = []
            else:
                probes = probe_candidate(
                    session,
                    candidate,
                    baseline,
                    args.timeout,
                    args.delay_ms,
                    args.max_probes_per_param,
                )
                total_probes += len(probes)
                for probe in probes:
                    if probe.get("error"):
                        total_errors += 1
                        continue
                    signals = probe.get("signals") or {}
                    total_sql_errors += len(signals.get("sql_error_markers") or [])
                    if signals.get("status_changed") or signals.get("body_hash_changed"):
                        total_differential += 1
                    if signals.get("payload_reflected"):
                        total_reflected += 1
                    if signals.get("challenge_markers"):
                        total_challenges += 1
                result = assess_candidate(candidate, baseline, probes)

            if result["requires_review"]:
                overall_review = True
            if result["finding"]:
                overall_finding = True
                confirmed.append(f"{candidate['url']}?{candidate['parameter']}")

            candidate_results.append({
                "source": candidate["source"],
                "url": candidate["url"],
                "parameter": candidate["parameter"],
                "method": candidate["method"],
                "value_profile": candidate.get("value_profile", "unknown"),
                "baseline": baseline,
                "assessment": result,
                "probe_count": len(probes),
            })
            all_probe_records.extend(probes)
            print(
                f"  -> {result['result'].upper()} | "
                f"finding={result['finding']} | "
                f"review={result['requires_review']}"
            )
        except requests.RequestException as exc:
            total_errors += 1
            candidate_results.append({
                "source": candidate["source"],
                "url": candidate["url"],
                "parameter": candidate["parameter"],
                "method": candidate["method"],
                "value_profile": candidate.get("value_profile", "unknown"),
                "assessment": {
                    "result": "requires_review",
                    "finding": False,
                    "requires_review": True,
                    "note": f"Request error: {exc}",
                },
                "probe_count": 0,
            })
            overall_review = True
            print(f"  -> REVIEW | request error: {exc}")

    if overall_finding:
        overall_result = "confirmed"
    elif overall_review:
        overall_result = "requires_review"
    elif candidates:
        overall_result = "pass"
    else:
        overall_result = "not_confirmed"

    data["source_status"]["session"] = "completed"
    data["source_status"]["logout_cross_check"] = "completed"
    data["checklist"]["status"] = "completed"
    data["results"] = {
        "links_discovered": len(urls),
        "same_origin_links": len(urls),
        "query_parameter_candidates": len(candidates),
        "tested_parameters": len(candidate_results),
        "probes_sent": total_probes,
        "baseline_requests": total_baselines,
        "sql_error_signals": total_sql_errors,
        "differential_signals": total_differential,
        "reflected_payload_signals": total_reflected,
        "challenge_stops": total_challenges,
        "request_errors": total_errors,
        "probe_configuration": {
            "max_probes_per_param": args.max_probes_per_param,
            "delay_ms": args.delay_ms,
        },
        "candidates": candidate_results,
        "probes": all_probe_records,
    }
    data["summary"] = {
        "result": overall_result,
        "finding": overall_finding,
        "requires_review": overall_review,
        "note": (
            "Confirmed SQL injection evidence observed in controlled differential probes."
            if overall_finding
            else "No automatically confirmed SQL injection; review candidates if signals were observed."
        ),
    }
    data["assessment"] = dict(data["summary"])
    data["assessment"]["confirmed_candidates"] = confirmed
    data["cve_correlation"] = {
        "status": "not-tested",
        "candidate_count": 0,
        "candidates": [],
        "assessment_note": (
            "No CVE is inferred from SQLi behavior. CVE correlation remains secondary "
            "and requires a technically relevant affected component/version; this script "
            "does not invent CVE candidates from response behavior alone."
        ),
    }
    data["updated_at"] = now_iso()
    save_yaml(artifact_path(), data)

    save_json(
        evidence_path(),
        {
            "schema_version": SCHEMA_VERSION,
            "project_id": context.project_id,
            "session_id": session_info["session_id"],
            "target": target_url,
            "crawl": {
                "pages": pages,
                "forms": forms,
                "urls": urls,
            },
            "candidate_results": candidate_results,
            "probes": all_probe_records,
            "security": {
                "plaintext_session_persisted": False,
                "password_persisted": False,
                "csrf_secret_persisted": False,
                "cookie_value_persisted": False,
            },
            "generated_at": now_iso(),
        },
    )

    print()
    print("=" * 72)
    print(" SQL Injection Assessment Result")
    print("=" * 72)
    print(f"Links discovered : {len(urls)}")
    print(f"Candidates       : {len(candidates)}")
    print(f"Baselines        : {total_baselines}")
    print(f"Probes sent      : {total_probes}")
    print(f"SQL error signals: {total_sql_errors}")
    print(f"Differentials    : {total_differential}")
    print(f"Challenge stops  : {total_challenges}")
    print(f"Request errors   : {total_errors}")
    print(f"Assessment       : {overall_result}")
    print(f"Finding          : {overall_finding}")
    print(f"Requires review  : {overall_review}")
    print(f"Evidence         : {evidence_path()}")
    return 0


def cmd_show(_: argparse.Namespace) -> int:
    data = load_artifact()
    project_match(data)
    print(yaml.safe_dump(data, allow_unicode=True, sort_keys=False))
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    data = load_artifact()
    project_match(data)
    results = data.get("results") or {}
    assessment = data.get("assessment") or {}
    print("=" * 72)
    print(" SQL Injection Status")
    print("=" * 72)
    print(f"Project ID : {data.get('project_id')}")
    print(f"Checklist  : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Result     : {assessment.get('result', '-')}")
    print(f"Finding    : {assessment.get('finding', False)}")
    print(f"Review     : {assessment.get('requires_review', False)}")
    print(f"Links      : {results.get('links_discovered', 0)}")
    print(f"Candidates : {results.get('query_parameter_candidates', 0)}")
    print(f"Probes     : {results.get('probes_sent', 0)}")
    return 0


def cmd_verify(_: argparse.Namespace) -> int:
    data = load_artifact()
    project_match(data)
    errors: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak canonical")
    if data.get("project_id") != active_context().project_id:
        errors.append("project_id tidak sesuai active project")
    tool = data.get("tool") or {}
    if tool.get("script") != "sqli.py":
        errors.append("tool.script harus sqli.py")
    if tool.get("version") != SCRIPT_VERSION:
        errors.append("tool.version tidak sesuai SCRIPT_VERSION")
    checklist = data.get("checklist") or {}
    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist.id tidak canonical")
    target = data.get("target") or {}
    if target.get("assessment_type") != "Black Box":
        errors.append("target.assessment_type harus Black Box")
    if target.get("authorized_ports") != [80, 443]:
        errors.append("authorized_ports harus [80, 443]")
    evidence = data.get("evidence") or {}
    expected_evidence = f"{PHASE_DIR}/{CHECKLIST_DIR}/evidence/{EVIDENCE_FILE}"
    if evidence.get("sqli_probes") != expected_evidence:
        errors.append("evidence.sqli_probes tidak canonical")

    for path in (artifact_path(), evidence_path()):
        if path.exists() and path.read_bytes().startswith(b"\xef\xbb\xbf"):
            errors.append(f"UTF-8 BOM ditemukan: {path}")

    try:
        verify_key(active_context().project_id)
    except SecretsError as exc:
        errors.append(f"project encryption key invalid: {exc}")

    if errors:
        print("[FAIL] SQL Injection verify gagal:")
        for error in errors:
            print(f"  - {error}")
        return 1

    results = data.get("results") or {}
    print("[PASS] SQL Injection memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {active_context().project_id}")
    print(f"[PASS] File      : {artifact_path()}")
    print(f"[PASS] Candidates: {results.get('query_parameter_candidates', 0)}")
    print(f"[PASS] Probes    : {results.get('probes_sent', 0)}")
    print("[PASS] Encoding  : UTF-8 tanpa BOM")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools - bounded SQL Injection assessment"
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("version", help="Tampilkan versi dan metodologi.")
    sub.add_parser("init", help="Inisialisasi canonical sqli.yaml.")
    sub.add_parser("show", help="Tampilkan artifact lengkap.")
    sub.add_parser("status", help="Tampilkan status ringkas.")
    sub.add_parser("verify", help="Validasi canonical artifact dan encryption key.")

    crawl = sub.add_parser(
        "crawl",
        help="Crawl same-origin links dan buat kandidat parameter tanpa mengirim payload SQLi.",
    )
    add_common(crawl)

    analyze = sub.add_parser(
        "analyze",
        help="Crawl dan jalankan bounded SQLi probes pada kandidat parameter.",
    )
    add_common(analyze)

    return parser


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--max-links",
        type=int,
        default=DEFAULT_MAX_LINKS,
        help="Maksimum link untuk crawl; 0 = semua same-origin link yang ditemukan.",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=DEFAULT_MAX_DEPTH,
        help=f"Kedalaman crawl maksimum (default {DEFAULT_MAX_DEPTH}).",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=DEFAULT_MAX_CANDIDATES,
        help="Maksimum parameter yang diprobe; 0 = unlimited.",
    )
    parser.add_argument(
        "--max-params-per-url",
        type=int,
        default=DEFAULT_MAX_PARAMS_PER_URL,
    )
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=DEFAULT_DELAY_MS,
        help="Delay antar request untuk menjaga assessment bounded.",
    )
    parser.add_argument(
        "--max-probes-per-param",
        type=int,
        default=DEFAULT_MAX_PROBES_PER_PARAM,
        help=f"Jumlah payload SQLi per parameter; default {DEFAULT_MAX_PROBES_PER_PARAM}.",
    )


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
    except SQLiError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except requests.RequestException as exc:
        print(f"[FAIL] Request error: {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] SQLi ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
