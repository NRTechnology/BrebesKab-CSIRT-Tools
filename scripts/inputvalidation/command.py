#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Command Injection Assessment

Checklist: 7-003 Command Injection
Schema: 1.0

Purpose:
    Crawl same-origin pages from the authorized target, identify GET query
    parameters and GET-form inputs, and perform bounded, non-destructive
    Command Injection probes using an explicitly authorized authenticated
    session.

Security / assessment model:
    - Black Box assessment.
    - Target and ports are taken from the active project/scope artifacts.
    - Only same-origin HTTP(S) URLs are crawled.
    - Authentication is provided by an existing SUCCESS session.
    - This script never logs in.
    - Session plaintext exists only in memory.
    - Session credentials are never written to evidence or stdout.
    - GET-only probe engine.
    - No POST submission.
    - No file upload.
    - No persistence.
    - No reverse shell.
    - No external callback.
    - No command that modifies the target system.
    - No file read/write command is intentionally executed.
    - Payloads only attempt to emit a unique marker.
    - Reflection alone is NOT considered Command Injection.
    - A marker appearing without the original payload is treated as a
      stronger execution indicator, but automatic finding remains conservative.
    - Timing is recorded as supporting forensic evidence, not automatic proof.
    - Challenge responses are preserved and probing is stopped for that
      candidate.

Typical workflow:

    python scripts/inputvalidation/command.py version
    python scripts/inputvalidation/command.py init
    python scripts/inputvalidation/command.py crawl
    python scripts/inputvalidation/command.py analyze
    python scripts/inputvalidation/command.py show
    python scripts/inputvalidation/command.py status
    python scripts/inputvalidation/command.py verify

The script writes only its own artifacts:

    07-input-validation/command/command.yaml
    07-input-validation/command/evidence/command-probes.json
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
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

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


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"

CHECKLIST_ID = "7-003"
CHECKLIST_NAME = "Command Injection"

PHASE_NAME = "07 Input Validation"
PHASE_DIR = "07-input-validation"
CHECKLIST_DIR = "command"

ARTIFACT_FILE = "command.yaml"
EVIDENCE_FILE = "command-probes.json"

DEFAULT_TIMEOUT = 15
DEFAULT_MAX_LINKS = 0
DEFAULT_MAX_CANDIDATES = 200
DEFAULT_MAX_PARAMS_PER_URL = 5
DEFAULT_MAX_BODY_BYTES = 262144
DEFAULT_DELAY_MS = 150
DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_PROBES_PER_PARAM = 6


# ---------------------------------------------------------------------------
# Safe command-injection payloads
# ---------------------------------------------------------------------------
#
# IMPORTANT:
# These payloads are intentionally limited to commands whose only purpose
# is producing a unique marker.
#
# They do NOT:
#   - read files
#   - write files
#   - delete files
#   - spawn shells
#   - download anything
#   - create persistence
#   - access credentials
#   - create reverse shells
#   - make external callbacks
#
# The marker is unique per probe.
#
# ---------------------------------------------------------------------------

PAYLOAD_TEMPLATES: tuple[tuple[str, str], ...] = (
    (
        "semicolon-echo",
        "; echo BREBESCMD_{token}",
    ),
    (
        "and-echo",
        "&& echo BREBESCMD_{token}",
    ),
    (
        "pipe-echo",
        "| echo BREBESCMD_{token}",
    ),
    (
        "newline-echo",
        "\n echo BREBESCMD_{token}",
    ),
    (
        "semicolon-printf",
        "; printf BREBESCMD_{token}",
    ),
    (
        "command-substitution",
        "$(printf BREBESCMD_{token})",
    ),
)


# ---------------------------------------------------------------------------
# Challenge detection
# ---------------------------------------------------------------------------

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
    "request blocked",
    "forbidden",
)


# ---------------------------------------------------------------------------
# Paths / imports
# ---------------------------------------------------------------------------

SCRIPTS_DIR = Path(__file__).resolve().parents[1]

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

try:
    from context import load_active_context, get_active_project_path
    from secrets import SecretsError, decrypt, verify_key
except ImportError as exc:
    print(f"[ERROR] Gagal memuat scripts.context/scripts.secrets: {exc}")
    raise SystemExit(1)


class CommandInjectionError(RuntimeError):
    """Controlled error for command injection assessment."""


# ---------------------------------------------------------------------------
# HTML parser
# ---------------------------------------------------------------------------

class LinkParser(HTMLParser):
    """
    Stdlib-only parser for same-origin links and GET forms.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)

        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []

        self._current_form: Optional[dict[str, Any]] = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, Optional[str]]],
    ) -> None:
        tag = tag.lower()
        data = {str(key).lower(): value for key, value in attrs}

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

        if tag in {"input", "textarea", "select"}:
            if self._current_form is None:
                return

            name = data.get("name")

            if name:
                self._current_form["inputs"].append(str(name))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(
        timespec="seconds"
    )


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
        raise CommandInjectionError(
            f"Artifact tidak ditemukan: {path}"
        )

    raw = path.read_bytes()

    if raw.startswith(b"\xef\xbb\xbf"):
        raise CommandInjectionError(
            f"File menggunakan UTF-8 BOM: {path}"
        )

    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CommandInjectionError(
            f"File bukan UTF-8 valid: {path}"
        ) from exc

    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

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


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        json.dump(
            data,
            handle,
            ensure_ascii=False,
            indent=2,
        )
        handle.write("\n")


def body_fingerprint(text: str) -> str:
    return hashlib.sha256(
        text.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def target_origin(target_url: str) -> tuple[str, str, int]:
    parsed = urlsplit(target_url)

    if parsed.scheme not in {"http", "https"}:
        raise CommandInjectionError(
            f"Target URL tidak valid: {target_url}"
        )

    if not parsed.hostname:
        raise CommandInjectionError(
            f"Hostname target tidak ditemukan: {target_url}"
        )

    port = parsed.port

    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    return (
        parsed.scheme.lower(),
        parsed.hostname.lower(),
        port,
    )


def is_in_scope_url(
    url: str,
    target_url: str,
) -> bool:
    try:
        target_scheme, target_host, target_port = target_origin(
            target_url
        )

        parsed = urlsplit(url)

        if parsed.scheme.lower() != target_scheme:
            return False

        if (parsed.hostname or "").lower() != target_host:
            return False

        candidate_port = parsed.port

        if candidate_port is None:
            candidate_port = (
                443
                if parsed.scheme.lower() == "https"
                else 80
            )

        return candidate_port == target_port

    except ValueError:
        return False


def canonical_url(url: str) -> str:
    parsed = urlsplit(url)

    path = parsed.path or "/"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            parsed.query,
            "",
        )
    )


def normalized_path(url: str) -> str:
    parsed = urlsplit(url)

    path = parsed.path or "/"

    if not path.startswith("/"):
        path = "/" + path

    return path


# ---------------------------------------------------------------------------
# Scope / project
# ---------------------------------------------------------------------------

def active_context() -> Any:
    context = load_active_context()

    if (
        str(context.assessment_type or "")
        .strip()
        .lower()
        != "black box"
    ):
        raise CommandInjectionError(
            "Assessment type active project bukan Black Box. "
            f"Nilai saat ini: {context.assessment_type!r}"
        )

    return context


def load_scope_target() -> dict[str, Any]:
    """
    Read authoritative IN-001 scope item.
    Never infer target from DNS.
    """

    context = active_context()

    scope_file = (
        project_path()
        / "01-preparation"
        / "scope"
        / "scope.yaml"
    )

    data = load_yaml(scope_file)

    if not isinstance(data, dict):
        raise CommandInjectionError(
            "scope.yaml tidak valid."
        )

    section = (
        data.get("scope")
        if isinstance(data.get("scope"), dict)
        else data
    )

    items = (
        section.get("in_scope", [])
        if isinstance(section, dict)
        else []
    )

    if not isinstance(items, list):
        raise CommandInjectionError(
            "scope.yaml field in_scope tidak valid."
        )

    for item in items:
        if not isinstance(item, dict):
            continue

        scope_id = str(
            item.get("scope_id")
            or item.get("id")
            or ""
        ).strip()

        value = str(
            item.get("value")
            or item.get("hostname")
            or item.get("url")
            or ""
        ).strip()

        scope_type = str(
            item.get("type")
            or ""
        ).strip().lower()

        ports = item.get("ports") or []

        if scope_id != "IN-001":
            continue

        if not value:
            continue

        if scope_type not in {
            "domain",
            "hostname",
            "url",
        }:
            continue

        numeric_ports = sorted(
            int(port)
            for port in ports
            if str(port).isdigit()
        )

        if numeric_ports != [80, 443]:
            raise CommandInjectionError(
                "IN-001 authorized ports tidak sesuai: "
                f"{ports!r}"
            )

        target = (
            value
            if scope_type == "url"
            else f"https://{value}"
        )

        return {
            "scope_id": scope_id,
            "hostname": (
                urlsplit(target).hostname
                or value
            ),
            "url": target.rstrip("/"),
            "ports": [80, 443],
        }

    raise CommandInjectionError(
        "IN-001 domain/hostname tidak ditemukan "
        "pada scope.yaml."
    )


def project_match(data: dict[str, Any]) -> None:
    context = active_context()

    if str(data.get("project_id")) != str(
        context.project_id
    ):
        raise CommandInjectionError(
            "project_id pada command.yaml tidak sesuai "
            "active project."
        )


# ---------------------------------------------------------------------------
# Session handling
# ---------------------------------------------------------------------------

def recursive_find_session_ids(
    value: Any,
) -> set[str]:
    found: set[str] = set()

    if isinstance(value, dict):
        for key, item in value.items():
            if (
                str(key).lower()
                in {"session_id", "session"}
                and isinstance(item, str)
            ):
                if re.fullmatch(
                    r"S-\d{3,}",
                    item.strip(),
                    re.IGNORECASE,
                ):
                    found.add(
                        item.strip().upper()
                    )

            found.update(
                recursive_find_session_ids(item)
            )

    elif isinstance(value, list):
        for item in value:
            found.update(
                recursive_find_session_ids(item)
            )

    return found


def logout_marks_session_invalidated(
    data: Any,
    session_id: str,
) -> bool:
    if not isinstance(data, dict):
        return False

    if (
        session_id.upper()
        not in recursive_find_session_ids(data)
    ):
        return False

    def walk(value: Any) -> bool:
        if isinstance(value, dict):
            for key, item in value.items():
                key_lower = str(key).lower()

                if (
                    key_lower
                    in {
                        "session_invalidated",
                        "invalidated",
                        "logout_completed",
                    }
                    and item is True
                ):
                    return True

                if walk(item):
                    return True

        elif isinstance(value, list):
            return any(
                walk(item)
                for item in value
            )

        return False

    return walk(data)


def decrypt_session_value(
    ciphertext: str,
    project_id: str,
) -> str:
    if not ciphertext:
        raise CommandInjectionError(
            "Encrypted session value kosong."
        )

    try:
        return decrypt(
            ciphertext,
            project_id=project_id,
        )

    except SecretsError as exc:
        raise CommandInjectionError(
            f"Gagal decrypt session value: {exc}"
        ) from exc


def load_usable_session() -> dict[str, Any]:
    context = active_context()

    session_file = (
        project_path()
        / "05-authentication"
        / "session"
        / "session.yaml"
    )

    logout_file = (
        project_path()
        / "05-authentication"
        / "logout"
        / "logout.yaml"
    )

    data = load_yaml(session_file)

    if not isinstance(data, dict):
        raise CommandInjectionError(
            "session.yaml tidak valid."
        )

    sessions = data.get("sessions")

    if not isinstance(sessions, list):
        raise CommandInjectionError(
            "session.yaml field 'sessions' tidak valid."
        )

    logout_data: Any = None

    if logout_file.exists():
        logout_data = load_yaml(logout_file)

    usable: list[dict[str, Any]] = []

    for record in sessions:
        if not isinstance(record, dict):
            continue

        session_id = str(
            record.get("session_id")
            or ""
        ).strip().upper()

        if not re.fullmatch(
            r"S-\d{3,}",
            session_id,
        ):
            continue

        if (
            str(record.get("status") or "")
            .lower()
            != "active"
        ):
            continue

        authentication = record.get(
            "authentication"
        )

        if not isinstance(
            authentication,
            dict,
        ):
            continue

        if (
            str(
                authentication.get("outcome")
                or ""
            ).upper()
            != "SUCCESS"
        ):
            continue

        if (
            str(
                authentication.get("type")
                or "cookie"
            ).lower()
            != "cookie"
        ):
            continue

        ciphertext = str(
            authentication.get(
                "value_encrypted"
            )
            or authentication.get(
                "encrypted_value"
            )
            or ""
        ).strip()

        name = str(
            authentication.get("name")
            or ""
        ).strip()

        if not ciphertext or not name:
            continue

        if logout_marks_session_invalidated(
            logout_data,
            session_id,
        ):
            continue

        usable.append(record)

    if not usable:
        raise CommandInjectionError(
            "Tidak ada authenticated SUCCESS "
            "session yang usable. "
            "Acquire a new session dengan "
            "session.py."
        )

    usable.sort(
        key=lambda item: str(
            item.get("updated_at")
            or item.get("created_at")
            or ""
        ),
        reverse=True,
    )

    record = usable[0]

    authentication = record[
        "authentication"
    ]

    plaintext = decrypt_session_value(
        str(
            authentication.get(
                "value_encrypted"
            )
            or authentication.get(
                "encrypted_value"
            )
        ),
        context.project_id,
    )

    if not plaintext:
        raise CommandInjectionError(
            "Session value berhasil didecrypt "
            "tetapi kosong."
        )

    try:
        verify_key(
            context.project_id
        )
    except SecretsError as exc:
        raise CommandInjectionError(
            f"Project encryption key tidak valid: {exc}"
        ) from exc

    return {
        "session_id": str(
            record.get("session_id")
        ),
        "account_id": str(
            record.get("account_id")
            or ""
        ),
        "cookie_name": str(
            authentication.get("name")
        ),
        "cookie_value": plaintext,
        "domain": str(
            authentication.get("domain")
            or ""
        ),
        "path": str(
            authentication.get("path")
            or "/"
        ),
    }


def build_session(
    base_url: str,
    session_info: dict[str, Any],
) -> requests.Session:
    session = requests.Session()

    session.trust_env = True

    session.headers.update(
        {
            "User-Agent": (
                "BrebesKab-CSIRT-Tools/"
                "command.py"
            ),
            "Accept": (
                "text/html,"
                "application/xhtml+xml,"
                "application/json;q=0.9,"
                "*/*;q=0.8"
            ),
            "Accept-Language": (
                "en-US,en;q=0.9"
            ),
            "Cache-Control": "no-cache",
        }
    )

    hostname = (
        session_info.get("domain")
        or urlsplit(base_url).hostname
        or ""
    )

    session.cookies.set(
        session_info["cookie_name"],
        session_info["cookie_value"],
        domain=hostname,
        path=session_info.get(
            "path"
        )
        or "/",
    )

    return session


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

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
        for chunk in response.iter_content(
            chunk_size=8192
        ):
            if not chunk:
                continue

            remaining = (
                DEFAULT_MAX_BODY_BYTES
                - total
            )

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

    body = raw.decode(
        response.encoding
        or "utf-8",
        errors="replace",
    )

    return response, body


def safe_headers(
    response: requests.Response,
) -> dict[str, str]:

    secret_headers = {
        "authorization",
        "cookie",
        "set-cookie",
        "proxy-authorization",
    }

    result: dict[str, str] = {}

    for key, value in response.headers.items():

        if key.lower() in secret_headers:
            result[key] = "[REDACTED]"
        else:
            result[key] = str(value)[:1000]

    return result


def safe_response(
    response: requests.Response,
    body: str,
) -> dict[str, Any]:

    elapsed_ms: Optional[float] = None

    try:
        elapsed_ms = round(
            response.elapsed.total_seconds()
            * 1000,
            2,
        )
    except Exception:
        pass

    return {
        "status": response.status_code,
        "url": response.url,
        "headers": safe_headers(response),
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "content_length": len(body),
        "body_sha256": body_fingerprint(
            body
        ),
        "body_sample": body[:4000],
        "elapsed_ms": elapsed_ms,
    }


def detect_challenge(
    text: str,
) -> list[str]:

    sample = text.lower()

    return [
        marker
        for marker in CHALLENGE_PATTERNS
        if marker in sample
    ]


# ---------------------------------------------------------------------------
# Crawl
# ---------------------------------------------------------------------------

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


def is_safe_crawl_url(
    url: str,
) -> bool:

    path = normalized_path(
        url
    ).lower()

    return not any(
        re.search(
            pattern,
            path,
        )
        for pattern
        in STATE_CHANGING_PATH_PATTERNS
    )


def discover_links(
    session: requests.Session,
    target_url: str,
    timeout: int,
    max_links: int,
    max_depth: int,
    delay_ms: int,
) -> tuple[
    list[str],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:

    start = canonical_url(
        target_url
    )

    queue: list[
        tuple[str, int]
    ] = [
        (start, 0)
    ]

    visited: set[str] = set()
    discovered: set[str] = set()

    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []

    while queue:

        current, depth = queue.pop(0)

        current = canonical_url(
            current
        )

        if (
            current in visited
            or not is_in_scope_url(
                current,
                target_url,
            )
            or not is_safe_crawl_url(
                current
            )
        ):
            continue

        if (
            max_links
            and len(visited)
            >= max_links
        ):
            break

        visited.add(current)

        try:
            response, body = request_no_redirect(
                session,
                current,
                timeout,
            )

        except requests.RequestException as exc:

            pages.append(
                {
                    "url": current,
                    "depth": depth,
                    "status": None,
                    "error": str(exc),
                }
            )

            continue

        challenge = detect_challenge(
            body
        )

        parser = LinkParser()

        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        if (
            "html"
            in content_type.lower()
            or "text"
            in content_type.lower()
        ):
            try:
                parser.feed(body)
            except Exception:
                pass

        pages.append(
            {
                "url": current,
                "depth": depth,
                "status": response.status_code,
                "content_type": content_type,
                "body_sha256": body_fingerprint(
                    body
                ),
                "body_length": len(body),
                "challenge_markers": challenge,
            }
        )

        for href in parser.links:

            absolute = canonical_url(
                urljoin(
                    current,
                    href,
                )
            )

            if (
                is_in_scope_url(
                    absolute,
                    target_url,
                )
                and is_safe_crawl_url(
                    absolute
                )
            ):
                discovered.add(
                    absolute
                )

                if (
                    absolute
                    not in visited
                    and depth < max_depth
                ):
                    queue.append(
                        (
                            absolute,
                            depth + 1,
                        )
                    )

        for form in parser.forms:

            action = canonical_url(
                urljoin(
                    current,
                    str(
                        form.get(
                            "action"
                        )
                        or current
                    ),
                )
            )

            if (
                not is_in_scope_url(
                    action,
                    target_url,
                )
                or not is_safe_crawl_url(
                    action
                )
            ):
                continue

            if (
                str(
                    form.get(
                        "method"
                    )
                    or "get"
                ).lower()
                == "get"
            ):
                forms.append(
                    {
                        "page": current,
                        "action": action,
                        "method": "GET",
                        "inputs": list(
                            form.get(
                                "inputs"
                            )
                            or []
                        ),
                    }
                )

                discovered.add(
                    action
                )

        if delay_ms:
            time.sleep(
                max(
                    0,
                    delay_ms,
                )
                / 1000.0
            )

    urls = sorted(
        {
            start,
            *visited,
            *discovered,
        }
    )

    return (
        urls,
        pages,
        forms,
    )


# ---------------------------------------------------------------------------
# Candidate handling
# ---------------------------------------------------------------------------

def candidate_parameters(
    urls: list[str],
    forms: list[dict[str, Any]],
    max_params: int,
) -> list[dict[str, Any]]:

    candidates: list[
        dict[str, Any]
    ] = []

    seen: set[
        tuple[str, str, str]
    ] = set()

    for url in urls:

        parsed = urlsplit(url)

        params = parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )

        for name, value in params[
            :max_params
        ]:

            key = (
                canonical_url(url),
                name,
                "GET",
            )

            if key in seen:
                continue

            seen.add(key)

            candidates.append(
                {
                    "source": "link",
                    "url": canonical_url(
                        url
                    ),
                    "parameter": name,
                    "original_value": value,
                    "value_profile": (
                        "numeric"
                        if re.fullmatch(
                            r"-?\d+(?:\.\d+)?",
                            value or "",
                        )
                        else (
                            "uuid"
                            if re.fullmatch(
                                r"[0-9a-fA-F]{8}-"
                                r"[0-9a-fA-F-]{27,}",
                                value or "",
                            )
                            else "text_or_unknown"
                        )
                    ),
                    "method": "GET",
                }
            )

    for form in forms:

        for name in list(
            form.get("inputs")
            or []
        )[:max_params]:

            action = canonical_url(
                str(
                    form.get(
                        "action"
                    )
                    or ""
                )
            )

            key = (
                action,
                name,
                "GET",
            )

            if key in seen:
                continue

            seen.add(key)

            candidates.append(
                {
                    "source": "get-form",
                    "url": action,
                    "page": str(
                        form.get(
                            "page"
                        )
                        or ""
                    ),
                    "parameter": str(name),
                    "original_value": "",
                    "value_profile": (
                        "empty_form_value"
                    ),
                    "method": "GET",
                }
            )

    return candidates


def mutate_query(
    url: str,
    parameter: str,
    value: str,
) -> str:

    parsed = urlsplit(url)

    pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    replaced = False

    output: list[
        tuple[str, str]
    ] = []

    for name, old_value in pairs:

        if (
            name == parameter
            and not replaced
        ):
            output.append(
                (
                    name,
                    value,
                )
            )

            replaced = True

        else:
            output.append(
                (
                    name,
                    old_value,
                )
            )

    if not replaced:
        output.append(
            (
                parameter,
                value,
            )
        )

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            urlencode(output),
            "",
        )
    )


def build_candidate_url(
    candidate: dict[str, Any],
    value: str,
) -> str:

    return mutate_query(
        str(candidate["url"]),
        str(candidate["parameter"]),
        value,
    )


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------

def make_token(
    candidate_index: int,
    probe_index: int,
) -> str:

    seed = (
        f"{candidate_index}:"
        f"{probe_index}:"
        f"{time.time_ns()}"
    )

    return hashlib.sha256(
        seed.encode("utf-8")
    ).hexdigest()[:12].upper()


def render_payload(
    template: str,
    token: str,
) -> str:

    return template.format(
        token=token
    )


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def baseline_for_candidate(
    session: requests.Session,
    candidate: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:

    original = str(
        candidate.get(
            "original_value"
        )
        or ""
    )

    url = build_candidate_url(
        candidate,
        original,
    )

    response, body = request_no_redirect(
        session,
        url,
        timeout,
    )

    return {
        "url": url,
        "response": safe_response(
            response,
            body,
        ),
        "challenge_markers": detect_challenge(
            body
        ),
    }


# ---------------------------------------------------------------------------
# Reflection / execution analysis
# ---------------------------------------------------------------------------

def marker_occurrences(
    body: str,
    marker: str,
) -> int:

    if not marker:
        return 0

    return len(
        re.findall(
            re.escape(marker),
            body,
            flags=re.IGNORECASE,
        )
    )


def find_marker_context(
    body: str,
    marker: str,
    limit: int = 8,
    context_chars: int = 240,
) -> list[dict[str, Any]]:

    contexts: list[
        dict[str, Any]
    ] = []

    if not marker:
        return contexts

    for match in re.finditer(
        re.escape(marker),
        body,
        flags=re.IGNORECASE,
    ):

        start = max(
            0,
            match.start()
            - context_chars,
        )

        end = min(
            len(body),
            match.end()
            + context_chars,
        )

        contexts.append(
            {
                "offset": match.start(),
                "excerpt": body[
                    start:end
                ],
            }
        )

        if len(contexts) >= limit:
            break

    return contexts


def payload_reflected(
    body: str,
    payload: str,
) -> bool:

    if not payload:
        return False

    return payload.lower() in body.lower()


def marker_is_unaccompanied(
    body: str,
    marker: str,
    payload: str,
) -> bool:

    if not marker:
        return False

    if marker.lower() not in body.lower():
        return False

    # Stronger indicator:
    # marker appears, but the original injected payload does not.
    #
    # This is still NOT automatically treated as confirmed RCE.
    return not payload_reflected(
        body,
        payload,
    )


def timing_delta(
    baseline_ms: Optional[float],
    probe_ms: Optional[float],
) -> Optional[float]:

    if (
        baseline_ms is None
        or probe_ms is None
    ):
        return None

    return round(
        probe_ms - baseline_ms,
        2,
    )


def probe_candidate(
    session: requests.Session,
    candidate: dict[str, Any],
    baseline: dict[str, Any],
    timeout: int,
    delay_ms: int,
    candidate_index: int,
    max_probes: int,
) -> list[dict[str, Any]]:

    probes: list[
        dict[str, Any]
    ] = []

    baseline_response = (
        baseline.get("response")
        or {}
    )

    baseline_ms = (
        baseline_response.get(
            "elapsed_ms"
        )
    )

    baseline_challenges = (
        baseline.get(
            "challenge_markers"
        )
        or []
    )

    templates = PAYLOAD_TEMPLATES[
        :max_probes
    ]

    for probe_index, (
        payload_name,
        template,
    ) in enumerate(
        templates,
        start=1,
    ):

        token = make_token(
            candidate_index,
            probe_index,
        )

        marker = (
            f"BREBESCMD_{token}"
        )

        payload = render_payload(
            template,
            token,
        )

        request_url = build_candidate_url(
            candidate,
            (
                str(
                    candidate.get(
                        "original_value"
                    )
                    or ""
                )
                + payload
            ),
        )

        started = time.perf_counter()

        try:
            response, body = request_no_redirect(
                session,
                request_url,
                timeout,
            )

            elapsed_client_ms = round(
                (
                    time.perf_counter()
                    - started
                )
                * 1000,
                2,
            )

            challenge_markers = detect_challenge(
                body
            )

            reflected = payload_reflected(
                body,
                payload,
            )

            marker_found = (
                marker.lower()
                in body.lower()
            )

            unaccompanied = (
                marker_is_unaccompanied(
                    body,
                    marker,
                    payload,
                )
            )

            delta = timing_delta(
                baseline_ms,
                (
                    safe_response(
                        response,
                        body,
                    ).get(
                        "elapsed_ms"
                    )
                    or elapsed_client_ms
                ),
            )

            error_response = (
                response.status_code >= 400
            )

            probe = {
                "candidate": {
                    "source": candidate.get(
                        "source"
                    ),
                    "url": candidate.get(
                        "url"
                    ),
                    "parameter": candidate.get(
                        "parameter"
                    ),
                    "method": "GET",
                },
                "payload": {
                    "name": payload_name,
                    "template": template,
                    "value": payload,
                    "marker": marker,
                    "destructive": False,
                },
                "request": {
                    "method": "GET",
                    "url": request_url,
                    "parameter": candidate.get(
                        "parameter"
                    ),
                },
                "response": safe_response(
                    response,
                    body,
                ),
                "signals": {
                    "payload_reflected": reflected,
                    "marker_found": marker_found,
                    "marker_unaccompanied": (
                        unaccompanied
                    ),
                    "challenge_markers": (
                        challenge_markers
                    ),
                    "baseline_challenge_markers": (
                        baseline_challenges
                    ),
                    "error_response": (
                        error_response
                    ),
                    "timing_delta_ms": delta,
                    "timing_anomaly": (
                        delta is not None
                        and delta >= 3000
                    ),
                },
                "forensic": {
                    "marker_occurrences": (
                        marker_occurrences(
                            body,
                            marker,
                        )
                    ),
                    "marker_contexts": (
                        find_marker_context(
                            body,
                            marker,
                        )
                    ),
                    "body_length_delta": (
                        len(body)
                        - int(
                            baseline_response.get(
                                "content_length"
                            )
                            or 0
                        )
                    ),
                    "body_sha256": (
                        body_fingerprint(
                            body
                        )
                    ),
                    "baseline_body_sha256": (
                        baseline_response.get(
                            "body_sha256"
                        )
                    ),
                    "client_elapsed_ms": (
                        elapsed_client_ms
                    ),
                },
                "error": None,
            }

            probes.append(
                probe
            )

            # Do not continue hammering a challenge response.
            if challenge_markers:
                break

        except requests.RequestException as exc:

            probes.append(
                {
                    "candidate": {
                        "source": candidate.get(
                            "source"
                        ),
                        "url": candidate.get(
                            "url"
                        ),
                        "parameter": candidate.get(
                            "parameter"
                        ),
                        "method": "GET",
                    },
                    "payload": {
                        "name": payload_name,
                        "template": template,
                        "value": payload,
                        "marker": marker,
                        "destructive": False,
                    },
                    "request": {
                        "method": "GET",
                        "url": request_url,
                        "parameter": candidate.get(
                            "parameter"
                        ),
                    },
                    "response": {},
                    "signals": {
                        "payload_reflected": False,
                        "marker_found": False,
                        "marker_unaccompanied": False,
                        "challenge_markers": [],
                        "error_response": False,
                        "timing_delta_ms": None,
                        "timing_anomaly": False,
                    },
                    "forensic": {},
                    "error": str(exc),
                }
            )

        if delay_ms:
            time.sleep(
                max(
                    0,
                    delay_ms,
                )
                / 1000.0
            )

    return probes


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

def assess_candidate(
    candidate: dict[str, Any],
    baseline: dict[str, Any],
    probes: list[dict[str, Any]],
) -> dict[str, Any]:

    reflected = False
    marker_observed = False
    unaccompanied_marker = False
    timing_anomaly = False
    challenge = bool(
        baseline.get(
            "challenge_markers"
        )
    )

    request_errors = 0

    for probe in probes:

        signals = (
            probe.get(
                "signals"
            )
            or {}
        )

        reflected = (
            reflected
            or bool(
                signals.get(
                    "payload_reflected"
                )
            )
        )

        marker_observed = (
            marker_observed
            or bool(
                signals.get(
                    "marker_found"
                )
            )
        )

        unaccompanied_marker = (
            unaccompanied_marker
            or bool(
                signals.get(
                    "marker_unaccompanied"
                )
            )
        )

        timing_anomaly = (
            timing_anomaly
            or bool(
                signals.get(
                    "timing_anomaly"
                )
            )
        )

        challenge = (
            challenge
            or bool(
                signals.get(
                    "challenge_markers"
                )
            )
        )

        if probe.get("error"):
            request_errors += 1

    # ---------------------------------------------------------------
    # Conservative assessment model
    # ---------------------------------------------------------------

    if unaccompanied_marker:

        result = "requires_review"

        finding = False

        requires_review = True

        note = (
            "Unique command marker was observed "
            "without the complete injected payload "
            "being reflected. This is a strong "
            "execution indicator, but requires "
            "manual verification before reporting "
            "Command Injection."
        )

    elif challenge:

        result = "requires_review"

        finding = False

        requires_review = True

        note = (
            "Challenge/block response detected. "
            "Evidence is preserved and additional "
            "probing was stopped."
        )

    elif reflected:

        result = "not_confirmed"

        finding = False

        requires_review = True

        note = (
            "Injected payload was reflected, but "
            "no controlled command execution "
            "marker was confirmed."
        )

    elif timing_anomaly:

        result = "requires_review"

        finding = False

        requires_review = True

        note = (
            "Timing anomaly observed, but timing "
            "alone is insufficient to establish "
            "command execution."
        )

    elif request_errors == len(probes) and probes:

        result = "request_error"

        finding = False

        requires_review = True

        note = (
            "All probes produced request errors. "
            "Manual verification is required."
        )

    else:

        result = "pass"

        finding = False

        requires_review = False

        note = (
            "No controlled command execution "
            "indicator was observed."
        )

    return {
        "result": result,
        "finding": finding,
        "requires_review": requires_review,
        "payload_reflected": reflected,
        "marker_observed": marker_observed,
        "unaccompanied_marker": (
            unaccompanied_marker
        ),
        "timing_anomaly": timing_anomaly,
        "request_errors": request_errors,
        "note": note,
    }


def aggregate_summary(
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:

    strong = [
        candidate
        for candidate in candidates
        if (
            candidate.get(
                "assessment"
            )
            or {}
        ).get(
            "unaccompanied_marker"
        )
    ]

    reviews = [
        candidate
        for candidate in candidates
        if (
            candidate.get(
                "assessment"
            )
            or {}
        ).get(
            "requires_review"
        )
    ]

    if strong:

        return {
            "result": "requires_review",
            "finding": False,
            "requires_review": True,
            "note": (
                "Strong command execution "
                "indicators were observed and "
                "require manual verification."
            ),
        }

    if reviews:

        return {
            "result": "requires_review",
            "finding": False,
            "requires_review": True,
            "note": (
                "Some candidates require manual "
                "review based on reflection, "
                "challenge, timing, or request "
                "errors."
            ),
        }

    if candidates:

        return {
            "result": "pass",
            "finding": False,
            "requires_review": False,
            "note": (
                "No controlled Command Injection "
                "indicator observed."
            ),
        }

    return {
        "result": "not-tested",
        "finding": False,
        "requires_review": False,
        "note": (
            "Tidak ada candidate yang diuji."
        ),
    }


# ---------------------------------------------------------------------------
# Artifact
# ---------------------------------------------------------------------------

def initial_artifact() -> dict[str, Any]:

    context = active_context()

    scope_target = load_scope_target()

    now = now_iso()

    return {
        "schema_version": SCHEMA_VERSION,

        "project_id": context.project_id,

        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "command.py",
            "version": SCRIPT_VERSION,
        },

        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "focus": (
                "Controlled Command Injection "
                "assessment against discovered "
                "same-origin GET parameters and "
                "GET-form inputs."
            ),
            "status": "initialized",
        },

        "target": {
            "application": context.project_id,
            "hostname": scope_target[
                "hostname"
            ],
            "url": scope_target["url"],
            "environment": (
                getattr(
                    context,
                    "environment",
                    "",
                )
                or ""
            ),
            "assessment_type": str(
                context.assessment_type
            ),
            "scope_id": scope_target[
                "scope_id"
            ],
            "scope_reference": (
                "01-preparation/scope/scope.yaml"
            ),
            "authorized_ports": scope_target[
                "ports"
            ],
        },

        "methodology": {
            "description": (
                "Same-origin crawl followed "
                "by bounded non-destructive "
                "Command Injection probes."
            ),

            "authenticated_session_required": True,

            "session_source": (
                "05-authentication/"
                "session/session.yaml"
            ),

            "logout_cross_check": (
                "05-authentication/"
                "logout/logout.yaml"
            ),

            "session_secret_encryption": (
                "project Fernet key via "
                "scripts/secrets.py"
            ),

            "plaintext_session_persisted": False,

            "same_origin_only": True,

            "redirect_following": False,

            "get_only_probe_engine": True,

            "non_destructive_payloads_only": True,

            "post_forms": False,

            "file_upload": False,

            "file_read_commands": False,

            "file_write_commands": False,

            "reverse_shell": False,

            "external_callbacks": False,

            "persistence": False,

            "credential_access": False,

            "automatic_finding": False,

            "reflection_is_finding": False,

            "forensic_detail": {
                "response_fingerprint": True,
                "response_timing": True,
                "payload_reflection": True,
                "marker_observation": True,
                "marker_context": True,
                "challenge_detail": True,
                "error_response": True,
                "timing_delta": True,
            },
        },

        "baseline": {
            "active_project": (
                ".runtime/active-project.yaml"
            ),
            "scope_source": (
                "01-preparation/scope/"
                "scope.yaml"
            ),
            "session_source": (
                "05-authentication/"
                "session/session.yaml"
            ),
            "logout_source": (
                "05-authentication/"
                "logout/logout.yaml"
            ),
            "encryption_key_source": (
                ".runtime/secrets/"
                "<PROJECT-ID>/"
                "encryption.key"
            ),
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
            "optional": [],
            "not_required": [
                "Nmap",
                "ffuf",
                "Gobuster",
                "sqlmap",
                "ZAP",
                "Hydra",
                "Playwright",
                "Chromium",
            ],
        },

        "probe": {
            "engine": "requests.Session",

            "crawl": {
                "max_links": DEFAULT_MAX_LINKS,
                "max_depth": DEFAULT_MAX_DEPTH,
                "max_candidates": (
                    DEFAULT_MAX_CANDIDATES
                ),
                "max_params_per_url": (
                    DEFAULT_MAX_PARAMS_PER_URL
                ),
            },

            "payloads": [
                name
                for name, _
                in PAYLOAD_TEMPLATES
            ],

            "delay_ms": DEFAULT_DELAY_MS,

            "max_probes_per_param": (
                DEFAULT_MAX_PROBES_PER_PARAM
            ),
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
            "marker_observed_signals": 0,
            "unaccompanied_marker_signals": 0,
            "timing_anomaly_signals": 0,
            "challenge_stops": 0,
            "error_response_probes": 0,
            "request_errors": 0,
            "candidates": [],
            "probes": [],
        },

        "summary": {
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
            "note": (
                "Belum dilakukan assessment."
            ),
        },

        "assessment": {
            "result": "not-tested",
            "finding": False,
            "requires_review": False,
            "note": (
                "Belum dilakukan assessment."
            ),
        },

        "evidence": {
            "command_probes": (
                f"{PHASE_DIR}/"
                f"{CHECKLIST_DIR}/evidence/"
                f"{EVIDENCE_FILE}"
            ),
        },

        "errors": [],

        "notes": [
            (
                "Raw evidence is preserved; "
                "report redaction is a separate layer."
            ),
            (
                "Payload reflection alone is "
                "not Command Injection."
            ),
            (
                "Command payloads are restricted "
                "to marker-producing operations."
            ),
            (
                "No file read/write commands "
                "are intentionally executed."
            ),
            (
                "No reverse shell or external "
                "callback is attempted."
            ),
            (
                "Challenge responses are "
                "recorded and probing stops."
            ),
            (
                "Timing anomaly is supporting "
                "evidence only."
            ),
            (
                "This script never modifies "
                "session.yaml or logout.yaml."
            ),
        ],

        "generated_at": now,
        "updated_at": now,
    }


def init_artifact() -> dict[str, Any]:

    path = artifact_path()

    if path.exists():

        data = load_yaml(path)

        if not isinstance(
            data,
            dict,
        ):
            raise CommandInjectionError(
                "command.yaml memiliki format "
                "yang tidak valid."
            )

        return data

    data = initial_artifact()

    save_yaml(
        path,
        data,
    )

    return data


def load_artifact() -> dict[str, Any]:

    data = load_yaml(
        artifact_path()
    )

    if not isinstance(
        data,
        dict,
    ):
        raise CommandInjectionError(
            "command.yaml harus berupa "
            "mapping/object YAML."
        )

    return data


# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

def update_result_counts(
    data: dict[str, Any],
    candidates: list[dict[str, Any]],
    probes: list[dict[str, Any]],
) -> None:

    results = data.setdefault(
        "results",
        {},
    )

    results[
        "tested_parameters"
    ] = len(candidates)

    results[
        "probes_sent"
    ] = len(probes)

    results[
        "baseline_requests"
    ] = sum(
        1
        for candidate
        in candidates
        if candidate.get("baseline")
    )

    results[
        "reflected_payload_signals"
    ] = sum(
        1
        for probe
        in probes
        if (
            probe.get(
                "signals"
            )
            or {}
        ).get(
            "payload_reflected"
        )
    )

    results[
        "marker_observed_signals"
    ] = sum(
        1
        for probe
        in probes
        if (
            probe.get(
                "signals"
            )
            or {}
        ).get(
            "marker_found"
        )
    )

    results[
        "unaccompanied_marker_signals"
    ] = sum(
        1
        for probe
        in probes
        if (
            probe.get(
                "signals"
            )
            or {}
        ).get(
            "marker_unaccompanied"
        )
    )

    results[
        "timing_anomaly_signals"
    ] = sum(
        1
        for probe
        in probes
        if (
            probe.get(
                "signals"
            )
            or {}
        ).get(
            "timing_anomaly"
        )
    )

    results[
        "challenge_stops"
    ] = sum(
        1
        for probe
        in probes
        if (
            probe.get(
                "signals"
            )
            or {}
        ).get(
            "challenge_markers"
        )
    )

    results[
        "error_response_probes"
    ] = sum(
        1
        for probe
        in probes
        if (
            probe.get(
                "signals"
            )
            or {}
        ).get(
            "error_response"
        )
    )

    results[
        "request_errors"
    ] = sum(
        1
        for probe
        in probes
        if probe.get("error")
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_version(
    _: argparse.Namespace,
) -> int:

    print(
        "BrebesKab-CSIRT-Tools "
        f"Command Injection {SCRIPT_VERSION}"
    )

    print(
        f"Checklist : "
        f"{CHECKLIST_ID} "
        f"{CHECKLIST_NAME}"
    )

    print(
        f"Schema    : {SCHEMA_VERSION}"
    )

    return 0


def cmd_init(
    _: argparse.Namespace,
) -> int:

    data = init_artifact()

    print(
        "[PASS] Command Injection "
        "artifact siap."
    )

    print(
        f"[PASS] Checklist : "
        f"{CHECKLIST_ID} "
        f"{CHECKLIST_NAME}"
    )

    print(
        f"[PASS] Project   : "
        f"{data.get('project_id')}"
    )

    print(
        f"[PASS] File      : "
        f"{artifact_path()}"
    )

    return 0


def cmd_crawl(
    args: argparse.Namespace,
) -> int:

    data = init_artifact()

    project_match(data)

    target = load_scope_target()

    session_info = load_usable_session()

    data["source_status"][
        "session"
    ] = "completed"

    data["source_status"][
        "logout_cross_check"
    ] = "completed"

    session = build_session(
        target["url"],
        session_info,
    )

    urls, pages, forms = discover_links(
        session,
        target["url"],
        args.timeout,
        args.max_links,
        args.max_depth,
        args.delay_ms,
    )

    candidates = candidate_parameters(
        urls,
        forms,
        args.max_params_per_url,
    )

    if (
        args.max_candidates
        and len(candidates)
        > args.max_candidates
    ):
        candidates = candidates[
            :args.max_candidates
        ]

    data["crawl"] = {
        "pages": pages,
        "forms": forms,
        "urls": urls,
    }

    data["results"][
        "links_discovered"
    ] = len(urls)

    data["results"][
        "same_origin_links"
    ] = len(
        [
            url
            for url in urls
            if is_in_scope_url(
                url,
                target["url"],
            )
        ]
    )

    data["results"][
        "query_parameter_candidates"
    ] = len(
        [
            candidate
            for candidate in candidates
            if candidate.get(
                "source"
            )
            == "link"
        ]
    )

    data["results"][
        "get_form_candidates"
    ] = len(
        [
            candidate
            for candidate in candidates
            if candidate.get(
                "source"
            )
            == "get-form"
        ]
    )

    data["candidates"] = candidates

    data["checklist"][
        "status"
    ] = "crawled"

    data["updated_at"] = now_iso()

    save_yaml(
        artifact_path(),
        data,
    )

    print(
        "[PASS] Command Injection "
        "crawl selesai."
    )

    print(
        f"[PASS] Links     : {len(urls)}"
    )

    print(
        f"[PASS] Candidates: "
        f"{len(candidates)}"
    )

    print(
        f"[PASS] GET forms : "
        f"{len([c for c in candidates if c.get('source') == 'get-form'])}"
    )

    print(
        f"[PASS] File      : "
        f"{artifact_path()}"
    )

    return 0


def cmd_analyze(
    args: argparse.Namespace,
) -> int:

    data = init_artifact()

    project_match(data)

    target = load_scope_target()

    session_info = load_usable_session()

    data["source_status"][
        "session"
    ] = "completed"

    data["source_status"][
        "logout_cross_check"
    ] = "completed"

    session = build_session(
        target["url"],
        session_info,
    )

    urls, pages, forms = discover_links(
        session,
        target["url"],
        args.timeout,
        args.max_links,
        args.max_depth,
        args.delay_ms,
    )

    candidates = candidate_parameters(
        urls,
        forms,
        args.max_params_per_url,
    )

    if (
        args.max_candidates
        and len(candidates)
        > args.max_candidates
    ):
        candidates = candidates[
            :args.max_candidates
        ]

    all_probes: list[
        dict[str, Any]
    ] = []

    assessed_candidates: list[
        dict[str, Any]
    ] = []

    for index, candidate in enumerate(
        candidates,
        start=1,
    ):

        try:

            baseline = baseline_for_candidate(
                session,
                candidate,
                args.timeout,
            )

        except requests.RequestException as exc:

            assessed_candidates.append(
                {
                    **candidate,

                    "baseline": {
                        "error": str(exc)
                    },

                    "probes": [],

                    "assessment": {
                        "result": (
                            "request_error"
                        ),
                        "finding": False,
                        "requires_review": True,
                        "note": (
                            "Baseline request "
                            "failed; candidate "
                            "requires manual "
                            "review."
                        ),
                    },
                }
            )

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

        assessment = assess_candidate(
            candidate,
            baseline,
            probes,
        )

        candidate_record = {
            **candidate,
            "baseline": baseline,
            "probes": probes,
            "assessment": assessment,
        }

        assessed_candidates.append(
            candidate_record
        )

        all_probes.extend(
            probes
        )

    data["crawl"] = {
        "pages": pages,
        "forms": forms,
        "urls": urls,
    }

    data["candidates"] = (
        assessed_candidates
    )

    data["results"][
        "links_discovered"
    ] = len(urls)

    data["results"][
        "same_origin_links"
    ] = len(
        [
            url
            for url in urls
            if is_in_scope_url(
                url,
                target["url"],
            )
        ]
    )

    data["results"][
        "query_parameter_candidates"
    ] = len(
        [
            candidate
            for candidate
            in assessed_candidates
            if candidate.get(
                "source"
            )
            == "link"
        ]
    )

    data["results"][
        "get_form_candidates"
    ] = len(
        [
            candidate
            for candidate
            in assessed_candidates
            if candidate.get(
                "source"
            )
            == "get-form"
        ]
    )

    update_result_counts(
        data,
        assessed_candidates,
        all_probes,
    )

    summary = aggregate_summary(
        assessed_candidates
    )

    data["summary"] = summary

    data["assessment"] = dict(
        summary
    )

    data["checklist"][
        "status"
    ] = "completed"

    data["updated_at"] = now_iso()

    evidence = {
        "schema_version": (
            SCHEMA_VERSION
        ),

        "tool": {
            "name": (
                "BrebesKab-CSIRT-Tools"
            ),
            "script": "command.py",
            "version": SCRIPT_VERSION,
        },

        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
        },

        "project_id": data.get(
            "project_id"
        ),

        "target": data.get(
            "target"
        ),

        "methodology": data.get(
            "methodology"
        ),

        "generated_at": now_iso(),

        "candidates": (
            assessed_candidates
        ),
    }

    save_json(
        evidence_path(),
        evidence,
    )

    data["results"][
        "probes"
    ] = all_probes

    save_yaml(
        artifact_path(),
        data,
    )

    print(
        "[PASS] Command Injection "
        f"analysis selesai: "
        f"{summary['result']}"
    )

    print(
        f"[INFO] Candidates: "
        f"{len(assessed_candidates)}"
    )

    print(
        f"[INFO] Probes    : "
        f"{len(all_probes)}"
    )

    print(
        f"[INFO] Finding   : "
        f"{summary['finding']}"
    )

    print(
        f"[INFO] Review    : "
        f"{summary['requires_review']}"
    )

    print(
        f"[PASS] Artifact  : "
        f"{artifact_path()}"
    )

    print(
        f"[PASS] Evidence  : "
        f"{evidence_path()}"
    )

    return 0


def cmd_show(
    _: argparse.Namespace,
) -> int:

    data = load_artifact()

    project_match(data)

    print(
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
    )

    return 0


def cmd_status(
    _: argparse.Namespace,
) -> int:

    data = load_artifact()

    project_match(data)

    checklist = data.get(
        "checklist"
    ) or {}

    summary = data.get(
        "summary"
    ) or {}

    results = data.get(
        "results"
    ) or {}

    print(
        f"Checklist : "
        f"{checklist.get('id')} "
        f"{checklist.get('name')}"
    )

    print(
        f"Status    : "
        f"{checklist.get('status')}"
    )

    print(
        f"Result    : "
        f"{summary.get('result')}"
    )

    print(
        f"Finding   : "
        f"{summary.get('finding')}"
    )

    print(
        f"Review    : "
        f"{summary.get('requires_review')}"
    )

    print(
        f"Candidates: "
        f"{results.get('tested_parameters', 0)}"
    )

    print(
        f"Probes    : "
        f"{results.get('probes_sent', 0)}"
    )

    print(
        f"Markers   : "
        f"{results.get('marker_observed_signals', 0)}"
    )

    print(
        f"Execution : "
        f"{results.get('unaccompanied_marker_signals', 0)}"
    )

    print(
        f"Artifact  : "
        f"{artifact_path()}"
    )

    return 0


def cmd_verify(
    _: argparse.Namespace,
) -> int:

    data = load_artifact()

    project_match(data)

    errors: list[str] = []

    if (
        data.get("schema_version")
        != SCHEMA_VERSION
    ):
        errors.append(
            "schema_version tidak sesuai"
        )

    tool = data.get(
        "tool"
    ) or {}

    if (
        str(
            tool.get("script")
        )
        != "command.py"
    ):
        errors.append(
            "tool.script bukan command.py"
        )

    if (
        str(
            tool.get("version")
        )
        != SCRIPT_VERSION
    ):
        errors.append(
            "tool.version tidak sesuai"
        )

    checklist = data.get(
        "checklist"
    ) or {}

    if (
        checklist.get("id")
        != CHECKLIST_ID
    ):
        errors.append(
            "checklist.id bukan 7-003"
        )

    results = data.get(
        "results"
    ) or {}

    candidates = data.get(
        "candidates"
    ) or []

    probes = results.get(
        "probes"
    ) or []

    if not isinstance(
        candidates,
        list,
    ):
        errors.append(
            "candidates bukan list"
        )

    if not isinstance(
        probes,
        list,
    ):
        errors.append(
            "results.probes bukan list"
        )

    if (
        int(
            results.get(
                "tested_parameters",
                -1,
            )
        )
        != len(candidates)
    ):
        errors.append(
            "tested_parameters tidak "
            "sama dengan jumlah candidates"
        )

    if (
        int(
            results.get(
                "probes_sent",
                -1,
            )
        )
        != len(probes)
    ):
        errors.append(
            "probes_sent tidak sama "
            "dengan jumlah probes"
        )

    if not evidence_path().exists():

        errors.append(
            f"evidence tidak ditemukan: "
            f"{evidence_path()}"
        )

    else:

        raw = evidence_path().read_bytes()

        if raw.startswith(
            b"\xef\xbb\xbf"
        ):
            errors.append(
                "evidence menggunakan "
                "UTF-8 BOM"
            )

        try:
            raw.decode("utf-8")

        except UnicodeDecodeError:
            errors.append(
                "evidence bukan UTF-8 valid"
            )

    target_url = str(
        (
            data.get("target")
            or {}
        ).get("url")
        or ""
    )

    # Verify that every probe remains
    # GET-only and same-origin.
    for index, probe in enumerate(
        probes,
        start=1,
    ):

        request = (
            probe.get(
                "request"
            )
            or {}
        )

        method = str(
            request.get(
                "method"
            )
            or ""
        ).upper()

        if method != "GET":
            errors.append(
                f"probe #{index} bukan GET"
            )

        url = str(
            request.get(
                "url"
            )
            or ""
        )

        if (
            url
            and not is_in_scope_url(
                url,
                target_url,
            )
        ):
            errors.append(
                f"probe #{index} "
                "berada di luar scope"
            )

        payload = (
            probe.get(
                "payload"
            )
            or {}
        )

        if payload.get(
            "destructive"
        ) is not False:
            errors.append(
                f"probe #{index} "
                "payload tidak ditandai "
                "non-destructive"
            )

        # Credential/session material
        # must never enter evidence.
        evidence_text = json.dumps(
            probe,
            ensure_ascii=False,
        ).lower()

        forbidden_evidence_keys = {
            '"cookie_value"',
            '"authorization"',
            '"password"',
            '"session_secret"',
        }

        for key in forbidden_evidence_keys:

            if key in evidence_text:
                errors.append(
                    f"probe #{index} "
                    f"mengandung sensitive "
                    f"field {key}"
                )

    if errors:

        print(
            "[FAIL] Command Injection "
            "tidak memenuhi validasi."
        )

        for error in errors:
            print(
                f"[FAIL] {error}"
            )

        return 1

    artifact_raw = (
        artifact_path().read_bytes()
    )

    encoding_ok = True

    if artifact_raw.startswith(
        b"\xef\xbb\xbf"
    ):
        encoding_ok = False

    try:
        artifact_raw.decode(
            "utf-8"
        )

    except UnicodeDecodeError:
        encoding_ok = False

    print(
        "[PASS] Command Injection "
        "memenuhi validasi."
    )

    print(
        f"[PASS] Checklist : "
        f"{CHECKLIST_ID} "
        f"{CHECKLIST_NAME}"
    )

    print(
        f"[PASS] Project   : "
        f"{data.get('project_id')}"
    )

    print(
        f"[PASS] File      : "
        f"{artifact_path()}"
    )

    print(
        f"[PASS] Candidates: "
        f"{len(candidates)}"
    )

    print(
        f"[PASS] Probes    : "
        f"{len(probes)}"
    )

    print(
        f"[PASS] Encoding  : "
        f"{'UTF-8 tanpa BOM' if encoding_ok else 'INVALID'}"
    )

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_common(
    parser: argparse.ArgumentParser,
) -> None:

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
    )

    parser.add_argument(
        "--max-links",
        type=int,
        default=DEFAULT_MAX_LINKS,
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=DEFAULT_MAX_DEPTH,
    )

    parser.add_argument(
        "--max-candidates",
        type=int,
        default=DEFAULT_MAX_CANDIDATES,
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
    )

    parser.add_argument(
        "--max-probes-per-param",
        type=int,
        default=DEFAULT_MAX_PROBES_PER_PARAM,
    )


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description=(
            "BrebesKab-CSIRT-Tools "
            "Command Injection assessment "
            "(checklist 7-003)."
        )
    )

    sub = parser.add_subparsers(
        dest="command"
    )

    sub.add_parser(
        "version",
        help="Tampilkan versi tool.",
    )

    sub.add_parser(
        "init",
        help="Buat artifact command.yaml.",
    )

    for command, help_text in [
        (
            "crawl",
            (
                "Crawl same-origin dan "
                "identifikasi candidate input."
            ),
        ),
        (
            "analyze",
            (
                "Crawl + bounded Command "
                "Injection assessment."
            ),
        ),
    ]:

        command_parser = sub.add_parser(
            command,
            help=help_text,
        )

        add_common(
            command_parser
        )

    sub.add_parser(
        "show",
        help="Tampilkan command.yaml.",
    )

    sub.add_parser(
        "status",
        help="Tampilkan status checklist.",
    )

    sub.add_parser(
        "verify",
        help="Validasi artifact dan evidence.",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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

        parser.error(
            f"Command tidak dikenal: "
            f"{args.command}"
        )

        return 2

    except KeyboardInterrupt:

        print(
            "\n[WARN] Assessment "
            "dibatalkan oleh pengguna."
        )

        return 130

    except CommandInjectionError as exc:

        print(
            f"[FAIL] {exc}"
        )

        return 1

    except requests.RequestException as exc:

        print(
            f"[FAIL] Request error: {exc}"
        )

        return 1

    except Exception as exc:

        print(
            f"[FAIL] COMMAND INJECTION ERROR: "
            f"{exc}"
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())