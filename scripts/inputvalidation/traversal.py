#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BrebesKab-CSIRT-Tools
Path Traversal / Directory Traversal Assessment

Script  : traversal.py
Version : 1.0.3
Checklist: 7-004 Path Traversal

Lifecycle:
    version
    init
    crawl
    analyze
    show
    status
    verify

Methodology:
    - Authenticated session
    - Same-origin only
    - GET-only
    - Non-destructive traversal probes
    - No POST
    - No upload
    - No file modification
    - No command execution
    - No reverse shell
    - No external callback
    - No credential harvesting
    - Reflection is NOT a finding
    - HTTP 500 is NOT automatically a finding
    - Evidence is preserved for manual verification

Important:
    This tool is designed for authorized security assessment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import requests
import yaml


SCRIPT_NAME = "traversal.py"
SCRIPT_VERSION = "1.0.3"

CHECKLIST_ID = "7-004"
CHECKLIST_NAME = "Path Traversal"

MAX_LINKS = 0
MAX_DEPTH = 5
MAX_CANDIDATES = 200
MAX_PARAMS_PER_URL = 5

REQUEST_TIMEOUT = 20
REQUEST_DELAY_MS = 150
MAX_BODY_SAMPLE = 12000
MAX_CONTEXTS = 10

PROJECT_ROOT_NAME = "projects"

ARTIFACT_DIR = Path("07-input-validation") / "traversal"
ARTIFACT_FILE = ARTIFACT_DIR / "traversal.yaml"
EVIDENCE_DIR = ARTIFACT_DIR / "evidence"
EVIDENCE_FILE = EVIDENCE_DIR / "traversal-probes.json"

# Parameters whose semantic names strongly suggest file/path handling.
PATH_PARAMETER_NAMES = {
    "file",
    "filepath",
    "file_path",
    "filename",
    "file_name",
    "path",
    "pathname",
    "document",
    "document_id",
    "doc",
    "download",
    "download_file",
    "downloadfile",
    "attachment",
    "attachment_id",
    "attachmentid",
    "media",
    "media_id",
    "mediaid",
    "image",
    "image_id",
    "imageid",
    "photo",
    "photo_id",
    "photoid",
    "template",
    "view",
    "resource",
    "resource_id",
    "resourceid",
    "include",
    "include_file",
    "source",
    "src",
    "target",
    "uri",
    "url",
    "idx",
}

# Harmless traversal target indicators.
#
# We deliberately avoid:
#   /etc/shadow
#   private keys
#   .env
#   database credentials
#   SSH keys
#   application secrets
#
# /etc/hostname is intentionally low-impact and useful as a file-read
# confirmation target on Linux systems.
LINUX_FILE_TARGETS = [
    {
        "name": "etc-hostname",
        "path": "/etc/hostname",
        "indicators": [
            "localhost",
        ],
        "description": "Linux host identity file",
    },
]

# Generic error signatures are forensic signals only.
ERROR_SIGNATURES = [
    r"no such file or directory",
    r"failed to open stream",
    r"include\(",
    r"require\(",
    r"file_get_contents",
    r"readfile",
    r"fopen",
    r"open_basedir restriction",
    r"not a directory",
    r"is a directory",
    r"permission denied",
    r"access denied",
    r"invalid file",
    r"invalid path",
]

# Responses which commonly indicate that an upstream WAF/challenge
# intervened. They are NOT automatically interpreted as WAF proof.
CHALLENGE_MARKERS = [
    "captcha",
    "recaptcha",
    "turnstile",
    "cloudflare",
    "challenge-platform",
    "cf-chl-",
    "access denied",
    "request blocked",
    "security challenge",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def body_sample(text: str) -> str:
    if len(text) <= MAX_BODY_SAMPLE:
        return text

    return text[:MAX_BODY_SAMPLE] + "\n...[TRUNCATED]..."


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_yaml(path: Path, default=None):
    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or default
    except Exception:
        return default


def save_yaml(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as fh:
        yaml.safe_dump(
            data,
            fh,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(
            data,
            fh,
            ensure_ascii=False,
            indent=2,
        )


def read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8") as fh:
        return fh.read()


def project_root() -> Path:
    """
    Locate project root from .runtime/active-project.yaml.

    Expected:
        .runtime/active-project.yaml

    Example:
        project_id: PENTEST-2026-002
    """

    active = Path(".runtime") / "active-project.yaml"

    data = load_yaml(active, {})
    project_id = None

    if isinstance(data, dict):
        project_id = (
            data.get("project_id")
            or data.get("active_project")
            or data.get("id")
        )

    if not project_id:
        env_project = os.environ.get("BREBES_PROJECT_ID")
        if env_project:
            project_id = env_project

    if not project_id:
        raise RuntimeError(
            "Project aktif tidak ditemukan. "
            "Pastikan .runtime/active-project.yaml tersedia."
        )

    root = Path(PROJECT_ROOT_NAME) / str(project_id)

    if not root.exists():
        raise RuntimeError(
            f"Project directory tidak ditemukan: {root}"
        )

    return root


def project_artifact_path() -> Path:
    return project_root() / ARTIFACT_FILE


def project_evidence_path() -> Path:
    return project_root() / EVIDENCE_FILE


def get_project_data():
    root = project_root()

    scope_file = root / "01-preparation" / "scope" / "scope.yaml"
    session_file = root / "05-authentication" / "session" / "session.yaml"
    logout_file = root / "05-authentication" / "logout" / "logout.yaml"

    scope = load_yaml(scope_file, {})
    session = load_yaml(session_file, {})
    logout = load_yaml(logout_file, {})

    return root, scope, session, logout


def discover_target(scope):
    """
    Read the authoritative IN-001 scope item from scope.yaml.

    Supported project scope structure:
        scope:
          in_scope:
            - scope_id: IN-001
              type: domain|hostname|url
              value: example.test
              ports: [80, 443]

    This intentionally follows the same scope-reading contract used by the
    established input-validation scripts: the target is taken from
    in_scope[].value and never inferred from DNS or from arbitrary recursive
    fields.
    """

    if not isinstance(scope, dict):
        raise RuntimeError("scope.yaml tidak valid.")

    # Some project artifacts wrap the actual scope under "scope".
    section = (
        scope.get("scope")
        if isinstance(scope.get("scope"), dict)
        else scope
    )

    items = (
        section.get("in_scope", [])
        if isinstance(section, dict)
        else []
    )

    if not isinstance(items, list):
        raise RuntimeError(
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

        if (
            scope_id == "IN-001"
            and value
            and scope_type in {
                "domain",
                "hostname",
                "url",
            }
        ):
            authorized_ports = sorted(
                {
                    safe_int(p)
                    for p in ports
                    if str(p).isdigit()
                }
            )

            # IN-001 in this project is authorized for HTTP/HTTPS.
            if authorized_ports != [80, 443]:
                raise RuntimeError(
                    "IN-001 authorized ports tidak sesuai: "
                    f"{ports!r}"
                )

            if scope_type == "url":
                target = value
            else:
                target = f"https://{value}"

            parsed = urlparse(target)

            if parsed.scheme.lower() not in {
                "http",
                "https",
            }:
                raise RuntimeError(
                    f"Target URL tidak valid: {target}"
                )

            hostname = parsed.hostname or ""
            if not hostname:
                raise RuntimeError(
                    f"Hostname target tidak valid: {target}"
                )

            return {
                "hostname": hostname,
                "url": target.rstrip("/"),
                "environment": (
                    scope.get("environment")
                    or scope.get("target_environment")
                    or "Production"
                ),
                "assessment_type": (
                    scope.get("assessment_type")
                    or scope.get("assessment")
                    or "Black Box"
                ),
                "scope_id": scope_id,
                "authorized_ports": [80, 443],
            }

    raise RuntimeError(
        "IN-001 domain/hostname tidak ditemukan di scope.yaml."
    )


def extract_session_material(session_data):
    """
    Best-effort extraction of session information.

    Supported forms:
        headers:
            Cookie: ...
            Authorization: ...

        cookies:
            name: value

        session:
            headers: ...
            cookies: ...

    If the project's session.yaml contains encrypted material that
    cannot be represented directly, the script fails safely instead
    of storing or printing plaintext credentials.
    """

    if not isinstance(session_data, dict):
        raise RuntimeError("session.yaml tidak valid.")

    headers = {}
    cookies = {}

    def merge_headers(value):
        if not isinstance(value, dict):
            return

        for key, val in value.items():
            if val is None:
                continue

            # Do not accidentally expose secrets in console.
            headers[str(key)] = str(val)

    def merge_cookies(value):
        if isinstance(value, dict):
            for key, val in value.items():
                if val is not None:
                    cookies[str(key)] = str(val)

        elif isinstance(value, list):
            for item in value:
                if not isinstance(item, dict):
                    continue

                name = item.get("name")
                value = item.get("value")

                if name and value is not None:
                    cookies[str(name)] = str(value)

    merge_headers(session_data.get("headers"))
    merge_cookies(session_data.get("cookies"))

    nested = session_data.get("session")

    if isinstance(nested, dict):
        merge_headers(nested.get("headers"))
        merge_cookies(nested.get("cookies"))

    # Some session artifacts use request_headers.
    merge_headers(session_data.get("request_headers"))

    # If a Cookie header exists, do not duplicate it.
    return headers, cookies


def build_session(session_data):
    session = requests.Session()

    headers, cookies = extract_session_material(session_data)

    session.headers.update(
        {
            "User-Agent": (
                "BrebesKab-CSIRT-Tools/"
                + SCRIPT_VERSION
            ),
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
        }
    )

    if headers:
        session.headers.update(headers)

    if cookies:
        session.cookies.update(cookies)

    return session


def same_origin(url, target_url):
    a = urlparse(url)
    b = urlparse(target_url)

    return (
        a.scheme.lower() == b.scheme.lower()
        and a.hostname.lower() == b.hostname.lower()
        and (a.port or default_port(a.scheme))
        == (b.port or default_port(b.scheme))
    )


def default_port(scheme):
    return 443 if scheme.lower() == "https" else 80


def normalize_url(url):
    parsed = urlparse(url)

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        )
    )


def extract_links(base_url, response_text):
    """
    Lightweight href extractor without requiring BeautifulSoup.

    This intentionally avoids external crawling dependencies.
    """

    links = []

    pattern = re.compile(
        r"""(?:href|src)\s*=\s*["']([^"']+)["']""",
        re.IGNORECASE,
    )

    for raw in pattern.findall(response_text or ""):
        raw = raw.strip()

        if not raw:
            continue

        if raw.startswith(
            (
                "#",
                "javascript:",
                "mailto:",
                "tel:",
                "data:",
            )
        ):
            continue

        absolute = urljoin(base_url, raw)
        absolute = normalize_url(absolute)

        links.append(absolute)

    return links


def extract_get_forms(base_url, response_text):
    """
    Minimal GET-form parser.

    Returns:
        [
            {
                url,
                method,
                parameters: [...]
            }
        ]
    """

    forms = []

    form_pattern = re.compile(
        r"<form\b([^>]*)>(.*?)</form>",
        re.IGNORECASE | re.DOTALL,
    )

    attr_pattern = re.compile(
        r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*["']([^"']*)["']"""
    )

    for form_attrs, form_body in form_pattern.findall(
        response_text or ""
    ):
        attrs = dict(attr_pattern.findall(form_attrs))

        method = attrs.get("method", "GET").upper()

        if method != "GET":
            continue

        action = attrs.get("action", base_url)
        action = urljoin(base_url, action)
        action = normalize_url(action)

        parameters = []

        input_pattern = re.compile(
            r"<input\b([^>]*)>",
            re.IGNORECASE | re.DOTALL,
        )

        for input_attrs in input_pattern.findall(form_body):
            item_attrs = dict(attr_pattern.findall(input_attrs))

            name = item_attrs.get("name")

            if not name:
                continue

            input_type = item_attrs.get(
                "type",
                "text",
            ).lower()

            if input_type in {
                "submit",
                "button",
                "image",
                "reset",
                "file",
            }:
                continue

            parameters.append(
                {
                    "name": name,
                    "value": item_attrs.get("value", ""),
                    "type": input_type,
                }
            )

        if parameters:
            forms.append(
                {
                    "url": action,
                    "method": "GET",
                    "parameters": parameters,
                }
            )

    return forms


def candidate_from_url(url, source="link"):
    parsed = urlparse(url)

    if not parsed.query:
        return []

    pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    candidates = []

    seen = set()

    for name, value in pairs[:MAX_PARAMS_PER_URL]:
        key = (normalize_url(url), name)

        if key in seen:
            continue

        seen.add(key)

        candidates.append(
            {
                "source": source,
                "url": normalize_url(url),
                "parameter": name,
                "original_value": value,
                "value_profile": classify_value(value),
                "method": "GET",
            }
        )

    return candidates


def classify_value(value):
    value = str(value or "")

    if re.fullmatch(r"\d+", value):
        return "numeric"

    if re.fullmatch(
        r"[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}",
        value,
    ):
        return "uuid"

    if "/" in value or "\\" in value:
        return "path-like"

    if "." in value:
        return "filename-like"

    if len(value) > 40:
        return "long-string"

    return "string"


def candidate_score(candidate):
    name = candidate["parameter"].lower()
    value = candidate.get("original_value", "")

    score = 0

    if name in PATH_PARAMETER_NAMES:
        score += 10

    if any(
        token in name
        for token in (
            "file",
            "path",
            "download",
            "document",
            "attachment",
            "image",
            "media",
            "template",
            "resource",
            "source",
            "target",
        )
    ):
        score += 5

    if candidate.get("value_profile") in {
        "path-like",
        "filename-like",
    }:
        score += 3

    if "/" in value or "\\" in value:
        score += 3

    return score


def select_candidates(candidates):
    """
    Keep path-relevant candidates first.

    We do not discard low-score candidates completely because a path
    traversal vulnerability can technically occur behind an arbitrary
    parameter name.
    """

    unique = {}

    for candidate in candidates:
        key = (
            candidate["url"],
            candidate["parameter"],
        )

        if key not in unique:
            candidate["priority_score"] = candidate_score(
                candidate
            )
            unique[key] = candidate

    result = list(unique.values())

    result.sort(
        key=lambda x: (
            -x.get("priority_score", 0),
            x["url"],
            x["parameter"],
        )
    )

    return result[:MAX_CANDIDATES]


def build_url_with_parameter(
    original_url,
    parameter,
    value,
):
    parsed = urlparse(original_url)

    pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    replaced = False
    output = []

    for name, old_value in pairs:
        if name == parameter and not replaced:
            output.append((name, value))
            replaced = True
        else:
            output.append((name, old_value))

    if not replaced:
        output.append((parameter, value))

    query = urlencode(
        output,
        doseq=True,
    )

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            query,
            "",
        )
    )


def request_snapshot(response, elapsed_ms):
    content_type = response.headers.get(
        "Content-Type",
        "",
    )

    text = response.text or ""

    return {
        "status": response.status_code,
        "url": response.url,
        "headers": {
            key: value
            for key, value in response.headers.items()
            if key.lower()
            in {
                "server",
                "content-type",
                "content-length",
                "content-encoding",
                "cache-control",
                "location",
                "x-powered-by",
                "date",
            }
        },
        "content_type": content_type,
        "content_length": len(response.content),
        "body_sha256": sha256_text(text),
        "body_sample": body_sample(text),
        "elapsed_ms": round(elapsed_ms, 2),
    }


def find_markers(text, markers):
    lowered = (text or "").lower()

    found = []

    for marker in markers:
        if marker.lower() in lowered:
            found.append(marker)

    return found


def find_error_signatures(text):
    lowered = (text or "").lower()

    found = []

    for signature in ERROR_SIGNATURES:
        if re.search(signature, lowered):
            found.append(signature)

    return found


def extract_contexts(text, needles):
    text = text or ""

    contexts = []

    for needle in needles:
        if not needle:
            continue

        start = 0

        while True:
            pos = text.find(needle, start)

            if pos < 0:
                break

            left = max(0, pos - 220)
            right = min(
                len(text),
                pos + len(needle) + 320,
            )

            contexts.append(
                {
                    "offset": pos,
                    "excerpt": text[left:right],
                }
            )

            start = pos + max(len(needle), 1)

            if len(contexts) >= MAX_CONTEXTS:
                return contexts

    return contexts


def traversal_payloads():
    """
    Payloads are intentionally read-only.

    The target file is /etc/hostname.
    We do not attempt to modify, delete, execute, or exfiltrate files.
    """

    token = uuid.uuid4().hex[:12].upper()

    return [
        {
            "name": "relative-1",
            "template": "../{target}",
            "value": f"../etc/hostname",
            "target": "/etc/hostname",
            "depth": 1,
            "destructive": False,
        },
        {
            "name": "relative-2",
            "template": "../../{target}",
            "value": "../../etc/hostname",
            "target": "/etc/hostname",
            "depth": 2,
            "destructive": False,
        },
        {
            "name": "relative-3",
            "template": "../../../{target}",
            "value": "../../../etc/hostname",
            "target": "/etc/hostname",
            "depth": 3,
            "destructive": False,
        },
        {
            "name": "relative-4",
            "template": "../../../../{target}",
            "value": "../../../../etc/hostname",
            "target": "/etc/hostname",
            "depth": 4,
            "destructive": False,
        },
        {
            "name": "encoded-slash",
            "template": "..%2f..%2f..%2f..%2fetc%2fhostname",
            "value": "..%2f..%2f..%2f..%2fetc%2fhostname",
            "target": "/etc/hostname",
            "depth": 4,
            "destructive": False,
        },
        {
            "name": "encoded-dot-slash",
            "template": "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhostname",
            "value": (
                "%2e%2e%2f%2e%2e%2f%2e%2e%2f"
                "%2e%2e%2fetc%2fhostname"
            ),
            "target": "/etc/hostname",
            "depth": 4,
            "destructive": False,
        },
    ]


def response_indicates_file_content(
    text,
    target="/etc/hostname",
):
    """
    Conservative detector.

    A traversal finding requires actual evidence of file content or
    a very strong path-boundary escape indicator.

    Since /etc/hostname content is environment-specific, this function
    intentionally does NOT guess arbitrary hostname values.
    """

    text = text or ""

    indicators = []

    if target == "/etc/hostname":
        # Common characteristics of /etc/hostname:
        # a short single-line hostname.
        # We deliberately do not mark arbitrary short text as proof.
        if re.search(
            r"(?:^|\n)[A-Za-z0-9][A-Za-z0-9._-]{1,63}(?:\r?\n|$)",
            text,
        ):
            indicators.append(
                "hostname-like-content"
            )

    return indicators


def detect_challenge(
    response,
    text,
    baseline,
):
    """
    Detect a likely upstream challenge/block without treating generic
    marker words as proof.

    Important v1.0.3 behavior:
      - captcha/recaptcha/turnstile text alone is NOT a challenge stop.
      - markers already present in the baseline are NOT a challenge stop.
      - HTTP 500 alone is NOT a challenge stop.
      - a strong status/header signal may establish a challenge/block.
      - all marker evidence is still preserved separately for forensics.
    """

    marker_list = find_markers(
        text,
        CHALLENGE_MARKERS,
    )

    baseline_text = ""
    if isinstance(baseline, dict):
        snapshot = baseline.get("snapshot") or {}
        baseline_text = snapshot.get("body_sample") or ""

    baseline_markers = find_markers(
        baseline_text,
        CHALLENGE_MARKERS,
    )

    new_markers = [
        item
        for item in marker_list
        if item not in baseline_markers
    ]

    status = safe_int(
        response.get("status"),
        0,
    )

    headers = response.get("headers") or {}
    normalized_headers = {
        str(key).lower(): str(value).lower()
        for key, value in headers.items()
    }

    # Strong provider/header-level challenge signal.
    header_challenge = (
        "cf-mitigated" in normalized_headers
        and "challenge"
        in normalized_headers["cf-mitigated"]
    )

    # A 403/429 combined with a challenge marker is materially stronger
    # than merely finding the word "captcha" in application HTML.
    status_challenge = (
        status in {403, 429}
        and bool(marker_list)
    )

    # A newly introduced challenge page marker is useful only when the
    # response is an explicit block/challenge status. This prevents an
    # application debug page containing "captcha" from stopping probes.
    new_marker_block = (
        status in {403, 429}
        and bool(new_markers)
    )

    detected = bool(
        header_challenge
        or status_challenge
        or new_marker_block
    )

    return {
        "detected": detected,
        "markers": marker_list,
        "baseline_markers": baseline_markers,
        "new_markers": new_markers,
        "header_signal": header_challenge,
        "status_signal": status_challenge,
    }


def assess_probe(
    candidate,
    payload,
    baseline,
    response,
    text,
    contexts,
):
    challenge = detect_challenge(
        response,
        text,
        baseline,
    )

    challenge_markers = challenge["markers"]
    challenge_detected = challenge["detected"]

    error_signatures = find_error_signatures(text)

    target_indicators = response_indicates_file_content(
        text,
        payload.get("target"),
    )

    payload_reflected = (
        payload["value"] in text
        or payload["value"].replace(
            "%2f",
            "/",
        ) in text.lower()
    )

    traversal_strings_reflected = bool(
        contexts
    )

    status_changed = (
        response["status"]
        != baseline["snapshot"]["status"]
    )

    body_changed = (
        response["body_sha256"]
        != baseline["snapshot"]["body_sha256"]
    )

    # Strong evidence is intentionally narrow.
    strong_file_read = bool(target_indicators)

    # A reflected payload, HTTP 500, changed response, generic path error,
    # or generic challenge marker is NOT enough.
    finding = False

    if strong_file_read:
        finding = True

    if challenge_detected:
        result = "requires_review"
    elif strong_file_read:
        result = "potential_finding"
    elif error_signatures or status_changed or body_changed:
        result = "requires_review"
    elif payload_reflected or traversal_strings_reflected:
        result = "not_confirmed"
    else:
        result = "not_confirmed"

    return {
        "result": result,
        "finding": finding,
        "requires_review": (
            result in {
                "requires_review",
                "potential_finding",
            }
        ),
        "payload_reflected": payload_reflected,
        "traversal_string_reflected": traversal_strings_reflected,
        "file_content_indicators": target_indicators,
        "challenge_detected": challenge_detected,
        "challenge_markers": challenge_markers,
        "baseline_challenge_markers": challenge[
            "baseline_markers"
        ],
        "new_challenge_markers": challenge[
            "new_markers"
        ],
        "challenge_header_signal": challenge[
            "header_signal"
        ],
        "challenge_status_signal": challenge[
            "status_signal"
        ],
        "error_signatures": error_signatures,
        "status_changed": status_changed,
        "body_changed": body_changed,
        "note": (
            "Traversal payload reflected or response changed; "
            "no confirmed file read."
            if not strong_file_read
            else
            "Potential file-content disclosure observed; "
            "manual verification required."
        ),
    }


def make_artifact(target):
    return {
        "schema_version": "1.0",
        "project_id": None,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": SCRIPT_NAME,
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": "07 Input Validation",
            "focus": (
                "Controlled Path Traversal assessment against "
                "discovered same-origin GET parameters and GET-form inputs."
            ),
            "status": "initialized",
        },
        "target": {
            "application": None,
            "hostname": target["hostname"],
            "url": target["url"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_id": target["scope_id"],
            "scope_reference": (
                "01-preparation/scope/scope.yaml"
            ),
            "authorized_ports": target[
                "authorized_ports"
            ],
        },
        "methodology": {
            "description": (
                "Same-origin crawl followed by bounded "
                "non-destructive Path Traversal probes."
            ),
            "authenticated_session_required": True,
            "session_source": (
                "05-authentication/session/session.yaml"
            ),
            "logout_cross_check": (
                "05-authentication/logout/logout.yaml"
            ),
            "session_secret_encryption": (
                "project Fernet key via scripts/secrets.py"
            ),
            "plaintext_session_persisted": False,
            "same_origin_only": True,
            "redirect_following": False,
            "get_only_probe_engine": True,
            "non_destructive_payloads_only": True,
            "post_forms": False,
            "file_upload": False,
            "file_write": False,
            "file_delete": False,
            "command_execution": False,
            "reverse_shell": False,
            "external_callbacks": False,
            "persistence": False,
            "credential_access": False,
            "automatic_finding": False,
            "reflection_is_finding": False,
            "http_500_is_finding": False,
            "forensic_detail": {
                "response_fingerprint": True,
                "response_timing": True,
                "payload_reflection": True,
                "traversal_context": True,
                "file_content_indicator": True,
                "challenge_detail": True,
                "challenge_requires_strong_signal": True,
                "challenge_marker_alone_is_not_stop": True,
                "error_response": True,
                "body_hash": True,
            },
        },
        "baseline": {
            "active_project": (
                ".runtime/active-project.yaml"
            ),
            "scope_source": (
                "01-preparation/scope/scope.yaml"
            ),
            "session_source": (
                "05-authentication/session/session.yaml"
            ),
            "logout_source": (
                "05-authentication/logout/logout.yaml"
            ),
            "encryption_key_source": (
                ".runtime/secrets/<PROJECT-ID>/encryption.key"
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
                "max_links": MAX_LINKS,
                "max_depth": MAX_DEPTH,
                "max_candidates": MAX_CANDIDATES,
                "max_params_per_url": MAX_PARAMS_PER_URL,
            },
            "payloads": [
                item["name"]
                for item in traversal_payloads()
            ],
            "delay_ms": REQUEST_DELAY_MS,
            "max_probes_per_param": len(
                traversal_payloads()
            ),
            "target_files": [
                item["path"]
                for item in LINUX_FILE_TARGETS
            ],
        },
        "source_status": {
            "active_project": "unknown",
            "scope": "unknown",
            "session": "unknown",
            "logout_cross_check": "unknown",
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
            "traversal_context_signals": 0,
            "file_content_signals": 0,
            "challenge_stops": 0,
            "error_response_probes": 0,
            "request_errors": 0,
            "findings": 0,
            "requires_review": 0,
            "candidates": [],
            "probes": [],
        },
        "notes": [
            (
                "Traversal reflection is not a finding."
            ),
            (
                "HTTP 500 is not automatically a finding."
            ),
            (
                "Actual file-content disclosure requires "
                "strong evidence and manual verification."
            ),
            (
                "Only non-destructive read-oriented probes "
                "are used."
            ),
            (
                "Sensitive files and credentials are intentionally "
                "excluded from automated probing."
            ),
            (
                "Raw forensic evidence is preserved."
            ),
            (
                "Generic challenge markers alone do not stop probing; "
                "strong status/header signals are required."
            ),
            (
                "HTTP 500 responses remain forensic evidence and do not "
                "stop the remaining traversal payloads."
            ),
        ],
        "generated_at": utc_now(),
    }


def cmd_version():
    print(
        f"BrebesKab-CSIRT-Tools Path Traversal "
        f"{SCRIPT_VERSION}"
    )
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("Schema    : 1.0")


def cmd_init():
    root, scope, session, logout = get_project_data()

    target = discover_target(scope)

    artifact = make_artifact(target)

    project_id = root.name

    artifact["project_id"] = project_id
    artifact["target"]["application"] = project_id

    artifact["source_status"] = {
        "active_project": "completed",
        "scope": "completed",
        "session": (
            "completed"
            if session
            else "missing"
        ),
        "logout_cross_check": (
            "completed"
            if logout
            else "missing"
        ),
    }

    path = root / ARTIFACT_FILE

    save_yaml(path, artifact)

    print(
        "[PASS] Path Traversal artifact siap."
    )
    print(
        f"[PASS] Checklist : "
        f"{CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(
        f"[PASS] Project   : {project_id}"
    )
    print(
        f"[PASS] File      : {path}"
    )


def cmd_crawl():
    root, scope, session_data, logout = (
        get_project_data()
    )

    target = discover_target(scope)

    artifact_path = root / ARTIFACT_FILE
    artifact = load_yaml(
        artifact_path,
        None,
    )

    if not artifact:
        raise RuntimeError(
            "Artifact belum ada. Jalankan init terlebih dahulu."
        )

    http = build_session(session_data)

    start_url = target["url"]

    queue = [
        (start_url, 0)
    ]

    visited = set()
    links = set()

    candidates = []
    form_candidates = []

    while queue:
        current, depth = queue.pop(0)

        current = normalize_url(current)

        if current in visited:
            continue

        if depth > MAX_DEPTH:
            continue

        if not same_origin(
            current,
            target["url"],
        ):
            continue

        visited.add(current)

        if (
            MAX_LINKS > 0
            and len(visited) > MAX_LINKS
        ):
            break

        try:
            started = time.perf_counter()

            response = http.get(
                current,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
            )

            elapsed = (
                time.perf_counter()
                - started
            ) * 1000

            links.add(current)

            content_type = response.headers.get(
                "Content-Type",
                "",
            ).lower()

            if "text/html" not in content_type:
                continue

            text = response.text or ""

            for link in extract_links(
                current,
                text,
            ):
                if same_origin(
                    link,
                    target["url"],
                ):
                    links.add(link)

                    if link not in visited:
                        queue.append(
                            (link, depth + 1)
                        )

                    candidates.extend(
                        candidate_from_url(
                            link,
                            source="link",
                        )
                    )

            forms = extract_get_forms(
                current,
                text,
            )

            for form in forms:
                if not same_origin(
                    form["url"],
                    target["url"],
                ):
                    continue

                for parameter in form[
                    "parameters"
                ]:
                    form_candidate = {
                        "source": "get_form",
                        "url": form["url"],
                        "parameter": parameter[
                            "name"
                        ],
                        "original_value": parameter.get(
                            "value",
                            "",
                        ),
                        "value_profile": classify_value(
                            parameter.get(
                                "value",
                                "",
                            )
                        ),
                        "method": "GET",
                    }

                    form_candidates.append(
                        form_candidate
                    )

        except requests.RequestException:
            continue

    all_candidates = (
        candidates + form_candidates
    )

    selected = select_candidates(
        all_candidates
    )

    artifact["checklist"]["status"] = "crawled"

    artifact["probe"]["crawl"][
        "max_links"
    ] = MAX_LINKS

    artifact["results"][
        "links_discovered"
    ] = len(links)

    artifact["results"][
        "same_origin_links"
    ] = len(links)

    artifact["results"][
        "query_parameter_candidates"
    ] = len(
        {
            (
                x["url"],
                x["parameter"],
            )
            for x in candidates
        }
    )

    artifact["results"][
        "get_form_candidates"
    ] = len(
        {
            (
                x["url"],
                x["parameter"],
            )
            for x in form_candidates
        }
    )

    artifact["results"]["candidates"] = selected

    save_yaml(
        artifact_path,
        artifact,
    )

    print(
        "[PASS] Path Traversal crawl selesai."
    )
    print(
        f"[PASS] Links     : {len(links)}"
    )
    print(
        "[PASS] Query candidates: "
        f"{artifact['results']['query_parameter_candidates']}"
    )
    print(
        "[PASS] GET forms : "
        f"{artifact['results']['get_form_candidates']}"
    )
    print(
        f"[PASS] Candidates: {len(selected)}"
    )
    print(
        f"[PASS] File      : {artifact_path}"
    )


def perform_baseline(
    http,
    candidate,
):
    started = time.perf_counter()

    try:
        response = http.get(
            candidate["url"],
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        return {
            "ok": True,
            "snapshot": request_snapshot(
                response,
                elapsed,
            ),
            "error": None,
        }

    except requests.RequestException as exc:
        return {
            "ok": False,
            "snapshot": None,
            "error": str(exc),
        }


def perform_probe(
    http,
    candidate,
    payload,
):
    probe_url = build_url_with_parameter(
        candidate["url"],
        candidate["parameter"],
        payload["value"],
    )

    started = time.perf_counter()

    try:
        response = http.get(
            probe_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        return {
            "ok": True,
            "url": probe_url,
            "snapshot": request_snapshot(
                response,
                elapsed,
            ),
            "body": response.text or "",
            "error": None,
        }

    except requests.RequestException as exc:
        return {
            "ok": False,
            "url": probe_url,
            "snapshot": None,
            "body": "",
            "error": str(exc),
        }


def cmd_analyze():
    root, scope, session_data, logout = (
        get_project_data()
    )

    target = discover_target(scope)

    artifact_path = root / ARTIFACT_FILE

    artifact = load_yaml(
        artifact_path,
        None,
    )

    if not artifact:
        raise RuntimeError(
            "Artifact belum ada."
        )

    candidates = artifact[
        "results"
    ].get(
        "candidates",
        [],
    )

    if not candidates:
        raise RuntimeError(
            "Tidak ada candidate. "
            "Jalankan crawl terlebih dahulu."
        )

    http = build_session(session_data)

    probes = []

    tested = set()

    total_request_errors = 0
    challenge_stops = 0
    findings = 0
    requires_review = 0
    reflected = 0
    traversal_contexts = 0
    file_content_signals = 0
    error_probes = 0
    baseline_requests = 0

    payloads = traversal_payloads()

    for candidate in candidates:

        candidate_key = (
            candidate["url"],
            candidate["parameter"],
        )

        baseline = perform_baseline(
            http,
            candidate,
        )

        if not baseline["ok"]:
            total_request_errors += 1

            probes.append(
                {
                    "candidate": candidate,
                    "baseline": {
                        "error": baseline["error"]
                    },
                    "probes": [],
                    "assessment": {
                        "result": "requires_review",
                        "finding": False,
                        "requires_review": True,
                        "note": (
                            "Baseline request failed."
                        ),
                    },
                }
            )

            tested.add(candidate_key)
            continue

        baseline_requests += 1

        candidate_record = {
            "candidate": candidate,
            "baseline": baseline,
            "probes": [],
            "assessment": None,
        }

        for payload in payloads:

            if REQUEST_DELAY_MS > 0:
                time.sleep(
                    REQUEST_DELAY_MS / 1000.0
                )

            result = perform_probe(
                http,
                candidate,
                payload,
            )

            if not result["ok"]:
                total_request_errors += 1

                candidate_record[
                    "probes"
                ].append(
                    {
                        "candidate": {
                            "source": candidate[
                                "source"
                            ],
                            "url": candidate[
                                "url"
                            ],
                            "parameter": candidate[
                                "parameter"
                            ],
                            "method": candidate[
                                "method"
                            ],
                        },
                        "payload": payload,
                        "request": {
                            "method": "GET",
                            "url": result["url"],
                            "parameter": candidate[
                                "parameter"
                            ],
                        },
                        "response": None,
                        "signals": {},
                        "forensic": {},
                        "error": result[
                            "error"
                        ],
                    }
                )

                continue

            response_snapshot = result[
                "snapshot"
            ]

            text = result["body"]

            contexts = extract_contexts(
                text,
                [
                    payload["value"],
                    payload["value"].replace(
                        "%2f",
                        "/",
                    ),
                    "../",
                    "..\\",
                    "/etc/hostname",
                ],
            )

            assessment = assess_probe(
                candidate,
                payload,
                baseline,
                response_snapshot,
                text,
                contexts,
            )

            if assessment[
                "payload_reflected"
            ]:
                reflected += 1

            if assessment[
                "traversal_string_reflected"
            ]:
                traversal_contexts += 1

            if assessment[
                "file_content_indicators"
            ]:
                file_content_signals += 1

            if response_snapshot[
                "status"
            ] >= 400:
                error_probes += 1

            if assessment[
                "challenge_detected"
            ]:
                challenge_stops += 1

            if assessment[
                "finding"
            ]:
                findings += 1

            if assessment[
                "requires_review"
            ]:
                requires_review += 1

            probe_record = {
                "candidate": {
                    "source": candidate[
                        "source"
                    ],
                    "url": candidate[
                        "url"
                    ],
                    "parameter": candidate[
                        "parameter"
                    ],
                    "method": candidate[
                        "method"
                    ],
                },
                "payload": payload,
                "request": {
                    "method": "GET",
                    "url": result["url"],
                    "parameter": candidate[
                        "parameter"
                    ],
                },
                "response": response_snapshot,
                "signals": {
                    "payload_reflected": assessment[
                        "payload_reflected"
                    ],
                    "traversal_string_reflected": assessment[
                        "traversal_string_reflected"
                    ],
                    "file_content_indicators": assessment[
                        "file_content_indicators"
                    ],
                    "challenge_detected": assessment[
                        "challenge_detected"
                    ],
                    "challenge_markers": assessment[
                        "challenge_markers"
                    ],
                    "baseline_challenge_markers": assessment[
                        "baseline_challenge_markers"
                    ],
                    "new_challenge_markers": assessment[
                        "new_challenge_markers"
                    ],
                    "challenge_header_signal": assessment[
                        "challenge_header_signal"
                    ],
                    "challenge_status_signal": assessment[
                        "challenge_status_signal"
                    ],
                    "error_signatures": assessment[
                        "error_signatures"
                    ],
                    "status_changed": assessment[
                        "status_changed"
                    ],
                    "body_changed": assessment[
                        "body_changed"
                    ],
                },
                "forensic": {
                    "contexts": contexts,
                    "body_length_delta": (
                        response_snapshot[
                            "content_length"
                        ]
                        - baseline[
                            "snapshot"
                        ][
                            "content_length"
                        ]
                    ),
                    "body_sha256": response_snapshot[
                        "body_sha256"
                    ],
                    "baseline_body_sha256": baseline[
                        "snapshot"
                    ][
                        "body_sha256"
                    ],
                    "client_elapsed_ms": response_snapshot[
                        "elapsed_ms"
                    ],
                },
                "error": None,
            }

            candidate_record[
                "probes"
            ].append(
                probe_record
            )

            # Stop additional probes only for a clearly detected
            # upstream challenge/block. Generic marker words and HTTP 500
            # responses deliberately do not stop payload coverage.
            if assessment[
                "challenge_detected"
            ]:
                break

        # Candidate-level assessment.
        candidate_results = (
            candidate_record["probes"]
        )

        candidate_finding = any(
            item.get("signals", {}).get(
                "file_content_indicators"
            )
            for item in candidate_results
        )

        candidate_challenge = any(
            item.get("signals", {}).get(
                "challenge_detected"
            )
            for item in candidate_results
        )

        candidate_errors = any(
            item.get("signals", {}).get(
                "error_signatures"
            )
            for item in candidate_results
        )

        candidate_reflection = any(
            item.get("signals", {}).get(
                "payload_reflected"
            )
            for item in candidate_results
        )

        if candidate_finding:
            candidate_result = (
                "potential_finding"
            )
        elif candidate_challenge:
            candidate_result = (
                "requires_review"
            )
        elif candidate_errors:
            candidate_result = (
                "requires_review"
            )
        elif candidate_reflection:
            candidate_result = (
                "not_confirmed"
            )
        else:
            candidate_result = (
                "not_confirmed"
            )

        candidate_record[
            "assessment"
        ] = {
            "result": candidate_result,
            "finding": candidate_finding,
            "requires_review": (
                candidate_result
                in {
                    "potential_finding",
                    "requires_review",
                }
            ),
            "payload_reflected": candidate_reflection,
            "challenge_detected": candidate_challenge,
            "error_signals": candidate_errors,
            "note": (
                "Potential file-content disclosure "
                "requires manual verification."
                if candidate_finding
                else
                "No confirmed Path Traversal. "
                "Reflection/errors/challenge signals "
                "are preserved as forensic evidence."
            ),
        }

        probes.append(
            candidate_record
        )

        tested.add(candidate_key)

    artifact[
        "checklist"
    ]["status"] = "completed"

    artifact[
        "results"
    ]["tested_parameters"] = len(tested)

    artifact[
        "results"
    ]["probes_sent"] = sum(
        len(item["probes"])
        for item in probes
    )

    artifact[
        "results"
    ]["baseline_requests"] = baseline_requests

    artifact[
        "results"
    ]["reflected_payload_signals"] = reflected

    artifact[
        "results"
    ]["traversal_context_signals"] = traversal_contexts

    artifact[
        "results"
    ]["file_content_signals"] = file_content_signals

    artifact[
        "results"
    ]["challenge_stops"] = challenge_stops

    artifact[
        "results"
    ]["error_response_probes"] = error_probes

    artifact[
        "results"
    ]["request_errors"] = total_request_errors

    artifact[
        "results"
    ]["findings"] = findings

    artifact[
        "results"
    ]["requires_review"] = requires_review

    artifact[
        "results"
    ]["probes"] = probes

    # Do not place huge probe data inside YAML.
    artifact["results"]["probes"] = []

    save_yaml(
        artifact_path,
        artifact,
    )

    evidence = {
        "schema_version": "1.0",
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": SCRIPT_NAME,
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
        },
        "project_id": root.name,
        "target": target,
        "generated_at": utc_now(),
        "methodology": artifact[
            "methodology"
        ],
        "results": {
            "tested_parameters": len(tested),
            "probes_sent": sum(
                len(item["probes"])
                for item in probes
            ),
            "baseline_requests": baseline_requests,
            "reflected_payload_signals": reflected,
            "traversal_context_signals": traversal_contexts,
            "file_content_signals": file_content_signals,
            "challenge_stops": challenge_stops,
            "error_response_probes": error_probes,
            "request_errors": total_request_errors,
            "findings": findings,
            "requires_review": requires_review,
        },
        "candidates": candidates,
        "probe_records": probes,
        "notes": [
            (
                "Reflection is not proof of Path Traversal."
            ),
            (
                "HTTP 500 is not proof of Path Traversal."
            ),
            (
                "File-content indicators require manual verification."
            ),
            (
                "Sensitive files are intentionally excluded."
            ),
            (
                "Generic challenge markers are preserved but are not "
                "treated as challenge stops without stronger evidence."
            ),
            (
                "HTTP 500 responses do not stop traversal payload coverage."
            ),
        ],
    }

    evidence_path = root / EVIDENCE_FILE

    save_json(
        evidence_path,
        evidence,
    )

    print(
        "[PASS] Path Traversal analyze selesai."
    )
    print(
        f"[PASS] Candidates: {len(candidates)}"
    )
    print(
        f"[PASS] Tested    : {len(tested)}"
    )
    print(
        f"[PASS] Probes    : {sum(len(x['probes']) for x in probes)}"
    )
    print(
        f"[PASS] Reflected : {reflected}"
    )
    print(
        f"[PASS] File read : {file_content_signals}"
    )
    print(
        f"[PASS] Challenge : {challenge_stops}"
    )
    print(
        f"[PASS] HTTP error: {error_probes}"
    )
    print(
        f"[PASS] Findings  : {findings}"
    )
    print(
        f"[PASS] Review    : {requires_review}"
    )
    print(
        f"[PASS] Evidence  : {evidence_path}"
    )


def cmd_show():
    root = project_root()

    path = root / ARTIFACT_FILE

    if not path.exists():
        raise RuntimeError(
            "Artifact belum ditemukan."
        )

    print(read_text(path))


def cmd_status():
    root = project_root()

    artifact_path = root / ARTIFACT_FILE
    evidence_path = root / EVIDENCE_FILE

    print(
        f"Script   : {SCRIPT_NAME}"
    )
    print(
        f"Version  : {SCRIPT_VERSION}"
    )
    print(
        f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(
        f"Artifact : "
        f"{'OK' if artifact_path.exists() else 'MISSING'}"
    )
    print(
        f"Evidence : "
        f"{'OK' if evidence_path.exists() else 'MISSING'}"
    )

    if artifact_path.exists():
        artifact = load_yaml(
            artifact_path,
            {},
        )

        results = artifact.get(
            "results",
            {},
        )

        print(
            f"Candidates: "
            f"{len(results.get('candidates', []))}"
        )
        print(
            f"Tested   : "
            f"{results.get('tested_parameters', 0)}"
        )
        print(
            f"Probes   : "
            f"{results.get('probes_sent', 0)}"
        )
        print(
            f"Findings : "
            f"{results.get('findings', 0)}"
        )
        print(
            f"Review   : "
            f"{results.get('requires_review', 0)}"
        )


def validate_utf8_no_bom(path: Path):
    raw = path.read_bytes()

    if raw.startswith(b"\xef\xbb\xbf"):
        return False

    try:
        raw.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def cmd_verify():
    root = project_root()

    artifact_path = root / ARTIFACT_FILE
    evidence_path = root / EVIDENCE_FILE

    failures = []

    if not artifact_path.exists():
        failures.append(
            f"artifact tidak ditemukan: {artifact_path}"
        )

    if not evidence_path.exists():
        failures.append(
            f"evidence tidak ditemukan: {evidence_path}"
        )

    if failures:
        print(
            "[FAIL] Path Traversal tidak memenuhi validasi."
        )

        for item in failures:
            print(f"[FAIL] {item}")

        return 1

    artifact = load_yaml(
        artifact_path,
        {},
    )

    evidence = load_yaml(
        evidence_path,
        None,
    )

    if evidence is not None:
        # JSON can technically parse as YAML.
        pass

    if artifact.get("schema_version") != "1.0":
        failures.append(
            "schema_version bukan 1.0"
        )

    tool = artifact.get("tool", {})

    if tool.get("script") != SCRIPT_NAME:
        failures.append(
            "script tidak sesuai"
        )

    if tool.get("version") != SCRIPT_VERSION:
        failures.append(
            "version tidak sesuai"
        )

    checklist = artifact.get(
        "checklist",
        {},
    )

    if checklist.get("id") != CHECKLIST_ID:
        failures.append(
            "checklist ID tidak sesuai"
        )

    if checklist.get("name") != CHECKLIST_NAME:
        failures.append(
            "checklist name tidak sesuai"
        )

    results = artifact.get(
        "results",
        {},
    )

    candidates = results.get(
        "candidates",
        [],
    )

    tested = safe_int(
        results.get(
            "tested_parameters",
            0,
        )
    )

    probes = safe_int(
        results.get(
            "probes_sent",
            0,
        )
    )

    if tested != len(candidates):
        failures.append(
            "tested_parameters tidak sama "
            "dengan jumlah candidates"
        )

    if probes <= 0:
        failures.append(
            "probes_sent harus lebih besar dari 0"
        )

    methodology = artifact.get(
        "methodology",
        {},
    )

    required_false = [
        "post_forms",
        "file_upload",
        "file_write",
        "file_delete",
        "command_execution",
        "reverse_shell",
        "external_callbacks",
        "persistence",
        "credential_access",
    ]

    for field in required_false:
        if methodology.get(field) is not False:
            failures.append(
                f"{field} harus false"
            )

    if methodology.get(
        "reflection_is_finding"
    ) is not False:
        failures.append(
            "reflection_is_finding harus false"
        )

    if methodology.get(
        "http_500_is_finding"
    ) is not False:
        failures.append(
            "http_500_is_finding harus false"
        )

    if not validate_utf8_no_bom(
        artifact_path
    ):
        failures.append(
            "artifact bukan UTF-8 tanpa BOM"
        )

    if not validate_utf8_no_bom(
        evidence_path
    ):
        failures.append(
            "evidence bukan UTF-8 tanpa BOM"
        )

    # Validate evidence as JSON.
    try:
        with evidence_path.open(
            "r",
            encoding="utf-8",
        ) as fh:
            evidence_json = json.load(fh)
    except Exception as exc:
        failures.append(
            f"evidence JSON tidak valid: {exc}"
        )
        evidence_json = {}

    evidence_results = evidence_json.get(
        "results",
        {},
    )

    if safe_int(
        evidence_results.get(
            "tested_parameters",
            0,
        )
    ) != tested:
        failures.append(
            "evidence tested_parameters "
            "tidak sama dengan artifact"
        )

    if safe_int(
        evidence_results.get(
            "probes_sent",
            0,
        )
    ) != probes:
        failures.append(
            "evidence probes_sent "
            "tidak sama dengan artifact"
        )

    # Validate every payload is non-destructive.
    for record in evidence_json.get(
        "probe_records",
        [],
    ):
        for probe in record.get(
            "probes",
            [],
        ):
            payload = probe.get(
                "payload",
                {},
            )

            if payload.get(
                "destructive"
            ) is not False:
                failures.append(
                    "payload destructive "
                    "bukan false"
                )

            payload_value = str(
                payload.get(
                    "value",
                    "",
                )
            ).lower()

            forbidden = [
                "/etc/shadow",
                ".env",
                "id_rsa",
                "authorized_keys",
                "database.php",
                "config.php",
                "password",
                "secret",
            ]

            for item in forbidden:
                if item in payload_value:
                    failures.append(
                        "payload mengandung "
                        f"target sensitif: {item}"
                    )

    if failures:
        print(
            "[FAIL] Path Traversal tidak memenuhi validasi."
        )

        for item in failures:
            print(f"[FAIL] {item}")

        return 1

    print(
        "[PASS] Path Traversal memenuhi validasi."
    )
    print(
        f"[PASS] Checklist : "
        f"{CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(
        f"[PASS] Project   : "
        f"{artifact.get('project_id')}"
    )
    print(
        f"[PASS] File      : {artifact_path}"
    )
    print(
        f"[PASS] Candidates: {len(candidates)}"
    )
    print(
        f"[PASS] Probes    : {probes}"
    )
    print(
        "[PASS] Encoding  : UTF-8 tanpa BOM"
    )

    return 0


def main():
    parser = argparse.ArgumentParser(
        description=(
            "BrebesKab-CSIRT-Tools "
            "Path Traversal assessment"
        )
    )

    parser.add_argument(
        "command",
        choices=[
            "version",
            "init",
            "crawl",
            "analyze",
            "show",
            "status",
            "verify",
        ],
    )

    args = parser.parse_args()

    try:
        if args.command == "version":
            cmd_version()
            return 0

        if args.command == "init":
            cmd_init()
            return 0

        if args.command == "crawl":
            cmd_crawl()
            return 0

        if args.command == "analyze":
            cmd_analyze()
            return 0

        if args.command == "show":
            cmd_show()
            return 0

        if args.command == "status":
            cmd_status()
            return 0

        if args.command == "verify":
            return cmd_verify()

    except KeyboardInterrupt:
        print(
            "\n[WARN] Proses dihentikan oleh pengguna."
        )
        return 130

    except Exception as exc:
        print(
            f"[FAIL] {exc}"
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())