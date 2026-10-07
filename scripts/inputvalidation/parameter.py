#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
HTTP Parameter Pollution (HPP)

Checklist : 7-006
Version   : 1.0.0
Schema    : 1.0

Purpose:
    Bounded, authenticated, same-origin testing for duplicate HTTP parameters.
    This script intentionally tests parameter parsing behavior only.

Safety boundary:
    - GET only
    - Same-origin only
    - Uses the existing authenticated session
    - Non-destructive probes
    - No SQLi, XSS, command injection, path traversal, template injection,
      file access, upload, callback, reverse shell, or credential harvesting
    - Duplicate acceptance, response changes, first/last-wins behavior,
      and HTTP errors are NOT automatic findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import requests
import yaml


SCRIPT_NAME = "BrebesKab-CSIRT-Tools HTTP Parameter Pollution"
SCRIPT_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "7-006"
CHECKLIST_NAME = "HTTP Parameter Pollution"

PROJECT_ID = "PENTEST-2026-002"
SCOPE_ID = "IN-001"

ROOT = Path(__file__).resolve().parents[2]
PROJECT_DIR = ROOT / "projects" / PROJECT_ID
SCOPE_FILE = PROJECT_DIR / "01-preparation" / "scope" / "scope.yaml"
SESSION_FILE = PROJECT_DIR / "05-authentication" / "session" / "session.yaml"

ARTIFACT_DIR = PROJECT_DIR / "07-input-validation" / "parameter"
ARTIFACT_FILE = ARTIFACT_DIR / "parameter.yaml"
EVIDENCE_DIR = ARTIFACT_DIR / "evidence"
EVIDENCE_FILE = EVIDENCE_DIR / "parameter-probes.json"

MAX_LINKS = 0
MAX_DEPTH = 5
MAX_CANDIDATES = 200
MAX_PARAMS_PER_URL = 5
REQUEST_TIMEOUT = 20
REQUEST_DELAY_MS = 150
MAX_BODY_SAMPLE = 12000
MAX_CONTEXTS = 10
MAX_PROBES_PER_PARAMETER = 3

# Parameters whose names commonly indicate security/session material.
# They remain in evidence, but are never automatic HPP findings.
PROTECTED_PARAMETER_TOKENS = (
    "csrf",
    "token",
    "nonce",
    "session",
    "cookie",
    "signature",
    "sig",
    "hash",
    "auth",
)

# Candidate scoring is only prioritization; it is never a finding signal.
HIGH_PRIORITY_NAMES = {
    "id",
    "idx",
    "page",
    "item",
    "file",
    "path",
    "url",
    "redirect",
    "target",
    "action",
}
NORMAL_PRIORITY_NAMES = {
    "q",
    "query",
    "keyword",
    "search",
    "category",
    "sort",
    "order",
    "filter",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def die(message: str, code: int = 1) -> None:
    print(f"[FAIL] {message}")
    raise SystemExit(code)


def ensure_dirs() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def read_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        die(f"File tidak ditemukan: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        die(f"Gagal membaca YAML {path}: {exc}")
    if not isinstance(data, dict):
        die(f"Format YAML tidak valid: {path}")
    return data


def write_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )
    path.write_text(text, encoding="utf-8", newline="\n")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8", newline="\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def body_sample(body: str) -> str:
    if not body:
        return ""
    return body[:MAX_BODY_SAMPLE]


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.params,
            parsed.query,
            "",
        )
    )


def host_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def same_origin(base_url: str, target_url: str) -> bool:
    a = urlparse(base_url)
    b = urlparse(target_url)
    return (
        a.scheme.lower() == b.scheme.lower()
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and (a.port or (443 if a.scheme.lower() == "https" else 80))
        == (b.port or (443 if b.scheme.lower() == "https" else 80))
    )


def discover_scope() -> Dict[str, Any]:
    data = read_yaml(SCOPE_FILE)
    section = data.get("scope") if isinstance(data.get("scope"), dict) else data
    in_scope = section.get("in_scope", []) if isinstance(section, dict) else []

    if not isinstance(in_scope, list):
        die("scope.yaml: in_scope tidak ditemukan.")

    for item in in_scope:
        if not isinstance(item, dict):
            continue
        if str(item.get("scope_id", "")) != SCOPE_ID:
            continue

        value = item.get("value") or item.get("hostname") or item.get("url")
        scope_type = str(item.get("type", "")).lower()
        ports = item.get("ports", [80, 443])

        if not value:
            die(f"Scope {SCOPE_ID} tidak memiliki value/hostname/url.")

        if scope_type not in {"domain", "hostname", "url"}:
            die(f"Scope {SCOPE_ID} memiliki type tidak didukung: {scope_type}")

        try:
            ports = [int(p) for p in ports]
        except Exception:
            die(f"Scope {SCOPE_ID} memiliki ports tidak valid.")

        if not ({80, 443} & set(ports)):
            die(f"Scope {SCOPE_ID} tidak mengizinkan port 80/443.")

        if scope_type == "url":
            url = str(value).rstrip("/")
        else:
            url = f"https://{str(value).strip().rstrip('/')}"

        parsed = urlparse(url)
        if not parsed.hostname:
            die(f"Scope {SCOPE_ID} menghasilkan URL tidak valid: {url}")

        return {
            "scope_id": SCOPE_ID,
            "hostname": parsed.hostname,
            "url": url,
            "ports": ports,
        }

    die(f"Target hostname/URL tidak ditemukan di scope.yaml untuk {SCOPE_ID}")
    return {}


def load_session() -> requests.Session:
    data = read_yaml(SESSION_FILE)

    session_data = data.get("session") if isinstance(data.get("session"), dict) else data
    session = requests.Session()

    headers = {}
    cookies = {}

    if isinstance(session_data, dict):
        raw_headers = session_data.get("headers", {})
        raw_cookies = session_data.get("cookies", {})

        if isinstance(raw_headers, dict):
            headers.update({str(k): str(v) for k, v in raw_headers.items()})

        if isinstance(raw_cookies, dict):
            cookies.update({str(k): str(v) for k, v in raw_cookies.items()})

    if headers:
        session.headers.update(headers)
    if cookies:
        session.cookies.update(cookies)

    session.headers.setdefault("User-Agent", "BrebesKab-CSIRT-Tools/7-006")
    session.headers.setdefault("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")

    return session


def parameter_score(name: str) -> int:
    lower = name.lower()
    if lower in HIGH_PRIORITY_NAMES:
        return 20
    if lower in NORMAL_PRIORITY_NAMES:
        return 16
    if any(token in lower for token in PROTECTED_PARAMETER_TOKENS):
        return 20
    return 10


def protected_parameter(name: str) -> bool:
    lower = name.lower()
    return any(token in lower for token in PROTECTED_PARAMETER_TOKENS)


def extract_links(base_url: str, html: str) -> List[str]:
    links: List[str] = []
    # Deliberately simple HTML URL extraction; this is discovery, not a browser.
    patterns = [
        r"""href\s*=\s*["']([^"']+)["']""",
        r"""action\s*=\s*["']([^"']+)["']""",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html or "", flags=re.I):
            raw = match.group(1).strip()
            if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            absolute = urljoin(base_url, raw)
            if same_origin(base_url, absolute):
                links.append(normalize_url(absolute))
    return links


def extract_get_forms(base_url: str, html: str) -> List[Dict[str, Any]]:
    forms: List[Dict[str, Any]] = []

    for match in re.finditer(
        r"<form\b([^>]*)>(.*?)</form\s*>",
        html or "",
        flags=re.I | re.S,
    ):
        attrs = match.group(1)
        body = match.group(2)

        method_match = re.search(r"""\bmethod\s*=\s*["']?([^"'\s>]+)""", attrs, flags=re.I)
        method = (method_match.group(1) if method_match else "GET").upper()
        if method != "GET":
            continue

        action_match = re.search(r"""\baction\s*=\s*["']([^"']*)["']""", attrs, flags=re.I)
        action = urljoin(base_url, action_match.group(1) if action_match else base_url)
        action = normalize_url(action)

        if not same_origin(base_url, action):
            continue

        params: List[Dict[str, str]] = []
        for input_match in re.finditer(
            r"""<(?:input|select|textarea)\b([^>]*)>""",
            body,
            flags=re.I | re.S,
        ):
            attrs2 = input_match.group(1)
            name_match = re.search(r"""\bname\s*=\s*["']([^"']+)["']""", attrs2, flags=re.I)
            if not name_match:
                continue

            name = name_match.group(1)
            value_match = re.search(r"""\bvalue\s*=\s*["']([^"']*)["']""", attrs2, flags=re.I)
            value = value_match.group(1) if value_match else ""
            params.append({"name": name, "value": value})

        if params:
            forms.append({
                "url": action,
                "method": "GET",
                "params": params,
            })

    return forms


def request_snapshot(
    session: requests.Session,
    method: str,
    url: str,
    parameter: Optional[str] = None,
    value: Optional[str] = None,
) -> Dict[str, Any]:
    started = time.perf_counter()
    request_error = None
    response = None

    try:
        response = session.request(
            method=method,
            url=url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        request_error = str(exc)

    elapsed = round((time.perf_counter() - started) * 1000, 2)

    if request_error:
        return {
            "request": {
                "method": method,
                "url": url,
                "parameter": parameter,
                "value": value,
            },
            "response": None,
            "elapsed_ms": elapsed,
            "request_error": request_error,
        }

    body = response.text or ""
    headers = {str(k).lower(): str(v) for k, v in response.headers.items()}

    return {
        "request": {
            "method": method,
            "url": url,
            "parameter": parameter,
            "value": value,
        },
        "response": {
            "status": response.status_code,
            "reason": response.reason,
            "url": response.url,
            "content_type": headers.get("content-type", ""),
            "body_length": len(body),
            "body_hash": sha256_text(body),
            "body_sample": body_sample(body),
            "headers": headers,
        },
        "elapsed_ms": elapsed,
        "request_error": None,
    }


def build_query_url(url: str, pairs: List[Tuple[str, str]]) -> str:
    parsed = urlparse(url)
    query = urlencode(pairs, doseq=True)
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


def query_pairs(url: str) -> List[Tuple[str, str]]:
    return parse_qsl(
        urlparse(url).query,
        keep_blank_values=True,
    )


def replace_parameter(url: str, parameter: str, value: str) -> str:
    pairs = query_pairs(url)
    found = False
    out: List[Tuple[str, str]] = []

    for key, old_value in pairs:
        if key == parameter and not found:
            out.append((key, value))
            found = True
        else:
            out.append((key, old_value))

    if not found:
        out.append((parameter, value))

    return build_query_url(url, out)


def duplicate_parameter_url(
    url: str,
    parameter: str,
    first_value: str,
    second_value: str,
) -> str:
    pairs = query_pairs(url)
    out: List[Tuple[str, str]] = []
    inserted = False

    for key, value in pairs:
        if key == parameter and not inserted:
            out.append((key, first_value))
            out.append((key, second_value))
            inserted = True
        elif key != parameter:
            out.append((key, value))

    if not inserted:
        out.extend([
            (parameter, first_value),
            (parameter, second_value),
        ])

    return build_query_url(url, out)


def candidate_key(candidate: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        normalize_url(candidate["url"]),
        candidate["method"].upper(),
        candidate["parameter"],
    )


def crawl_application(
    session: requests.Session,
    scope: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    start_url = scope["url"]
    queue: List[Tuple[str, int]] = [(start_url, 0)]
    visited: set[str] = set()
    links: List[str] = []
    candidates: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    get_forms: List[Dict[str, Any]] = []

    while queue:
        current, depth = queue.pop(0)
        current = normalize_url(current)

        if current in visited:
            continue
        if depth > MAX_DEPTH:
            continue
        if not same_origin(start_url, current):
            continue

        visited.add(current)

        snapshot = request_snapshot(session, "GET", current)
        if snapshot.get("request_error"):
            continue

        response = snapshot.get("response") or {}
        body = response.get("body_sample", "")

        links.append(current)

        # Query candidates are discovered only after same-origin validation.
        pairs = query_pairs(current)
        seen_params = set()
        for name, value in pairs:
            if name in seen_params:
                continue
            seen_params.add(name)
            candidate = {
                "url": current,
                "method": "GET",
                "parameter": name,
                "original_value": value,
                "source": "query",
                "score": parameter_score(name),
                "depth": depth,
            }
            candidates[candidate_key(candidate)] = candidate

        forms = extract_get_forms(current, body)
        for form in forms:
            get_forms.append(form)
            for item in form["params"][:MAX_PARAMS_PER_URL]:
                name = item["name"]
                candidate = {
                    "url": form["url"],
                    "method": "GET",
                    "parameter": name,
                    "original_value": item.get("value", ""),
                    "source": "get_form",
                    "score": parameter_score(name),
                    "depth": depth,
                }
                candidates[candidate_key(candidate)] = candidate

        if depth < MAX_DEPTH:
            for link in extract_links(current, body):
                if link not in visited:
                    queue.append((link, depth + 1))

        if MAX_LINKS and len(visited) >= MAX_LINKS:
            break

    ordered = sorted(
        candidates.values(),
        key=lambda x: (-int(x["score"]), int(x["depth"]), x["url"], x["parameter"]),
    )[:MAX_CANDIDATES]

    return ordered, {
        "links": len(links),
        "query_candidates": sum(1 for c in ordered if c["source"] == "query"),
        "get_forms": len(get_forms),
        "get_form_records": get_forms,
    }


def semantic_change_indicators(
    baseline: Dict[str, Any],
    probe: Dict[str, Any],
) -> Dict[str, Any]:
    b = baseline.get("response") or {}
    p = probe.get("response") or {}

    if not b or not p:
        return {
            "status_changed": False,
            "body_changed": False,
            "content_type_changed": False,
            "response_url_changed": False,
            "http_error": bool(p and int(p.get("status", 0)) >= 400),
        }

    return {
        "status_changed": b.get("status") != p.get("status"),
        "body_changed": b.get("body_hash") != p.get("body_hash"),
        "content_type_changed": b.get("content_type") != p.get("content_type"),
        "response_url_changed": b.get("url") != p.get("url"),
        "http_error": int(p.get("status", 0)) >= 400,
    }


def classify_duplicate_behavior(
    same: Dict[str, Any],
    first_second: Dict[str, Any],
    second_first: Dict[str, Any],
    baseline: Dict[str, Any],
) -> Dict[str, Any]:
    same_r = same.get("response") or {}
    fs_r = first_second.get("response") or {}
    sf_r = second_first.get("response") or {}
    base_r = baseline.get("response") or {}

    if not same_r or not fs_r or not sf_r or not base_r:
        return {
            "behavior": "request_error_or_no_response",
            "duplicate_accepted": False,
            "order_sensitive": False,
            "first_wins": False,
            "last_wins": False,
            "combined_or_other": False,
            "requires_review": True,
            "reason": "One or more probe responses unavailable.",
        }

    same_status = same_r.get("status") == base_r.get("status")
    fs_status = fs_r.get("status")
    sf_status = sf_r.get("status")

    fs_hash = fs_r.get("body_hash")
    sf_hash = sf_r.get("body_hash")

    same_body = same_r.get("body_hash") == base_r.get("body_hash")
    order_sensitive = (
        fs_status != sf_status
        or fs_hash != sf_hash
    )

    # We can infer a likely parser behavior only when the two different-value
    # orders produce different responses. This remains behavioral evidence,
    # never an automatic security finding.
    if order_sensitive:
        behavior = "order_sensitive"
    elif same_body and fs_hash == sf_hash:
        behavior = "duplicate_normalized_or_ignored"
    else:
        behavior = "duplicate_accepted_same_observable_result"

    return {
        "behavior": behavior,
        "duplicate_accepted": True,
        "order_sensitive": order_sensitive,
        "first_wins": False,
        "last_wins": False,
        "combined_or_other": not order_sensitive and not same_body,
        "requires_review": order_sensitive,
        "reason": (
            "Ordering changes the observable response; application parsing "
            "semantics require manual verification."
            if order_sensitive
            else "Duplicate handling observed without demonstrated security impact."
        ),
    }


def analyze_candidate(
    session: requests.Session,
    candidate: Dict[str, Any],
) -> Dict[str, Any]:
    parameter = candidate["parameter"]
    original = str(candidate.get("original_value", ""))

    baseline_url = replace_parameter(candidate["url"], parameter, original)
    baseline = request_snapshot(
        session,
        "GET",
        baseline_url,
        parameter=parameter,
        value=original,
    )

    # Probe 1: same value duplicated.
    same_url = duplicate_parameter_url(
        candidate["url"],
        parameter,
        original,
        original,
    )
    same = request_snapshot(
        session,
        "GET",
        same_url,
        parameter=parameter,
        value=f"{original}|{original}",
    )
    time.sleep(REQUEST_DELAY_MS / 1000)

    # Probe 2: first -> second.
    first_value = original if original else "BREBES_HPP_A"
    second_value = "BREBES_HPP_B"

    first_second_url = duplicate_parameter_url(
        candidate["url"],
        parameter,
        first_value,
        second_value,
    )
    first_second = request_snapshot(
        session,
        "GET",
        first_second_url,
        parameter=parameter,
        value=f"{first_value}|{second_value}",
    )
    time.sleep(REQUEST_DELAY_MS / 1000)

    # Probe 3: reverse order.
    second_first_url = duplicate_parameter_url(
        candidate["url"],
        parameter,
        second_value,
        first_value,
    )
    second_first = request_snapshot(
        session,
        "GET",
        second_first_url,
        parameter=parameter,
        value=f"{second_value}|{first_value}",
    )

    classification = classify_duplicate_behavior(
        same,
        first_second,
        second_first,
        baseline,
    )

    probes = [
        {
            "probe_id": "duplicate-same",
            "variant": "duplicate_same_value",
            "values": [original, original],
            "request": same["request"],
            "response": same.get("response"),
            "elapsed_ms": same["elapsed_ms"],
            "request_error": same.get("request_error"),
            "signals": semantic_change_indicators(baseline, same),
        },
        {
            "probe_id": "duplicate-first-second",
            "variant": "duplicate_first_second",
            "values": [first_value, second_value],
            "request": first_second["request"],
            "response": first_second.get("response"),
            "elapsed_ms": first_second["elapsed_ms"],
            "request_error": first_second.get("request_error"),
            "signals": semantic_change_indicators(baseline, first_second),
        },
        {
            "probe_id": "duplicate-second-first",
            "variant": "duplicate_second_first",
            "values": [second_value, first_value],
            "request": second_first["request"],
            "response": second_first.get("response"),
            "elapsed_ms": second_first["elapsed_ms"],
            "request_error": second_first.get("request_error"),
            "signals": semantic_change_indicators(baseline, second_first),
        },
    ]

    finding = False

    # Deliberately conservative: no automatic HPP finding is created from
    # parsing behavior alone. Manual review remains available.
    requires_review = bool(
        classification["requires_review"]
        or any(p["signals"]["body_changed"] for p in probes)
        or any(p["signals"]["status_changed"] for p in probes)
        or any(p["signals"]["http_error"] for p in probes)
    )

    protected = protected_parameter(parameter)

    return {
        "candidate": deepcopy(candidate),
        "baseline": baseline,
        "probes": probes,
        "analysis": {
            **classification,
            "protected_parameter_context": protected,
            "automatic_security_impact": False,
            "finding": finding,
            "requires_review": requires_review,
            "finding_reason": None,
            "manual_review_reason": (
                "Security impact is not demonstrated automatically. "
                "Review duplicate-parameter parsing only if the behavior is "
                "relevant to an application security control."
                if requires_review
                else None
            ),
        },
    }


def methodology() -> Dict[str, Any]:
    return {
        "description": (
            "Same-origin crawl and bounded non-destructive GET probes for "
            "HTTP Parameter Pollution using the existing authenticated session."
        ),
        "authentication": "Authenticated session from session.yaml",
        "same_origin_only": True,
        "redirect_following": False,
        "http_methods": ["GET"],
        "automatic_finding": True,
        "duplicate_parameter_is_finding": False,
        "response_change_is_finding": False,
        "http_500_is_finding": False,
        "http_error_is_finding": False,
        "first_wins_is_finding": False,
        "last_wins_is_finding": False,
        "order_sensitivity_requires_manual_review": True,
        "security_impact_required_for_finding": True,
        "protected_parameter_context_is_not_automatic_finding": True,
        "non_destructive": True,
        "forensic_evidence_preserved": True,
        "no_sql_injection": True,
        "no_xss": True,
        "no_command_injection": True,
        "no_path_traversal": True,
        "no_expression_template_injection": True,
        "no_file_read_write_delete": True,
        "no_upload": True,
        "no_reverse_shell": True,
        "no_external_callbacks": True,
        "no_credential_harvesting": True,
    }


def payload_policy() -> Dict[str, Any]:
    return {
        "probe_type": "duplicate_parameter",
        "variants": [
            {
                "id": "duplicate-same",
                "variant": "duplicate_same_value",
                "purpose": "Determine whether identical duplicate parameters are accepted or normalized.",
            },
            {
                "id": "duplicate-first-second",
                "variant": "duplicate_first_second",
                "purpose": "Compare parser behavior when the first value differs from the second.",
            },
            {
                "id": "duplicate-second-first",
                "variant": "duplicate_second_first",
                "purpose": "Compare parser behavior under reversed duplicate ordering.",
            },
        ],
        "values": {
            "empty_original": "BREBES_HPP_A",
            "alternate": "BREBES_HPP_B",
        },
        "excluded_payload_classes": [
            "SQL injection",
            "XSS",
            "Command injection",
            "Path traversal",
            "Expression/template injection",
        ],
    }


def cmd_version() -> None:
    print(SCRIPT_NAME)
    print(f"Version   : {SCRIPT_VERSION}")
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema    : {SCHEMA_VERSION}")


def cmd_init() -> None:
    ensure_dirs()
    scope = discover_scope()

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "script": {
            "name": SCRIPT_NAME,
            "version": SCRIPT_VERSION,
            "checklist_id": CHECKLIST_ID,
            "checklist": CHECKLIST_NAME,
        },
        "project": {
            "project_id": PROJECT_ID,
        },
        "target": {
            "scope_id": scope["scope_id"],
            "hostname": scope["hostname"],
            "url": scope["url"],
            "environment": "Production",
            "mode": "Black Box",
            "ports": scope["ports"],
        },
        "methodology": methodology(),
        "toolchain": {
            "language": "Python",
            "libraries": [
                "requests",
                "PyYAML",
                "urllib.parse",
                "hashlib",
                "re",
                "argparse",
            ],
            "external_scanners": [],
            "nmap": False,
            "ffuf": False,
            "sqlmap": False,
            "commix": False,
        },
        "payload_policy": payload_policy(),
        "crawler": {
            "max_depth": MAX_DEPTH,
            "max_candidates": MAX_CANDIDATES,
            "max_params_per_url": MAX_PARAMS_PER_URL,
        },
        "results": {
            "status": "initialized",
            "links": 0,
            "query_candidates": 0,
            "get_forms": 0,
            "candidates": 0,
            "tested": 0,
            "probes": 0,
            "duplicate_accepted": 0,
            "order_sensitive": 0,
            "findings": 0,
            "requires_review": 0,
            "request_errors": 0,
            "http_errors": 0,
        },
        "candidates": [],
        "notes": [
            "Duplicate parameter acceptance is forensic evidence, not a finding.",
            "First-wins and last-wins behavior are parsing observations, not findings.",
            "Response changes are not automatic security findings.",
            "HTTP 4xx/5xx responses cannot confirm HPP vulnerability.",
            "Automatic finding requires demonstrated security impact and reproducibility.",
            "Ordering-sensitive behavior is preserved for manual review.",
            "Security/session/token-style parameters are not automatic findings.",
            "Only non-destructive duplicate-parameter probes are used.",
            "SQLi, XSS, Command Injection, Path Traversal, and Expression/Template Injection are separate checklists.",
            "External links are not candidates and are never tested.",
        ],
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }

    write_yaml(ARTIFACT_FILE, artifact)

    print("[PASS] Parameter artifact siap.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {PROJECT_ID}")
    print(f"[PASS] File      : {ARTIFACT_FILE}")


def cmd_crawl() -> None:
    ensure_dirs()
    scope = discover_scope()
    session = load_session()

    candidates, crawl_meta = crawl_application(session, scope)

    artifact = read_yaml(ARTIFACT_FILE) if ARTIFACT_FILE.exists() else {}
    artifact["results"] = {
        "status": "crawled",
        "links": crawl_meta["links"],
        "query_candidates": crawl_meta["query_candidates"],
        "get_forms": crawl_meta["get_forms"],
        "candidates": len(candidates),
        "tested": 0,
        "probes": 0,
        "duplicate_accepted": 0,
        "order_sensitive": 0,
        "findings": 0,
        "requires_review": 0,
        "request_errors": 0,
        "http_errors": 0,
    }
    artifact["candidates"] = candidates
    artifact["crawl"] = {
        "links": crawl_meta["links"],
        "get_forms": crawl_meta["get_form_records"],
    }
    artifact["updated_at"] = now_iso()

    write_yaml(ARTIFACT_FILE, artifact)

    print("[PASS] Parameter crawl selesai.")
    print(f"[PASS] Links     : {crawl_meta['links']}")
    print(f"[PASS] Query candidates: {crawl_meta['query_candidates']}")
    print(f"[PASS] GET forms : {crawl_meta['get_forms']}")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(f"[PASS] File      : {ARTIFACT_FILE}")


def cmd_analyze() -> None:
    ensure_dirs()
    scope = discover_scope()
    session = load_session()

    if not ARTIFACT_FILE.exists():
        die("Artifact belum ada. Jalankan init dan crawl terlebih dahulu.")

    artifact = read_yaml(ARTIFACT_FILE)
    candidates = artifact.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        die("Candidate belum tersedia. Jalankan crawl terlebih dahulu.")

    started_at = now_iso()
    records: List[Dict[str, Any]] = []

    duplicate_accepted = 0
    order_sensitive = 0
    findings = 0
    requires_review = 0
    request_errors = 0
    http_errors = 0
    probes_count = 0

    for index, candidate in enumerate(candidates, start=1):
        if not isinstance(candidate, dict):
            continue

        if candidate.get("method", "GET").upper() != "GET":
            continue

        if not same_origin(scope["url"], candidate.get("url", "")):
            continue

        result = analyze_candidate(session, candidate)
        records.append(result)

        analysis = result["analysis"]
        if analysis["duplicate_accepted"]:
            duplicate_accepted += 1
        if analysis["order_sensitive"]:
            order_sensitive += 1
        if analysis["finding"]:
            findings += 1
        if analysis["requires_review"]:
            requires_review += 1

        for probe in result["probes"]:
            probes_count += 1
            if probe.get("request_error"):
                request_errors += 1
            response = probe.get("response") or {}
            if response and int(response.get("status", 0)) >= 400:
                http_errors += 1

        if index < len(candidates):
            time.sleep(REQUEST_DELAY_MS / 1000)

    completed_at = now_iso()

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "script": {
            "name": SCRIPT_NAME,
            "version": SCRIPT_VERSION,
            "checklist_id": CHECKLIST_ID,
        },
        "project_id": PROJECT_ID,
        "target": {
            "scope_id": scope["scope_id"],
            "hostname": scope["hostname"],
            "url": scope["url"],
        },
        "methodology": methodology(),
        "payload_policy": payload_policy(),
        "analysis": {
            "started_at": started_at,
            "completed_at": completed_at,
            "candidate_count": len(records),
            "probe_count": probes_count,
            "duplicate_accepted": duplicate_accepted,
            "order_sensitive": order_sensitive,
            "findings": findings,
            "requires_review": requires_review,
            "request_errors": request_errors,
            "http_errors": http_errors,
        },
        "records": records,
    }

    write_json(EVIDENCE_FILE, evidence)

    artifact["results"] = {
        "status": "completed",
        "started_at": started_at,
        "completed_at": completed_at,
        "links": int(artifact.get("results", {}).get("links", 0)),
        "query_candidates": int(artifact.get("results", {}).get("query_candidates", 0)),
        "get_forms": int(artifact.get("results", {}).get("get_forms", 0)),
        "candidates": len(records),
        "tested": len(records),
        "probes": probes_count,
        "duplicate_accepted": duplicate_accepted,
        "order_sensitive": order_sensitive,
        "findings": findings,
        "requires_review": requires_review,
        "request_errors": request_errors,
        "http_errors": http_errors,
    }
    artifact["evidence"] = {
        "file": str(EVIDENCE_FILE),
        "records": len(records),
    }
    artifact["updated_at"] = completed_at

    write_yaml(ARTIFACT_FILE, artifact)

    print("[PASS] Parameter analyze selesai.")
    print(f"[PASS] Candidates : {len(records)}")
    print(f"[PASS] Tested     : {len(records)}")
    print(f"[PASS] Probes     : {probes_count}")
    print(f"[PASS] Duplicate  : {duplicate_accepted}")
    print(f"[PASS] Order diff : {order_sensitive}")
    print(f"[PASS] Findings   : {findings}")
    print(f"[PASS] Review     : {requires_review}")
    print(f"[PASS] HTTP error : {http_errors}")
    print(f"[PASS] Evidence   : {EVIDENCE_FILE}")


def cmd_show() -> None:
    if not ARTIFACT_FILE.exists():
        die("Artifact belum ada.")
    artifact = read_yaml(ARTIFACT_FILE)

    print(f"Script     : {artifact.get('script', {}).get('name')}")
    print(f"Version    : {artifact.get('script', {}).get('version')}")
    print(f"Checklist  : {artifact.get('script', {}).get('checklist_id')}")
    print(f"Project    : {artifact.get('project', {}).get('project_id')}")
    print(f"Target     : {artifact.get('target', {}).get('url')}")

    results = artifact.get("results", {})
    print("")
    for key in (
        "status",
        "links",
        "query_candidates",
        "get_forms",
        "candidates",
        "tested",
        "probes",
        "duplicate_accepted",
        "order_sensitive",
        "findings",
        "requires_review",
        "request_errors",
        "http_errors",
    ):
        if key in results:
            print(f"{key:20}: {results[key]}")


def cmd_status() -> None:
    if not ARTIFACT_FILE.exists():
        print("[INFO] Parameter artifact belum dibuat.")
        return

    artifact = read_yaml(ARTIFACT_FILE)
    results = artifact.get("results", {})

    print(f"[INFO] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[INFO] Version   : {artifact.get('script', {}).get('version')}")
    print(f"[INFO] Status    : {results.get('status', 'unknown')}")
    print(f"[INFO] Candidates: {results.get('candidates', 0)}")
    print(f"[INFO] Probes    : {results.get('probes', 0)}")
    print(f"[INFO] Findings  : {results.get('findings', 0)}")
    print(f"[INFO] Review    : {results.get('requires_review', 0)}")


def verify_utf8_no_bom(path: Path) -> bool:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        return False
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def verify() -> bool:
    failures: List[str] = []

    if not ARTIFACT_FILE.exists():
        failures.append("Artifact parameter.yaml tidak ditemukan.")
        for failure in failures:
            print(f"[FAIL] {failure}")
        return False

    artifact = read_yaml(ARTIFACT_FILE)

    script = artifact.get("script", {})
    project = artifact.get("project", {})
    target = artifact.get("target", {})
    method = artifact.get("methodology", {})
    toolchain = artifact.get("toolchain", {})
    results = artifact.get("results", {})
    candidates = artifact.get("candidates", [])

    if script.get("version") != SCRIPT_VERSION:
        failures.append("Version artifact tidak sesuai script.")
    if script.get("checklist_id") != CHECKLIST_ID:
        failures.append("Checklist ID tidak sesuai.")
    if project.get("project_id") != PROJECT_ID:
        failures.append("Project ID tidak sesuai.")
    if target.get("scope_id") != SCOPE_ID:
        failures.append("Scope ID tidak sesuai.")
    if target.get("hostname") != host_from_url(target.get("url", "")):
        failures.append("Hostname target tidak sesuai URL.")

    required_true = [
        "same_origin_only",
        "redirect_following",
        "non_destructive",
        "duplicate_parameter_is_finding",
        "response_change_is_finding",
        "http_500_is_finding",
        "http_error_is_finding",
        "first_wins_is_finding",
        "last_wins_is_finding",
        "order_sensitivity_requires_manual_review",
        "security_impact_required_for_finding",
        "protected_parameter_context_is_not_automatic_finding",
        "forensic_evidence_preserved",
        "no_sql_injection",
        "no_xss",
        "no_command_injection",
        "no_path_traversal",
        "no_expression_template_injection",
        "no_file_read_write_delete",
        "no_upload",
        "no_reverse_shell",
        "no_external_callbacks",
        "no_credential_harvesting",
    ]
    for key in required_true:
        if method.get(key) is not True:
            failures.append(f"Methodology {key} harus true.")

    if method.get("http_methods") != ["GET"]:
        failures.append("HTTP methods harus GET saja.")

    if toolchain.get("external_scanners") != []:
        failures.append("External scanner harus kosong.")
    for key in ("nmap", "ffuf", "sqlmap", "commix"):
        if toolchain.get(key) is not False:
            failures.append(f"Toolchain {key} harus false.")

    if not isinstance(candidates, list):
        failures.append("Candidates harus berupa list.")

    if not EVIDENCE_FILE.exists():
        failures.append("Evidence parameter-probes.json tidak ditemukan.")

    if EVIDENCE_FILE.exists():
        try:
            evidence = json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
            if evidence.get("script", {}).get("version") != SCRIPT_VERSION:
                failures.append("Version evidence tidak sesuai.")
            if evidence.get("script", {}).get("checklist_id") != CHECKLIST_ID:
                failures.append("Checklist ID evidence tidak sesuai.")
            evidence_method = evidence.get("methodology", {})
            if evidence_method.get("security_impact_required_for_finding") is not True:
                failures.append("Evidence harus mewajibkan security impact.")
            records = evidence.get("records", [])
            if not isinstance(records, list):
                failures.append("Evidence records harus berupa list.")
            elif isinstance(candidates, list) and len(records) != len(candidates):
                failures.append("Jumlah evidence records tidak sama dengan candidates.")

            for record in records if isinstance(records, list) else []:
                analysis = record.get("analysis", {})
                if analysis.get("finding") and not analysis.get("automatic_security_impact"):
                    failures.append("Finding tanpa automatic security impact tidak valid.")
                    break
                if analysis.get("finding") and analysis.get("protected_parameter_context"):
                    failures.append("Protected parameter tidak boleh menjadi automatic finding.")
                    break
        except Exception as exc:
            failures.append(f"Evidence JSON tidak valid: {exc}")

    if ARTIFACT_FILE.exists() and not verify_utf8_no_bom(ARTIFACT_FILE):
        failures.append("Artifact bukan UTF-8 tanpa BOM.")

    if EVIDENCE_FILE.exists() and not verify_utf8_no_bom(EVIDENCE_FILE):
        failures.append("Evidence bukan UTF-8 tanpa BOM.")

    if failures:
        for failure in failures:
            print(f"[FAIL] {failure}")
        return False

    print("[PASS] Parameter memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {PROJECT_ID}")
    print(f"[PASS] File      : {ARTIFACT_FILE}")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(f"[PASS] Probes    : {results.get('probes', 0)}")
    print("[PASS] Encoding  : UTF-8 tanpa BOM")
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=SCRIPT_NAME,
    )
    parser.add_argument(
        "command",
        choices=["version", "init", "crawl", "analyze", "show", "status", "verify"],
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    commands = {
        "version": cmd_version,
        "init": cmd_init,
        "crawl": cmd_crawl,
        "analyze": cmd_analyze,
        "show": cmd_show,
        "status": cmd_status,
    }

    if args.command == "verify":
        return 0 if verify() else 1

    commands[args.command]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
