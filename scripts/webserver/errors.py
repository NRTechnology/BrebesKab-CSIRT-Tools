#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Web Server Assessment - 4-010 Error Information Disclosure

Controlled error-response assessment for:
    - 404 Not Found
    - 400 Bad Request (safe URL/path conditions)
    - method-related error responses on known endpoints

Design:
- Uses the authorized project scope as the source of target authority.
- Uses Recon directory.yaml as the endpoint source; no discovery/brute force.
- Tests HTTP and HTTPS separately.
- Does not follow redirects.
- Does not send mutation payloads or perform application CRUD operations.
- Stores raw probe evidence for auditability.
- Detects common technical-information disclosure indicators in error responses.
- Correlates CVE candidates from 4-001 version.yaml as heuristic evidence only.
- Does not automatically declare a vulnerability from an error response or CVE match.

Commands:
    python errors.py version
    python errors.py init
    python errors.py analyze
    python errors.py list
    python errors.py verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
import yaml


APP_VERSION = "1.0.1"
SCHEMA_VERSION = "1.0"

CHECKLIST_ID = "4-010"
CHECKLIST_NAME = "Errors / Error Information Disclosure"

METHODS = [
    "GET",
    "HEAD",
]

DEFAULT_TIMEOUT = 15
MAX_BODY_BYTES = 65536

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_ROOT = PROJECT_ROOT / "projects"

RECON_DIRECTORY_REL = Path("02-reconnaissance") / "directory" / "directory.yaml"
VERSION_ARTIFACT_REL = (
    Path("04-web-server-configuration") / "version" / "version.yaml"
)
SCOPE_REL = Path("01-preparation") / "scope" / "scope.yaml"

WEBSERVER_REL = Path("04-web-server-configuration") / "errors"
ARTIFACT_NAME = "errors.yaml"
EVIDENCE_NAME = "errors-probes.json"

USER_AGENT = "BrebesKab-CSIRT-Tools/4-010"

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}

# Known technical disclosure indicators.
# These are indicators only; detection does not equal a vulnerability.
INDICATORS = {
    "stack_trace": (
        r"traceback \(most recent call last\)",
        r"stack trace",
        r"stacktrace",
        r"exception at",
        r"at\s+[\w.$]+\([^)]*\)",
        r"caused by:",
    ),
    "filesystem_path": (
        r"/var/www/",
        r"/var/www/html/",
        r"/home/[^/\s]+/",
        r"/srv/www/",
        r"/opt/[^/\s]+/",
        r"[A-Za-z]:\\(?:[^\\\r\n]+\\)+",
        r"application[/\\](?:controllers|models|views|config)",
        r"system[/\\](?:core|database|libraries)",
    ),
    "php_error": (
        r"\bPHP\s+(?:Fatal error|Warning|Notice|Parse error|Deprecated)\b",
        r"\bFatal error:\b",
        r"\bWarning:\b.*\bon line\s+\d+",
        r"\bNotice:\b.*\bon line\s+\d+",
    ),
    "framework_debug": (
        r"codeigniter",
        r"laravel",
        r"symfony",
        r"yii framework",
        r"cakephp",
        r"slim framework",
        r"debug toolbar",
        r"whoops",
    ),
    "database_error": (
        r"SQLSTATE\[[0-9A-Z]+\]",
        r"mysql(?:nd)?\s+error",
        r"mysqli?_",
        r"pdo(?:exception|_exception)",
        r"postgres(?:ql)?\s+error",
        r"sqlite(?:3)?\s+error",
        r"ORA-\d{4,}",
        r"database connection",
        r"db connection",
    ),
    "debug_marker": (
        r"\bDEBUG\b\s*[:=]",
        r"\bAPP_DEBUG\b\s*[:=]",
        r"debug\s+mode",
        r"development\s+mode",
        r"environment\s*[:=]\s*(?:local|development|dev)",
    ),
    "credential_pattern": (
        r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s<]{3,}",
        r"(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]?[^'\"\s<]{6,}",
        r"Authorization:\s*(?:Bearer|Basic)\s+\S+",
    ),
    "source_code_marker": (
        r"<\?php",
        r"\bnamespace\s+[A-Za-z_][\w\\]*\s*;",
        r"\bfunction\s+[A-Za-z_]\w*\s*\(",
    ),
}

# These strings can legitimately identify the framework/application without
# proving information disclosure. They are retained as evidence indicators.
FRAMEWORK_NAMES = (
    "codeigniter",
    "laravel",
    "symfony",
    "yii",
    "cakephp",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {path}")

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ValueError(f"Root YAML bukan mapping: {path}")

    return data


def save_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            data,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            data,
            handle,
            ensure_ascii=False,
            indent=2,
        )


def project_id_from_dir(project_dir_path: Path) -> str:
    return project_dir_path.name


def project_dir() -> Path:
    project_id = find_current_project_id()
    return PROJECTS_ROOT / project_id


def find_current_project_id() -> str:
    candidates = sorted(
        [p.name for p in PROJECTS_ROOT.iterdir() if p.is_dir()]
    ) if PROJECTS_ROOT.exists() else []

    preferred = [
        p for p in candidates
        if p.upper().startswith("PENTEST-")
    ]

    if len(preferred) == 1:
        return preferred[0]

    if len(preferred) > 1:
        return preferred[-1]

    raise RuntimeError(
        f"Tidak dapat menentukan project pada: {PROJECTS_ROOT}"
    )


def artifact_dir() -> Path:
    return project_dir() / WEBSERVER_REL


def artifact_path() -> Path:
    return artifact_dir() / ARTIFACT_NAME


def evidence_path() -> Path:
    return artifact_dir() / "evidence" / EVIDENCE_NAME


def recon_directory_path() -> Path:
    return project_dir() / RECON_DIRECTORY_REL


def version_artifact_path() -> Path:
    return project_dir() / VERSION_ARTIFACT_REL


def get_scope_entries(scope_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    scope = scope_data.get("scope", {})
    if not isinstance(scope, dict):
        return []

    entries = scope.get("in_scope", [])
    if not isinstance(entries, list):
        return []

    return [
        entry for entry in entries
        if isinstance(entry, dict)
    ]


def get_authorized_targets(scope_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []

    for entry in get_scope_entries(scope_data):
        if entry.get("type") != "domain":
            continue

        value = str(entry.get("value", "")).strip()
        if not value:
            continue

        ports = entry.get("ports", [80, 443])
        if not isinstance(ports, list):
            ports = [80, 443]

        normalized_ports: List[int] = []
        for port in ports:
            try:
                normalized_ports.append(int(port))
            except (TypeError, ValueError):
                continue

        targets.append(
            {
                "scope_id": entry.get("scope_id"),
                "type": "domain",
                "value": value,
                "ports": normalized_ports,
            }
        )

    return targets


def choose_primary_scope(scope_data: Dict[str, Any]) -> Dict[str, Any]:
    targets = get_authorized_targets(scope_data)

    if not targets:
        raise ValueError(
            "Domain target tidak ditemukan pada scope.in_scope."
        )

    return targets[0]


def load_project_scope() -> Dict[str, Any]:
    candidates = [
        project_dir() / SCOPE_REL,
        project_dir() / "scope.yaml",
        project_dir() / "scope.yml",
    ]

    for path in candidates:
        if path.exists():
            return load_yaml(path)

    expected = project_dir() / SCOPE_REL
    raise FileNotFoundError(
        f"scope.yaml tidak ditemukan. Lokasi canonical: {expected}"
    )


def normalize_path(value: str) -> Optional[str]:
    if not isinstance(value, str):
        return None

    value = value.strip()
    if not value:
        return None

    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        value = parsed.path or "/"
        if parsed.query:
            value += "?" + parsed.query

    if not value.startswith("/"):
        value = "/" + value

    value = value.split("#", 1)[0]
    value = re.sub(r"/{2,}", "/", value)

    return value or "/"


def is_skip_path(path: str) -> bool:
    clean = path.split("?", 1)[0].rstrip("/") or "/"
    return clean in {
        "/robots.txt",
        "/favicon.ico",
    }


def extract_recon_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    directory_block = data.get("directory", {})

    if not isinstance(directory_block, dict):
        return []

    results = directory_block.get("results", [])

    if not isinstance(results, list):
        return []

    return [
        item for item in results
        if isinstance(item, dict)
    ]


def build_error_candidates(
    recon_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Select known Recon paths as baseline endpoint sources.

    Error-specific probes are generated from these known paths plus
    deterministic non-existent paths. No brute-force discovery is performed.
    """
    results = extract_recon_results(recon_data)

    selected: Dict[str, Dict[str, Any]] = {}

    for item in results:
        path = normalize_path(
            item.get("path")
            or item.get("uri")
            or item.get("endpoint")
            or item.get("url")
            or ""
        )

        if not path or is_skip_path(path):
            continue

        key = path.lower()

        if key not in selected:
            selected[key] = {
                "path": path,
                "source": "recon-directory",
                "source_classification": item.get("classification"),
                "source_status_code": item.get("status_code"),
                "source_url": item.get("url"),
            }

    values = list(selected.values())
    values.sort(
        key=lambda item: item["path"].lower()
    )

    return values


def build_error_paths(
    candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Build a small, deterministic set of safe error conditions.

    1. A guaranteed-looking non-existent path.
    2. Each known Recon candidate with a deterministic missing child.
    3. The original known path, useful for observing whether the normal
       response itself contains an error/debug page.

    The generated missing paths are not directory brute-force candidates.
    """
    selected: Dict[str, Dict[str, Any]] = {}

    def add(path: str, source: str, parent: Optional[str] = None) -> None:
        normalized = normalize_path(path)
        if not normalized:
            return
        key = normalized.lower()
        if key not in selected:
            selected[key] = {
                "path": normalized,
                "source": source,
                "parent_path": parent,
            }

    add(
        "/__brebes_csirt_404_pentest_2026_002__/",
        "controlled-nonexistent-baseline",
    )

    for candidate in candidates:
        path = candidate["path"]

        if path == "/":
            child = "/__brebes_csirt_missing_child_pentest_2026_002__/"
        else:
            base = path.rstrip("/")
            child = (
                f"{base}/"
                "__brebes_csirt_missing_child_pentest_2026_002__/"
            )

        add(
            child,
            "controlled-missing-child",
            parent=path,
        )

    # Include known paths separately so the tool can identify normal
    # application/framework error responses without assuming they are errors.
    for candidate in candidates:
        add(
            candidate["path"],
            "recon-known-endpoint",
            parent=None,
        )

    values = list(selected.values())
    values.sort(
        key=lambda item: (
            0 if item["source"] == "controlled-nonexistent-baseline" else 1,
            item["path"].lower(),
        )
    )

    return values


def build_urls(
    domain: str,
    ports: Iterable[int],
    path: str,
) -> List[Tuple[str, str, int, str]]:
    output: List[Tuple[str, str, int, str]] = []

    for port in ports:
        if port == 80:
            scheme = "http"
        elif port == 443:
            scheme = "https"
        else:
            continue

        base = f"{scheme}://{domain}"
        url = urljoin(base + "/", path.lstrip("/"))

        if path == "/":
            url = base + "/"

        output.append((scheme.upper(), scheme, port, url))

    return output


def load_version_cves() -> List[Dict[str, Any]]:
    """Load and triage CVE candidates from canonical 4-001 version.yaml.

    The authoritative source is:
        cve_correlation.products[].cves[]

    Legacy layouts are accepted only as compatibility fallbacks. CVE matches
    remain candidate evidence and never create an automatic finding.
    """
    path = version_artifact_path()

    if not path.exists():
        return []

    try:
        data = load_yaml(path)
    except Exception:
        return []

    correlation = data.get("cve_correlation", {})
    products = correlation.get("products", []) if isinstance(correlation, dict) else []

    candidates: List[Dict[str, Any]] = []
    seen = set()

    keywords = (
        "error",
        "exception",
        "information disclosure",
        "stack trace",
        "debug",
        "http response",
        "http request",
        "http server",
    )

    def add_candidate(
        item: Dict[str, Any],
        product: Optional[str] = None,
        version: Optional[str] = None,
    ) -> None:
        cve_id = (
            item.get("cve_id")
            or item.get("cve")
            or item.get("id")
        )
        if not cve_id:
            return

        cve_id = str(cve_id).strip()
        if not cve_id or cve_id in seen:
            return

        description_parts: List[str] = []
        for key in (
            "description",
            "summary",
            "title",
            "details",
            "vulnerability",
        ):
            value = item.get(key)
            if value is not None:
                description_parts.append(str(value))

        description = " ".join(description_parts).strip()
        lower = description.lower()

        if not any(keyword in lower for keyword in keywords):
            return

        seen.add(cve_id)

        candidate = {
            "cve_id": cve_id,
            "description": description,
            "source": str(path),
            "correlation": "error-response-related keyword match",
            "classification": "cve-candidate",
        }

        if product is not None:
            candidate["product"] = product
        if version is not None:
            candidate["version"] = version

        # Preserve authoritative CVE metadata from 4-001 where available.
        metadata_keys = (
            "vuln_status",
            "published",
            "last_modified",
            "cwe",
            "cvss",
            "known_exploited_vulnerability",
            "kev_date_added",
            "applicability",
            "nvd_url",
            "correlation_basis",
            "requires_validation",
            "finding",
        )
        for key in metadata_keys:
            if key in item:
                candidate[key] = item[key]

        candidates.append(candidate)

    # Canonical 4-001 source.
    if isinstance(products, list):
        for product_entry in products:
            if not isinstance(product_entry, dict):
                continue

            product_name = product_entry.get("product")
            product_version = product_entry.get("version")
            cves = product_entry.get("cves", [])

            if not isinstance(cves, list):
                continue

            for item in cves:
                if isinstance(item, dict):
                    add_candidate(
                        item,
                        str(product_name) if product_name is not None else None,
                        str(product_version) if product_version is not None else None,
                    )

    # Compatibility fallback for older artifacts only.
    if not candidates:
        legacy_candidates = correlation.get("candidates", []) if isinstance(correlation, dict) else []
        if isinstance(legacy_candidates, list):
            for item in legacy_candidates:
                if isinstance(item, dict):
                    add_candidate(item)

    if not candidates:
        legacy_wrapper = data.get("webserver_version", {})
        if isinstance(legacy_wrapper, dict):
            legacy_correlation = legacy_wrapper.get("cve_correlation", {})
            if isinstance(legacy_correlation, dict):
                legacy_candidates = legacy_correlation.get("candidates", [])
                if isinstance(legacy_candidates, list):
                    for item in legacy_candidates:
                        if isinstance(item, dict):
                            add_candidate(item)

    return candidates


def response_headers_subset(
    headers: requests.structures.CaseInsensitiveDict,
) -> Dict[str, str]:
    interesting = (
        "server",
        "allow",
        "location",
        "content-type",
        "content-length",
        "www-authenticate",
        "x-powered-by",
        "x-generator",
        "x-runtime",
        "x-debug",
        "x-debug-token",
        "x-debug-token-link",
    )

    output: Dict[str, str] = {}

    for key in interesting:
        value = headers.get(key)
        if value is not None:
            output[key] = value

    return output


def safe_body_sample(body: bytes) -> str:
    sample = body[:MAX_BODY_BYTES]

    try:
        return sample.decode("utf-8", errors="replace")
    except Exception:
        return repr(sample)


def detect_indicators(body_text: str) -> Dict[str, Any]:
    detected: Dict[str, List[str]] = {}
    lower = body_text.lower()

    for category, patterns in INDICATORS.items():
        matches: List[str] = []

        for pattern in patterns:
            try:
                if re.search(pattern, body_text, flags=re.IGNORECASE):
                    matches.append(pattern)
            except re.error:
                continue

        if matches:
            detected[category] = matches

    framework_mentions = [
        name for name in FRAMEWORK_NAMES
        if name in lower
    ]

    return {
        "detected": detected,
        "categories": sorted(detected.keys()),
        "framework_mentions": framework_mentions,
        "technical_disclosure_indicator": bool(
            detected.get("stack_trace")
            or detected.get("filesystem_path")
            or detected.get("php_error")
            or detected.get("database_error")
            or detected.get("debug_marker")
            or detected.get("credential_pattern")
            or detected.get("source_code_marker")
        ),
    }


def classify_error_response(
    status_code: Optional[int],
    indicators: Dict[str, Any],
    source: str,
) -> str:
    if status_code is None:
        return "probe-error"

    if 300 <= status_code <= 399:
        return "error-redirected"

    if status_code in {401, 403}:
        return "error-access-controlled"

    if status_code == 404:
        if indicators.get("technical_disclosure_indicator"):
            return "error-information-disclosure"
        return "error-not-found"

    if status_code in {400, 408, 413, 414, 415, 422, 429}:
        if indicators.get("technical_disclosure_indicator"):
            return "error-information-disclosure"
        return "error-response-normal"

    if 500 <= status_code <= 599:
        if indicators.get("technical_disclosure_indicator"):
            return "error-information-disclosure"
        return "error-server-error"

    if indicators.get("technical_disclosure_indicator"):
        return "error-information-disclosure"

    if source == "recon-known-endpoint":
        return "known-endpoint-response"

    return "error-response-normal"


def probe_error(
    session: requests.Session,
    url: str,
    method: str,
    source: str,
    parent_path: Optional[str],
) -> Dict[str, Any]:
    started = utc_now()

    result: Dict[str, Any] = {
        "url": url,
        "method": method,
        "started_at": started,
        "allow_redirects": False,
        "timeout_seconds": DEFAULT_TIMEOUT,
        "request_body_sent": False,
        "source": source,
        "parent_path": parent_path,
    }

    try:
        response = session.request(
            method=method,
            url=url,
            headers=DEFAULT_HEADERS,
            allow_redirects=False,
            timeout=DEFAULT_TIMEOUT,
            verify=True,
            data=None,
        )

        body = response.content[:MAX_BODY_BYTES]
        body_text = safe_body_sample(body)
        headers = response_headers_subset(response.headers)
        indicators = detect_indicators(body_text)

        result.update(
            {
                "status_code": response.status_code,
                "reason": response.reason,
                "headers": headers,
                "server": response.headers.get("Server"),
                "allow": response.headers.get("Allow"),
                "location": response.headers.get("Location"),
                "content_type": response.headers.get("Content-Type"),
                "content_length": len(response.content),
                "body_sample_length": len(body),
                "body_sha256": sha256_bytes(body),
                "body_sample": body_text,
                "indicators": indicators,
                "classification": classify_error_response(
                    response.status_code,
                    indicators,
                    source,
                ),
                "error": None,
                "completed_at": utc_now(),
            }
        )

    except requests.exceptions.SSLError as exc:
        result.update(
            {
                "status_code": None,
                "classification": "probe-error",
                "error_type": "ssl-error",
                "error": str(exc),
                "completed_at": utc_now(),
            }
        )

    except requests.exceptions.Timeout as exc:
        result.update(
            {
                "status_code": None,
                "classification": "probe-error",
                "error_type": "timeout",
                "error": str(exc),
                "completed_at": utc_now(),
            }
        )

    except requests.exceptions.RequestException as exc:
        result.update(
            {
                "status_code": None,
                "classification": "probe-error",
                "error_type": "request-error",
                "error": str(exc),
                "completed_at": utc_now(),
            }
        )

    except Exception as exc:
        result.update(
            {
                "status_code": None,
                "classification": "probe-error",
                "error_type": "unexpected-error",
                "error": repr(exc),
                "completed_at": utc_now(),
            }
        )

    return result


def summarize_probes(
    probes: List[Dict[str, Any]],
) -> Dict[str, int]:
    summary = {
        "probes": len(probes),
        "information_disclosure": 0,
        "not_found": 0,
        "access_controlled": 0,
        "redirected": 0,
        "server_errors": 0,
        "normal_error": 0,
        "known_endpoint": 0,
        "probe_errors": 0,
        "other": 0,
    }

    for item in probes:
        classification = item.get("classification")

        if classification == "error-information-disclosure":
            summary["information_disclosure"] += 1
        elif classification == "error-not-found":
            summary["not_found"] += 1
        elif classification == "error-access-controlled":
            summary["access_controlled"] += 1
        elif classification == "error-redirected":
            summary["redirected"] += 1
        elif classification == "error-server-error":
            summary["server_errors"] += 1
        elif classification == "error-response-normal":
            summary["normal_error"] += 1
        elif classification == "known-endpoint-response":
            summary["known_endpoint"] += 1
        elif classification == "probe-error":
            summary["probe_errors"] += 1
        else:
            summary["other"] += 1

    return summary


def assessment_from_probes(
    probes: List[Dict[str, Any]],
    cves: List[Dict[str, Any]],
) -> Dict[str, Any]:
    disclosures = [
        item for item in probes
        if item.get("classification") == "error-information-disclosure"
    ]

    errors = [
        item for item in probes
        if item.get("classification") == "probe-error"
    ]

    requires_review = bool(disclosures or errors)

    if errors:
        status = "probe-errors"
        assessment = (
            "Error-response probing menghasilkan error dan memerlukan "
            "review; tidak ada automatic vulnerability finding."
        )
    elif disclosures:
        status = "information-disclosure-review"
        assessment = (
            "Satu atau lebih error response menunjukkan indikator "
            "technical information disclosure; evidence dicatat untuk "
            "manual review. Tidak ada automatic vulnerability finding."
        )
    else:
        status = "errors-no-disclosure"
        assessment = (
            "Controlled error responses tidak menunjukkan indikator "
            "technical information disclosure pada body yang diuji. "
            "Informasi server/framework yang bersifat umum tidak otomatis "
            "dikategorikan sebagai vulnerability."
        )

    return {
        "status": status,
        "finding": False,
        "requires_review": requires_review,
        "information_disclosure_count": len(disclosures),
        "probe_error_count": len(errors),
        "cve_candidate_count": len(cves),
        "summary": assessment,
    }


def initialize_artifact() -> int:
    scope = load_project_scope()
    target = choose_primary_scope(scope)

    recon_path = recon_directory_path()
    if not recon_path.exists():
        raise FileNotFoundError(
            f"Recon directory.yaml tidak ditemukan: {recon_path}"
        )

    recon_data = load_yaml(recon_path)
    recon_results = extract_recon_results(recon_data)
    candidates = build_error_candidates(recon_data)
    error_paths = build_error_paths(candidates)

    project_id = project_id_from_dir(project_dir())
    recon_status = recon_data.get("directory", {})
    if isinstance(recon_status, dict):
        recon_status = recon_status.get("status", "")
    else:
        recon_status = recon_data.get("status", "")

    data = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "errors.py",
            "version": APP_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": "Error information disclosure",
            "phase": "04 Web Server Configuration",
            "focus": "Technical information disclosure in HTTP error responses",
            "status": "initialized",
        },
        "target": {
            "application": target.get("application", "Bangsaku"),
            "hostname": target["value"],
            "url": f"https://{target['value']}",
            "environment": target.get("environment", "Production"),
            "assessment_type": target.get("assessment_type", "Grey Box"),
            "scope_id": target.get("scope_id"),
            "scope_reference": str(project_dir() / SCOPE_REL),
            "authorized_ports": target["ports"],
        },
        "methodology": {
            "endpoint_source": "Recon directory.yaml",
            "endpoint_source_path": str(recon_path),
            "error_paths": (
                "Recon-known endpoints plus deterministic non-existent "
                "baseline and missing-child paths"
            ),
            "discovery": False,
            "brute_force": False,
            "redirect_following": False,
            "mutation_payload": False,
            "application_crud": False,
            "raw_evidence_retained": True,
            "automatic_finding": False,
            "cve_correlation": "4-001 version.yaml heuristic candidate evidence only",
        },
        "baseline": {
            "recon_status": recon_status,
            "recon_paths": len(recon_results),
            "selected_candidates": len(candidates),
            "generated_error_paths": len(error_paths),
        },
        "toolchain": {
            "python": "requests + PyYAML",
            "optional_tools": [],
            "required_tools": ["Python", "requests", "PyYAML"],
        },
        "probe": {
            "methods": METHODS,
            "authorized_ports": target["ports"],
            "timeout_seconds": DEFAULT_TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "allow_redirects": False,
            "verify_tls": True,
            "request_body_sent": False,
        },
        "source_status": {
            "directory": recon_status or "unknown",
            "version": "completed" if version_artifact_path().exists() else "missing",
        },
        "results": {
            "candidates": candidates,
            "error_paths": error_paths,
            "probes": [],
        },
        "summary": summarize_probes([]),
        "cve_correlation": {
            "source": "04-web-server-configuration/version/version.yaml",
            "method": "canonical 4-001 cve_correlation.products[].cves[]",
            "candidates": [],
            "candidate_count": 0,
        },
        "assessment": {
            "result": "initialized",
            "finding": False,
            "requires_review": False,
            "information_disclosure_count": 0,
            "probe_error_count": 0,
            "cve_candidate_count": 0,
            "summary": (
                "Artifact diinisialisasi; belum dilakukan "
                "error-response probing."
            ),
        },
        "evidence": {
            "raw_probe_file": str(evidence_path()),
            "raw_evidence_retained": True,
        },
        "errors": [],
        "notes": [
            "Error responses are evidence, not automatic vulnerabilities.",
            "Server/framework identification alone is not classified as a vulnerability.",
            "No redirect following is performed.",
            "No application CRUD operation is intentionally executed.",
            "No brute-force directory discovery is performed.",
            "CVE correlation is heuristic candidate evidence only.",
            "Report-generation redaction is separate from raw evidence collection.",
        ],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
    }

    save_yaml(artifact_path(), data)

    print("[PASS] Error Information Disclosure berhasil diinisialisasi.")
    print(f"PROJECT         : {data['project_id']}")
    print(f"TARGET          : {target['value']}")
    print(f"PORTS           : {', '.join(map(str, target['ports']))}")
    print(f"METHODS         : {', '.join(METHODS)}")
    print(f"RECON PATHS     : {len(recon_results)}")
    print(f"CANDIDATES      : {len(candidates)}")
    print(f"ERROR PATHS     : {len(error_paths)}")
    print(f"SOURCE          : {recon_path}")
    print(f"FILE            : {artifact_path()}")

    return 0


def analyze() -> int:
    scope = load_project_scope()
    target = choose_primary_scope(scope)

    recon_path = recon_directory_path()
    recon_data = load_yaml(recon_path)
    recon_results = extract_recon_results(recon_data)
    candidates = build_error_candidates(recon_data)
    error_paths = build_error_paths(candidates)

    cves = load_version_cves()

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    probes: List[Dict[str, Any]] = []

    for error_path in error_paths:
        path = error_path["path"]

        for scheme_label, scheme, port, url in build_urls(
            target["value"],
            target["ports"],
            path,
        ):
            for method in METHODS:
                result = probe_error(
                    session,
                    url,
                    method,
                    error_path["source"],
                    error_path.get("parent_path"),
                )

                result.update(
                    {
                        "scheme": scheme_label,
                        "scheme_lower": scheme,
                        "port": port,
                        "path": path,
                        "endpoint_source": error_path["source"],
                    }
                )

                probes.append(result)

    summary = summarize_probes(probes)
    assessment = assessment_from_probes(probes, cves)

    project_id = project_id_from_dir(project_dir())
    recon_status = recon_data.get("directory", {})
    if isinstance(recon_status, dict):
        recon_status = recon_status.get("status", "")
    else:
        recon_status = recon_data.get("status", "")

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "errors.py",
            "version": APP_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": "Error information disclosure",
            "phase": "04 Web Server Configuration",
            "focus": "Technical information disclosure in HTTP error responses",
            "status": "completed",
        },
        "target": {
            "application": target.get("application", "Bangsaku"),
            "hostname": target["value"],
            "url": f"https://{target['value']}",
            "environment": target.get("environment", "Production"),
            "assessment_type": target.get("assessment_type", "Grey Box"),
            "scope_id": target.get("scope_id"),
            "scope_reference": str(project_dir() / SCOPE_REL),
            "authorized_ports": target["ports"],
        },
        "methodology": {
            "endpoint_source": "Recon directory.yaml",
            "endpoint_source_path": str(recon_path),
            "error_paths": (
                "Recon-known endpoints plus deterministic non-existent "
                "baseline and missing-child paths"
            ),
            "discovery": False,
            "brute_force": False,
            "redirect_following": False,
            "mutation_payload": False,
            "application_crud": False,
            "raw_evidence_retained": True,
            "automatic_finding": False,
            "cve_correlation": "4-001 version.yaml heuristic candidate evidence only",
        },
        "baseline": {
            "recon_status": recon_status,
            "recon_paths": len(recon_results),
            "selected_candidates": len(candidates),
            "generated_error_paths": len(error_paths),
        },
        "toolchain": {
            "python": "requests + PyYAML",
            "optional_tools": [],
            "required_tools": ["Python", "requests", "PyYAML"],
        },
        "probe": {
            "methods": METHODS,
            "authorized_ports": target["ports"],
            "timeout_seconds": DEFAULT_TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "allow_redirects": False,
            "verify_tls": True,
            "request_body_sent": False,
            "probe_count": len(probes),
        },
        "source_status": {
            "directory": recon_status or "unknown",
            "version": "completed" if version_artifact_path().exists() else "missing",
        },
        "results": {
            "candidates": candidates,
            "error_paths": error_paths,
            "probes": probes,
        },
        "summary": summary,
        "cve_correlation": {
            "source": "04-web-server-configuration/version/version.yaml",
            "method": "canonical 4-001 cve_correlation.products[].cves[]",
            "candidates": cves,
            "candidate_count": len(cves),
        },
        "assessment": {
            "result": assessment["status"],
            "finding": False,
            "requires_review": assessment["requires_review"],
            "information_disclosure_count": assessment[
                "information_disclosure_count"
            ],
            "probe_error_count": assessment["probe_error_count"],
            "cve_candidate_count": assessment["cve_candidate_count"],
            "summary": assessment["summary"],
        },
        "evidence": {
            "raw_probe_file": str(evidence_path()),
            "raw_evidence_retained": True,
            "probe_sha256": sha256_bytes(
                json.dumps(
                    probes,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            ),
        },
        "errors": [
            {
                "type": item.get("error_type", "probe-error"),
                "message": item.get("error"),
                "url": item.get("url"),
                "method": item.get("method"),
            }
            for item in probes
            if item.get("classification") == "probe-error"
        ],
        "notes": [
            "Error responses are evidence, not automatic vulnerabilities.",
            "Server/framework identification alone is not classified as a vulnerability.",
            "No redirect following is performed.",
            "No application CRUD operation is intentionally executed.",
            "No brute-force directory discovery is performed.",
            "CVE correlation is heuristic candidate evidence only.",
            "Report-generation redaction is separate from raw evidence collection.",
        ],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
    }

    save_yaml(artifact_path(), artifact)

    raw_evidence = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "generated_at": utc_now(),
        "checklist_id": CHECKLIST_ID,
        "target": target,
        "methods": METHODS,
        "endpoint_source": {
            "type": "recon-directory",
            "path": str(recon_path),
            "recon_paths": len(recon_results),
            "selected_candidates": len(candidates),
            "generated_error_paths": len(error_paths),
        },
        "probes": probes,
    }

    save_json(evidence_path(), raw_evidence)

    print("[PASS] Error Information Disclosure berhasil dianalisis.")
    print(f"PROJECT         : {artifact['project_id']}")
    print(f"TARGET          : {target['value']}")
    print(f"ERROR PATHS     : {len(error_paths)}")
    print(f"METHODS         : {len(METHODS)}")
    print(f"PROBES          : {summary['probes']}")
    print(f"DISCLOSURE      : {summary['information_disclosure']}")
    print(f"NOT FOUND       : {summary['not_found']}")
    print(f"ACCESS CONTROL  : {summary['access_controlled']}")
    print(f"REDIRECTED      : {summary['redirected']}")
    print(f"SERVER ERRORS   : {summary['server_errors']}")
    print(f"PROBE ERRORS    : {summary['probe_errors']}")
    print(f"CVE CANDIDATES  : {len(cves)}")
    print(f"REQUIRES REVIEW : {assessment['requires_review']}")
    print(f"STATUS          : {assessment['status']}")
    print(f"FILE            : {artifact_path()}")

    return 0


def load_artifact() -> Dict[str, Any]:
    return load_yaml(artifact_path())


def list_results() -> int:
    data = load_artifact()

    checklist = data.get("checklist", {})
    target = data.get("target", {})
    summary = data.get("summary", {})
    cve_correlation = data.get("cve_correlation", {})
    assessment = data.get("assessment", {})
    results = data.get("results", {})

    print(f"PROJECT: {data.get('project_id')}")
    print(f"STATUS : {checklist.get('status')}")
    print(f"TARGET : {target.get('hostname')}")
    print()

    print(
        "SCHEME PORT METHOD PATH                           "
        "STATUS CLASSIFICATION"
    )
    print("-" * 110)

    probes = results.get("probes", [])
    if not isinstance(probes, list):
        probes = []

    for item in probes:
        scheme = str(item.get("scheme", "-"))
        port = str(item.get("port", "-"))
        method = str(item.get("method", "-"))
        path = str(item.get("path", "-"))
        status = str(item.get("status_code", "-"))
        classification = str(item.get("classification", "-"))

        print(
            f"{scheme:<6} {port:<5} {method:<7} "
            f"{path[:34]:<35} {status:<6} {classification}"
        )

    print()
    print("SUMMARY")
    print("-" * 110)
    if isinstance(summary, dict):
        for key, value in summary.items():
            print(f"{key}: {value}")

    cves = (
        cve_correlation.get("candidates", [])
        if isinstance(cve_correlation, dict)
        else []
    )
    if not isinstance(cves, list):
        cves = []

    print()
    print(f"CVE CANDIDATES: {len(cves)}")

    for cve in cves:
        print(
            f"  - {cve.get('cve_id')}: "
            f"{cve.get('description', '')[:180]}"
        )

    print()
    print("ASSESSMENT")
    print("-" * 110)
    print(f"result          : {assessment.get('result')}")
    print(f"finding         : {assessment.get('finding')}")
    print(f"requires_review : {assessment.get('requires_review')}")
    print(f"summary         : {assessment.get('summary')}")

    return 0


def verify() -> int:
    try:
        data = load_artifact()
    except Exception as exc:
        print(f"[FAIL] Tidak dapat membaca artifact: {exc}")
        return 1

    errors: List[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version harus {SCHEMA_VERSION}")

    if data.get("project_id") != project_id_from_dir(project_dir()):
        errors.append("project_id tidak sesuai active project directory")

    checklist = data.get("checklist", {})
    if not isinstance(checklist, dict):
        errors.append("checklist bukan mapping")
        checklist = {}

    if checklist.get("id") != CHECKLIST_ID:
        errors.append(f"checklist.id harus {CHECKLIST_ID}")

    if checklist.get("status") != "completed":
        errors.append("checklist.status bukan completed")

    target = data.get("target", {})
    if not isinstance(target, dict):
        errors.append("target tidak valid")
        target = {}

    hostname = target.get("hostname")
    if not hostname:
        errors.append("target.hostname kosong")

    authorized_ports = target.get("authorized_ports", [])
    if not isinstance(authorized_ports, list):
        errors.append("target.authorized_ports bukan list")
        authorized_ports = []

    supported_ports = [
        int(port)
        for port in authorized_ports
        if str(port).isdigit() and int(port) in {80, 443}
    ]
    supported_ports = list(dict.fromkeys(supported_ports))

    methodology = data.get("methodology", {})
    if not isinstance(methodology, dict):
        errors.append("methodology bukan mapping")
        methodology = {}

    if methodology.get("endpoint_source") != "Recon directory.yaml":
        errors.append("methodology endpoint source harus Recon directory.yaml")

    if methodology.get("discovery") is not False:
        errors.append("discovery harus False")

    if methodology.get("brute_force") is not False:
        errors.append("brute_force harus False")

    if methodology.get("redirect_following") is not False:
        errors.append("redirect_following harus False")

    if methodology.get("mutation_payload") is not False:
        errors.append("mutation_payload harus False")

    if methodology.get("automatic_finding") is not False:
        errors.append("automatic_finding harus False")

    probe_config = data.get("probe", {})
    if not isinstance(probe_config, dict):
        errors.append("probe bukan mapping")
        probe_config = {}

    if probe_config.get("methods") != METHODS:
        errors.append("probe.methods tidak sesuai GET/HEAD")

    if probe_config.get("authorized_ports") != authorized_ports:
        errors.append("probe.authorized_ports tidak sama dengan target.authorized_ports")

    if probe_config.get("allow_redirects") is not False:
        errors.append("probe.allow_redirects harus False")

    if probe_config.get("verify_tls") is not True:
        errors.append("probe.verify_tls harus True")

    if probe_config.get("request_body_sent") is not False:
        errors.append("probe.request_body_sent harus False")

    baseline = data.get("baseline", {})
    if not isinstance(baseline, dict):
        errors.append("baseline bukan mapping")
        baseline = {}

    recon_count = baseline.get("recon_paths")
    candidate_count = baseline.get("selected_candidates")
    generated_error_paths = baseline.get("generated_error_paths")

    results = data.get("results", {})
    if not isinstance(results, dict):
        errors.append("results bukan mapping")
        results = {}

    candidates = results.get("candidates", [])
    error_paths = results.get("error_paths", [])
    probes = results.get("probes", [])

    if not isinstance(candidates, list):
        errors.append("results.candidates bukan list")
        candidates = []

    if not isinstance(error_paths, list):
        errors.append("results.error_paths bukan list")
        error_paths = []

    if not isinstance(probes, list):
        errors.append("results.probes bukan list")
        probes = []

    if generated_error_paths != len(error_paths):
        errors.append(
            "baseline.generated_error_paths tidak sama dengan results.error_paths"
        )

    if candidate_count != len(candidates):
        errors.append(
            "baseline.selected_candidates tidak sama dengan results.candidates"
        )

    expected_probe_count = (
        len(error_paths)
        * len(METHODS)
        * len(supported_ports)
    )

    if len(probes) != expected_probe_count:
        errors.append(
            f"jumlah probes {len(probes)} != "
            f"error_paths({len(error_paths)}) x "
            f"methods({len(METHODS)}) x "
            f"targets({len(supported_ports)}) "
            f"= {expected_probe_count}"
        )

    expected_pairs = {
        (80, "HTTP"),
        (443, "HTTPS"),
    }
    expected_pairs = {
        pair for pair in expected_pairs
        if pair[0] in supported_ports
    }

    observed_pairs = {
        (item.get("port"), str(item.get("scheme", "")).upper())
        for item in probes
        if isinstance(item, dict)
    }

    if observed_pairs != expected_pairs:
        errors.append(
            "kombinasi target scheme/port tidak sesuai: "
            f"observed={sorted(observed_pairs)} "
            f"expected={sorted(expected_pairs)}"
        )

    required_probe_keys = {
        "url",
        "method",
        "scheme",
        "port",
        "path",
        "classification",
    }

    for index, item in enumerate(probes):
        if not isinstance(item, dict):
            errors.append(f"probe[{index}] bukan mapping")
            continue

        missing = required_probe_keys - set(item.keys())
        if missing:
            errors.append(
                f"probe[{index}] missing keys: "
                f"{', '.join(sorted(missing))}"
            )

        if item.get("method") not in METHODS:
            errors.append(
                f"probe[{index}] method tidak valid: {item.get('method')}"
            )

        if item.get("port") not in {80, 443}:
            errors.append(
                f"probe[{index}] port di luar checklist: {item.get('port')}"
            )

        if item.get("request_body_sent") not in {False, None}:
            errors.append(
                f"probe[{index}] request body seharusnya tidak dikirim"
            )

    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        errors.append("summary bukan mapping")
        summary = {}

    recalculated = summarize_probes(probes)
    for key, value in recalculated.items():
        if summary.get(key) != value:
            errors.append(
                f"summary.{key}={summary.get(key)} "
                f"berbeda dari hasil recalculation={value}"
            )

    cve_correlation = data.get("cve_correlation", {})
    if not isinstance(cve_correlation, dict):
        errors.append("cve_correlation bukan mapping")
        cve_correlation = {}

    cves = cve_correlation.get("candidates", [])
    if not isinstance(cves, list):
        errors.append("cve_correlation.candidates bukan list")
        cves = []

    if cve_correlation.get("candidate_count") != len(cves):
        errors.append("cve_correlation.candidate_count tidak konsisten")

    assessment = data.get("assessment", {})
    if not isinstance(assessment, dict):
        errors.append("assessment bukan mapping")
        assessment = {}

    if assessment.get("finding") is not False:
        errors.append(
            "assessment.finding harus False; "
            "checklist ini tidak membuat automatic vulnerability finding"
        )

    expected_review = bool(
        summary.get("information_disclosure", 0)
        or summary.get("probe_errors", 0)
    )

    if assessment.get("requires_review") != expected_review:
        errors.append(
            "assessment.requires_review tidak sesuai hasil probe"
        )

    if assessment.get("information_disclosure_count") != summary.get(
        "information_disclosure"
    ):
        errors.append(
            "assessment.information_disclosure_count tidak konsisten"
        )

    if assessment.get("probe_error_count") != summary.get("probe_errors"):
        errors.append("assessment.probe_error_count tidak konsisten")

    if assessment.get("cve_candidate_count") != len(cves):
        errors.append("assessment.cve_candidate_count tidak konsisten")

    source_status = data.get("source_status", {})
    if not isinstance(source_status, dict):
        errors.append("source_status bukan mapping")
        source_status = {}

    if source_status.get("directory") in {None, ""}:
        errors.append("source_status.directory kosong")

    if not isinstance(recon_count, int):
        errors.append("baseline.recon_paths bukan integer")

    if not isinstance(candidate_count, int):
        errors.append("baseline.selected_candidates bukan integer")

    if errors:
        print("[FAIL] Error Information Disclosure gagal validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] Error Information Disclosure memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Version   : {APP_VERSION}")
    print(f"[PASS] Status    : {checklist.get('status')}")
    print(f"[PASS] Target    : {target.get('hostname')}")
    print(f"[PASS] Recon     : {recon_count} path(s)")
    print(f"[PASS] Candidates: {candidate_count}")
    print(f"[PASS] ErrorPaths: {len(error_paths)}")
    print(f"[PASS] Methods   : {len(METHODS)}")
    print(f"[PASS] Probes    : {len(probes)}")
    print(
        f"[PASS] Disclosure: "
        f"{summary.get('information_disclosure')}"
    )
    print(f"[PASS] CVE       : {len(cves)} candidate(s)")
    print(
        f"[PASS] Review    : "
        f"{1 if assessment.get('requires_review') else 0}"
    )
    print(
        "[PASS] CVE Triage: error/CVE correlation is candidate "
        "evidence; no automatic finding."
    )
    print(
        "[PASS] Assessment: technical error indicators are "
        "review evidence; no automatic vulnerability finding."
    )

    return 0


def show_version() -> int:
    print(f"errors.py v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("Methods:")
    for method in METHODS:
        print(f"  - {method}")
    print("Endpoint source: Recon directory.yaml")
    print("CVE source: 4-001 version.yaml")
    print("Redirect following: disabled")
    print("Mutation payload: none")
    print("Discovery/brute force: disabled")
    print("Automatic finding: disabled")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "BrebesKab-CSIRT-Tools - "
            "4-010 Error Information Disclosure"
        )
    )

    parser.add_argument(
        "command",
        choices=[
            "version",
            "init",
            "analyze",
            "list",
            "verify",
        ],
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "version":
            return show_version()

        if args.command == "init":
            return initialize_artifact()

        if args.command == "analyze":
            return analyze()

        if args.command == "list":
            return list_results()

        if args.command == "verify":
            return verify()

        parser.error("Command tidak dikenal.")
        return 2

    except KeyboardInterrupt:
        print("\n[FAIL] Dihentikan oleh pengguna.")
        return 130

    except Exception as exc:
        print(f"[FAIL] {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
