#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Web Server Assessment - 4-008 Debug Exposure

Version : 1.0.0
Schema  : 1.0

Purpose
-------
Controlled assessment for production debug exposure.

Design:
- Uses authorized project scope as target authority.
- Uses Recon directory.yaml as endpoint source; no discovery/brute force.
- Correlates prior 4-010 error evidence as supporting evidence only.
- Correlates CVE candidates from 4-001 version.yaml as heuristic evidence only.
- Tests HTTP and HTTPS separately.
- GET and HEAD only.
- Does not follow redirects.
- Does not send mutation payloads.
- Stores raw probe evidence for auditability.
- Does not automatically declare a vulnerability.
- Framework identification alone is not a vulnerability.
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


APP_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"

CHECKLIST_ID = "4-008"
CHECKLIST_NAME = "Debug Exposure"

METHODS = ["GET", "HEAD"]

DEFAULT_TIMEOUT = 15
MAX_BODY_BYTES = 65536

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_ROOT = PROJECT_ROOT / "projects"

RECON_DIRECTORY_REL = Path("02-reconnaissance") / "directory" / "directory.yaml"
VERSION_ARTIFACT_REL = (
    Path("04-web-server-configuration") / "version" / "version.yaml"
)
SCOPE_REL = Path("01-preparation") / "scope" / "scope.yaml"

WEBSERVER_REL = Path("04-web-server-configuration") / "debug"
ARTIFACT_NAME = "debug.yaml"
EVIDENCE_NAME = "debug-probes.json"

ERRORS_ARTIFACT_REL = (
    Path("04-web-server-configuration") / "errors" / "errors.yaml"
)

USER_AGENT = "BrebesKab-CSIRT-Tools/4-008"

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}

# These are evidence indicators, not automatic vulnerability findings.
INDICATORS = {
    "debugbar": (
        r"\bdebugbar\b",
        r"\bdebugbar_loader\b",
        r"\bdebugbar_dynamic_script\b",
        r"\bdebugbar_dynamic_style\b",
    ),
    "kint": (
        r"\bkint\b",
        r"\bkint-rich-script\b",
        r"\bkint-rich\b",
    ),
    "debug_toolbar": (
        r"\bdebug\s*toolbar\b",
        r"\bdebug-toolbar\b",
        r"\btoolbar\b.{0,100}\bdebug\b",
    ),
    "stack_trace": (
        r"\bstack\s*trace\b",
        r"\bstacktrace\b",
        r"\btraceback\b",
        r'"trace"\s*:\s*\[',
        r"\bcaused by:\b",
    ),
    "exception_detail": (
        r"\b[A-Za-z_][A-Za-z0-9_\\]*Exception\b",
        r"\bPageNotFoundException\b",
        r"\bErrorException\b",
    ),
    "filesystem_path": (
        r"(?i)(?:/home|/var/www|/var/apps|/srv/www|/opt)[^<>\r\n]{2,}",
        r"(?i)[A-Za-z]:\\(?:[^\\\r\n]+\\)+",
    ),
    "runtime_debug": (
        r"\bmemory(?: usage|_usage)\b",
        r"\bexecution(?: time|_time)\b",
        r"\bloaded files?\b",
        r"\brequest(?: information|_information)\b",
        r"\benvironment(?: information|_information)\b",
        r"\bqueries?\b",
    ),
    "framework_debug": (
        r"\bcodeigniter\b",
        r"\bci_debug\b",
        r"\bdebugbar\b",
        r"\bkint\b",
    ),
    "source_code_marker": (
        r"<\?php",
        r"\bnamespace\s+[A-Za-z_][\w\\]*\s*;",
        r"\bfunction\s+[A-Za-z_]\w*\s*\(",
    ),
    "debug_header": (
        r"(?i)\bx-debug\b",
        r"(?i)\bx-debug-token\b",
        r"(?i)\bx-debug-token-link\b",
    ),
}

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
        json.dump(data, handle, ensure_ascii=False, indent=2)


def project_id_from_dir(project_dir_path: Path) -> str:
    return project_dir_path.name


def find_current_project_id() -> str:
    candidates = (
        sorted([p.name for p in PROJECTS_ROOT.iterdir() if p.is_dir()])
        if PROJECTS_ROOT.exists()
        else []
    )

    preferred = [p for p in candidates if p.upper().startswith("PENTEST-")]

    if len(preferred) == 1:
        return preferred[0]

    if len(preferred) > 1:
        return preferred[-1]

    raise RuntimeError(
        f"Tidak dapat menentukan project pada: {PROJECTS_ROOT}"
    )


def project_dir() -> Path:
    return PROJECTS_ROOT / find_current_project_id()


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


def errors_artifact_path() -> Path:
    return project_dir() / ERRORS_ARTIFACT_REL


def get_scope_entries(scope_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    scope = scope_data.get("scope", {})
    if not isinstance(scope, dict):
        return []

    entries = scope.get("in_scope", [])
    if not isinstance(entries, list):
        return []

    return [entry for entry in entries if isinstance(entry, dict)]


def get_authorized_targets(
    scope_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
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

        normalized_ports = [
            port for port in normalized_ports if port in {80, 443}
        ]

        targets.append(
            {
                "scope_id": entry.get("scope_id"),
                "type": "domain",
                "value": value,
                "ports": sorted(set(normalized_ports)),
            }
        )

    return targets


def choose_primary_scope(
    scope_data: Dict[str, Any],
) -> Dict[str, Any]:
    targets = get_authorized_targets(scope_data)

    if not targets:
        raise ValueError(
            "Domain target tidak ditemukan pada scope.in_scope."
        )

    target = targets[0]

    if not target["ports"]:
        raise ValueError(
            "Scope target tidak memiliki port 80/443 untuk checklist 4-008."
        )

    return target


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

    value = value.split("#", 1)[0]

    if not value.startswith("/"):
        value = "/" + value

    value = re.sub(r"/{2,}", "/", value)

    return value or "/"


def is_skip_path(path: str) -> bool:
    clean = path.split("?", 1)[0].rstrip("/") or "/"
    return clean in {"/robots.txt", "/favicon.ico"}


def extract_recon_results(
    data: Dict[str, Any],
) -> List[Dict[str, Any]]:
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


def build_candidates(
    recon_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Use consolidated Recon paths only.

    No new directory discovery or brute force is performed.
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
    values.sort(key=lambda item: item["path"].lower())

    return values


def load_prior_debug_paths() -> List[str]:
    """
    Read 4-010 only as supporting correlation.

    It does not expand the authoritative Recon endpoint source.
    """
    path = errors_artifact_path()

    if not path.exists():
        return []

    try:
        data = load_yaml(path)
    except Exception:
        return []

    block = data.get("errors", {})
    if not isinstance(block, dict):
        return []

    probes = block.get("probes", [])
    if not isinstance(probes, list):
        return []

    paths: set[str] = set()

    for item in probes:
        if not isinstance(item, dict):
            continue

        indicators = item.get("indicators", {})
        classification = str(
            item.get("classification", "")
        ).lower()

        if (
            classification == "error-information-disclosure"
            or (
                isinstance(indicators, dict)
                and indicators.get("technical_disclosure_indicator")
            )
        ):
            path = normalize_path(str(item.get("path", "")))
            if path:
                paths.add(path)

    return sorted(paths)


def load_version_cves() -> List[Dict[str, Any]]:
    """
    Heuristic CVE correlation from the existing 4-001 artifact.

    This function intentionally does not declare applicability.
    """
    path = version_artifact_path()

    if not path.exists():
        return []

    try:
        data = load_yaml(path)
    except Exception:
        return []

    selected: List[Dict[str, Any]] = []
    seen: set[str] = set()

    def walk(value: Any) -> Iterable[Dict[str, Any]]:
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)

    keywords = (
        "debug",
        "error",
        "exception",
        "information disclosure",
        "stack trace",
        "http response",
        "http request",
        "http server",
    )

    for item in walk(data):
        cve_id = (
            item.get("cve_id")
            or item.get("id")
            or item.get("cve")
        )

        if not cve_id:
            continue

        cve_id = str(cve_id).strip()

        description_parts = []
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
            continue

        if cve_id in seen:
            continue

        seen.add(cve_id)

        selected.append(
            {
                "cve_id": cve_id,
                "description": description,
                "source": str(path),
                "correlation": (
                    "debug/error-related keyword correlation from 4-001"
                ),
                "classification": "cve-candidate",
            }
        )

    return selected


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


def response_headers_subset(
    headers: requests.structures.CaseInsensitiveDict,
) -> Dict[str, str]:
    interesting = (
        "server",
        "content-type",
        "content-length",
        "location",
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
    return sample.decode("utf-8", errors="replace")


def detect_indicators(body_text: str) -> Dict[str, Any]:
    detected: Dict[str, List[str]] = {}

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

    lower = body_text.lower()

    framework_mentions = [
        name for name in FRAMEWORK_NAMES
        if name in lower
    ]

    high_confidence = sorted(
        category
        for category in detected
        if category in {
            "debugbar",
            "kint",
            "debug_toolbar",
            "stack_trace",
            "exception_detail",
            "runtime_debug",
            "debug_header",
        }
    )

    technical_disclosure = bool(
        high_confidence
        or detected.get("filesystem_path")
        or detected.get("source_code_marker")
    )

    return {
        "detected": detected,
        "categories": sorted(detected.keys()),
        "framework_mentions": framework_mentions,
        "high_confidence_categories": high_confidence,
        "technical_disclosure_indicator": technical_disclosure,
    }


def classify_debug_response(
    status_code: Optional[int],
    indicators: Dict[str, Any],
) -> str:
    if status_code is None:
        return "probe-error"

    high_confidence = indicators.get("high_confidence_categories", [])

    if high_confidence:
        return "debug-information-disclosure"

    if indicators.get("technical_disclosure_indicator"):
        return "technical-information-disclosure"

    if 300 <= status_code <= 399:
        return "redirected"

    if status_code in {401, 403}:
        return "access-controlled"

    if status_code == 404:
        return "not-found"

    if 500 <= status_code <= 599:
        return "server-error"

    return "no-debug-indicator"


def probe_debug(
    session: requests.Session,
    url: str,
    method: str,
    source: str,
    prior_4_010: bool,
    prior_4_010_path: bool,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "url": url,
        "method": method,
        "started_at": utc_now(),
        "allow_redirects": False,
        "timeout_seconds": DEFAULT_TIMEOUT,
        "request_body_sent": False,
        "endpoint_source": source,
        "prior_4_010_correlation": prior_4_010,
        "prior_4_010_path_correlation": prior_4_010_path,
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
        indicators = detect_indicators(body_text)

        result.update(
            {
                "status_code": response.status_code,
                "reason": response.reason,
                "headers": response_headers_subset(response.headers),
                "server": response.headers.get("Server"),
                "location": response.headers.get("Location"),
                "content_type": response.headers.get("Content-Type"),
                "content_length": len(response.content),
                "body_sample_length": len(body),
                "body_sha256": sha256_bytes(body),
                "body_sample": body_text,
                "indicators": indicators,
                "classification": classify_debug_response(
                    response.status_code,
                    indicators,
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
        "debug_information_disclosure": 0,
        "technical_information_disclosure": 0,
        "no_debug_indicator": 0,
        "not_found": 0,
        "access_controlled": 0,
        "redirected": 0,
        "server_errors": 0,
        "probe_errors": 0,
        "other": 0,
    }

    for item in probes:
        classification = item.get("classification")

        if classification == "debug-information-disclosure":
            summary["debug_information_disclosure"] += 1
        elif classification == "technical-information-disclosure":
            summary["technical_information_disclosure"] += 1
        elif classification == "no-debug-indicator":
            summary["no_debug_indicator"] += 1
        elif classification == "not-found":
            summary["not_found"] += 1
        elif classification == "access-controlled":
            summary["access_controlled"] += 1
        elif classification == "redirected":
            summary["redirected"] += 1
        elif classification == "server-error":
            summary["server_errors"] += 1
        elif classification == "probe-error":
            summary["probe_errors"] += 1
        else:
            summary["other"] += 1

    return summary


def assessment_from_probes(
    probes: List[Dict[str, Any]],
    cves: List[Dict[str, Any]],
) -> Dict[str, Any]:
    debug_disclosures = [
        item for item in probes
        if item.get("classification") == "debug-information-disclosure"
    ]

    technical_disclosures = [
        item for item in probes
        if item.get("classification")
        == "technical-information-disclosure"
    ]

    probe_errors = [
        item for item in probes
        if item.get("classification") == "probe-error"
    ]

    requires_review = bool(
        debug_disclosures
        or technical_disclosures
        or probe_errors
    )

    if probe_errors:
        status = "probe-errors"
        summary = (
            "Debug exposure probing menghasilkan probe error dan "
            "memerlukan review. Tidak ada automatic vulnerability finding."
        )
    elif debug_disclosures:
        status = "debug-exposure-review"
        summary = (
            "Satu atau lebih response menunjukkan debug information "
            "yang terekspos kepada client. Evidence dicatat untuk manual "
            "review. Tidak ada automatic vulnerability finding."
        )
    elif technical_disclosures:
        status = "technical-disclosure-review"
        summary = (
            "Response menunjukkan technical information yang berpotensi "
            "berhubungan dengan debug exposure. Evidence dicatat untuk "
            "manual review. Tidak ada automatic vulnerability finding."
        )
    else:
        status = "no-debug-exposure-observed"
        summary = (
            "Controlled response tidak menunjukkan indikator debug "
            "exposure pada body yang diuji. Identifikasi framework/server "
            "saja tidak otomatis dikategorikan sebagai vulnerability."
        )

    return {
        "status": status,
        "finding": False,
        "requires_review": requires_review,
        "debug_information_disclosure_count": len(debug_disclosures),
        "technical_information_disclosure_count": len(
            technical_disclosures
        ),
        "probe_error_count": len(probe_errors),
        "cve_candidate_count": len(cves),
        "summary": summary,
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
    candidates = build_candidates(recon_data)
    prior_paths = load_prior_debug_paths()

    data = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id_from_dir(project_dir()),
        "updated_at": utc_now(),
        "debug": {
            "status": "initialized",
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": "Bangsaku",
            "target": {
                "type": target["type"],
                "value": target["value"],
                "ports": target["ports"],
                "scope_id": target.get("scope_id"),
            },
            "method_set": METHODS,
            "endpoint_source": {
                "type": "recon-directory",
                "path": str(recon_path),
                "recon_paths": len(recon_results),
                "selected_candidates": len(candidates),
            },
            "prior_4_010": {
                "artifact": str(errors_artifact_path()),
                "correlated_paths": prior_paths,
                "correlated_path_count": len(prior_paths),
            },
            "probes": [],
            "summary": {
                "probes": 0,
                "debug_information_disclosure": 0,
                "technical_information_disclosure": 0,
                "no_debug_indicator": 0,
                "not_found": 0,
                "access_controlled": 0,
                "redirected": 0,
                "server_errors": 0,
                "probe_errors": 0,
                "other": 0,
            },
            "cve_candidates": [],
            "assessment": {
                "status": "initialized",
                "finding": False,
                "requires_review": False,
                "summary": (
                    "Artifact diinisialisasi; belum dilakukan "
                    "debug-exposure probing."
                ),
            },
            "assessment_policy": {
                "automatic_finding": False,
                "notes": [
                    "Debug indicators are evidence, not automatic vulnerabilities.",
                    "Framework identification alone is not a vulnerability.",
                    "No redirect following is performed.",
                    "No mutation payload is intentionally sent.",
                    "No brute-force directory discovery is performed.",
                    "4-010 evidence is supporting correlation only.",
                    "CVE correlation is heuristic candidate evidence only.",
                    "Raw evidence is retained for auditability.",
                ],
            },
        },
    }

    save_yaml(artifact_path(), data)

    print("[PASS] Debug Exposure berhasil diinisialisasi.")
    print(f"PROJECT         : {data['project_id']}")
    print(f"TARGET          : {target['value']}")
    print(f"PORTS           : {', '.join(map(str, target['ports']))}")
    print(f"METHODS         : {', '.join(METHODS)}")
    print(f"RECON PATHS     : {len(recon_results)}")
    print(f"CANDIDATES      : {len(candidates)}")
    print(
        f"4-010 CORRELATION: {len(prior_paths)} path(s)"
    )
    print(f"SOURCE          : {recon_path}")
    print(f"FILE            : {artifact_path()}")

    return 0


def analyze() -> int:
    scope = load_project_scope()
    target = choose_primary_scope(scope)

    recon_path = recon_directory_path()
    recon_data = load_yaml(recon_path)
    recon_results = extract_recon_results(recon_data)
    candidates = build_candidates(recon_data)

    prior_paths = set(load_prior_debug_paths())
    cves = load_version_cves()

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    probes: List[Dict[str, Any]] = []

    for candidate in candidates:
        path = candidate["path"]

        for scheme_label, scheme, port, url in build_urls(
            target["value"],
            target["ports"],
            path,
        ):
            for method in METHODS:
                result = probe_debug(
                    session=session,
                    url=url,
                    method=method,
                    source="recon-directory",
                    prior_4_010=path in prior_paths,
                    prior_4_010_path=path in prior_paths,
                )

                result.update(
                    {
                        "scheme": scheme_label,
                        "scheme_lower": scheme,
                        "port": port,
                        "path": path,
                    }
                )

                probes.append(result)

    summary = summarize_probes(probes)
    assessment = assessment_from_probes(probes, cves)

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id_from_dir(project_dir()),
        "updated_at": utc_now(),
        "debug": {
            "status": "completed",
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": "Bangsaku",
            "target": {
                "type": target["type"],
                "value": target["value"],
                "ports": target["ports"],
                "scope_id": target.get("scope_id"),
            },
            "method_set": METHODS,
            "endpoint_source": {
                "type": "recon-directory",
                "path": str(recon_path),
                "recon_paths": len(recon_results),
                "selected_candidates": len(candidates),
            },
            "prior_4_010": {
                "artifact": str(errors_artifact_path()),
                "correlated_paths": sorted(prior_paths),
                "correlated_path_count": len(prior_paths),
            },
            "probes": probes,
            "summary": summary,
            "cve_candidates": cves,
            "assessment": assessment,
            "assessment_policy": {
                "automatic_finding": False,
                "notes": [
                    "Debug indicators are evidence, not automatic vulnerabilities.",
                    "Framework identification alone is not a vulnerability.",
                    "No redirect following is performed.",
                    "No mutation payload is intentionally sent.",
                    "No brute-force directory discovery is performed.",
                    "4-010 evidence is supporting correlation only.",
                    "CVE correlation is heuristic candidate evidence only.",
                    "Raw evidence is retained for auditability.",
                ],
            },
        },
    }

    save_yaml(artifact_path(), artifact)

    raw_evidence = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id_from_dir(project_dir()),
        "generated_at": utc_now(),
        "checklist_id": CHECKLIST_ID,
        "target": target,
        "methods": METHODS,
        "endpoint_source": {
            "type": "recon-directory",
            "path": str(recon_path),
            "recon_paths": len(recon_results),
            "selected_candidates": len(candidates),
        },
        "prior_4_010": {
            "artifact": str(errors_artifact_path()),
            "correlated_paths": sorted(prior_paths),
        },
        "probes": probes,
    }

    save_json(evidence_path(), raw_evidence)

    print("[PASS] Debug Exposure berhasil dianalisis.")
    print(f"PROJECT         : {artifact['project_id']}")
    print(f"TARGET          : {target['value']}")
    print(f"ENDPOINTS       : {len(candidates)}")
    print(f"METHODS         : {len(METHODS)}")
    print(f"PROBES          : {summary['probes']}")
    print(
        f"DEBUG DISCLOSURE: "
        f"{summary['debug_information_disclosure']}"
    )
    print(
        f"TECHNICAL INFO  : "
        f"{summary['technical_information_disclosure']}"
    )
    print(f"NO INDICATOR    : {summary['no_debug_indicator']}")
    print(f"ACCESS CONTROL  : {summary['access_controlled']}")
    print(f"REDIRECTED      : {summary['redirected']}")
    print(f"NOT FOUND       : {summary['not_found']}")
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
    block = data.get("debug", {})

    print(f"PROJECT: {data.get('project_id')}")
    print(f"STATUS : {block.get('status')}")
    print(f"TARGET : {block.get('target', {}).get('value')}")
    print()

    print(
        "SCHEME PORT METHOD PATH                           "
        "STATUS CLASSIFICATION"
    )
    print("-" * 115)

    probes = block.get("probes", [])
    if not isinstance(probes, list):
        probes = []

    for item in probes:
        scheme = str(item.get("scheme", "-"))
        port = str(item.get("port", "-"))
        method = str(item.get("method", "-"))
        path = str(item.get("path", "-"))
        status = str(item.get("status_code", "-"))
        classification = str(
            item.get("classification", "-")
        )

        print(
            f"{scheme:<6} {port:<5} {method:<7} "
            f"{path[:34]:<35} {status:<6} {classification}"
        )

    summary = block.get("summary", {})
    print()
    print("SUMMARY")
    print("-" * 115)

    for key, value in summary.items():
        print(f"{key}: {value}")

    cves = block.get("cve_candidates", [])
    print()
    print(f"CVE CANDIDATES: {len(cves)}")

    for cve in cves:
        print(
            f"  - {cve.get('cve_id')}: "
            f"{cve.get('description', '')[:180]}"
        )

    assessment = block.get("assessment", {})
    print()
    print("ASSESSMENT")
    print("-" * 115)
    print(f"status          : {assessment.get('status')}")
    print(f"finding         : {assessment.get('finding')}")
    print(
        f"requires_review : "
        f"{assessment.get('requires_review')}"
    )
    print(f"summary         : {assessment.get('summary')}")

    prior = block.get("prior_4_010", {})
    if isinstance(prior, dict):
        print()
        print("4-010 CORRELATION")
        print("-" * 115)
        print(
            f"paths           : "
            f"{prior.get('correlated_path_count', 0)}"
        )
        for path in prior.get("correlated_paths", []):
            print(f"  - {path}")

    return 0


def verify() -> int:
    try:
        data = load_artifact()
    except Exception as exc:
        print(f"[FAIL] Tidak dapat membaca artifact: {exc}")
        return 1

    block = data.get("debug")

    if not isinstance(block, dict):
        print("[FAIL] Block debug tidak ditemukan.")
        return 1

    errors: List[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version harus {SCHEMA_VERSION}"
        )

    if block.get("checklist_id") != CHECKLIST_ID:
        errors.append(
            f"checklist_id harus {CHECKLIST_ID}"
        )

    if block.get("status") != "completed":
        errors.append("status artifact bukan completed")

    target = block.get("target", {})
    if not isinstance(target, dict):
        errors.append("target tidak valid")
        target = {}

    if not target.get("value"):
        errors.append("target.value kosong")

    method_set = block.get("method_set")
    if method_set != METHODS:
        errors.append("method_set tidak sesuai dengan GET/HEAD")

    endpoint_source = block.get("endpoint_source", {})
    if not isinstance(endpoint_source, dict):
        errors.append("endpoint_source tidak valid")
        endpoint_source = {}

    if endpoint_source.get("type") != "recon-directory":
        errors.append(
            "endpoint source harus recon-directory"
        )

    recon_count = endpoint_source.get("recon_paths")
    candidate_count = endpoint_source.get("selected_candidates")

    if not isinstance(recon_count, int):
        errors.append(
            "endpoint_source.recon_paths bukan integer"
        )

    if not isinstance(candidate_count, int):
        errors.append(
            "endpoint_source.selected_candidates bukan integer"
        )

    probes = block.get("probes", [])
    summary = block.get("summary", {})
    cves = block.get("cve_candidates", [])

    if not isinstance(probes, list):
        errors.append("probes bukan list")
        probes = []

    if not isinstance(summary, dict):
        errors.append("summary bukan mapping")
        summary = {}

    if not isinstance(cves, list):
        errors.append("cve_candidates bukan list")
        cves = []

    target_ports = target.get("ports", [])
    if not isinstance(target_ports, list):
        target_ports = []

    supported_ports = []
    for port in target_ports:
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            continue
        if port_int in {80, 443}:
            supported_ports.append(port_int)

    supported_ports = list(dict.fromkeys(supported_ports))

    expected_probe_count = (
        candidate_count
        * len(METHODS)
        * len(supported_ports)
        if isinstance(candidate_count, int)
        else 0
    )

    if len(probes) != expected_probe_count:
        errors.append(
            f"jumlah probes {len(probes)} != "
            f"candidates({candidate_count}) x "
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
        "indicators",
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
                f"probe[{index}] method tidak valid: "
                f"{item.get('method')}"
            )

        if item.get("port") not in {80, 443}:
            errors.append(
                f"probe[{index}] port di luar checklist: "
                f"{item.get('port')}"
            )

        if item.get("request_body_sent") not in {False, None}:
            errors.append(
                f"probe[{index}] request body seharusnya tidak dikirim"
            )

        if item.get("allow_redirects") is not False:
            errors.append(
                f"probe[{index}] redirect following harus disabled"
            )

    recalculated = summarize_probes(probes)

    for key, value in recalculated.items():
        if summary.get(key) != value:
            errors.append(
                f"summary.{key}={summary.get(key)} "
                f"berbeda dari hasil recalculation={value}"
            )

    assessment = block.get("assessment", {})

    if not isinstance(assessment, dict):
        errors.append("assessment bukan mapping")
        assessment = {}

    if assessment.get("finding") is not False:
        errors.append(
            "assessment.finding harus False; "
            "checklist ini tidak membuat automatic vulnerability finding"
        )

    expected_review = bool(
        summary.get("debug_information_disclosure", 0)
        or summary.get("technical_information_disclosure", 0)
        or summary.get("probe_errors", 0)
    )

    if assessment.get("requires_review") != expected_review:
        errors.append(
            "assessment.requires_review tidak sesuai hasil probe"
        )

    if len(cves) != int(
        assessment.get("cve_candidate_count", len(cves))
    ):
        errors.append(
            "cve_candidate_count tidak konsisten"
        )

    prior = block.get("prior_4_010", {})
    if not isinstance(prior, dict):
        errors.append("prior_4_010 bukan mapping")
    else:
        correlated_paths = prior.get("correlated_paths", [])
        correlated_count = prior.get("correlated_path_count")
        if not isinstance(correlated_paths, list):
            errors.append(
                "prior_4_010.correlated_paths bukan list"
            )
        elif correlated_count != len(correlated_paths):
            errors.append(
                "prior_4_010.correlated_path_count tidak konsisten"
            )

    if errors:
        print("[FAIL] Debug Exposure gagal validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] Debug Exposure memenuhi validasi.")
    print(
        f"[PASS] Checklist : "
        f"{CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(f"[PASS] Status    : {block.get('status')}")
    print(f"[PASS] Target    : {target.get('value')}")
    print(f"[PASS] Recon     : {recon_count} path(s)")
    print(f"[PASS] Candidates: {candidate_count}")
    print(f"[PASS] Methods   : {len(METHODS)}")
    print(f"[PASS] Probes    : {len(probes)}")
    print(
        f"[PASS] Debug     : "
        f"{summary.get('debug_information_disclosure')}"
    )
    print(
        f"[PASS] Technical : "
        f"{summary.get('technical_information_disclosure')}"
    )
    print(f"[PASS] CVE       : {len(cves)} candidate(s)")
    print(
        f"[PASS] Review    : "
        f"{1 if assessment.get('requires_review') else 0}"
    )
    print(
        "[PASS] CVE Triage: debug/CVE correlation is candidate "
        "evidence; no automatic finding."
    )
    print(
        "[PASS] Assessment: debug indicators are review evidence; "
        "no automatic vulnerability finding."
    )

    return 0


def show_version() -> int:
    print(f"debug.py v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("Methods:")
    for method in METHODS:
        print(f"  - {method}")
    print("Endpoint source: Recon directory.yaml")
    print("Supporting evidence: 4-010 errors.yaml")
    print("CVE source: 4-001 version.yaml")
    print("Redirect following: disabled")
    print("Mutation payload: none")
    print("Discovery/brute force: disabled")
    print("Automatic finding: disabled")
    print("Raw evidence: retained")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "BrebesKab-CSIRT-Tools - "
            "4-008 Debug Exposure"
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
