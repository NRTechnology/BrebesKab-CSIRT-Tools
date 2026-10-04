#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Web Server Assessment - 4-009 HTTP Methods Exposure

Controlled HTTP method assessment for:
    GET, HEAD, POST, OPTIONS, PUT, PATCH, DELETE, TRACE

Design:
- Uses the authorized project scope as the source of target authority.
- Uses Recon directory.yaml as the endpoint source; no discovery/brute force.
- Tests HTTP and HTTPS separately.
- Does not follow redirects.
- Does not send mutation payloads or perform application CRUD operations.
- Stores raw probe evidence for auditability.
- Correlates CVE candidates from 4-001 version.yaml as heuristic evidence only.
- Does not automatically declare a vulnerability from an accepted method or CVE match.

Commands:
    python methods.py version
    python methods.py init
    python methods.py analyze
    python methods.py list
    python methods.py verify
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


APP_VERSION = "1.0.2"
SCHEMA_VERSION = "1.0"

CHECKLIST_ID = "4-009"
CHECKLIST_NAME = "HTTP Methods / HTTP Method Exposure"

METHODS = [
    "GET",
    "HEAD",
    "POST",
    "OPTIONS",
    "PUT",
    "PATCH",
    "DELETE",
    "TRACE",
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

WEBSERVER_REL = Path("04-web-server-configuration") / "methods"
ARTIFACT_NAME = "methods.yaml"
EVIDENCE_NAME = "methods-probes.json"

USER_AGENT = "BrebesKab-CSIRT-Tools/4-009"

DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
}

# Method testing is intentionally limited to harmless/observational requests.
# No request body is sent for POST/PUT/PATCH/DELETE.
SAFE_METHODS = set(METHODS)

DIRECTORY_LIKE_FALLBACKS = {
    "assets",
    "backup",
    "cgi-bin",
    "controlpanel",
    "cpanel",
    "dashboard",
    "data",
    "docs",
    "files",
    "images",
    "isp",
    "livechat",
    "login",
    "logout",
    "myadmin",
    "phpmyadmin",
    "phpMyAdmin",
    "setting",
    "storage",
    "upload",
    "uploads",
    "user",
    "webapp",
    "webmail",
}

SKIP_PATH_PATTERNS = (
    "/robots.txt",
    "/favicon.ico",
)

FILE_EXTENSIONS = (
    ".7z",
    ".bak",
    ".backup",
    ".bin",
    ".bz2",
    ".conf",
    ".css",
    ".csv",
    ".doc",
    ".docx",
    ".gz",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".log",
    ".map",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".tgz",
    ".txt",
    ".webmanifest",
    ".webp",
    ".woff",
    ".woff2",
    ".xls",
    ".xlsx",
    ".xml",
    ".zip",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


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


def project_id_from_dir(project_dir: Path) -> str:
    return project_dir.name


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
        # Prefer the latest lexicographically only when the repository
        # contains more than one project and no explicit selector exists.
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

        normalized_ports = []
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

    # Current project uses a single authorized domain. If multiple exist,
    # process the first deterministically and preserve the scope evidence.
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

    # Avoid fragment testing.
    value = value.split("#", 1)[0]

    # Do not preserve an accidental double slash except root.
    value = re.sub(r"/{2,}", "/", value)

    return value or "/"


def path_extension(path: str) -> str:
    clean = path.split("?", 1)[0].lower()
    final = clean.rstrip("/").rsplit("/", 1)[-1]
    if "." not in final:
        return ""
    return "." + final.rsplit(".", 1)[-1]


def is_file_like(path: str) -> bool:
    return path_extension(path) in FILE_EXTENSIONS


def is_skip_path(path: str) -> bool:
    clean = path.split("?", 1)[0].rstrip("/") or "/"
    return clean in SKIP_PATH_PATTERNS


def is_directory_candidate(path: str, classification: str, status_code: Any) -> bool:
    path = normalize_path(path) or "/"
    classification = str(classification or "").lower()

    if path == "/":
        return True

    if is_skip_path(path):
        return False

    if is_file_like(path):
        return False

    if path.endswith("/"):
        return True

    if classification in {
        "discovery-candidate",
        "interesting",
        "directory",
        "directory-candidate",
    }:
        return True

    try:
        code = int(status_code)
    except (TypeError, ValueError):
        code = 0

    last = path.rstrip("/").rsplit("/", 1)[-1]
    if last in DIRECTORY_LIKE_FALLBACKS:
        return True

    if code in {301, 302, 303, 307, 308}:
        return True

    return False


def extract_recon_results(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    directory_block = data.get("directory", {})

    if not isinstance(directory_block, dict):
        return []

    results = directory_block.get("results", [])

    if not isinstance(results, list):
        return []

    output = []
    for item in results:
        if isinstance(item, dict):
            output.append(item)

    return output


def build_endpoint_candidates(
    recon_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    results = extract_recon_results(recon_data)

    selected: Dict[str, Dict[str, Any]] = {}

    # Always include the authorized root baseline.
    selected["/"] = {
        "path": "/",
        "source": "baseline",
        "source_classification": "authorized-baseline",
        "source_status_code": 200,
        "source_url": None,
    }

    for item in results:
        path = normalize_path(
            item.get("path")
            or item.get("uri")
            or item.get("endpoint")
            or item.get("url")
            or ""
        )

        if not path:
            continue

        if not is_directory_candidate(
            path,
            item.get("classification", ""),
            item.get("status_code"),
        ):
            continue

        if is_skip_path(path):
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

    # Deterministic ordering: root first, then lexical.
    values = list(selected.values())
    values.sort(
        key=lambda item: (
            0 if item["path"] == "/" else 1,
            item["path"].lower(),
        )
    )
    return values


def classify_method_response(
    method: str,
    status_code: int,
    headers: Dict[str, str],
    body: bytes,
) -> str:
    if status_code in {401, 403}:
        return "method-access-controlled"

    if status_code == 405:
        return "method-not-allowed"

    if status_code in {400, 408, 413, 414, 415, 422, 429}:
        return "method-request-rejected"

    if status_code in {301, 302, 303, 307, 308}:
        return "method-redirected"

    if status_code == 404:
        return "method-not-found"

    if 500 <= status_code <= 599:
        return "method-server-error"

    allow = headers.get("allow", "")
    if method in {"OPTIONS"} and status_code < 400:
        return "method-accepted"

    if 200 <= status_code <= 299:
        return "method-accepted"

    if 300 <= status_code <= 399:
        return "method-redirected"

    if body:
        return "method-other-response"

    return "method-other"


def response_headers_subset(headers: requests.structures.CaseInsensitiveDict) -> Dict[str, str]:
    interesting = (
        "server",
        "allow",
        "location",
        "content-type",
        "content-length",
        "www-authenticate",
        "access-control-allow-methods",
        "access-control-allow-origin",
        "x-powered-by",
        "x-generator",
        "x-runtime",
    )

    output: Dict[str, str] = {}

    for key in interesting:
        value = headers.get(key)
        if value is not None:
            output[key] = value

    return output


def safe_body_sample(body: bytes) -> str:
    # Keep raw evidence bounded. This is not intended to redact evidence.
    sample = body[:MAX_BODY_BYTES]

    try:
        text = sample.decode("utf-8", errors="replace")
    except Exception:
        text = repr(sample)

    return text


def probe_method(
    session: requests.Session,
    url: str,
    method: str,
) -> Dict[str, Any]:
    started = utc_now()

    result: Dict[str, Any] = {
        "url": url,
        "method": method,
        "started_at": started,
        "allow_redirects": False,
        "timeout_seconds": DEFAULT_TIMEOUT,
        "request_body_sent": False,
    }

    try:
        response = session.request(
            method=method,
            url=url,
            headers=DEFAULT_HEADERS,
            allow_redirects=False,
            timeout=DEFAULT_TIMEOUT,
            verify=True,
            # Explicitly no data/body for all methods.
            data=None,
        )

        body = response.content[:MAX_BODY_BYTES]
        headers = response_headers_subset(response.headers)

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
                "body_sample": safe_body_sample(body),
                "classification": classify_method_response(
                    method,
                    response.status_code,
                    response.headers,
                    body,
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


def build_urls(
    domain: str,
    ports: Iterable[int],
    path: str,
) -> List[Tuple[str, str, int]]:
    output = []

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
    path = version_artifact_path()

    if not path.exists():
        return []

    try:
        data = load_yaml(path)
    except Exception:
        return []

    candidates: List[Dict[str, Any]] = []

    def walk(value: Any) -> Iterable[Dict[str, Any]]:
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)

    keywords = (
        "http method",
        "method handling",
        "request method",
        "trace",
        "put",
        "patch",
        "delete",
        "options",
        "webdav",
        "request smuggling",
        "http request",
        "http request parsing",
    )

    seen = set()

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

        candidates.append(
            {
                "cve_id": cve_id,
                "description": description,
                "source": str(path),
                "correlation": "http-method-related keyword match",
                "classification": "cve-candidate",
            }
        )

    return candidates


def summarize_probes(
    probes: List[Dict[str, Any]],
) -> Dict[str, int]:
    summary = {
        "probes": len(probes),
        "accepted": 0,
        "rejected": 0,
        "not_allowed": 0,
        "access_controlled": 0,
        "redirected": 0,
        "not_found": 0,
        "server_errors": 0,
        "request_rejected": 0,
        "probe_errors": 0,
        "other": 0,
    }

    for item in probes:
        classification = item.get("classification")

        if classification == "method-accepted":
            summary["accepted"] += 1
        elif classification == "method-not-allowed":
            summary["not_allowed"] += 1
        elif classification == "method-access-controlled":
            summary["access_controlled"] += 1
        elif classification == "method-redirected":
            summary["redirected"] += 1
        elif classification == "method-not-found":
            summary["not_found"] += 1
        elif classification == "method-server-error":
            summary["server_errors"] += 1
        elif classification == "method-request-rejected":
            summary["request_rejected"] += 1
        elif classification == "probe-error":
            summary["probe_errors"] += 1
        elif classification in {
            "method-other",
            "method-other-response",
        }:
            summary["other"] += 1

    return summary


def assessment_from_probes(
    probes: List[Dict[str, Any]],
    cves: List[Dict[str, Any]],
) -> Dict[str, Any]:
    accepted_mutating = [
        item
        for item in probes
        if item.get("method") in {"PUT", "PATCH", "DELETE"}
        and item.get("classification") == "method-accepted"
    ]

    accepted_trace = [
        item
        for item in probes
        if item.get("method") == "TRACE"
        and item.get("classification") == "method-accepted"
    ]

    accepted_post = [
        item
        for item in probes
        if item.get("method") == "POST"
        and item.get("classification") == "method-accepted"
    ]

    errors = [
        item for item in probes
        if item.get("classification") == "probe-error"
    ]

    # Accepted methods are evidence, not automatic findings.
    requires_review = bool(
        accepted_mutating
        or accepted_trace
        or errors
    )

    if errors:
        status = "probe-errors"
        assessment = (
            "HTTP method probing menghasilkan error dan memerlukan review; "
            "tidak ada automatic vulnerability finding."
        )
    elif accepted_mutating:
        status = "method-accepted-review"
        assessment = (
            "PUT/PATCH/DELETE diterima pada satu atau lebih endpoint; "
            "perilaku dicatat sebagai evidence untuk review konfigurasi/API. "
            "Tidak ada automatic vulnerability finding."
        )
    elif accepted_trace:
        status = "trace-accepted-review"
        assessment = (
            "TRACE diterima pada satu atau lebih endpoint; "
            "perilaku dicatat sebagai evidence untuk review. "
            "Tidak ada automatic vulnerability finding."
        )
    elif accepted_post:
        status = "post-accepted"
        assessment = (
            "POST diterima pada satu atau lebih endpoint; "
            "perilaku dapat sesuai fungsi aplikasi dan dicatat sebagai evidence. "
            "Tidak ada automatic vulnerability finding."
        )
    else:
        status = "methods-restricted"
        assessment = (
            "HTTP methods selain yang diizinkan tidak menunjukkan acceptance "
            "berisiko pada probe terkontrol; tidak ada automatic vulnerability finding."
        )

    return {
        "status": status,
        "finding": False,
        "requires_review": requires_review,
        "accepted_mutating_count": len(accepted_mutating),
        "accepted_trace_count": len(accepted_trace),
        "accepted_post_count": len(accepted_post),
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
    candidates = build_endpoint_candidates(recon_data)

    data = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id_from_dir(project_dir()),
        "updated_at": utc_now(),
        "methods": {
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
                "recon_status": recon_data.get(
                    "directory", {}
                ).get(
                    "status",
                    recon_data.get("status", ""),
                ),
                "recon_paths": len(recon_results),
                "selected_candidates": len(candidates),
            },
            "probes": [],
            "summary": {
                "probes": 0,
                "accepted": 0,
                "rejected": 0,
                "not_allowed": 0,
                "access_controlled": 0,
                "redirected": 0,
                "not_found": 0,
                "server_errors": 0,
                "request_rejected": 0,
                "probe_errors": 0,
                "other": 0,
            },
            "cve_candidates": [],
            "assessment": {
                "status": "initialized",
                "finding": False,
                "requires_review": False,
                "summary": (
                    "Artifact diinisialisasi; belum dilakukan method probing."
                ),
            },
        },
    }

    save_yaml(artifact_path(), data)

    print("[PASS] HTTP Methods berhasil diinisialisasi.")
    print(f"PROJECT         : {data['project_id']}")
    print(f"TARGET          : {target['value']}")
    print(f"PORTS           : {', '.join(map(str, target['ports']))}")
    print(f"METHODS         : {', '.join(METHODS)}")
    print(f"RECON PATHS     : {len(recon_results)}")
    print(f"CANDIDATES      : {len(candidates)}")
    print(f"SOURCE          : {recon_path}")
    print(f"FILE            : {artifact_path()}")

    return 0


def analyze() -> int:
    scope = load_project_scope()
    target = choose_primary_scope(scope)

    recon_path = recon_directory_path()
    recon_data = load_yaml(recon_path)
    recon_results = extract_recon_results(recon_data)
    candidates = build_endpoint_candidates(recon_data)

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
                result = probe_method(
                    session,
                    url,
                    method,
                )

                result.update(
                    {
                        "scheme": scheme_label,
                        "scheme_lower": scheme,
                        "port": port,
                        "path": path,
                        "endpoint_source": candidate["source"],
                        "endpoint_source_classification": candidate[
                            "source_classification"
                        ],
                        "endpoint_source_status_code": candidate[
                            "source_status_code"
                        ],
                    }
                )

                probes.append(result)

    summary = summarize_probes(probes)
    assessment = assessment_from_probes(probes, cves)

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id_from_dir(project_dir()),
        "updated_at": utc_now(),
        "methods": {
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
                "recon_status": recon_data.get(
                    "directory", {}
                ).get(
                    "status",
                    recon_data.get("status", ""),
                ),
                "recon_paths": len(recon_results),
                "selected_candidates": len(candidates),
            },
            "endpoint_candidates": candidates,
            "probes": probes,
            "summary": summary,
            "cve_candidates": cves,
            "assessment": assessment,
            "assessment_policy": {
                "automatic_finding": False,
                "notes": [
                    "Accepted HTTP methods are evidence, not automatic vulnerabilities.",
                    "PUT/PATCH/DELETE probes send no request body.",
                    "TRACE acceptance is recorded for security review.",
                    "CVE correlation is heuristic candidate evidence only.",
                    "No redirect following is performed.",
                    "No application CRUD operation is intentionally executed.",
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
        "probes": probes,
    }

    save_json(evidence_path(), raw_evidence)

    print("[PASS] HTTP Methods berhasil dianalisis.")
    print(f"PROJECT         : {artifact['project_id']}")
    print(f"TARGET          : {target['value']}")
    print(f"ENDPOINTS       : {len(candidates)}")
    print(f"METHODS         : {len(METHODS)}")
    print(f"PROBES          : {summary['probes']}")
    print(f"ACCEPTED        : {summary['accepted']}")
    print(f"NOT ALLOWED     : {summary['not_allowed']}")
    print(f"ACCESS CONTROL  : {summary['access_controlled']}")
    print(f"REDIRECTED      : {summary['redirected']}")
    print(f"NOT FOUND       : {summary['not_found']}")
    print(f"REQUEST REJECT  : {summary['request_rejected']}")
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
    block = data.get("methods", {})

    print(f"PROJECT: {data.get('project_id')}")
    print(f"STATUS : {block.get('status')}")
    print(f"TARGET : {block.get('target', {}).get('value')}")
    print()

    print(
        "SCHEME PORT METHOD    PATH                         "
        "STATUS CLASSIFICATION"
    )
    print("-" * 100)

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
            f"{scheme:<6} {port:<5} {method:<9} "
            f"{path[:28]:<29} {status:<6} {classification}"
        )

    summary = block.get("summary", {})
    print()
    print("SUMMARY")
    print("-" * 100)
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
    print("-" * 100)
    print(f"status          : {assessment.get('status')}")
    print(f"finding         : {assessment.get('finding')}")
    print(
        f"requires_review : {assessment.get('requires_review')}"
    )
    print(f"summary         : {assessment.get('summary')}")

    return 0


def verify() -> int:
    try:
        data = load_artifact()
    except Exception as exc:
        print(f"[FAIL] Tidak dapat membaca artifact: {exc}")
        return 1

    block = data.get("methods")
    if not isinstance(block, dict):
        print("[FAIL] Block methods tidak ditemukan.")
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
        errors.append(
            "method_set tidak sesuai dengan 8 method yang diwajibkan"
        )

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

    candidates = block.get("endpoint_candidates", [])
    probes = block.get("probes", [])
    summary = block.get("summary", {})
    cves = block.get("cve_candidates", [])

    if not isinstance(candidates, list):
        errors.append("endpoint_candidates bukan list")
        candidates = []

    if not isinstance(probes, list):
        errors.append("probes bukan list")
        probes = []

    if not isinstance(summary, dict):
        errors.append("summary bukan mapping")
        summary = {}

    if not isinstance(cves, list):
        errors.append("cve_candidates bukan list")
        cves = []

    if candidate_count != len(candidates):
        errors.append(
            "jumlah selected_candidates tidak sama dengan endpoint_candidates"
        )

    # analyze() probes every candidate against every supported target
    # (HTTP/80 and HTTPS/443) and every method. The previous validator
    # counted only candidates x methods and therefore rejected the valid
    # 2-scheme artifact (32 x 8 x 2 = 512).
    target_ports = target.get("ports", [])
    if not isinstance(target_ports, list):
        target_ports = []

    supported_target_ports = [
        int(port)
        for port in target_ports
        if str(port).isdigit() and int(port) in {80, 443}
    ]
    supported_target_ports = list(dict.fromkeys(supported_target_ports))

    if not supported_target_ports:
        errors.append("target tidak memiliki port HTTP/HTTPS yang didukung")

    expected_target_count = len(supported_target_ports)
    expected_probe_count = (
        len(candidates) * len(METHODS) * expected_target_count
    )

    if len(probes) != expected_probe_count:
        errors.append(
            f"jumlah probes {len(probes)} != "
            f"candidates({len(candidates)}) x "
            f"methods({len(METHODS)}) x "
            f"targets({expected_target_count}) "
            f"= {expected_probe_count}"
        )

    expected_target_pairs = {
        (80, "HTTP"),
        (443, "HTTPS"),
    }
    expected_target_pairs = {
        pair for pair in expected_target_pairs
        if pair[0] in supported_target_ports
    }

    observed_target_pairs = {
        (item.get("port"), str(item.get("scheme", "")).upper())
        for item in probes
        if isinstance(item, dict)
    }

    if observed_target_pairs != expected_target_pairs:
        errors.append(
            "kombinasi target scheme/port tidak sesuai: "
            f"observed={sorted(observed_target_pairs)} "
            f"expected={sorted(expected_target_pairs)}"
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
                f"probe[{index}] method tidak valid: "
                f"{item.get('method')}"
            )

        if item.get("port") not in {80, 443}:
            errors.append(
                f"probe[{index}] port di luar checklist: "
                f"{item.get('port')}"
            )

        if item.get("request_body_sent") not in {
            False,
            None,
        }:
            errors.append(
                f"probe[{index}] request body seharusnya tidak dikirim"
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

    if len(cves) != int(
        assessment.get("cve_candidate_count", len(cves))
    ):
        errors.append(
            "cve_candidate_count tidak konsisten"
        )

    if not isinstance(recon_count, int):
        errors.append(
            "endpoint_source.recon_paths bukan integer"
        )

    if errors:
        print("[FAIL] HTTP Methods gagal validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] HTTP Methods memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {block.get('status')}")
    print(f"[PASS] Target    : {target.get('value')}")
    print(f"[PASS] Recon     : {recon_count} path(s)")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(f"[PASS] Methods   : {len(METHODS)}")
    print(f"[PASS] Probes    : {len(probes)}")
    print(f"[PASS] Accepted  : {summary.get('accepted')}")
    print(f"[PASS] Rejected  : {summary.get('not_allowed')}")
    print(f"[PASS] CVE       : {len(cves)} candidate(s)")
    print(
        f"[PASS] Review    : "
        f"{1 if assessment.get('requires_review') else 0}"
    )
    print(
        "[PASS] CVE Triage: HTTP method/CVE correlation is "
        "candidate evidence; no automatic finding."
    )
    print(
        "[PASS] Assessment: accepted methods are recorded as "
        "evidence for review; no automatic vulnerability finding."
    )

    return 0


def show_version() -> int:
    print(f"methods.py v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("Methods:")
    for method in METHODS:
        print(f"  - {method}")
    print("Endpoint source: Recon directory.yaml")
    print("CVE source: 4-001 version.yaml")
    print("Redirect following: disabled")
    print("Mutation payload: none")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools - 4-009 HTTP Methods"
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
