#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - API Discovery

Version: 1.1.3
Checklist: 2-007 - API discovery

API discovery is evidence-driven. Existing endpoints from endpoint.yaml are
classified using observable metadata/path evidence, then only endpoints that
are sufficiently interesting are verified with safe GET requests. Common API
and documentation paths are also probed as a small temporary baseline.

No credentials, tokens, cookie values, or response bodies are stored.
No POST/PUT/PATCH/DELETE/TRACE/OPTIONS requests are performed.

Temporary dictionary paths will later move to:
    config/dictionaries/api/

Storage:
    projects/<PROJECT-ID>/02-reconnaissance/api/api.yaml
    projects/<PROJECT-ID>/02-reconnaissance/api/evidence/api-probes.json
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

# The repository contains scripts/reconnaissance/http.py. Remove the local
# script directory before importing urllib.request, otherwise it can shadow
# the standard-library http package used by urllib.request.
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent
for _entry in (str(SCRIPT_DIR), str(SCRIPTS_DIR)):
    while _entry in sys.path:
        sys.path.remove(_entry)
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

import urllib.error
import urllib.request
import yaml

try:
    from activity import record_activity
except ImportError:
    def record_activity(*args: Any, **kwargs: Any) -> None:
        return None

try:
    from context import ProjectContext, require_active_project
except ImportError:
    ProjectContext = Any  # type: ignore[misc,assignment]
    def require_active_project() -> Any:
        raise RuntimeError("context.py tidak dapat di-import.")

SCRIPT_VERSION = "1.1.3"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "2-007"
CHECKLIST_NAME = "API discovery"
REQUEST_TIMEOUT = 10
MAX_RESPONSE_BYTES = 1_000_000

# Temporary baseline. Do not treat these paths as proof of an API.
# They will later move to config/dictionaries/api/.
BASELINE_API_PATHS = [
    "api", "api/", "api/v1", "api/v1/", "api/v2", "api/v2/",
    "swagger", "swagger/", "swagger.json", "swagger.yaml",
    "swagger/index.html", "openapi.json", "openapi.yaml",
    "docs", "docs/", "api-docs", "api-docs/", "redoc", "redoc/",
]

API_PATH_MARKERS = (
    "/api", "/graphql", "/graphiql", "/swagger", "/openapi", "/redoc",
)

API_DOC_MARKERS = (
    "swagger", "openapi", "redoc", "graphql", "api documentation", "api docs",
)

API_CONTENT_TYPES = (
    "application/json", "application/problem+json", "application/hal+json",
    "application/vnd.api+json", "application/graphql-response+json",
    "application/xml", "text/xml",
)

HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")

STATIC_EXTENSIONS = {
    ".css", ".js", ".mjs", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".wav", ".ogg", ".mp4", ".webm", ".avi",
    ".zip", ".gz", ".br", ".pdf",
}

STATIC_PATH_MARKERS = (
    "/assets/", "/static/", "/css/", "/js/", "/images/", "/img/",
    "/fonts/", "/media/", "/favicon",
)

HTTP_SUCCESS_CODES = {200, 201, 202, 203, 204}
HTTP_REDIRECT_CODES = {301, 302, 303, 307, 308}
HTTP_ACCESS_CODES = {401, 403, 405}

CLASSIFICATIONS = {
    "api-candidate",
    "possible-api",
    "non-api",
    "unknown",
}

PROBE_CLASSIFICATIONS = CLASSIFICATIONS | {"not-found"}


class APIError(RuntimeError):
    pass


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def project_context() -> ProjectContext:
    return require_active_project()


def project_root() -> Path:
    return Path(project_context().project_path)


def api_dir() -> Path:
    return project_root() / "02-reconnaissance" / "api"


def api_file() -> Path:
    return api_dir() / "api.yaml"


def evidence_dir() -> Path:
    return api_dir() / "evidence"


def target_file() -> Path:
    return project_root() / "02-reconnaissance" / "target" / "target.yaml"


def endpoint_file() -> Path:
    return project_root() / "02-reconnaissance" / "endpoint" / "endpoint.yaml"


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise APIError(f"{label} tidak ditemukan: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise APIError(f"{label} YAML tidak valid: {exc}") from exc
    if not isinstance(data, dict):
        raise APIError(f"{label} harus berupa mapping/object.")
    return data


def _save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def _record_activity(message: str, status: str = "in-progress") -> None:
    try:
        record_activity(CHECKLIST_ID, CHECKLIST_ID, message, status)
    except TypeError:
        try:
            record_activity(
                phase="02-reconnaissance",
                item=CHECKLIST_ID,
                action=message,
                status=status,
            )
        except Exception:
            pass
    except Exception:
        pass


def _load_target() -> dict[str, Any]:
    data = _load_yaml(target_file(), "Target reconnaissance")
    if data.get("project_id") != project_root().name:
        raise APIError("Project ID pada target.yaml tidak sesuai active project.")
    target = data.get("target")
    if not isinstance(target, dict):
        raise APIError("Field 'target' pada target.yaml harus berupa mapping/object.")
    if str(target.get("status", "")).lower() != "completed":
        raise APIError("Target reconnaissance belum completed.")
    return data


def _load_endpoints() -> dict[str, Any]:
    data = _load_yaml(endpoint_file(), "Endpoint reconnaissance")
    if data.get("project_id") != project_root().name:
        raise APIError("Project ID pada endpoint.yaml tidak sesuai active project.")
    endpoint = data.get("endpoint")
    if not isinstance(endpoint, dict):
        raise APIError("Field 'endpoint' pada endpoint.yaml harus berupa mapping/object.")
    if str(endpoint.get("status", "")).lower() != "completed":
        raise APIError(
            "Endpoint reconnaissance belum completed. Jalankan:\n"
            "  python scripts/reconnaissance/endpoint.py verify"
        )
    if not isinstance(endpoint.get("endpoints"), list):
        raise APIError("Field 'endpoints' pada endpoint.yaml harus berupa list.")
    return data


def _target_meta(data: dict[str, Any]) -> dict[str, str]:
    target = data["target"]
    url = str(target.get("target_url", "")).strip()
    parsed = urlparse(url)
    if not url or parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise APIError("target_url pada target.yaml tidak valid.")
    return {
        "target_url": url,
        "base_url": url if url.endswith("/") else url + "/",
        "hostname": str(target.get("hostname") or parsed.hostname).lower(),
        "environment": str(target.get("environment", "")).strip(),
        "assessment_type": str(target.get("assessment_type", "")).strip(),
        "scope_reference": str(target.get("scope_reference", "")).strip(),
    }


def _normalize_url(value: str, base_url: str) -> str | None:
    value = str(value or "").strip()
    if not value:
        return None
    absolute = urljoin(base_url, value)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return absolute


def _same_host(url: str, hostname: str) -> bool:
    return str(urlparse(url).hostname or "").lower() == hostname.lower()


def _safe_path(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return path + (("?" + parsed.query) if parsed.query else "")


def _path_only(url: str) -> str:
    return (urlparse(url).path or "/").lower()


def _field_text(raw: dict[str, Any], *names: str) -> str:
    parts: list[str] = []
    for name in names:
        value = raw.get(name)
        if isinstance(value, list):
            parts.extend(str(x) for x in value)
        elif isinstance(value, dict):
            parts.extend(str(x) for x in value.values())
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts).strip()


def _raw_methods(raw: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for name in ("method", "methods", "http_method", "http_methods"):
        value = raw.get(name)
        if isinstance(value, list):
            values.extend(str(x).upper() for x in value)
        elif value:
            values.append(str(value).upper())
    return sorted(set(values)) or ["GET"]


def _classify_endpoint(raw: dict[str, Any], url: str) -> dict[str, Any]:
    path = _path_only(url)
    parsed = urlparse(url)
    evidence: list[str] = []
    signals: list[str] = []

    text = _field_text(
        raw,
        "type", "content_type", "content_types", "source", "category",
        "description", "title", "name", "notes", "method", "methods",
    ).lower()

    methods = _raw_methods(raw)
    suffix = Path(parsed.path or "/").suffix.lower()

    # Static resources are explicitly non-API. This is intentionally checked
    # before API-like path markers so /assets/.../script.js cannot become an
    # API candidate just because metadata happens to contain a weak marker.
    if suffix in STATIC_EXTENSIONS or any(marker in path for marker in STATIC_PATH_MARKERS):
        evidence.append("Static-resource path or file extension")
        signals.append("static-resource")
        return {
            "classification": "non-api",
            "evidence": evidence,
            "signals": signals,
            "methods": methods,
        }

    # Strong evidence comes from explicit endpoint metadata or observed API
    # documentation indicators. Path names alone remain insufficient.
    if any(marker in text for marker in (
        "application/json",
        "application/problem+json",
        "application/vnd.api+json",
        "application/hal+json",
    )):
        evidence.append("Endpoint metadata indicates JSON/API response")
        signals.append("json-metadata")

    if any(marker in text for marker in API_DOC_MARKERS):
        evidence.append("Endpoint metadata indicates API/documentation resource")
        signals.append("documentation-metadata")

    # Require an API-like path segment, not merely a substring such as
    # /apicalendar. This is still medium evidence, not proof.
    path_segments = [part for part in path.split("/") if part]
    api_like_segment = any(
        segment == marker.lstrip("/")
        for segment in path_segments
        for marker in API_PATH_MARKERS
    )
    if api_like_segment:
        evidence.append("API-like URL path")
        signals.append("api-like-path")

    if path.endswith((".json", ".yaml", ".yml")):
        evidence.append("Structured API/documentation file extension")
        signals.append("structured-extension")

    # A non-GET method is useful evidence only when endpoint discovery actually
    # recorded it. It is never inferred from names such as send/chat/history.
    if any(method in {"POST", "PUT", "PATCH", "DELETE"} for method in methods):
        evidence.append("Endpoint metadata exposes a non-GET HTTP method")
        signals.append("non-get-method")

    # JavaScript discovery is provenance, not API proof. Do not classify an
    # endpoint as API merely because it was found in JavaScript.
    if str(raw.get("source", "")).lower() in {"javascript", "js", "javascript-analysis"}:
        evidence.append("Endpoint was discovered from JavaScript")
        signals.append("javascript-source")

    strong = {"json-metadata", "documentation-metadata"}
    medium = {"api-like-path", "structured-extension", "non-get-method"}

    strong_count = len(strong.intersection(signals))
    medium_count = len(medium.intersection(signals))

    if strong_count >= 1:
        classification = "api-candidate"
    elif medium_count >= 2:
        classification = "api-candidate"
    elif medium_count >= 1:
        classification = "possible-api"
    else:
        classification = "unknown"

    return {
        "classification": classification,
        "evidence": evidence,
        "signals": signals,
        "methods": methods,
    }

def _extract_endpoints(endpoint_data: dict[str, Any], meta: dict[str, str]) -> list[dict[str, Any]]:
    raw_endpoints = endpoint_data["endpoint"].get("endpoints") or []
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_endpoints:
        if not isinstance(raw, dict):
            continue
        url = _normalize_url(str(raw.get("url", "")), meta["base_url"])
        if not url or not _same_host(url, meta["hostname"]) or url in seen:
            continue
        seen.add(url)
        info = _classify_endpoint(raw, url)
        results.append({
            "url": url,
            "path": _safe_path(url),
            "method": ",".join(info["methods"]),
            "methods": info["methods"],
            "source": "endpoint.yaml",
            "classification": info["classification"],
            "evidence": info["evidence"],
            "signals": info["signals"],
            "scope_status": "requires-scope-verification",
            "verified": False,
        })
    return results


def _baseline_probe_targets(base_url: str) -> list[dict[str, Any]]:
    """Build verification targets from the temporary dictionary.

    These are probe targets only. A dictionary entry is not an API candidate
    until the target produces observable API evidence.
    """
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in BASELINE_API_PATHS:
        url = urljoin(base_url, item.lstrip("/"))
        if url in seen:
            continue
        seen.add(url)
        results.append({
            "url": url,
            "path": _safe_path(url),
            "method": "GET",
            "methods": ["GET"],
            "source": "temporary-api-baseline",
            "pre_probe_classification": "probe-target",
            "evidence": ["Common API/documentation baseline path selected for verification"],
            "signals": ["baseline-dictionary"],
            "scope_status": "requires-scope-verification",
            "verified": False,
        })
    return results


def _unique(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        url = str(item.get("url", "")).strip()
        if not url or url in seen:
            continue
        seen.add(url)
        result.append(item)
    return result


def _response_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _classify_response(status: int, content_type: str, body: bytes, location: str = "") -> tuple[str, list[str]]:
    ct = content_type.lower()
    sample = body[:65536].decode("utf-8", errors="ignore").lower()
    evidence: list[str] = []
    api_signal = False
    if any(x in ct for x in API_CONTENT_TYPES):
        api_signal = True
        evidence.append(f"API-like Content-Type: {content_type}")
    if any(x in sample for x in ("openapi", "swagger", '"paths"', '"swagger"', "graphql")):
        api_signal = True
        evidence.append("API/documentation markers observed in bounded response sample")
    if status in HTTP_ACCESS_CODES and api_signal:
        return "api-candidate", evidence + [f"HTTP access status: {status}"]
    if api_signal and status in HTTP_SUCCESS_CODES:
        return "api-candidate", evidence + [f"HTTP success status: {status}"]
    if status == 404:
        return "not-found", ["HTTP 404: resource not found"]

    if status in HTTP_REDIRECT_CODES:
        if location:
            evidence.append(f"HTTP redirect observed: {status}")
        return "possible-api", evidence or [f"HTTP redirect observed: {status}"]

    if status in HTTP_ACCESS_CODES:
        return "unknown", [f"HTTP access status: {status}"]
    if status in HTTP_SUCCESS_CODES:
        if any(x in ct for x in HTML_CONTENT_TYPES):
            return "non-api", [f"HTML Content-Type: {content_type or '-'}", f"HTTP success status: {status}"]
        return "unknown", [f"HTTP success status: {status}", f"Content-Type: {content_type or '-'}"]
    return "unknown", [f"HTTP status: {status}"]


def _probe(url: str, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"BrebesKab-CSIRT-Tools/{SCRIPT_VERSION}",
            "Accept": "application/json, application/problem+json, text/html;q=0.8, */*;q=0.1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.getcode() or 0)
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            content_type = headers.get("content-type", "")
            location = headers.get("location", "")
            body = response.read(MAX_RESPONSE_BYTES)
            classification, evidence = _classify_response(status, content_type, body, location)
            return {
                "url": url,
                "status_code": status,
                "final_url": response.geturl(),
                "content_type": content_type,
                "location_present": bool(location),
                "response_length": len(body),
                "response_sha256": _response_hash(body),
                "classification": classification,
                "evidence": evidence,
                "request_error": False,
            }
    except urllib.error.HTTPError as exc:
        headers = {str(k).lower(): str(v) for k, v in exc.headers.items()} if exc.headers else {}
        content_type = headers.get("content-type", "")
        location = headers.get("location", "")
        body = b""
        try:
            body = exc.read(MAX_RESPONSE_BYTES)
        except Exception:
            pass
        classification, evidence = _classify_response(exc.code, content_type, body, location)
        return {
            "url": url,
            "status_code": int(exc.code),
            "final_url": url,
            "content_type": content_type,
            "location_present": bool(location),
            "response_length": len(body),
            "response_sha256": _response_hash(body) if body else "",
            "classification": classification,
            "evidence": evidence,
            "request_error": False,
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "url": url,
            "status_code": None,
            "final_url": "",
            "content_type": "",
            "location_present": False,
            "response_length": 0,
            "response_sha256": "",
            "classification": "unknown",
            "evidence": [f"GET request error: {type(exc).__name__}"],
            "request_error": True,
        }


def _merge_classification(candidate: dict[str, Any], probe: dict[str, Any]) -> str:
    """Return the evidence-based result after probing.

    A dictionary entry is only a probe target. Its pre-probe state must never
    promote an inconclusive response to an API classification.
    """
    post = str(probe.get("classification", "unknown"))
    if post in PROBE_CLASSIFICATIONS:
        return post
    return "unknown"


def _empty_document(meta: dict[str, str], endpoint_count: int) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "api": {
            "status": "not-started",
            "application": "",
            "target_url": meta["target_url"],
            "base_url": meta["base_url"],
            "hostname": meta["hostname"],
            "environment": meta["environment"],
            "assessment_type": meta["assessment_type"],
            "scope_reference": meta["scope_reference"],
            "method": "evidence-driven endpoint analysis + controlled GET",
            "dictionary": {
                "mode": "temporary-built-in-baseline",
                "future_path": "config/dictionaries/api/",
                "note": "Temporary only; baseline paths are not proof of an API.",
            },
            "endpoint_source_count": endpoint_count,
            "same_host_count": 0,
            "endpoint_analysis": [],
            "candidates": [],
            "probe_targets": [],
            "probes": [],
            "summary": {
                "endpoint_count": endpoint_count,
                "same_host_count": 0,
                "candidate_count": 0,
                "api_candidate_count": 0,
                "possible_api_count": 0,
                "non_api_count": 0,
                "unknown_count": 0,
                "probe_target_count": 0,
                "probed_count": 0,
                "not_found_count": 0,
                "request_error_count": 0,
            },
            "evidence": [],
            "discovered_at": "",
            "notes": "",
        },
    }


def init() -> int:
    target = _load_target()
    endpoints = _load_endpoints()
    meta = _target_meta(target)
    endpoint_items = endpoints["endpoint"].get("endpoints") or []

    data = _empty_document(meta, len(endpoint_items))
    data["api"]["application"] = str(endpoints["endpoint"].get("application", ""))

    analysis = _extract_endpoints(endpoints, meta)
    candidates = [
        item for item in analysis
        if item.get("classification") in {"api-candidate", "possible-api"}
    ]

    data["api"]["endpoint_analysis"] = analysis
    data["api"]["candidates"] = candidates
    data["api"]["same_host_count"] = len(analysis)

    summary = data["api"]["summary"]
    summary["endpoint_count"] = len(endpoint_items)
    summary["same_host_count"] = len(analysis)
    summary["candidate_count"] = len(candidates)
    summary["api_candidate_count"] = sum(
        1 for item in candidates if item.get("classification") == "api-candidate"
    )
    summary["possible_api_count"] = sum(
        1 for item in candidates if item.get("classification") == "possible-api"
    )
    summary["non_api_count"] = sum(
        1 for item in analysis if item.get("classification") == "non-api"
    )
    summary["unknown_count"] = sum(
        1 for item in analysis if item.get("classification") == "unknown"
    )

    _save_yaml(api_file(), data)
    _record_activity(
        f"API discovery initialized: {len(analysis)} same-host endpoints analyzed",
        "in-progress",
    )

    print("[PASS] API Discovery berhasil diinisialisasi.")
    print(f"PROJECT             : {project_root().name}")
    print(f"TARGET              : {meta['target_url']}")
    print(f"ENDPOINTS ANALYZED  : {len(endpoint_items)}")
    print(f"SAME-HOST           : {len(analysis)}")
    print(f"API CANDIDATES      : {summary['api_candidate_count']}")
    print(f"POSSIBLE API        : {summary['possible_api_count']}")
    print(f"NON-API             : {summary['non_api_count']}")
    print(f"UNKNOWN             : {summary['unknown_count']}")
    print(f"GET PROBE ELIGIBLE  : {len(candidates)}")
    print(f"FILE                : {api_file()}")
    return 0


def _load_api() -> dict[str, Any]:
    data = _load_yaml(api_file(), "API reconnaissance")
    if data.get("project_id") != project_root().name:
        raise APIError("Project ID pada api.yaml tidak sesuai active project.")
    if str(data.get("schema_version", "")) != SCHEMA_VERSION:
        raise APIError("Schema api.yaml tidak didukung.")
    if not isinstance(data.get("api"), dict):
        raise APIError("Field 'api' pada api.yaml harus berupa mapping/object.")
    return data


def discover(timeout: int = REQUEST_TIMEOUT, probe_baseline: bool = True) -> int:
    data = _load_api()
    api = data["api"]
    base_url = str(api.get("base_url", "")).strip()
    if not base_url:
        raise APIError("base_url belum tersedia pada api.yaml.")
    if timeout < 1:
        print("[FAIL] Timeout harus >= 1.")
        return 1

    analysis = list(api.get("endpoint_analysis") or [])
    endpoint_candidates = [
        item for item in analysis
        if str(item.get("classification", "unknown")) in {"api-candidate", "possible-api"}
    ]

    probe_targets = _baseline_probe_targets(base_url) if probe_baseline else []
    candidates = _unique(endpoint_candidates)

    api["status"] = "in-progress"
    api["endpoint_analysis"] = analysis
    api["candidates"] = candidates
    api["probe_targets"] = probe_targets
    api["same_host_count"] = len(analysis)
    api["updated_at"] = now_iso()
    _save_yaml(api_file(), data)

    print("[INFO] Menjalankan 2-007: API discovery")
    print(f"[INFO] Target              : {base_url}")
    print(f"[INFO] Endpoints analyzed  : {api.get('endpoint_source_count', 0)}")
    print(f"[INFO] Same-host           : {len(analysis)}")
    print(f"[INFO] Pre-existing API candidates : {len(endpoint_candidates)}")
    print(f"[INFO] Dictionary probe targets : {len(probe_targets)}")
    print(f"[INFO] GET probes          : {len(candidates) + len(probe_targets)}")
    print("[INFO] Method              : evidence-driven classification + controlled GET")
    print("[INFO] State-changing HTTP : disabled")
    print("[INFO] Dictionary          : temporary built-in baseline")

    _record_activity(f"API discovery started: {base_url}", "in-progress")
    probes: list[dict[str, Any]] = []

    all_probe_targets = _unique(candidates + probe_targets)

    for index, candidate in enumerate(all_probe_targets, 1):
        url = str(candidate.get("url", "")).strip()
        print(f"[INFO] [{index}/{len(all_probe_targets)}] GET {url}")
        result = _probe(url, timeout)
        result["source"] = candidate.get("source", "")
        result["pre_probe_classification"] = candidate.get(
            "classification",
            candidate.get("pre_probe_classification", "probe-target"),
        )
        result["candidate_evidence"] = list(candidate.get("evidence") or [])
        result["candidate_signals"] = list(candidate.get("signals") or [])
        result["scope_status"] = candidate.get(
            "scope_status", "requires-scope-verification"
        )
        result["final_classification"] = _merge_classification(candidate, result)
        probes.append(result)

        # Keep source endpoint analysis separate from dictionary probe targets.
        # A dictionary hit is not promoted into endpoint_analysis merely because
        # it was probed.
        for item in candidates:
            if item.get("url") == url:
                # Keep the pre-probe endpoint classification intact. The probe
                # result is verification evidence, not a replacement for the
                # source classification.
                item["verified"] = True
                item["verification"] = {
                    "status_code": result.get("status_code"),
                    "classification": result.get("final_classification"),
                    "evidence": result.get("evidence", []),
                }
                break


    evidence_path = evidence_dir() / "api-probes.json"
    evidence_dir().mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(probes, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # Classification counts for the source endpoint analysis are deliberately
    # kept separate from temporary dictionary probes.
    summary = {
        "endpoint_count": int(api.get("endpoint_source_count", 0)),
        "same_host_count": len(analysis),
        "candidate_count": len(candidates),
        "api_candidate_count": sum(
            1 for x in analysis if x.get("classification") == "api-candidate"
        ),
        "possible_api_count": sum(
            1 for x in analysis if x.get("classification") == "possible-api"
        ),
        "non_api_count": sum(
            1 for x in analysis if x.get("classification") == "non-api"
        ),
        "unknown_count": sum(
            1 for x in analysis if x.get("classification") == "unknown"
        ),
        "probe_target_count": len(probe_targets),
        "probed_count": len(probes),
        "probe_api_candidate_count": sum(
            1 for x in probes if x.get("final_classification") == "api-candidate"
        ),
        "probe_possible_api_count": sum(
            1 for x in probes if x.get("final_classification") == "possible-api"
        ),
        "probe_non_api_count": sum(
            1 for x in probes if x.get("final_classification") == "non-api"
        ),
        "not_found_count": sum(
            1 for x in probes if x.get("final_classification") == "not-found"
        ),
        "request_error_count": sum(
            1 for x in probes if x.get("request_error")
        ),
    }

    api["endpoint_analysis"] = analysis
    api["candidates"] = candidates
    api["probe_targets"] = probe_targets
    api["probes"] = probes
    api["summary"] = summary
    api["evidence"] = [str(evidence_path.relative_to(project_root()))]
    api["discovered_at"] = now_iso()
    api["status"] = "completed"
    api["updated_at"] = now_iso()
    _save_yaml(api_file(), data)

    print()
    print(f"ENDPOINTS ANALYZED : {summary['endpoint_count']}")
    print(f"SAME-HOST          : {summary['same_host_count']}")
    print(f"CANDIDATES          : {summary['candidate_count']}")
    print(f"API CANDIDATES      : {summary['api_candidate_count']}")
    print(f"POSSIBLE API        : {summary['possible_api_count']}")
    print(f"NON-API             : {summary['non_api_count']}")
    print(f"UNKNOWN             : {summary['unknown_count']}")
    print(f"PROBE TARGETS       : {summary['probe_target_count']}")
    print(f"GET PROBES          : {summary['probed_count']}")
    print(f"PROBE API           : {summary['probe_api_candidate_count']}")
    print(f"PROBE POSSIBLE API  : {summary['probe_possible_api_count']}")
    print(f"PROBE NON-API       : {summary['probe_non_api_count']}")
    print(f"NOT FOUND           : {summary['not_found_count']}")
    print(f"REQUEST ERRORS      : {summary['request_error_count']}")
    print("STATUS              : completed")
    _record_activity("API discovery completed", "completed")
    return 0


def _unique_strings(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def list_items() -> int:
    data = _load_api()
    api = data["api"]
    analysis = api.get("endpoint_analysis") or []
    candidates = api.get("candidates") or []

    print(f"Project ID         : {data.get('project_id')}")
    print(f"Endpoints analyzed : {len(analysis)}")
    probe_targets = api.get("probe_targets") or []
    probes = api.get("probes") or []
    print(f"GET candidates     : {len(candidates)}")
    print(f"Dictionary targets : {len(probe_targets)}")
    print(f"GET probes         : {len(probes)}")
    print(
        "Classification     : "
        f"api={sum(1 for x in analysis if x.get('classification') == 'api-candidate')}, "
        f"possible={sum(1 for x in analysis if x.get('classification') == 'possible-api')}, "
        f"non-api={sum(1 for x in analysis if x.get('classification') == 'non-api')}, "
        f"unknown={sum(1 for x in analysis if x.get('classification') == 'unknown')}"
    )
    print(
        "Probe results      : "
        f"api={sum(1 for x in probes if x.get('final_classification') == 'api-candidate')}, "
        f"possible={sum(1 for x in probes if x.get('final_classification') == 'possible-api')}, "
        f"non-api={sum(1 for x in probes if x.get('final_classification') == 'non-api')}, "
        f"not-found={sum(1 for x in probes if x.get('final_classification') == 'not-found')}, "
        f"unknown={sum(1 for x in probes if x.get('final_classification') == 'unknown')}"
    )
    print()

    for item in analysis:
        print(f"[{item.get('classification', 'unknown')}] {item.get('path', '-')}")
        print(f"  Source   : {item.get('source', '-')}")
        print(f"  Evidence : {'; '.join(item.get('evidence') or []) or '-'}")
        print(f"  Scope    : {item.get('scope_status', '-')}")
    return 0


def show() -> int:
    data = _load_api()
    print(yaml.safe_dump(data["api"], allow_unicode=True, sort_keys=False))
    return 0


def verify() -> int:
    data = _load_api()
    api = data["api"]
    errors: list[str] = []

    if api.get("status") != "completed":
        errors.append(f"Status belum completed: {api.get('status')}")

    analysis = api.get("endpoint_analysis")
    candidates = api.get("candidates")
    probe_targets = api.get("probe_targets")
    probes = api.get("probes")

    if not isinstance(analysis, list):
        errors.append("endpoint_analysis harus berupa list.")
        analysis = []
    if not isinstance(candidates, list):
        errors.append("candidates harus berupa list.")
        candidates = []
    if not isinstance(probe_targets, list):
        errors.append("probe_targets harus berupa list.")
        probe_targets = []
    if not isinstance(probes, list):
        errors.append("probes harus berupa list.")
        probes = []

    allowed_candidates = {"api-candidate", "possible-api"}
    for item in analysis:
        if item.get("classification") not in CLASSIFICATIONS:
            errors.append(
                f"Classification tidak valid: {item.get('classification')!r}"
            )
            break
        if not isinstance(item.get("evidence"), list):
            errors.append(f"Evidence tidak valid untuk {item.get('path')}")
            break

    allowed_candidates = {"api-candidate", "possible-api"}
    analysis_urls = {
        str(item.get("url")) for item in analysis if item.get("url")
    }
    for item in candidates:
        if item.get("classification") not in allowed_candidates:
            errors.append(
                "candidates hanya boleh berisi api-candidate/possible-api: "
                f"{item.get('path')}"
            )
            break
        if item.get("source") == "endpoint.yaml" and item.get("url") not in analysis_urls:
            errors.append(
                f"Candidate endpoint tidak ditemukan dalam endpoint_analysis: "
                f"{item.get('path')}"
            )
            break

    for item in probe_targets:
        if item.get("source") != "temporary-api-baseline":
            errors.append(
                f"probe_target source tidak valid: {item.get('path')}"
            )
            break
        if item.get("pre_probe_classification") != "probe-target":
            errors.append(
                f"probe_target tidak boleh memiliki classification API sebelum probe: "
                f"{item.get('path')}"
            )
            break

    for item in probes:
        final_classification = item.get("final_classification")
        if final_classification not in PROBE_CLASSIFICATIONS:
            errors.append(
                f"Final probe classification tidak valid: {final_classification!r}"
            )
            break

    summary = api.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary harus berupa mapping/object.")
    else:
        for key in (
            "endpoint_count",
            "same_host_count",
            "candidate_count",
            "api_candidate_count",
            "possible_api_count",
            "non_api_count",
            "unknown_count",
            "probed_count",
        ):
            if not isinstance(summary.get(key), int):
                errors.append(f"summary.{key} tidak valid.")

        if summary.get("same_host_count") != len(analysis):
            errors.append("summary.same_host_count tidak sesuai endpoint_analysis.")
        if summary.get("candidate_count") != len(candidates):
            errors.append("summary.candidate_count tidak sesuai candidates.")
        if summary.get("probe_target_count") != len(probe_targets):
            errors.append("summary.probe_target_count tidak sesuai probe_targets.")
        if summary.get("probed_count") != len(probes):
            errors.append("summary.probed_count tidak sesuai probes.")
        if summary.get("probe_api_candidate_count") != sum(
            1 for x in probes if x.get("final_classification") == "api-candidate"
        ):
            errors.append("summary.probe_api_candidate_count tidak sesuai probes.")
        if summary.get("probe_possible_api_count") != sum(
            1 for x in probes if x.get("final_classification") == "possible-api"
        ):
            errors.append("summary.probe_possible_api_count tidak sesuai probes.")
        if summary.get("probe_non_api_count") != sum(
            1 for x in probes if x.get("final_classification") == "non-api"
        ):
            errors.append("summary.probe_non_api_count tidak sesuai probes.")
        if summary.get("not_found_count") != sum(
            1 for x in probes if x.get("final_classification") == "not-found"
        ):
            errors.append("summary.not_found_count tidak sesuai probes.")

    if errors:
        print("[FAIL] API Discovery verification gagal.")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("[PASS] API Discovery memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {api.get('status')}")
    print(f"[PASS] Endpoints : {len(analysis)}")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(
        f"[PASS] API       : "
        f"{sum(1 for x in analysis if x.get('classification') == 'api-candidate')}"
    )
    print(
        f"[PASS] Possible  : "
        f"{sum(1 for x in analysis if x.get('classification') == 'possible-api')}"
    )
    print(
        f"[PASS] Non-API   : "
        f"{sum(1 for x in analysis if x.get('classification') == 'non-api')}"
    )
    print(
        f"[PASS] Unknown   : "
        f"{sum(1 for x in analysis if x.get('classification') == 'unknown')}"
    )
    _record_activity("API discovery verified", "completed")
    return 0


def status() -> int:
    data = _load_api()
    api = data["api"]
    s = api.get("summary") or {}
    print(f"Project ID         : {data.get('project_id')}")
    print(f"Status             : {api.get('status', '-')}")
    print(f"Target             : {api.get('target_url', '-')}")
    print(f"Endpoints analyzed : {s.get('endpoint_count', 0)}")
    print(f"Same-host          : {s.get('same_host_count', 0)}")
    print(f"Candidates         : {s.get('candidate_count', 0)}")
    print(f"API                : {s.get('api_candidate_count', 0)}")
    print(f"Possible           : {s.get('possible_api_count', 0)}")
    print(f"Non-API            : {s.get('non_api_count', 0)}")
    print(f"Unknown            : {s.get('unknown_count', 0)}")
    print(f"Probe targets      : {s.get('probe_target_count', 0)}")
    print(f"GET probes         : {s.get('probed_count', 0)}")
    print(f"Probe API          : {s.get('probe_api_candidate_count', 0)}")
    print(f"Probe possible     : {s.get('probe_possible_api_count', 0)}")
    print(f"Probe non-API      : {s.get('probe_non_api_count', 0)}")
    print(f"Not found          : {s.get('not_found_count', 0)}")
    print(f"Errors             : {s.get('request_error_count', 0)}")
    print(f"Dictionary         : {api.get('dictionary', {}).get('mode', '-')}")
    print(f"File               : {api_file()}")
    return 0


def remove() -> int:
    path = api_file()
    if not path.exists():
        print("[INFO] API Discovery belum ada.")
        return 0
    confirm = input("Hapus seluruh data API Discovery untuk project aktif? [y/N]: ").strip().lower()
    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0
    shutil.rmtree(api_dir())
    _record_activity("API discovery data removed", "completed")
    print("[PASS] API Discovery berhasil dihapus.")
    return 0


def version() -> int:
    print(f"BrebesKab-CSIRT-Tools api.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : evidence-driven endpoint analysis + controlled GET")
    print("Endpoint classification: api-candidate | possible-api | non-api | unknown")
    print("Probe result: api-candidate | possible-api | non-api | not-found | unknown")
    print("Dictionary: temporary built-in baseline (probe targets only)")
    return 0


def help_text() -> None:
    print("""BrebesKab-CSIRT-Tools - API Discovery

Usage:
  python scripts/reconnaissance/api.py <command>

Commands:
  init       Analyze all endpoints from endpoint.yaml and initialize api.yaml
  discover   Verify only API/possible-API candidates with safe GET requests
  list       List endpoint classifications and evidence
  show       Show complete API discovery document
  verify     Validate API discovery result
  status     Show API discovery status
  remove     Remove API discovery data
  version    Show script version

Safety:
  GET only. No POST/PUT/PATCH/DELETE/TRACE/OPTIONS.
  Unknown/non-API endpoints are retained as evidence and are not probed.
""")


def main() -> int:
    commands = {
        "init": init,
        "discover": discover,
        "list": list_items,
        "show": show,
        "verify": verify,
        "status": status,
        "remove": remove,
        "version": version,
        "help": lambda: (help_text() or 0),
    }
    command = sys.argv[1].lower() if len(sys.argv) > 1 else "help"
    if command not in commands:
        print(f"[FAIL] Command tidak dikenal: {command}")
        help_text()
        return 1
    try:
        return int(commands[command]())
    except APIError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] Unexpected error: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
