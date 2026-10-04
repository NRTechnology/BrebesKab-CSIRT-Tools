#!/usr/bin/env python3
"""
env.py - Environment File Exposure
Checklist: 4-006
Project: BrebesKab-CSIRT-Tools

Purpose
-------
Controlled assessment of environment/configuration files that may be
accidentally exposed through HTTP/HTTPS.

This script:
- Uses the authorized scope from scope.yaml.
- Uses Recon directory.yaml as the authoritative endpoint source.
- Adds a small, bounded set of environment-file candidates.
- Probes only GET and HEAD.
- Does not follow redirects.
- Does not submit request bodies or mutate server state.
- Classifies responses based on HTTP behavior AND conservative content
  indicators, not status code alone.
- Correlates observed server product/version information with the
  existing 4-001 version.yaml CVE candidate evidence.
- Never treats a CVE/version match as a confirmed vulnerability.
- Keeps raw probe evidence intact for later audit/report processing.

Report-generation/redaction is intentionally outside this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import requests
    from requests import Response
except ImportError:
    print("[ERROR] Modul 'requests' belum terpasang.")
    print("        Install: python -m pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[ERROR] Modul 'PyYAML' belum terpasang.")
    print("        Install: python -m pip install pyyaml")
    sys.exit(1)


APP_NAME = "BrebesKab-CSIRT-Tools"
APP_VERSION = "1.0.3"
SCHEMA_VERSION = "1.0"

CHECKLIST_ID = "4-006"
CHECKLIST_NAME = "Environment File Exposure"

METHODS = ("GET", "HEAD")
DEFAULT_TIMEOUT = 15
MAX_BODY_BYTES = 256 * 1024
BODY_SAMPLE_CHARS = 4000

ROOT_CANDIDATE_PATHS = (
    "/.env",
    "/.env.example",
    "/.env.local",
    "/.env.production",
    "/.env.dev",
    "/.env.backup",
)

ENV_ASSIGNMENT_RE = re.compile(
    r"(?m)^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]{1,80}[ \t]*="
)

KEY_PATTERNS = {
    "app_environment": re.compile(
        r"(?mi)^[ \t]*(?:export[ \t]+)?APP_(?:ENV|DEBUG|URL)[ \t]*="
    ),
    "database_configuration": re.compile(
        r"(?mi)^[ \t]*(?:export[ \t]+)?"
        r"(?:DB_HOST|DB_PORT|DB_DATABASE|DB_USERNAME|DB_PASSWORD|"
        r"DATABASE_URL)[ \t]*="
    ),
    "secret_configuration": re.compile(
        r"(?mi)^[ \t]*(?:export[ \t]+)?"
        r"(?:API_KEY|SECRET_KEY|ENCRYPTION_KEY|JWT_SECRET|APP_KEY)[ \t]*="
    ),
    "generic_environment_assignment": ENV_ASSIGNMENT_RE,
}

# These are useful for detecting an environment-file-like response without
# making the classifier too aggressive.
ENV_VALUE_RE = re.compile(
    r"(?mi)^[ \t]*(?:export[ \t]+)?"
    r"[A-Z][A-Z0-9_]{1,80}[ \t]*=[ \t]*(?:[^\r\n#]*)(?:\r?$)"
)

TEXT_CONTENT_TYPES = (
    "text/plain",
    "text/css",
    "application/json",
    "application/javascript",
    "text/javascript",
    "text/html",
)

STATUS_ACCESS_CONTROL = {401, 403, 405}
STATUS_REDIRECT = {300, 301, 302, 303, 307, 308}
STATUS_NOT_FOUND = {404, 410}
STATUS_SERVER_ERROR = set(range(500, 600))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(str(path))

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError(f"YAML root bukan object: {path}")

    return data


def dump_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            data,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def dump_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            data,
            handle,
            ensure_ascii=False,
            indent=2,
        )


def project_root_from_script() -> Path:
    # scripts/webserver/env.py -> project root
    return Path(__file__).resolve().parents[2]


def find_project_root() -> Path:
    """
    Locate the active pentest project root.

    Repository layout:
        <repository>/
        ├── scripts/
        │   └── webserver/
        │       └── env.py
        └── projects/
            └── PENTEST-2026-002/
                ├── active-project.yaml
                ├── 01-preparation/
                │   └── scope/
                │       └── scope.yaml
                ├── 02-reconnaissance/
                │   └── directory/
                │       └── directory.yaml
                └── 04-web-server-configuration/

    The active project directory is therefore different from the Git
    repository root. We first look for a project directory containing
    the canonical scope and reconnaissance artifacts, then fall back
    to the current working directory / repository root for compatibility.
    """
    repo_root = project_root_from_script()
    cwd = Path.cwd().resolve()

    def is_project_root(candidate: Path) -> bool:
        return (
            (
                candidate
                / "01-preparation"
                / "scope"
                / "scope.yaml"
            ).exists()
            and (
                candidate
                / "02-reconnaissance"
                / "directory"
                / "directory.yaml"
            ).exists()
        )

    # 1. The current working directory may already be the active project.
    if is_project_root(cwd):
        return cwd

    # 2. The repository may contain the active project under projects/.
    projects_dir = repo_root / "projects"
    if projects_dir.is_dir():
        project_candidates = sorted(
            (
                item
                for item in projects_dir.iterdir()
                if item.is_dir()
            ),
            key=lambda item: item.name.lower(),
        )

        # Prefer a project explicitly marked as active.
        for candidate in project_candidates:
            if not is_project_root(candidate):
                continue

            active_marker = candidate / "active-project.yaml"
            if active_marker.exists():
                return candidate

        # Fallback: first directory with the canonical project structure.
        for candidate in project_candidates:
            if is_project_root(candidate):
                return candidate

    # 3. Compatibility fallback for projects executed directly from root.
    if is_project_root(repo_root):
        return repo_root

    # 4. Legacy/root-level scope layout.
    for candidate in (cwd, repo_root):
        if (
            (candidate / "scope.yaml").exists()
            or (candidate / "scope.yml").exists()
        ):
            return candidate

    return repo_root


def locate_scope(root: Path) -> Path:
    """
    Locate the authoritative project scope.

    Current project layout:
        01-preparation/scope/scope.yaml

    Root-level scope.yaml/scope.yml remains a compatibility fallback.
    """
    candidates = [
        root / "01-preparation" / "scope" / "scope.yaml",
        root / "01-preparation" / "scope" / "scope.yml",
        root / "scope.yaml",
        root / "scope.yml",
    ]

    for path in candidates:
        if path.exists():
            return path

    searched = ", ".join(str(item) for item in candidates)
    raise FileNotFoundError(
        "scope.yaml tidak ditemukan. Path yang diperiksa: "
        f"{searched}"
    )


def discover_project_name(scope: Dict[str, Any], root: Path) -> str:
    project = scope.get("project")
    if isinstance(project, dict):
        for key in ("id", "name", "project_id", "project_name"):
            value = project.get(key)
            if value:
                return str(value)

    for key in ("project_id", "project_name", "name"):
        value = scope.get(key)
        if value:
            return str(value)

    # Preserve the current project naming convention when scope does not
    # explicitly contain a project field.
    return root.name


def extract_in_scope(scope: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract authorized scope entries from the canonical scope.yaml layout.

    Canonical structure:
        scope:
          in_scope:
            - scope_id: IN-001
              type: domain
              value: example.test
              ports:
                - 80
                - 443

    A top-level in_scope fallback is retained for compatibility with
    older project artifacts.
    """
    scope_section = scope.get("scope", {})

    if isinstance(scope_section, dict):
        items = scope_section.get("in_scope", [])
    else:
        items = []

    # Compatibility fallback for legacy artifacts.
    if not items:
        items = scope.get("in_scope", [])

    if not isinstance(items, list):
        raise ValueError(
            "scope.in_scope harus berupa list pada struktur scope.yaml."
        )

    normalized: List[Dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue

        value = item.get("value")
        if not value:
            continue

        ports = item.get("ports", [80, 443])
        if not isinstance(ports, list):
            ports = [80, 443]

        normalized.append(
            {
                "scope_id": item.get("scope_id"),
                "type": item.get("type"),
                "value": str(value).strip(),
                "ports": [
                    int(port)
                    for port in ports
                    if str(port).isdigit()
                ],
            }
        )

    return normalized


def select_domain_target(scope: Dict[str, Any]) -> Tuple[str, List[int], str]:
    entries = extract_in_scope(scope)

    for item in entries:
        if item.get("type") == "domain":
            ports = item.get("ports") or [80, 443]
            return item["value"], ports, str(item.get("scope_id") or "")

    for item in entries:
        value = item["value"]
        if "." in value and not value.replace(".", "").isdigit():
            ports = item.get("ports") or [80, 443]
            return value, ports, str(item.get("scope_id") or "")

    raise ValueError("Domain target tidak ditemukan pada scope.")


def canonical_path(value: str) -> str:
    if not value:
        return "/"

    path = value.strip()

    if not path.startswith("/"):
        path = "/" + path

    # Do not permit query strings/fragments from an artifact to become part
    # of the controlled candidate path.
    path = path.split("?", 1)[0].split("#", 1)[0]

    if not path:
        return "/"

    return path


def load_recon_paths(root: Path) -> List[str]:
    path = root / "02-reconnaissance" / "directory" / "directory.yaml"
    data = load_yaml(path)

    source = data.get("directory", {})
    if isinstance(source, dict):
        results = source.get("results", [])
    elif isinstance(source, list):
        results = source
    else:
        results = []

    paths: List[str] = []

    if isinstance(results, list):
        for item in results:
            if isinstance(item, str):
                paths.append(canonical_path(item))
                continue

            if not isinstance(item, dict):
                continue

            for key in ("path", "url_path", "endpoint", "uri"):
                value = item.get(key)
                if value:
                    paths.append(canonical_path(str(value)))
                    break

    # Some older/alternate artifacts can expose paths at the root.
    if not paths:
        for key in ("paths", "results", "endpoints"):
            source_list = data.get(key)
            if not isinstance(source_list, list):
                continue

            for item in source_list:
                if isinstance(item, str):
                    paths.append(canonical_path(item))
                elif isinstance(item, dict):
                    for path_key in (
                        "path",
                        "url_path",
                        "endpoint",
                        "uri",
                    ):
                        value = item.get(path_key)
                        if value:
                            paths.append(canonical_path(str(value)))
                            break

            if paths:
                break

    return sorted(set(paths))


def derive_environment_candidates(recon_paths: Iterable[str]) -> List[str]:
    """
    Recon remains authoritative for discovered endpoints, but environment
    files are sensitive server-side configuration targets that may not be
    discovered by directory enumeration. Therefore a small explicit,
    bounded candidate set is permitted.

    If Recon already contains an environment path, it is retained once.
    """
    candidates = {canonical_path(path) for path in recon_paths}

    for path in ROOT_CANDIDATE_PATHS:
        candidates.add(path)

    return sorted(
        candidates,
        key=lambda item: (
            0 if item in ROOT_CANDIDATE_PATHS else 1,
            item.lower(),
        ),
    )


def load_version_artifact(root: Path) -> Dict[str, Any]:
    path = root / "04-web-server-configuration" / "version" / "version.yaml"
    if not path.exists():
        return {}

    try:
        return load_yaml(path)
    except Exception:
        return {}


def load_error_artifact(root: Path) -> Dict[str, Any]:
    path = root / "04-web-server-configuration" / "errors" / "errors.yaml"
    if not path.exists():
        return {}

    try:
        return load_yaml(path)
    except Exception:
        return {}


def extract_cve_candidates(version_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    The 4-001 artifact is authoritative for the observed version/CVE
    candidate relationship. This function intentionally does not query NVD.
    """
    candidates: List[Dict[str, Any]] = []

    possible_containers = [
        version_data.get("cve"),
        version_data.get("cves"),
        version_data.get("cve_correlation"),
        version_data.get("cve_candidates"),
        version_data.get("assessment"),
    ]

    for container in possible_containers:
        if isinstance(container, list):
            for item in container:
                if isinstance(item, dict):
                    candidates.append(item)
        elif isinstance(container, dict):
            for key in ("candidates", "results", "items"):
                value = container.get(key)
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            candidates.append(item)

    # De-duplicate by CVE id when possible.
    unique: Dict[str, Dict[str, Any]] = {}

    for item in candidates:
        cve_id = (
            item.get("cve_id")
            or item.get("id")
            or item.get("cve")
            or item.get("CVE")
        )

        if cve_id:
            unique[str(cve_id)] = item

    return list(unique.values())


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def get_content_type(response: Response) -> str:
    return response.headers.get("Content-Type", "")


def is_textual_content(content_type: str) -> bool:
    normalized = content_type.lower()
    return (
        normalized.startswith(TEXT_CONTENT_TYPES)
        or "charset=" in normalized
        or normalized.startswith("application/xml")
        or normalized.startswith("application/x-www-form-urlencoded")
    )


def safe_body_text(response: Response) -> str:
    """
    Bound the amount of body retained in memory.

    Raw evidence is intentionally not redacted at this stage. The body
    sample is bounded to avoid accidentally downloading a large resource.
    """
    raw = response.content[:MAX_BODY_BYTES]

    return raw.decode(
        response.encoding or "utf-8",
        errors="replace",
    )


def body_sample(text: str) -> str:
    if len(text) <= BODY_SAMPLE_CHARS:
        return text
    return text[:BODY_SAMPLE_CHARS] + "\n...[truncated]..."


def detect_environment_indicators(
    body: str,
    content_type: str,
    path: str,
) -> Dict[str, Any]:
    indicators: List[str] = []
    matched_lines: List[str] = []

    for name, pattern in KEY_PATTERNS.items():
        if pattern.search(body):
            indicators.append(name)

    for match in ENV_VALUE_RE.finditer(body):
        line = match.group(0).strip()
        if line and len(matched_lines) < 30:
            matched_lines.append(line)

    # A conservative environment-file score.
    score = 0

    if "application/json" not in content_type.lower():
        score += 1

    if "generic_environment_assignment" in indicators:
        score += 2

    if "app_environment" in indicators:
        score += 2

    if "database_configuration" in indicators:
        score += 3

    if "secret_configuration" in indicators:
        score += 3

    # Explicit .env-style paths get one additional signal, but path alone
    # can never make a response "exposed".
    if path in ROOT_CANDIDATE_PATHS:
        score += 1

    return {
        "indicator_names": sorted(set(indicators)),
        "matched_assignment_count": len(matched_lines),
        "matched_assignment_samples": matched_lines,
        "score": score,
        "environment_like": score >= 3,
    }


def classify_response(
    path: str,
    method: str,
    status_code: int,
    content_type: str,
    body: str,
    indicators: Dict[str, Any],
) -> str:
    if status_code in STATUS_ACCESS_CONTROL:
        return "access-controlled"

    if status_code in STATUS_REDIRECT:
        return "redirected"

    if status_code in STATUS_NOT_FOUND:
        return "not-found"

    if status_code in STATUS_SERVER_ERROR:
        return "server-error"

    if method == "HEAD":
        # HEAD has no response body by design. A 2xx response to an
        # environment candidate is useful evidence, but content exposure
        # itself must be established with GET.
        if 200 <= status_code < 300:
            return "candidate-accessible"
        return "application-response"

    if 200 <= status_code < 300:
        if indicators.get("environment_like"):
            if path == "/.env":
                return "environment-file-exposed"

            if path.endswith(".example"):
                return "environment-file-template-exposed"

            return "environment-file-candidate"

        # A normal application HTML page at /.env is commonly an application
        # fallback rather than an exposed file.
        if "text/html" in content_type.lower():
            return "application-response"

        return "application-response"

    return "application-response"


def make_url(scheme: str, target: str, port: int, path: str) -> str:
    if scheme == "http":
        default_port = 80
    else:
        default_port = 443

    host = target
    if ":" in target and not target.startswith("["):
        host = f"[{target}]"

    if port == default_port:
        return f"{scheme}://{host}{path}"

    return f"{scheme}://{host}:{port}{path}"


def target_pairs(target: str, ports: Iterable[int]) -> List[Tuple[str, int]]:
    pairs: List[Tuple[str, int]] = []

    for port in sorted(set(int(port) for port in ports)):
        if port == 80:
            pairs.append(("http", 80))
        elif port == 443:
            pairs.append(("https", 443))

    return pairs


def request_once(
    session: requests.Session,
    method: str,
    url: str,
    timeout: int,
) -> Dict[str, Any]:
    started = time.perf_counter()

    try:
        response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=False,
            data=None,
            headers={
                "User-Agent": (
                    "BrebesKab-CSIRT-Tools/"
                    f"{APP_VERSION} "
                    f"Checklist/{CHECKLIST_ID}"
                ),
                "Accept": "*/*",
            },
        )

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        body = ""
        if method != "HEAD":
            body = safe_body_text(response)

        content_type = get_content_type(response)
        indicators = detect_environment_indicators(
            body,
            content_type,
            "",
        )

        return {
            "request_ok": True,
            "error": None,
            "status_code": response.status_code,
            "headers": {
                "Content-Type": content_type,
                "Content-Length": response.headers.get("Content-Length"),
                "Location": response.headers.get("Location"),
                "Server": response.headers.get("Server"),
                "X-Powered-By": response.headers.get("X-Powered-By"),
            },
            "elapsed_ms": elapsed_ms,
            "body": body,
            "body_length": len(response.content),
            "body_sha256": sha256_text(body) if body else None,
            "response_url": response.url,
            "redirect_followed": False,
            "content_type": content_type,
        }

    except requests.RequestException as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        return {
            "request_ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "status_code": None,
            "headers": {},
            "elapsed_ms": elapsed_ms,
            "body": "",
            "body_length": 0,
            "body_sha256": None,
            "response_url": None,
            "redirect_followed": False,
            "content_type": "",
        }


def build_probe_record(
    result: Dict[str, Any],
    *,
    project: str,
    scope_id: str,
    target: str,
    scheme: str,
    port: int,
    path: str,
    method: str,
) -> Dict[str, Any]:
    body = result.get("body", "")
    content_type = result.get("content_type", "")

    indicators = detect_environment_indicators(
        body,
        content_type,
        path,
    )

    if not result["request_ok"]:
        classification = "probe-error"
    else:
        classification = classify_response(
            path,
            method,
            int(result["status_code"]),
            content_type,
            body,
            indicators,
        )

    return {
        "timestamp": utc_now(),
        "project": project,
        "checklist_id": CHECKLIST_ID,
        "scope_id": scope_id,
        "target": target,
        "scheme": scheme,
        "port": port,
        "path": path,
        "method": method,
        "url": make_url(scheme, target, port, path),
        "status_code": result.get("status_code"),
        "headers": result.get("headers", {}),
        "content_type": content_type,
        "elapsed_ms": result.get("elapsed_ms"),
        "body_length": result.get("body_length", 0),
        "body_sha256": result.get("body_sha256"),
        "body_sample": body_sample(body) if body else "",
        "environment_indicators": indicators,
        "classification": classification,
        "request_ok": result.get("request_ok"),
        "error": result.get("error"),
        "redirect_followed": False,
        "mutation": False,
        "request_body": None,
    }


def is_sensitive_environment_classification(classification: str) -> bool:
    return classification in {
        "environment-file-exposed",
        "environment-file-template-exposed",
        "environment-file-candidate",
    }


def summarize_probes(
    probes: List[Dict[str, Any]],
) -> Dict[str, int]:
    summary = {
        "environment_file_exposed": 0,
        "environment_file_template_exposed": 0,
        "environment_file_candidate": 0,
        "candidate_accessible": 0,
        "application_response": 0,
        "access_controlled": 0,
        "redirected": 0,
        "not_found": 0,
        "server_errors": 0,
        "probe_errors": 0,
    }

    for probe in probes:
        classification = probe.get("classification")

        if classification == "environment-file-exposed":
            summary["environment_file_exposed"] += 1
        elif classification == "environment-file-template-exposed":
            summary["environment_file_template_exposed"] += 1
        elif classification == "environment-file-candidate":
            summary["environment_file_candidate"] += 1
        elif classification == "candidate-accessible":
            summary["candidate_accessible"] += 1
        elif classification == "application-response":
            summary["application_response"] += 1
        elif classification == "access-controlled":
            summary["access_controlled"] += 1
        elif classification == "redirected":
            summary["redirected"] += 1
        elif classification == "not-found":
            summary["not_found"] += 1
        elif classification == "server-error":
            summary["server_errors"] += 1
        elif classification == "probe-error":
            summary["probe_errors"] += 1

    return summary


def relevant_cve_candidates(
    version_data: Dict[str, Any],
    probes: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Keep the CVE relationship conservative.

    4-006 does not independently decide whether a CVE applies. It only
    carries forward candidate evidence from 4-001 when environment exposure
    was actually observed.
    """
    exposure_observed = any(
        is_sensitive_environment_classification(
            str(probe.get("classification", ""))
        )
        for probe in probes
    )

    if not exposure_observed:
        return []

    candidates = extract_cve_candidates(version_data)

    result = []
    for item in candidates:
        cve_id = (
            item.get("cve_id")
            or item.get("id")
            or item.get("cve")
            or item.get("CVE")
        )

        if not cve_id:
            continue

        result.append(
            {
                "cve_id": str(cve_id),
                "source": "4-001 version.yaml",
                "classification": "candidate",
                "reason": (
                    "Inherited from observed product/version correlation "
                    "in 4-001; environment-file exposure is separate "
                    "evidence and does not establish CVE applicability."
                ),
            }
        )

    return result


def build_artifact(
    *,
    project: str,
    target: str,
    ports: List[int],
    scope_id: str,
    recon_count: int,
    candidates: List[str],
    probes: List[Dict[str, Any]],
    version_data: Dict[str, Any],
    error_data: Dict[str, Any],
) -> Dict[str, Any]:
    summary = summarize_probes(probes)
    cve_candidates = relevant_cve_candidates(version_data, probes)

    exposure_count = (
        summary["environment_file_exposed"]
        + summary["environment_file_template_exposed"]
        + summary["environment_file_candidate"]
    )

    technical_exposure = exposure_count > 0
    requires_review = technical_exposure or summary["probe_errors"] > 0

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": APP_NAME,
            "script": "env.py",
            "version": APP_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "category": "web-server-configuration",
        },
        "project": project,
        "target": {
            "type": "domain",
            "value": target,
            "scope_id": scope_id,
            "ports": ports,
        },
        "status": "completed",
        "assessment": {
            "finding": False,
            "requires_review": requires_review,
            "classification": (
                "environment-file-exposure-review"
                if requires_review
                else "no-environment-file-exposure-observed"
            ),
            "statement": (
                "Environment/configuration file exposure indicators were "
                "observed and require manual security assessment."
                if technical_exposure
                else (
                    "No environment-file exposure indicator was observed "
                    "in the controlled probes."
                )
            ),
            "automatic_finding_disabled": True,
        },
        "methodology": {
            "methods": list(METHODS),
            "redirect_following": False,
            "request_body": None,
            "mutation": False,
            "brute_force": False,
            "discovery": False,
            "body_limit_bytes": MAX_BODY_BYTES,
            "body_sample_chars": BODY_SAMPLE_CHARS,
        },
        "sources": {
            "recon_directory": (
                "02-reconnaissance/directory/directory.yaml"
            ),
            "version": (
                "04-web-server-configuration/version/version.yaml"
            ),
            "errors": (
                "04-web-server-configuration/errors/errors.yaml"
            ),
        },
        "recon": {
            "path_count": recon_count,
            "candidate_count": len(candidates),
            "candidate_source": "Recon directory + bounded explicit environment paths",
        },
        "summary": {
            "probes": len(probes),
            **summary,
            "environment_exposure_observed": exposure_count,
        },
        "cve": {
            "candidate_count": len(cve_candidates),
            "triage": (
                "CVE candidates are inherited from 4-001 version "
                "correlation. Version/CVE match is not a vulnerability "
                "finding and requires prerequisite/configuration/target "
                "evidence."
            ),
            "candidates": cve_candidates,
        },
        "correlation": {
            "error_checklist": CHECKLIST_ID,
            "supporting_4_010_available": bool(error_data),
            "supporting_4_010_note": (
                "4-010 is supporting evidence only; this checklist "
                "performs independent controlled environment-file probes."
            ),
        },
        "probes": probes,
        "generated_at": utc_now(),
    }


def print_version() -> None:
    print(f"{Path(__file__).name} v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("Methods:")
    for method in METHODS:
        print(f"  - {method}")
    print("Endpoint source: Recon directory.yaml + bounded environment candidates")
    print("Supporting evidence: 4-010 errors.yaml")
    print("CVE source: 4-001 version.yaml")
    print("Redirect following: disabled")
    print("Mutation payload: none")
    print("Discovery/brute force: disabled")
    print("Automatic finding: disabled")
    print("Raw evidence: retained")
    print("Report redaction: separate report-generation layer")


def command_init(root: Path) -> int:
    scope_path = locate_scope(root)
    scope = load_yaml(scope_path)

    project = discover_project_name(scope, root)
    target, ports, scope_id = select_domain_target(scope)

    recon_paths = load_recon_paths(root)
    candidates = derive_environment_candidates(recon_paths)

    output = root / "04-web-server-configuration" / "env" / "env.yaml"

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": APP_NAME,
            "script": "env.py",
            "version": APP_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
        },
        "project": project,
        "target": {
            "type": "domain",
            "value": target,
            "scope_id": scope_id,
            "ports": ports,
        },
        "status": "initialized",
        "methodology": {
            "methods": list(METHODS),
            "redirect_following": False,
            "mutation": False,
            "brute_force": False,
            "discovery": False,
        },
        "sources": {
            "recon_directory": (
                "02-reconnaissance/directory/directory.yaml"
            ),
            "version": (
                "04-web-server-configuration/version/version.yaml"
            ),
            "errors": (
                "04-web-server-configuration/errors/errors.yaml"
            ),
        },
        "recon": {
            "path_count": len(recon_paths),
            "candidate_count": len(candidates),
            "candidate_source": "Recon directory + bounded explicit environment paths",
        },
        "candidates": candidates,
        "probes": [],
        "assessment": {
            "finding": False,
            "requires_review": False,
        },
        "cve": {
            "candidate_count": 0,
            "candidates": [],
        },
        "generated_at": utc_now(),
    }

    dump_yaml(output, artifact)

    print("[PASS] Environment File Exposure berhasil diinisialisasi.")
    print(f"PROJECT         : {project}")
    print(f"TARGET          : {target}")
    print(f"PORTS           : {', '.join(map(str, ports))}")
    print(f"METHODS         : {', '.join(METHODS)}")
    print(f"RECON PATHS     : {len(recon_paths)}")
    print(f"CANDIDATES      : {len(candidates)}")
    print("SOURCE          : "
          "02-reconnaissance/directory/directory.yaml")
    print(f"FILE            : {output}")

    return 0


def command_analyze(
    root: Path,
    timeout: int,
    max_candidates: Optional[int] = None,
) -> int:
    scope_path = locate_scope(root)
    scope = load_yaml(scope_path)

    project = discover_project_name(scope, root)
    target, ports, scope_id = select_domain_target(scope)

    recon_paths = load_recon_paths(root)
    candidates = derive_environment_candidates(recon_paths)

    if max_candidates is not None:
        if max_candidates < 1:
            raise ValueError("--max-candidates harus >= 1")
        candidates = candidates[:max_candidates]

    version_data = load_version_artifact(root)
    error_data = load_error_artifact(root)

    output = root / "04-web-server-configuration" / "env" / "env.yaml"
    evidence_output = (
        root
        / "04-web-server-configuration"
        / "env"
        / "evidence"
        / "env-probes.json"
    )

    session = requests.Session()

    probes: List[Dict[str, Any]] = []

    pairs = target_pairs(target, ports)

    for scheme, port in pairs:
        for path in candidates:
            for method in METHODS:
                url = make_url(scheme, target, port, path)

                result = request_once(
                    session,
                    method,
                    url,
                    timeout,
                )

                probe = build_probe_record(
                    result,
                    project=project,
                    scope_id=scope_id,
                    target=target,
                    scheme=scheme,
                    port=port,
                    path=path,
                    method=method,
                )

                probes.append(probe)

    artifact = build_artifact(
        project=project,
        target=target,
        ports=ports,
        scope_id=scope_id,
        recon_count=len(recon_paths),
        candidates=candidates,
        probes=probes,
        version_data=version_data,
        error_data=error_data,
    )

    dump_json(
        evidence_output,
        {
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": APP_NAME,
                "script": "env.py",
                "version": APP_VERSION,
            },
            "checklist": CHECKLIST_ID,
            "project": project,
            "target": target,
            "generated_at": utc_now(),
            "probes": probes,
        },
    )

    dump_yaml(output, artifact)

    summary = artifact["summary"]
    cve_count = artifact["cve"]["candidate_count"]

    print("[PASS] Environment File Exposure berhasil dianalisis.")
    print(f"PROJECT         : {project}")
    print(f"TARGET          : {target}")
    print(f"CANDIDATES      : {len(candidates)}")
    print(f"METHODS         : {len(METHODS)}")
    print(f"PROBES          : {len(probes)}")
    print(
        "ENV EXPOSED     : "
        f"{summary['environment_file_exposed']}"
    )
    print(
        "ENV TEMPLATE    : "
        f"{summary['environment_file_template_exposed']}"
    )
    print(
        "ENV CANDIDATE   : "
        f"{summary['environment_file_candidate']}"
    )
    print(
        "ACCESS CONTROL  : "
        f"{summary['access_controlled']}"
    )
    print(
        "REDIRECTED      : "
        f"{summary['redirected']}"
    )
    print(
        "NOT FOUND       : "
        f"{summary['not_found']}"
    )
    print(
        "APPLICATION     : "
        f"{summary['application_response']}"
    )
    print(
        "SERVER ERRORS   : "
        f"{summary['server_errors']}"
    )
    print(
        "PROBE ERRORS    : "
        f"{summary['probe_errors']}"
    )
    print(f"CVE CANDIDATES  : {cve_count}")
    print(
        "REQUIRES REVIEW : "
        f"{artifact['assessment']['requires_review']}"
    )
    print(f"STATUS          : {artifact['assessment']['classification']}")
    print(f"FILE            : {output}")
    print(f"EVIDENCE        : {evidence_output}")

    return 0


def load_existing_artifact(root: Path) -> Dict[str, Any]:
    path = root / "04-web-server-configuration" / "env" / "env.yaml"
    return load_yaml(path)


def command_list(root: Path) -> int:
    artifact = load_existing_artifact(root)

    probes = artifact.get("probes", [])
    if not isinstance(probes, list):
        probes = []

    interesting = [
        probe
        for probe in probes
        if probe.get("classification")
        in {
            "environment-file-exposed",
            "environment-file-template-exposed",
            "environment-file-candidate",
            "candidate-accessible",
            "probe-error",
        }
    ]

    if not interesting:
        print("[INFO] Tidak ada environment-file observation yang perlu ditampilkan.")
        return 0

    print(
        f"[INFO] {len(interesting)} observation(s) "
        "environment-file/candidate:"
    )

    for probe in interesting:
        print(
            f"- {probe.get('scheme', '').upper()} "
            f"{probe.get('port')} "
            f"{probe.get('method')} "
            f"{probe.get('path')} "
            f"-> {probe.get('status_code')} "
            f"[{probe.get('classification')}]"
        )

        indicators = probe.get("environment_indicators") or {}
        names = indicators.get("indicator_names") or []

        if names:
            print(f"  indicators: {', '.join(names)}")

    return 0


def command_verify(root: Path) -> int:
    artifact = load_existing_artifact(root)

    errors: List[str] = []

    if artifact.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai.")

    checklist = artifact.get("checklist", {})
    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist.id tidak sesuai.")

    probes = artifact.get("probes")
    if not isinstance(probes, list):
        errors.append("probes harus berupa list.")
        probes = []

    target = artifact.get("target", {})
    target_value = target.get("value")
    ports = target.get("ports") or []

    candidates = artifact.get("recon", {}).get("candidate_count", 0)

    expected_pairs = len(
        target_pairs(
            str(target_value or ""),
            [int(p) for p in ports],
        )
    )
    expected_probes = int(candidates) * len(METHODS) * expected_pairs

    if len(probes) != expected_probes:
        errors.append(
            f"Jumlah probes {len(probes)} != expected {expected_probes}."
        )

    allowed_classifications = {
        "environment-file-exposed",
        "environment-file-template-exposed",
        "environment-file-candidate",
        "candidate-accessible",
        "application-response",
        "access-controlled",
        "redirected",
        "not-found",
        "server-error",
        "probe-error",
    }

    for index, probe in enumerate(probes):
        if probe.get("method") not in METHODS:
            errors.append(f"Probe #{index}: method tidak valid.")

        if probe.get("classification") not in allowed_classifications:
            errors.append(f"Probe #{index}: classification tidak valid.")

        if probe.get("redirect_followed") is not False:
            errors.append(
                f"Probe #{index}: redirect_followed harus false."
            )

        if probe.get("request_body") is not None:
            errors.append(
                f"Probe #{index}: request_body harus None."
            )

        if probe.get("mutation") is not False:
            errors.append(f"Probe #{index}: mutation harus false.")

        if probe.get("request_ok"):
            status = probe.get("status_code")
            if status is None:
                errors.append(
                    f"Probe #{index}: request_ok true tetapi "
                    "status_code kosong."
                )

        classification = probe.get("classification")
        indicators = probe.get("environment_indicators") or {}

        if classification == "environment-file-exposed":
            if probe.get("path") != "/.env":
                errors.append(
                    f"Probe #{index}: environment-file-exposed "
                    "harus berasal dari /.env."
                )

            if not indicators.get("environment_like"):
                errors.append(
                    f"Probe #{index}: exposed tetapi "
                    "environment_like false."
                )

    assessment = artifact.get("assessment", {})

    if assessment.get("finding") is not False:
        errors.append(
            "assessment.finding harus false; automatic finding disabled."
        )

    summary = artifact.get("summary", {})
    expected_review = (
        (
            int(summary.get("environment_file_exposed", 0))
            + int(summary.get("environment_file_template_exposed", 0))
            + int(summary.get("environment_file_candidate", 0))
        ) > 0
        or int(summary.get("probe_errors", 0)) > 0
    )

    if assessment.get("requires_review") != expected_review:
        errors.append(
            "assessment.requires_review tidak konsisten dengan summary."
        )

    cve = artifact.get("cve", {})
    if not isinstance(cve.get("candidates", []), list):
        errors.append("cve.candidates harus berupa list.")

    if errors:
        print("[FAIL] Environment File Exposure gagal validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] Environment File Exposure memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {artifact.get('status')}")
    print(f"[PASS] Target    : {target_value}")
    print(f"[PASS] Candidates: {candidates}")
    print(f"[PASS] Methods   : {len(METHODS)}")
    print(f"[PASS] Probes    : {len(probes)}")
    print(
        "[PASS] Exposed   : "
        f"{summary.get('environment_file_exposed', 0)}"
    )
    print(
        "[PASS] Template  : "
        f"{summary.get('environment_file_template_exposed', 0)}"
    )
    print(
        "[PASS] Candidate : "
        f"{summary.get('environment_file_candidate', 0)}"
    )
    print(
        "[PASS] CVE       : "
        f"{cve.get('candidate_count', 0)} candidate(s)"
    )
    print(
        "[PASS] Review    : "
        f"{1 if assessment.get('requires_review') else 0}"
    )
    print(
        "[PASS] CVE Triage: candidate classification is inherited from "
        "4-001; no automatic finding."
    )
    print(
        "[PASS] Assessment: environment-file indicators are review "
        "evidence; no automatic vulnerability finding."
    )

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "4-006 Environment File Exposure - "
            "BrebesKab-CSIRT-Tools"
        )
    )

    parser.add_argument(
        "command",
        choices=("version", "init", "analyze", "list", "verify"),
        help="Command yang dijalankan.",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout dalam detik (default: {DEFAULT_TIMEOUT}).",
    )

    parser.add_argument(
        "--max-candidates",
        type=int,
        default=None,
        help=(
            "Batasi jumlah candidate untuk controlled test. "
            "Opsional; jangan digunakan untuk assessment normal."
        ),
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("--timeout harus >= 1")

    root = args.root.resolve() if args.root else find_project_root()

    try:
        if args.command == "version":
            print_version()
            return 0

        if args.command == "init":
            return command_init(root)

        if args.command == "analyze":
            return command_analyze(
                root,
                timeout=args.timeout,
                max_candidates=args.max_candidates,
            )

        if args.command == "list":
            return command_list(root)

        if args.command == "verify":
            return command_verify(root)

        parser.error("Command tidak dikenal.")
        return 2

    except FileNotFoundError as exc:
        print(f"[ERROR] File tidak ditemukan: {exc}")
        return 1
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 1
    except yaml.YAMLError as exc:
        print(f"[ERROR] YAML tidak valid: {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[WARN] Dihentikan oleh pengguna.")
        return 130
    except Exception as exc:
        print(f"[ERROR] {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
