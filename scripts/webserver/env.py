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
APP_VERSION = "1.0.5"
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
    # scripts/webserver/env.py -> repository root
    return Path(__file__).resolve().parents[2]


def load_active_context(root: Path) -> Dict[str, Any]:
    """
    Load the repository-level active project context.

    Canonical runtime layout:
        <repository>/.runtime/active-project.yaml

    Compatibility fallback is intentionally retained for older executions.
    """
    runtime_file = root / ".runtime" / "active-project.yaml"
    if not runtime_file.exists():
        return {}

    data = load_yaml(runtime_file)
    if not isinstance(data, dict):
        return {}

    project_path_raw = data.get("project_path")
    if project_path_raw:
        project_path = Path(str(project_path_raw))
        if not project_path.is_absolute():
            project_path = root / project_path
        data["_resolved_project_path"] = str(project_path.resolve())

    return data


def find_project_root() -> Path:
    """
    Locate the active pentest project using the canonical runtime context.

    The authoritative selector is:
        <repository>/.runtime/active-project.yaml

    The resolved project_path must contain the canonical scope and Recon
    directory artifacts. Legacy project discovery remains as a compatibility
    fallback so existing executions are not broken.
    """
    repo_root = project_root_from_script()
    cwd = Path.cwd().resolve()

    def is_project_root(candidate: Path) -> bool:
        return (
            (candidate / "01-preparation" / "scope" / "scope.yaml").exists()
            and (
                candidate
                / "02-reconnaissance"
                / "directory"
                / "directory.yaml"
            ).exists()
        )

    # 1. Canonical active-project runtime context.
    try:
        context = load_active_context(repo_root)
    except Exception:
        context = {}

    resolved = context.get("_resolved_project_path")
    if resolved:
        active_root = Path(resolved)
        if is_project_root(active_root):
            return active_root

    # 2. Current working directory may already be the active project.
    if is_project_root(cwd):
        return cwd

    # 3. Legacy project discovery for compatibility.
    projects_dir = repo_root / "projects"
    if projects_dir.is_dir():
        project_candidates = sorted(
            (item for item in projects_dir.iterdir() if item.is_dir()),
            key=lambda item: item.name.lower(),
        )

        for candidate in project_candidates:
            if not is_project_root(candidate):
                continue
            if (candidate / "active-project.yaml").exists():
                return candidate

        for candidate in project_candidates:
            if is_project_root(candidate):
                return candidate

    # 4. Compatibility fallback for projects executed directly from root.
    if is_project_root(repo_root):
        return repo_root

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
    Build the bounded target set specifically for environment-file exposure.

    Recon is used only as supporting evidence: if Recon already discovered
    an environment-style path, it is retained. Ordinary application paths
    such as /favicon.ico, /robots.txt, /login, /dashboard, etc. are NOT
    environment-file candidates.

    This checklist must test environment/configuration exposure, not replay
    the entire Recon directory list.
    """
    environment_paths = set(ROOT_CANDIDATE_PATHS)

    for path in recon_paths:
        canonical = canonical_path(path)
        lower = canonical.lower()

        if (
            lower.startswith("/.env")
            or lower in {
                "/env",
                "/environment",
                "/config/.env",
                "/config/env",
                "/config/environment",
            }
        ):
            environment_paths.add(canonical)

    return sorted(
        environment_paths,
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
    Read CVE candidate evidence from the canonical 4-001 artifact.

    Canonical source:
        cve_correlation.products[].cves[]

    Compatibility fallbacks are retained for older version.yaml artifacts.
    This function never queries NVD and never decides vulnerability status.
    """
    candidates: List[Dict[str, Any]] = []

    correlation = version_data.get("cve_correlation")
    if isinstance(correlation, dict):
        products = correlation.get("products", [])
        if isinstance(products, list):
            for product in products:
                if not isinstance(product, dict):
                    continue
                product_name = product.get("product")
                product_version = product.get("version")
                cves = product.get("cves", [])
                if not isinstance(cves, list):
                    continue
                for item in cves:
                    if not isinstance(item, dict):
                        continue
                    enriched = dict(item)
                    if product_name is not None:
                        enriched.setdefault("product", product_name)
                    if product_version is not None:
                        enriched.setdefault("version", product_version)
                    candidates.append(enriched)

        # Compatibility with intermediate canonical artifacts.
        for key in ("candidates", "results", "items"):
            value = correlation.get(key)
            if isinstance(value, list):
                candidates.extend(
                    item for item in value if isinstance(item, dict)
                )

    # Legacy fallbacks.
    for container in (
        version_data.get("cve"),
        version_data.get("cves"),
        version_data.get("cve_candidates"),
        version_data.get("assessment"),
    ):
        if isinstance(container, list):
            candidates.extend(
                item for item in container if isinstance(item, dict)
            )
        elif isinstance(container, dict):
            for key in ("candidates", "results", "items"):
                value = container.get(key)
                if isinstance(value, list):
                    candidates.extend(
                        item for item in value if isinstance(item, dict)
                    )

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


def source_status(source: Dict[str, Any]) -> str:
    """Read checklist status from canonical or legacy artifacts."""
    checklist = source.get("checklist")
    if isinstance(checklist, dict) and checklist.get("status"):
        return str(checklist.get("status"))

    if source.get("status"):
        return str(source.get("status"))

    return "missing"


def build_source_status(
    *,
    root: Path,
    recon_paths: List[str],
    version_data: Dict[str, Any],
    error_data: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "scope": {
            "path": "01-preparation/scope/scope.yaml",
            "status": "available",
        },
        "recon_directory": {
            "path": "02-reconnaissance/directory/directory.yaml",
            "status": "available" if recon_paths else "missing",
        },
        "version_4_001": {
            "path": "04-web-server-configuration/version/version.yaml",
            "status": source_status(version_data),
        },
        "errors_4_010": {
            "path": "04-web-server-configuration/errors/errors.yaml",
            "status": source_status(error_data),
        },
    }


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
    is_environment_candidate: bool,
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
            if is_environment_candidate:
                return "candidate-accessible"
            return "application-response"
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
            path in ROOT_CANDIDATE_PATHS
            or path.lower().startswith("/.env"),
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
    root: Path,
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

    context = load_active_context(project_root_from_script())
    application = context.get("application") or ""
    environment = context.get("environment") or "Production"
    assessment_type = context.get("assessment_type") or "Grey Box"
    project_id = context.get("project_id") or project

    now = utc_now()

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": str(project_id),
        "tool": {
            "name": APP_NAME,
            "script": "env.py",
            "version": APP_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": "04 Web Server Configuration",
            "focus": "Environment/configuration file exposure",
            "status": "completed",
        },
        "target": {
            "application": application,
            "hostname": target,
            "url": f"https://{target}",
            "environment": environment,
            "assessment_type": assessment_type,
            "scope_id": scope_id,
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": ports,
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
            "candidate_source": (
                "Bounded environment/configuration paths; Recon used only "
                "to retain discovered environment-style paths"
            ),
            "boundary": (
                "Controlled GET/HEAD probes only; no authentication "
                "guessing, exploitation, mutation, or destructive action."
            ),
        },
        "baseline": {
            "recon_path_count": recon_count,
            "candidate_count": len(candidates),
            "authorized_ports": ports,
            "methods": list(METHODS),
        },
        "toolchain": {
            "python": "runtime",
            "http_client": "requests",
            "yaml": "PyYAML",
            "supporting_checklist": "4-010 Error Information Disclosure",
            "cve_source": "4-001 Server Version Disclosure",
        },
        "probe": {
            "protocols": ["http", "https"],
            "methods": list(METHODS),
            "timeout_seconds": DEFAULT_TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "redirect_following": False,
            "request_body": None,
            "mutation": False,
        },
        "source_status": build_source_status(
            root=root,
            recon_paths=load_recon_paths(root),
            version_data=version_data,
            error_data=error_data,
        ),
        "results": {
            "candidates": candidates,
            "probes": probes,
        },
        "summary": {
            "probes": len(probes),
            **summary,
            "environment_exposure_observed": exposure_count,
        },
        "cve_correlation": {
            "source": "04-web-server-configuration/version/version.yaml",
            "candidate_count": len(cve_candidates),
            "candidates": cve_candidates,
            "triage": (
                "CVE candidates are inherited from 4-001 version "
                "correlation. Version/CVE match is not a vulnerability "
                "finding and requires prerequisite/configuration/target "
                "evidence."
            ),
        },
        "assessment": {
            "result": (
                "environment-file-exposure-review"
                if requires_review
                else "no-environment-file-exposure-observed"
            ),
            "finding": False,
            "requires_review": requires_review,
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
        "evidence": {
            "raw_probe_file": (
                "04-web-server-configuration/env/evidence/env-probes.json"
            ),
            "supporting_4_010": {
                "available": bool(error_data),
                "path": "04-web-server-configuration/errors/errors.yaml",
                "role": "supporting evidence only",
            },
        },
        "errors": {
            "probe_errors": summary["probe_errors"],
        },
        "notes": [
            "Raw probe evidence is retained without report-layer redaction.",
            "Report generation/redaction is intentionally outside this script.",
            "CVE correlation is candidate evidence only; no automatic finding is created.",
        ],
        "generated_at": now,
        "updated_at": now,
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

    context = load_active_context(project_root_from_script())
    application = context.get("application") or ""
    environment = context.get("environment") or "Production"
    assessment_type = context.get("assessment_type") or "Grey Box"
    project_id = context.get("project_id") or project
    now = utc_now()

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "project_id": str(project_id),
        "tool": {
            "name": APP_NAME,
            "script": "env.py",
            "version": APP_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": "04 Web Server Configuration",
            "focus": "Environment/configuration file exposure",
            "status": "initialized",
        },
        "target": {
            "application": application,
            "hostname": target,
            "url": f"https://{target}",
            "environment": environment,
            "assessment_type": assessment_type,
            "scope_id": scope_id,
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": ports,
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
            "candidate_source": (
                "Bounded environment/configuration paths; Recon used only "
                "to retain discovered environment-style paths"
            ),
        },
        "baseline": {
            "recon_path_count": len(recon_paths),
            "candidate_count": len(candidates),
            "authorized_ports": ports,
            "methods": list(METHODS),
        },
        "toolchain": {
            "http_client": "requests",
            "yaml": "PyYAML",
            "supporting_checklist": "4-010 Error Information Disclosure",
            "cve_source": "4-001 Server Version Disclosure",
        },
        "probe": {
            "protocols": ["http", "https"],
            "methods": list(METHODS),
            "timeout_seconds": DEFAULT_TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "redirect_following": False,
            "request_body": None,
            "mutation": False,
        },
        "source_status": {
            "scope": {
                "path": "01-preparation/scope/scope.yaml",
                "status": "available",
            },
            "recon_directory": {
                "path": "02-reconnaissance/directory/directory.yaml",
                "status": "available" if recon_paths else "missing",
            },
            "version_4_001": {
                "path": "04-web-server-configuration/version/version.yaml",
                "status": (
                    "available"
                    if (
                        root
                        / "04-web-server-configuration"
                        / "version"
                        / "version.yaml"
                    ).exists()
                    else "missing"
                ),
            },
            "errors_4_010": {
                "path": "04-web-server-configuration/errors/errors.yaml",
                "status": (
                    "available"
                    if (
                        root
                        / "04-web-server-configuration"
                        / "errors"
                        / "errors.yaml"
                    ).exists()
                    else "missing"
                ),
            },
        },
        "results": {
            "candidates": candidates,
            "probes": [],
        },
        "summary": {
            "probes": 0,
            **summarize_probes([]),
            "environment_exposure_observed": 0,
        },
        "cve_correlation": {
            "source": "04-web-server-configuration/version/version.yaml",
            "candidate_count": 0,
            "candidates": [],
            "triage": (
                "CVE candidates are candidate evidence only; no automatic "
                "vulnerability finding."
            ),
        },
        "assessment": {
            "result": "initialized",
            "finding": False,
            "requires_review": False,
            "automatic_finding_disabled": True,
        },
        "evidence": {
            "raw_probe_file": (
                "04-web-server-configuration/env/evidence/env-probes.json"
            ),
        },
        "errors": {
            "probe_errors": 0,
        },
        "notes": [
            "Raw probe evidence is retained without report-layer redaction.",
            "Report generation/redaction is intentionally outside this script.",
        ],
        "generated_at": now,
        "updated_at": now,
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
        root=root,
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
            "project_id": project,
            "target": {
                "hostname": target,
                "scope_id": scope_id,
                "authorized_ports": ports,
            },
            "generated_at": utc_now(),
            "probes": probes,
        },
    )

    dump_yaml(output, artifact)

    summary = artifact["summary"]
    cve_count = artifact["cve_correlation"]["candidate_count"]

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
    print(f"STATUS          : {artifact['assessment']['result']}")
    print(f"FILE            : {output}")
    print(f"EVIDENCE        : {evidence_output}")

    return 0


def load_existing_artifact(root: Path) -> Dict[str, Any]:
    path = root / "04-web-server-configuration" / "env" / "env.yaml"
    return load_yaml(path)


def command_list(root: Path) -> int:
    artifact = load_existing_artifact(root)

    probes = artifact.get("results", {}).get("probes", [])
    if not isinstance(probes, list):
        probes = []

    interesting = [
        probe
        for probe in probes
        if (
            probe.get("classification")
            in {
                "environment-file-exposed",
                "environment-file-template-exposed",
                "environment-file-candidate",
                "candidate-accessible",
                "probe-error",
            }
            and (
                str(probe.get("path", "")).lower().startswith("/.env")
                or str(probe.get("path", "")).lower() in {
                    "/env",
                    "/environment",
                    "/config/.env",
                    "/config/env",
                    "/config/environment",
                }
                or probe.get("classification") == "probe-error"
            )
        )
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

    if not artifact.get("project_id"):
        errors.append("project_id tidak boleh kosong.")

    tool = artifact.get("tool", {})
    if not isinstance(tool, dict) or tool.get("script") != "env.py":
        errors.append("tool.script tidak sesuai.")

    checklist = artifact.get("checklist", {})
    if not isinstance(checklist, dict):
        errors.append("checklist harus berupa object.")
        checklist = {}

    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist.id tidak sesuai.")

    target = artifact.get("target", {})
    if not isinstance(target, dict):
        errors.append("target harus berupa object.")
        target = {}

    target_value = target.get("hostname")
    ports = target.get("authorized_ports") or []

    if not target_value:
        errors.append("target.hostname tidak boleh kosong.")

    if not isinstance(ports, list):
        errors.append("target.authorized_ports harus berupa list.")
        ports = []

    results = artifact.get("results", {})
    if not isinstance(results, dict):
        errors.append("results harus berupa object.")
        results = {}

    probes = results.get("probes")
    if not isinstance(probes, list):
        errors.append("results.probes harus berupa list.")
        probes = []

    candidates = results.get("candidates")
    if not isinstance(candidates, list):
        errors.append("results.candidates harus berupa list.")
        candidates = []

    expected_pairs = len(
        target_pairs(
            str(target_value or ""),
            [int(p) for p in ports if str(p).isdigit()],
        )
    )
    expected_probes = len(candidates) * len(METHODS) * expected_pairs

    status = checklist.get("status")
    if status == "completed" and len(probes) != expected_probes:
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
            if probe.get("status_code") is None:
                errors.append(
                    f"Probe #{index}: request_ok true tetapi "
                    "status_code kosong."
                )

        classification = probe.get("classification")
        indicators = probe.get("environment_indicators") or {}
        path_lower = str(probe.get("path", "")).lower()
        is_environment_candidate = (
            path_lower.startswith("/.env")
            or path_lower in {
                "/env",
                "/environment",
                "/config/.env",
                "/config/env",
                "/config/environment",
            }
        )

        if classification == "candidate-accessible" and not is_environment_candidate:
            errors.append(
                f"Probe #{index}: candidate-accessible hanya boleh "
                "digunakan untuk environment candidate."
            )

        if classification in {
            "environment-file-exposed",
            "environment-file-template-exposed",
            "environment-file-candidate",
            "candidate-accessible",
        } and not is_environment_candidate:
            errors.append(
                f"Probe #{index}: environment classification pada "
                "non-environment path."
            )

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

    summary = artifact.get("summary", {})
    if not isinstance(summary, dict):
        errors.append("summary harus berupa object.")
        summary = {}

    recalculated = summarize_probes(probes)
    for key, value in recalculated.items():
        if int(summary.get(key, -1)) != int(value):
            errors.append(
                f"summary.{key} tidak konsisten: "
                f"{summary.get(key)} != {value}."
            )

    expected_exposure = (
        recalculated["environment_file_exposed"]
        + recalculated["environment_file_template_exposed"]
        + recalculated["environment_file_candidate"]
    )
    if int(summary.get("environment_exposure_observed", -1)) != expected_exposure:
        errors.append(
            "summary.environment_exposure_observed tidak konsisten."
        )

    assessment = artifact.get("assessment", {})
    if not isinstance(assessment, dict):
        errors.append("assessment harus berupa object.")
        assessment = {}

    expected_review = expected_exposure > 0 or recalculated["probe_errors"] > 0

    if assessment.get("finding") is not False:
        errors.append(
            "assessment.finding harus false; automatic finding disabled."
        )

    if assessment.get("requires_review") != expected_review:
        errors.append(
            "assessment.requires_review tidak konsisten dengan summary."
        )

    cve = artifact.get("cve_correlation", {})
    if not isinstance(cve, dict):
        errors.append("cve_correlation harus berupa object.")
        cve = {}

    cve_candidates = cve.get("candidates", [])
    if not isinstance(cve_candidates, list):
        errors.append("cve_correlation.candidates harus berupa list.")
        cve_candidates = []

    if int(cve.get("candidate_count", -1)) != len(cve_candidates):
        errors.append(
            "cve_correlation.candidate_count tidak konsisten dengan candidates."
        )

    source_status_data = artifact.get("source_status", {})
    if not isinstance(source_status_data, dict):
        errors.append("source_status harus berupa object.")

    if errors:
        print("[FAIL] Environment File Exposure gagal validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] Environment File Exposure memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Version   : {APP_VERSION}")
    print(f"[PASS] Status    : {status}")
    print(f"[PASS] Target    : {target_value}")
    print(f"[PASS] Candidates: {len(candidates)}")
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
