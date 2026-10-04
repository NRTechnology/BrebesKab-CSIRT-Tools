#!/usr/bin/env python3
"""
git.py - Git Repository / Metadata Exposure
Checklist: 4-007
Project: BrebesKab-CSIRT-Tools

Purpose
-------
Controlled assessment of Git repository metadata that may be accidentally
exposed through HTTP/HTTPS.

This script:
- Uses the authorized scope from scope.yaml.
- Uses Recon directory.yaml as the authoritative endpoint source.
- Adds a small, bounded set of Git metadata candidates.
- Probes only GET and HEAD.
- Does not follow redirects.
- Does not submit request bodies or mutate server state.
- Does not clone, reconstruct, or recursively download a Git repository.
- Classifies responses using HTTP behavior and conservative Git metadata
  indicators, not status code alone.
- Uses 4-001 version.yaml as supporting CVE/version evidence. It does not
  turn a server version match into a Git exposure finding.
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
from typing import Any, Dict, List, Optional, Tuple

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
APP_VERSION = "1.0.2"
SCHEMA_VERSION = "1.0"

CHECKLIST_ID = "4-007"
CHECKLIST_NAME = "Git Exposure"

METHODS = ("GET", "HEAD")
DEFAULT_TIMEOUT = 15
MAX_BODY_BYTES = 256 * 1024
BODY_SAMPLE_CHARS = 4000

# Bounded, non-bruteforce Git metadata candidates.
# We intentionally do not probe Git object hashes or recursively enumerate
# refs/objects because this checklist is for exposure assessment, not source
# code/repository extraction.
ROOT_CANDIDATE_PATHS = (
    "/.git/",
    "/.git/HEAD",
    "/.git/config",
    "/.git/description",
    "/.git/index",
    "/.git/packed-refs",
    "/.git/refs/heads/",
    "/.git/refs/tags/",
    "/.git/logs/HEAD",
)

GIT_HEAD_RE = re.compile(
    r"(?m)^[ \t]*ref:[ \t]+refs/heads/[^\r\n]+[ \t]*$"
)

GIT_CONFIG_SECTION_RE = re.compile(
    r"(?mi)^[ \t]*\[(?:core|remote|branch|user|http|credential|submodule)"
    r"(?:\s+[^]]+)?\][ \t]*$"
)

GIT_CONFIG_ASSIGNMENT_RE = re.compile(
    r"(?mi)^[ \t]*(?:repositoryformatversion|filemode|bare|"
    r"logallrefupdates|url|fetch|merge|path|ignorecase)[ \t]*="
)

GIT_REF_RE = re.compile(
    r"(?mi)(?:^|\s)refs/(?:heads|tags)/[A-Za-z0-9._/@+\-]+"
)

GIT_LOG_RE = re.compile(
    r"(?mi)^[0-9a-f]{40}[ \t]+[0-9a-f]{40}[ \t]+"
    r".{1,120}(?:\t|[ \t]+).+"
)

GIT_INDEX_SIGNATURE = b"DIRC"
GIT_PACK_SIGNATURE = b"PACK"

TEXT_CONTENT_TYPES = (
    "text/plain",
    "text/html",
    "text/css",
    "application/json",
    "application/javascript",
    "text/javascript",
    "application/octet-stream",
)

STATUS_ACCESS_CONTROL = {401, 403, 405}
STATUS_REDIRECT = {300, 301, 302, 303, 307, 308}
STATUS_NOT_FOUND = {404, 410}
STATUS_SERVER_ERROR = set(range(500, 600))

GIT_PATHS = {item.lower() for item in ROOT_CANDIDATE_PATHS}


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
        json.dump(data, handle, ensure_ascii=False, indent=2)


def project_root_from_script() -> Path:
    # scripts/webserver/git.py -> repository root
    return Path(__file__).resolve().parents[2]


def find_project_root() -> Path:
    """
    Locate the active pentest project root.

    Canonical repository layout:
        <repository>/
        ├── scripts/webserver/git.py
        └── projects/PENTEST-2026-002/
            ├── active-project.yaml
            ├── 01-preparation/scope/scope.yaml
            └── 02-reconnaissance/directory/directory.yaml
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

    if is_project_root(cwd):
        return cwd

    projects_dir = repo_root / "projects"
    if projects_dir.is_dir():
        candidates = sorted(
            (item for item in projects_dir.iterdir() if item.is_dir()),
            key=lambda item: item.name.lower(),
        )

        for candidate in candidates:
            if is_project_root(candidate) and (
                candidate / "active-project.yaml"
            ).exists():
                return candidate

        for candidate in candidates:
            if is_project_root(candidate):
                return candidate

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

    return root.name


def extract_in_scope(scope: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Canonical structure:
        scope:
          in_scope:
            - scope_id: IN-001
              type: domain
              value: example.test
              ports: [80, 443]
    """
    scope_section = scope.get("scope", {})

    if isinstance(scope_section, dict):
        items = scope_section.get("in_scope", [])
    else:
        items = []

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


def select_domain_target(
    scope: Dict[str, Any],
) -> Tuple[str, List[int], str]:
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

    path = path.split("?", 1)[0].split("#", 1)[0]

    return path or "/"


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

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(paths))


def is_git_path(path: str) -> bool:
    lower = canonical_path(path).lower()
    return lower.startswith("/.git/" ) or lower == "/.git"


def derive_git_candidates(recon_paths: List[str]) -> List[str]:
    """
    Build a bounded Git candidate list.

    Recon is used only to retain discovered Git-style paths. Ordinary Recon
    endpoints are deliberately excluded so this checklist cannot turn into
    generic endpoint fuzzing.
    """
    candidates: List[str] = list(ROOT_CANDIDATE_PATHS)

    for path in recon_paths:
        normalized = canonical_path(path)
        lower = normalized.lower()

        if (
            lower == "/.git"
            or lower.startswith("/.git/")
        ):
            candidates.append(normalized)

    return list(dict.fromkeys(candidates))


def load_version_artifact(root: Path) -> Dict[str, Any]:
    path = (
        root
        / "04-web-server-configuration"
        / "version"
        / "version.yaml"
    )

    if not path.exists():
        return {}

    try:
        return load_yaml(path)
    except Exception:
        return {}


def load_error_artifact(root: Path) -> Dict[str, Any]:
    path = (
        root
        / "04-web-server-configuration"
        / "errors"
        / "errors.yaml"
    )

    if not path.exists():
        return {}

    try:
        return load_yaml(path)
    except Exception:
        return {}


def make_url(
    scheme: str,
    target: str,
    port: int,
    path: str,
) -> str:
    default_port = (
        (scheme == "http" and int(port) == 80)
        or (scheme == "https" and int(port) == 443)
    )

    authority = target if default_port else f"{target}:{port}"

    return f"{scheme}://{authority}{canonical_path(path)}"


def target_pairs(
    target: str,
    ports: List[int],
) -> List[Tuple[str, int]]:
    pairs: List[Tuple[str, int]] = []

    for port in ports:
        port_int = int(port)

        if port_int == 80:
            pairs.append(("http", port_int))
        elif port_int == 443:
            pairs.append(("https", port_int))

    return pairs


def request_once(
    session: requests.Session,
    method: str,
    url: str,
    timeout: int,
) -> Dict[str, Any]:
    started = time.perf_counter()

    try:
        response: Response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=False,
            data=None,
            headers={
                "User-Agent": (
                    "BrebesKab-CSIRT-Tools/"
                    f"{APP_VERSION} "
                    "Git-Exposure-Assessment"
                ),
                "Accept": "*/*",
                "Connection": "close",
            },
            stream=True,
        )

        elapsed_ms = round(
            (time.perf_counter() - started) * 1000,
            2,
        )

        content_type = response.headers.get("Content-Type", "")
        location = response.headers.get("Location")
        server = response.headers.get("Server")

        body_bytes = b""
        body_truncated = False

        # HEAD responses intentionally have no body to classify. For GET,
        # read only a bounded amount of data. We never recursively fetch
        # linked resources or Git objects.
        if method == "GET":
            remaining = MAX_BODY_BYTES
            chunks: List[bytes] = []

            for chunk in response.iter_content(
                chunk_size=8192,
            ):
                if not chunk:
                    continue

                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    body_truncated = True
                    break

                chunks.append(chunk)
                remaining -= len(chunk)

                if remaining <= 0:
                    body_truncated = True
                    break

            body_bytes = b"".join(chunks)

        response.close()

        return {
            "request_ok": True,
            "status_code": response.status_code,
            "reason": response.reason,
            "headers": {
                "content_type": content_type,
                "content_length": response.headers.get("Content-Length"),
                "location": location,
                "server": server,
                "etag": response.headers.get("ETag"),
                "last_modified": response.headers.get("Last-Modified"),
            },
            "elapsed_ms": elapsed_ms,
            "body_bytes": body_bytes,
            "body_truncated": body_truncated,
            "error": None,
        }

    except requests.RequestException as exc:
        elapsed_ms = round(
            (time.perf_counter() - started) * 1000,
            2,
        )

        return {
            "request_ok": False,
            "status_code": None,
            "reason": None,
            "headers": {},
            "elapsed_ms": elapsed_ms,
            "body_bytes": b"",
            "body_truncated": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def decode_body(body_bytes: bytes) -> Tuple[str, str]:
    if not body_bytes:
        return "", "utf-8"

    candidates = ["utf-8", "utf-8-sig", "latin-1"]

    for encoding in candidates:
        try:
            return body_bytes.decode(encoding), encoding
        except UnicodeDecodeError:
            continue

    return body_bytes.decode("utf-8", errors="replace"), "utf-8-replace"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def body_fingerprint(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip().lower()

    if not normalized:
        return ""

    return hashlib.sha256(
        normalized[:BODY_SAMPLE_CHARS].encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def looks_like_application_response(
    content_type: str,
    text: str,
    path: str,
) -> bool:
    """
    Conservative application-response detector.

    A 200 response is not considered Git exposure merely because a Git path
    was requested. Common application/debug/HTML responses are separated from
    actual Git metadata indicators.
    """
    lower_text = text.lower()
    content_lower = (content_type or "").lower()

    if "text/html" in content_lower:
        if (
            "<html" in lower_text
            or "<!doctype" in lower_text
            or "<body" in lower_text
        ):
            return True

    application_markers = (
        "codeigniter",
        "laravel",
        "debugbar",
        "kint",
        "page not found",
        "the requested url was not found",
        "route not found",
    )

    return any(marker in lower_text for marker in application_markers)


def detect_git_indicators(
    path: str,
    body_bytes: bytes,
    content_type: str,
) -> Dict[str, Any]:
    text, encoding = decode_body(body_bytes)
    lower_path = canonical_path(path).lower()

    names: List[str] = []
    strong = False
    metadata_like = False
    environment_like = False

    if GIT_HEAD_RE.search(text):
        names.append("git_head_ref")
        strong = True
        metadata_like = True

    if GIT_CONFIG_SECTION_RE.search(text):
        names.append("git_config_section")
        strong = True
        metadata_like = True

    if GIT_CONFIG_ASSIGNMENT_RE.search(text):
        names.append("git_config_assignment")
        strong = True
        metadata_like = True

    if GIT_REF_RE.search(text):
        names.append("git_ref")
        strong = True
        metadata_like = True

    if GIT_LOG_RE.search(text):
        names.append("git_reflog_like")
        strong = True
        metadata_like = True

    # Binary signatures are meaningful only for the paths where they are
    # expected. We do not attempt to parse or reconstruct Git objects.
    if lower_path.endswith("/index") and body_bytes.startswith(
        GIT_INDEX_SIGNATURE
    ):
        names.append("git_index_signature")
        strong = True
        metadata_like = True

    if lower_path.endswith("/packed-refs"):
        if re.search(
            rb"(?m)^(?:[0-9a-f]{40})[ \t]+refs/",
            body_bytes,
        ):
            names.append("git_packed_refs")
            strong = True
            metadata_like = True

    if lower_path.endswith("/logs/head") and GIT_LOG_RE.search(text):
        names.append("git_logs_head")
        strong = True
        metadata_like = True

    # Weak supporting marker: a body explicitly identifying Git metadata.
    if ".git/" in text.lower() and not names:
        names.append("git_path_marker")
        metadata_like = True

    # Detect environment/secret-looking assignments only as contextual
    # evidence. This is not used as a Git exposure condition by itself.
    if re.search(
        r"(?mi)^[ \t]*(?:export[ \t]+)?"
        r"(?:[A-Z][A-Z0-9_]{1,80})[ \t]*=",
        text,
    ):
        environment_like = True

    is_textual = (
        not body_bytes
        or "text/" in (content_type or "").lower()
        or "json" in (content_type or "").lower()
        or "javascript" in (content_type or "").lower()
        or encoding.startswith("utf")
    )

    return {
        "indicator_names": names,
        "strong_git_indicator": strong,
        "metadata_like": metadata_like,
        "environment_like": environment_like,
        "textual": is_textual,
        "body_sample": text[:BODY_SAMPLE_CHARS],
        "body_sample_truncated": len(text) > BODY_SAMPLE_CHARS,
    }


def classify_response(
    method: str,
    path: str,
    result: Dict[str, Any],
) -> str:
    if not result.get("request_ok"):
        return "probe-error"

    status = result.get("status_code")
    headers = result.get("headers") or {}
    content_type = str(headers.get("content_type") or "")

    body = result.get("body_bytes") or b""
    indicators = detect_git_indicators(
        path,
        body,
        content_type,
    )

    if status in STATUS_SERVER_ERROR:
        return "server-error"

    if status in STATUS_ACCESS_CONTROL:
        return "access-controlled"

    if status in STATUS_REDIRECT:
        return "redirected"

    if status in STATUS_NOT_FOUND:
        return "not-found"

    if status is None:
        return "probe-error"

    # For HEAD, there is intentionally no response body to classify.
    # A 2xx HEAD alone is not enough to claim Git exposure. GET must provide
    # metadata evidence before a positive Git classification is made.
    if method == "HEAD":
        if 200 <= int(status) < 300:
            return "application-response"
        return "application-response"

    if indicators["strong_git_indicator"]:
        if path.lower().endswith("/config"):
            return "git-config-exposed"

        if path.lower().endswith("/head"):
            return "git-head-exposed"

        return "git-metadata-exposed"

    text, _ = decode_body(body)

    if (
        200 <= int(status) < 300
        and indicators["metadata_like"]
        and not looks_like_application_response(
            content_type,
            text,
            path,
        )
    ):
        return "git-metadata-candidate"

    if 200 <= int(status) < 300:
        return "application-response"

    return "application-response"


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
    classification = classify_response(
        method,
        path,
        result,
    )

    body_bytes = result.get("body_bytes") or b""
    body_text, encoding = decode_body(body_bytes)
    headers = result.get("headers") or {}

    indicators = detect_git_indicators(
        path,
        body_bytes,
        str(headers.get("content_type") or ""),
    )

    # Raw evidence intentionally retains the body locally. Report generation
    # is responsible for redacting secrets/tokens/credentials later.
    return {
        "project": project,
        "scope_id": scope_id,
        "target": target,
        "scheme": scheme,
        "port": int(port),
        "method": method,
        "path": canonical_path(path),
        "url": make_url(
            scheme,
            target,
            int(port),
            path,
        ),
        "request_ok": bool(result.get("request_ok")),
        "request_body": None,
        "mutation": False,
        "redirect_followed": False,
        "status_code": result.get("status_code"),
        "reason": result.get("reason"),
        "response_headers": headers,
        "response_time_ms": result.get("elapsed_ms"),
        "content_encoding": encoding,
        "body_length": len(body_bytes),
        "body_truncated": bool(result.get("body_truncated")),
        "body_sha256": sha256_bytes(body_bytes),
        "body_fingerprint": body_fingerprint(body_text),
        "body": body_text,
        "git_indicators": {
            "indicator_names": indicators["indicator_names"],
            "strong_git_indicator": indicators["strong_git_indicator"],
            "metadata_like": indicators["metadata_like"],
            "environment_like": indicators["environment_like"],
            "textual": indicators["textual"],
        },
        "classification": classification,
        "error": result.get("error"),
    }


def build_summary(probes: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {
        "git_metadata_exposed": 0,
        "git_config_exposed": 0,
        "git_head_exposed": 0,
        "git_metadata_candidate": 0,
        "access_controlled": 0,
        "redirected": 0,
        "not_found": 0,
        "application_response": 0,
        "server_errors": 0,
        "probe_errors": 0,
    }

    mapping = {
        "git-metadata-exposed": "git_metadata_exposed",
        "git-config-exposed": "git_config_exposed",
        "git-head-exposed": "git_head_exposed",
        "git-metadata-candidate": "git_metadata_candidate",
        "access-controlled": "access_controlled",
        "redirected": "redirected",
        "not-found": "not_found",
        "application-response": "application_response",
        "server-error": "server_errors",
        "probe-error": "probe_errors",
    }

    for probe in probes:
        classification = probe.get("classification")
        key = mapping.get(classification)

        if key:
            counts[key] += 1

    return counts


def build_cve_correlation(
    version_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Git exposure is not automatically a CVE.

    We inspect the 4-001 artifact only to retain traceability to the
    established product/version evidence. No CVE is assigned to a Git
    exposure unless a direct, target-specific correlation is established.
    Therefore this checklist starts with zero CVE candidates.
    """
    version_checklist = version_data.get("checklist", {})
    version_target = version_data.get("target", {})
    version_summary = version_data.get("summary", {})

    if not isinstance(version_checklist, dict):
        version_checklist = {}
    if not isinstance(version_target, dict):
        version_target = {}
    if not isinstance(version_summary, dict):
        version_summary = {}

    source_target = (
        version_target.get("hostname")
        or version_target.get("value")
    )

    return {
        "source": (
            "04-web-server-configuration/version/version.yaml"
            if version_data
            else None
        ),
        "source_checklist": version_checklist.get("id"),
        "source_target": source_target,
        "source_disclosed_versions": version_summary.get("unique_versions"),
        "candidate_count": 0,
        "candidates": [],
        "assessment_note": (
            "Tidak ada CVE yang dikaitkan otomatis dengan Git exposure. "
            "CVE/version evidence dari 4-001 hanya digunakan sebagai "
            "supporting traceability; version match bukan vulnerability."
        ),
    }


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
    summary = build_summary(probes)

    positive_count = (
        summary["git_metadata_exposed"]
        + summary["git_config_exposed"]
        + summary["git_head_exposed"]
        + summary["git_metadata_candidate"]
    )

    requires_review = (
        positive_count > 0
        or summary["probe_errors"] > 0
    )

    if summary["probe_errors"] > 0:
        classification = "probe-error-review"
    elif positive_count > 0:
        classification = "git-exposure-review"
    else:
        classification = "no-git-exposure-observed"

    cve = build_cve_correlation(version_data)

    target_url = make_url("https", target, 443, "/")

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": APP_NAME,
            "script": "git.py",
            "version": APP_VERSION,
        },
        "project_id": project,
        "checklist": {
            "id": CHECKLIST_ID,
            "name": "Git repository / metadata exposure",
            "phase": "04 Web Server Configuration",
            "focus": (
                "Controlled assessment of accidentally exposed Git "
                "repository metadata through HTTP/HTTPS."
            ),
            "status": "completed",
        },
        "target": {
            "application": target,
            "hostname": target,
            "url": target_url,
            "environment": "Production",
            "assessment_type": "Grey Box",
            "scope_id": scope_id,
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": ports,
        },
        "methodology": {
            "description": (
                "Controlled GET/HEAD assessment of a bounded set of Git "
                "metadata paths. Recon directory.yaml is authoritative for "
                "discovered /.git-style candidates; no generic endpoint "
                "fuzzing is performed."
            ),
            "methods": list(METHODS),
            "redirect_following": False,
            "mutation": False,
            "request_body": False,
            "repository_clone": False,
            "recursive_git_object_download": False,
            "discovery_bruteforce": False,
            "classification": (
                "HTTP behavior plus conservative Git metadata indicators; "
                "HTTP status alone is not treated as Git exposure."
            ),
            "automatic_finding": False,
        },
        "baseline": {
            "scope_source": "01-preparation/scope/scope.yaml",
            "recon_source": (
                "02-reconnaissance/directory/directory.yaml"
            ),
            "version_source": (
                "04-web-server-configuration/version/version.yaml"
            ),
            "error_source": (
                "04-web-server-configuration/errors/errors.yaml"
            ),
            "candidate_policy": (
                "Bounded Git metadata paths plus discovered /.git-style "
                "paths from Recon."
            ),
        },
        "toolchain": {
            "python": True,
            "requests": True,
            "pyyaml": True,
            "optional_tools": [],
        },
        "probe": {
            "methods": list(METHODS),
            "authorized_ports": ports,
            "timeout_seconds": DEFAULT_TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "body_sample_chars": BODY_SAMPLE_CHARS,
            "redirects": False,
            "streaming": True,
            "mutation": False,
            "repository_clone": False,
        },
        "source_status": {
            "scope": "completed",
            "directory": "completed",
            "version": "completed" if version_data else "unknown",
            "errors": "completed" if error_data else "unknown",
        },
        "results": {
            "recon_path_count": recon_count,
            "candidate_count": len(candidates),
            "probe_count": len(probes),
            "summary": summary,
        },
        "summary": summary,
        "cve_correlation": cve,
        "assessment": {
            "result": classification,
            "finding": False,
            "requires_review": requires_review,
            "classification": classification,
            "note": (
                "Git metadata indicators are review evidence; no automatic "
                "vulnerability finding is created."
            ),
        },
        "evidence": {
            "raw_probe_file": (
                "04-web-server-configuration/git/evidence/"
                "git-probes.json"
            ),
            "raw_body_retained": True,
            "report_redaction": (
                "separate report-generation layer"
            ),
            "supporting_artifacts": {
                "version": bool(version_data),
                "version_source": (
                    "04-web-server-configuration/version/version.yaml"
                    if version_data
                    else None
                ),
                "errors": bool(error_data),
                "errors_source": (
                    "04-web-server-configuration/errors/errors.yaml"
                    if error_data
                    else None
                ),
            },
        },
        "errors": [
            probe.get("error")
            for probe in probes
            if probe.get("error")
        ],
        "notes": [
            "Git exposure is not automatically mapped to a CVE.",
            (
                "4-001 version evidence is supporting traceability only; "
                "version match is not a vulnerability finding."
            ),
            "Repository cloning and recursive object retrieval are disabled.",
        ],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
        "candidates": candidates,
        "probes": probes,
    }


def print_version() -> None:
    print(f"git.py v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("Methods:")
    for method in METHODS:
        print(f"  - {method}")
    print("Endpoint source: Recon directory.yaml + bounded Git candidates")
    print("Supporting evidence: 4-010 errors.yaml")
    print("CVE source: 4-001 version.yaml")
    print("Redirect following: disabled")
    print("Mutation payload: none")
    print("Discovery/brute force: disabled")
    print("Repository clone: disabled")
    print("Automatic finding: disabled")
    print("Raw evidence: retained")
    print("Report redaction: separate report-generation layer")


def command_init(root: Path) -> int:
    scope_path = locate_scope(root)
    scope = load_yaml(scope_path)

    project = discover_project_name(scope, root)
    target, ports, scope_id = select_domain_target(scope)

    recon_paths = load_recon_paths(root)
    candidates = derive_git_candidates(recon_paths)

    output = (
        root
        / "04-web-server-configuration"
        / "git"
        / "git.yaml"
    )

    target_url = make_url("https", target, 443, "/")

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": APP_NAME,
            "script": "git.py",
            "version": APP_VERSION,
        },
        "project_id": project,
        "checklist": {
            "id": CHECKLIST_ID,
            "name": "Git repository / metadata exposure",
            "phase": "04 Web Server Configuration",
            "focus": (
                "Controlled assessment of accidentally exposed Git "
                "repository metadata through HTTP/HTTPS."
            ),
            "status": "initialized",
        },
        "target": {
            "application": target,
            "hostname": target,
            "url": target_url,
            "environment": "Production",
            "assessment_type": "Grey Box",
            "scope_id": scope_id,
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": ports,
        },
        "methodology": {
            "description": (
                "Controlled GET/HEAD assessment of bounded Git metadata "
                "paths. Recon is used only for discovered /.git-style paths."
            ),
            "methods": list(METHODS),
            "redirect_following": False,
            "mutation": False,
            "request_body": False,
            "repository_clone": False,
            "recursive_git_object_download": False,
            "discovery_bruteforce": False,
            "automatic_finding": False,
        },
        "baseline": {
            "scope_source": "01-preparation/scope/scope.yaml",
            "recon_source": (
                "02-reconnaissance/directory/directory.yaml"
            ),
            "version_source": (
                "04-web-server-configuration/version/version.yaml"
            ),
            "error_source": (
                "04-web-server-configuration/errors/errors.yaml"
            ),
        },
        "toolchain": {
            "python": True,
            "requests": True,
            "pyyaml": True,
            "optional_tools": [],
        },
        "probe": {
            "methods": list(METHODS),
            "authorized_ports": ports,
            "timeout_seconds": DEFAULT_TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "body_sample_chars": BODY_SAMPLE_CHARS,
            "redirects": False,
            "mutation": False,
            "repository_clone": False,
        },
        "source_status": {
            "scope": "completed",
            "directory": "completed",
            "version": "unknown",
            "errors": "unknown",
        },
        "results": {
            "recon_path_count": len(recon_paths),
            "candidate_count": len(candidates),
            "probe_count": 0,
            "summary": build_summary([]),
        },
        "summary": build_summary([]),
        "cve_correlation": {
            "source": (
                "04-web-server-configuration/version/version.yaml"
            ),
            "source_checklist": None,
            "source_target": None,
            "source_disclosed_versions": None,
            "candidate_count": 0,
            "candidates": [],
            "assessment_note": (
                "Tidak ada CVE yang dikaitkan otomatis dengan Git exposure. "
                "CVE/version evidence dari 4-001 hanya digunakan sebagai "
                "supporting traceability; version match bukan vulnerability."
            ),
        },
        "assessment": {
            "result": "initialized",
            "finding": False,
            "requires_review": False,
            "classification": "initialized",
            "note": (
                "Git metadata indicators are review evidence; no automatic "
                "vulnerability finding is created."
            ),
        },
        "evidence": {
            "raw_probe_file": (
                "04-web-server-configuration/git/evidence/"
                "git-probes.json"
            ),
            "raw_body_retained": True,
            "report_redaction": "separate report-generation layer",
        },
        "errors": [],
        "notes": [
            "Repository cloning and recursive object retrieval are disabled.",
            "Automatic vulnerability finding is disabled.",
        ],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
        "candidates": candidates,
        "probes": [],
    }

    dump_yaml(output, artifact)

    print("[PASS] Git Exposure berhasil diinisialisasi.")
    print(f"PROJECT         : {project}")
    print(f"TARGET          : {target}")
    print(f"PORTS           : {', '.join(map(str, ports))}")
    print(f"METHODS         : {', '.join(METHODS)}")
    print(f"RECON PATHS     : {len(recon_paths)}")
    print(f"CANDIDATES      : {len(candidates)}")
    print(
        "SOURCE          : "
        "02-reconnaissance/directory/directory.yaml"
    )
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
    candidates = derive_git_candidates(recon_paths)

    if max_candidates is not None:
        if max_candidates < 1:
            raise ValueError("--max-candidates harus >= 1")
        candidates = candidates[:max_candidates]

    version_data = load_version_artifact(root)
    error_data = load_error_artifact(root)

    output = (
        root
        / "04-web-server-configuration"
        / "git"
        / "git.yaml"
    )

    evidence_output = (
        root
        / "04-web-server-configuration"
        / "git"
        / "evidence"
        / "git-probes.json"
    )

    session = requests.Session()
    probes: List[Dict[str, Any]] = []

    for scheme, port in target_pairs(target, ports):
        for path in candidates:
            for method in METHODS:
                url = make_url(
                    scheme,
                    target,
                    port,
                    path,
                )

                result = request_once(
                    session,
                    method,
                    url,
                    timeout,
                )

                probes.append(
                    build_probe_record(
                        result,
                        project=project,
                        scope_id=scope_id,
                        target=target,
                        scheme=scheme,
                        port=port,
                        path=path,
                        method=method,
                    )
                )

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

    artifact["checklist"]["status"] = "completed"
    artifact["updated_at"] = utc_now()

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project,
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
        },
        "target": {
            "hostname": target,
            "scope_id": scope_id,
            "authorized_ports": ports,
        },
        "tool": {
            "name": APP_NAME,
            "script": "git.py",
            "version": APP_VERSION,
        },
        "generated_at": utc_now(),
        "raw_evidence_policy": {
            "body_retained": True,
            "report_redaction": "separate report-generation layer",
            "repository_clone": False,
        },
        "probes": probes,
    }

    dump_json(evidence_output, evidence)
    dump_yaml(output, artifact)

    summary = artifact["summary"]

    print("[PASS] Git Exposure berhasil dianalisis.")
    print(f"PROJECT         : {project}")
    print(f"TARGET          : {target}")
    print(f"CANDIDATES      : {len(candidates)}")
    print(f"METHODS         : {len(METHODS)}")
    print(f"PROBES          : {len(probes)}")
    print(
        "GIT EXPOSED     : "
        f"{summary['git_metadata_exposed']}"
    )
    print(
        "GIT CONFIG      : "
        f"{summary['git_config_exposed']}"
    )
    print(
        "GIT HEAD        : "
        f"{summary['git_head_exposed']}"
    )
    print(
        "GIT CANDIDATE   : "
        f"{summary['git_metadata_candidate']}"
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
    print(
        "CVE CANDIDATES  : "
        f"{artifact['cve_correlation']['candidate_count']}"
    )
    print(
        "REQUIRES REVIEW : "
        f"{artifact['assessment']['requires_review']}"
    )
    print(f"STATUS          : {artifact['assessment']['classification']}")
    print(f"FILE            : {output}")
    print(f"EVIDENCE        : {evidence_output}")

    return 0


def load_existing_artifact(root: Path) -> Dict[str, Any]:
    path = (
        root
        / "04-web-server-configuration"
        / "git"
        / "git.yaml"
    )
    return load_yaml(path)


def command_list(root: Path) -> int:
    artifact = load_existing_artifact(root)

    probes = artifact.get("probes", [])
    if not isinstance(probes, list):
        probes = []

    interesting_classifications = {
        "git-metadata-exposed",
        "git-config-exposed",
        "git-head-exposed",
        "git-metadata-candidate",
        "probe-error",
    }

    interesting = [
        probe
        for probe in probes
        if probe.get("classification") in interesting_classifications
    ]

    if not interesting:
        print("[INFO] Tidak ada Git exposure observation yang perlu ditampilkan.")
        return 0

    print(
        f"[INFO] {len(interesting)} observation(s) "
        "Git exposure/candidate:"
    )

    for probe in interesting:
        print(
            f"- {str(probe.get('scheme', '')).upper()} "
            f"{probe.get('port')} "
            f"{probe.get('method')} "
            f"{probe.get('path')} "
            f"-> {probe.get('status_code')} "
            f"[{probe.get('classification')}]"
        )

        indicators = probe.get("git_indicators") or {}
        names = indicators.get("indicator_names") or []

        if names:
            print(f"  indicators: {', '.join(names)}")

    return 0


def command_verify(root: Path) -> int:
    artifact = load_existing_artifact(root)
    errors: List[str] = []

    if artifact.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai.")

    project_id = artifact.get("project_id")
    if not project_id:
        errors.append("project_id wajib tersedia.")

    checklist = artifact.get("checklist", {})
    if not isinstance(checklist, dict):
        checklist = {}
        errors.append("checklist harus berupa object.")

    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist.id tidak sesuai.")

    if checklist.get("phase") != "04 Web Server Configuration":
        errors.append("checklist.phase tidak sesuai.")

    if checklist.get("status") not in {"initialized", "completed"}:
        errors.append("checklist.status tidak valid.")

    target = artifact.get("target", {})
    if not isinstance(target, dict):
        target = {}
        errors.append("target harus berupa object.")

    target_hostname = target.get("hostname")
    ports = target.get("authorized_ports") or []

    if not target_hostname:
        errors.append("target.hostname wajib tersedia.")

    if not isinstance(ports, list):
        errors.append("target.authorized_ports harus berupa list.")
        ports = []

    methodology = artifact.get("methodology", {})
    if not isinstance(methodology, dict):
        methodology = {}
        errors.append("methodology harus berupa object.")

    if methodology.get("repository_clone") is not False:
        errors.append("methodology.repository_clone harus false.")

    if methodology.get("redirect_following") is not False:
        errors.append("methodology.redirect_following harus false.")

    if methodology.get("mutation") is not False:
        errors.append("methodology.mutation harus false.")

    if methodology.get("automatic_finding") is not False:
        errors.append("methodology.automatic_finding harus false.")

    probe_config = artifact.get("probe", {})
    if not isinstance(probe_config, dict):
        probe_config = {}
        errors.append("probe harus berupa object.")

    if probe_config.get("methods") != list(METHODS):
        errors.append("probe.methods tidak sesuai.")

    if probe_config.get("redirects") is not False:
        errors.append("probe.redirects harus false.")

    probes = artifact.get("probes")
    if not isinstance(probes, list):
        errors.append("probes harus berupa list.")
        probes = []

    results = artifact.get("results", {})
    if not isinstance(results, dict):
        results = {}
        errors.append("results harus berupa object.")

    candidates = int(results.get("candidate_count", 0) or 0)
    expected_pairs = 0
    try:
        expected_pairs = len(
            target_pairs(
                str(target_hostname or ""),
                [int(port) for port in ports],
            )
        )
    except (TypeError, ValueError):
        errors.append("target.authorized_ports tidak valid.")

    expected_probes = (
        candidates
        * len(METHODS)
        * expected_pairs
    )

    if len(probes) != expected_probes:
        errors.append(
            f"Jumlah probes {len(probes)} != expected "
            f"{expected_probes}."
        )

    allowed_classifications = {
        "git-metadata-exposed",
        "git-config-exposed",
        "git-head-exposed",
        "git-metadata-candidate",
        "access-controlled",
        "redirected",
        "not-found",
        "application-response",
        "server-error",
        "probe-error",
    }

    for index, probe in enumerate(probes):
        method = probe.get("method")
        classification = probe.get("classification")
        path = canonical_path(str(probe.get("path") or ""))

        if method not in METHODS:
            errors.append(f"Probe #{index}: method tidak valid.")

        if classification not in allowed_classifications:
            errors.append(
                f"Probe #{index}: classification tidak valid."
            )

        if probe.get("redirect_followed") is not False:
            errors.append(
                f"Probe #{index}: redirect_followed harus false."
            )

        if probe.get("request_body") is not None:
            errors.append(
                f"Probe #{index}: request_body harus None."
            )

        if probe.get("mutation") is not False:
            errors.append(
                f"Probe #{index}: mutation harus false."
            )

        if not is_git_path(path):
            errors.append(
                f"Probe #{index}: path bukan Git candidate."
            )

        if (
            classification in {
                "git-metadata-exposed",
                "git-config-exposed",
                "git-head-exposed",
                "git-metadata-candidate",
            }
            and method != "GET"
        ):
            errors.append(
                f"Probe #{index}: Git exposure classification "
                "harus berasal dari GET."
            )

        if classification == "git-config-exposed":
            if not path.lower().endswith("/config"):
                errors.append(
                    f"Probe #{index}: git-config-exposed harus "
                    "berasal dari /.git/config."
                )

        if classification == "git-head-exposed":
            if not path.lower().endswith("/head"):
                errors.append(
                    f"Probe #{index}: git-head-exposed harus "
                    "berasal dari /.git/HEAD."
                )

        if classification in {
            "git-metadata-exposed",
            "git-config-exposed",
            "git-head-exposed",
        }:
            indicators = probe.get("git_indicators") or {}
            if not indicators.get("strong_git_indicator"):
                errors.append(
                    f"Probe #{index}: positive Git classification "
                    "tanpa strong_git_indicator."
                )

    summary = artifact.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
        errors.append("summary harus berupa object.")

    summary_keys = {
        "git_metadata_exposed",
        "git_config_exposed",
        "git_head_exposed",
        "git_metadata_candidate",
        "access_controlled",
        "redirected",
        "not_found",
        "application_response",
        "server_errors",
        "probe_errors",
    }

    for key in summary_keys:
        try:
            int(summary.get(key, 0))
        except (TypeError, ValueError):
            errors.append(f"summary.{key} tidak valid.")

    calculated_summary = build_summary(probes)
    for key in summary_keys:
        if int(summary.get(key, 0)) != calculated_summary[key]:
            errors.append(
                f"summary.{key} tidak konsisten dengan probes."
            )

    assessment = artifact.get("assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}
        errors.append("assessment harus berupa object.")

    if assessment.get("finding") is not False:
        errors.append(
            "assessment.finding harus false; automatic finding disabled."
        )

    positive_count = (
        int(summary.get("git_metadata_exposed", 0))
        + int(summary.get("git_config_exposed", 0))
        + int(summary.get("git_head_exposed", 0))
        + int(summary.get("git_metadata_candidate", 0))
    )

    expected_review = (
        positive_count > 0
        or int(summary.get("probe_errors", 0)) > 0
    )

    if assessment.get("requires_review") != expected_review:
        errors.append(
            "assessment.requires_review tidak konsisten dengan summary."
        )

    expected_classification = (
        "probe-error-review"
        if int(summary.get("probe_errors", 0)) > 0
        else (
            "git-exposure-review"
            if positive_count > 0
            else "no-git-exposure-observed"
        )
    )

    if assessment.get("classification") != expected_classification:
        errors.append(
            "assessment.classification tidak konsisten dengan summary."
        )

    cve = artifact.get("cve_correlation", {})
    if not isinstance(cve, dict):
        cve = {}
        errors.append("cve_correlation harus berupa object.")

    cve_candidates = cve.get("candidates", [])
    if not isinstance(cve_candidates, list):
        errors.append("cve_correlation.candidates harus berupa list.")
        cve_candidates = []

    if cve.get("candidate_count") != len(cve_candidates):
        errors.append(
            "cve_correlation.candidate_count tidak konsisten "
            "dengan candidates."
        )

    if cve.get("candidate_count") != 0:
        errors.append(
            "4-007 tidak boleh membuat CVE candidate otomatis."
        )

    if artifact.get("project_id") != project_id:
        errors.append("project_id tidak konsisten.")

    if errors:
        print("[FAIL] Git Exposure gagal validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] Git Exposure memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(
        f"[PASS] Version   : {artifact.get('tool', {}).get('version', APP_VERSION)}"
    )
    print(f"[PASS] Status    : {checklist.get('status')}")
    print(f"[PASS] Target    : {target_hostname}")
    print(f"[PASS] Candidates: {candidates}")
    print(f"[PASS] Methods   : {len(METHODS)}")
    print(f"[PASS] Probes    : {len(probes)}")
    print(
        f"[PASS] Git       : "
        f"{summary.get('git_metadata_exposed', 0)}"
    )
    print(
        f"[PASS] Config    : "
        f"{summary.get('git_config_exposed', 0)}"
    )
    print(
        f"[PASS] HEAD      : "
        f"{summary.get('git_head_exposed', 0)}"
    )
    print(
        f"[PASS] Candidate : "
        f"{summary.get('git_metadata_candidate', 0)}"
    )
    print(
        f"[PASS] CVE       : "
        f"{cve.get('candidate_count', 0)} candidate(s)"
    )
    print(
        f"[PASS] Review    : "
        f"{1 if assessment.get('requires_review') else 0}"
    )
    print(
        "[PASS] CVE Triage: Git exposure is not automatically mapped "
        "to a CVE; version evidence remains supporting evidence."
    )
    print(
        "[PASS] Assessment: Git metadata indicators are review evidence; "
        "no automatic vulnerability finding."
    )

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "4-007 Git Exposure - controlled Git metadata exposure "
            "assessment."
        )
    )

    parser.add_argument(
        "command",
        choices=(
            "version",
            "init",
            "analyze",
            "list",
            "verify",
        ),
        help="Command yang dijalankan.",
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help=(
            "Project root. Jika tidak diberikan, project aktif "
            "akan dideteksi otomatis."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=(
            f"HTTP timeout dalam detik. Default: {DEFAULT_TIMEOUT}"
        ),
    )

    parser.add_argument(
        "--max-candidates",
        type=int,
        default=None,
        help=(
            "Batasi jumlah kandidat untuk controlled test. "
            "Tidak diperlukan pada pengujian normal."
        ),
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.timeout < 1:
        parser.error("--timeout harus >= 1")

    root = (
        args.root.resolve()
        if args.root
        else find_project_root()
    )

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
