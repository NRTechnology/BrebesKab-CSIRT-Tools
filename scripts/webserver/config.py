#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - webserver/config.py

Checklist: 4-005 Web server configuration exposure

Boundary
--------
- Controlled HTTP GET only.
- No authentication guessing, brute force, exploitation, or destructive action.
- Raw evidence is retained; report generation is responsible for redaction.
- CVE correlation is review/triage evidence only and never creates an automatic
  vulnerability finding.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import typer
import yaml

APP_NAME = "BrebesKab-CSIRT-Tools config.py"
APP_VERSION = "1.0.4"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "4-005"
CHECKLIST_NAME = "Web server configuration exposure"
PHASE_NAME = "04 Web Server Configuration"

DEFAULT_TIMEOUT = 15
MAX_BODY_BYTES = 65536
REQUEST_USER_AGENT = f"BrebesKab-CSIRT-Tools/{APP_VERSION} Web-Server-Config"

app = typer.Typer(add_completion=False, no_args_is_help=True)

# Conservative public configuration / server-information paths.
PROBE_PATHS = [
    "/.htaccess",
    "/.user.ini",
    "/php.ini",
    "/httpd.conf",
    "/apache.conf",
    "/apache2.conf",
    "/web.config",
    "/config.php",
    "/config.php.bak",
    "/config.php.old",
    "/config.php.save",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/server-status",
    "/server-info",
]

# CVE descriptions/configuration metadata inherited from 4-001 are filtered
# here so config.py records only configuration-relevant candidates.
CVE_KEYWORDS = (
    "configuration",
    "config",
    ".htaccess",
    "allowoverride",
    "mod_userdir",
    "mod_cgid",
    "mod_rewrite",
    "virtualdocumentroot",
    "limitrequestfieldsize",
    "server side includes",
    "ssi",
)

SECRET_PATTERNS = (
    re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]"),
    re.compile(r"(?i)\b(api[_-]?key|secret|token)\s*[:=]"),
    re.compile(r"(?i)\b(db[_-]?(user|pass|password|host|name))\s*[:=]"),
)

CONFIG_CONTENT_MARKERS = (
    "require_once",
    "require ",
    "define(",
    "database",
    "db_host",
    "db_user",
    "db_password",
    "password",
    "secret",
    "api_key",
    "documentroot",
    "allowoverride",
    "rewriteengine",
    "php_value",
    "php_admin_value",
    "<configuration",
    "[database]",
)

# Indicators of externally exposed application/framework error information.
# These are deliberately conservative: a generic 404 page is not classified as
# an error-information disclosure unless one or more strong indicators are
# present in the response body.
ERROR_INFO_PATTERNS = (
    ("framework_exception", re.compile(
        r"(?i)(?:exception|error)\s*(?:class|type)?\s*[:=]?\s*"
        r"(?:CodeIgniter|Laravel|Symfony|CakePHP|Yii|Slim)"
    )),
    ("codeigniter_exception", re.compile(
        r"(?i)\b(?:CodeIgniter\\)?(?:\w+Exception|PageNotFoundException)\b"
    )),
    ("stack_trace", re.compile(
        r"(?i)\b(?:stack trace|stacktrace|traceback|exception trace)\b"
    )),
    ("filesystem_path", re.compile(
        r"(?i)(?:/home/[^\s<>]+|/var/www/[^\s<>]+|"
        r"/var/apps/[^\s<>]+|[A-Z]:\\[^\r\n<>]+)"
    )),
    ("source_file_disclosure", re.compile(
        r"(?i)\b(?:CodeIgniter|Laravel|Symfony|system|vendor)[^\r\n<>]*\.php\b"
    )),
    ("line_number_disclosure", re.compile(
        r'(?i)(?:"(?:line|line_number)"|\b(?:line|ln)\b)\s*[:#]?\s*\d{1,6}\b'
    )),
    ("trace_field", re.compile(
        r'(?i)"(?:trace|traceback|stack_trace)"\s*[:=]'
    )),
)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def discover_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def write_yaml(path: Path, data: dict[str, Any]) -> None:
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
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def discover_project_id(repo_root: Path) -> str:
    candidates = list(
        (repo_root / "projects").glob("*/02-reconnaissance/network/network.yaml")
    )
    if len(candidates) == 1:
        data = load_yaml(candidates[0])
        value = str(
            data.get("project_id")
            or data.get("network", {}).get("project_id")
            or ""
        ).strip()
        if value:
            return value

    active = list((repo_root / "projects").glob("*/active-project.yaml"))
    if len(active) == 1:
        data = load_yaml(active[0])
        value = str(data.get("project_id") or "").strip()
        if value:
            return value

    if candidates:
        return candidates[0].parents[2].name

    raise RuntimeError("Tidak dapat menemukan active project di projects/.")


def project_dir(repo_root: Path, project_id: str) -> Path:
    path = repo_root / "projects" / project_id
    if not path.is_dir():
        raise FileNotFoundError(f"Project path tidak ditemukan: {path}")
    return path


def artifact_root(repo_root: Path, project_id: str) -> Path:
    return project_dir(repo_root, project_id) / "04-web-server-configuration" / "config"


def artifact_file(repo_root: Path, project_id: str) -> Path:
    return artifact_root(repo_root, project_id) / "config.yaml"


def evidence_root(repo_root: Path, project_id: str) -> Path:
    return artifact_root(repo_root, project_id) / "evidence"


def source_paths(repo_root: Path, project_id: str) -> dict[str, Path]:
    root = project_dir(repo_root, project_id)
    return {
        "scope": root / "01-preparation" / "scope" / "scope.yaml",
        "version": root / "04-web-server-configuration" / "version" / "version.yaml",
        "directory": root / "02-reconnaissance" / "directory" / "directory.yaml",
    }


def load_context(repo_root: Path, project_id: str) -> dict[str, Any]:
    sources = source_paths(repo_root, project_id)
    scope = load_yaml(sources["scope"])

    scope_block = scope.get("scope", {})
    items = scope_block.get("in_scope", []) if isinstance(scope_block, dict) else []
    if not isinstance(items, list):
        items = []

    hostname = ""
    authorized_ports: list[int] = []
    scope_id = ""

    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "domain":
            continue
        hostname = str(item.get("value") or "").strip()
        scope_id = str(item.get("scope_id") or "").strip()
        raw_ports = item.get("ports", [])
        if isinstance(raw_ports, list):
            for port in raw_ports:
                try:
                    authorized_ports.append(int(port))
                except (TypeError, ValueError):
                    pass
        break

    if not hostname:
        raise ValueError("Domain target tidak ditemukan pada scope.")

    return {
        "hostname": hostname,
        "target_url": f"https://{hostname}/",
        "authorized_ports": sorted(set(authorized_ports)),
        "scope_id": scope_id,
        "sources": sources,
    }


def source_status(path: Path, block_name: str) -> str:
    """Read source status from canonical schema, with legacy fallback.

    Canonical Web Server checklist artifacts keep completion status under
    ``checklist.status``.  The legacy wrapper schema used a named block such
    as ``webserver_version.status``.  Prefer the canonical location so the
    reader follows the current 4-001 version.yaml without changing probe
    behavior.
    """
    try:
        data = load_yaml(path)
    except FileNotFoundError:
        return "not-available"

    checklist = data.get("checklist", {})
    if isinstance(checklist, dict):
        status = checklist.get("status")
        if status:
            return str(status)

    block = data.get(block_name, {})
    if isinstance(block, dict):
        return str(block.get("status") or "unknown")

    return "unknown"


def initial_artifact(context: dict[str, Any], project_id: str) -> dict[str, Any]:
    """Create the canonical 4-005 artifact skeleton.

    The probe methodology and candidate set remain unchanged. Only the
    artifact layout is normalized so summary.py can consume all Web Server
    checklist artifacts consistently.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "focus": "Public exposure of web-server configuration and detailed error information",
            "status": "initialized",
        },
        "target": {
            "application": "Bangsaku",
            "hostname": context["hostname"],
            "url": context["target_url"],
            "environment": "Production",
            "assessment_type": "Black Box",
            "scope_id": context["scope_id"],
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": context["authorized_ports"],
        },
        "methodology": {
            "method": "Controlled HTTP GET against configuration-sensitive paths",
            "candidate_sources": ["bounded"],
            "redirect_following": False,
            "mutation": False,
            "bruteforce": False,
            "exploitation": False,
            "authentication_guessing": False,
        },
        "baseline": {
            "version_4_001": "04-web-server-configuration/version/version.yaml",
            "recon_directory": "02-reconnaissance/directory/directory.yaml",
        },
        "toolchain": {
            "required": ["Python", "requests", "PyYAML"],
            "optional": [],
        },
        "probe": {
            "paths": PROBE_PATHS,
            "methods": ["GET"],
            "ports": context["authorized_ports"],
            "schemes": ["http", "https"],
            "allow_redirects": False,
            "timeout_seconds": DEFAULT_TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "request_count": 0,
        },
        "source_status": {},
        "results": [],
        "summary": {
            "probes": 0,
            "accessible": 0,
            "access_controlled": 0,
            "redirects": 0,
            "not_found": 0,
            "error_information_disclosures": 0,
            "not_confirmed": 0,
            "probe_errors": 0,
            "secret_pattern_observations": 0,
            "requires_review": 0,
        },
        "cve_correlation": {
            "source": "4-001 version/CPE evidence",
            "status": "not-run",
            "candidate_count": 0,
            "requires_validation": 0,
            "candidates": [],
        },
        "assessment": {
            "result": "not-analyzed",
            "classification": "not-analyzed",
            "requires_review": False,
            "finding": False,
            "note": (
                "Configuration-path accessibility and externally exposed detailed "
                "error information are observations requiring assessment. They do "
                "not by themselves prove a vulnerability or confirm exploitable "
                "debug configuration."
            ),
        },
        "evidence": {},
        "errors": [],
        "notes": [
            "Configuration exposure is evidence; it is not an automatic vulnerability finding.",
            "Detailed framework/error information in an HTTP response is classified as an observation requiring review; it is not by itself proof that debug mode is enabled.",
            "Raw evidence is retained; credential/secret redaction is performed during report generation.",
            "CVE correlation is triage evidence only and does not establish exploitability.",
        ],
        "generated_at": now_iso(),
        "updated_at": now_iso(),
    }


def extract_config_cves(version_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract configuration-relevant CVE candidates from 4-001.

    The canonical 4-001 artifact stores ``cve_correlation`` at the YAML root.
    Keep a legacy ``webserver_version`` fallback so older artifacts remain
    readable, without changing the existing CVE filtering logic below.
    """
    correlation = version_data.get("cve_correlation", {})

    if not isinstance(correlation, dict) or not correlation:
        ws = version_data.get("webserver_version", {})
        if isinstance(ws, dict):
            correlation = ws.get("cve_correlation", {})

    if not isinstance(correlation, dict):
        return []

    products = correlation.get("products", [])
    if not isinstance(products, list):
        return []

    selected: list[dict[str, Any]] = []
    seen: set[str] = set()

    for product in products:
        if not isinstance(product, dict):
            continue
        cves = product.get("cves", [])
        if not isinstance(cves, list):
            continue

        for cve in cves:
            if not isinstance(cve, dict):
                continue
            cve_id = str(cve.get("cve") or "").strip()
            if not cve_id or cve_id in seen:
                continue

            applicability = cve.get("applicability", {})
            classification = {}
            if isinstance(applicability, dict):
                classification = applicability.get("classification", {})
            blob = " ".join(
                [
                    cve_id,
                    str(cve.get("description") or ""),
                    json.dumps(applicability, ensure_ascii=False),
                    json.dumps(classification, ensure_ascii=False),
                ]
            ).lower()

            if not any(keyword in blob for keyword in CVE_KEYWORDS):
                continue

            seen.add(cve_id)
            selected.append(
                {
                    "cve": cve_id,
                    "product": product.get("product", ""),
                    "version": product.get("version", ""),
                    "severity": cve.get("cvss", {}).get("severity", "")
                    if isinstance(cve.get("cvss"), dict)
                    else "",
                    "cvss": cve.get("cvss", {}).get("score", "")
                    if isinstance(cve.get("cvss"), dict)
                    else "",
                    "description": cve.get("description", ""),
                    "classification": (
                        classification.get("primary", "")
                        if isinstance(classification, dict)
                        else ""
                    ),
                    "requires_validation": True,
                    "finding": False,
                    "nvd_url": cve.get("nvd_url", ""),
                    "correlation_basis": (
                        "configuration-relevant candidate from 4-001 "
                        "NVD CPE applicability correlation"
                    ),
                }
            )

    return selected


def detect_error_information(text: str) -> list[str]:
    """Return conservative indicators of detailed error/debug information."""
    indicators: list[str] = []
    for name, pattern in ERROR_INFO_PATTERNS:
        if pattern.search(text):
            indicators.append(name)
    return indicators


def probe(url: str) -> dict[str, Any]:
    started = now_iso()
    try:
        response = requests.get(
            url,
            headers={"User-Agent": REQUEST_USER_AGENT, "Accept": "*/*"},
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=False,
            verify=True,
            stream=True,
        )

        raw = b""
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            raw += chunk
            if len(raw) >= MAX_BODY_BYTES:
                raw = raw[:MAX_BODY_BYTES]
                break

        content_type = response.headers.get("Content-Type", "")
        text = raw.decode("utf-8", errors="replace")
        lowered = text.lower()

        secret_observed = any(
            pattern.search(text) is not None for pattern in SECRET_PATTERNS
        )
        marker_hits = [
            marker for marker in CONFIG_CONTENT_MARKERS if marker in lowered
        ]
        error_information_indicators = detect_error_information(text)

        status = response.status_code
        if error_information_indicators and status == 404:
            classification = "error-information-disclosure"
        elif status in (200, 206):
            classification = "accessible"
        elif status in (301, 302, 303, 307, 308):
            classification = "redirect"
        elif status in (401, 403):
            classification = "access-controlled"
        elif status == 404:
            classification = "not-found"
        else:
            classification = "not-confirmed"

        return {
            "url": url,
            "method": "GET",
            "started_at": started,
            "completed_at": now_iso(),
            "status_code": status,
            "final_url": response.url,
            "headers": dict(response.headers.items()),
            "content_type": content_type,
            "content_length": len(raw),
            "body_truncated": len(raw) >= MAX_BODY_BYTES,
            "body_sha256": sha256_bytes(raw),
            "body_preview": text[:4000],
            "config_marker_hits": marker_hits,
            "secret_pattern_observed": secret_observed,
            "error_information_indicators": error_information_indicators,
            "error_information_disclosure": bool(error_information_indicators),
            "classification": classification,
            "error": "",
        }
    except requests.RequestException as exc:
        return {
            "url": url,
            "method": "GET",
            "started_at": started,
            "completed_at": now_iso(),
            "status_code": None,
            "final_url": url,
            "headers": {},
            "content_type": "",
            "content_length": 0,
            "body_truncated": False,
            "body_sha256": "",
            "body_preview": "",
            "config_marker_hits": [],
            "secret_pattern_observed": False,
            "error_information_indicators": [],
            "error_information_disclosure": False,
            "classification": "probe-error",
            "error": str(exc),
        }


def compact_result(result: dict[str, Any], scheme: str, path: str) -> dict[str, Any]:
    return {
        "scheme": scheme,
        "path": path,
        "url": result["url"],
        "status_code": result["status_code"],
        "final_url": result["final_url"],
        "content_type": result["content_type"],
        "content_length": result["content_length"],
        "body_truncated": result["body_truncated"],
        "body_sha256": result["body_sha256"],
        "config_marker_hits": result["config_marker_hits"],
        "secret_pattern_observed": result["secret_pattern_observed"],
        "error_information_indicators": result["error_information_indicators"],
        "error_information_disclosure": result["error_information_disclosure"],
        "classification": result["classification"],
        "error": result["error"],
    }


@app.command("version")
def version_cmd() -> None:
    print(f"config.py v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("Mode: controlled HTTP GET only")
    print("Network probes: enabled by analyze")
    print("Artifact: canonical Web Server Configuration schema")
    print("CVE correlation: inherited configuration-relevant candidates from 4-001")
    print("Finding creation: disabled")
    print("Report redaction: separate report-generation layer")


@app.command("init")
def init_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    context = load_context(repo_root, project_id)
    path = artifact_file(repo_root, project_id)
    write_yaml(path, initial_artifact(context, project_id))

    print("[PASS] Web Server Configuration berhasil diinisialisasi.")
    print(f"PROJECT : {project_id}")
    print(f"TARGET  : {context['hostname']}")
    print(f"FILE    : {path}")


@app.command("analyze")
def analyze_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    context = load_context(repo_root, project_id)
    path = artifact_file(repo_root, project_id)

    if not path.is_file():
        raise typer.BadParameter(
            "Artifact belum diinisialisasi. Jalankan init terlebih dahulu."
        )

    artifact = load_yaml(path)
    sources = context["sources"]

    checklist = artifact["checklist"]
    target = artifact["target"]
    methodology = artifact["methodology"]
    probe_config = artifact["probe"]

    checklist["status"] = "completed"

    artifact["source_status"] = {
        "version": source_status(sources["version"], "webserver_version"),
        "directory": source_status(sources["directory"], "directory"),
    }

    full_evidence: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for scheme in ("http", "https"):
        base = f"{scheme}://{context['hostname']}"
        for path_item in PROBE_PATHS:
            result = probe(base + path_item)
            full_evidence.append(
                {
                    "scheme": scheme,
                    "path": path_item,
                    **result,
                }
            )
            results.append(compact_result(result, scheme, path_item))
            if result["error"]:
                errors.append(
                    {
                        "url": result["url"],
                        "error": result["error"],
                    }
                )

    evidence_dir = evidence_root(repo_root, project_id)
    evidence_file = evidence_dir / "config-probes.json"
    write_json(
        evidence_file,
        {
            "schema_version": "1.0",
            "generated_at": now_iso(),
            "target": context["target_url"],
            "request_policy": {
                "method": "GET",
                "allow_redirects": False,
                "max_body_bytes": MAX_BODY_BYTES,
            },
            "results": full_evidence,
        },
    )

    accessible = [
        item for item in results if item["classification"] == "accessible"
    ]
    controlled = [
        item for item in results if item["classification"] == "access-controlled"
    ]
    redirects = [
        item for item in results if item["classification"] == "redirect"
    ]
    not_found = [
        item for item in results if item["classification"] == "not-found"
    ]
    error_information_disclosures = [
        item
        for item in results
        if item["classification"] == "error-information-disclosure"
    ]
    not_confirmed = [
        item for item in results if item["classification"] == "not-confirmed"
    ]
    probe_errors = [
        item for item in results if item["classification"] == "probe-error"
    ]
    secret_observations = [
        item for item in results if item["secret_pattern_observed"]
    ]

    version_data = {}
    try:
        version_data = load_yaml(sources["version"])
    except FileNotFoundError:
        pass

    cve_candidates = extract_config_cves(version_data)
    requires_review = bool(
        accessible
        or controlled
        or redirects
        or secret_observations
        or error_information_disclosures
        or cve_candidates
    )

    if accessible:
        assessment_result = "configuration-exposure-observed"
    elif error_information_disclosures:
        assessment_result = "error-information-disclosure-observed"
    elif controlled:
        assessment_result = "configuration-paths-access-controlled"
    elif not_confirmed:
        assessment_result = "configuration-not-confirmed"
    else:
        assessment_result = "no-configuration-exposure-observed"

    checklist["status"] = "completed"

    probe_config.update(
        {
            "paths": PROBE_PATHS,
            "methods": ["GET"],
            "ports": context["authorized_ports"],
            "schemes": ["http", "https"],
            "allow_redirects": False,
            "timeout_seconds": DEFAULT_TIMEOUT,
            "max_body_bytes": MAX_BODY_BYTES,
            "request_count": len(results),
            "completed_at": now_iso(),
        }
    )

    artifact["results"] = results
    artifact["summary"] = {
        "probes": len(results),
        "accessible": len(accessible),
        "access_controlled": len(controlled),
        "redirects": len(redirects),
        "not_found": len(not_found),
        "error_information_disclosures": len(error_information_disclosures),
        "not_confirmed": len(not_confirmed),
        "probe_errors": len(probe_errors),
        "secret_pattern_observations": len(secret_observations),
        "requires_review": int(requires_review),
    }
    artifact["assessment"] = {
        "result": assessment_result,
        "classification": assessment_result,
        "requires_review": requires_review,
        "finding": False,
        "note": (
            "Configuration-path accessibility and externally exposed detailed "
            "error information are observations requiring assessment. They do "
            "not by themselves prove a vulnerability or confirm exploitable "
            "debug configuration."
        ),
    }
    artifact["cve_correlation"] = {
        "source": "4-001 version/CPE evidence",
        "status": "completed" if version_data else "not-available",
        "candidate_count": len(cve_candidates),
        "requires_validation": len(cve_candidates),
        "candidates": cve_candidates,
        "note": (
            "Only configuration-relevant candidates inherited from 4-001 "
            "are recorded. Version/CPE correlation does not prove exploitability "
            "or applicability of configuration prerequisites."
        ),
    }
    artifact["evidence"] = {
        "config_probes": str(
            evidence_file.relative_to(repo_root)
        ).replace("\\", "/"),
        "raw_evidence_retained": True,
        "report_redaction": "separate report-generation layer; raw evidence is not redacted",
    }
    artifact["errors"] = errors
    artifact["updated_at"] = now_iso()

    write_yaml(path, artifact)

    print("[PASS] Web Server Configuration berhasil dianalisis.")
    print(f"PROJECT         : {project_id}")
    print(f"TARGET          : {context['hostname']}")
    print(f"PROBES          : {len(results)}")
    print(f"ACCESSIBLE      : {len(accessible)}")
    print(f"ACCESS CONTROL  : {len(controlled)}")
    print(f"NOT FOUND       : {len(not_found)}")
    print(f"PROBE ERRORS    : {len(probe_errors)}")
    print(f"CVE CANDIDATES  : {len(cve_candidates)}")
    print(f"REQUIRES REVIEW : {int(requires_review)}")
    print("STATUS          : completed")
    print(f"FILE            : {path}")


@app.command("list")
def list_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    path = artifact_file(repo_root, project_id)
    data = load_yaml(path)

    print(f"PROJECT: {project_id}")
    print(f"STATUS : {data.get('checklist', {}).get('status', '')}")
    print(f"TARGET : {data.get('target', {}).get('hostname', '')}")
    print()
    print("SCHEME  PATH                       STATUS  CLASSIFICATION           REVIEW")
    print("-" * 78)

    for item in data.get("results", []):
        review = item.get("classification") in (
            "accessible",
            "access-controlled",
            "error-information-disclosure",
        )
        print(
            f"{str(item.get('scheme', '')).upper():6} "
            f"{str(item.get('path', ''))[:26]:26} "
            f"{str(item.get('status_code', '')):7} "
            f"{str(item.get('classification', ''))[:24]:24} "
            f"{str(review)}"
        )

    cve = data.get("cve_correlation", {})
    print()
    print(f"CVE CANDIDATES: {cve.get('candidate_count', 0)}")


@app.command("show")
def show_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    path = artifact_file(repo_root, project_id)
    data = load_yaml(path)

    print(f"PROJECT: {project_id}")
    print(f"FILE   : {path}")
    print()
    print(yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    ))


@app.command("verify")
def verify_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    path = artifact_file(repo_root, project_id)

    try:
        data = load_yaml(path)
    except Exception as exc:
        print(f"[FAIL] Artifact tidak dapat dibaca: {exc}")
        raise typer.Exit(code=1)

    errors: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai.")
    if data.get("project_id") != project_id:
        errors.append("project_id tidak sesuai.")

    checklist = data.get("checklist", {})
    target = data.get("target", {})
    methodology = data.get("methodology", {})
    baseline = data.get("baseline", {})
    toolchain = data.get("toolchain", {})
    probe = data.get("probe", {})
    source_status_data = data.get("source_status", {})
    results = data.get("results")
    summary = data.get("summary", {})
    cve = data.get("cve_correlation", {})
    assessment = data.get("assessment", {})
    evidence = data.get("evidence", {})

    if not isinstance(checklist, dict):
        errors.append("checklist tidak valid.")
        checklist = {}
    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist ID tidak sesuai.")
    if checklist.get("name") != CHECKLIST_NAME:
        errors.append("checklist name tidak sesuai.")
    if checklist.get("phase") != PHASE_NAME:
        errors.append("checklist phase tidak sesuai.")
    if checklist.get("status") != "completed":
        errors.append("checklist status bukan completed.")

    if not isinstance(target, dict):
        errors.append("target tidak valid.")
        target = {}
    if not target.get("hostname"):
        errors.append("target.hostname kosong.")
    if not target.get("url"):
        errors.append("target.url kosong.")
    if not isinstance(target.get("authorized_ports"), list):
        errors.append("target.authorized_ports tidak valid.")

    if not isinstance(methodology, dict):
        errors.append("methodology tidak valid.")
    else:
        if methodology.get("method") != (
            "Controlled HTTP GET against configuration-sensitive paths"
        ):
            errors.append("methodology.method tidak sesuai.")
        if methodology.get("redirect_following") is not False:
            errors.append("redirect_following harus false.")
        if methodology.get("mutation") is not False:
            errors.append("mutation harus false.")
        if methodology.get("bruteforce") is not False:
            errors.append("bruteforce harus false.")

    if not isinstance(baseline, dict):
        errors.append("baseline tidak valid.")
    else:
        if not baseline.get("version_4_001"):
            errors.append("baseline 4-001 tidak tercatat.")
        if not baseline.get("recon_directory"):
            errors.append("baseline recon directory tidak tercatat.")

    if not isinstance(toolchain, dict):
        errors.append("toolchain tidak valid.")

    if not isinstance(probe, dict):
        errors.append("probe tidak valid.")
        probe = {}

    if probe.get("methods") != ["GET"]:
        errors.append("probe.methods tidak sesuai.")
    if probe.get("schemes") != ["http", "https"]:
        errors.append("probe.schemes tidak sesuai.")
    if probe.get("allow_redirects") is not False:
        errors.append("probe.allow_redirects harus false.")
    if probe.get("paths") != PROBE_PATHS:
        errors.append("probe.paths tidak sesuai dengan bounded candidate set.")

    if not isinstance(source_status_data, dict):
        errors.append("source_status tidak valid.")

    if not isinstance(results, list) or not results:
        errors.append("results kosong.")
        results = []

    if not isinstance(summary, dict):
        errors.append("summary tidak valid.")
        summary = {}

    expected_summary = {
        "probes": len(results),
        "accessible": sum(
            1 for item in results if item.get("classification") == "accessible"
        ),
        "access_controlled": sum(
            1
            for item in results
            if item.get("classification") == "access-controlled"
        ),
        "redirects": sum(
            1 for item in results if item.get("classification") == "redirect"
        ),
        "not_found": sum(
            1 for item in results if item.get("classification") == "not-found"
        ),
        "error_information_disclosures": sum(
            1
            for item in results
            if item.get("classification") == "error-information-disclosure"
        ),
        "not_confirmed": sum(
            1
            for item in results
            if item.get("classification") == "not-confirmed"
        ),
        "probe_errors": sum(
            1 for item in results if item.get("classification") == "probe-error"
        ),
        "secret_pattern_observations": sum(
            1 for item in results if item.get("secret_pattern_observed")
        ),
    }

    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            errors.append(
                f"summary.{key} tidak konsisten: "
                f"expected={expected}, actual={summary.get(key)}"
            )

    expected_requires_review = bool(
        expected_summary["accessible"]
        or expected_summary["access_controlled"]
        or expected_summary["redirects"]
        or expected_summary["secret_pattern_observations"]
        or expected_summary["error_information_disclosures"]
        or cve.get("candidate_count", 0)
    )
    if summary.get("requires_review") != int(expected_requires_review):
        errors.append("summary.requires_review tidak konsisten.")

    if not isinstance(cve, dict):
        errors.append("cve_correlation tidak valid.")
        cve = {}
    else:
        candidates = cve.get("candidates", [])
        if not isinstance(candidates, list):
            errors.append("cve_correlation.candidates tidak valid.")
            candidates = []
        if cve.get("candidate_count") != len(candidates):
            errors.append(
                "candidate_count tidak sama dengan jumlah CVE candidates."
            )
        if any(
            isinstance(item, dict) and item.get("finding") is True
            for item in candidates
        ):
            errors.append("CVE candidate tidak boleh menjadi automatic finding.")

    if not isinstance(assessment, dict):
        errors.append("assessment tidak valid.")
        assessment = {}
    else:
        if assessment.get("finding") is True:
            errors.append("config.py tidak boleh membuat automatic finding.")
        if assessment.get("requires_review") != expected_requires_review:
            errors.append("assessment.requires_review tidak konsisten.")
        if assessment.get("result") != assessment.get("classification"):
            errors.append("assessment.result/classification tidak konsisten.")

    evidence_rel = evidence.get("config_probes", "") if isinstance(evidence, dict) else ""
    if not evidence_rel:
        errors.append("Evidence config probes belum tercatat.")
    elif not (repo_root / evidence_rel).is_file():
        errors.append("File evidence config probes tidak ditemukan.")

    if errors:
        print("[FAIL] Web Server Configuration gagal validasi.")
        for error in errors:
            print(f"- {error}")
        raise typer.Exit(code=1)

    print("[PASS] Web Server Configuration memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Version   : {APP_VERSION}")
    print(f"[PASS] Status    : {checklist.get('status')}")
    print(f"[PASS] Target    : {target.get('hostname')}")
    print(f"[PASS] Probes    : {summary.get('probes')}")
    print(f"[PASS] Accessible: {summary.get('accessible')}")
    print(
        "[PASS] Error Info: "
        f"{summary.get('error_information_disclosures', 0)} observation(s)"
    )
    print(f"[PASS] CVE       : {cve.get('candidate_count')} candidate(s)")
    print(f"[PASS] Review    : {summary.get('requires_review')}")
    print("[PASS] CVE Triage: configuration candidates are evidence; no automatic finding.")
    print("[PASS] Assessment: configuration exposure/CVE correlation dicatat sebagai evidence.")


if __name__ == "__main__":
    app()
