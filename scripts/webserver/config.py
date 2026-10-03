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
APP_VERSION = "1.0.1"
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
    try:
        data = load_yaml(path)
    except FileNotFoundError:
        return "not-available"
    block = data.get(block_name, {})
    if isinstance(block, dict):
        return str(block.get("status") or "unknown")
    return "unknown"


def initial_artifact(context: dict[str, Any], project_id: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "updated_at": now_iso(),
        "webserver_config": {
            "status": "not-started",
            "checklist": {
                "id": CHECKLIST_ID,
                "name": CHECKLIST_NAME,
                "phase": PHASE_NAME,
            },
            "application": "Bangsaku",
            "hostname": context["hostname"],
            "target_url": context["target_url"],
            "environment": "Production",
            "assessment_type": "Black Box",
            "scope_reference": "01-preparation/scope/scope.yaml",
            "scope_id": context["scope_id"],
            "authorized_ports": context["authorized_ports"],
            "method": "controlled HTTP GET against configuration-sensitive paths",
            "source_status": {},
            "probe": {
                "paths": PROBE_PATHS,
                "request_count": 0,
            },
            "results": [],
            "assessment": {
                "result": "not-analyzed",
                "requires_review": False,
                "finding": False,
            },
            "cve_correlation": {
                "source": "4-001 version/CPE evidence",
                "status": "not-run",
                "candidate_count": 0,
                "requires_validation": 0,
                "candidates": [],
            },
            "evidence": {},
            "errors": [],
            "notes": [
                "Configuration exposure is evidence; it is not an automatic vulnerability finding.",
                "Raw evidence is retained; credential/secret redaction is performed during report generation.",
                "CVE correlation is triage evidence only and does not establish exploitability.",
            ],
        },
    }


def extract_config_cves(version_data: dict[str, Any]) -> list[dict[str, Any]]:
    ws = version_data.get("webserver_version", {})
    correlation = ws.get("cve_correlation", {})
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

        status = response.status_code
        if status in (200, 206):
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
        "classification": result["classification"],
        "error": result["error"],
    }


@app.command("version")
def version_cmd() -> None:
    print(f"config.py v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")


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
        raise typer.BadParameter("Artifact belum diinisialisasi. Jalankan init terlebih dahulu.")

    artifact = load_yaml(path)
    block = artifact["webserver_config"]
    sources = context["sources"]

    block["source_status"] = {
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
        or cve_candidates
    )

    if accessible:
        assessment_result = "configuration-exposure-observed"
    elif controlled:
        assessment_result = "configuration-paths-access-controlled"
    elif not_confirmed:
        assessment_result = "configuration-not-confirmed"
    else:
        assessment_result = "no-configuration-exposure-observed"

    block["status"] = "completed"
    block["probe"] = {
        "paths": PROBE_PATHS,
        "request_count": len(results),
        "schemes": ["http", "https"],
        "allow_redirects": False,
        "max_body_bytes": MAX_BODY_BYTES,
        "completed_at": now_iso(),
    }
    block["results"] = results
    block["summary"] = {
        "probes": len(results),
        "accessible": len(accessible),
        "access_controlled": len(controlled),
        "redirects": len(redirects),
        "not_found": len(not_found),
        "not_confirmed": len(not_confirmed),
        "probe_errors": len(probe_errors),
        "secret_pattern_observations": len(secret_observations),
        "requires_review": int(requires_review),
    }
    block["assessment"] = {
        "result": assessment_result,
        "requires_review": requires_review,
        "finding": False,
        "note": (
            "HTTP accessibility of a configuration-sensitive path is an "
            "observation. It does not by itself prove a vulnerability."
        ),
    }
    block["cve_correlation"] = {
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
    block["evidence"] = {
        "config_probes": str(
            evidence_file.relative_to(repo_root)
        ).replace("\\", "/"),
    }
    block["errors"] = errors
    block["updated_at"] = now_iso()
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
    block = data["webserver_config"]

    print(f"PROJECT: {project_id}")
    print(f"STATUS : {block.get('status', '')}")
    print(f"TARGET : {block.get('hostname', '')}")
    print()
    print("SCHEME  PATH                       STATUS  CLASSIFICATION           REVIEW")
    print("-" * 78)

    for item in block.get("results", []):
        review = item.get("classification") in (
            "accessible",
            "access-controlled",
        )
        print(
            f"{str(item.get('scheme', '')).upper():6} "
            f"{str(item.get('path', ''))[:26]:26} "
            f"{str(item.get('status_code', '')):7} "
            f"{str(item.get('classification', ''))[:24]:24} "
            f"{str(review)}"
        )

    cve = block.get("cve_correlation", {})
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

    block = data.get("webserver_config", {})
    errors: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai.")
    if data.get("project_id") != project_id:
        errors.append("project_id tidak sesuai.")
    if block.get("status") != "completed":
        errors.append("status bukan completed.")
    checklist = block.get("checklist", {})
    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist ID tidak sesuai.")
    if not block.get("hostname"):
        errors.append("hostname kosong.")

    results = block.get("results")
    summary = block.get("summary", {})
    cve = block.get("cve_correlation", {})
    assessment = block.get("assessment", {})
    evidence = block.get("evidence", {})

    if not isinstance(results, list) or not results:
        errors.append("results kosong.")
    if not isinstance(summary, dict):
        errors.append("summary tidak valid.")
    elif summary.get("probes") != len(results or []):
        errors.append("summary.probes tidak sama dengan jumlah results.")

    if not isinstance(cve, dict):
        errors.append("cve_correlation tidak valid.")
    else:
        candidates = cve.get("candidates", [])
        if cve.get("candidate_count") != len(candidates):
            errors.append("candidate_count tidak sama dengan jumlah CVE candidates.")
        if any(item.get("finding") is True for item in candidates):
            errors.append("CVE candidate tidak boleh menjadi automatic finding.")

    if not isinstance(assessment, dict):
        errors.append("assessment tidak valid.")
    elif assessment.get("finding") is True:
        errors.append("config.py tidak boleh membuat automatic finding.")

    evidence_rel = evidence.get("config_probes", "")
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
    print(f"[PASS] Status    : {block.get('status')}")
    print(f"[PASS] Target    : {block.get('hostname')}")
    print(f"[PASS] Probes    : {summary.get('probes')}")
    print(f"[PASS] Accessible: {summary.get('accessible')}")
    print(f"[PASS] CVE       : {cve.get('candidate_count')} candidate(s)")
    print(f"[PASS] Review    : {summary.get('requires_review')}")
    print("[PASS] CVE Triage: configuration candidates are evidence; no automatic finding.")
    print("[PASS] Assessment: configuration exposure/CVE correlation dicatat sebagai evidence.")


if __name__ == "__main__":
    app()
