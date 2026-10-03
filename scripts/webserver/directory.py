#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Web Server Configuration - Checklist 4-002
Directory listing / directory indexing exposure

Design:
- Consumes authoritative directory discovery evidence from Recon (Gobuster).
- Does NOT run Gobuster or perform directory brute-force discovery.
- Selects directory-like paths from the Recon artifact.
- Performs controlled HTTP/HTTPS GET requests against the authorized hostname.
- Detects directory-index/listing indicators.
- Correlates relevant CVE candidates inherited from Web Server 4-001.
- Never turns version/CVE correlation into an automatic finding.
- Raw evidence is retained; report-generation is responsible for redaction.

CLI:
    python directory.py version
    python directory.py init
    python directory.py analyze
    python directory.py status
    python directory.py list
    python directory.py show
    python directory.py verify
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
import typer
import yaml


APP_VERSION = "1.0.1"
SCHEMA_VERSION = "1.0"

CHECKLIST_ID = "4-002"
CHECKLIST_NAME = "Directory listing / directory indexing exposure"
PHASE_NAME = "04 Web Server Configuration"

PROJECT_ID = "PENTEST-2026-002"

REQUEST_TIMEOUT = 15
MAX_BODY_BYTES = 65536
USER_AGENT = "BrebesKab-CSIRT-Tools/4-002"

INDEX_MARKERS = (
    r"<title>\s*index of\b",
    r"<h1>\s*index of\b",
    r">\s*index of\s*/",
    r"parent directory",
    r"apache.*autoindex",
    r"nginx.*autoindex",
    r"<table[^>]+id=[\"']indexlist[\"']",
)

DIRECTORY_CLASSIFICATIONS = {
    "directory-index-observed",
    "discovery-candidate",
}

SKIP_FILE_EXTENSIONS = {
    ".php",
    ".html",
    ".htm",
    ".txt",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".js",
    ".css",
    ".ico",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".bak",
    ".old",
    ".save",
}

app = typer.Typer(add_completion=False, no_args_is_help=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def project_root() -> Path:
    return repo_root() / "projects" / PROJECT_ID


def scope_path() -> Path:
    return project_root() / "01-preparation" / "scope" / "scope.yaml"


def recon_directory_path() -> Path:
    return project_root() / "02-reconnaissance" / "directory" / "directory.yaml"


def version_artifact_path() -> Path:
    return project_root() / "04-web-server-configuration" / "version" / "version.yaml"


def output_dir() -> Path:
    return project_root() / "04-web-server-configuration" / "directory"


def artifact_path() -> Path:
    return output_dir() / "directory.yaml"


def evidence_dir() -> Path:
    return output_dir() / "evidence"


def evidence_path() -> Path:
    return evidence_dir() / "directory-probes.json"


def relative_to_repo(path: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root().resolve()).as_posix()
    except ValueError:
        return str(path).replace("\\", "/")


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"File tidak ditemukan: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root bukan object: {path}")
    return data


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(
            data,
            fh,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tool_version(command: list[str]) -> Optional[str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        text = (result.stdout or result.stderr or "").strip()
        return text.splitlines()[0] if text else None
    except Exception:
        return None


def get_scope_context() -> dict[str, Any]:
    data = load_yaml(scope_path())
    block = data.get("scope", {})
    if not isinstance(block, dict):
        raise ValueError("scope.yaml tidak memiliki block scope yang valid.")

    items = block.get("in_scope", [])
    if not isinstance(items, list):
        raise ValueError("scope.in_scope tidak valid.")

    target = None
    for item in items:
        if not isinstance(item, dict):
            continue
        if str(item.get("scope_id", "")) == "IN-001":
            target = item
            break

    if target is None:
        for item in items:
            if not isinstance(item, dict):
                continue
            if str(item.get("type", "")).lower() == "domain":
                target = item
                break

    if target is None:
        raise ValueError("Domain target tidak ditemukan pada scope.")

    hostname = str(target.get("value", "")).strip()
    if not hostname:
        raise ValueError("Hostname scope kosong.")

    ports = []
    for value in target.get("ports", []) or []:
        try:
            ports.append(int(value))
        except (TypeError, ValueError):
            continue

    authorized_ports = sorted(set(p for p in ports if p in (80, 443)))
    if not authorized_ports:
        raise ValueError("Scope tidak memiliki port web 80/443.")

    return {
        "scope_id": str(target.get("scope_id", "IN-001")),
        "hostname": hostname,
        "ports": authorized_ports,
        "target_url": f"https://{hostname}/",
        "scope_reference": relative_to_repo(scope_path()),
    }


def extract_recon_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    directory_block = data.get("directory", {})
    if isinstance(directory_block, dict):
        results = directory_block.get("results", [])
    else:
        results = []

    if not isinstance(results, list):
        raise ValueError("directory.results pada Recon artifact tidak valid.")

    normalized: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path", "")).strip()
        if not path:
            continue
        if not path.startswith("/"):
            path = "/" + path
        normalized.append(
            {
                "path": path,
                "status_code": item.get("status_code"),
                "content_length": item.get("content_length"),
                "classification": str(item.get("classification", "")).strip(),
                "redirect": str(item.get("redirect", "") or ""),
            }
        )
    return normalized


def looks_directory_like(item: dict[str, Any]) -> tuple[bool, str]:
    path = str(item.get("path", "")).strip()
    classification = str(item.get("classification", "")).lower()
    status = item.get("status_code")

    if path.endswith("/"):
        return True, "path-ends-with-slash"

    if classification == "discovery-candidate":
        # Recon marks redirects such as /assets or /cpanel as candidates.
        # Only treat likely directory redirects as directory candidates.
        if status in (301, 302, 307, 308):
            return True, "recon-discovery-candidate-redirect"

    lower = path.lower()
    last = lower.rstrip("/").rsplit("/", 1)[-1]
    if any(last.endswith(ext) for ext in SKIP_FILE_EXTENSIONS):
        return False, "file-extension"

    # Known directory-style names are only a fallback. This does not discover
    # anything; it merely consumes an already observed Recon path.
    directory_names = {
        "assets",
        "cgi-bin",
        "controlpanel",
        "cpanel",
        "isp",
        "uploads",
        "upload",
        "images",
        "image",
        "files",
        "file",
        "public",
        "static",
        "storage",
        "webapp",
        "webmail",
        "admin",
        "dashboard",
        "livechat",
        "setting",
        "user",
        "myadmin",
        "phpmyadmin",
    }
    if last in directory_names:
        return True, "directory-name-heuristic"

    return False, "not-directory-like"


def select_directory_candidates(
    recon_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in recon_results:
        path = str(item["path"])
        ok, reason = looks_directory_like(item)
        if not ok:
            continue

        # Avoid probing the same normalized path twice.
        normalized = path if path.endswith("/") else path + "/"
        if normalized in seen:
            continue
        seen.add(normalized)

        selected.append(
            {
                **item,
                "probe_path": normalized,
                "selection_reason": reason,
            }
        )

    return selected


def build_bases(hostname: str, ports: list[int]) -> list[tuple[str, int]]:
    bases: list[tuple[str, int]] = []
    if 80 in ports:
        bases.append((f"http://{hostname}", 80))
    if 443 in ports:
        bases.append((f"https://{hostname}", 443))
    return bases


def read_response_body(response: requests.Response) -> tuple[bytes, bool]:
    content = response.content or b""
    if len(content) > MAX_BODY_BYTES:
        return content[:MAX_BODY_BYTES], True
    return content, False


def detect_index_markers(body: bytes) -> list[str]:
    text = body.decode("utf-8", errors="replace")
    markers: list[str] = []
    for pattern in INDEX_MARKERS:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            markers.append(pattern)
    return markers


def classify_response(
    status_code: int,
    content_type: str,
    body: bytes,
    location: str,
) -> tuple[str, bool, list[str]]:
    markers = detect_index_markers(body)

    if status_code in (200, 206) and markers:
        return "directory-index-observed", True, markers

    if status_code in (401, 403):
        return "access-controlled", False, markers

    if status_code == 404:
        return "not-found", False, markers

    if status_code in (301, 302, 303, 307, 308):
        return "redirected", False, markers

    if status_code in (200, 206):
        lower_ct = content_type.lower()
        if "text/html" in lower_ct:
            return "accessible-no-index", False, markers
        return "accessible-non-html", False, markers

    if status_code in (400, 421, 429):
        return "request-rejected", True, markers

    if status_code >= 500:
        return "server-error", True, markers

    return "other-response", True, markers


def probe_url(
    session: requests.Session,
    url: str,
    host: str,
    scheme: str,
    port: int,
    path: str,
) -> dict[str, Any]:
    started = utc_now()
    try:
        response = session.get(
            url,
            headers={
                "Host": host,
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            },
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
            verify=True,
        )

        body, truncated = read_response_body(response)
        content_type = response.headers.get("Content-Type", "")
        location = response.headers.get("Location", "")
        classification, review, markers = classify_response(
            response.status_code,
            content_type,
            body,
            location,
        )

        return {
            "scheme": scheme,
            "port": port,
            "url": url,
            "path": path,
            "host": host,
            "method": "GET",
            "started_at": started,
            "completed_at": utc_now(),
            "status_code": response.status_code,
            "content_type": content_type,
            "location": location,
            "server": response.headers.get("Server", ""),
            "x_powered_by": response.headers.get("X-Powered-By", ""),
            "content_length": len(body),
            "body_truncated": truncated,
            "body_sha256": sha256_bytes(body),
            "body_preview": body.decode("utf-8", errors="replace")[:4000],
            "index_markers": markers,
            "classification": classification,
            "requires_review": review,
            "error": "",
        }
    except requests.RequestException as exc:
        return {
            "scheme": scheme,
            "port": port,
            "url": url,
            "path": path,
            "host": host,
            "method": "GET",
            "started_at": started,
            "completed_at": utc_now(),
            "status_code": None,
            "content_type": "",
            "location": "",
            "server": "",
            "x_powered_by": "",
            "content_length": 0,
            "body_truncated": False,
            "body_sha256": "",
            "body_preview": "",
            "index_markers": [],
            "classification": "probe-error",
            "requires_review": True,
            "error": str(exc),
        }


def load_version_cves() -> tuple[list[dict[str, Any]], str]:
    path = version_artifact_path()
    if not path.is_file():
        return [], "not-found"

    try:
        data = load_yaml(path)
    except Exception:
        return [], "error"

    block = data.get("webserver_version", {})
    if not isinstance(block, dict):
        return [], "invalid"

    correlation = block.get("cve_correlation", {})
    if not isinstance(correlation, dict):
        return [], "not-available"

    raw_candidates = correlation.get("candidates", [])
    if not isinstance(raw_candidates, list):
        return [], "invalid"

    candidates: list[dict[str, Any]] = []
    keywords = (
        "directory",
        "index",
        "autoindex",
        "mod_autoindex",
        "alias",
        "documentroot",
        "path disclosure",
        "file disclosure",
        "filesystem",
        "directory listing",
    )

    for item in raw_candidates:
        if not isinstance(item, dict):
            continue
        description = str(item.get("description", "")).lower()
        product = str(item.get("product", "")).lower()

        if "apache" not in product and "http server" not in product:
            continue

        if any(keyword in description for keyword in keywords):
            candidate = {
                "cve": item.get("cve", ""),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "severity": item.get("severity", ""),
                "cvss": item.get("cvss"),
                "description": item.get("description", ""),
                "classification": "condition-dependent",
                "requires_validation": True,
                "finding": False,
                "nvd_url": item.get("nvd_url", ""),
                "correlation_basis": (
                    "directory/index-related candidate inherited from "
                    "4-001 NVD CPE applicability correlation"
                ),
            }
            candidates.append(candidate)

    return candidates, "completed"


def initialize_artifact() -> dict[str, Any]:
    scope = get_scope_context()
    recon_path = recon_directory_path()

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "project_id": PROJECT_ID,
        "updated_at": utc_now(),
        "webserver_directory": {
            "status": "not-started",
            "checklist": {
                "id": CHECKLIST_ID,
                "name": CHECKLIST_NAME,
                "phase": PHASE_NAME,
            },
            "application": "Bangsaku",
            "hostname": scope["hostname"],
            "target_url": scope["target_url"],
            "environment": "Production",
            "assessment_type": "Black Box",
            "scope_reference": scope["scope_reference"],
            "scope_id": scope["scope_id"],
            "authorized_ports": scope["ports"],
            "method": (
                "Consume completed Recon directory evidence and perform controlled "
                "HTTP/HTTPS GET against selected directory-like paths; no directory "
                "brute-force discovery is performed by this checklist."
            ),
            "source": {
                "recon_directory": relative_to_repo(recon_path),
                "version": relative_to_repo(version_artifact_path()),
            },
            "probe": {
                "requests_library": "requests",
                "allow_redirects": False,
                "max_body_bytes": MAX_BODY_BYTES,
                "timeout_seconds": REQUEST_TIMEOUT,
                "candidate_source": "02-reconnaissance/directory/directory.yaml",
                "candidate_selection": "directory-like paths from Recon artifact",
            },
            "results": [],
            "cve_correlation": {
                "source": "4-001 version/CPE evidence",
                "status": "not-run",
                "candidate_count": 0,
                "requires_validation": 0,
                "candidates": [],
            },
            "assessment": {
                "result": "not-analyzed",
                "requires_review": False,
                "finding": False,
                "note": (
                    "Directory listing/index behavior is assessed from Recon-derived "
                    "candidate paths; no automatic vulnerability finding."
                ),
            },
            "evidence": {
                "directory_probes": relative_to_repo(evidence_path()),
            },
            "errors": [],
            "notes": [
                "Recon directory.yaml is the authoritative candidate source.",
                "Gobuster is not executed by Web Server 4-002.",
                "HTTP/HTTPS probes are controlled GET requests only.",
                "HTTP 200 alone does not prove directory listing.",
                "Directory index markers are required before classification as directory-index-observed.",
                "Raw evidence is retained; credential/secret redaction belongs to report generation.",
                "CVE correlation is triage evidence only and does not establish exploitability or applicability.",
            ],
            "summary": {
                "recon_paths": 0,
                "selected_candidates": 0,
                "probes": 0,
                "directory_index_observed": 0,
                "accessible_no_index": 0,
                "access_controlled": 0,
                "not_found": 0,
                "redirected": 0,
                "probe_errors": 0,
                "requires_review": 0,
            },
        },
    }
    return artifact


@app.command()
def version() -> None:
    """Show script and schema version."""
    print(f"directory.py v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")


@app.command()
def init() -> None:
    """Initialize the Web Server 4-002 artifact."""
    try:
        artifact = initialize_artifact()
        save_yaml(artifact_path(), artifact)
        print("[PASS] Directory Listing berhasil diinisialisasi.")
        print(f"PROJECT : {PROJECT_ID}")
        print(f"TARGET  : {artifact['webserver_directory']['hostname']}")
        print(
            "PORTS   : "
            + ", ".join(
                str(p) for p in artifact["webserver_directory"]["authorized_ports"]
            )
        )
        print(f"SOURCE  : {artifact['webserver_directory']['source']['recon_directory']}")
        print(f"FILE    : {artifact_path()}")
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise typer.Exit(code=1)


@app.command()
def analyze() -> None:
    """Analyze Recon-derived directory candidates with controlled HTTP GET."""
    try:
        if not recon_directory_path().is_file():
            raise FileNotFoundError(
                f"Recon directory artifact belum ditemukan: {recon_directory_path()}"
            )

        artifact = initialize_artifact()
        block = artifact["webserver_directory"]
        scope = get_scope_context()
        recon = load_yaml(recon_directory_path())
        recon_status = str(
            recon.get("directory", {}).get("status", recon.get("status", ""))
        )

        recon_results = extract_recon_results(recon)
        candidates = select_directory_candidates(recon_results)

        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})

        results: list[dict[str, Any]] = []
        errors: list[str] = []

        for base_url, port in build_bases(scope["hostname"], scope["ports"]):
            scheme = urlparse(base_url).scheme

            for candidate in candidates:
                path = candidate["probe_path"]
                url = urljoin(base_url + "/", path.lstrip("/"))

                result = probe_url(
                    session=session,
                    url=url,
                    host=scope["hostname"],
                    scheme=scheme,
                    port=port,
                    path=path,
                )

                result["recon_source"] = {
                    "path": candidate["path"],
                    "status_code": candidate.get("status_code"),
                    "content_length": candidate.get("content_length"),
                    "classification": candidate.get("classification"),
                    "redirect": candidate.get("redirect"),
                    "selection_reason": candidate.get("selection_reason"),
                }

                results.append(result)

                if result["error"]:
                    errors.append(
                        f"{scheme}:{port}{path}: {result['error']}"
                    )

        cve_candidates, cve_status = load_version_cves()

        index_count = sum(
            r["classification"] == "directory-index-observed" for r in results
        )
        no_index_count = sum(
            r["classification"] in {"accessible-no-index", "accessible-non-html"}
            for r in results
        )
        access_count = sum(
            r["classification"] == "access-controlled" for r in results
        )
        not_found_count = sum(
            r["classification"] == "not-found" for r in results
        )
        redirect_count = sum(
            r["classification"] == "redirected" for r in results
        )
        error_count = sum(
            r["classification"] == "probe-error" for r in results
        )
        review_count = sum(bool(r.get("requires_review")) for r in results)

        finding = False
        if index_count > 0:
            assessment_result = "directory-index-observed"
            requires_review = True
            note = (
                "Directory index/listing markers were observed on one or more "
                "Recon-derived paths. This is an evidence-based observation; "
                "impact and intended exposure require assessment."
            )
        elif error_count > 0:
            assessment_result = "probe-errors"
            requires_review = True
            note = (
                "Some directory probes failed. Results must be reviewed before "
                "drawing a conclusion."
            )
        elif results:
            assessment_result = "no-directory-index-observed"
            requires_review = bool(review_count)
            note = (
                "No directory-index markers were observed in the controlled probes. "
                "A successful HTTP response alone is not evidence of directory listing."
            )
        else:
            assessment_result = "no-candidates"
            requires_review = True
            note = (
                "No directory-like candidates were derived from the Recon artifact; "
                "the checklist cannot establish directory-index behavior."
            )

        evidence = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "target": scope["target_url"],
            "hostname": scope["hostname"],
            "authorized_ports": scope["ports"],
            "source": {
                "recon_directory": relative_to_repo(recon_directory_path()),
                "recon_status": recon_status,
                "candidate_count": len(candidates),
                "recon_result_count": len(recon_results),
            },
            "request_policy": {
                "method": "GET",
                "allow_redirects": False,
                "timeout_seconds": REQUEST_TIMEOUT,
                "max_body_bytes": MAX_BODY_BYTES,
                "user_agent": USER_AGENT,
            },
            "candidate_paths": candidates,
            "results": results,
        }
        save_json(evidence_path(), evidence)

        block["status"] = "completed"
        block["updated_at"] = utc_now()
        block["probe"]["completed_at"] = utc_now()
        block["probe"]["recon_status"] = recon_status
        block["probe"]["candidate_count"] = len(candidates)
        block["probe"]["recon_result_count"] = len(recon_results)
        block["results"] = results
        block["cve_correlation"] = {
            "source": "4-001 version/CPE evidence",
            "status": cve_status,
            "candidate_count": len(cve_candidates),
            "requires_validation": sum(
                bool(c.get("requires_validation")) for c in cve_candidates
            ),
            "candidates": cve_candidates,
            "note": (
                "Only directory/index-related candidates inherited from 4-001 "
                "are recorded. Version/CPE correlation does not prove exploitability "
                "or configuration prerequisites."
            ),
        }
        block["assessment"] = {
            "result": assessment_result,
            "requires_review": requires_review,
            "finding": finding,
            "note": note,
        }
        block["evidence"] = {
            "directory_probes": relative_to_repo(evidence_path()),
            "recon_directory": relative_to_repo(recon_directory_path()),
        }
        block["errors"] = errors
        block["summary"] = {
            "recon_paths": len(recon_results),
            "selected_candidates": len(candidates),
            "probes": len(results),
            "directory_index_observed": index_count,
            "accessible_no_index": no_index_count,
            "access_controlled": access_count,
            "not_found": not_found_count,
            "redirected": redirect_count,
            "probe_errors": error_count,
            "requires_review": review_count,
        }

        save_yaml(artifact_path(), artifact)

        print("[PASS] Directory Listing berhasil dianalisis.")
        print(f"PROJECT         : {PROJECT_ID}")
        print(f"TARGET          : {scope['hostname']}")
        print(f"RECON PATHS     : {len(recon_results)}")
        print(f"CANDIDATES      : {len(candidates)}")
        print(f"PROBES          : {len(results)}")
        print(f"INDEX OBSERVED  : {index_count}")
        print(f"ACCESS CONTROL  : {access_count}")
        print(f"NO INDEX        : {no_index_count}")
        print(f"NOT FOUND       : {not_found_count}")
        print(f"REDIRECTED      : {redirect_count}")
        print(f"PROBE ERRORS    : {error_count}")
        print(f"CVE CANDIDATES  : {len(cve_candidates)}")
        print(f"REQUIRES REVIEW : {int(bool(requires_review))}")
        print("STATUS          : completed")
        print(f"FILE            : {artifact_path()}")
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise typer.Exit(code=1)


@app.command()
def status() -> None:
    """Show concise lifecycle status."""
    try:
        data = load_yaml(artifact_path())
        block = data.get("webserver_directory", {})
        summary = block.get("summary", {})
        assessment = block.get("assessment", {})
        cve = block.get("cve_correlation", {})

        print(f"PROJECT         : {data.get('project_id', '-')}")
        print(f"STATUS          : {block.get('status', '-')}")
        print(f"TARGET          : {block.get('hostname', '-')}")
        print(f"RECON PATHS     : {summary.get('recon_paths', 0)}")
        print(f"CANDIDATES      : {summary.get('selected_candidates', 0)}")
        print(f"PROBES          : {summary.get('probes', 0)}")
        print(f"INDEX OBSERVED  : {summary.get('directory_index_observed', 0)}")
        print(f"CVE CANDIDATES  : {cve.get('candidate_count', 0)}")
        print(f"REQUIRES REVIEW : {int(bool(assessment.get('requires_review')))}")
        print(f"FINDING         : {int(bool(assessment.get('finding')))}")
        print(f"FILE            : {artifact_path()}")
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise typer.Exit(code=1)


@app.command(name="list")
def list_results() -> None:
    """List concise probe classifications."""
    try:
        data = load_yaml(artifact_path())
        block = data.get("webserver_directory", {})
        results = block.get("results", [])
        summary = block.get("summary", {})
        cve = block.get("cve_correlation", {})

        print(f"PROJECT: {data.get('project_id', '-')}")
        print(f"STATUS : {block.get('status', '-')}")
        print(f"TARGET : {block.get('hostname', '-')}")
        print()
        print(
            "SCHEME PORT PATH".ljust(34)
            + "STATUS".ljust(9)
            + "CLASSIFICATION".ljust(30)
            + "REVIEW"
        )
        print("-" * 90)

        for item in results:
            path = str(item.get("path", ""))[:30]
            print(
                f"{str(item.get('scheme', '')).upper():<7}"
                f"{str(item.get('port', '')):<5}"
                f"{path:<30}"
                f"{str(item.get('status_code', '-')):<9}"
                f"{str(item.get('classification', '')):<30}"
                f"{int(bool(item.get('requires_review')))}"
            )

        print()
        print("SUMMARY")
        print("-" * 90)
        for key in (
            "recon_paths",
            "selected_candidates",
            "probes",
            "directory_index_observed",
            "accessible_no_index",
            "access_controlled",
            "not_found",
            "redirected",
            "probe_errors",
            "requires_review",
        ):
            print(f"{key}: {summary.get(key, 0)}")

        print()
        print(f"CVE CANDIDATES: {cve.get('candidate_count', 0)}")
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise typer.Exit(code=1)


@app.command()
def show() -> None:
    """Show the complete YAML artifact."""
    try:
        if not artifact_path().is_file():
            raise FileNotFoundError(f"Artifact belum ditemukan: {artifact_path()}")
        print(f"PROJECT: {PROJECT_ID}")
        print(f"FILE   : {artifact_path()}")
        print()
        print(artifact_path().read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise typer.Exit(code=1)


@app.command()
def verify() -> None:
    """Validate Web Server 4-002 artifact and evidence integrity."""
    try:
        data = load_yaml(artifact_path())
        block = data.get("webserver_directory", {})
        errors: list[str] = []

        if data.get("schema_version") != SCHEMA_VERSION:
            errors.append("schema_version tidak sesuai.")

        if data.get("project_id") != PROJECT_ID:
            errors.append("project_id tidak sesuai.")

        if block.get("status") != "completed":
            errors.append("status belum completed.")

        checklist = block.get("checklist", {})
        if checklist.get("id") != CHECKLIST_ID:
            errors.append("checklist.id tidak sesuai.")
        if checklist.get("name") != CHECKLIST_NAME:
            errors.append("checklist.name tidak sesuai.")

        results = block.get("results")
        summary = block.get("summary", {})
        assessment = block.get("assessment", {})
        cve = block.get("cve_correlation", {})
        evidence = block.get("evidence", {})
        source = block.get("source", {})

        if not isinstance(results, list) or not results:
            errors.append("results kosong.")

        if not isinstance(summary, dict):
            errors.append("summary tidak valid.")
        else:
            if summary.get("probes") != len(results or []):
                errors.append("summary.probes tidak sama dengan jumlah results.")

        recon_rel = source.get("recon_directory", "")
        if not recon_rel:
            errors.append("source.recon_directory belum tercatat.")
        elif not (repo_root() / Path(recon_rel)).is_file():
            errors.append("Recon directory artifact tidak ditemukan.")

        evidence_rel = evidence.get("directory_probes", "")
        if not evidence_rel:
            errors.append("Evidence directory probes belum tercatat.")
        elif not (repo_root() / Path(evidence_rel)).is_file():
            errors.append("File evidence directory probes tidak ditemukan.")

        if not isinstance(cve, dict):
            errors.append("cve_correlation tidak valid.")
        else:
            candidates = cve.get("candidates", [])
            if cve.get("candidate_count") != len(candidates):
                errors.append(
                    "candidate_count tidak sama dengan jumlah CVE candidates."
                )
            if any(item.get("finding") is True for item in candidates):
                errors.append("CVE candidate tidak boleh menjadi automatic finding.")

        if not isinstance(assessment, dict):
            errors.append("assessment tidak valid.")
        elif assessment.get("finding") is True:
            errors.append("directory.py tidak boleh membuat automatic finding.")

        if errors:
            print("[FAIL] Directory Listing gagal validasi.")
            for error in errors:
                print(f"[FAIL] {error}")
            raise typer.Exit(code=1)

        print("[PASS] Directory Listing memenuhi validasi.")
        print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
        print(f"[PASS] Status    : {block.get('status')}")
        print(f"[PASS] Target    : {block.get('hostname')}")
        print(f"[PASS] Recon     : {summary.get('recon_paths', 0)} path(s)")
        print(f"[PASS] Candidates: {summary.get('selected_candidates', 0)}")
        print(f"[PASS] Probes    : {summary.get('probes', 0)}")
        print(
            f"[PASS] Index     : "
            f"{summary.get('directory_index_observed', 0)} observation(s)"
        )
        print(f"[PASS] CVE       : {cve.get('candidate_count', 0)} candidate(s)")
        print(f"[PASS] Review    : {int(bool(assessment.get('requires_review')))}")
        print(
            "[PASS] CVE Triage: directory/index candidates are evidence; "
            "no automatic finding."
        )
        print(
            "[PASS] Assessment: directory listing/index behavior is recorded "
            "for review; no automatic vulnerability finding."
        )
    except typer.Exit:
        raise
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
