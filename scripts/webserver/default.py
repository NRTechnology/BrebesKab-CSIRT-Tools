#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - webserver/default.py

Checklist: 4-003 Default Virtual Host / Unintended Host Handling

Boundary
--------
- Controlled HTTP GET only.
- Compares the authorized hostname with controlled alternate Host headers.
- HTTPS tests keep the target hostname as TLS SNI while changing the HTTP Host
  header. This isolates HTTP virtual-host handling from TLS certificate/SNI
  behavior.
- No brute force, host fuzzing, cache poisoning, request smuggling,
  authentication guessing, exploitation, or destructive action.
- Raw evidence is retained; report generation is responsible for redaction.
- CVE correlation is review/triage evidence only and never creates an automatic
  vulnerability finding.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import typer
import yaml

APP_NAME = "BrebesKab-CSIRT-Tools default.py"
APP_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "4-003"
CHECKLIST_NAME = "Default virtual host / unintended host handling"
PHASE_NAME = "04 Web Server Configuration"

DEFAULT_TIMEOUT = 15
MAX_BODY_BYTES = 65536
REQUEST_USER_AGENT = f"BrebesKab-CSIRT-Tools/{APP_VERSION} Web-Server-Default"
OBSERVED_IP = "36.94.238.158"

HOST_VARIANTS = (
    ("authorized", "authorized hostname", "normal"),
    ("unknown", "unknown.invalid", "unknown-host"),
    ("ip", OBSERVED_IP, "ip-host"),
)

# A difference between the authorized Host and an alternate Host is an
# observation that requires assessment. It is not automatically a vulnerability.
CVE_KEYWORDS = (
    "virtual host",
    "virtualhost",
    "vhost",
    "host header",
    "host-header",
    "hostname",
    "request host",
    "host name",
    "mod_vhost",
    "mod_alias",
    "mod_rewrite",
    "serveralias",
    "server name",
    "servername",
    "default virtual",
)

app = typer.Typer(add_completion=False, no_args_is_help=True)


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
    path.write_text(
        yaml.safe_dump(
            data,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        ),
        encoding="utf-8",
        newline="\n",
    )


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
    return project_dir(repo_root, project_id) / "04-web-server-configuration" / "default"


def artifact_file(repo_root: Path, project_id: str) -> Path:
    return artifact_root(repo_root, project_id) / "default.yaml"


def evidence_root(repo_root: Path, project_id: str) -> Path:
    return artifact_root(repo_root, project_id) / "evidence"


def source_paths(repo_root: Path, project_id: str) -> dict[str, Path]:
    root = project_dir(repo_root, project_id)
    return {
        "scope": root / "01-preparation" / "scope" / "scope.yaml",
        "version": root / "04-web-server-configuration" / "version" / "version.yaml",
        "service": root / "03-infrastructure" / "service" / "service.yaml",
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

    ports = sorted(set(authorized_ports))
    supported_ports = [port for port in (80, 443) if port in ports]

    if not supported_ports:
        raise ValueError("Scope tidak memiliki port 80/443 untuk checklist 4-003.")

    return {
        "hostname": hostname,
        "target_url": f"https://{hostname}/",
        "authorized_ports": ports,
        "probe_ports": supported_ports,
        "scope_id": scope_id,
        "observed_ip": OBSERVED_IP,
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
        "webserver_default": {
            "status": "not-started",
            "checklist": {
                "id": CHECKLIST_ID,
                "name": CHECKLIST_NAME,
                "phase": PHASE_NAME,
            },
            "application": "Bangsaku",
            "hostname": context["hostname"],
            "target_url": context["target_url"],
            "observed_ip": context["observed_ip"],
            "environment": "Production",
            "assessment_type": "Black Box",
            "scope_reference": "01-preparation/scope/scope.yaml",
            "scope_id": context["scope_id"],
            "authorized_ports": context["authorized_ports"],
            "probe_ports": context["probe_ports"],
            "method": (
                "controlled HTTP GET comparing the authorized Host header with "
                "unknown.invalid and the observed IP; HTTPS keeps target hostname "
                "as TLS SNI while changing the HTTP Host header"
            ),
            "source_status": {},
            "probe": {
                "host_variants": [
                    {"id": item_id, "value": value, "role": role}
                    for item_id, value, role in HOST_VARIANTS
                ],
                "request_count": 0,
                "ports": context["probe_ports"],
            },
            "results": [],
            "comparisons": [],
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
                "A default/alternate virtual-host response is an observation requiring assessment, not an automatic vulnerability finding.",
                "HTTPS probes preserve the authorized hostname in TLS SNI and change only the HTTP Host header.",
                "The observed IP is used as a controlled Host-header value; it is not treated as a separate scope target.",
                "Raw evidence is retained; credential/secret redaction is performed during report generation.",
                "CVE correlation is triage evidence only and does not establish exploitability or applicability.",
            ],
        },
    }


def extract_default_host_cves(version_data: dict[str, Any]) -> list[dict[str, Any]]:
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
            cvss = cve.get("cvss", {})
            if not isinstance(cvss, dict):
                cvss = {}

            selected.append(
                {
                    "cve": cve_id,
                    "product": product.get("product", ""),
                    "version": product.get("version", ""),
                    "severity": cvss.get("severity", ""),
                    "cvss": cvss.get("score", ""),
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
                        "default/virtual-host-relevant candidate from 4-001 "
                        "NVD CPE applicability correlation"
                    ),
                }
            )

    return selected


def response_fingerprint(
    status_code: int | None,
    content_type: str,
    location: str,
    body_sha256: str,
    content_length: int,
) -> str:
    value = "|".join(
        [
            str(status_code),
            content_type.lower().strip(),
            location.strip(),
            body_sha256,
            str(content_length),
        ]
    )
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_location(location: str) -> str:
    if not location:
        return ""
    return location.strip()


def classify_host_response(
    *,
    variant_id: str,
    status_code: int | None,
    error: str,
) -> str:
    if error:
        return "probe-error"
    if variant_id == "authorized":
        return "authorized-baseline"
    if status_code is None:
        return "not-confirmed"
    if status_code in (200, 206):
        return "alternate-host-served"
    if status_code in (301, 302, 303, 307, 308):
        return "alternate-host-redirect"
    if status_code in (400, 401, 403, 404):
        return "alternate-host-rejected"
    return "alternate-host-other-response"


def probe(
    *,
    scheme: str,
    port: int,
    hostname: str,
    host_value: str,
    variant_id: str,
    variant_role: str,
) -> dict[str, Any]:
    started = now_iso()
    url = f"{scheme}://{hostname}/"
    headers = {
        "User-Agent": REQUEST_USER_AGENT,
        "Accept": "*/*",
        "Host": host_value,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
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
        location = response.headers.get("Location", "")
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")
        text = raw.decode("utf-8", errors="replace")
        body_sha = sha256_bytes(raw)
        fingerprint = response_fingerprint(
            response.status_code,
            content_type,
            location,
            body_sha,
            len(raw),
        )

        return {
            "scheme": scheme,
            "port": port,
            "url": url,
            "tls_sni": hostname if scheme == "https" else None,
            "host_header": host_value,
            "host_variant": variant_id,
            "host_role": variant_role,
            "method": "GET",
            "started_at": started,
            "completed_at": now_iso(),
            "status_code": response.status_code,
            "final_url": response.url,
            "headers": dict(response.headers.items()),
            "content_type": content_type,
            "location": normalize_location(location),
            "server": server,
            "x_powered_by": powered_by,
            "content_length": len(raw),
            "body_truncated": len(raw) >= MAX_BODY_BYTES,
            "body_sha256": body_sha,
            "body_preview": text[:4000],
            "response_fingerprint": fingerprint,
            "classification": classify_host_response(
                variant_id=variant_id,
                status_code=response.status_code,
                error="",
            ),
            "error": "",
        }
    except requests.RequestException as exc:
        return {
            "scheme": scheme,
            "port": port,
            "url": url,
            "tls_sni": hostname if scheme == "https" else None,
            "host_header": host_value,
            "host_variant": variant_id,
            "host_role": variant_role,
            "method": "GET",
            "started_at": started,
            "completed_at": now_iso(),
            "status_code": None,
            "final_url": url,
            "headers": {},
            "content_type": "",
            "location": "",
            "server": "",
            "x_powered_by": "",
            "content_length": 0,
            "body_truncated": False,
            "body_sha256": "",
            "body_preview": "",
            "response_fingerprint": "",
            "classification": classify_host_response(
                variant_id=variant_id,
                status_code=None,
                error=str(exc),
            ),
            "error": str(exc),
        }


def curl_available() -> bool:
    return shutil.which("curl") is not None


def curl_probe(
    *,
    scheme: str,
    hostname: str,
    host_value: str,
) -> dict[str, Any]:
    """Optional curl header/body corroboration. Requests remains mandatory."""
    if not curl_available():
        return {
            "available": False,
            "used": False,
            "command": [],
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "curl executable not found",
        }

    url = f"{scheme}://{hostname}/"
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--max-redirs",
        "0",
        "--max-time",
        str(DEFAULT_TIMEOUT),
        "--noproxy",
        "*",
        "-D",
        "-",
        "-o",
        "-",
        "-H",
        f"Host: {host_value}",
        url,
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=DEFAULT_TIMEOUT + 5,
            check=False,
        )
        return {
            "available": True,
            "used": True,
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout[:12000],
            "stderr": completed.stderr[:4000],
            "error": "",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "available": True,
            "used": False,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": str(exc),
        }


def compact_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "scheme": result["scheme"],
        "port": result["port"],
        "host_variant": result["host_variant"],
        "host_role": result["host_role"],
        "host_header": result["host_header"],
        "tls_sni": result["tls_sni"],
        "status_code": result["status_code"],
        "content_type": result["content_type"],
        "location": result["location"],
        "server": result["server"],
        "x_powered_by": result["x_powered_by"],
        "content_length": result["content_length"],
        "body_sha256": result["body_sha256"],
        "response_fingerprint": result["response_fingerprint"],
        "classification": result["classification"],
        "error": result["error"],
    }


def compare_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    comparisons: list[dict[str, Any]] = []
    groups: dict[tuple[str, int], dict[str, dict[str, Any]]] = {}

    for result in results:
        key = (str(result["scheme"]), int(result["port"]))
        groups.setdefault(key, {})[str(result["host_variant"])] = result

    for (scheme, port), variants in sorted(groups.items()):
        baseline = variants.get("authorized")
        if not baseline:
            continue

        for alternate_id in ("unknown", "ip"):
            alternate = variants.get(alternate_id)
            if not alternate:
                continue

            comparable = not baseline["error"] and not alternate["error"]
            differences: list[str] = []
            if comparable:
                if baseline["status_code"] != alternate["status_code"]:
                    differences.append("status_code")
                if baseline["content_type"] != alternate["content_type"]:
                    differences.append("content_type")
                if baseline["location"] != alternate["location"]:
                    differences.append("location")
                if baseline["server"] != alternate["server"]:
                    differences.append("server")
                if baseline["x_powered_by"] != alternate["x_powered_by"]:
                    differences.append("x_powered_by")
                if baseline["body_sha256"] != alternate["body_sha256"]:
                    differences.append("body_sha256")
                if baseline["content_length"] != alternate["content_length"]:
                    differences.append("content_length")

            if not comparable:
                comparison = "not-comparable"
                interpretation = "One or both probes failed; repeat/triage is required."
            elif not differences:
                comparison = "equivalent-response"
                interpretation = (
                    "Alternate Host produced an equivalent response fingerprint "
                    "to the authorized hostname; default/host-insensitive handling "
                    "requires review."
                )
            elif alternate["classification"] in (
                "alternate-host-rejected",
                "alternate-host-redirect",
            ):
                comparison = "host-rejected-or-separated"
                interpretation = (
                    "Alternate Host produced a different response and was rejected "
                    "or redirected; this is evidence of host-sensitive handling."
                )
            else:
                comparison = "host-response-differs"
                interpretation = (
                    "Alternate Host produced a different response; assess whether "
                    "the selected/default virtual host is intentional and safe."
                )

            comparisons.append(
                {
                    "scheme": scheme,
                    "port": port,
                    "baseline_host": baseline["host_header"],
                    "alternate_variant": alternate_id,
                    "alternate_host": alternate["host_header"],
                    "comparable": comparable,
                    "differences": differences,
                    "comparison": comparison,
                    "requires_review": comparable and comparison != "host-rejected-or-separated",
                    "interpretation": interpretation,
                    "baseline_status": baseline["status_code"],
                    "alternate_status": alternate["status_code"],
                    "baseline_fingerprint": baseline["response_fingerprint"],
                    "alternate_fingerprint": alternate["response_fingerprint"],
                }
            )

    return comparisons


@app.command("version")
def version_cmd() -> None:
    print(f"default.py v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")


@app.command("init")
def init_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    context = load_context(repo_root, project_id)
    path = artifact_file(repo_root, project_id)
    write_yaml(path, initial_artifact(context, project_id))

    print("[PASS] Default Virtual Host berhasil diinisialisasi.")
    print(f"PROJECT : {project_id}")
    print(f"TARGET  : {context['hostname']}")
    print(f"PORTS   : {', '.join(str(p) for p in context['probe_ports'])}")
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
    block = artifact["webserver_default"]
    sources = context["sources"]

    block["source_status"] = {
        "version": source_status(sources["version"], "webserver_version"),
        "service": source_status(sources["service"], "service_enumeration"),
    }

    full_evidence: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    curl_evidence: list[dict[str, Any]] = []

    for port in context["probe_ports"]:
        scheme = "https" if port == 443 else "http"
        for variant_id, host_value, role in HOST_VARIANTS:
            result = probe(
                scheme=scheme,
                port=port,
                hostname=context["hostname"],
                host_value=host_value if variant_id != "authorized" else context["hostname"],
                variant_id=variant_id,
                variant_role=role,
            )
            full_evidence.append(result)
            results.append(compact_result(result))

            if result["error"]:
                errors.append(
                    {
                        "scheme": scheme,
                        "port": port,
                        "host_variant": variant_id,
                        "host_header": result["host_header"],
                        "error": result["error"],
                    }
                )

            if variant_id != "authorized":
                curl_result = curl_probe(
                    scheme=scheme,
                    hostname=context["hostname"],
                    host_value=result["host_header"],
                )
                curl_evidence.append(
                    {
                        "scheme": scheme,
                        "port": port,
                        "host_variant": variant_id,
                        "host_header": result["host_header"],
                        **curl_result,
                    }
                )

    comparisons = compare_results(full_evidence)
    requires_review_comparisons = [
        item for item in comparisons if item.get("requires_review")
    ]
    probe_errors = [item for item in results if item["classification"] == "probe-error"]
    equivalent = [
        item for item in comparisons if item["comparison"] == "equivalent-response"
    ]
    rejected = [
        item for item in comparisons if item["comparison"] == "host-rejected-or-separated"
    ]
    differing = [
        item for item in comparisons if item["comparison"] == "host-response-differs"
    ]

    version_data: dict[str, Any] = {}
    try:
        version_data = load_yaml(sources["version"])
    except FileNotFoundError:
        pass

    cve_candidates = extract_default_host_cves(version_data)
    requires_review = bool(
        requires_review_comparisons
        or equivalent
        or differing
        or probe_errors
        or cve_candidates
    )

    if probe_errors and not comparisons:
        assessment_result = "probe-incomplete"
    elif equivalent:
        assessment_result = "default-host-response-observed"
    elif differing:
        assessment_result = "alternate-host-response-differs"
    elif rejected and not requires_review_comparisons:
        assessment_result = "alternate-host-rejected-or-separated"
    else:
        assessment_result = "host-handling-not-confirmed"

    evidence_dir = evidence_root(repo_root, project_id)
    evidence_file = evidence_dir / "default-host-probes.json"
    write_json(
        evidence_file,
        {
            "schema_version": "1.0",
            "generated_at": now_iso(),
            "target": context["target_url"],
            "observed_ip": context["observed_ip"],
            "request_policy": {
                "method": "GET",
                "allow_redirects": False,
                "max_body_bytes": MAX_BODY_BYTES,
                "authorized_host": context["hostname"],
                "alternate_hosts": ["unknown.invalid", context["observed_ip"]],
                "https_sni": context["hostname"],
                "https_note": (
                    "For HTTPS, the URL hostname remains the TLS SNI while the "
                    "HTTP Host header is changed for alternate-host probes."
                ),
            },
            "results": full_evidence,
            "comparisons": comparisons,
            "curl_corroboration": curl_evidence,
        },
    )

    block["status"] = "completed" if not probe_errors else "partial"
    block["probe"] = {
        "host_variants": [
            {
                "id": item_id,
                "value": context["hostname"] if item_id == "authorized" else value,
                "role": role,
            }
            for item_id, value, role in HOST_VARIANTS
        ],
        "ports": context["probe_ports"],
        "schemes": [
            "http" if 80 in context["probe_ports"] else None,
            "https" if 443 in context["probe_ports"] else None,
        ],
        "request_count": len(results),
        "allow_redirects": False,
        "max_body_bytes": MAX_BODY_BYTES,
        "requests_library": "requests",
        "curl_corroboration": curl_available(),
        "completed_at": now_iso(),
    }
    block["probe"]["schemes"] = [item for item in block["probe"]["schemes"] if item]
    block["results"] = results
    block["comparisons"] = comparisons
    block["summary"] = {
        "probes": len(results),
        "comparisons": len(comparisons),
        "equivalent_responses": len(equivalent),
        "host_rejected_or_separated": len(rejected),
        "different_responses": len(differing),
        "probe_errors": len(probe_errors),
        "requires_review_comparisons": len(requires_review_comparisons),
        "requires_review": int(requires_review),
    }
    block["assessment"] = {
        "result": assessment_result,
        "requires_review": requires_review,
        "finding": False,
        "note": (
            "Default/alternate virtual-host behavior is an observation requiring "
            "assessment. A matching or differing response does not by itself prove "
            "host-header poisoning, cache poisoning, request smuggling, access-control "
            "bypass, or another vulnerability."
        ),
    }
    block["cve_correlation"] = {
        "source": "4-001 version/CPE evidence",
        "status": "completed" if version_data else "not-available",
        "candidate_count": len(cve_candidates),
        "requires_validation": len(cve_candidates),
        "candidates": cve_candidates,
        "note": (
            "Only virtual-host/default-host relevant candidates inherited from 4-001 "
            "are recorded. Version/CPE correlation does not prove exploitability or "
            "configuration prerequisites."
        ),
    }
    block["evidence"] = {
        "default_host_probes": str(
            evidence_file.relative_to(repo_root)
        ).replace("\\", "/"),
    }
    block["errors"] = errors
    block["updated_at"] = now_iso()
    artifact["updated_at"] = now_iso()

    write_yaml(path, artifact)

    print("[PASS] Default Virtual Host berhasil dianalisis.")
    print(f"PROJECT         : {project_id}")
    print(f"TARGET          : {context['hostname']}")
    print(f"PROBES          : {len(results)}")
    print(f"COMPARISONS     : {len(comparisons)}")
    print(f"EQUIVALENT      : {len(equivalent)}")
    print(f"REJECTED/SEPAR. : {len(rejected)}")
    print(f"DIFFERENT       : {len(differing)}")
    print(f"PROBE ERRORS    : {len(probe_errors)}")
    print(f"CVE CANDIDATES  : {len(cve_candidates)}")
    print(f"REQUIRES REVIEW : {int(requires_review)}")
    print(f"STATUS          : {block['status']}")
    print(f"FILE            : {path}")


@app.command("list")
def list_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    path = artifact_file(repo_root, project_id)
    data = load_yaml(path)
    block = data["webserver_default"]

    print(f"PROJECT: {project_id}")
    print(f"STATUS : {block.get('status', '')}")
    print(f"TARGET : {block.get('hostname', '')}")
    print()
    print("SCHEME PORT HOST-VARIANT  STATUS CLASSIFICATION              REVIEW")
    print("-" * 78)

    review_variants = {
        "alternate-host-served",
        "alternate-host-other-response",
    }

    for item in block.get("results", []):
        review = item.get("classification") in review_variants
        print(
            f"{str(item.get('scheme', '')).upper():6} "
            f"{str(item.get('port', '')):4} "
            f"{str(item.get('host_variant', '')):13} "
            f"{str(item.get('status_code', '')):6} "
            f"{str(item.get('classification', ''))[:27]:27} "
            f"{str(review)}"
        )

    print()
    print("COMPARISONS")
    print("-" * 78)
    for item in block.get("comparisons", []):
        print(
            f"{str(item.get('scheme', '')).upper():6} "
            f"{str(item.get('port', '')):4} "
            f"{str(item.get('alternate_variant', '')):13} "
            f"{str(item.get('comparison', '')):30} "
            f"review={item.get('requires_review', False)}"
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
    print(
        yaml.safe_dump(
            data,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )
    )


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

    block = data.get("webserver_default", {})
    errors: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai.")
    if data.get("project_id") != project_id:
        errors.append("project_id tidak sesuai.")
    if block.get("status") not in ("completed", "partial"):
        errors.append("status bukan completed/partial.")

    checklist = block.get("checklist", {})
    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist ID tidak sesuai.")
    if not block.get("hostname"):
        errors.append("hostname kosong.")

    results = block.get("results")
    comparisons = block.get("comparisons")
    summary = block.get("summary", {})
    cve = block.get("cve_correlation", {})
    assessment = block.get("assessment", {})
    evidence = block.get("evidence", {})
    probe = block.get("probe", {})

    if not isinstance(results, list) or not results:
        errors.append("results kosong.")
    if not isinstance(comparisons, list) or not comparisons:
        errors.append("comparisons kosong.")
    if not isinstance(summary, dict):
        errors.append("summary tidak valid.")
    else:
        if summary.get("probes") != len(results or []):
            errors.append("summary.probes tidak sama dengan jumlah results.")
        if summary.get("comparisons") != len(comparisons or []):
            errors.append("summary.comparisons tidak sama dengan jumlah comparisons.")

    if not isinstance(probe, dict) or not probe.get("host_variants"):
        errors.append("probe.host_variants kosong.")
    if not isinstance(cve, dict):
        errors.append("cve_correlation tidak valid.")
    elif cve.get("candidate_count") != len(cve.get("candidates", []) or []):
        errors.append("cve candidate_count tidak sama dengan candidates.")

    if not isinstance(assessment, dict):
        errors.append("assessment tidak valid.")
    elif assessment.get("finding") is not False:
        errors.append("assessment.finding harus false; finding tidak dibuat otomatis.")

    evidence_path = evidence.get("default_host_probes") if isinstance(evidence, dict) else ""
    if not evidence_path:
        errors.append("evidence.default_host_probes kosong.")
    else:
        absolute = repo_root / Path(str(evidence_path))
        if not absolute.is_file():
            errors.append(f"Evidence tidak ditemukan: {absolute}")
        else:
            try:
                evidence_data = json.loads(absolute.read_text(encoding="utf-8"))
                if len(evidence_data.get("results", [])) != len(results or []):
                    errors.append("Jumlah evidence.results tidak sama dengan artifact.results.")
                if len(evidence_data.get("comparisons", [])) != len(comparisons or []):
                    errors.append("Jumlah evidence.comparisons tidak sama dengan artifact.comparisons.")
            except Exception as exc:
                errors.append(f"Evidence JSON tidak valid: {exc}")

    if errors:
        print("[FAIL] Default Virtual Host gagal validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        raise typer.Exit(code=1)

    print("[PASS] Default Virtual Host memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {block.get('status')}")
    print(f"[PASS] Target    : {block.get('hostname')}")
    print(f"[PASS] Probes    : {summary.get('probes', 0)}")
    print(f"[PASS] Compare   : {summary.get('comparisons', 0)}")
    print(f"[PASS] Equivalent: {summary.get('equivalent_responses', 0)}")
    print(f"[PASS] Rejected  : {summary.get('host_rejected_or_separated', 0)}")
    print(f"[PASS] Different : {summary.get('different_responses', 0)}")
    print(f"[PASS] CVE       : {cve.get('candidate_count', 0)} candidate(s)")
    print(f"[PASS] Review    : {summary.get('requires_review', 0)}")
    print("[PASS] CVE Triage: host/default candidates are evidence; no automatic finding.")
    print("[PASS] Assessment: default virtual-host behavior is recorded for review; no automatic vulnerability finding.")


if __name__ == "__main__":
    try:
        app()
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"[FAIL] {exc}")
        raise SystemExit(1)
