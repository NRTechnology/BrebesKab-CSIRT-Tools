#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Recon Summary

Phase : 02 Reconnaissance
Item  : 02-007 Recon Summary
Version: 1.0.0

Purpose:
    Consolidate the completed reconnaissance results into one summary
    document for the current pentest project.

Design:
    - "init" creates the summary document structure.
    - "generate" reads the completed reconnaissance documents and
      updates summary.yaml.
    - No network requests are performed by this module.
    - No vulnerability testing is performed.
    - No credentials, tokens, cookie values, or response bodies are stored.
    - Existing reconnaissance documents remain the source of truth.
    - The summary is an aggregation layer, not a replacement for evidence.

Input documents:
    02-reconnaissance/target/target.yaml
    02-reconnaissance/dns/dns.yaml
    02-reconnaissance/network/network.yaml
    02-reconnaissance/technology/technology.yaml
    02-reconnaissance/http/http.yaml
    02-reconnaissance/endpoint/endpoint.yaml

Output:
    02-reconnaissance/summary/summary.yaml
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# Prevent scripts/reconnaissance/http.py from shadowing Python's stdlib http.
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent
script_dir_string = str(SCRIPT_DIR)

sys.path[:] = [
    entry for entry in sys.path
    if entry != script_dir_string
]

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

import yaml

from activity import record_activity
from context import require_active_project


VERSION = "1.0.0"

RECON_DIR_NAME = "02-reconnaissance"
SUMMARY_DIR_NAME = "summary"
SUMMARY_FILE_NAME = "summary.yaml"

RECON_DOCUMENTS = {
    "target": ("target", "target.yaml"),
    "dns": ("dns", "dns.yaml"),
    "network": ("network", "network.yaml"),
    "technology": ("technology", "technology.yaml"),
    "http": ("http", "http.yaml"),
    "endpoint": ("endpoint", "endpoint.yaml"),
}

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
}

REQUIRED_MODULES = (
    "target",
    "dns",
    "network",
    "technology",
    "http",
    "endpoint",
)


def now_iso() -> str:
    jakarta = timezone(timedelta(hours=7))
    return datetime.now(jakarta).isoformat(timespec="seconds")


def project_context():
    return require_active_project()


def recon_root() -> Path:
    return project_context().project_path / RECON_DIR_NAME


def summary_file() -> Path:
    return recon_root() / SUMMARY_DIR_NAME / SUMMARY_FILE_NAME


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {path}")

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Format YAML tidak valid: {path}")

    return data


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(
            data,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def document_path(name: str) -> Path:
    if name not in RECON_DOCUMENTS:
        raise ValueError(f"Dokumen reconnaissance tidak dikenal: {name}")

    directory, filename = RECON_DOCUMENTS[name]
    return recon_root() / directory / filename


def load_recon_document(name: str) -> dict[str, Any]:
    return load_yaml(document_path(name))


def module_status(name: str, data: dict[str, Any]) -> str:
    """
    Return the module lifecycle status.

    Recon documents use two conventions:
        target.yaml / dns.yaml / network.yaml / technology.yaml
            <module>:
              status: ...

        http.yaml / endpoint.yaml
            status: ...

    This helper supports both so the summary module remains compatible
    with the existing reconnaissance documents.
    """
    nested = data.get(name)

    if isinstance(nested, dict):
        status = nested.get("status")
        if isinstance(status, str):
            return status.strip().lower()

    status = data.get("status")
    if isinstance(status, str):
        return status.strip().lower()

    return ""


def require_project_id(data: dict[str, Any], name: str) -> None:
    ctx = project_context()
    project_id = str(data.get("project_id", "")).strip()

    if project_id != ctx.project_id:
        raise RuntimeError(
            f"Project ID pada {name}.yaml tidak sesuai active project. "
            f"Context: {ctx.project_id}; File: {project_id or '-'}"
        )


def validate_source_documents(
    documents: dict[str, dict[str, Any]],
) -> dict[str, str]:
    statuses: dict[str, str] = {}

    for name, data in documents.items():
        require_project_id(data, name)

        status = module_status(name, data)
        statuses[name] = status

        if status not in VALID_STATUSES:
            raise RuntimeError(
                f"Status {name} reconnaissance tidak valid: "
                f"{status or '-'}"
            )

    return statuses


def require_completed_sources(
    documents: dict[str, dict[str, Any]],
    statuses: dict[str, str],
) -> None:
    incomplete = [
        name
        for name in REQUIRED_MODULES
        if statuses.get(name) != "completed"
    ]

    if incomplete:
        raise RuntimeError(
            "Reconnaissance belum lengkap. Modul yang belum completed: "
            + ", ".join(incomplete)
        )


def get_module_payload(
    name: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """
    Return the useful module mapping without mutating the source document.

    Most modules store their state under a top-level module key. HTTP and
    endpoint currently keep their state at the document root.
    """
    nested = data.get(name)

    if isinstance(nested, dict):
        return nested

    return data


def count_open_ports(network: dict[str, Any]) -> int:
    payload = get_module_payload("network", network)

    ports = payload.get("ports")
    if isinstance(ports, list):
        return len(ports)

    open_ports = payload.get("open_ports")
    if isinstance(open_ports, list):
        return len(open_ports)

    return 0


def count_endpoint_types(endpoint: dict[str, Any]) -> dict[str, int]:
    payload = get_module_payload("endpoint", endpoint)

    endpoints = payload.get("endpoints")
    if not isinstance(endpoints, list):
        return {
            "total": 0,
            "same_host": 0,
            "external": 0,
        }

    same_host = 0
    external = 0

    for item in endpoints:
        if not isinstance(item, dict):
            continue

        if item.get("same_host") is True:
            same_host += 1
        elif item.get("same_host") is False:
            external += 1

    return {
        "total": len(endpoints),
        "same_host": same_host,
        "external": external,
    }


def technology_names(technology: dict[str, Any]) -> list[str]:
    payload = get_module_payload("technology", technology)

    items = payload.get("technologies")
    if not isinstance(items, list):
        items = payload.get("technology")

    if not isinstance(items, list):
        return []

    names: list[str] = []

    for item in items:
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
        else:
            name = str(item).strip()

        if name and name not in names:
            names.append(name)

    return names


def build_summary(
    documents: dict[str, dict[str, Any]],
    statuses: dict[str, str],
) -> dict[str, Any]:
    ctx = project_context()

    target = get_module_payload("target", documents["target"])
    dns = get_module_payload("dns", documents["dns"])
    network = get_module_payload("network", documents["network"])
    technology = get_module_payload("technology", documents["technology"])
    http = get_module_payload("http", documents["http"])
    endpoint = get_module_payload("endpoint", documents["endpoint"])

    endpoint_counts = count_endpoint_types(endpoint)

    http_data = http.get("http")
    https_data = http.get("https")
    comparison = http.get("comparison")

    if not isinstance(http_data, dict):
        http_data = {}

    if not isinstance(https_data, dict):
        https_data = {}

    if not isinstance(comparison, dict):
        comparison = {}

    ipv4 = dns.get("ipv4")
    ipv6 = dns.get("ipv6")

    if isinstance(ipv4, list):
        ipv4_list = [str(value) for value in ipv4 if str(value).strip()]
    elif isinstance(ipv4, str) and ipv4.strip():
        ipv4_list = [ipv4.strip()]
    else:
        ipv4_list = []

    if isinstance(ipv6, list):
        ipv6_list = [str(value) for value in ipv6 if str(value).strip()]
    elif isinstance(ipv6, str) and ipv6.strip():
        ipv6_list = [ipv6.strip()]
    else:
        ipv6_list = []

    return {
        "schema_version": "1.0",
        "project_id": ctx.project_id,
        "status": "in-progress",
        "application": str(
            target.get("application")
            or technology.get("application")
            or ""
        ).strip(),
        "target_url": str(
            target.get("target_url")
            or technology.get("target_url")
            or ""
        ).strip(),
        "hostname": str(
            target.get("hostname")
            or technology.get("hostname")
            or ""
        ).strip(),
        "environment": str(
            target.get("environment")
            or technology.get("environment")
            or ""
        ).strip(),
        "assessment_type": str(
            target.get("assessment_type")
            or technology.get("assessment_type")
            or ""
        ).strip(),
        "scope_reference": str(
            target.get("scope_reference")
            or technology.get("scope_reference")
            or ""
        ).strip(),
        "reconnaissance": {
            "target_identification": {
                "status": statuses["target"],
                "target_url": target.get("target_url", ""),
                "hostname": target.get("hostname", ""),
                "scheme": target.get("scheme", ""),
                "port": target.get("port", ""),
            },
            "dns": {
                "status": statuses["dns"],
                "hostname": dns.get("hostname", ""),
                "ipv4": ipv4_list,
                "ipv6": ipv6_list,
            },
            "network": {
                "status": statuses["network"],
                "target": network.get("target", ""),
                "open_ports": count_open_ports(network),
                "ports": network.get("ports", []),
            },
            "technology": {
                "status": statuses["technology"],
                "server": (
                    technology.get("http", {}).get("server", "")
                    if isinstance(technology.get("http"), dict)
                    else ""
                ),
                "powered_by": (
                    technology.get("http", {}).get("powered_by", "")
                    if isinstance(technology.get("http"), dict)
                    else ""
                ),
                "technologies": technology_names(technology),
            },
            "http": {
                "status": statuses["http"],
                "http_status": http_data.get("status_code"),
                "http_final_url": http_data.get("final_url", ""),
                "https_status": https_data.get("status_code"),
                "https_final_url": https_data.get("final_url", ""),
                "http_to_https_redirect": comparison.get(
                    "http_to_https_redirect"
                ),
                "https_available": comparison.get("https_available"),
                "tls_version": (
                    https_data.get("tls", {}).get("tls_version", "")
                    if isinstance(https_data.get("tls"), dict)
                    else ""
                ),
                "certificate_verified": (
                    https_data.get("tls", {}).get("certificate_verified")
                    if isinstance(https_data.get("tls"), dict)
                    else None
                ),
            },
            "endpoint": {
                "status": statuses["endpoint"],
                "total": endpoint_counts["total"],
                "same_host": endpoint_counts["same_host"],
                "external": endpoint_counts["external"],
                "html_links": (
                    endpoint.get("summary", {}).get("html_links", 0)
                    if isinstance(endpoint.get("summary"), dict)
                    else 0
                ),
                "forms": (
                    endpoint.get("summary", {}).get("forms", 0)
                    if isinstance(endpoint.get("summary"), dict)
                    else 0
                ),
                "javascript": (
                    endpoint.get("summary", {}).get("javascript", 0)
                    if isinstance(endpoint.get("summary"), dict)
                    else 0
                ),
                "robots": (
                    endpoint.get("summary", {}).get("robots", 0)
                    if isinstance(endpoint.get("summary"), dict)
                    else 0
                ),
                "sitemap": (
                    endpoint.get("summary", {}).get("sitemap", 0)
                    if isinstance(endpoint.get("summary"), dict)
                    else 0
                ),
            },
        },
        "recon_status": {
            "target": statuses["target"],
            "dns": statuses["dns"],
            "network": statuses["network"],
            "technology": statuses["technology"],
            "http": statuses["http"],
            "endpoint": statuses["endpoint"],
        },
        "observations": [],
        "notes": "",
        "generated_at": now_iso(),
    }


def add_observation(
    summary: dict[str, Any],
    observation_id: str,
    title: str,
    source: str,
    detail: str,
    classification: str = "observation",
) -> None:
    observations = summary.setdefault("observations", [])

    observations.append(
        {
            "id": observation_id,
            "classification": classification,
            "title": title,
            "source": source,
            "detail": detail,
        }
    )


def build_observations(
    summary: dict[str, Any],
    documents: dict[str, dict[str, Any]],
) -> None:
    http = get_module_payload("http", documents["http"])
    endpoint = get_module_payload("endpoint", documents["endpoint"])
    technology = get_module_payload("technology", documents["technology"])

    comparison = http.get("comparison")
    if isinstance(comparison, dict):
        if comparison.get("http_to_https_redirect") is False:
            add_observation(
                summary,
                "OBS-001",
                "HTTP does not redirect to HTTPS",
                "02-005 HTTP / HTTPS reconnaissance",
                "HTTP returned a response without redirecting to the HTTPS target.",
            )

    server = ""
    powered_by = ""

    http_section = technology.get("http")
    if isinstance(http_section, dict):
        server = str(http_section.get("server", "")).strip()
        powered_by = str(http_section.get("powered_by", "")).strip()

    if server:
        add_observation(
            summary,
            "OBS-002",
            "Web server information exposed",
            "02-004 Technology Identification",
            f"Server header observed: {server}",
        )

    if powered_by:
        add_observation(
            summary,
            "OBS-003",
            "Runtime information exposed",
            "02-004 Technology Identification",
            f"X-Powered-By observed: {powered_by}",
        )

    technologies = technology.get("technologies")
    if isinstance(technologies, list):
        for item in technologies:
            if not isinstance(item, dict):
                continue

            name = str(item.get("name", "")).strip()
            detail = str(item.get("detail", "")).strip()

            if name == "CodeIgniter 4":
                add_observation(
                    summary,
                    "OBS-004",
                    "CodeIgniter 4 indicated by reconnaissance",
                    "02-004 Technology Identification / 02-006 Endpoint Discovery",
                    detail or "CodeIgniter 4 indication observed.",
                )

    endpoints = endpoint.get("endpoints")
    if isinstance(endpoints, list):
        chat_paths = sorted(
            {
                str(item.get("url", "")).strip()
                for item in endpoints
                if isinstance(item, dict)
                and "/webapp/chat/" in str(item.get("url", ""))
            }
        )

        if chat_paths:
            add_observation(
                summary,
                "OBS-005",
                "Chat-related application endpoints discovered",
                "02-006 Endpoint Discovery",
                f"{len(chat_paths)} same-host chat endpoint(s) discovered.",
            )


def cmd_init() -> int:
    ctx = project_context()
    path = summary_file()

    if path.exists():
        raise RuntimeError(
            f"Summary sudah ada: {path}\n"
            "Gunakan 'generate' untuk memperbarui hasil summary."
        )

    data = {
        "schema_version": "1.0",
        "project_id": ctx.project_id,
        "status": "not-started",
        "application": "",
        "target_url": "",
        "hostname": "",
        "environment": "",
        "assessment_type": "",
        "scope_reference": "",
        "reconnaissance": {},
        "recon_status": {},
        "observations": [],
        "notes": "",
        "generated_at": "",
    }

    save_yaml(path, data)

    print("[PASS] Recon Summary berhasil diinisialisasi.")
    print(f"PROJECT: {ctx.project_id}")
    print(f"FILE   : {path}")

    return 0


def cmd_generate() -> int:
    ctx = project_context()

    documents = {
        name: load_recon_document(name)
        for name in RECON_DOCUMENTS
    }

    statuses = validate_source_documents(documents)
    require_completed_sources(documents, statuses)

    summary = build_summary(documents, statuses)
    build_observations(summary, documents)

    save_yaml(summary_file(), summary)

    record_activity(
        phase="02-reconnaissance",
        item="02-007",
        action="Reconnaissance summary generated",
        status="in-progress",
    )

    print("[PASS] Recon Summary berhasil dibuat.")
    print(f"PROJECT: {ctx.project_id}")
    print(f"FILE   : {summary_file()}")
    print("STATUS : in-progress")
    print("SOURCES: target, dns, network, technology, http, endpoint")

    return 0


def cmd_show() -> int:
    ctx = project_context()
    path = summary_file()

    data = load_yaml(path)

    print(f"PROJECT: {ctx.project_id}")
    print(f"FILE   : {path}")
    print()
    print(yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    ).rstrip())

    return 0


def validate_summary(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    ctx = project_context()

    if str(data.get("project_id", "")).strip() != ctx.project_id:
        errors.append("Project ID tidak sesuai active project.")

    status = str(data.get("status", "")).strip().lower()
    if status not in VALID_STATUSES:
        errors.append("Status summary tidak valid.")

    required_top_level = (
        "application",
        "target_url",
        "hostname",
        "environment",
        "assessment_type",
        "scope_reference",
        "reconnaissance",
        "recon_status",
    )

    for field in required_top_level:
        if field not in data:
            errors.append(f"Field wajib tidak ditemukan: {field}")

    recon_status = data.get("recon_status")
    if not isinstance(recon_status, dict):
        errors.append("Field recon_status tidak valid.")
    else:
        incomplete = [
            name
            for name in REQUIRED_MODULES
            if str(recon_status.get(name, "")).strip().lower()
            != "completed"
        ]

        if incomplete:
            errors.append(
                "Reconnaissance belum completed: "
                + ", ".join(incomplete)
            )

    reconnaissance = data.get("reconnaissance")
    if not isinstance(reconnaissance, dict):
        errors.append("Field reconnaissance tidak valid.")

    return errors


def cmd_verify() -> int:
    ctx = project_context()
    path = summary_file()

    data = load_yaml(path)
    errors = validate_summary(data)

    if errors:
        print("[FAIL] Recon Summary belum memenuhi validasi.")
        for error in errors:
            print(f"  - {error}")
        return 1

    data["status"] = "completed"
    data["verified_at"] = now_iso()
    save_yaml(path, data)

    record_activity(
        phase="02-reconnaissance",
        item="02-007",
        action="Reconnaissance summary verified",
        status="completed",
    )

    print("[PASS] Recon Summary memenuhi validasi.")
    print("[PASS] Status: completed")
    print(f"PROJECT: {ctx.project_id}")

    return 0


def cmd_status() -> int:
    ctx = project_context()
    path = summary_file()

    if not path.exists():
        print(f"Project ID : {ctx.project_id}")
        print("Status     : not-initialized")
        return 0

    data = load_yaml(path)
    status = str(data.get("status", "unknown")).strip().lower()

    print(f"Project ID : {ctx.project_id}")
    print(f"Status     : {status}")

    return 0


def cmd_remove() -> int:
    ctx = project_context()
    path = summary_file()

    if not path.exists():
        print("[INFO] Recon Summary belum ada.")
        return 0

    path.unlink()

    print("[PASS] Recon Summary berhasil dihapus.")
    print(f"PROJECT: {ctx.project_id}")
    print(f"FILE   : {path}")

    return 0


def cmd_list() -> int:
    ctx = project_context()
    path = summary_file()

    if not path.exists():
        print(f"Project ID : {ctx.project_id}")
        print("Summary    : belum tersedia")
        return 0

    data = load_yaml(path)
    observations = data.get("observations", [])

    print(f"PROJECT      : {ctx.project_id}")
    print(f"STATUS       : {data.get('status', '-')}")
    print(f"OBSERVATIONS : {len(observations) if isinstance(observations, list) else 0}")

    if isinstance(observations, list):
        for item in observations:
            if not isinstance(item, dict):
                continue

            print(
                f"  [{item.get('id', '-')}] "
                f"{item.get('title', '-')}"
            )

    return 0


def print_help() -> None:
    print(
        f"""BrebesKab-CSIRT-Tools
Reconnaissance Summary v{VERSION}

Usage:
  python scripts/reconnaissance/summary.py init
  python scripts/reconnaissance/summary.py generate
  python scripts/reconnaissance/summary.py list
  python scripts/reconnaissance/summary.py show
  python scripts/reconnaissance/summary.py verify
  python scripts/reconnaissance/summary.py status
  python scripts/reconnaissance/summary.py remove
  python scripts/reconnaissance/summary.py version

The active project is resolved automatically through context.py.
No --project argument is required.

init      Create summary.yaml.
generate  Aggregate completed reconnaissance documents.
list      Show summary status and observations.
show      Show the complete summary document.
verify    Validate the summary and mark completed.
status    Show the current lifecycle status.
remove    Remove summary.yaml.
version   Show the script version.

Source documents:
  - target.yaml
  - dns.yaml
  - network.yaml
  - technology.yaml
  - http.yaml
  - endpoint.yaml

This module does not perform network requests or vulnerability testing.
"""
    )


def main() -> int:
    if len(sys.argv) < 2:
        print_help()
        return 0

    command = sys.argv[1].strip().lower()

    try:
        if command == "init":
            return cmd_init()

        if command == "generate":
            return cmd_generate()

        if command == "list":
            return cmd_list()

        if command == "show":
            return cmd_show()

        if command == "verify":
            return cmd_verify()

        if command == "status":
            return cmd_status()

        if command == "remove":
            return cmd_remove()

        if command == "version":
            print(f"Reconnaissance Summary v{VERSION}")
            return 0

        if command in {"--help", "-h", "help"}:
            print_help()
            return 0

        print(f"[FAIL] Perintah tidak dikenal: {command}")
        print()
        print_help()
        return 1

    except Exception as exc:
        print(f"[FAIL] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
