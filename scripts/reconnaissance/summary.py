#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Recon Summary

Phase : 02 Reconnaissance
Item  : Recon Summary
Version: 1.1.1

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


VERSION = "1.1.2"

RECON_DIR_NAME = "02-reconnaissance"
SUMMARY_DIR_NAME = "summary"
SUMMARY_FILE_NAME = "summary.yaml"

RECON_DOCUMENTS = {
    "target": ("target", "target.yaml"),
    "dns": ("dns", "dns.yaml"),
    "network": ("network", "network.yaml"),
    "technology": ("technology", "technology.yaml"),
    "http": ("http", "http.yaml"),
    "subdomain": ("subdomain", "subdomain.yaml"),
    "endpoint": ("endpoint", "endpoint.yaml"),
    "directory": ("directory", "directory.yaml"),
    "api": ("api", "api.yaml"),
    "attack": ("attack", "attack.yaml"),
}

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "partial",
    "completed",
    "skipped",
    "failed",
    "blocked",
}

# Lifecycle policy used by generate():
#   completed   -> include
#   partial     -> ask: include or skip
#   skipped     -> skip automatically
#   not-started -> generation is prohibited
#   in-progress -> ask: generate and skip / cancel
#   failed      -> ask: generate and skip / cancel
#   blocked     -> ask: generate and skip / cancel


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
    included_modules: set[str],
) -> dict[str, Any]:
    ctx = project_context()

    target = get_module_payload("target", documents["target"])
    dns = get_module_payload("dns", documents["dns"])
    network = get_module_payload("network", documents["network"])
    technology = get_module_payload("technology", documents["technology"])
    http = get_module_payload("http", documents["http"])
    endpoint = get_module_payload("endpoint", documents["endpoint"])

    endpoint_counts = count_endpoint_types(endpoint) if "endpoint" in included_modules else {
        "total": 0,
        "same_host": 0,
        "external": 0,
    }

    http_data = http.get("http") if "http" in included_modules else {}
    https_data = http.get("https") if "http" in included_modules else {}
    comparison = http.get("comparison") if "http" in included_modules else {}

    if not isinstance(http_data, dict):
        http_data = {}
    if not isinstance(https_data, dict):
        https_data = {}
    if not isinstance(comparison, dict):
        comparison = {}

    ipv4 = dns.get("ipv4") if "dns" in included_modules else []
    ipv6 = dns.get("ipv6") if "dns" in included_modules else []

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

    def payload(name: str) -> dict[str, Any]:
        return get_module_payload(name, documents[name]) if name in included_modules else {}

    summary = {
        "schema_version": "1.1",
        "project_id": ctx.project_id,
        "status": "in-progress",
        "application": str(
            target.get("application") or technology.get("application") or ""
        ).strip(),
        "target_url": str(
            target.get("target_url") or technology.get("target_url") or ""
        ).strip(),
        "hostname": str(
            target.get("hostname") or technology.get("hostname") or ""
        ).strip(),
        "environment": str(
            target.get("environment") or technology.get("environment") or ""
        ).strip(),
        "assessment_type": str(
            target.get("assessment_type") or technology.get("assessment_type") or ""
        ).strip(),
        "scope_reference": str(
            target.get("scope_reference") or technology.get("scope_reference") or ""
        ).strip(),
        "reconnaissance": {},
        "recon_status": dict(statuses),
        "module_decisions": {},
        "observations": [],
        "notes": "",
        "generated_at": now_iso(),
    }

    if "target" in included_modules:
        summary["reconnaissance"]["target_identification"] = {
            "status": statuses["target"],
            "target_url": target.get("target_url", ""),
            "hostname": target.get("hostname", ""),
            "scheme": target.get("scheme", ""),
            "port": target.get("port", ""),
        }

    if "dns" in included_modules:
        summary["reconnaissance"]["dns"] = {
            "status": statuses["dns"],
            "hostname": dns.get("hostname", ""),
            "ipv4": ipv4_list,
            "ipv6": ipv6_list,
        }

    if "network" in included_modules:
        summary["reconnaissance"]["network"] = {
            "status": statuses["network"],
            "target": network.get("target", ""),
            "open_ports": count_open_ports(network),
            "ports": network.get("ports", []),
        }

    if "technology" in included_modules:
        technology_payload = technology
        summary["reconnaissance"]["technology"] = {
            "status": statuses["technology"],
            "server": (
                technology_payload.get("http", {}).get("server", "")
                if isinstance(technology_payload.get("http"), dict)
                else ""
            ),
            "powered_by": (
                technology_payload.get("http", {}).get("powered_by", "")
                if isinstance(technology_payload.get("http"), dict)
                else ""
            ),
            "technologies": technology_names(technology_payload),
        }

    if "http" in included_modules:
        summary["reconnaissance"]["http"] = {
            "status": statuses["http"],
            "http_status": http_data.get("status_code"),
            "http_final_url": http_data.get("final_url", ""),
            "https_status": https_data.get("status_code"),
            "https_final_url": https_data.get("final_url", ""),
            "http_to_https_redirect": comparison.get("http_to_https_redirect"),
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
        }

    if "subdomain" in included_modules:
        subdomain = payload("subdomain")
        summary["reconnaissance"]["subdomain"] = {
            "status": statuses["subdomain"],
            "candidate_count": (
                subdomain.get("summary", {}).get("candidates_total", 0)
                if isinstance(subdomain.get("summary"), dict)
                else 0
            ),
            "resolved_count": (
                subdomain.get("summary", {}).get("resolved_total", 0)
                if isinstance(subdomain.get("summary"), dict)
                else 0
            ),
            "unresolved_count": (
                subdomain.get("summary", {}).get("unresolved_total", 0)
                if isinstance(subdomain.get("summary"), dict)
                else 0
            ),
        }

    if "endpoint" in included_modules:
        endpoint_payload = endpoint
        endpoint_summary = (
            endpoint_payload.get("summary", {})
            if isinstance(endpoint_payload.get("summary"), dict)
            else {}
        )
        summary["reconnaissance"]["endpoint"] = {
            "status": statuses["endpoint"],
            "total": endpoint_counts["total"],
            "same_host": endpoint_counts["same_host"],
            "external": endpoint_counts["external"],
            "html_links": endpoint_summary.get("html_links", 0),
            "forms": endpoint_summary.get("forms", 0),
            "javascript": endpoint_summary.get("javascript", 0),
            "robots": endpoint_summary.get("robots", 0),
            "sitemap": endpoint_summary.get("sitemap", 0),
        }

    if "directory" in included_modules:
        directory = payload("directory")
        directory_summary = (
            directory.get("summary", {})
            if isinstance(directory.get("summary"), dict)
            else {}
        )

        # directory.py uses:
        #   summary.total
        #   summary.interesting
        #   summary.possible_false_positive
        # There is no summary.found field.
        directory_results = (
            directory.get("results")
            if isinstance(directory.get("results"), list)
            else []
        )
        directory_total = directory_summary.get(
            "total",
            len(directory_results),
        )

        summary["reconnaissance"]["directory"] = {
            "status": statuses["directory"],
            "found": int(directory_total or 0),
            "interesting": int(
                directory_summary.get("interesting", 0) or 0
            ),
            "possible_false_positive": int(
                directory_summary.get("possible_false_positive", 0) or 0
            ),
        }

    if "api" in included_modules:
        api = payload("api")
        api_summary = (
            api.get("summary", {})
            if isinstance(api.get("summary"), dict)
            else {}
        )

        # api.py v1.1.3 deliberately keeps baseline probe targets
        # separate from API classification. Therefore probe counts are
        # derived from the actual probe_targets/probes evidence rather
        # than treating summary.candidate_count as probe_targets.
        probe_targets = (
            api.get("probe_targets")
            if isinstance(api.get("probe_targets"), list)
            else []
        )
        probes = (
            api.get("probes")
            if isinstance(api.get("probes"), list)
            else []
        )

        probe_not_found = sum(
            1
            for item in probes
            if isinstance(item, dict)
            and (
                str(item.get("probe_classification", "")).lower()
                == "not-found"
                or item.get("status_code") == 404
            )
        )

        summary["reconnaissance"]["api"] = {
            "status": statuses["api"],
            "api_candidates": int(
                api_summary.get("api_candidate_count", 0) or 0
            ),
            "possible_api": int(
                api_summary.get("possible_api_count", 0) or 0
            ),
            "non_api": int(
                api_summary.get("non_api_count", 0) or 0
            ),
            "unknown": int(
                api_summary.get("unknown_count", 0) or 0
            ),
            "probe_targets": len(probe_targets),
            "probed": len(probes),
            "probe_not_found": probe_not_found,
        }

    if "attack" in included_modules:
        attack = payload("attack")
        attack_summary = (
            attack.get("summary", {})
            if isinstance(attack.get("summary"), dict)
            else {}
        )
        summary["reconnaissance"]["attack_surface"] = {
            "status": statuses["attack"],
            "ipv4_count": attack_summary.get("ipv4_count", 0),
            "ipv6_count": attack_summary.get("ipv6_count", 0),
            "open_port_count": attack_summary.get("open_port_count", 0),
            "technology_count": attack_summary.get("technology_count", 0),
            "subdomain_candidate_count": attack_summary.get(
                "subdomain_candidate_count", 0
            ),
            "endpoint_count": attack_summary.get("endpoint_count", 0),
            "same_host_endpoint_count": attack_summary.get(
                "same_host_endpoint_count", 0
            ),
            "directory_count": attack_summary.get("directory_count", 0),
            "api_candidate_count": attack_summary.get("api_candidate_count", 0),
            "possible_api_count": attack_summary.get("possible_api_count", 0),
        }

    for name, status in statuses.items():
        summary["module_decisions"][name] = (
            "included" if name in included_modules else "skipped"
        )

    return summary


def prompt_module_decisions(statuses: dict[str, str]) -> set[str]:
    """Apply the agreed summary generation lifecycle policy."""
    not_started = [
        name for name, status in statuses.items() if status == "not-started"
    ]
    if not_started:
        print("[FAIL] Reconnaissance memiliki module berstatus not-started:")
        for name in not_started:
            print(f"  - {name}")
        print("Summary tidak dapat di-generate sampai module tersebut dimulai.")
        raise RuntimeError("Terdapat reconnaissance berstatus not-started.")

    included: set[str] = set()

    for name, status in statuses.items():
        if status == "completed":
            included.add(name)
            continue

        if status == "skipped":
            print(f"[INFO] {name} dilewati otomatis (status: skipped).")
            continue

        if status == "partial":
            answer = input(
                f"[WARN] {name} berstatus partial. "
                "Include module ini dalam summary? [Y/n]: "
            ).strip().lower()
            if answer in {"", "y", "yes"}:
                included.add(name)
                print(f"[INFO] {name} akan di-include.")
            else:
                print(f"[INFO] {name} akan di-skip.")
            continue

        if status in {"in-progress", "failed", "blocked"}:
            answer = input(
                f"[WARN] {name} berstatus {status}. "
                "Lanjut generate dan skip module ini? [y/N]: "
            ).strip().lower()
            if answer in {"y", "yes"}:
                print(f"[INFO] {name} akan di-skip.")
                continue

            print("[INFO] Generate dibatalkan.")
            raise RuntimeError("Generate summary dibatalkan oleh user.")

        raise RuntimeError(
            f"Status {name} tidak memiliki policy generate: {status or '-'}"
        )

    return included

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
    http = get_module_payload("http", documents["http"]) if "http" in documents else {}
    endpoint = get_module_payload("endpoint", documents["endpoint"]) if "endpoint" in documents else {}
    technology = get_module_payload("technology", documents["technology"]) if "technology" in documents else {}

    comparison = http.get("comparison")
    if isinstance(comparison, dict):
        if comparison.get("http_to_https_redirect") is False:
            add_observation(
                summary,
                "OBS-001",
                "HTTP does not redirect to HTTPS",
                "3-006 HTTP configuration",
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
            "2-003 Technology fingerprinting",
            f"Server header observed: {server}",
        )

    if powered_by:
        add_observation(
            summary,
            "OBS-003",
            "Runtime information exposed",
            "2-003 Technology fingerprinting",
            f"X-Powered-By observed: {powered_by}",
        )

    technologies = technology.get("technologies")
    if isinstance(technologies, list):
        for item in technologies:
            if not isinstance(item, dict):
                continue

            name = str(item.get("name", "")).strip()
            detail = str(item.get("detail", "")).strip()

            if name == "CodeIgniter":
                add_observation(
                    summary,
                    "OBS-004",
                    "CodeIgniter indicated by reconnaissance",
                    "2-003 Technology fingerprinting",
                    detail or "CodeIgniter indication observed.",
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
                "2-005 Endpoint discovery",
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
        "schema_version": "1.1",
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
    included_modules = prompt_module_decisions(statuses)

    summary = build_summary(documents, statuses, included_modules)
    build_observations(
        summary,
        {name: documents[name] for name in included_modules},
    )

    # A successfully generated Summary is a completed artifact.
    # Verification is a separate lifecycle step and may add verified_at later.
    summary["status"] = "completed"

    save_yaml(summary_file(), summary)

    record_activity(
        phase="02-reconnaissance",
        item="recon-summary",
        action="Reconnaissance summary generated",
        status="completed",
    )

    skipped = [
        name for name in statuses if name not in included_modules
    ]

    print("[PASS] Recon Summary berhasil dibuat.")
    print(f"PROJECT: {ctx.project_id}")
    print(f"FILE   : {summary_file()}")
    print("STATUS : completed")
    print(
        "INCLUDED: "
        + (", ".join(name for name in statuses if name in included_modules) or "-")
    )
    print(
        "SKIPPED : "
        + (", ".join(skipped) or "-")
    )

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
    if status not in {"not-started", "in-progress", "completed"}:
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
        "module_decisions",
    )

    for field in required_top_level:
        if field not in data:
            errors.append(f"Field wajib tidak ditemukan: {field}")

    recon_status = data.get("recon_status")
    if not isinstance(recon_status, dict):
        errors.append("Field recon_status tidak valid.")
    else:
        for name, source_status in recon_status.items():
            if name not in RECON_DOCUMENTS:
                errors.append(f"Module reconnaissance tidak dikenal: {name}")
            elif str(source_status).strip().lower() not in VALID_STATUSES:
                errors.append(
                    f"Status {name} tidak valid: {source_status!r}"
                )

    decisions = data.get("module_decisions")
    if not isinstance(decisions, dict):
        errors.append("Field module_decisions tidak valid.")
    else:
        for name, source_status in (recon_status or {}).items():
            decision = decisions.get(name)
            if decision not in {"included", "skipped"}:
                errors.append(
                    f"Decision {name} harus 'included' atau 'skipped'."
                )

            if source_status == "completed" and decision != "included":
                errors.append(
                    f"Module completed harus included: {name}."
                )

            if source_status == "not-started":
                errors.append(
                    f"Summary tidak boleh memuat module not-started: {name}."
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
        item="recon-summary",
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
generate  Aggregate reconnaissance documents using the lifecycle policy.
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
  - subdomain.yaml
  - endpoint.yaml
  - directory.yaml
  - api.yaml
  - attack.yaml

Generate policy:
  completed   -> include
  partial     -> ask user: include or skip
  skipped     -> skip automatically
  not-started -> generation is prohibited
  in-progress -> ask user: generate and skip or cancel
  failed      -> ask user: generate and skip or cancel
  blocked     -> ask user: generate and skip or cancel

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
