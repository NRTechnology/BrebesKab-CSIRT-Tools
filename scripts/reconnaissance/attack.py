#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Attack Surface Mapping

Version: 1.0.0
Checklist: 2-008 - Attack surface mapping

Attack Surface Mapping aggregates completed reconnaissance results into a
single evidence-based attack surface view.

This module does NOT perform new network or application scanning.
It reads existing reconnaissance artifacts only.

Inputs:
    02-reconnaissance/target/target.yaml
    02-reconnaissance/dns/dns.yaml
    02-reconnaissance/network/network.yaml
    02-reconnaissance/technology/technology.yaml
    02-reconnaissance/subdomain/subdomain.yaml
    02-reconnaissance/endpoint/endpoint.yaml
    02-reconnaissance/directory/directory.yaml
    02-reconnaissance/api/api.yaml

Output:
    02-reconnaissance/attack/attack.yaml

Important:
    Discovered assets are observations, not automatically authorized targets.
    Scope authorization remains defined by 01-preparation/scope/scope.yaml.
"""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path
from typing import Any

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

for _entry in (str(SCRIPT_DIR), str(SCRIPTS_DIR)):
    while _entry in sys.path:
        sys.path.remove(_entry)

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

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


SCRIPT_VERSION = "1.0.2"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "2-008"
CHECKLIST_NAME = "Attack surface mapping"

RECON_DIR_NAME = "02-reconnaissance"
OUTPUT_DIR_NAME = "attack"
OUTPUT_FILE_NAME = "attack.yaml"

SOURCE_FILES = {
    "target": ("target", "target.yaml"),
    "dns": ("dns", "dns.yaml"),
    "network": ("network", "network.yaml"),
    "technology": ("technology", "technology.yaml"),
    "subdomain": ("subdomain", "subdomain.yaml"),
    "endpoint": ("endpoint", "endpoint.yaml"),
    "directory": ("directory", "directory.yaml"),
    "api": ("api", "api.yaml"),
}


class AttackError(RuntimeError):
    """Raised when attack surface mapping cannot be completed safely."""


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def project_context() -> ProjectContext:
    return require_active_project()


def project_root() -> Path:
    return Path(project_context().project_path)


def recon_root() -> Path:
    return project_root() / RECON_DIR_NAME


def attack_dir() -> Path:
    return recon_root() / OUTPUT_DIR_NAME


def attack_file() -> Path:
    return attack_dir() / OUTPUT_FILE_NAME


def source_file(name: str) -> Path:
    directory, filename = SOURCE_FILES[name]
    return recon_root() / directory / filename


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise AttackError(f"{label} tidak ditemukan: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise AttackError(f"{label} YAML tidak valid: {exc}") from exc

    if not isinstance(data, dict):
        raise AttackError(f"{label} harus berupa mapping/object.")

    return data


def _save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        ),
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


def _load_source(name: str, required: bool = True) -> dict[str, Any] | None:
    path = source_file(name)

    if not path.exists():
        if required:
            raise AttackError(f"{name} reconnaissance tidak ditemukan: {path}")
        return None

    return _load_yaml(path, f"{name.capitalize()} reconnaissance")


def _validate_project_id(data: dict[str, Any], name: str) -> None:
    expected = project_root().name
    actual = str(data.get("project_id", ""))

    if actual != expected:
        raise AttackError(
            f"Project ID pada {name} tidak sesuai active project: "
            f"{actual!r} != {expected!r}"
        )


def _status(data: dict[str, Any], section: str) -> str:
    value = data.get(section)
    if isinstance(value, dict):
        return str(value.get("status", "")).lower()
    return ""


def _require_completed(
    name: str,
    data: dict[str, Any] | None,
    section: str,
) -> None:
    if data is None:
        raise AttackError(f"{name} reconnaissance tidak tersedia.")

    _validate_project_id(data, name)

    status = _status(data, section)

    if status != "completed":
        raise AttackError(
            f"{name} reconnaissance belum completed "
            f"(status={status or 'unknown'})."
        )


def _target_meta(target_data: dict[str, Any]) -> dict[str, str]:
    target = target_data.get("target")

    if not isinstance(target, dict):
        raise AttackError("Field 'target' pada target.yaml harus berupa mapping/object.")

    return {
        "application": str(target.get("application", "")),
        "target_url": str(target.get("target_url", "")),
        "hostname": str(target.get("hostname", "")),
        "environment": str(target.get("environment", "")),
        "assessment_type": str(target.get("assessment_type", "")),
        "scope_reference": str(target.get("scope_reference", "")),
    }


def _safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _collect_dns(data: dict[str, Any]) -> dict[str, Any]:
    dns = data.get("dns")
    if not isinstance(dns, dict):
        return {
            "hostname": "",
            "ipv4": [],
            "ipv6": [],
            "status": "unavailable",
        }

    return {
        "hostname": str(dns.get("hostname", "")),
        "ipv4": _safe_list(dns.get("ipv4")),
        "ipv6": _safe_list(dns.get("ipv6")),
        "status": str(dns.get("status", "")),
    }


def _collect_network(data: dict[str, Any]) -> dict[str, Any]:
    """
    Read the actual network.yaml schema.

    network.yaml stores IPv4/IPv6 and the discovered ports directly under
    network. It does not use a targets[].ports structure.
    """
    network = data.get("network")
    if not isinstance(network, dict):
        return {
            "ipv4": [],
            "ipv6": [],
            "network_ranges": [],
            "targets": [],
            "open_ports": [],
            "status": "unavailable",
            "port_scan": {},
        }

    ipv4 = _safe_list(network.get("ipv4"))
    ipv6 = _safe_list(network.get("ipv6"))
    network_ranges = _safe_list(network.get("network_ranges"))
    ports = _safe_list(network.get("ports"))

    open_ports: list[dict[str, Any]] = []

    for item in ports:
        if not isinstance(item, dict):
            continue

        state = str(item.get("state", "")).lower()

        # The source is already the controlled Nmap result. Preserve only
        # open ports in the attack-surface open_ports collection.
        if state == "open":
            open_ports.append(
                {
                    "port": item.get("port"),
                    "protocol": str(item.get("protocol", "tcp")),
                    "state": state,
                    "service": str(item.get("service", "")),
                }
            )

    targets = [
        {
            "address": str(address),
            "ports": open_ports,
        }
        for address in ipv4
    ]

    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "network_ranges": network_ranges,
        "targets": targets,
        "open_ports": open_ports,
        "status": str(network.get("status", "")),
        "port_scan": network.get("port_scan", {}),
    }



def _collect_technology(data: dict[str, Any]) -> dict[str, Any]:
    """
    Read technology.yaml's actual schema.

    Detected technologies are stored directly in technology.technologies.
    The category field in each item is preserved rather than inventing a
    different category structure.
    """
    technology = data.get("technology")
    if not isinstance(technology, dict):
        return {
            "technologies": [],
            "categories": {},
            "status": "unavailable",
        }

    source_items = _safe_list(technology.get("technologies"))
    technologies: list[dict[str, Any]] = []
    categories: dict[str, list[dict[str, Any]]] = {}

    for item in source_items:
        if not isinstance(item, dict):
            continue

        category = str(item.get("category", "")).strip() or "other"
        normalized = {
            "name": str(item.get("name", "")),
            "category": category,
            "version": str(item.get("version", "")),
            "confidence": str(item.get("confidence", "")),
            "detail": str(item.get("detail", "")),
            "sources": _safe_list(item.get("sources")),
        }

        technologies.append(normalized)
        categories.setdefault(category, []).append(normalized)

    return {
        "technologies": technologies,
        "categories": categories,
        "status": str(technology.get("status", "")),
    }



def _collect_subdomains(data: dict[str, Any]) -> dict[str, Any]:
    """
    Read subdomain.yaml's actual v1.3.1 schema.

    Candidates use ipv4/ipv6 and dns_classification. The source deliberately
    keeps all 22 DNS candidates as observations while marking them as
    possible wildcard/shared infrastructure and requiring scope verification.
    """
    subdomain = data.get("subdomain")
    if not isinstance(subdomain, dict):
        return {
            "candidates": [],
            "candidate_count": 0,
            "direct_dns_candidate_count": 0,
            "possible_shared_count": 0,
            "unresolved_count": 0,
            "resolved_count": 0,
            "status": "unavailable",
            "dns_environment": {},
        }

    candidates = _safe_list(subdomain.get("candidates"))
    normalized: list[dict[str, Any]] = []

    possible_shared = 0
    direct_dns = 0
    unresolved = 0
    resolved = 0

    for item in candidates:
        if not isinstance(item, dict):
            continue

        hostname = str(item.get("hostname", "")).strip()
        ipv4 = _safe_list(item.get("ipv4"))
        ipv6 = _safe_list(item.get("ipv6"))
        classification = str(item.get("dns_classification", "")).strip()
        scope_status = str(item.get("scope_status", "")).strip()

        if ipv4 or ipv6:
            resolved += 1
        else:
            unresolved += 1

        if classification == "possible-wildcard-shared-infrastructure":
            possible_shared += 1
        elif classification == "candidate":
            direct_dns += 1

        normalized.append(
            {
                "hostname": hostname,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "dns_classification": classification,
                "scope_status": scope_status,
                "source": _safe_list(item.get("source")),
            }
        )

    summary = subdomain.get("summary")
    if not isinstance(summary, dict):
        summary = {}

    return {
        "candidates": normalized,
        "candidate_count": int(
            summary.get("candidates_total", len(normalized)) or len(normalized)
        ),
        "direct_dns_candidate_count": int(
            summary.get("direct_dns_candidate_total", direct_dns)
            or direct_dns
        ),
        "possible_shared_count": int(
            summary.get("possible_shared_infrastructure_total", possible_shared)
            or possible_shared
        ),
        "unresolved_count": int(
            summary.get("unresolved_total", unresolved) or unresolved
        ),
        "resolved_count": int(
            summary.get("resolved_total", resolved) or resolved
        ),
        "status": str(subdomain.get("status", "")),
        "dns_environment": subdomain.get("dns_environment", {}),
    }



def _collect_endpoints(data: dict[str, Any]) -> dict[str, Any]:
    """
    Read the actual endpoint.yaml schema.

    endpoint.yaml stores endpoint metadata as:
        method
        url
        same_host
        sources
        detail

    It does not store path or type fields. The attack-surface mapping must
    preserve the source schema rather than inventing empty fields.
    """
    endpoint = data.get("endpoint")

    if not isinstance(endpoint, dict):
        return {
            "total": 0,
            "same_host": 0,
            "external": 0,
            "endpoints": [],
            "summary": {},
            "status": "unavailable",
        }

    endpoints = _safe_list(endpoint.get("endpoints"))

    same_host = 0
    external = 0
    normalized: list[dict[str, Any]] = []

    for item in endpoints:
        if not isinstance(item, dict):
            continue

        is_same_host = bool(item.get("same_host", False))
        if is_same_host:
            same_host += 1
        else:
            external += 1

        normalized.append(
            {
                "method": str(item.get("method", "")),
                "url": str(item.get("url", "")),
                "same_host": is_same_host,
                "sources": _safe_list(item.get("sources")),
                "detail": str(item.get("detail", "")),
            }
        )

    summary = endpoint.get("summary")
    if isinstance(summary, dict):
        same_host = int(summary.get("same_host", same_host) or same_host)
        external = int(summary.get("external", external) or external)
    else:
        summary = {}

    return {
        "total": len(normalized),
        "same_host": same_host,
        "external": external,
        "endpoints": normalized,
        "summary": summary,
        "status": str(endpoint.get("status", "")),
    }


def _collect_directory(data: dict[str, Any]) -> dict[str, Any]:
    directory = data.get("directory")

    if not isinstance(directory, dict):
        return {
            "results": [],
            "found_count": 0,
            "interesting_count": 0,
            "status": "unavailable",
        }

    results = _safe_list(directory.get("results"))

    normalized: list[dict[str, Any]] = []

    for item in results:
        if not isinstance(item, dict):
            continue

        normalized.append(
            {
                "path": str(item.get("path", "")),
                "status_code": item.get("status_code"),
                "content_length": item.get("content_length"),
                "classification": str(item.get("classification", "")),
                "redirect": str(item.get("redirect", "")),
            }
        )

    summary = directory.get("summary")
    if not isinstance(summary, dict):
        summary = {}

    return {
        "results": normalized,
        "found_count": int(
            summary.get("found", len(normalized)) or len(normalized)
        ),
        "interesting_count": int(
            summary.get("interesting", len(normalized)) or len(normalized)
        ),
        "possible_false_positive_count": int(
            summary.get("possible_false_positive", 0) or 0
        ),
        "status": str(directory.get("status", "")),
    }


def _collect_api(data: dict[str, Any]) -> dict[str, Any]:
    api = data.get("api")

    if not isinstance(api, dict):
        return {
            "api_candidates": 0,
            "possible_api": 0,
            "non_api": 0,
            "unknown": 0,
            "probe_targets": 0,
            "probed": 0,
            "probe_not_found": 0,
            "request_errors": 0,
            "status": "unavailable",
        }

    summary = api.get("summary")
    if not isinstance(summary, dict):
        summary = {}

    probes = _safe_list(api.get("probes"))

    probe_not_found = sum(
        1
        for item in probes
        if isinstance(item, dict)
        and str(item.get("probe_classification", "")).lower() == "not-found"
    )

    if not probe_not_found:
        probe_not_found = sum(
            1
            for item in probes
            if isinstance(item, dict)
            and item.get("status_code") == 404
        )

    return {
        "api_candidates": int(summary.get("api_candidate_count", 0) or 0),
        "possible_api": int(summary.get("possible_api_count", 0) or 0),
        "non_api": int(summary.get("non_api_count", 0) or 0),
        "unknown": int(summary.get("unknown_count", 0) or 0),
        "probe_targets": int(
            summary.get("probe_target_count", 0)
            or len(api.get("probe_targets") or [])
        ),
        "probed": int(summary.get("probed_count", 0) or len(probes)),
        "probe_api": int(summary.get("probe_api_count", 0) or 0),
        "probe_possible_api": int(summary.get("probe_possible_api_count", 0) or 0),
        "probe_non_api": int(summary.get("probe_non_api_count", 0) or 0),
        "probe_not_found": int(
            summary.get("probe_not_found_count", probe_not_found) or probe_not_found
        ),
        "request_errors": int(summary.get("request_error_count", 0) or 0),
        "status": str(api.get("status", "")),
    }


def _scope_note() -> str:
    return (
        "Attack surface observations do not expand authorization scope. "
        "Discovered hosts, ports, services, paths, endpoints, and technologies "
        "must be checked against 01-preparation/scope/scope.yaml before testing."
    )


def _build_document(
    target: dict[str, Any],
    dns: dict[str, Any],
    network: dict[str, Any],
    technology: dict[str, Any],
    subdomain: dict[str, Any],
    endpoint: dict[str, Any],
    directory: dict[str, Any],
    api: dict[str, Any],
) -> dict[str, Any]:
    meta = _target_meta(target)

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "attack": {
            "status": "completed",
            "checklist": {
                "id": CHECKLIST_ID,
                "name": CHECKLIST_NAME,
            },
            "application": meta["application"],
            "target_url": meta["target_url"],
            "hostname": meta["hostname"],
            "environment": meta["environment"],
            "assessment_type": meta["assessment_type"],
            "scope_reference": meta["scope_reference"],
            "method": "aggregation of completed reconnaissance evidence",
            "scope_note": _scope_note(),
            "primary_target": {
                "hostname": meta["hostname"],
                "target_url": meta["target_url"],
                "environment": meta["environment"],
                "assessment_type": meta["assessment_type"],
            },
            "dns": dns,
            "network": network,
            "technology": technology,
            "subdomains": subdomain,
            "endpoints": endpoint,
            "directories": directory,
            "api": api,
            "summary": {
                "ipv4_count": len(dns.get("ipv4", [])),
                "ipv6_count": len(dns.get("ipv6", [])),
                "open_port_count": len(network.get("open_ports", [])),
                "technology_count": len(technology.get("technologies", [])),
                "subdomain_candidate_count": int(
                    subdomain.get("candidate_count", 0) or 0
                ),
                "endpoint_count": int(endpoint.get("total", 0) or 0),
                "same_host_endpoint_count": int(
                    endpoint.get("same_host", 0) or 0
                ),
                "directory_count": int(
                    directory.get("found_count", 0) or 0
                ),
                "api_candidate_count": int(
                    api.get("api_candidates", 0) or 0
                ),
                "possible_api_count": int(
                    api.get("possible_api", 0) or 0
                ),
            },
            "source_status": {},
            "evidence_sources": [
                "02-reconnaissance/target/target.yaml",
                "02-reconnaissance/dns/dns.yaml",
                "02-reconnaissance/network/network.yaml",
                "02-reconnaissance/technology/technology.yaml",
                "02-reconnaissance/subdomain/subdomain.yaml",
                "02-reconnaissance/endpoint/endpoint.yaml",
                "02-reconnaissance/directory/directory.yaml",
                "02-reconnaissance/api/api.yaml",
            ],
            "generated_at": now_iso(),
            "notes": "",
        },
    }


def _load_all_sources() -> dict[str, dict[str, Any]]:
    loaded: dict[str, dict[str, Any]] = {}

    for name in SOURCE_FILES:
        data = _load_source(name, required=True)
        assert data is not None

        _validate_project_id(data, name)
        loaded[name] = data

    _require_completed("Target", loaded["target"], "target")
    _require_completed("DNS", loaded["dns"], "dns")
    _require_completed("Network", loaded["network"], "network")
    _require_completed("Technology", loaded["technology"], "technology")
    _require_completed("Endpoint", loaded["endpoint"], "endpoint")
    _require_completed("Directory", loaded["directory"], "directory")
    _require_completed("API", loaded["api"], "api")

    # Subdomain discovery is currently partial. It is still useful as
    # attack-surface evidence, but its partial state must remain visible.
    if _status(loaded["subdomain"], "subdomain") not in {
        "completed",
        "partial",
    }:
        raise AttackError(
            "Subdomain reconnaissance harus berstatus completed atau partial."
        )

    return loaded


def init() -> int:
    sources = _load_all_sources()

    target = sources["target"]
    meta = _target_meta(target)

    document = _build_document(
        target=target,
        dns=_collect_dns(sources["dns"]),
        network=_collect_network(sources["network"]),
        technology=_collect_technology(sources["technology"]),
        subdomain=_collect_subdomains(sources["subdomain"]),
        endpoint=_collect_endpoints(sources["endpoint"]),
        directory=_collect_directory(sources["directory"]),
        api=_collect_api(sources["api"]),
    )

    # Keep source statuses explicit in the final document.
    document["attack"]["source_status"] = {
        name: _status(data, name)
        for name, data in sources.items()
    }

    document["attack"]["status"] = "not-started"

    _save_yaml(attack_file(), document)

    _record_activity(
        "Attack surface mapping initialized from reconnaissance evidence",
        "in-progress",
    )

    print("[PASS] Attack Surface Mapping berhasil diinisialisasi.")
    print(f"PROJECT             : {project_root().name}")
    print(f"TARGET              : {meta['target_url']}")
    print(f"IPV4                : {len(document['attack']['dns']['ipv4'])}")
    print(f"IPV6                : {len(document['attack']['dns']['ipv6'])}")
    print(
        f"OPEN PORTS          : "
        f"{len(document['attack']['network']['open_ports'])}"
    )
    print(
        f"TECHNOLOGIES        : "
        f"{len(document['attack']['technology']['technologies'])}"
    )
    print(
        f"SUBDOMAIN CANDIDATES: "
        f"{document['attack']['subdomains']['candidate_count']}"
    )
    print(
        f"ENDPOINTS           : "
        f"{document['attack']['endpoints']['total']}"
    )
    print(
        f"DIRECTORIES         : "
        f"{document['attack']['directories']['found_count']}"
    )
    print(
        f"API CANDIDATES      : "
        f"{document['attack']['api']['api_candidates']}"
    )
    print(f"FILE                : {attack_file()}")

    return 0


def generate() -> int:
    sources = _load_all_sources()

    document = _build_document(
        target=sources["target"],
        dns=_collect_dns(sources["dns"]),
        network=_collect_network(sources["network"]),
        technology=_collect_technology(sources["technology"]),
        subdomain=_collect_subdomains(sources["subdomain"]),
        endpoint=_collect_endpoints(sources["endpoint"]),
        directory=_collect_directory(sources["directory"]),
        api=_collect_api(sources["api"]),
    )

    document["attack"]["source_status"] = {
        name: _status(data, name)
        for name, data in sources.items()
    }

    document["attack"]["status"] = "completed"
    document["attack"]["generated_at"] = now_iso()

    _save_yaml(attack_file(), document)

    _record_activity(
        "Attack surface mapping generated from reconnaissance evidence",
        "completed",
    )

    print("[PASS] Attack Surface Mapping berhasil dibuat.")
    print(f"PROJECT             : {project_root().name}")
    print(f"TARGET              : {document['attack']['target_url']}")
    print(
        f"ENDPOINTS           : "
        f"{document['attack']['summary']['endpoint_count']}"
    )
    print(
        f"OPEN PORTS          : "
        f"{document['attack']['summary']['open_port_count']}"
    )
    print(
        f"DIRECTORIES         : "
        f"{document['attack']['summary']['directory_count']}"
    )
    print(
        f"API CANDIDATES      : "
        f"{document['attack']['summary']['api_candidate_count']}"
    )
    print("STATUS              : completed")

    return 0


def list_items() -> int:
    data = _load_attack()
    attack = data["attack"]

    print(f"Project ID         : {data.get('project_id')}")
    print(f"Status             : {attack.get('status', '-')}")
    print(f"Target             : {attack.get('target_url', '-')}")
    print()

    print("SOURCE STATUS")
    for name, status_value in (attack.get("source_status") or {}).items():
        print(f"  {name:<15}: {status_value}")

    print()
    print("ATTACK SURFACE")

    dns = attack.get("dns") or {}
    print(
        f"  IPv4             : "
        f"{', '.join(str(x) for x in dns.get('ipv4', [])) or '-'}"
    )
    print(
        f"  IPv6             : "
        f"{', '.join(str(x) for x in dns.get('ipv6', [])) or '-'}"
    )

    network = attack.get("network") or {}
    print(f"  Open ports       : {len(network.get('open_ports', []))}")

    endpoints = attack.get("endpoints") or {}
    print(f"  Endpoints        : {endpoints.get('total', 0)}")
    print(f"  Same-host        : {endpoints.get('same_host', 0)}")

    directories = attack.get("directories") or {}
    print(f"  Directories      : {directories.get('found_count', 0)}")

    subdomains = attack.get("subdomains") or {}
    print(f"  Subdomains       : {subdomains.get('candidate_count', 0)}")

    api = attack.get("api") or {}
    print(f"  API candidates   : {api.get('api_candidates', 0)}")
    print(f"  Possible API     : {api.get('possible_api', 0)}")

    print()
    print("SCOPE")
    print(f"  {attack.get('scope_note', '-')}")

    return 0


def _load_attack() -> dict[str, Any]:
    data = _load_yaml(attack_file(), "Attack surface mapping")

    if data.get("project_id") != project_root().name:
        raise AttackError(
            "Project ID pada attack.yaml tidak sesuai active project."
        )

    if str(data.get("schema_version", "")) != SCHEMA_VERSION:
        raise AttackError("Schema attack.yaml tidak didukung.")

    if not isinstance(data.get("attack"), dict):
        raise AttackError(
            "Field 'attack' pada attack.yaml harus berupa mapping/object."
        )

    return data


def show() -> int:
    data = _load_attack()
    print(
        yaml.safe_dump(
            data["attack"],
            allow_unicode=True,
            sort_keys=False,
        )
    )
    return 0


def verify() -> int:
    data = _load_attack()
    attack = data["attack"]
    errors: list[str] = []

    if attack.get("status") != "completed":
        errors.append(
            f"Status belum completed: {attack.get('status')}"
        )

    required_sections = (
        "primary_target",
        "dns",
        "network",
        "technology",
        "subdomains",
        "endpoints",
        "directories",
        "api",
        "summary",
        "source_status",
        "evidence_sources",
    )

    for section in required_sections:
        if section not in attack:
            errors.append(f"Section '{section}' tidak ditemukan.")

    source_status = attack.get("source_status")
    if not isinstance(source_status, dict):
        errors.append("source_status harus berupa mapping/object.")
    else:
        required_sources = set(SOURCE_FILES)
        missing = required_sources - set(source_status)
        if missing:
            errors.append(
                "Source status tidak lengkap: "
                + ", ".join(sorted(missing))
            )

        for name, status_value in source_status.items():
            if name == "subdomain":
                if status_value not in {"completed", "partial"}:
                    errors.append(
                        f"Status subdomain tidak valid: {status_value!r}"
                    )
            elif status_value != "completed":
                errors.append(
                    f"Source {name} belum completed: {status_value!r}"
                )

    evidence_sources = attack.get("evidence_sources")
    if not isinstance(evidence_sources, list) or not evidence_sources:
        errors.append("evidence_sources harus berupa list yang tidak kosong.")

    summary = attack.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary harus berupa mapping/object.")
    else:
        for key in (
            "ipv4_count",
            "ipv6_count",
            "open_port_count",
            "technology_count",
            "subdomain_candidate_count",
            "endpoint_count",
            "same_host_endpoint_count",
            "directory_count",
            "api_candidate_count",
            "possible_api_count",
        ):
            if not isinstance(summary.get(key), int):
                errors.append(f"summary.{key} harus berupa integer.")

    dns = attack.get("dns")
    if isinstance(dns, dict):
        if not isinstance(dns.get("ipv4"), list):
            errors.append("dns.ipv4 harus berupa list.")
        if not isinstance(dns.get("ipv6"), list):
            errors.append("dns.ipv6 harus berupa list.")

    endpoints = attack.get("endpoints")
    if isinstance(endpoints, dict):
        if not isinstance(endpoints.get("endpoints"), list):
            errors.append("endpoints.endpoints harus berupa list.")

    directories = attack.get("directories")
    if isinstance(directories, dict):
        if not isinstance(directories.get("results"), list):
            errors.append("directories.results harus berupa list.")

    api = attack.get("api")
    if isinstance(api, dict):
        for key in (
            "api_candidates",
            "possible_api",
            "non_api",
            "unknown",
            "probe_targets",
            "probed",
            "request_errors",
        ):
            if not isinstance(api.get(key), int):
                errors.append(f"api.{key} harus berupa integer.")

    if errors:
        print("[FAIL] Attack Surface Mapping verification gagal.")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("[PASS] Attack Surface Mapping memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {attack.get('status')}")
    print(f"[PASS] Target    : {attack.get('target_url', '-')}")
    print(
        f"[PASS] Endpoints : "
        f"{summary.get('endpoint_count', 0) if isinstance(summary, dict) else 0}"
    )
    print(
        f"[PASS] Open ports: "
        f"{summary.get('open_port_count', 0) if isinstance(summary, dict) else 0}"
    )
    print(
        f"[PASS] Technologies: "
        f"{summary.get('technology_count', 0) if isinstance(summary, dict) else 0}"
    )
    print(
        f"[PASS] Directories: "
        f"{summary.get('directory_count', 0) if isinstance(summary, dict) else 0}"
    )
    print(
        f"[PASS] API       : "
        f"{summary.get('api_candidate_count', 0) if isinstance(summary, dict) else 0}"
    )

    _record_activity(
        "Attack surface mapping verified",
        "completed",
    )

    return 0


def status() -> int:
    data = _load_attack()
    attack = data["attack"]
    summary = attack.get("summary") or {}

    print(f"Project ID         : {data.get('project_id')}")
    print(f"Status             : {attack.get('status', '-')}")
    print(f"Target             : {attack.get('target_url', '-')}")
    print(f"IPv4               : {summary.get('ipv4_count', 0)}")
    print(f"IPv6               : {summary.get('ipv6_count', 0)}")
    print(f"Open ports         : {summary.get('open_port_count', 0)}")
    print(f"Technologies       : {summary.get('technology_count', 0)}")
    print(
        f"Subdomain candidates: "
        f"{summary.get('subdomain_candidate_count', 0)}"
    )
    print(f"Endpoints          : {summary.get('endpoint_count', 0)}")
    print(
        f"Same-host endpoints: "
        f"{summary.get('same_host_endpoint_count', 0)}"
    )
    print(f"Directories        : {summary.get('directory_count', 0)}")
    print(f"API candidates     : {summary.get('api_candidate_count', 0)}")
    print(f"Possible API       : {summary.get('possible_api_count', 0)}")
    print(f"File               : {attack_file()}")

    return 0


def remove() -> int:
    import shutil

    path = attack_file()

    if not path.exists():
        print("[INFO] Attack Surface Mapping belum ada.")
        return 0

    confirm = input(
        "Hapus seluruh data Attack Surface Mapping untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(attack_dir())
    _record_activity(
        "Attack surface mapping data removed",
        "completed",
    )
    print("[PASS] Attack Surface Mapping berhasil dihapus.")

    return 0


def version() -> int:
    print(f"BrebesKab-CSIRT-Tools attack.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : aggregation of completed reconnaissance evidence")
    print("Scanner  : none")
    print("Scope    : observations do not expand authorization")
    return 0


def help_text() -> None:
    print(
        """BrebesKab-CSIRT-Tools - Attack Surface Mapping

Usage:
  python scripts/reconnaissance/attack.py <command>

Commands:
  init       Initialize attack surface mapping from reconnaissance results
  generate   Generate the consolidated attack surface map
  list       List attack surface summary
  show       Show complete attack surface document
  verify     Validate attack surface mapping
  status     Show attack surface mapping status
  remove     Remove attack surface mapping data
  version    Show script version

Method:
  Aggregates existing reconnaissance evidence.
  No new network or application scanning is performed.

Sources:
  target.yaml
  dns.yaml
  network.yaml
  technology.yaml
  subdomain.yaml
  endpoint.yaml
  directory.yaml
  api.yaml

Important:
  Discovered assets do not automatically become authorized targets.
  Always verify against 01-preparation/scope/scope.yaml before testing.
"""
    )


def main() -> int:
    commands = {
        "init": init,
        "generate": generate,
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
    except AttackError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except Exception as exc:
        print(
            f"[FAIL] Unexpected error: "
            f"{type(exc).__name__}: {exc}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
