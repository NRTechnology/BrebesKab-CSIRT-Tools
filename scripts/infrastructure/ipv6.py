#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Infrastructure - IPv6 Exposure

Version: 1.0.1

Checklist mapping:
    3-005 - IPv6 exposure

Purpose:
    Determine whether the in-scope target hostname/address has observable IPv6
    exposure and, when IPv6 addresses are discovered, characterize reachable
    TCP services for evidence correlation.

Design principles:
    - Reuse completed 02-reconnaissance/network/network.yaml before new discovery.
    - The IPv6 value in network.yaml is the primary reconnaissance baseline.
    - A DNS AAAA lookup is used as a controlled confirmation step; it does not
      modify network.yaml.
    - If IPv6 addresses are discovered, controlled Nmap IPv6 scanning may be
      performed against those addresses to characterize open TCP services.
    - Nmap is not run when no IPv6 address is known or discovered.
    - Scope is applied to service exposure; an IPv6 address derived from the
      in-scope hostname is retained as target evidence, while port authorization
      is compared against scope.yaml.
    - IPv6 exposure is evidence, not an automatic vulnerability finding.
    - No exploitation, brute force, credential testing, UDP abuse, neighbor
      discovery attacks, routing attacks, or denial-of-service methods are used.
    - The module maintains its own lifecycle state in ipv6.yaml.

Commands:
    init
    analyze
    list
    show
    verify
    status
    remove
    version

Storage:
    projects/<PROJECT-ID>/03-infrastructure/ipv6/ipv6.yaml
    projects/<PROJECT-ID>/03-infrastructure/ipv6/evidence/dns-aaaa.json
    projects/<PROJECT-ID>/03-infrastructure/ipv6/evidence/nmap-ipv6.xml
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml


# ---------------------------------------------------------------------------
# Import bootstrap
# ---------------------------------------------------------------------------

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
    record_activity = None

try:
    from context import require_active_project
except ImportError as exc:
    raise RuntimeError(
        "Tidak dapat mengimpor context.py. Jalankan script dari repository "
        "BrebesKab-CSIRT-Tools."
    ) from exc


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "1.0.1"
SCHEMA_VERSION = "1.1"

CHECKLIST_ID = "3-005"
CHECKLIST_NAME = "IPv6 exposure"

PREPARATION_DIR = "01-preparation"
RECON_DIR = "02-reconnaissance"
INFRASTRUCTURE_DIR = "03-infrastructure"

SCOPE_DIR = "scope"
SCOPE_FILE = "scope.yaml"

NETWORK_DIR = "network"
NETWORK_FILE = "network.yaml"

IPV6_DIR = "ipv6"
IPV6_FILE = "ipv6.yaml"
EVIDENCE_DIR = "evidence"
DNS_EVIDENCE_FILE = "dns-aaaa.json"
NMAP_EVIDENCE_FILE = "nmap-ipv6.xml"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
    "skipped",
    "failed",
    "blocked",
}

NMAP_EXECUTABLE = "nmap"
NMAP_TIMEOUT = 120
NMAP_TOP_PORTS = 100


class IPv6ExposureError(RuntimeError):
    """Raised when IPv6 exposure analysis cannot be completed safely."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def project_context():
    return require_active_project()


def project_root() -> Path:
    return Path(project_context().project_path)


def scope_file() -> Path:
    return project_root() / PREPARATION_DIR / SCOPE_DIR / SCOPE_FILE


def network_file() -> Path:
    return project_root() / RECON_DIR / NETWORK_DIR / NETWORK_FILE


def ipv6_dir() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / IPV6_DIR


def ipv6_file() -> Path:
    return ipv6_dir() / IPV6_FILE


def evidence_dir() -> Path:
    return ipv6_dir() / EVIDENCE_DIR


def dns_evidence_file() -> Path:
    return evidence_dir() / DNS_EVIDENCE_FILE


def nmap_evidence_file() -> Path:
    return evidence_dir() / NMAP_EVIDENCE_FILE


def record(action: str, status: str) -> None:
    if record_activity is None:
        return

    try:
        record_activity(
            phase="03-infrastructure",
            item=CHECKLIST_ID,
            action=action,
            status=status,
            context=project_context(),
        )
        return
    except TypeError:
        pass
    except Exception:
        return

    try:
        record_activity(
            phase="03-infrastructure",
            item=CHECKLIST_ID,
            action=action,
            status=status,
        )
    except Exception:
        pass


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise IPv6ExposureError(f"{label} tidak ditemukan: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IPv6ExposureError(
            f"Gagal membaca {label}: {path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise IPv6ExposureError(
            f"Format {label} harus berupa mapping/object."
        )

    return data


def save_yaml(path: Path, data: dict[str, Any]) -> None:
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


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def require_project_id(data: dict[str, Any], label: str) -> None:
    expected = project_root().name
    actual = str(data.get("project_id", "")).strip()

    if actual != expected:
        raise IPv6ExposureError(
            f"Project ID pada {label} tidak sesuai active project. "
            f"Expected: {expected}; Found: {actual or '-'}"
        )


def nested_payload(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise IPv6ExposureError(
            f"Field '{name}' pada dokumen tidak valid."
        )
    return value


def safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------


def load_network() -> dict[str, Any]:
    data = load_yaml(network_file(), "network.yaml")
    require_project_id(data, "network.yaml")

    network = nested_payload(data, "network")
    status = str(network.get("status", "")).strip().lower()

    if status != "completed":
        raise IPv6ExposureError(
            "Reconnaissance network belum completed. "
            "Jalankan network.py terlebih dahulu."
        )

    if not isinstance(network.get("ipv4"), list):
        raise IPv6ExposureError(
            "Field network.ipv4 pada network.yaml harus berupa list."
        )

    if not isinstance(network.get("ipv6"), list):
        raise IPv6ExposureError(
            "Field network.ipv6 pada network.yaml harus berupa list."
        )

    if not isinstance(network.get("ports"), list):
        raise IPv6ExposureError(
            "Field network.ports pada network.yaml harus berupa list."
        )

    return data


def load_scope() -> dict[str, Any]:
    data = load_yaml(scope_file(), "scope.yaml")
    require_project_id(data, "scope.yaml")

    scope = nested_payload(data, "scope")

    if not isinstance(scope.get("in_scope"), list):
        raise IPv6ExposureError(
            "Field scope.in_scope pada scope.yaml harus berupa list."
        )

    if not isinstance(scope.get("out_of_scope"), list):
        raise IPv6ExposureError(
            "Field scope.out_of_scope pada scope.yaml harus berupa list."
        )

    return data


# ---------------------------------------------------------------------------
# Target / scope normalization
# ---------------------------------------------------------------------------


def target_metadata(network_data: dict[str, Any]) -> dict[str, Any]:
    network = nested_payload(network_data, "network")

    ipv4 = [
        str(value).strip()
        for value in safe_list(network.get("ipv4"))
        if str(value).strip()
    ]
    ipv6 = [
        str(value).strip()
        for value in safe_list(network.get("ipv6"))
        if str(value).strip()
    ]

    target_url = str(network.get("target_url", "")).strip()
    hostname = str(network.get("hostname", "")).strip().rstrip(".")

    if not hostname and target_url:
        parsed = urlparse(target_url)
        hostname = (parsed.hostname or "").strip().rstrip(".")

    return {
        "application": str(network.get("application", "")).strip(),
        "target_url": target_url,
        "hostname": hostname,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "environment": str(network.get("environment", "")).strip(),
        "assessment_type": str(network.get("assessment_type", "")).strip(),
        "scope_reference": str(network.get("scope_reference", "")).strip(),
    }


def authorized_ports(scope_data: dict[str, Any]) -> set[int]:
    scope = nested_payload(scope_data, "scope")
    ports: set[int] = set()

    for item in safe_list(scope.get("in_scope")):
        if not isinstance(item, dict):
            continue

        for raw in safe_list(item.get("ports")):
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                ports.add(port)

    return ports


def normalize_ipv6(address: str) -> str:
    raw = str(address).strip()
    if not raw:
        return ""

    try:
        parsed = ipaddress.IPv6Address(raw)
    except ValueError as exc:
        raise IPv6ExposureError(
            f"IPv6 address tidak valid: {address!r}"
        ) from exc

    return str(parsed)


def normalize_ipv6_list(values: list[Any]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        text = str(value).strip()
        if not text:
            continue

        try:
            address = normalize_ipv6(text)
        except IPv6ExposureError:
            continue

        if address not in seen:
            seen.add(address)
            normalized.append(address)

    return sorted(normalized)


# ---------------------------------------------------------------------------
# DNS AAAA confirmation
# ---------------------------------------------------------------------------


def resolve_ipv6(hostname: str) -> dict[str, Any]:
    """
    Confirm IPv6/AAAA records without confusing resolver failure with
    a legitimate 'no AAAA observed' result.

    AF_UNSPEC is intentionally used so that a successful hostname resolution
    returning only IPv4 can be distinguished from a resolver/hostname error.
    """
    started_at = now_iso()
    result: dict[str, Any] = {
        "hostname": hostname,
        "resolver": "python-socket",
        "query_family": "AF_UNSPEC",
        "started_at": started_at,
        "addresses": [],
        "ipv4_addresses": [],
        "status": "not-attempted",
        "error": "",
        "completed_at": "",
    }

    if not hostname:
        result["status"] = "skipped"
        result["error"] = "Hostname target tidak tersedia."
        result["completed_at"] = now_iso()
        return result

    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        ipv4_addresses: list[str] = []
        ipv6_addresses: list[str] = []

        for info in infos:
            family = info[0]
            sockaddr = info[4]
            if not sockaddr:
                continue

            address = str(sockaddr[0]).split("%", 1)[0]

            if family == socket.AF_INET:
                if address and address not in ipv4_addresses:
                    ipv4_addresses.append(address)
                continue

            if family == socket.AF_INET6:
                try:
                    normalized = normalize_ipv6(address)
                except IPv6ExposureError:
                    continue
                if normalized not in ipv6_addresses:
                    ipv6_addresses.append(normalized)

        result["ipv4_addresses"] = sorted(ipv4_addresses)
        result["addresses"] = sorted(ipv6_addresses)
        result["status"] = "resolved" if ipv6_addresses else "no-aaaa-observed"

    except socket.gaierror as exc:
        result["status"] = "resolver-error"
        result["error"] = f"gaierror: {exc}"
    except OSError as exc:
        result["status"] = "resolver-error"
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        result["completed_at"] = now_iso()

    return result


# ---------------------------------------------------------------------------
# Nmap IPv6 service scan
# ---------------------------------------------------------------------------


def remove_stale_nmap_evidence() -> None:
    """Remove previous Nmap XML so skipped runs cannot be mistaken for current evidence."""
    path = nmap_evidence_file()
    try:
        if path.exists():
            path.unlink()
    except OSError as exc:
        raise IPv6ExposureError(
            f"Gagal menghapus Nmap evidence lama: {path}: {exc}"
        ) from exc


def parse_nmap_ipv6_xml(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    if not path.exists():
        return [], []

    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        return [], [f"Gagal parse Nmap XML: {exc}"]

    results: list[dict[str, Any]] = []
    errors: list[str] = []

    for host in root.findall("host"):
        addresses: list[dict[str, str]] = []
        for address in host.findall("address"):
            addresses.append(
                {
                    "addr": str(address.get("addr", "")),
                    "addrtype": str(address.get("addrtype", "")),
                }
            )

        ipv6_address = next(
            (
                item["addr"]
                for item in addresses
                if item.get("addrtype") == "ipv6"
            ),
            "",
        )

        host_state = "unknown"
        status = host.find("status")
        if status is not None:
            host_state = str(status.get("state", "unknown"))

        ports_node = host.find("ports")
        if ports_node is None:
            continue

        for port in ports_node.findall("port"):
            state_node = port.find("state")
            state = str(
                state_node.get("state", "") if state_node is not None else ""
            )

            if state != "open":
                continue

            service_node = port.find("service")
            service_name = ""
            product = ""
            version = ""
            extrainfo = ""

            if service_node is not None:
                service_name = str(service_node.get("name", ""))
                product = str(service_node.get("product", ""))
                version = str(service_node.get("version", ""))
                extrainfo = str(service_node.get("extrainfo", ""))

            results.append(
                {
                    "address": ipv6_address,
                    "port": int(port.get("portid", "0")),
                    "protocol": str(port.get("protocol", "tcp")),
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "host_state": host_state,
                }
            )

    return results, errors


def run_nmap_ipv6(
    addresses: list[str],
) -> dict[str, Any]:
    evidence_path = nmap_evidence_file()
    started_at = now_iso()

    result: dict[str, Any] = {
        "tool": NMAP_EXECUTABLE,
        "command": [],
        "addresses": addresses,
        "status": "not-run",
        "started_at": started_at,
        "completed_at": "",
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "evidence_file": str(evidence_path),
        "error": "",
    }

    if not addresses:
        result["status"] = "skipped-no-ipv6"
        result["completed_at"] = now_iso()
        return result

    executable = shutil.which(NMAP_EXECUTABLE)
    if not executable:
        result["status"] = "tool-unavailable"
        result["error"] = "nmap tidak ditemukan pada PATH."
        result["completed_at"] = now_iso()
        return result

    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        executable,
        "-6",
        "-Pn",
        "--top-ports",
        str(NMAP_TOP_PORTS),
        "--open",
        "-oX",
        str(evidence_path),
        *addresses,
    ]

    result["command"] = command

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT,
            check=False,
        )
        result["returncode"] = completed.returncode
        result["stdout"] = completed.stdout[-12000:]
        result["stderr"] = completed.stderr[-12000:]

        if completed.returncode == 0:
            result["status"] = "completed"
        else:
            result["status"] = "failed"
            result["error"] = (
                completed.stderr.strip()
                or f"Nmap return code {completed.returncode}."
            )
    except subprocess.TimeoutExpired as exc:
        result["status"] = "timeout"
        result["error"] = f"Nmap timeout after {NMAP_TIMEOUT}s."
        result["stdout"] = str(exc.stdout or "")[-12000:]
        result["stderr"] = str(exc.stderr or "")[-12000:]
    except OSError as exc:
        result["status"] = "execution-error"
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        result["completed_at"] = now_iso()

    return result


# ---------------------------------------------------------------------------
# Document construction
# ---------------------------------------------------------------------------


def empty_document(
    network_data: dict[str, Any],
    scope_data: dict[str, Any],
) -> dict[str, Any]:
    target = target_metadata(network_data)
    ports = sorted(authorized_ports(scope_data))

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "ipv6": {
            "status": "not-started",
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": target["application"],
            "target_url": target["target_url"],
            "hostname": target["hostname"],
            "ipv4": target["ipv4"],
            "ipv6_baseline": target["ipv6"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_reference": target["scope_reference"],
            "method": "network.yaml baseline + DNS AAAA confirmation + controlled Nmap IPv6 service scan",
            "authorized_ports": ports,
            "sources": {
                "network": "02-reconnaissance/network/network.yaml",
                "scope": "01-preparation/scope/scope.yaml",
                "dns_evidence": "03-infrastructure/ipv6/evidence/dns-aaaa.json",
                "nmap_evidence": "03-infrastructure/ipv6/evidence/nmap-ipv6.xml",
            },
            "discovery_rules": {
                "baseline": "Reuse network.ipv6 from completed network.yaml.",
                "dns_confirmation": "Resolve target hostname for IPv6/AAAA using Python socket.",
                "service_confirmation": "If IPv6 addresses are known, run Nmap -6 against those addresses.",
                "vulnerability_rule": "IPv6 exposure is evidence and is not automatically a vulnerability.",
            },
            "dns_confirmation": {},
            "addresses": [],
            "services": [],
            "summary": {
                "baseline_ipv6_addresses": len(target["ipv6"]),
                "dns_ipv6_addresses": 0,
                "confirmed_ipv6_addresses": 0,
                "open_ipv6_services": 0,
                "authorized_open_ipv6_services": 0,
                "outside_scope_open_ipv6_services": 0,
                "unknown_scope_open_ipv6_services": 0,
                "nmap_status": "not-run",
                "requires_review": 0,
                "errors": 0,
            },
            "assessment": {
                "exposure": "not-assessed",
                "result": "not-assessed",
                "rationale": "IPv6 exposure has not been analyzed yet.",
            },
            "notes": [
                "Initialized from completed network.yaml and scope.yaml.",
            ],
            "generated_at": now_iso(),
        },
    }


def classify_service_scope(port: int, authorized: set[int]) -> tuple[str, str, bool]:
    if port in authorized:
        return "in-scope", "authorized", False

    return "outside-scope-port", "requires-review", True


def build_address_records(
    baseline: list[str],
    dns_addresses: list[str],
    nmap_services: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    all_addresses = sorted(set(baseline) | set(dns_addresses))
    service_by_address: dict[str, list[dict[str, Any]]] = {}

    for service in nmap_services:
        address = str(service.get("address", "")).strip()
        if not address:
            continue
        service_by_address.setdefault(address, []).append(service)

    records: list[dict[str, Any]] = []
    for address in all_addresses:
        source = []
        if address in baseline:
            source.append("network.yaml")
        if address in dns_addresses:
            source.append("dns-aaaa")

        records.append(
            {
                "address": address,
                "sources": source,
                "nmap_observed": address in service_by_address,
                "open_services": service_by_address.get(address, []),
            }
        )

    return records


def build_document(
    network_data: dict[str, Any],
    scope_data: dict[str, Any],
    dns_result: dict[str, Any],
    nmap_run: dict[str, Any],
    nmap_services: list[dict[str, Any]],
    errors: list[str],
) -> dict[str, Any]:
    target = target_metadata(network_data)
    baseline = normalize_ipv6_list(target["ipv6"])
    dns_addresses = normalize_ipv6_list(dns_result.get("addresses") or [])
    known_addresses = sorted(set(baseline) | set(dns_addresses))
    authorized = authorized_ports(scope_data)

    services: list[dict[str, Any]] = []
    for item in nmap_services:
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue

        scope_status, assessment, requires_review = classify_service_scope(
            port,
            authorized,
        )

        service_record = dict(item)
        service_record.update(
            {
                "scope_status": scope_status,
                "assessment": assessment,
                "requires_review": requires_review,
            }
        )
        services.append(service_record)

    address_records = build_address_records(
        baseline,
        dns_addresses,
        services,
    )

    confirmed_addresses = sorted(set(known_addresses))
    open_services = len(services)
    authorized_open = sum(
        1 for service in services if service.get("assessment") == "authorized"
    )
    outside_scope_open = sum(
        1
        for service in services
        if service.get("scope_status") == "outside-scope-port"
    )
    requires_review = sum(
        1 for service in services if service.get("requires_review") is True
    )

    if errors:
        exposure = "not-confirmed"
        rationale = (
            "IPv6 exposure assessment is incomplete because one or more discovery "
            "or service-confirmation steps returned an error. "
            f"{len(errors)} error(s) were recorded; existing baseline/evidence is retained."
        )
    elif not known_addresses:
        exposure = "not-observed"
        rationale = (
            "No IPv6 address was present in completed network.yaml and hostname "
            "resolution completed successfully without returning any IPv6/AAAA address."
        )
    elif open_services:
        exposure = "observed"
        rationale = (
            f"{len(known_addresses)} IPv6 address(es) were observed and "
            f"{open_services} open IPv6 TCP service(s) were returned by Nmap."
        )
    else:
        exposure = "address-observed-no-open-service-confirmed"
        rationale = (
            f"{len(known_addresses)} IPv6 address(es) were observed and the controlled "
            "Nmap IPv6 scan completed without confirming an open TCP service."
        )

    notes = [
        "Administrative classification is not performed by this checklist.",
        "IPv6 address exposure is not automatically considered a vulnerability.",
        "Nmap is run only when IPv6 addresses are known or discovered.",
        "The completed network.yaml IPv6 field is retained as the reconnaissance baseline.",
        "DNS confirmation distinguishes successful resolution with no AAAA from resolver failure.",
    ]
    notes.extend(errors)

    document = empty_document(network_data, scope_data)
    ipv6 = document["ipv6"]

    ipv6.update(
        {
            "status": "in-progress",
            "dns_confirmation": dns_result,
            "addresses": address_records,
            "services": services,
            "summary": {
                "baseline_ipv6_addresses": len(baseline),
                "dns_ipv6_addresses": len(dns_addresses),
                "confirmed_ipv6_addresses": len(confirmed_addresses),
                "open_ipv6_services": open_services,
                "authorized_open_ipv6_services": authorized_open,
                "outside_scope_open_ipv6_services": outside_scope_open,
                "unknown_scope_open_ipv6_services": 0,
                "nmap_status": str(nmap_run.get("status", "not-run")),
                "requires_review": requires_review,
                "errors": len(errors),
            },
            "assessment": {
                "exposure": exposure,
                "result": "evidence-only" if not errors else "evidence-incomplete",
                "rationale": rationale,
            },
            "nmap": nmap_run,
            "notes": notes,
            "generated_at": now_iso(),
        }
    )

    document["updated_at"] = now_iso()
    return document



# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init() -> int:
    network_data = load_network()
    scope_data = load_scope()

    document = empty_document(network_data, scope_data)
    save_yaml(ipv6_file(), document)

    record("IPv6 exposure initialized", "in-progress")

    target = target_metadata(network_data)
    print("[PASS] IPv6 Exposure initialized.")
    print(f"PROJECT          : {project_root().name}")
    print(f"TARGET           : {target['hostname'] or '-'}")
    print(f"BASELINE IPV6    : {len(target['ipv6'])}")
    print(f"AUTHORIZED PORTS : {len(document['ipv6']['authorized_ports'])}")
    print(f"FILE             : {ipv6_file()}")
    return 0


def cmd_analyze() -> int:
    network_data = load_network()
    scope_data = load_scope()
    target = target_metadata(network_data)

    baseline_ipv6 = normalize_ipv6_list(target["ipv6"])
    dns_result = resolve_ipv6(target["hostname"])
    dns_addresses = normalize_ipv6_list(dns_result.get("addresses") or [])
    known_addresses = sorted(set(baseline_ipv6) | set(dns_addresses))

    save_json(
        dns_evidence_file(),
        {
            "schema_version": SCHEMA_VERSION,
            "project_id": project_root().name,
            "generated_at": now_iso(),
            "method": "Python socket AF_UNSPEC resolution with IPv6 filtering",
            "target_hostname": target["hostname"],
            "network_baseline_ipv6": baseline_ipv6,
            "result": dns_result,
        },
    )

    errors: list[str] = []
    if dns_result.get("status") == "resolver-error":
        errors.append(str(dns_result.get("error") or "DNS resolver error."))
    elif dns_result.get("status") == "skipped":
        errors.append(str(dns_result.get("error") or "DNS confirmation skipped."))

    if known_addresses:
        print(f"[INFO] IPv6 addresses to scan: {len(known_addresses)}")
        nmap_run = run_nmap_ipv6(known_addresses)
    else:
        print("[INFO] No IPv6 address observed; Nmap IPv6 scan skipped.")
        remove_stale_nmap_evidence()
        nmap_run = run_nmap_ipv6([])

    nmap_services: list[dict[str, Any]] = []
    if nmap_run.get("status") == "completed":
        parsed_services, parse_errors = parse_nmap_ipv6_xml(nmap_evidence_file())
        nmap_services = parsed_services
        errors.extend(parse_errors)
    elif nmap_run.get("error"):
        errors.append(str(nmap_run["error"]))

    document = build_document(
        network_data=network_data,
        scope_data=scope_data,
        dns_result=dns_result,
        nmap_run=nmap_run,
        nmap_services=nmap_services,
        errors=sorted(set(error for error in errors if error)),
    )

    save_yaml(ipv6_file(), document)

    ipv6 = document["ipv6"]
    summary = ipv6["summary"]

    record(
        (
            "IPv6 exposure analyzed: "
            f"{summary['confirmed_ipv6_addresses']} address(es), "
            f"{summary['open_ipv6_services']} open service(s), "
            f"{summary['errors']} error(s)"
        ),
        "in-progress",
    )

    print("[PASS] IPv6 Exposure analysis completed.")
    print(f"HOSTNAME                : {ipv6['hostname']}")
    print(f"BASELINE IPV6           : {summary['baseline_ipv6_addresses']}")
    print(f"DNS STATUS              : {dns_result.get('status', '-')}")
    print(f"DNS IPV6                : {summary['dns_ipv6_addresses']}")
    print(f"CONFIRMED IPV6          : {summary['confirmed_ipv6_addresses']}")
    print(f"OPEN IPV6 SERVICES      : {summary['open_ipv6_services']}")
    print(f"AUTHORIZED OPEN         : {summary['authorized_open_ipv6_services']}")
    print(f"OUTSIDE-SCOPE OPEN      : {summary['outside_scope_open_ipv6_services']}")
    print(f"REQUIRES REVIEW         : {summary['requires_review']}")
    print(f"NMAP STATUS             : {summary['nmap_status']}")
    print(f"ERRORS                  : {summary['errors']}")
    print(f"FILE                    : {ipv6_file()}")
    print(f"DNS EVIDENCE            : {dns_evidence_file()}")
    print(f"NMAP EVIDENCE           : {nmap_evidence_file() if nmap_evidence_file().exists() else '-'}")
    return 0



def cmd_list() -> int:
    path = ipv6_file()
    if not path.exists():
        print("[FAIL] ipv6.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "ipv6.yaml")
    require_project_id(data, "ipv6.yaml")
    ipv6 = nested_payload(data, "ipv6")
    summary = ipv6.get("summary") or {}

    print(f"Project ID : {data.get('project_id', '-')}")
    print(f"Status     : {ipv6.get('status', '-')}")
    print(f"Hostname   : {ipv6.get('hostname', '-')}")
    print()
    print("ADDRESSES:")

    addresses = ipv6.get("addresses") or []
    if not addresses:
        print("  [none]")
    else:
        for item in addresses:
            if not isinstance(item, dict):
                continue
            print(
                f"  {item.get('address', '-'):39} "
                f"sources={','.join(item.get('sources') or []) or '-':20} "
                f"nmap={str(item.get('nmap_observed', False)).lower()}"
            )

    print()
    print("OPEN SERVICES:")
    services = ipv6.get("services") or []
    if not services:
        print("  [none]")
    else:
        for item in services:
            print(
                f"  {item.get('address', '-'):39} "
                f"{int(item.get('port', 0)):5d}/{item.get('protocol', 'tcp'):3} "
                f"{item.get('service', '-'):<16} "
                f"scope={item.get('scope_status', '-'):18} "
                f"review={str(item.get('requires_review', False)).lower()}"
            )

    print()
    print("SUMMARY:")
    print(f"  Confirmed IPv6 : {summary.get('confirmed_ipv6_addresses', 0)}")
    print(f"  Open services  : {summary.get('open_ipv6_services', 0)}")
    print(f"  Review         : {summary.get('requires_review', 0)}")
    return 0


def cmd_show() -> int:
    path = ipv6_file()
    if not path.exists():
        print("[FAIL] ipv6.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "ipv6.yaml")
    require_project_id(data, "ipv6.yaml")

    print(f"PROJECT: {project_root().name}")
    print(f"FILE   : {path}")
    print()
    print(
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        ).rstrip()
    )
    return 0


def validate_document(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            f"schema_version tidak sesuai: {data.get('schema_version')!r}"
        )

    require_project_id(data, "ipv6.yaml")
    ipv6 = nested_payload(data, "ipv6")

    status = str(ipv6.get("status", "")).strip()
    if status not in VALID_STATUSES:
        errors.append(f"Status IPv6 tidak valid: {status or '-'}")

    for key in (
        "application",
        "target_url",
        "hostname",
        "environment",
        "assessment_type",
    ):
        if not str(ipv6.get(key, "")).strip():
            errors.append(f"Field ipv6.{key} kosong.")

    for field in (
        "ipv4",
        "ipv6_baseline",
        "authorized_ports",
        "addresses",
        "services",
        "notes",
    ):
        if not isinstance(ipv6.get(field), list):
            errors.append(f"Field ipv6.{field} harus berupa list.")

    if not isinstance(ipv6.get("summary"), dict):
        errors.append("Field ipv6.summary harus berupa mapping/object.")

    if not isinstance(ipv6.get("assessment"), dict):
        errors.append("Field ipv6.assessment harus berupa mapping/object.")

    dns_confirmation = ipv6.get("dns_confirmation")
    if not isinstance(dns_confirmation, dict):
        errors.append("Field ipv6.dns_confirmation harus berupa mapping/object.")
    else:
        dns_status = str(dns_confirmation.get("status", "")).strip()
        valid_dns_statuses = {
            "not-attempted",
            "resolved",
            "no-aaaa-observed",
            "resolver-error",
            "skipped",
        }
        if dns_status not in valid_dns_statuses:
            errors.append(f"Status DNS IPv6 tidak valid: {dns_status or '-'}")

    return errors


def cmd_verify() -> int:
    path = ipv6_file()
    if not path.exists():
        print("[FAIL] ipv6.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "ipv6.yaml")
    errors = validate_document(data)

    ipv6 = data.get("ipv6") if isinstance(data.get("ipv6"), dict) else {}
    status = str(ipv6.get("status", "")).strip()

    if status not in {"in-progress", "completed"}:
        errors.append(
            f"Status belum siap diverifikasi: {status or '-'}"
        )

    summary = ipv6.get("summary") if isinstance(ipv6.get("summary"), dict) else {}
    known_ipv6 = int(summary.get("confirmed_ipv6_addresses", 0) or 0)
    error_count = int(summary.get("errors", 0) or 0)
    nmap_status = str(summary.get("nmap_status", "not-run"))

    dns_confirmation = ipv6.get("dns_confirmation")
    if isinstance(dns_confirmation, dict):
        dns_status = str(dns_confirmation.get("status", ""))
        dns_error = str(dns_confirmation.get("error", "")).strip()
        if dns_status == "resolver-error" and not dns_error:
            errors.append("DNS resolver berstatus resolver-error tetapi field error kosong.")

        if dns_status == "no-aaaa-observed" and dns_error:
            errors.append(
                "DNS berstatus no-aaaa-observed tetapi masih memiliki field error; "
                "status tersebut harus benar-benar merepresentasikan resolution sukses."
            )

    if error_count > 0:
        errors.append(
            f"Assessment memiliki {error_count} error; checklist belum boleh ditandai completed."
        )

    if known_ipv6 > 0:
        if nmap_status != "completed":
            errors.append(
                "IPv6 address terobservasi tetapi Nmap IPv6 service scan belum completed."
            )
        if not nmap_evidence_file().exists():
            errors.append(
                "IPv6 address terobservasi tetapi evidence nmap-ipv6.xml tidak ditemukan."
            )
    else:
        if nmap_status != "skipped-no-ipv6":
            errors.append(
                "Tidak ada IPv6 terkonfirmasi tetapi Nmap status bukan skipped-no-ipv6."
            )
        if nmap_evidence_file().exists():
            errors.append(
                "Tidak ada IPv6 terkonfirmasi tetapi Nmap evidence lama masih tersedia."
            )

    if errors:
        print("[FAIL] IPv6 Exposure verification gagal.")
        for error in errors:
            print(f"  - {error}")
        return 1

    if status == "in-progress":
        ipv6["status"] = "completed"
        data["updated_at"] = now_iso()
        save_yaml(path, data)
        status = "completed"

    print("[PASS] IPv6 Exposure memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {status}")
    print(f"[PASS] Hostname  : {ipv6.get('hostname', '-')}")
    print(f"[PASS] IPv6     : {summary.get('confirmed_ipv6_addresses', 0)}")
    print(f"[PASS] Services : {summary.get('open_ipv6_services', 0)}")
    print(
        "[PASS] Assessment: IPv6 exposure dicatat sebagai evidence; "
        "tidak otomatis dianggap vulnerability."
    )

    record("IPv6 exposure verified", "completed")
    return 0



def cmd_status() -> int:
    path = ipv6_file()
    if not path.exists():
        print("[INFO] IPv6 Exposure belum ada.")
        return 0

    data = load_yaml(path, "ipv6.yaml")
    require_project_id(data, "ipv6.yaml")
    ipv6 = nested_payload(data, "ipv6")
    summary = ipv6.get("summary") or {}

    print(f"PROJECT                 : {data.get('project_id', '-')}")
    print(f"STATUS                  : {ipv6.get('status', '-')}")
    print(f"HOSTNAME                : {ipv6.get('hostname', '-')}")
    print(f"BASELINE IPV6           : {summary.get('baseline_ipv6_addresses', 0)}")
    print(f"DNS IPV6                : {summary.get('dns_ipv6_addresses', 0)}")
    print(f"CONFIRMED IPV6          : {summary.get('confirmed_ipv6_addresses', 0)}")
    print(f"OPEN IPV6 SERVICES      : {summary.get('open_ipv6_services', 0)}")
    print(f"AUTHORIZED OPEN         : {summary.get('authorized_open_ipv6_services', 0)}")
    print(f"OUTSIDE-SCOPE OPEN      : {summary.get('outside_scope_open_ipv6_services', 0)}")
    print(f"REQUIRES REVIEW         : {summary.get('requires_review', 0)}")
    print(f"NMAP STATUS             : {summary.get('nmap_status', 'not-run')}")
    print(f"ERRORS                  : {summary.get('errors', 0)}")
    print(f"FILE                    : {path}")
    print(f"DNS EVIDENCE            : {dns_evidence_file() if dns_evidence_file().exists() else '-'}")
    print(f"NMAP EVIDENCE           : {nmap_evidence_file() if nmap_evidence_file().exists() else '-'}")
    return 0


def cmd_remove() -> int:
    path = ipv6_dir()
    if not path.exists():
        print("[INFO] IPv6 Exposure belum ada.")
        return 0

    confirm = input(
        "Hapus seluruh data IPv6 Exposure untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(path)
    record("IPv6 exposure data removed", "completed")
    print("[PASS] IPv6 Exposure berhasil dihapus.")
    return 0


def cmd_version() -> int:
    print(f"BrebesKab-CSIRT-Tools ipv6.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : Network baseline + AF_UNSPEC DNS confirmation + Nmap IPv6")
    print("Baseline : 02-reconnaissance/network/network.yaml")
    print("Scope    : 01-preparation/scope/scope.yaml")
    print("Scan     : nmap -6 -Pn --top-ports 100 --open")
    print("Rule     : IPv6 exposure is evidence, not an automatic vulnerability")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Infrastructure IPv6 Exposure\n"
        "\n"
        "Checklist:\n"
        "  3-005 IPv6 exposure\n"
        "\n"
        "Usage:\n"
        "  python scripts/infrastructure/ipv6.py init\n"
        "  python scripts/infrastructure/ipv6.py analyze\n"
        "  python scripts/infrastructure/ipv6.py list\n"
        "  python scripts/infrastructure/ipv6.py show\n"
        "  python scripts/infrastructure/ipv6.py verify\n"
        "  python scripts/infrastructure/ipv6.py status\n"
        "  python scripts/infrastructure/ipv6.py remove\n"
        "  python scripts/infrastructure/ipv6.py version\n"
        "\n"
        "Design:\n"
        "  - Reuses completed network.yaml as the IPv6 baseline.\n"
        "  - Confirms hostname resolution using Python socket and filters IPv6 results.\n"
        "  - Runs Nmap IPv6 service scanning only when IPv6 addresses are known and confirmed.\n"
        "  - Compares discovered IPv6 services with scope.yaml authorization.\n"
        "  - Does not perform exploitation, brute force, or destructive testing.\n"
        "  - IPv6 exposure is evidence and is not automatically a vulnerability.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Infrastructure IPv6 Exposure - checklist 3-005",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="help",
        choices=(
            "init",
            "analyze",
            "list",
            "show",
            "verify",
            "status",
            "remove",
            "version",
            "help",
        ),
    )

    args = parser.parse_args(argv)

    try:
        if args.command == "help":
            print_help()
            return 0
        if args.command == "init":
            return cmd_init()
        if args.command == "analyze":
            return cmd_analyze()
        if args.command == "list":
            return cmd_list()
        if args.command == "show":
            return cmd_show()
        if args.command == "verify":
            return cmd_verify()
        if args.command == "status":
            return cmd_status()
        if args.command == "remove":
            return cmd_remove()
        if args.command == "version":
            return cmd_version()

        raise IPv6ExposureError(f"Command tidak dikenal: {args.command}")

    except IPv6ExposureError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Dibatalkan oleh pengguna.")
        return 130
    except Exception as exc:
        print(f"[FAIL] Unexpected error: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
