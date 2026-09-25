#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Infrastructure - Service Enumeration

Version: 1.0.0

Checklist mapping:
    3-002 - Service enumeration

Purpose:
    Enumerate services on TCP ports that are explicitly authorized by the
    active assessment scope, using the completed Reconnaissance network
    result as the baseline.

Design:
    - Does NOT repeat the reconnaissance TCP port scan.
    - Reads 02-reconnaissance/network/network.yaml.
    - Reads 01-preparation/scope/scope.yaml.
    - Only probes ports explicitly listed in the active in-scope entries.
    - Uses Nmap service/version detection (-sV).
    - Does not test discovered out-of-scope ports.
    - Does not use NSE vulnerability scripts or brute force.
    - Stores service metadata, not response bodies or credentials.
    - Nmap XML is retained as technical evidence.
    - The module has its own lifecycle state in service.yaml.

Commands:
    init
    enumerate
    list
    show
    verify
    status
    remove
    version

Storage:
    projects/<PROJECT-ID>/03-infrastructure/service/service.yaml
    projects/<PROJECT-ID>/03-infrastructure/service/evidence/nmap-service.xml
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

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
SCHEMA_VERSION = "1.0"

CHECKLIST_ID = "3-002"
CHECKLIST_NAME = "Service enumeration"

PREPARATION_DIR = "01-preparation"
RECON_DIR = "02-reconnaissance"
INFRASTRUCTURE_DIR = "03-infrastructure"

SCOPE_DIR = "scope"
SCOPE_FILE = "scope.yaml"

NETWORK_DIR = "network"
NETWORK_FILE = "network.yaml"

SERVICE_DIR = "service"
SERVICE_FILE = "service.yaml"
EVIDENCE_DIR = "evidence"
NMAP_EVIDENCE_FILE = "nmap-service.xml"

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


class ServiceEnumerationError(RuntimeError):
    """Raised when service enumeration cannot be completed safely."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_iso() -> str:
    """Return current local time as ISO-8601 with seconds."""
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def project_context():
    """Return the active project context."""
    return require_active_project()


def project_root() -> Path:
    """Return the active project directory."""
    return Path(project_context().project_path)


def scope_file() -> Path:
    return project_root() / PREPARATION_DIR / SCOPE_DIR / SCOPE_FILE


def network_file() -> Path:
    return project_root() / RECON_DIR / NETWORK_DIR / NETWORK_FILE


def service_dir() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / SERVICE_DIR


def service_file() -> Path:
    return service_dir() / SERVICE_FILE


def evidence_dir() -> Path:
    return service_dir() / EVIDENCE_DIR


def nmap_evidence_file() -> Path:
    return evidence_dir() / NMAP_EVIDENCE_FILE


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise ServiceEnumerationError(
            f"{label} tidak ditemukan: {path}"
        )

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise ServiceEnumerationError(
            f"Gagal membaca {label}: {path}\n{exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ServiceEnumerationError(
            f"YAML {label} tidak valid: {path}\n{exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ServiceEnumerationError(
            f"Format {label} tidak valid: root harus berupa mapping."
        )

    return data


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump(
                data,
                handle,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except OSError as exc:
        raise ServiceEnumerationError(
            f"Gagal menulis: {path}\n{exc}"
        ) from exc


def record(
    action: str,
    status: str,
) -> None:
    """Write activity without making activity logging a hard dependency."""
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


def project_id_from_data(data: dict[str, Any]) -> str:
    return str(data.get("project_id", "")).strip()


def require_project_id(data: dict[str, Any], label: str) -> None:
    expected = project_root().name
    actual = project_id_from_data(data)

    if actual != expected:
        raise ServiceEnumerationError(
            f"Project ID pada {label} tidak sesuai active project. "
            f"Expected: {expected}; Found: {actual or '-'}"
        )


def nested_payload(
    data: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise ServiceEnumerationError(
            f"Field '{name}' pada dokumen tidak valid."
        )
    return value


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------

def load_network() -> dict[str, Any]:
    data = load_yaml(network_file(), "network.yaml")
    require_project_id(data, "network.yaml")

    network = nested_payload(data, "network")

    status = str(network.get("status", "")).strip().lower()
    if status != "completed":
        raise ServiceEnumerationError(
            "Reconnaissance network belum completed. "
            "Jalankan network.py terlebih dahulu."
        )

    ports = network.get("ports")
    if not isinstance(ports, list):
        raise ServiceEnumerationError(
            "Field network.ports pada network.yaml harus berupa list."
        )

    return data


def load_scope() -> dict[str, Any]:
    data = load_yaml(scope_file(), "scope.yaml")
    require_project_id(data, "scope.yaml")

    scope = data.get("scope")
    if not isinstance(scope, dict):
        raise ServiceEnumerationError(
            "Field 'scope' pada scope.yaml tidak valid."
        )

    in_scope = scope.get("in_scope")
    out_of_scope = scope.get("out_of_scope")

    if not isinstance(in_scope, list):
        raise ServiceEnumerationError(
            "Field scope.in_scope pada scope.yaml harus berupa list."
        )

    if not isinstance(out_of_scope, list):
        raise ServiceEnumerationError(
            "Field scope.out_of_scope pada scope.yaml harus berupa list."
        )

    return data


def target_from_network(
    network_data: dict[str, Any],
) -> dict[str, str]:
    network = nested_payload(network_data, "network")

    ipv4 = network.get("ipv4") or []
    hostname = str(network.get("hostname", "")).strip()
    target_url = str(network.get("target_url", "")).strip()

    if not isinstance(ipv4, list):
        ipv4 = []

    target_ip = next(
        (
            str(value).strip()
            for value in ipv4
            if str(value).strip()
        ),
        "",
    )

    if not target_ip:
        raise ServiceEnumerationError(
            "network.yaml tidak memiliki IPv4 target yang dapat digunakan."
        )

    return {
        "target_ip": target_ip,
        "hostname": hostname,
        "target_url": target_url,
        "application": str(network.get("application", "")).strip(),
        "environment": str(network.get("environment", "")).strip(),
        "assessment_type": str(
            network.get("assessment_type", "")
        ).strip(),
        "scope_reference": str(
            network.get("scope_reference", "")
        ).strip(),
    }


# ---------------------------------------------------------------------------
# Scope handling
# ---------------------------------------------------------------------------

def normalize_ports(value: Any) -> list[int]:
    """Normalize a scope ports value into unique valid TCP/UDP port numbers."""
    if value is None:
        return []

    if not isinstance(value, list):
        raise ServiceEnumerationError(
            "Field scope item 'ports' harus berupa list."
        )

    ports: set[int] = set()

    for raw in value:
        try:
            port = int(raw)
        except (TypeError, ValueError) as exc:
            raise ServiceEnumerationError(
                f"Port scope tidak valid: {raw!r}"
            ) from exc

        if not 1 <= port <= 65535:
            raise ServiceEnumerationError(
                f"Port scope di luar rentang 1-65535: {port}"
            )

        ports.add(port)

    return sorted(ports)


def normalize_protocols(value: Any) -> list[str]:
    if value is None:
        return []

    if not isinstance(value, list):
        raise ServiceEnumerationError(
            "Field scope item 'protocols' harus berupa list."
        )

    return sorted(
        {
            str(item).strip().lower()
            for item in value
            if str(item).strip()
        }
    )


def get_authorized_tcp_ports(
    scope_data: dict[str, Any],
) -> tuple[list[int], list[dict[str, Any]]]:
    """
    Return explicitly authorized TCP ports.

    Only ports declared in in_scope entries are authorized for active
    service enumeration. Ports discovered by Recon but absent from scope
    are never promoted into active testing.
    """
    scope = scope_data["scope"]
    items = scope["in_scope"]

    authorized: set[int] = set()
    references: list[dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue

        ports = normalize_ports(item.get("ports"))
        protocols = normalize_protocols(item.get("protocols"))

        # In preparation/scope, the "protocols" field describes the
        # application/service protocols (for example http/https), while
        # "ports" defines the authorized port numbers. For checklist 3-002,
        # the transport protocol being enumerated is TCP, so a scope item
        # with explicit ports is eligible even when its protocol values are
        # "http" / "https" rather than the literal string "tcp".
        #
        # Do not infer authorization from discovered Recon ports. The port
        # list in scope.yaml remains the authorization boundary.
        for port in ports:
            authorized.add(port)

        if ports:
            references.append(
                {
                    "scope_id": str(item.get("scope_id", "")).strip(),
                    "type": str(item.get("type", "")).strip(),
                    "value": str(item.get("value", "")).strip(),
                    "ports": ports,
                    "protocols": protocols,
                }
            )

    return sorted(authorized), references


def intersect_with_recon_ports(
    network_data: dict[str, Any],
    authorized_tcp_ports: list[int],
) -> tuple[list[int], list[int]]:
    """
    Return (ports_to_enumerate, authorized_but_not_observed_by_recon).

    The service module is not a second port scanner. Therefore a port must
    appear in both the explicit scope and the completed Recon network result.
    """
    network = nested_payload(network_data, "network")
    ports = network.get("ports")

    if not isinstance(ports, list):
        raise ServiceEnumerationError(
            "network.ports harus berupa list."
        )

    recon_tcp_open: set[int] = set()

    for item in ports:
        if not isinstance(item, dict):
            continue

        protocol = str(item.get("protocol", "")).strip().lower()
        state = str(item.get("state", "")).strip().lower()

        if protocol != "tcp" or state != "open":
            continue

        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue

        if 1 <= port <= 65535:
            recon_tcp_open.add(port)

    authorized = set(authorized_tcp_ports)

    return (
        sorted(authorized.intersection(recon_tcp_open)),
        sorted(authorized.difference(recon_tcp_open)),
    )


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------

def find_nmap() -> str:
    """
    Resolve nmap from PATH.

    No automatic download or installation is performed.
    """
    result = shutil.which(NMAP_EXECUTABLE)

    if result:
        return result

    raise ServiceEnumerationError(
        "Nmap tidak ditemukan di PATH. "
        "Pastikan Nmap sudah terpasang dan dapat dipanggil dengan "
        "'nmap --version'."
    )


def build_nmap_command(
    target_ip: str,
    ports: list[int],
    output_file: Path,
) -> list[str]:
    port_spec = ",".join(str(port) for port in ports)

    return [
        find_nmap(),
        "-Pn",
        "-sV",
        "--version-light",
        "--reason",
        "-p",
        port_spec,
        "-oX",
        str(output_file),
        target_ip,
    ]


def run_nmap(
    target_ip: str,
    ports: list[int],
) -> tuple[list[str], str, str]:
    evidence = nmap_evidence_file()
    evidence.parent.mkdir(parents=True, exist_ok=True)

    command = build_nmap_command(target_ip, ports, evidence)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=NMAP_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ServiceEnumerationError(
            f"Nmap service enumeration timeout setelah {NMAP_TIMEOUT} detik."
        ) from exc
    except OSError as exc:
        raise ServiceEnumerationError(
            f"Gagal menjalankan Nmap: {exc}"
        ) from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        detail = f"\n{stderr}" if stderr else ""
        raise ServiceEnumerationError(
            f"Nmap gagal dengan exit code {completed.returncode}.{detail}"
        )

    if not evidence.exists() or evidence.stat().st_size == 0:
        raise ServiceEnumerationError(
            "Nmap selesai tetapi file XML evidence tidak dibuat."
        )

    return command, completed.stdout.strip(), completed.stderr.strip()


# ---------------------------------------------------------------------------
# Nmap XML parser
# ---------------------------------------------------------------------------

def parse_nmap_xml(path: Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ServiceEnumerationError(
            f"Gagal membaca hasil Nmap XML: {path}\n{exc}"
        ) from exc

    results: list[dict[str, Any]] = []

    for host in root.findall("host"):
        address = host.find("address")
        host_ip = ""
        if address is not None:
            host_ip = str(address.get("addr", "")).strip()

        ports_node = host.find("ports")
        if ports_node is None:
            continue

        for port_node in ports_node.findall("port"):
            protocol = str(port_node.get("protocol", "")).strip().lower()

            try:
                port = int(port_node.get("portid", "0"))
            except ValueError:
                continue

            state_node = port_node.find("state")
            state = (
                str(state_node.get("state", "")).strip().lower()
                if state_node is not None
                else ""
            )

            service_node = port_node.find("service")

            service_name = ""
            product = ""
            version = ""
            extra_info = ""
            method = ""

            if service_node is not None:
                service_name = str(
                    service_node.get("name", "")
                ).strip()
                product = str(
                    service_node.get("product", "")
                ).strip()
                version = str(
                    service_node.get("version", "")
                ).strip()
                extra_info = str(
                    service_node.get("extrainfo", "")
                ).strip()
                method = str(
                    service_node.get("method", "")
                ).strip()

            reason = ""
            if state_node is not None:
                reason = str(
                    state_node.get("reason", "")
                ).strip()

            results.append(
                {
                    "host": host_ip,
                    "port": port,
                    "protocol": protocol,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "extra_info": extra_info,
                    "version_detection_method": method,
                    "state_reason": reason,
                }
            )

    return sorted(
        results,
        key=lambda item: (
            str(item.get("host", "")),
            int(item.get("port", 0)),
            str(item.get("protocol", "")),
        ),
    )


# ---------------------------------------------------------------------------
# Document handling
# ---------------------------------------------------------------------------

def empty_document(
    network_data: dict[str, Any],
    scope_data: dict[str, Any],
) -> dict[str, Any]:
    target = target_from_network(network_data)
    authorized_ports, scope_refs = get_authorized_tcp_ports(scope_data)
    ports_to_enumerate, missing_from_recon = intersect_with_recon_ports(
        network_data,
        authorized_ports,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "service": {
            "status": "not-started",
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": target["application"],
            "target_url": target["target_url"],
            "hostname": target["hostname"],
            "target_ip": target["target_ip"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_reference": target["scope_reference"],
            "source_network": (
                "02-reconnaissance/network/network.yaml"
            ),
            "source_scope": (
                "01-preparation/scope/scope.yaml"
            ),
            "method": "nmap -sV --version-light",
            "authorized_tcp_ports": authorized_ports,
            "recon_open_tcp_ports": [],
            "ports_to_enumerate": ports_to_enumerate,
            "authorized_not_observed_by_recon": missing_from_recon,
            "scope_items": scope_refs,
            "nmap": {
                "tool": "nmap",
                "command": "",
                "started_at": "",
                "completed_at": "",
                "exit_code": None,
                "evidence": "",
            },
            "results": [],
            "summary": {
                "authorized_ports": len(authorized_ports),
                "ports_enumerated": len(ports_to_enumerate),
                "services_found": 0,
                "open_services": 0,
                "filtered_or_other": 0,
            },
            "notes": "",
            "enumerated_at": "",
        },
    }


def load_service() -> dict[str, Any]:
    data = load_yaml(service_file(), "service.yaml")

    require_project_id(data, "service.yaml")

    service = nested_payload(data, "service")

    status = str(service.get("status", "")).strip().lower()
    if status not in VALID_STATUSES:
        raise ServiceEnumerationError(
            f"Status service tidak valid: {status or '-'}"
        )

    return data


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init() -> int:
    network_data = load_network()
    scope_data = load_scope()

    path = service_file()

    service_dir().mkdir(parents=True, exist_ok=True)
    evidence_dir().mkdir(parents=True, exist_ok=True)

    data = empty_document(network_data, scope_data)
    save_yaml(path, data)

    record(
        "Service enumeration initialized",
        "in-progress",
    )

    service = data["service"]

    print("[PASS] Service Enumeration berhasil diinisialisasi.")
    print(f"PROJECT: {project_root().name}")
    print(f"TARGET : {service['target_ip']}")
    print(
        "AUTHORIZED TCP PORTS: "
        + (
            ", ".join(map(str, service["authorized_tcp_ports"]))
            if service["authorized_tcp_ports"]
            else "-"
        )
    )
    print(
        "PORTS TO ENUMERATE: "
        + (
            ", ".join(map(str, service["ports_to_enumerate"]))
            if service["ports_to_enumerate"]
            else "-"
        )
    )
    print(f"FILE   : {path}")

    return 0


def cmd_enumerate() -> int:
    network_data = load_network()
    scope_data = load_scope()

    data = load_service()
    service = data["service"]

    authorized_ports, scope_refs = get_authorized_tcp_ports(scope_data)
    ports_to_enumerate, missing_from_recon = intersect_with_recon_ports(
        network_data,
        authorized_ports,
    )

    target = target_from_network(network_data)

    service["authorized_tcp_ports"] = authorized_ports
    service["ports_to_enumerate"] = ports_to_enumerate
    service["authorized_not_observed_by_recon"] = missing_from_recon
    service["scope_items"] = scope_refs
    service["target_ip"] = target["target_ip"]
    service["hostname"] = target["hostname"]
    service["target_url"] = target["target_url"]
    service["updated_at"] = now_iso()

    # Record the TCP ports seen by Recon for traceability.
    network = network_data["network"]
    recon_ports: list[int] = []

    for item in network.get("ports", []):
        if not isinstance(item, dict):
            continue

        if (
            str(item.get("protocol", "")).lower() == "tcp"
            and str(item.get("state", "")).lower() == "open"
        ):
            try:
                recon_ports.append(int(item.get("port")))
            except (TypeError, ValueError):
                continue

    service["recon_open_tcp_ports"] = sorted(set(recon_ports))

    if not authorized_ports:
        service["status"] = "blocked"
        service["notes"] = (
            "Tidak ada port TCP yang secara eksplisit tercantum "
            "sebagai in-scope. Service enumeration tidak dijalankan."
        )
        save_yaml(service_file(), data)

        record(
            "Service enumeration blocked: no authorized TCP ports",
            "blocked",
        )

        print("[BLOCKED] Tidak ada port TCP in-scope untuk service enumeration.")
        return 1

    if not ports_to_enumerate:
        service["status"] = "completed"
        service["nmap"]["command"] = ""
        service["nmap"]["started_at"] = ""
        service["nmap"]["completed_at"] = ""
        service["nmap"]["exit_code"] = 0
        service["nmap"]["evidence"] = ""
        service["results"] = []
        service["summary"] = {
            "authorized_ports": len(authorized_ports),
            "ports_enumerated": 0,
            "services_found": 0,
            "open_services": 0,
            "filtered_or_other": 0,
        }
        service["notes"] = (
            "Tidak ada port yang sekaligus authorized dan terobservasi "
            "open oleh Recon. Tidak dilakukan port scanning ulang."
        )
        service["enumerated_at"] = now_iso()

        save_yaml(service_file(), data)

        record(
            "Service enumeration completed: no eligible Recon ports",
            "completed",
        )

        print("[PASS] Service Enumeration selesai.")
        print("PORTS TO ENUMERATE: -")
        print("STATUS: completed")
        return 0

    service["status"] = "in-progress"
    save_yaml(service_file(), data)

    started_at = now_iso()

    try:
        command, stdout, stderr = run_nmap(
            target["target_ip"],
            ports_to_enumerate,
        )

        completed_at = now_iso()

        results = parse_nmap_xml(nmap_evidence_file())

        open_services = sum(
            1
            for item in results
            if str(item.get("state", "")).lower() == "open"
        )

        filtered_or_other = len(results) - open_services

        service["status"] = "completed"
        service["nmap"] = {
            "tool": "nmap",
            "command": " ".join(command),
            "started_at": started_at,
            "completed_at": completed_at,
            "exit_code": 0,
            "evidence": str(
                nmap_evidence_file().relative_to(project_root())
            ),
        }
        service["results"] = results
        service["summary"] = {
            "authorized_ports": len(authorized_ports),
            "ports_enumerated": len(ports_to_enumerate),
            "services_found": len(results),
            "open_services": open_services,
            "filtered_or_other": filtered_or_other,
        }
        service["notes"] = (
            "Service enumeration menggunakan hasil Recon sebagai baseline. "
            "Hanya port yang eksplisit in-scope dan sudah terobservasi open "
            "oleh Recon yang diprobe dengan Nmap -sV."
        )
        if stdout:
            service["notes"] += (
                " Nmap stdout tersedia hanya pada proses eksekusi dan "
                "tidak disimpan sebagai response body."
            )
        if stderr:
            service["notes"] += " Nmap menghasilkan diagnostic stderr."

        service["enumerated_at"] = completed_at
        save_yaml(service_file(), data)

        record(
            "Service enumeration completed",
            "completed",
        )

        print("[PASS] Service Enumeration berhasil.")
        print(f"TARGET : {target['target_ip']}")
        print(
            "PORTS  : "
            + ", ".join(map(str, ports_to_enumerate))
        )
        print(f"SERVICES: {len(results)}")
        print(f"STATUS : {service['status']}")
        print(f"FILE   : {service_file()}")

        return 0

    except Exception as exc:
        service["status"] = "failed"
        service["nmap"] = {
            "tool": "nmap",
            "command": "",
            "started_at": started_at,
            "completed_at": now_iso(),
            "exit_code": None,
            "evidence": (
                str(nmap_evidence_file().relative_to(project_root()))
                if nmap_evidence_file().exists()
                else ""
            ),
        }
        service["notes"] = f"Service enumeration gagal: {exc}"
        service["enumerated_at"] = now_iso()
        save_yaml(service_file(), data)

        record(
            "Service enumeration failed",
            "failed",
        )

        print(f"[FAIL] Service Enumeration gagal: {exc}")
        return 1


def cmd_list() -> int:
    data = load_service()
    service = data["service"]
    results = service.get("results") or []

    print(f"PROJECT: {data.get('project_id', '-')}")
    print(f"STATUS : {service.get('status', '-')}")
    print(f"TARGET : {service.get('target_ip', '-')}")
    print()

    if not results:
        print("[none]")
        return 0

    print(
        f"{'PORT':<7}"
        f"{'PROTO':<8}"
        f"{'STATE':<10}"
        f"{'SERVICE':<18}"
        f"{'PRODUCT':<28}"
        f"VERSION"
    )
    print("-" * 100)

    for item in results:
        print(
            f"{str(item.get('port', '-')):<7}"
            f"{str(item.get('protocol', '-')):<8}"
            f"{str(item.get('state', '-')):<10}"
            f"{str(item.get('service', '-')):<18}"
            f"{str(item.get('product', '-')):<28}"
            f"{str(item.get('version', '-'))}"
        )

    return 0


def cmd_show() -> int:
    data = load_service()

    print(f"PROJECT: {data.get('project_id', '-')}")
    print(f"FILE   : {service_file()}")
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


def cmd_status() -> int:
    data = load_service()
    service = data["service"]
    summary = service.get("summary") or {}

    print(f"Project ID        : {data.get('project_id', '-')}")
    print(f"Status             : {service.get('status', '-')}")
    print(f"Target IP          : {service.get('target_ip', '-')}")
    print(f"Hostname           : {service.get('hostname', '-')}")
    print(
        "Authorized TCP     : "
        + (
            ", ".join(
                map(str, service.get("authorized_tcp_ports") or [])
            )
            or "-"
        )
    )
    print(
        "Ports enumerated   : "
        + (
            ", ".join(
                map(str, service.get("ports_to_enumerate") or [])
            )
            or "-"
        )
    )
    print(
        f"Services found     : {summary.get('services_found', 0)}"
    )
    print(
        f"Open services      : {summary.get('open_services', 0)}"
    )
    print(
        f"Filtered/other     : {summary.get('filtered_or_other', 0)}"
    )
    print(f"Evidence           : {service.get('nmap', {}).get('evidence', '-')}")
    print(f"File               : {service_file()}")

    missing = service.get("authorized_not_observed_by_recon") or []
    if missing:
        print()
        print(
            "Authorized but not observed open by Recon: "
            + ", ".join(map(str, missing))
        )

    return 0


def cmd_verify() -> int:
    data = load_service()
    service = data["service"]

    errors: list[str] = []

    if service.get("checklist_id") != CHECKLIST_ID:
        errors.append("Checklist ID tidak sesuai 3-002.")

    status = str(service.get("status", "")).strip().lower()
    if status != "completed":
        errors.append(
            f"Status service belum completed: {status or '-'}"
        )

    authorized = service.get("authorized_tcp_ports")
    if not isinstance(authorized, list):
        errors.append(
            "authorized_tcp_ports harus berupa list."
        )

    ports = service.get("ports_to_enumerate")
    if not isinstance(ports, list):
        errors.append(
            "ports_to_enumerate harus berupa list."
        )

    results = service.get("results")
    if not isinstance(results, list):
        errors.append("results harus berupa list.")

    nmap = service.get("nmap")
    if not isinstance(nmap, dict):
        errors.append("Field nmap tidak valid.")
    else:
        if not str(nmap.get("command", "")).strip() and ports:
            errors.append(
                "Command Nmap tidak tercatat."
            )

        evidence = str(nmap.get("evidence", "")).strip()
        if ports and (
            not evidence
            or not (project_root() / evidence).exists()
        ):
            errors.append(
                "Evidence Nmap tidak ditemukan."
            )

    if isinstance(results, list):
        for index, item in enumerate(results, start=1):
            if not isinstance(item, dict):
                errors.append(
                    f"Result #{index} bukan mapping."
                )
                continue

            for field in (
                "port",
                "protocol",
                "state",
                "service",
            ):
                if field not in item:
                    errors.append(
                        f"Result #{index} tidak memiliki field '{field}'."
                    )

            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                errors.append(
                    f"Result #{index} memiliki port tidak valid."
                )
            else:
                if not 1 <= port <= 65535:
                    errors.append(
                        f"Result #{index} memiliki port di luar rentang."
                    )

            if str(item.get("protocol", "")).lower() != "tcp":
                errors.append(
                    f"Result #{index} bukan hasil TCP service enumeration."
                )

    if errors:
        print("[FAIL] Service Enumeration belum memenuhi validasi.")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("[PASS] Service Enumeration memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {status}")
    print(f"[PASS] Target    : {service.get('target_ip', '-')}")
    print(
        f"[PASS] Ports     : "
        f"{len(service.get('ports_to_enumerate') or [])}"
    )
    print(
        f"[PASS] Services  : "
        f"{len(service.get('results') or [])}"
    )

    record(
        "Service enumeration verified",
        "completed",
    )

    return 0


def cmd_remove() -> int:
    path = service_dir()

    if not path.exists():
        print("[INFO] Service Enumeration belum ada.")
        return 0

    confirm = input(
        "Hapus seluruh data Service Enumeration untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(path)

    record(
        "Service enumeration data removed",
        "completed",
    )

    print("[PASS] Service Enumeration berhasil dihapus.")
    return 0


def cmd_version() -> int:
    print(
        f"BrebesKab-CSIRT-Tools service.py v{SCRIPT_VERSION}"
    )
    print(
        f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : Nmap -sV --version-light")
    print("Baseline : 02-reconnaissance/network/network.yaml")
    print("Scope    : 01-preparation/scope/scope.yaml")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Infrastructure Service Enumeration\n"
        "\n"
        "Checklist:\n"
        "  3-002 Service enumeration\n"
        "\n"
        "Usage:\n"
        "  python scripts/infrastructure/service.py init\n"
        "  python scripts/infrastructure/service.py enumerate\n"
        "  python scripts/infrastructure/service.py list\n"
        "  python scripts/infrastructure/service.py show\n"
        "  python scripts/infrastructure/service.py verify\n"
        "  python scripts/infrastructure/service.py status\n"
        "  python scripts/infrastructure/service.py remove\n"
        "  python scripts/infrastructure/service.py version\n"
        "\n"
        "Design:\n"
        "  - Uses Recon network.yaml as the port baseline.\n"
        "  - Uses preparation scope.yaml as the authorization boundary.\n"
        "  - Does not scan discovered out-of-scope ports.\n"
        "  - Does not perform vulnerability NSE scripts.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Infrastructure Service Enumeration - checklist 3-002",
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="help",
        choices=(
            "init",
            "enumerate",
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
        if args.command in {"help"}:
            print_help()
            return 0

        if args.command == "init":
            return cmd_init()

        if args.command == "enumerate":
            return cmd_enumerate()

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

        raise ServiceEnumerationError(
            f"Command tidak dikenal: {args.command}"
        )

    except ServiceEnumerationError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Dibatalkan oleh pengguna.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
