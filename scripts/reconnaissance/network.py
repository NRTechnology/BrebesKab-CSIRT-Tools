#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - IP / Network

Version: 1.0.0

Checklist mapping:
    02-003 - IP / Network

Purpose:
    Record and verify network/IP information discovered for the active
    pentest project.

Design:
    - "init" reads the completed DNS reconnaissance document once and
      creates network.yaml.
    - After "init", this module uses network.yaml as its own state file.
    - "resolve" performs basic IP/network discovery for the target
      hostname using the system resolver.
    - "scan" optionally performs a controlled TCP port discovery using
      Nmap for the in-scope target IP.
    - No vulnerability testing is performed by this module.
    - No credentials, tokens, or sensitive application data are stored.

Storage:
    projects/<PROJECT-ID>/02-reconnaissance/network/network.yaml
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from activity import ActivityError, record_activity
from context import ContextError, ProjectContext, require_active_project


SCRIPT_VERSION = "1.0.0"

RECON_DIR_NAME = "02-reconnaissance"
DNS_DIR_NAME = "dns"
DNS_FILE_NAME = "dns.yaml"
NETWORK_DIR_NAME = "network"
NETWORK_FILE_NAME = "network.yaml"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
}


class NetworkError(RuntimeError):
    """Raised when network reconnaissance cannot be completed."""


def dns_file(context: ProjectContext) -> Path:
    """Return the upstream DNS reconnaissance file."""
    return (
        context.project_path
        / RECON_DIR_NAME
        / DNS_DIR_NAME
        / DNS_FILE_NAME
    )


def network_dir(context: ProjectContext) -> Path:
    """Return the network reconnaissance directory."""
    return context.project_path / RECON_DIR_NAME / NETWORK_DIR_NAME


def network_file(context: ProjectContext) -> Path:
    """Return the network reconnaissance YAML path."""
    return network_dir(context) / NETWORK_FILE_NAME


def _now() -> str:
    """Return current local timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    """Return the initial network reconnaissance document."""
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "network": {
            "status": "not-started",
            "application": "",
            "target_url": "",
            "hostname": "",
            "scheme": "",
            "port": "",
            "environment": "",
            "assessment_type": "",
            "scope_reference": "01-preparation/scope/scope.yaml",
            "ipv4": [],
            "ipv6": [],
            "network_ranges": [],
            "ports": [],
            "port_scan": {
                "status": "not-run",
                "tool": "",
                "command": "",
                "started_at": "",
                "completed_at": "",
            },
            "notes": "",
        },
    }


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    """Load a YAML mapping."""
    if not path.is_file():
        raise NetworkError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise NetworkError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise NetworkError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise NetworkError(f"Format {path.name} harus berupa mapping/object.")

    return data


def _load_dns_source(context: ProjectContext) -> dict[str, Any]:
    """
    Load the completed DNS document as the upstream source for init.

    dns.yaml is read only during initialization. After init succeeds,
    network.yaml becomes this module's own configuration/state file.
    """
    path = dns_file(context)
    data = _load_yaml(path, "DNS reconnaissance")

    if data.get("project_id") != context.project_id:
        raise NetworkError(
            "Project ID pada dns.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    dns = data.get("dns")
    if not isinstance(dns, dict):
        raise NetworkError(
            "Field 'dns' pada dns.yaml harus berupa mapping/object."
        )

    status = str(dns.get("status", "")).strip().lower()

    if status != "completed":
        raise NetworkError(
            "DNS / Domain belum completed.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/dns.py verify"
        )

    required_fields = {
        "application": dns.get("application"),
        "target_url": dns.get("target_url"),
        "hostname": dns.get("hostname"),
        "scheme": dns.get("scheme"),
        "port": dns.get("port"),
        "environment": dns.get("environment"),
        "assessment_type": dns.get("assessment_type"),
        "scope_reference": dns.get("scope_reference"),
    }

    missing = [
        name
        for name, value in required_fields.items()
        if not isinstance(value, str) or not value.strip()
    ]

    if missing:
        raise NetworkError(
            "DNS / Domain belum lengkap. Field kosong: "
            + ", ".join(missing)
        )

    ipv4 = dns.get("ipv4", [])
    ipv6 = dns.get("ipv6", [])

    if not isinstance(ipv4, list):
        raise NetworkError("Field 'ipv4' pada dns.yaml harus berupa list.")

    if not isinstance(ipv6, list):
        raise NetworkError("Field 'ipv6' pada dns.yaml harus berupa list.")

    if not ipv4 and not ipv6:
        raise NetworkError(
            "DNS / Domain tidak memiliki alamat IPv4/IPv6. "
            "Jalankan DNS resolution terlebih dahulu."
        )

    return data


def _build_from_dns(
    context: ProjectContext,
    dns_data: dict[str, Any],
) -> dict[str, Any]:
    """Build network.yaml from the completed DNS document."""
    dns = dns_data["dns"]
    data = _empty_document(context)

    data["network"].update(
        {
            "status": "not-started",
            "application": str(dns["application"]).strip(),
            "target_url": str(dns["target_url"]).strip(),
            "hostname": str(dns["hostname"]).strip().rstrip("."),
            "scheme": str(dns["scheme"]).strip().lower(),
            "port": str(dns["port"]).strip(),
            "environment": str(dns["environment"]).strip(),
            "assessment_type": str(dns["assessment_type"]).strip(),
            "scope_reference": str(
                dns["scope_reference"]
            ).strip(),
            "ipv4": _unique_strings(dns.get("ipv4", [])),
            "ipv6": _unique_strings(dns.get("ipv6", [])),
            "network_ranges": [],
            "ports": [],
            "port_scan": {
                "status": "not-run",
                "tool": "",
                "command": "",
                "started_at": "",
                "completed_at": "",
            },
            "notes": "",
        }
    )

    return data


def _load_network(context: ProjectContext) -> dict[str, Any]:
    """Load and validate network.yaml."""
    path = network_file(context)

    if not path.is_file():
        raise NetworkError(
            f"Network configuration belum tersedia: {path}\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/network.py init"
        )

    data = _load_yaml(path, "Network configuration")

    if data.get("project_id") != context.project_id:
        raise NetworkError(
            "Project ID pada network.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    network = data.get("network")

    if not isinstance(network, dict):
        raise NetworkError(
            "Field 'network' pada network.yaml harus berupa mapping/object."
        )

    defaults = _empty_document(context)["network"]

    for key, value in defaults.items():
        if key not in network:
            network[key] = value

    status = str(network.get("status", "not-started")).strip().lower()

    if status not in VALID_STATUSES:
        raise NetworkError(
            f"Status network tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data["network"] = network
    return data


def _save_network(
    context: ProjectContext,
    data: dict[str, Any],
) -> Path:
    """Save network.yaml."""
    directory = network_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = network_file(context)

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
        raise NetworkError(f"Gagal menulis: {path}\n{exc}") from exc

    return path


def initialize(
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    """
    Initialize network.yaml from completed dns.yaml.
    """
    if context is None:
        context = require_active_project()

    dns_data = _load_dns_source(context)
    data = _build_from_dns(context, dns_data)

    return _save_network(context, data)


def _unique_strings(values: list[Any]) -> list[str]:
    """Return unique non-empty strings while preserving order."""
    result: list[str] = []

    for value in values:
        value = str(value).strip()

        if value and value not in result:
            result.append(value)

    return result


def _validate_ip_list(
    values: Any,
    version: int,
    field_name: str,
) -> list[str]:
    """Validate and normalize an IP address list."""
    if not isinstance(values, list):
        raise NetworkError(f"{field_name} harus berupa list.")

    result: list[str] = []

    for value in values:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError as exc:
            raise NetworkError(
                f"Alamat IP tidak valid pada {field_name}: {value}"
            ) from exc

        if address.version != version:
            raise NetworkError(
                f"Alamat pada {field_name} bukan IPv{version}: {value}"
            )

        result.append(str(address))

    return _unique_strings(result)


def _discover_local_networks() -> list[str]:
    """
    Discover local interface networks where practical.

    Windows does not expose a portable interface/CIDR API through the
    Python standard library, so this function intentionally returns an
    empty list instead of guessing a network range.

    Network ranges can later be populated by an explicit network
    discovery implementation without changing the document structure.
    """
    return []


def _reverse_lookup(ip_address: str) -> str:
    """Perform a basic reverse DNS lookup for one IP address."""
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip_address)
        return str(hostname).rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""


def discover(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """
    Perform basic IP/network discovery from the hostname stored in
    network.yaml.

    This does not run vulnerability tests.
    """
    if context is None:
        context = require_active_project()

    data = _load_network(context)
    network = data["network"]

    hostname = str(network.get("hostname", "")).strip().rstrip(".")

    if not hostname:
        raise NetworkError(
            "Hostname belum tersedia pada network.yaml.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/network.py init"
        )

    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise NetworkError(
            f"IP discovery gagal untuk '{hostname}': {exc}"
        ) from exc
    except OSError as exc:
        raise NetworkError(
            f"IP discovery gagal untuk '{hostname}': {exc}"
        ) from exc

    ipv4: list[str] = []
    ipv6: list[str] = []

    for family, _socktype, _proto, _canonname, sockaddr in infos:
        address = str(sockaddr[0]).strip()

        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue

        if family == socket.AF_INET and parsed.version == 4:
            ipv4.append(str(parsed))
        elif family == socket.AF_INET6 and parsed.version == 6:
            ipv6.append(str(parsed))

    ipv4 = _unique_strings(ipv4)
    ipv6 = _unique_strings(ipv6)

    if not ipv4 and not ipv6:
        raise NetworkError(
            f"Tidak ditemukan alamat IPv4/IPv6 untuk '{hostname}'."
        )

    network["ipv4"] = ipv4
    network["ipv6"] = ipv6

    # Reverse DNS is informational only. It does not alter the target.
    reverse_dns: dict[str, str] = {}

    for address in ipv4 + ipv6:
        reverse = _reverse_lookup(address)

        if reverse:
            reverse_dns[address] = reverse

    if reverse_dns:
        notes = network.get("notes", "").strip()

        reverse_text = "; ".join(
            f"{address} -> {hostname}"
            for address, hostname in reverse_dns.items()
        )

        if notes:
            network["notes"] = f"{notes} Reverse DNS: {reverse_text}"
        else:
            network["notes"] = f"Reverse DNS: {reverse_text}"

    network["network_ranges"] = _discover_local_networks()
    network["status"] = "in-progress"

    _save_network(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-003",
            action=(
                f"IP / Network discovery recorded: {hostname} "
                f"(IPv4={len(ipv4)}, IPv6={len(ipv6)})"
            ),
            status="in-progress",
            context=context,
        )
    except ActivityError as exc:
        raise NetworkError(
            f"Network discovery berhasil disimpan, "
            f"tetapi activity gagal dicatat.\n{exc}"
        ) from exc

    return data


def _find_nmap() -> Optional[str]:
    """Return nmap executable name when available."""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode == 0:
        return "nmap"

    return None


def scan_ports(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """
    Perform controlled TCP port discovery with Nmap.

    The scan is limited to the target IPs already recorded in
    network.yaml. It does not perform vulnerability scripts.
    """
    if context is None:
        context = require_active_project()

    data = _load_network(context)
    network = data["network"]

    ipv4 = _validate_ip_list(
        network.get("ipv4", []),
        4,
        "ipv4",
    )

    if not ipv4:
        raise NetworkError(
            "Belum ada IPv4 target.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/network.py discover"
        )

    nmap = _find_nmap()

    if not nmap:
        raise NetworkError(
            "Nmap tidak ditemukan pada PATH."
        )

    target = ipv4[0]
    command = [
        nmap,
        "-Pn",
        "--top-ports",
        "100",
        "--open",
        target,
    ]

    started_at = _now()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NetworkError(
            f"Nmap timeout setelah 120 detik untuk {target}."
        ) from exc
    except OSError as exc:
        raise NetworkError(f"Gagal menjalankan Nmap: {exc}") from exc

    completed_at = _now()

    if result.returncode != 0:
        raise NetworkError(
            "Nmap gagal dijalankan.\n"
            + (result.stderr.strip() or result.stdout.strip())
        )

    ports: list[dict[str, Any]] = []

    for line in result.stdout.splitlines():
        line = line.strip()

        if not line:
            continue

        # Typical Nmap line:
        # 443/tcp open https
        parts = line.split()

        if len(parts) < 2:
            continue

        port_protocol = parts[0]
        state = parts[1]

        if "/" not in port_protocol or state != "open":
            continue

        port_number, protocol = port_protocol.split("/", 1)

        if not port_number.isdigit():
            continue

        service = parts[2] if len(parts) >= 3 else ""

        ports.append(
            {
                "port": int(port_number),
                "protocol": protocol,
                "state": state,
                "service": service,
            }
        )

    network["ports"] = ports
    network["port_scan"] = {
        "status": "completed",
        "tool": "nmap",
        "command": " ".join(command),
        "started_at": started_at,
        "completed_at": completed_at,
    }
    network["status"] = "in-progress"

    _save_network(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-003",
            action=(
                f"TCP port discovery recorded with Nmap: "
                f"{target} ({len(ports)} open ports)"
            ),
            status="in-progress",
            context=context,
        )
    except ActivityError as exc:
        raise NetworkError(
            f"Port discovery berhasil disimpan, "
            f"tetapi activity gagal dicatat.\n{exc}"
        ) from exc

    return data


def validate(
    *,
    context: Optional[ProjectContext] = None,
) -> list[str]:
    """Validate minimum IP/network reconnaissance information."""
    if context is None:
        context = require_active_project()

    data = _load_network(context)
    network = data["network"]
    errors: list[str] = []

    required_fields = {
        "application": network.get("application"),
        "target_url": network.get("target_url"),
        "hostname": network.get("hostname"),
        "scheme": network.get("scheme"),
        "port": network.get("port"),
        "environment": network.get("environment"),
        "assessment_type": network.get("assessment_type"),
        "scope_reference": network.get("scope_reference"),
    }

    for field, value in required_fields.items():
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} belum diisi.")

    if network.get("scheme") not in {"http", "https"}:
        errors.append("scheme harus berupa http atau https.")

    if not str(network.get("port", "")).isdigit():
        errors.append("port harus berupa angka.")

    try:
        ipv4 = _validate_ip_list(network.get("ipv4", []), 4, "ipv4")
    except NetworkError as exc:
        errors.append(str(exc))
        ipv4 = []

    try:
        ipv6 = _validate_ip_list(network.get("ipv6", []), 6, "ipv6")
    except NetworkError as exc:
        errors.append(str(exc))
        ipv6 = []

    if not ipv4 and not ipv6:
        errors.append("Minimal satu alamat IPv4 atau IPv6 harus tersedia.")

    ports = network.get("ports")

    if not isinstance(ports, list):
        errors.append("ports harus berupa list.")

    return errors


def verify(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Verify IP/network reconnaissance and mark it completed."""
    if context is None:
        context = require_active_project()

    errors = validate(context=context)

    if errors:
        raise NetworkError(
            "IP / Network reconnaissance belum lengkap:\n"
            + "\n".join(f"- {error}" for error in errors)
        )

    data = _load_network(context)
    data["network"]["status"] = "completed"

    _save_network(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-003",
            action="IP / Network reconnaissance verified",
            status="completed",
            context=context,
        )
    except ActivityError as exc:
        raise NetworkError(
            f"Network berhasil diverifikasi, "
            f"tetapi activity gagal dicatat.\n{exc}"
        ) from exc

    return data


def set_status(
    status: str,
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Set IP/network reconnaissance lifecycle status."""
    if context is None:
        context = require_active_project()

    normalized = status.strip().lower()

    if normalized not in VALID_STATUSES:
        raise NetworkError(
            f"Status tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data = _load_network(context)
    data["network"]["status"] = normalized
    _save_network(context, data)

    record_activity(
        phase="02-reconnaissance",
        item="02-003",
        action=f"IP / Network status changed to {normalized}",
        status="completed" if normalized == "completed" else "in-progress",
        context=context,
    )


def remove(
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Remove network.yaml."""
    if context is None:
        context = require_active_project()

    path = network_file(context)

    if not path.is_file():
        return False

    try:
        path.unlink()
    except OSError as exc:
        raise NetworkError(f"Gagal menghapus: {path}\n{exc}") from exc

    record_activity(
        phase="02-reconnaissance",
        item="02-003",
        action="IP / Network reconnaissance removed",
        status="completed",
        context=context,
    )

    return True


def print_summary(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print a concise IP/network summary."""
    if context is None:
        context = require_active_project()

    data = _load_network(context)
    network = data["network"]

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Reconnaissance IP / Network")
    print("=" * 72)
    print(f"Project ID       : {context.project_id}")
    print(f"Status           : {network.get('status', '')}")
    print(f"Application      : {network.get('application', '')}")
    print(f"Target URL       : {network.get('target_url', '')}")
    print(f"Hostname         : {network.get('hostname', '')}")
    print(f"Scheme           : {network.get('scheme', '')}")
    print(f"Port             : {network.get('port', '')}")
    print(f"Environment      : {network.get('environment', '')}")
    print(f"Assessment Type  : {network.get('assessment_type', '')}")
    print(f"IPv4             : {', '.join(network.get('ipv4', [])) or '-'}")
    print(f"IPv6             : {', '.join(network.get('ipv6', [])) or '-'}")
    print(
        f"Network Ranges   : "
        f"{', '.join(network.get('network_ranges', [])) or '-'}"
    )
    print(f"Open Ports       : {len(network.get('ports', []))}")
    print(
        f"Port Scan        : "
        f"{network.get('port_scan', {}).get('status', '-')}"
    )
    print(f"Scope Reference  : {network.get('scope_reference', '')}")
    print(f"File             : {network_file(context)}")


def print_full(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print the complete network document."""
    if context is None:
        context = require_active_project()

    data = _load_network(context)

    print(f"PROJECT: {context.project_id}")
    print(f"FILE   : {network_file(context)}")
    print()
    _print_value(data["network"])


def _print_value(value: Any, indent: int = 0) -> None:
    """Print nested YAML-like values."""
    prefix = " " * indent

    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print(f"{prefix}{key}:")
                _print_value(item, indent + 2)
            else:
                print(f"{prefix}{key}: {item}")

    elif isinstance(value, list):
        if not value:
            print(f"{prefix}[none]")
        else:
            for item in value:
                if isinstance(item, dict):
                    print(f"{prefix}-")
                    _print_value(item, indent + 2)
                else:
                    print(f"{prefix}- {item}")

    else:
        print(f"{prefix}{value}")


def print_help() -> None:
    """Print CLI help."""
    print(
        "Reconnaissance IP / Network\n"
        "\n"
        "Usage:\n"
        "  python scripts/reconnaissance/network.py init\n"
        "  python scripts/reconnaissance/network.py discover\n"
        "  python scripts/reconnaissance/network.py scan\n"
        "  python scripts/reconnaissance/network.py list\n"
        "  python scripts/reconnaissance/network.py show\n"
        "  python scripts/reconnaissance/network.py verify\n"
        "  python scripts/reconnaissance/network.py status\n"
        "  python scripts/reconnaissance/network.py remove\n"
        "  python scripts/reconnaissance/network.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
        "\n"
        "init      Read completed dns.yaml and create network.yaml.\n"
        "discover  Discover target IP addresses from network.yaml.\n"
        "scan      Run controlled Nmap TCP top-100 port discovery.\n"
        "list      Show a concise network reconnaissance summary.\n"
        "show      Show the complete network reconnaissance document.\n"
        "verify    Validate the network reconnaissance and mark completed.\n"
        "status    Show the current lifecycle status.\n"
        "remove    Remove network.yaml.\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    """Command-line entry point."""
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = args[0].lower()

    if command == "version":
        print(f"BrebesKab-CSIRT-Tools network.py v{SCRIPT_VERSION}")
        return 0

    try:
        context = require_active_project()

        if command == "init":
            path = initialize(context=context)
            print("[PASS] Network configuration siap dari DNS / Domain.")
            print(f"File: {path}")
            return 0

        if command in ("discover", "resolve"):
            data = discover(context=context)
            network = data["network"]

            print("[PASS] IP / Network discovery berhasil.")
            print(f"Hostname : {network.get('hostname', '')}")
            print(
                f"IPv4     : "
                f"{', '.join(network.get('ipv4', [])) or '-'}"
            )
            print(
                f"IPv6     : "
                f"{', '.join(network.get('ipv6', [])) or '-'}"
            )
            return 0

        if command == "scan":
            data = scan_ports(context=context)
            ports = data["network"].get("ports", [])

            print("[PASS] TCP port discovery berhasil.")
            print(f"Target   : {data['network'].get('ipv4', ['-'])[0]}")
            print(f"Open     : {len(ports)}")

            for item in ports:
                print(
                    f"  {item['port']}/{item['protocol']} "
                    f"{item['service']}".rstrip()
                )

            return 0

        if command == "list":
            print_summary(context=context)
            return 0

        if command == "show":
            print_full(context=context)
            return 0

        if command == "verify":
            verify(context=context)
            print("[PASS] IP / Network memenuhi validasi.")
            print("[PASS] Status: completed")
            return 0

        if command == "status":
            data = _load_network(context)
            print(f"Project ID : {context.project_id}")
            print(f"Status     : {data['network'].get('status', '')}")
            return 0

        if command == "remove":
            removed = remove(context=context)

            if not removed:
                print("[INFO] IP / Network reconnaissance belum ada.")
                return 1

            print("[PASS] IP / Network reconnaissance telah dihapus.")
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (ContextError, NetworkError, ActivityError) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
