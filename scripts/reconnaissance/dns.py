#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - DNS / Domain

Version: 1.1.0

Initialize DNS reconnaissance from the completed Target Identification
document, then use dns.yaml as the module's own configuration/state file.

The active project is resolved through context.py.
No --project argument is required.

Storage:
    projects/<PROJECT-ID>/02-reconnaissance/dns/dns.yaml

Upstream source used by "init":
    projects/<PROJECT-ID>/02-reconnaissance/target/target.yaml

Checklist mapping:
    02-002 - DNS / Domain

This module performs basic DNS resolution using the operating system
resolver. It does not perform subdomain brute force, zone transfer
testing, DNSSEC testing, or DNS vulnerability testing.
"""

from __future__ import annotations

import ipaddress
import socket
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


SCRIPT_VERSION = "1.1.0"

RECON_DIR_NAME = "02-reconnaissance"
TARGET_DIR_NAME = "target"
TARGET_FILE_NAME = "target.yaml"
DNS_DIR_NAME = "dns"
DNS_FILE_NAME = "dns.yaml"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
}


class DNSError(RuntimeError):
    """Raised when DNS data cannot be created or modified."""


def target_file(context: ProjectContext) -> Path:
    """Return the upstream Target Identification YAML path."""
    return (
        context.project_path
        / RECON_DIR_NAME
        / TARGET_DIR_NAME
        / TARGET_FILE_NAME
    )


def dns_dir(context: ProjectContext) -> Path:
    """Return the DNS reconnaissance directory."""
    return context.project_path / RECON_DIR_NAME / DNS_DIR_NAME


def dns_file(context: ProjectContext) -> Path:
    """Return the DNS YAML path."""
    return dns_dir(context) / DNS_FILE_NAME


def _now() -> str:
    """Return current local timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    """Return the initial DNS reconnaissance document."""
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "dns": {
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
            "canonical_name": "",
            "aliases": [],
            "resolver": "",
            "resolved_at": "",
            "notes": "",
        },
    }


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    """Load a YAML mapping."""
    if not path.is_file():
        raise DNSError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise DNSError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise DNSError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise DNSError(f"Format {path.name} harus berupa mapping/object.")

    return data


def _load_target_source(context: ProjectContext) -> dict[str, Any]:
    """
    Load Target Identification as the upstream source for init.

    target.yaml is intentionally read only during initialization.
    After init succeeds, dns.yaml becomes the DNS module's own
    configuration/state file.
    """
    path = target_file(context)
    data = _load_yaml(path, "Target Identification")

    if data.get("project_id") != context.project_id:
        raise DNSError(
            "Project ID pada target.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    target = data.get("target")
    if not isinstance(target, dict):
        raise DNSError(
            "Field 'target' pada target.yaml harus berupa mapping/object."
        )

    status = str(target.get("status", "")).strip().lower()
    if status != "completed":
        raise DNSError(
            "Target Identification belum completed.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/target.py verify"
        )

    required_fields = {
        "application": target.get("application"),
        "target_url": target.get("target_url"),
        "hostname": target.get("hostname"),
        "scheme": target.get("scheme"),
        "port": target.get("port"),
        "environment": target.get("environment"),
        "assessment_type": target.get("assessment_type"),
        "scope_reference": target.get("scope_reference"),
    }

    missing = [
        name
        for name, value in required_fields.items()
        if not isinstance(value, str) or not value.strip()
    ]

    if missing:
        raise DNSError(
            "Target Identification belum lengkap. Field kosong: "
            + ", ".join(missing)
        )

    return data


def _build_from_target(
    context: ProjectContext,
    target_data: dict[str, Any],
) -> dict[str, Any]:
    """Build the DNS module configuration from target.yaml."""
    target = target_data["target"]
    data = _empty_document(context)

    data["dns"].update(
        {
            "status": "not-started",
            "application": str(target["application"]).strip(),
            "target_url": str(target["target_url"]).strip(),
            "hostname": str(target["hostname"]).strip().rstrip("."),
            "scheme": str(target["scheme"]).strip().lower(),
            "port": str(target["port"]).strip(),
            "environment": str(target["environment"]).strip(),
            "assessment_type": str(target["assessment_type"]).strip(),
            "scope_reference": str(
                target["scope_reference"]
            ).strip(),
            "ipv4": [],
            "ipv6": [],
            "canonical_name": "",
            "aliases": [],
            "resolver": "",
            "resolved_at": "",
            "notes": str(target.get("notes", "")).strip(),
        }
    )

    return data


def _load_dns(context: ProjectContext) -> dict[str, Any]:
    """Load and validate dns.yaml."""
    path = dns_file(context)

    if not path.is_file():
        raise DNSError(
            f"DNS configuration belum tersedia: {path}\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/dns.py init"
        )

    data = _load_yaml(path, "DNS configuration")

    if data.get("project_id") != context.project_id:
        raise DNSError(
            "Project ID pada dns.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    dns = data.get("dns")
    if not isinstance(dns, dict):
        raise DNSError("Field 'dns' pada dns.yaml harus berupa mapping/object.")

    defaults = _empty_document(context)["dns"]
    for key, value in defaults.items():
        dns.setdefault(key, value)

    status = str(dns.get("status", "not-started")).strip().lower()
    if status not in VALID_STATUSES:
        raise DNSError(
            f"Status DNS tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data["dns"] = dns
    return data


def _save_dns(context: ProjectContext, data: dict[str, Any]) -> Path:
    """Save the DNS module's own configuration/state file."""
    directory = dns_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = dns_file(context)

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
        raise DNSError(f"Gagal menulis: {path}\n{exc}") from exc

    return path


def initialize(
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    """
    Initialize dns.yaml from target.yaml.

    target.yaml is read during initialization and its required target
    metadata is copied into dns.yaml. After that, dns.yaml is used as
    the DNS module's own configuration/state file.
    """
    if context is None:
        context = require_active_project()

    target_data = _load_target_source(context)
    data = _build_from_target(context, target_data)

    return _save_dns(context, data)


def _unique(values: list[str]) -> list[str]:
    """Return unique non-empty values while preserving order."""
    result: list[str] = []

    for value in values:
        value = str(value).strip()
        if value and value not in result:
            result.append(value)

    return result


def _resolve_dns(hostname: str) -> dict[str, Any]:
    """
    Resolve IPv4/IPv6 addresses using the operating system resolver.
    """
    hostname = hostname.strip().rstrip(".")

    if not hostname:
        raise DNSError("Hostname tidak boleh kosong.")

    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise DNSError(
            f"DNS resolution gagal untuk hostname '{hostname}': {exc}"
        ) from exc
    except OSError as exc:
        raise DNSError(
            f"DNS resolution gagal untuk hostname '{hostname}': {exc}"
        ) from exc

    ipv4: list[str] = []
    ipv6: list[str] = []
    canonical_names: list[str] = []

    for family, _socktype, _proto, canonname, sockaddr in infos:
        address = str(sockaddr[0]).strip()

        if canonname:
            canonical_names.append(str(canonname).rstrip("."))

        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError:
            continue

        if family == socket.AF_INET and parsed_address.version == 4:
            ipv4.append(str(parsed_address))
        elif family == socket.AF_INET6 and parsed_address.version == 6:
            ipv6.append(str(parsed_address))

    ipv4 = _unique(ipv4)
    ipv6 = _unique(ipv6)
    canonical_names = _unique(canonical_names)

    aliases: list[str] = []

    try:
        resolved_name, resolved_aliases, _resolved_addresses = (
            socket.gethostbyname_ex(hostname)
        )

        if resolved_name:
            canonical_names = _unique(
                canonical_names + [str(resolved_name).rstrip(".")]
            )

        aliases = _unique(
            [str(alias).rstrip(".") for alias in resolved_aliases]
        )
    except (socket.gaierror, OSError):
        pass

    if not ipv4 and not ipv6:
        raise DNSError(
            f"Hostname '{hostname}' berhasil diproses, tetapi tidak ada "
            "alamat IPv4/IPv6 yang dapat dicatat."
        )

    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "canonical_name": (
            canonical_names[0] if canonical_names else ""
        ),
        "aliases": aliases,
    }


def _resolver_info() -> str:
    """Return the resolver source used by the module."""
    return "system"


def resolve(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """
    Resolve the hostname stored in dns.yaml.

    This function does not read target.yaml.
    """
    if context is None:
        context = require_active_project()

    data = _load_dns(context)
    dns = data["dns"]

    hostname = str(dns.get("hostname", "")).strip()

    if not hostname:
        raise DNSError(
            "Hostname belum tersedia pada dns.yaml.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/dns.py init"
        )

    result = _resolve_dns(hostname)

    dns["ipv4"] = result["ipv4"]
    dns["ipv6"] = result["ipv6"]
    dns["canonical_name"] = result["canonical_name"]
    dns["aliases"] = result["aliases"]
    dns["resolver"] = _resolver_info()
    dns["resolved_at"] = _now()
    dns["status"] = "in-progress"

    _save_dns(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-002",
            action=(
                f"DNS resolution recorded: {hostname} "
                f"(IPv4={len(result['ipv4'])}, "
                f"IPv6={len(result['ipv6'])})"
            ),
            status="in-progress",
            context=context,
        )
    except ActivityError as exc:
        raise DNSError(
            f"DNS berhasil disimpan, tetapi activity gagal dicatat.\n{exc}"
        ) from exc

    return data


def get_dns(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Return the current DNS reconnaissance document."""
    if context is None:
        context = require_active_project()

    return _load_dns(context)


def validate(
    *,
    context: Optional[ProjectContext] = None,
) -> list[str]:
    """Validate the minimum DNS reconnaissance information."""
    if context is None:
        context = require_active_project()

    data = _load_dns(context)
    dns = data["dns"]
    errors: list[str] = []

    required_fields = {
        "application": dns.get("application"),
        "target_url": dns.get("target_url"),
        "hostname": dns.get("hostname"),
        "scheme": dns.get("scheme"),
        "port": dns.get("port"),
        "environment": dns.get("environment"),
        "assessment_type": dns.get("assessment_type"),
        "scope_reference": dns.get("scope_reference"),
        "resolved_at": dns.get("resolved_at"),
    }

    for field, value in required_fields.items():
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} belum diisi.")

    if dns.get("scheme") not in {"http", "https"}:
        errors.append("scheme harus berupa http atau https.")

    if not str(dns.get("port", "")).isdigit():
        errors.append("port harus berupa angka.")

    ipv4 = dns.get("ipv4")
    ipv6 = dns.get("ipv6")

    if not isinstance(ipv4, list):
        errors.append("ipv4 harus berupa list.")
    else:
        for address in ipv4:
            try:
                if ipaddress.ip_address(str(address)).version != 4:
                    errors.append(f"Alamat IPv4 tidak valid: {address}")
            except ValueError:
                errors.append(f"Alamat IPv4 tidak valid: {address}")

    if not isinstance(ipv6, list):
        errors.append("ipv6 harus berupa list.")
    else:
        for address in ipv6:
            try:
                if ipaddress.ip_address(str(address)).version != 6:
                    errors.append(f"Alamat IPv6 tidak valid: {address}")
            except ValueError:
                errors.append(f"Alamat IPv6 tidak valid: {address}")

    if isinstance(ipv4, list) and isinstance(ipv6, list):
        if not ipv4 and not ipv6:
            errors.append("Minimal satu alamat IPv4 atau IPv6 harus tersedia.")

    return errors


def verify(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """Verify DNS reconnaissance and mark it completed."""
    if context is None:
        context = require_active_project()

    errors = validate(context=context)

    if errors:
        raise DNSError(
            "DNS / Domain reconnaissance belum lengkap:\n"
            + "\n".join(f"- {error}" for error in errors)
        )

    data = _load_dns(context)
    data["dns"]["status"] = "completed"
    _save_dns(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-002",
            action="DNS / Domain reconnaissance verified",
            status="completed",
            context=context,
        )
    except ActivityError as exc:
        raise DNSError(
            f"DNS berhasil diverifikasi, tetapi activity gagal dicatat.\n{exc}"
        ) from exc

    return data


def set_status(
    status: str,
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Set DNS reconnaissance lifecycle status."""
    if context is None:
        context = require_active_project()

    normalized = status.strip().lower()

    if normalized not in VALID_STATUSES:
        raise DNSError(
            f"Status tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data = _load_dns(context)
    data["dns"]["status"] = normalized
    _save_dns(context, data)

    record_activity(
        phase="02-reconnaissance",
        item="02-002",
        action=f"DNS / Domain status changed to {normalized}",
        status="completed" if normalized == "completed" else "in-progress",
        context=context,
    )


def remove(
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    """Remove the DNS reconnaissance file."""
    if context is None:
        context = require_active_project()

    path = dns_file(context)

    if not path.is_file():
        return False

    try:
        path.unlink()
    except OSError as exc:
        raise DNSError(f"Gagal menghapus: {path}\n{exc}") from exc

    record_activity(
        phase="02-reconnaissance",
        item="02-002",
        action="DNS / Domain reconnaissance removed",
        status="completed",
        context=context,
    )

    return True


def print_summary(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print a concise DNS reconnaissance summary."""
    if context is None:
        context = require_active_project()

    data = _load_dns(context)
    dns = data["dns"]

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Reconnaissance DNS / Domain")
    print("=" * 72)
    print(f"Project ID       : {context.project_id}")
    print(f"Status           : {dns.get('status', '')}")
    print(f"Application      : {dns.get('application', '')}")
    print(f"Target URL       : {dns.get('target_url', '')}")
    print(f"Hostname         : {dns.get('hostname', '')}")
    print(f"Scheme           : {dns.get('scheme', '')}")
    print(f"Port             : {dns.get('port', '')}")
    print(f"Environment      : {dns.get('environment', '')}")
    print(f"Assessment Type  : {dns.get('assessment_type', '')}")
    print(f"IPv4             : {', '.join(dns.get('ipv4', [])) or '-'}")
    print(f"IPv6             : {', '.join(dns.get('ipv6', [])) or '-'}")
    print(f"Canonical Name   : {dns.get('canonical_name', '') or '-'}")
    print(f"Aliases          : {', '.join(dns.get('aliases', [])) or '-'}")
    print(f"Resolver         : {dns.get('resolver', '') or '-'}")
    print(f"Resolved At      : {dns.get('resolved_at', '') or '-'}")
    print(f"Scope Reference  : {dns.get('scope_reference', '')}")
    print(f"File             : {dns_file(context)}")


def print_full(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print the complete DNS document."""
    if context is None:
        context = require_active_project()

    data = _load_dns(context)

    print(f"PROJECT: {context.project_id}")
    print(f"FILE   : {dns_file(context)}")
    print()
    _print_value(data["dns"])


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
        "Reconnaissance DNS / Domain\n"
        "\n"
        "Usage:\n"
        "  python scripts/reconnaissance/dns.py init\n"
        "  python scripts/reconnaissance/dns.py resolve\n"
        "  python scripts/reconnaissance/dns.py list\n"
        "  python scripts/reconnaissance/dns.py show\n"
        "  python scripts/reconnaissance/dns.py verify\n"
        "  python scripts/reconnaissance/dns.py status\n"
        "  python scripts/reconnaissance/dns.py remove\n"
        "  python scripts/reconnaissance/dns.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
        "\n"
        "The init command reads target.yaml and creates dns.yaml.\n"
        "After init, DNS commands use dns.yaml as their own state file.\n"
        "\n"
        "The resolve command performs basic DNS resolution using the\n"
        "operating system resolver and records IPv4/IPv6 results.\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    """Command-line entry point."""
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = args[0].lower()

    # version should work even without an active project.
    if command == "version":
        print(f"BrebesKab-CSIRT-Tools dns.py v{SCRIPT_VERSION}")
        return 0

    try:
        context = require_active_project()

        if command == "init":
            path = initialize(context=context)
            print("[PASS] DNS configuration siap dari Target Identification.")
            print(f"File: {path}")
            return 0

        if command == "resolve":
            data = resolve(context=context)
            dns = data["dns"]
            print("[PASS] DNS resolution berhasil.")
            print(f"Hostname : {dns.get('hostname', '')}")
            print(
                f"IPv4     : {', '.join(dns.get('ipv4', [])) or '-'}"
            )
            print(
                f"IPv6     : {', '.join(dns.get('ipv6', [])) or '-'}"
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
            print("[PASS] DNS / Domain memenuhi validasi.")
            print("[PASS] Status: completed")
            return 0

        if command == "status":
            data = get_dns(context=context)
            print(f"Project ID : {context.project_id}")
            print(f"Status     : {data['dns'].get('status', '')}")
            return 0

        if command == "remove":
            removed = remove(context=context)
            if not removed:
                print("[INFO] DNS / Domain reconnaissance belum ada.")
                return 1

            print("[PASS] DNS / Domain reconnaissance telah dihapus.")
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (ContextError, DNSError, ActivityError) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
