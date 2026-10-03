#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Subdomain Discovery

Checklist:
    2-004 Subdomain discovery

Version:
    1.3.0

Design principles:
    - Read target context during `init`.
    - After init, discovery commands use subdomain.yaml.
    - Certificate Transparency (crt.sh) is a passive discovery source.
    - DNS-based discovery is bounded to a small candidate list.
    - Possible wildcard/shared infrastructure is assessed before candidate classification.
    - DNS resolution alone does not prove that a real subdomain exists.
    - Possible shared-infrastructure candidates are retained as evidence but are not counted as
      confirmed/authorized subdomains.
    - Source failures are recorded explicitly.
    - A discovery run is not successful merely because it found zero results.
    - `partial` means at least one discovery method completed while another
      method failed.
    - `failed` means all configured discovery methods failed.
    - Results from successful methods are preserved.
    - Discovered subdomains are reconnaissance evidence only. They do NOT
      automatically become authorized test targets. Scope remains the
      authority for testing.
    - No credentials, tokens, or sensitive data are stored.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import random
import re
import socket
import string
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# IMPORTANT:
# This directory contains http.py. If it remains in sys.path while requests
# is imported, Python can resolve the local http.py instead of the standard
# library `http` package. Remove SCRIPT_DIR BEFORE importing requests.
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent
REPO_ROOT = SCRIPT_DIR.parent.parent

script_dir_string = str(SCRIPT_DIR)
sys.path[:] = [entry for entry in sys.path if entry != script_dir_string]

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import requests
    import yaml
except ImportError as exc:
    print(f"[FAIL] Dependency tidak tersedia: {exc}")
    sys.exit(1)

try:
    from scripts.context import require_active_project
except ImportError:
    try:
        from context import require_active_project
    except ImportError:
        require_active_project = None

try:
    from scripts.activity import record_activity
except ImportError:
    try:
        from activity import record_activity
    except ImportError:
        record_activity = None


SCRIPT_VERSION = "1.3.1"
SCHEMA_VERSION = "1.3.1"
CHECKLIST_ID = "2-004"
CHECKLIST_NAME = "Subdomain discovery"

DISCOVERY_STATUS_NOT_STARTED = "not-started"
DISCOVERY_STATUS_COMPLETED = "completed"
DISCOVERY_STATUS_PARTIAL = "partial"
DISCOVERY_STATUS_FAILED = "failed"

SOURCE_STATUS_NOT_STARTED = "not-started"
SOURCE_STATUS_SUCCESS = "completed"
SOURCE_STATUS_FAILED = "failed"

DNS_CLASSIFICATION_CANDIDATE = "candidate"
DNS_CLASSIFICATION_POSSIBLE_SHARED = "possible-wildcard-shared-infrastructure"
DNS_CLASSIFICATION_UNRESOLVED = "unresolved"

# Deliberately bounded candidate list. This is reconnaissance discovery,
# not an unrestricted wordlist/brute-force engine.
DNS_CANDIDATES = [
    "www",
    "api",
    "app",
    "admin",
    "portal",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "pop",
    "ftp",
    "vpn",
    "dev",
    "test",
    "staging",
    "uat",
    "demo",
    "beta",
    "www1",
    "www2",
    "ns1",
    "ns2",
]

WILDCARD_PROBE_COUNT = 3
WILDCARD_PROBE_LENGTH = 18

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def project_context() -> Any:
    if require_active_project is None:
        raise RuntimeError("Module context.py tidak dapat diimpor.")
    return require_active_project()


def project_root() -> Path:
    context = project_context()

    if hasattr(context, "project_path"):
        return Path(context.project_path)

    if hasattr(context, "path"):
        return Path(context.path)

    raise RuntimeError("ProjectContext tidak menyediakan path project.")


def target_file() -> Path:
    return project_root() / "02-reconnaissance" / "target" / "target.yaml"


def output_dir() -> Path:
    return project_root() / "02-reconnaissance" / "subdomain"


def output_file() -> Path:
    return output_dir() / "subdomain.yaml"


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {path}")

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Format YAML tidak valid: {path}")

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


def normalize_hostname(value: str) -> str:
    value = (value or "").strip().lower().rstrip(".")

    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""

    if "/" in value:
        value = value.split("/", 1)[0]

    return value


def is_valid_domain(value: str) -> bool:
    return bool(DOMAIN_RE.fullmatch(value))


def is_same_or_child(hostname: str, domain: str) -> bool:
    hostname = normalize_hostname(hostname)
    domain = normalize_hostname(domain)

    return hostname == domain or hostname.endswith("." + domain)


def extract_domain_from_target(target: dict[str, Any]) -> str:
    target_block = target.get("target")

    if not isinstance(target_block, dict):
        raise ValueError("target.yaml tidak memiliki blok target.")

    hostname = normalize_hostname(str(target_block.get("hostname", "")))

    if not hostname:
        target_url = str(target_block.get("target_url", ""))
        hostname = normalize_hostname(target_url)

    if not hostname:
        raise ValueError("Hostname target tidak ditemukan.")

    if not is_valid_domain(hostname):
        raise ValueError(f"Hostname bukan domain yang valid: {hostname}")

    return hostname


def build_initial_document(target: dict[str, Any]) -> dict[str, Any]:
    project_id = str(target.get("project_id", "")).strip()

    if not project_id:
        raise ValueError("project_id tidak ditemukan pada target.yaml.")

    target_block = target.get("target")

    if not isinstance(target_block, dict):
        raise ValueError("target.yaml tidak memiliki blok target.")

    domain = extract_domain_from_target(target)

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "updated_at": now_iso(),
        "subdomain": {
            "status": DISCOVERY_STATUS_NOT_STARTED,
            "checklist_id": CHECKLIST_ID,
            "checklist": CHECKLIST_NAME,
            "application": str(target_block.get("application", "")),
            "target_url": str(target_block.get("target_url", "")),
            "hostname": domain,
            "domain": domain,
            "environment": str(target_block.get("environment", "")),
            "assessment_type": str(target_block.get("assessment_type", "")),
            "scope_reference": str(target_block.get("scope_reference", "")),
            "discovery_methods": [
                {
                    "id": "CRT-001",
                    "name": "Certificate Transparency",
                    "source": "crt.sh",
                    "type": "passive",
                    "status": SOURCE_STATUS_NOT_STARTED,
                },
                {
                    "id": "DNS-001",
                    "name": "DNS-based discovery",
                    "source": "DNS resolution",
                    "type": "active-recon",
                    "status": SOURCE_STATUS_NOT_STARTED,
                },
            ],
            "dns_environment": {
                "possible_shared_infrastructure": False,
                "status": "not-tested",
                "probe_count": 0,
                "resolved_probe_count": 0,
                "probe_hostnames": [],
                "probe_addresses": [],
                "classification": "",
                "notes": "",
            },
            "candidates": [],
            "subdomains": [],
            "summary": {
                "candidates_total": 0,
                "direct_dns_candidate_total": 0,
                "possible_shared_infrastructure_total": 0,
                "unresolved_total": 0,
                "resolved_total": 0,
            },
            "discovery_summary": {
                "methods_configured": 2,
                "methods_completed": 0,
                "methods_failed": 0,
                "methods_not_run": 2,
                "successful_methods": [],
                "failed_methods": [],
            },
            "errors": [],
            "notes": "",
            "discovered_at": "",
        },
    }


def load_document() -> dict[str, Any]:
    path = output_file()
    data = load_yaml(path)

    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"schema_version tidak didukung: {data.get('schema_version')}"
        )

    subdomain = data.get("subdomain")

    if not isinstance(subdomain, dict):
        raise ValueError("subdomain.yaml tidak memiliki blok subdomain.")

    if not data.get("project_id"):
        raise ValueError("project_id tidak tersedia.")

    return data


def update_document(data: dict[str, Any]) -> None:
    data["updated_at"] = now_iso()
    save_yaml(output_file(), data)


def record(
    phase_item: str,
    action: str,
    status: str = "in-progress",
) -> None:
    if record_activity is None:
        return

    try:
        record_activity(
            phase="02-reconnaissance",
            item=phase_item,
            action=action,
            status=status,
        )
    except TypeError:
        try:
            record_activity(
                "02-reconnaissance",
                phase_item,
                action,
                status,
            )
        except Exception:
            pass
    except Exception:
        pass


def ensure_method_records(block: dict[str, Any]) -> list[dict[str, Any]]:
    methods = block.get("discovery_methods")

    if not isinstance(methods, list):
        methods = []

    required = [
        {
            "id": "CRT-001",
            "name": "Certificate Transparency",
            "source": "crt.sh",
            "type": "passive",
        },
        {
            "id": "DNS-001",
            "name": "DNS-based discovery",
            "source": "DNS resolution",
            "type": "active-recon",
        },
    ]

    for required_method in required:
        existing = next(
            (
                item
                for item in methods
                if isinstance(item, dict)
                and item.get("id") == required_method["id"]
            ),
            None,
        )

        if existing is None:
            methods.append(
                {
                    **required_method,
                    "status": SOURCE_STATUS_NOT_STARTED,
                }
            )
        else:
            existing.setdefault("name", required_method["name"])
            existing.setdefault("source", required_method["source"])
            existing.setdefault("type", required_method["type"])
            existing.setdefault("status", SOURCE_STATUS_NOT_STARTED)

    block["discovery_methods"] = methods
    return methods


def certificate_transparency(
    domain: str,
    timeout: int = 15,
) -> tuple[list[str], dict[str, Any]]:
    """Query crt.sh Certificate Transparency data."""
    url = "https://crt.sh/"
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }

    source_result: dict[str, Any] = {
        "id": "CRT-001",
        "name": "Certificate Transparency",
        "source": "crt.sh",
        "type": "passive",
        "status": SOURCE_STATUS_FAILED,
        "started_at": now_iso(),
        "completed_at": "",
        "http_status": None,
        "result_count": 0,
        "error": "",
    }

    try:
        response = requests.get(
            url,
            params=params,
            timeout=timeout,
            headers={
                "User-Agent": "BrebesKab-CSIRT-Tools/1.3",
                "Accept": "application/json",
            },
        )

        source_result["http_status"] = response.status_code
        response.raise_for_status()
        rows = response.json()

    except requests.HTTPError as exc:
        source_result["error"] = f"HTTP error: {exc}"
        source_result["completed_at"] = now_iso()
        return [], source_result

    except requests.RequestException as exc:
        source_result["error"] = f"Request error: {exc}"
        source_result["completed_at"] = now_iso()
        return [], source_result

    except ValueError as exc:
        source_result["error"] = f"Invalid JSON response: {exc}"
        source_result["completed_at"] = now_iso()
        return [], source_result

    if not isinstance(rows, list):
        source_result["error"] = "crt.sh response format tidak sesuai."
        source_result["completed_at"] = now_iso()
        return [], source_result

    discovered: set[str] = set()

    for row in rows:
        if not isinstance(row, dict):
            continue

        names = str(row.get("name_value", ""))

        for raw_name in names.splitlines():
            name = normalize_hostname(raw_name).lstrip("*.")

            if (
                name
                and is_valid_domain(name)
                and is_same_or_child(name, domain)
            ):
                discovered.add(name)

    discovered.discard(domain)

    source_result["status"] = SOURCE_STATUS_SUCCESS
    source_result["result_count"] = len(discovered)
    source_result["completed_at"] = now_iso()

    return sorted(discovered), source_result


def resolve_hostname(hostname: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "hostname": hostname,
        "ipv4": [],
        "ipv6": [],
        "status": "unresolved",
        "error": "",
    }

    try:
        infos = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        result["error"] = str(exc)
        return result
    except OSError as exc:
        result["error"] = str(exc)
        return result

    ipv4: set[str] = set()
    ipv6: set[str] = set()

    for info in infos:
        address = info[4][0]

        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue

        if parsed.version == 4:
            ipv4.add(address)
        elif parsed.version == 6:
            ipv6.add(address)

    result["ipv4"] = sorted(ipv4)
    result["ipv6"] = sorted(ipv6)

    if ipv4 or ipv6:
        result["status"] = "resolved"

    return result


def random_probe_label() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "csirt-" + "".join(
        random.SystemRandom().choice(alphabet)
        for _ in range(WILDCARD_PROBE_LENGTH)
    )


def detect_dns_environment(
    domain: str,
) -> dict[str, Any]:
    """
    Assess possible wildcard/shared infrastructure by resolving random, highly unlikely labels.

    Three independent random labels are used. If they resolve consistently,
    the domain is flagged as possible wildcard/shared infrastructure.

    This does not prove the exact DNS implementation. It establishes a
    reconnaissance signal that candidate DNS answers may be generated by a
    shared infrastructure, reverse proxy routing, or DNS wildcard behavior rather than individual DNS records.
    """
    probe_hostnames: list[str] = []
    probe_addresses: set[str] = set()
    resolved_probe_count = 0
    probe_results: list[dict[str, Any]] = []

    for _ in range(WILDCARD_PROBE_COUNT):
        hostname = f"{random_probe_label()}.{domain}"
        result = resolve_hostname(hostname)

        probe_hostnames.append(hostname)

        addresses = sorted(
            set(result.get("ipv4", []))
            | set(result.get("ipv6", []))
        )

        if result.get("status") == "resolved":
            resolved_probe_count += 1
            probe_addresses.update(addresses)

        probe_results.append(
            {
                "hostname": hostname,
                "status": result.get("status"),
                "ipv4": result.get("ipv4", []),
                "ipv6": result.get("ipv6", []),
                "error": result.get("error", ""),
            }
        )

    possible_shared_infrastructure = (
        resolved_probe_count == WILDCARD_PROBE_COUNT
    )

    if possible_shared_infrastructure:
        status = "possible"
        classification = "possible-wildcard-shared-infrastructure"
        notes = (
            "Semua random DNS probes berhasil resolve. "
            "Ini hanya indikasi possible wildcard/shared infrastructure. "
            "Reverse proxy atau shared DNS infrastructure dapat menghasilkan "
            "pola yang sama; ini bukan bukti wildcard DNS."
        )
    elif resolved_probe_count > 0:
        status = "inconclusive"
        classification = "inconclusive"
        notes = (
            "Sebagian random DNS probes resolve. "
            "Hasil tidak dapat membedakan wildcard DNS dari shared infrastructure/reverse proxy."
        )
    else:
        status = "no-signal"
        classification = "no-possible-shared-infrastructure-signal"
        notes = (
            "Tidak ada random DNS probe yang resolve."
        )

    return {
        "possible_shared_infrastructure": possible_shared_infrastructure,
        "status": status,
        "probe_count": WILDCARD_PROBE_COUNT,
        "resolved_probe_count": resolved_probe_count,
        "probe_hostnames": probe_hostnames,
        "probe_addresses": sorted(probe_addresses),
        "classification": classification,
        "notes": notes,
        "probe_results": probe_results,
    }


def classify_candidate(
    hostname: str,
    resolution: dict[str, Any],
    environment: dict[str, Any],
) -> str:
    if resolution.get("status") != "resolved":
        return DNS_CLASSIFICATION_UNRESOLVED

    candidate_addresses = set(resolution.get("ipv4", []))
    candidate_addresses.update(resolution.get("ipv6", []))

    shared_infrastructure_addresses = set(environment.get("probe_addresses", []))

    if (
        environment.get("possible_shared_infrastructure")
        and candidate_addresses
        and candidate_addresses.issubset(shared_infrastructure_addresses)
    ):
        return DNS_CLASSIFICATION_POSSIBLE_SHARED

    return DNS_CLASSIFICATION_CANDIDATE


def dns_discovery(
    domain: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """
    Perform bounded DNS candidate discovery and possible shared-infrastructure classification.

    Returns:
        candidates, environment_result, source_result
    """
    source_result: dict[str, Any] = {
        "id": "DNS-001",
        "name": "DNS-based discovery",
        "source": "DNS resolution",
        "type": "active-recon",
        "status": SOURCE_STATUS_FAILED,
        "started_at": now_iso(),
        "completed_at": "",
        "candidate_count": len(DNS_CANDIDATES),
        "resolved_count": 0,
        "non_possible_shared_infrastructure_count": 0,
        "possible_shared_infrastructure_count": 0,
        "unresolved_count": 0,
        "error": "",
    }

    try:
        environment = detect_dns_environment(domain)

        candidates: list[dict[str, Any]] = []

        for label in DNS_CANDIDATES:
            hostname = f"{label}.{domain}"
            resolution = resolve_hostname(hostname)
            classification = classify_candidate(
                hostname,
                resolution,
                environment,
            )

            candidates.append(
                {
                    "hostname": hostname,
                    "status": resolution["status"],
                    "ipv4": resolution["ipv4"],
                    "ipv6": resolution["ipv6"],
                    "dns_classification": classification,
                    "source": ["dns-based-discovery"],
                    "resolution_error": resolution["error"],
                    "scope_status": "requires-scope-verification",
                }
            )

        resolved_count = sum(
            1
            for item in candidates
            if item["status"] == "resolved"
        )
        possible_shared_infrastructure_count = sum(
            1
            for item in candidates
            if item["dns_classification"] == DNS_CLASSIFICATION_POSSIBLE_SHARED
        )
        non_possible_shared_infrastructure_count = sum(
            1
            for item in candidates
            if item["dns_classification"] == DNS_CLASSIFICATION_CANDIDATE
        )
        unresolved_count = sum(
            1
            for item in candidates
            if item["dns_classification"] == DNS_CLASSIFICATION_UNRESOLVED
        )

        source_result["status"] = SOURCE_STATUS_SUCCESS
        source_result["completed_at"] = now_iso()
        source_result["resolved_count"] = resolved_count
        source_result["non_possible_shared_infrastructure_count"] = non_possible_shared_infrastructure_count
        source_result["possible_shared_infrastructure_count"] = possible_shared_infrastructure_count
        source_result["unresolved_count"] = unresolved_count

        return candidates, environment, source_result

    except Exception as exc:
        source_result["error"] = (
            f"DNS discovery error: {type(exc).__name__}: {exc}"
        )
        source_result["completed_at"] = now_iso()

        return [], {
            "possible_shared_infrastructure": False,
            "status": "error",
            "probe_count": 0,
            "resolved_probe_count": 0,
            "probe_hostnames": [],
            "probe_addresses": [],
            "classification": "",
            "notes": "",
            "probe_results": [],
        }, source_result


def rebuild_summary(
    candidates: list[dict[str, Any]],
) -> dict[str, int]:
    resolved = sum(
        1
        for item in candidates
        if isinstance(item, dict)
        and item.get("status") == "resolved"
    )

    direct_dns_candidate = sum(
        1
        for item in candidates
        if isinstance(item, dict)
        and item.get("dns_classification")
        == DNS_CLASSIFICATION_CANDIDATE
    )

    possible_shared_infrastructure = sum(
        1
        for item in candidates
        if isinstance(item, dict)
        and item.get("dns_classification")
        == DNS_CLASSIFICATION_POSSIBLE_SHARED
    )

    unresolved = sum(
        1
        for item in candidates
        if isinstance(item, dict)
        and item.get("dns_classification")
        == DNS_CLASSIFICATION_UNRESOLVED
    )

    return {
        "candidates_total": len(candidates),
        "direct_dns_candidate_total": direct_dns_candidate,
        "possible_shared_infrastructure_total": possible_shared_infrastructure,
        "unresolved_total": unresolved,
        "resolved_total": resolved,
    }


def calculate_discovery_status(
    methods: list[dict[str, Any]],
) -> str:
    completed = sum(
        1
        for method in methods
        if isinstance(method, dict)
        and method.get("status") == SOURCE_STATUS_SUCCESS
    )

    failed = sum(
        1
        for method in methods
        if isinstance(method, dict)
        and method.get("status") == SOURCE_STATUS_FAILED
    )

    not_started = sum(
        1
        for method in methods
        if isinstance(method, dict)
        and method.get("status") == SOURCE_STATUS_NOT_STARTED
    )

    if completed == 0 and failed > 0 and not_started == 0:
        return DISCOVERY_STATUS_FAILED

    if failed > 0 and completed > 0:
        return DISCOVERY_STATUS_PARTIAL

    if completed > 0 and failed == 0 and not_started == 0:
        return DISCOVERY_STATUS_COMPLETED

    if completed > 0 and not_started > 0:
        return DISCOVERY_STATUS_PARTIAL

    if failed > 0 and completed == 0:
        return DISCOVERY_STATUS_FAILED

    return DISCOVERY_STATUS_NOT_STARTED


def update_method_summary(block: dict[str, Any]) -> None:
    methods = ensure_method_records(block)

    completed = [
        item.get("name", item.get("id", "-"))
        for item in methods
        if item.get("status") == SOURCE_STATUS_SUCCESS
    ]

    failed = [
        item.get("name", item.get("id", "-"))
        for item in methods
        if item.get("status") == SOURCE_STATUS_FAILED
    ]

    not_run = [
        item.get("name", item.get("id", "-"))
        for item in methods
        if item.get("status") == SOURCE_STATUS_NOT_STARTED
    ]

    block["discovery_summary"] = {
        "methods_configured": len(methods),
        "methods_completed": len(completed),
        "methods_failed": len(failed),
        "methods_not_run": len(not_run),
        "successful_methods": completed,
        "failed_methods": failed,
    }


def add_source_error(
    block: dict[str, Any],
    source_result: dict[str, Any],
) -> None:
    error = source_result.get("error")

    if not error:
        return

    errors = block.get("errors")

    if not isinstance(errors, list):
        errors = []

    errors.append(
        {
            "source_id": source_result.get("id", ""),
            "source": source_result.get("source", ""),
            "type": source_result.get("type", ""),
            "http_status": source_result.get("http_status"),
            "error": error,
            "timestamp": now_iso(),
        }
    )

    block["errors"] = errors


def discover(
    resolve: bool = True,
    timeout: int = 15,
) -> int:
    data = load_document()
    block = data["subdomain"]

    domain = normalize_hostname(str(block.get("domain", "")))

    if not is_valid_domain(domain):
        print(f"[FAIL] Domain tidak valid: {domain}")
        return 1

    methods = ensure_method_records(block)

    # Reset source execution state for this run.
    for method in methods:
        method_id = method.get("id")

        if method_id in {"CRT-001", "DNS-001"}:
            method["status"] = SOURCE_STATUS_NOT_STARTED
            method["started_at"] = ""
            method["completed_at"] = ""
            method["error"] = ""

    block["errors"] = []
    block["candidates"] = []
    block["subdomains"] = []
    block["dns_environment"] = {
        "possible_shared_infrastructure": False,
        "status": "not-tested",
        "probe_count": 0,
        "resolved_probe_count": 0,
        "probe_hostnames": [],
        "probe_addresses": [],
        "classification": "",
        "notes": "",
    }

    print(f"[INFO] Menjalankan {CHECKLIST_ID}: {CHECKLIST_NAME}")
    print(f"[INFO] Domain: {domain}")

    # ------------------------------------------------------------------
    # CRT-001: Certificate Transparency
    # ------------------------------------------------------------------
    print("[INFO] Source: Certificate Transparency (crt.sh)")

    crt_discovered, crt_result = certificate_transparency(
        domain,
        timeout=timeout,
    )

    crt_method = next(
        method
        for method in methods
        if method.get("id") == "CRT-001"
    )

    crt_method.update(crt_result)

    if crt_result.get("status") == SOURCE_STATUS_SUCCESS:
        print(
            "[PASS] CRT discovery: "
            f"{len(crt_discovered)} subdomain ditemukan."
        )
    else:
        add_source_error(block, crt_result)

        print("[WARN] CRT discovery gagal.")
        print(
            f"       HTTP Status: "
            f"{crt_result.get('http_status', '-')}"
        )
        print(
            f"       Error: "
            f"{crt_result.get('error', '-')}"
        )

    # ------------------------------------------------------------------
    # DNS-001: DNS-based discovery
    # ------------------------------------------------------------------
    print("[INFO] Source: DNS-based discovery")

    dns_candidates, environment_result, dns_result = dns_discovery(
        domain,
    )

    dns_method = next(
        method
        for method in methods
        if method.get("id") == "DNS-001"
    )

    dns_method.update(dns_result)
    block["dns_environment"] = environment_result

    if dns_result.get("status") == SOURCE_STATUS_SUCCESS:
        print(
            "[PASS] DNS: "
            f"{dns_result.get('resolved_count', 0)} candidate "
            "ter-resolve."
        )

        if environment_result.get("possible_shared_infrastructure"):
            print(
                "[WARN] Possible wildcard/shared infrastructure terindikasi."
            )
            print(
                "       Candidate yang resolve ke shared infrastructure/probe address "
                "tidak dihitung sebagai confirmed/authorized subdomain."
            )
        elif environment_result.get("status") == "inconclusive":
            print(
                "[WARN] Possible wildcard/shared infrastructure belum dapat dipastikan."
            )
        else:
            print("[INFO] Tidak ada sinyal possible wildcard / shared infrastructure.")

    else:
        add_source_error(block, dns_result)

        print("[WARN] DNS discovery gagal.")
        print(
            f"       Error: {dns_result.get('error', '-')}"
        )

    # ------------------------------------------------------------------
    # Merge and classify evidence
    # ------------------------------------------------------------------
    all_candidates: dict[str, dict[str, Any]] = {}

    for item in dns_candidates:
        hostname = normalize_hostname(
            str(item.get("hostname", ""))
        )

        if hostname:
            all_candidates[hostname] = item

    # CRT results have higher evidence value than DNS candidate generation.
    # They are retained as candidates and marked with CRT source.
    for hostname in crt_discovered:
        hostname = normalize_hostname(hostname)

        if not hostname:
            continue

        if hostname in all_candidates:
            sources = all_candidates[hostname].setdefault(
                "source",
                [],
            )

            if "certificate_transparency" not in sources:
                sources.append("certificate_transparency")

            all_candidates[hostname]["crt_observed"] = True

        else:
            resolution = resolve_hostname(hostname)

            all_candidates[hostname] = {
                "hostname": hostname,
                "status": resolution["status"],
                "ipv4": resolution["ipv4"],
                "ipv6": resolution["ipv6"],
                "dns_classification": (
                    DNS_CLASSIFICATION_CANDIDATE
                    if resolution["status"] == "resolved"
                    else DNS_CLASSIFICATION_UNRESOLVED
                ),
                "source": ["certificate_transparency"],
                "resolution_error": resolution["error"],
                "scope_status": "requires-scope-verification",
                "crt_observed": True,
            }

    candidates = sorted(
        all_candidates.values(),
        key=lambda item: item.get("hostname", ""),
    )

    # `subdomains` intentionally contains only candidates that are not
    # classified as possible wildcard/shared infrastructure. Even these still require service and
    # scope verification.
    direct_dns_candidates = [
        item
        for item in candidates
        if item.get("dns_classification")
        == DNS_CLASSIFICATION_CANDIDATE
    ]

    block["candidates"] = candidates
    block["subdomains"] = direct_dns_candidates
    block["summary"] = rebuild_summary(candidates)

    update_method_summary(block)

    overall_status = calculate_discovery_status(methods)
    block["status"] = overall_status
    block["discovered_at"] = now_iso()

    update_document(data)

    summary = block["summary"]
    discovery_summary = block["discovery_summary"]

    print()
    print(f"DOMAIN       : {domain}")
    print(f"CANDIDATES   : {summary['candidates_total']}")
    print(f"RESOLVED     : {summary['resolved_total']}")
    print(f"POSSIBLE SHARED: {summary['possible_shared_infrastructure_total']}")
    print(f"NON-SHARED     : {summary['direct_dns_candidate_total']}")
    print(f"UNRESOLVED   : {summary['unresolved_total']}")
    print(
        f"METHODS      : "
        f"{discovery_summary['methods_completed']} completed, "
        f"{discovery_summary['methods_failed']} failed, "
        f"{discovery_summary['methods_not_run']} not-run"
    )
    print(f"STATUS       : {overall_status}")
    print(f"FILE         : {output_file()}")

    if overall_status == DISCOVERY_STATUS_COMPLETED:
        record(
            "2-004",
            (
                f"Subdomain discovery completed: {domain}; "
                f"candidates={summary['candidates_total']}, "
                f"non_possible_shared={summary['direct_dns_candidate_total']}, "
                f"possible_shared_infrastructure={summary['possible_shared_infrastructure_total']}"
            ),
            "completed",
        )

        print("[PASS] Subdomain discovery completed.")
        return 0

    if overall_status == DISCOVERY_STATUS_PARTIAL:
        record(
            "2-004",
            (
                f"Subdomain discovery partial: {domain}; "
                f"candidates={summary['candidates_total']}, "
                f"non_possible_shared={summary['direct_dns_candidate_total']}, "
                f"possible_shared_infrastructure={summary['possible_shared_infrastructure_total']}"
            ),
            "in-progress",
        )

        print(
            "[WARN] Subdomain discovery partial. "
            "Sebagian discovery source berhasil, sebagian gagal."
        )
        return 0

    if overall_status == DISCOVERY_STATUS_FAILED:
        record(
            "2-004",
            f"Subdomain discovery failed: {domain}",
            "failed",
        )

        print(
            "[FAIL] Subdomain discovery failed. "
            "Tidak ada discovery source yang berhasil."
        )
        return 1

    record(
        "2-004",
        f"Subdomain discovery not completed: {domain}",
        "in-progress",
    )

    return 1


def verify() -> int:
    data = load_document()
    block = data["subdomain"]

    errors: list[str] = []

    if not data.get("project_id"):
        errors.append("project_id kosong.")

    domain = normalize_hostname(str(block.get("domain", "")))

    if not domain or not is_valid_domain(domain):
        errors.append("domain tidak valid.")

    methods = block.get("discovery_methods")

    if not isinstance(methods, list) or not methods:
        errors.append("Tidak ada discovery method yang tercatat.")
        methods = []

    completed_methods = [
        item
        for item in methods
        if isinstance(item, dict)
        and item.get("status") == SOURCE_STATUS_SUCCESS
    ]

    failed_methods = [
        item
        for item in methods
        if isinstance(item, dict)
        and item.get("status") == SOURCE_STATUS_FAILED
    ]

    not_started_methods = [
        item
        for item in methods
        if isinstance(item, dict)
        and item.get("status") == SOURCE_STATUS_NOT_STARTED
    ]

    if not completed_methods:
        errors.append(
            "Tidak ada discovery source yang berhasil."
        )

    if not_started_methods:
        errors.append(
            "Masih ada discovery source yang belum dijalankan."
        )

    expected_status = calculate_discovery_status(methods)
    actual_status = block.get("status")

    if actual_status != expected_status:
        errors.append(
            "Status discovery tidak sesuai dengan status source: "
            f"{actual_status} != {expected_status}"
        )

    # A failed source means the overall discovery is partial. Therefore
    # verify does not mark the checklist fully completed.
    if expected_status != DISCOVERY_STATUS_COMPLETED:
        errors.append(
            "Hasil belum metodologis lengkap: "
            f"status discovery adalah {expected_status}."
        )

    environment = block.get("dns_environment")

    if not isinstance(environment, dict):
        errors.append("dns_environment harus berupa mapping.")
        environment = {}

    candidates = block.get("candidates")

    if not isinstance(candidates, list):
        errors.append("candidates harus berupa list.")
        candidates = []

    seen: set[str] = set()

    for item in candidates:
        if not isinstance(item, dict):
            errors.append(
                "Terdapat candidate subdomain yang bukan mapping."
            )
            continue

        hostname = normalize_hostname(
            str(item.get("hostname", ""))
        )

        if not hostname:
            errors.append("Terdapat candidate tanpa hostname.")
            continue

        if hostname in seen:
            errors.append(f"Duplikasi hostname: {hostname}")
            continue

        seen.add(hostname)

        if not is_valid_domain(hostname):
            errors.append(
                f"Hostname tidak valid: {hostname}"
            )
        elif not is_same_or_child(hostname, domain):
            errors.append(
                f"Hostname di luar domain target: {hostname}"
            )

        classification = item.get("dns_classification")

        if classification not in {
            DNS_CLASSIFICATION_CANDIDATE,
            DNS_CLASSIFICATION_POSSIBLE_SHARED,
            DNS_CLASSIFICATION_UNRESOLVED,
        }:
            errors.append(
                f"{hostname}: dns_classification tidak valid: "
                f"{classification}"
            )

        for key in ("ipv4", "ipv6"):
            if not isinstance(item.get(key, []), list):
                errors.append(
                    f"{hostname}: {key} harus berupa list."
                )

        if item.get("scope_status") != "requires-scope-verification":
            errors.append(
                f"{hostname}: scope_status tidak valid."
            )

    subdomains = block.get("subdomains")

    if not isinstance(subdomains, list):
        errors.append("subdomains harus berupa list.")
        subdomains = []

    candidate_names = {
        item.get("hostname")
        for item in candidates
        if isinstance(item, dict)
    }

    for item in subdomains:
        if not isinstance(item, dict):
            errors.append(
                "Terdapat subdomain record yang bukan mapping."
            )
            continue

        hostname = item.get("hostname")

        if hostname not in candidate_names:
            errors.append(
                f"{hostname}: subdomain tidak ada dalam candidates."
            )

        if item.get("dns_classification") == DNS_CLASSIFICATION_POSSIBLE_SHARED:
            errors.append(
                f"{hostname}: possible shared infrastructure candidate tidak boleh "
                "masuk daftar confirmed/authorized subdomains."
            )

    summary = block.get("summary")

    if not isinstance(summary, dict):
        errors.append("summary harus berupa mapping.")
    else:
        expected_summary = rebuild_summary(candidates)

        for key, expected in expected_summary.items():
            if summary.get(key) != expected:
                errors.append(
                    f"summary.{key} tidak sesuai: "
                    f"{summary.get(key)} != {expected}"
                )

    if errors:
        print(
            "[FAIL] Subdomain Discovery belum memenuhi "
            "validasi metodologis."
        )

        for error in errors:
            print(f"  - {error}")

        return 1

    block["status"] = DISCOVERY_STATUS_COMPLETED
    data["updated_at"] = now_iso()
    update_document(data)

    print("[PASS] Subdomain Discovery memenuhi validasi.")
    print("[PASS] Status: completed")
    print(f"PROJECT: {data['project_id']}")
    print(f"DOMAIN : {block['domain']}")
    print(
        "SCOPE  : Discovered subdomains tetap memerlukan "
        "verifikasi terhadap scope sebelum testing."
    )

    record(
        "2-004",
        "Subdomain discovery verified",
        "completed",
    )

    return 0


def status() -> int:
    data = load_document()
    block = data["subdomain"]
    discovery_summary = block.get("discovery_summary", {})
    environment = block.get("dns_environment", {})
    summary = block.get("summary", {})

    print(f"Project ID : {data.get('project_id', '-')}")
    print(f"Domain     : {block.get('domain', '-')}")
    print(f"Status     : {block.get('status', '-')}")
    print(
        "Candidates : "
        f"{summary.get('candidates_total', 0)}"
    )
    print(
        "Confirmed  : "
        f"{summary.get('direct_dns_candidate_total', 0)}"
    )
    print(
        "Possible Shared: "
        f"{summary.get('possible_shared_infrastructure_total', 0)}"
    )
    print(
        "Possible Shared Infrastructure: "
        f"{environment.get('status', '-')}"
    )
    print(
        "Methods    : "
        f"{discovery_summary.get('methods_completed', 0)} completed, "
        f"{discovery_summary.get('methods_failed', 0)} failed, "
        f"{discovery_summary.get('methods_not_run', 0)} not-run"
    )

    methods = block.get("discovery_methods", [])

    if isinstance(methods, list):
        for method in methods:
            if not isinstance(method, dict):
                continue

            print(
                f"  {method.get('id', '-')}: "
                f"{method.get('name', '-')} = "
                f"{method.get('status', '-')}"
            )

    return 0


def list_subdomains() -> int:
    data = load_document()
    block = data["subdomain"]

    candidates = block.get("candidates", [])

    print(f"PROJECT: {data.get('project_id', '-')}")
    print(f"DOMAIN : {block.get('domain', '-')}")
    print(f"STATUS : {block.get('status', '-')}")
    print(f"TOTAL  : {len(candidates)}")

    if not candidates:
        print("Tidak ada candidate subdomain yang tersimpan.")
        return 0

    for item in candidates:
        hostname = item.get("hostname", "-")
        state = item.get("status", "-")
        classification = item.get(
            "dns_classification",
            "-",
        )
        ipv4 = ", ".join(item.get("ipv4", [])) or "-"
        ipv6 = ", ".join(item.get("ipv6", [])) or "-"
        scope_status = item.get(
            "scope_status",
            "requires-scope-verification",
        )
        sources = ", ".join(item.get("source", [])) or "-"

        print(f"\n[{hostname}]")
        print(f"  Status         : {state}")
        print(f"  Classification : {classification}")
        print(f"  IPv4           : {ipv4}")
        print(f"  IPv6           : {ipv6}")
        print(f"  Source         : {sources}")
        print(f"  Scope          : {scope_status}")

    return 0


def show() -> int:
    data = load_document()

    print(f"PROJECT: {data.get('project_id', '-')}")
    print(f"FILE   : {output_file()}")
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


def remove() -> int:
    path = output_file()

    if not path.exists():
        print("[INFO] File Subdomain Discovery tidak ada.")
        return 0

    path.unlink()

    print("[PASS] Subdomain Discovery berhasil dihapus.")
    print(f"FILE: {path}")

    return 0


def init() -> int:
    context = project_context()
    target_path = target_file()

    target = load_yaml(target_path)
    target_project_id = str(target.get("project_id", "")).strip()

    if not target_project_id:
        print("[FAIL] project_id pada target.yaml kosong.")
        return 1

    active_project_id = getattr(context, "project_id", None)

    if (
        active_project_id
        and str(active_project_id) != target_project_id
    ):
        print(
            "[FAIL] project_id target.yaml tidak sesuai active project."
        )
        return 1

    document = build_initial_document(target)
    save_yaml(output_file(), document)

    print("[PASS] Subdomain Discovery berhasil diinisialisasi.")
    print(f"PROJECT: {target_project_id}")
    print(f"DOMAIN : {document['subdomain']['domain']}")
    print(f"FILE   : {output_file()}")

    return 0


def version() -> int:
    print(
        "BrebesKab-CSIRT-Tools "
        f"subdomain.py v{SCRIPT_VERSION}"
    )
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT - Subdomain Discovery"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    subparsers.add_parser(
        "init",
        help="Inisialisasi subdomain.yaml.",
    )

    subparsers.add_parser(
        "discover",
        help="Melakukan subdomain discovery.",
    )

    subparsers.add_parser(
        "list",
        help="Menampilkan candidate subdomain.",
    )

    subparsers.add_parser(
        "show",
        help="Menampilkan isi subdomain.yaml.",
    )

    subparsers.add_parser(
        "verify",
        help="Memvalidasi hasil discovery.",
    )

    subparsers.add_parser(
        "status",
        help="Menampilkan status.",
    )

    subparsers.add_parser(
        "remove",
        help="Menghapus hasil Subdomain Discovery.",
    )

    subparsers.add_parser(
        "version",
        help="Menampilkan versi script.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    commands = {
        "init": init,
        "discover": discover,
        "list": list_subdomains,
        "show": show,
        "verify": verify,
        "status": status,
        "remove": remove,
        "version": version,
    }

    try:
        return int(commands[args.command]())

    except KeyboardInterrupt:
        print("\n[WARN] Proses dibatalkan.")
        return 130

    except FileNotFoundError as exc:
        print(f"[FAIL] {exc}")
        return 1

    except ValueError as exc:
        print(f"[FAIL] {exc}")
        return 1

    except Exception as exc:
        print(f"[FAIL] {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
