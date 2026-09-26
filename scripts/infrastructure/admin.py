#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Infrastructure - Administrative Service Exposure

Version: 1.0.1

Checklist mapping:
    3-004 - Administrative service exposure

Purpose:
    Identify and characterize services/interfaces that can provide system,
    network, platform, or application administration access, using completed
    reconnaissance/infrastructure evidence as the baseline.

Design principles:
    - Reuse existing evidence before performing new discovery.
    - Does NOT repeat the reconnaissance TCP port scan.
    - Does NOT treat every open port as an administrative service.
    - Separates administrative classification from authorization/scope.
    - Outside-scope exposure is recorded for review but is not automatically
      classified as a vulnerability.
    - Endpoint/directory evidence is used to select additional HTTP probe targets.
    - Standard management paths are probe heuristics, not findings by themselves.
    - A web-management candidate is created only when the active HTTP GET
      probe records an HTTP response status of 200.
    - HTTP 3xx, 4xx, 5xx, timeout, and transport errors are retained as
      evidence but are not promoted to web-management candidates.
    - No brute force, login, credential testing, destructive methods, or
      exploitation are performed.
    - Active probing is best-effort and does not erase passive/source evidence.
    - Stores technical evidence for downstream Finding Review/Remediation.

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
    projects/<PROJECT-ID>/03-infrastructure/admin/admin.yaml
    projects/<PROJECT-ID>/03-infrastructure/admin/evidence/http-probes.json
"""

from __future__ import annotations

import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Import bootstrap
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

# This script lives in scripts/infrastructure while the repository also
# contains scripts/reconnaissance/http.py. When Python executes a script
# directly, its own directory is placed in sys.path[0]. Clean that entry
# BEFORE importing urllib, requests, or other packages that depend on the
# standard-library http package. Otherwise a local http.py can shadow
# Python's standard-library http package.
for _entry in (str(SCRIPT_DIR),):
    while _entry in sys.path:
        sys.path.remove(_entry)

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))


import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import ssl
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

import yaml

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

CHECKLIST_ID = "3-004"
CHECKLIST_NAME = "Administrative service exposure"

PREPARATION_DIR = "01-preparation"
RECON_DIR = "02-reconnaissance"
INFRASTRUCTURE_DIR = "03-infrastructure"

SCOPE_DIR = "scope"
SCOPE_FILE = "scope.yaml"

NETWORK_DIR = "network"
NETWORK_FILE = "network.yaml"

ENDPOINT_DIR = "endpoint"
ENDPOINT_FILE = "endpoint.yaml"

DIRECTORY_DIR = "directory"
DIRECTORY_FILE = "directory.yaml"

SERVICE_DIR = "service"
SERVICE_FILE = "service.yaml"

ADMIN_DIR = "admin"
ADMIN_FILE = "admin.yaml"
EVIDENCE_DIR = "evidence"
HTTP_PROBE_FILE = "http-probes.json"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
    "skipped",
    "failed",
    "blocked",
}

VALID_TYPES = {
    "administrative",
    "management-capable",
    "web-management-candidate",
    "non-administrative",
    "unknown",
}

VALID_ASSESSMENTS = {
    "authorized",
    "requires-review",
    "observed",
}

# Active probing is deliberately conservative. The current assessment's
# authorization boundary is still taken from scope.yaml; these are only
# path signatures for a primary in-scope web service.
STANDARD_MANAGEMENT_PATHS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/administrator/",
    "/management",
    "/management/",
    "/manager",
    "/manager/",
    "/control",
    "/control/",
    "/control-panel",
    "/control-panel/",
    "/panel",
    "/panel/",
    "/dashboard",
    "/dashboard/",
    "/webmin",
    "/webmin/",
    "/cockpit",
    "/cockpit/",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/adminer",
    "/adminer/",
    "/cpanel",
    "/cpanel/",
    "/whm",
    "/whm/",
    "/plesk",
    "/plesk/",
    "/server-status",
    "/server-status/",
    "/server-info",
    "/server-info/",
]

# Stronger path indicators. These increase confidence but are never treated
# as proof of a vulnerability by themselves.
WEB_PATH_RULES: dict[str, dict[str, Any]] = {
    "phpmyadmin": {
        "tokens": ("phpmyadmin",),
        "category": "database-management-interface",
    },
    "adminer": {
        "tokens": ("adminer",),
        "category": "database-management-interface",
    },
    "webmin": {
        "tokens": ("webmin",),
        "category": "server-management-interface",
    },
    "cockpit": {
        "tokens": ("cockpit",),
        "category": "server-management-interface",
    },
    "cpanel": {
        "tokens": ("cpanel",),
        "category": "hosting-management-interface",
    },
    "whm": {
        "tokens": ("whm", "whmcs"),
        "category": "hosting-management-interface",
    },
    "plesk": {
        "tokens": ("plesk",),
        "category": "hosting-management-interface",
    },
    "admin": {
        "tokens": ("/admin", "/administrator", "/management", "/manager"),
        "category": "application-management-interface",
    },
    "dashboard": {
        "tokens": ("/dashboard", "/panel", "/control", "/control-panel"),
        "category": "application-management-interface",
    },
}

# Service rules are intentionally classification rules, not vulnerability
# rules. Port matching is a strong signal; service/product text is a second
# signal and is preserved in the output.
SERVICE_RULES: list[dict[str, Any]] = [
    {
        "key": "ssh",
        "ports": {22},
        "tokens": ("ssh", "openssh"),
        "type": "administrative",
        "category": "direct-remote-administration",
        "confidence": "high",
        "description": "Remote terminal/administration service.",
    },
    {
        "key": "telnet",
        "ports": {23},
        "tokens": ("telnet",),
        "type": "administrative",
        "category": "direct-remote-administration",
        "confidence": "high",
        "description": "Remote terminal/administration service.",
    },
    {
        "key": "rdp",
        "ports": {3389},
        "tokens": ("rdp", "ms-wbt-server", "remote desktop", "terminal services"),
        "type": "administrative",
        "category": "remote-desktop-administration",
        "confidence": "high",
        "description": "Remote desktop administration service.",
    },
    {
        "key": "winrm",
        "ports": {5985, 5986},
        "tokens": ("winrm", "wsman", "windows remote management"),
        "type": "administrative",
        "category": "windows-remote-administration",
        "confidence": "high",
        "description": "Windows remote management service.",
    },
    {
        "key": "vnc",
        "ports": set(range(5900, 6000)),
        "tokens": ("vnc", "realvnc", "tightvnc", "tigervnc"),
        "type": "administrative",
        "category": "remote-desktop-administration",
        "confidence": "high",
        "description": "Remote desktop administration service.",
    },
    {
        "key": "webmin",
        "ports": {10000},
        "tokens": ("webmin",),
        "type": "administrative",
        "category": "server-management-interface",
        "confidence": "high",
        "description": "Server management interface.",
    },
    {
        "key": "cockpit",
        "ports": {9090},
        "tokens": ("cockpit",),
        "type": "administrative",
        "category": "server-management-interface",
        "confidence": "high",
        "description": "Server management interface.",
    },
    {
        "key": "cpanel",
        "ports": {2082, 2083, 2086, 2087},
        "tokens": ("cpanel", "whm"),
        "type": "administrative",
        "category": "hosting-management-interface",
        "confidence": "high",
        "description": "Hosting/server administration interface.",
    },
    {
        "key": "plesk",
        "ports": {8443, 8880},
        "tokens": ("plesk",),
        "type": "administrative",
        "category": "hosting-management-interface",
        "confidence": "high",
        "description": "Hosting/server administration interface.",
    },
    {
        "key": "snmp",
        "ports": {161, 162},
        "tokens": ("snmp",),
        "type": "management-capable",
        "category": "network-management-protocol",
        "confidence": "medium",
        "description": "Network/device management and monitoring protocol.",
    },
    {
        "key": "netconf",
        "ports": {830},
        "tokens": ("netconf",),
        "type": "administrative",
        "category": "network-configuration-management",
        "confidence": "high",
        "description": "Network configuration management protocol.",
    },
    {
        "key": "restconf",
        "ports": set(),
        "tokens": ("restconf",),
        "type": "administrative",
        "category": "network-configuration-management",
        "confidence": "high",
        "description": "Network configuration management API.",
    },
]

HTTP_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8880, 9090, 10000, 2082, 2083, 2086, 2087}
HTTP_SERVICE_TOKENS = (
    "http",
    "https",
    "http-proxy",
    "ssl/http",
    "www",
)

HTTP_TIMEOUT = 10
HTTP_DELAY = 0.15
MAX_HTTP_PROBES = 80
MAX_RESPONSE_BYTES = 512 * 1024
USER_AGENT = "BrebesKab-CSIRT-Tools/1.0.1 administrative-service-exposure"


class AdministrativeServiceError(RuntimeError):
    """Raised when administrative-service analysis cannot be completed safely."""


# ---------------------------------------------------------------------------
# General helpers
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


def endpoint_file() -> Path:
    return project_root() / RECON_DIR / ENDPOINT_DIR / ENDPOINT_FILE


def directory_file() -> Path:
    return project_root() / RECON_DIR / DIRECTORY_DIR / DIRECTORY_FILE


def service_file() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / SERVICE_DIR / SERVICE_FILE


def admin_dir() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / ADMIN_DIR


def admin_file() -> Path:
    return admin_dir() / ADMIN_FILE


def evidence_dir() -> Path:
    return admin_dir() / EVIDENCE_DIR


def http_probe_file() -> Path:
    return evidence_dir() / HTTP_PROBE_FILE


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise AdministrativeServiceError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise AdministrativeServiceError(
            f"Gagal membaca {label}: {path}\n{exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise AdministrativeServiceError(
            f"YAML {label} tidak valid: {path}\n{exc}"
        ) from exc

    if not isinstance(data, dict):
        raise AdministrativeServiceError(
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
        raise AdministrativeServiceError(f"Gagal menulis: {path}\n{exc}") from exc


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    except OSError as exc:
        raise AdministrativeServiceError(f"Gagal menulis: {path}\n{exc}") from exc


def record(action: str, status: str) -> None:
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


def require_project_id(data: dict[str, Any], label: str) -> None:
    expected = project_root().name
    actual = str(data.get("project_id", "")).strip()

    if actual != expected:
        raise AdministrativeServiceError(
            f"Project ID pada {label} tidak sesuai active project. "
            f"Expected: {expected}; Found: {actual or '-'}"
        )


def nested_payload(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise AdministrativeServiceError(
            f"Field '{name}' pada dokumen tidak valid."
        )
    return value


def safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def normalize_text(*values: Any) -> str:
    return " ".join(
        str(value).strip().lower()
        for value in values
        if str(value).strip()
    )


def extract_path(url_or_path: str) -> str:
    value = str(url_or_path or "").strip()
    if not value:
        return ""

    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    return value if value.startswith("/") else f"/{value}"


def path_token_text(path: str) -> str:
    normalized = extract_path(path).lower()
    return normalized.rstrip("/") or "/"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def html_title(body: bytes) -> str:
    text = body.decode("utf-8", errors="replace")
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:250]


def response_signature(body: bytes) -> dict[str, Any]:
    return {
        "sha256": sha256_bytes(body),
        "length": len(body),
        "title": html_title(body),
    }


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------


def load_scope() -> dict[str, Any]:
    data = load_yaml(scope_file(), "scope.yaml")
    require_project_id(data, "scope.yaml")

    scope = nested_payload(data, "scope")
    if not isinstance(scope.get("in_scope"), list):
        raise AdministrativeServiceError(
            "Field scope.in_scope pada scope.yaml harus berupa list."
        )

    return data


def load_network() -> dict[str, Any]:
    data = load_yaml(network_file(), "network.yaml")
    require_project_id(data, "network.yaml")

    network = nested_payload(data, "network")
    if str(network.get("status", "")).strip().lower() != "completed":
        raise AdministrativeServiceError(
            "Reconnaissance network belum completed. Jalankan network.py terlebih dahulu."
        )

    if not isinstance(network.get("ports"), list):
        raise AdministrativeServiceError(
            "Field network.ports pada network.yaml harus berupa list."
        )

    return data


def load_service() -> dict[str, Any]:
    data = load_yaml(service_file(), "service.yaml")
    require_project_id(data, "service.yaml")

    service = nested_payload(data, "service")
    if str(service.get("status", "")).strip().lower() != "completed":
        raise AdministrativeServiceError(
            "Service Enumeration belum completed. Jalankan service.py terlebih dahulu."
        )

    if not isinstance(service.get("results"), list):
        raise AdministrativeServiceError(
            "Field service.results pada service.yaml harus berupa list."
        )

    return data


def load_optional_source(path: Path, label: str) -> tuple[dict[str, Any] | None, str, str]:
    if not path.exists():
        return None, "unavailable", f"{label} tidak ditemukan."

    try:
        data = load_yaml(path, label)
    except AdministrativeServiceError as exc:
        return None, "invalid", str(exc)

    status = str(data.get("status", "")).strip().lower()
    if not status and isinstance(data.get(label.split(".")[0]), dict):
        status = str(data[label.split(".")[0]].get("status", "")).strip().lower()

    return data, status or "unknown", ""


# ---------------------------------------------------------------------------
# Scope / target metadata
# ---------------------------------------------------------------------------


def target_metadata(network_data: dict[str, Any]) -> dict[str, Any]:
    network = nested_payload(network_data, "network")
    ipv4 = network.get("ipv4") or []
    ipv6 = network.get("ipv6") or []

    if not isinstance(ipv4, list):
        ipv4 = []
    if not isinstance(ipv6, list):
        ipv6 = []

    return {
        "application": str(network.get("application", "")).strip(),
        "target_url": str(network.get("target_url", "")).strip(),
        "hostname": str(network.get("hostname", "")).strip(),
        "target_ip": next((str(item).strip() for item in ipv4 if str(item).strip()), ""),
        "ipv4": [str(item).strip() for item in ipv4 if str(item).strip()],
        "ipv6": [str(item).strip() for item in ipv6 if str(item).strip()],
        "environment": str(network.get("environment", "")).strip(),
        "assessment_type": str(network.get("assessment_type", "")).strip(),
        "scope_reference": str(network.get("scope_reference", "")).strip(),
    }


def scope_port_set(scope_data: dict[str, Any]) -> tuple[set[int], list[dict[str, Any]]]:
    scope = nested_payload(scope_data, "scope")
    authorized: set[int] = set()
    references: list[dict[str, Any]] = []

    for item in scope.get("in_scope", []):
        if not isinstance(item, dict):
            continue

        ports_raw = item.get("ports") or []
        if not isinstance(ports_raw, list):
            continue

        ports: list[int] = []
        for raw in ports_raw:
            try:
                port = int(raw)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                authorized.add(port)
                ports.append(port)

        if ports:
            references.append(
                {
                    "scope_id": str(item.get("scope_id", "")).strip(),
                    "type": str(item.get("type", "")).strip(),
                    "value": str(item.get("value", "")).strip(),
                    "ports": sorted(set(ports)),
                    "protocols": [
                        str(value).strip().lower()
                        for value in (item.get("protocols") or [])
                        if str(value).strip()
                    ],
                }
            )

    return authorized, references


def scope_status_for_port(port: int, authorized_ports: set[int]) -> tuple[str, str, bool]:
    if port in authorized_ports:
        return "in-scope", "authorized", False
    return "outside-scope", "requires-review", True


# ---------------------------------------------------------------------------
# Passive service classification
# ---------------------------------------------------------------------------


def service_metadata_index(service_data: dict[str, Any]) -> list[dict[str, Any]]:
    service = nested_payload(service_data, "service")
    output: list[dict[str, Any]] = []

    for raw in service.get("results", []):
        if not isinstance(raw, dict):
            continue

        try:
            port = int(raw.get("port"))
        except (TypeError, ValueError):
            continue

        protocol = str(raw.get("protocol", "")).strip().lower() or "tcp"
        state = str(raw.get("state", "")).strip().lower()
        service_name = str(raw.get("service", "")).strip()
        product = str(raw.get("product", "")).strip()
        version = str(raw.get("version", "")).strip()
        extra = str(raw.get("extrainfo", raw.get("extra_info", ""))).strip()
        cpe = raw.get("cpe")
        if isinstance(cpe, list):
            cpe_values = [str(value).strip() for value in cpe if str(value).strip()]
        elif cpe:
            cpe_values = [str(cpe).strip()]
        else:
            cpe_values = []

        output.append(
            {
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version,
                "extrainfo": extra,
                "cpe": cpe_values,
                "hostname": str(raw.get("hostname", "")).strip(),
                "tunnel": str(raw.get("tunnel", "")).strip(),
                "raw": raw,
            }
        )

    return sorted(output, key=lambda item: (item["port"], item["protocol"]))


def find_service_rule(service_item: dict[str, Any]) -> dict[str, Any] | None:
    port = int(service_item["port"])
    haystack = normalize_text(
        service_item.get("service"),
        service_item.get("product"),
        service_item.get("version"),
        service_item.get("extrainfo"),
        *service_item.get("cpe", []),
    )

    matches: list[tuple[int, dict[str, Any]]] = []

    for rule in SERVICE_RULES:
        port_match = port in rule["ports"] if rule["ports"] else False
        token_matches = [token for token in rule["tokens"] if token.lower() in haystack]
        score = (100 if port_match else 0) + (20 * len(token_matches))

        if score:
            rule_copy = dict(rule)
            rule_copy["matched_tokens"] = token_matches
            rule_copy["port_match"] = port_match
            matches.append((score, rule_copy))

    if not matches:
        return None

    matches.sort(key=lambda item: item[0], reverse=True)
    return matches[0][1]


def looks_like_web_service(service_item: dict[str, Any]) -> bool:
    port = int(service_item["port"])
    text = normalize_text(
        service_item.get("service"),
        service_item.get("product"),
        service_item.get("extrainfo"),
        service_item.get("tunnel"),
    )
    return port in HTTP_PORTS or any(token in text for token in HTTP_SERVICE_TOKENS)


def classify_service(service_item: dict[str, Any], authorized_ports: set[int]) -> dict[str, Any]:
    port = int(service_item["port"])
    protocol = str(service_item.get("protocol", "tcp")).strip().lower()
    scope_status, assessment, outside = scope_status_for_port(port, authorized_ports)

    rule = find_service_rule(service_item)

    if rule is not None:
        classification_type = str(rule["type"])
        category = str(rule["category"])
        confidence = str(rule["confidence"])
        matched_rule = str(rule["key"])
        matched_tokens = list(rule.get("matched_tokens", []))
        rationale = str(rule["description"])
    elif looks_like_web_service(service_item):
        classification_type = "non-administrative"
        category = "web-service"
        confidence = "high"
        matched_rule = "web-service"
        matched_tokens = []
        rationale = (
            "Service teridentifikasi sebagai HTTP/HTTPS/web service, tetapi belum ada "
            "indikasi administratif dari service metadata. Web management ditangani "
            "secara terpisah melalui endpoint/directory correlation."
        )
    else:
        has_metadata = any(
            str(service_item.get(field, "")).strip()
            for field in ("service", "product", "version", "extrainfo")
        ) or bool(service_item.get("cpe"))
        if has_metadata:
            classification_type = "non-administrative"
            category = "general-service"
            confidence = "medium"
            rationale = (
                "Tidak terdapat indikator administrative/management pada port atau "
                "metadata service yang tersedia."
            )
        else:
            classification_type = "unknown"
            category = "unclassified-service"
            confidence = "low"
            rationale = (
                "Metadata service tidak cukup untuk menentukan fungsi administrative "
                "atau non-administrative."
            )
        matched_rule = "none"
        matched_tokens = []

    requires_review = assessment == "requires-review" or classification_type in {
        "administrative",
        "management-capable",
        "web-management-candidate",
    }

    return {
        "port": port,
        "protocol": protocol,
        "state": str(service_item.get("state", "")).strip().lower(),
        "service": str(service_item.get("service", "")).strip(),
        "product": str(service_item.get("product", "")).strip(),
        "version": str(service_item.get("version", "")).strip(),
        "extrainfo": str(service_item.get("extrainfo", "")).strip(),
        "cpe": list(service_item.get("cpe", [])),
        "hostname": str(service_item.get("hostname", "")).strip(),
        "tunnel": str(service_item.get("tunnel", "")).strip(),
        "scope_status": scope_status,
        "assessment": assessment,
        "requires_review": requires_review,
        "classification": {
            "type": classification_type,
            "category": category,
            "confidence": confidence,
            "matched_rule": matched_rule,
            "matched_tokens": matched_tokens,
            "rationale": rationale,
        },
        "source": "03-infrastructure/service/service.yaml",
    }


# ---------------------------------------------------------------------------
# Web management correlation
# ---------------------------------------------------------------------------


def load_endpoint_items(endpoint_data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if endpoint_data is None:
        return []

    payload = endpoint_data.get("endpoint")
    if isinstance(payload, dict):
        return [item for item in safe_list(payload.get("endpoints")) if isinstance(item, dict)]

    return [item for item in safe_list(endpoint_data.get("endpoints")) if isinstance(item, dict)]


def load_directory_items(directory_data: dict[str, Any] | None) -> list[dict[str, Any]]:
    if directory_data is None:
        return []

    payload = directory_data.get("directory")
    if isinstance(payload, dict):
        items = payload.get("results")
    else:
        items = directory_data.get("directories") or directory_data.get("results")

    return [item for item in safe_list(items) if isinstance(item, dict)]


def match_web_path_rule(path: str) -> tuple[str, str, str, list[str]] | None:
    normalized = path_token_text(path)
    lower = normalized.lower()

    matches: list[tuple[int, str, str, str, list[str]]] = []

    for key, rule in WEB_PATH_RULES.items():
        matched = [token for token in rule["tokens"] if token in lower]
        if matched:
            score = max(len(token) for token in matched)
            matches.append(
                (
                    score,
                    key,
                    str(rule["category"]),
                    ",".join(matched),
                    matched,
                )
            )

    if not matches:
        return None

    matches.sort(reverse=True)
    _, key, category, _, matched = matches[0]

    confidence = "high" if key in {"phpmyadmin", "adminer", "webmin", "cockpit", "cpanel", "whm", "plesk"} else "medium"
    return key, category, confidence, matched


def correlate_web_candidates(
    endpoint_data: dict[str, Any] | None,
    directory_data: dict[str, Any] | None,
    authorized_ports: set[int],
    target_url: str,
) -> list[dict[str, Any]]:
    """Collect web management probe targets from passive evidence.

    Important: this function does NOT create a web-management candidate.
    Endpoint/directory matches and standard path rules are only heuristics
    used to decide which paths should receive controlled HTTP GET probes.
    A final web-management candidate is created later only when the active
    probe receives HTTP status code 200.
    """
    observations: dict[str, dict[str, Any]] = {}

    def add(
        path: str,
        source: str,
        url: str = "",
        status_code: Any = None,
        content_length: Any = None,
        redirect: str = "",
    ) -> None:
        path_value = extract_path(path)
        key = path_token_text(path_value)
        if not key or key == "/":
            return

        rule = match_web_path_rule(path_value)
        if rule is None:
            return

        item = observations.setdefault(
            key,
            {
                "path": path_value,
                "sources": [],
                "urls": [],
                "status_codes": [],
                "content_lengths": [],
                "redirects": [],
                "rule_matches": [],
            },
        )
        if source not in item["sources"]:
            item["sources"].append(source)
        if url and url not in item["urls"]:
            item["urls"].append(url)
        if status_code is not None:
            try:
                value = int(status_code)
                if value not in item["status_codes"]:
                    item["status_codes"].append(value)
            except (TypeError, ValueError):
                pass
        if content_length is not None:
            try:
                value = int(content_length)
                if value not in item["content_lengths"]:
                    item["content_lengths"].append(value)
            except (TypeError, ValueError):
                pass
        if redirect and redirect not in item["redirects"]:
            item["redirects"].append(redirect)
        if rule[0] not in item["rule_matches"]:
            item["rule_matches"].append(rule[0])

    for raw in load_endpoint_items(endpoint_data):
        url = str(raw.get("url", "")).strip()
        if not bool(raw.get("same_host", False)):
            continue
        add(url, "endpoint.yaml", url=url)

    for raw in load_directory_items(directory_data):
        add(
            str(raw.get("path", "")),
            "directory.yaml",
            status_code=raw.get("status_code"),
            content_length=raw.get("content_length"),
            redirect=str(raw.get("redirect", "")).strip(),
        )

    base = str(target_url or "").strip()
    parsed_target = urlparse(base)
    results: list[dict[str, Any]] = []

    for item in observations.values():
        candidate_urls = list(item["urls"])
        if not candidate_urls and parsed_target.scheme and parsed_target.netloc:
            candidate_urls.append(urljoin(base, item["path"]))

        port_candidates: set[int] = set()
        for url in candidate_urls:
            try:
                parsed = urlparse(url)
                port = parsed.port
                if port is None:
                    port = 443 if parsed.scheme.lower() == "https" else 80
                port_candidates.add(int(port))
            except ValueError:
                continue

        if not port_candidates and parsed_target.scheme:
            default_port = 443 if parsed_target.scheme.lower() == "https" else 80
            port_candidates.add(default_port)

        in_scope_ports = sorted(port for port in port_candidates if port in authorized_ports)
        outside_ports = sorted(port for port in port_candidates if port not in authorized_ports)
        assessment = "authorized" if in_scope_ports else "requires-review"

        rule = match_web_path_rule(item["path"])
        if rule is None:
            continue

        results.append(
            {
                "path": item["path"],
                "candidate_urls": sorted(set(candidate_urls)),
                "sources": sorted(item["sources"]),
                "observed_status_codes": sorted(item["status_codes"]),
                "observed_content_lengths": sorted(item["content_lengths"]),
                "observed_redirects": sorted(item["redirects"]),
                "matching_rules": item["rule_matches"],
                "category": rule[1],
                "confidence": rule[2],
                "scope_ports": {
                    "in_scope": in_scope_ports,
                    "outside_scope": outside_ports,
                },
                "assessment": assessment,
                "requires_review": False,
                "classification": "probe-target",
                "rationale": (
                    "Path digunakan sebagai target active HTTP probe berdasarkan "
                    "heuristic path matching. Ini bukan web-management candidate "
                    "sampai probe menghasilkan response HTTP 200."
                ),
            }
        )

    results.sort(key=lambda item: (item["category"], item["path"].lower()))
    return results


# ---------------------------------------------------------------------------
# Active HTTP probing
# ---------------------------------------------------------------------------


def primary_web_bases(
    network_data: dict[str, Any],
    service_classifications: list[dict[str, Any]],
    authorized_ports: set[int],
) -> list[str]:
    network = nested_payload(network_data, "network")
    target_url = str(network.get("target_url", "")).strip()
    hostname = str(network.get("hostname", "")).strip()

    candidates: list[str] = []
    if target_url:
        parsed = urlparse(target_url)
        base_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if base_port in authorized_ports:
            candidates.append(f"{parsed.scheme}://{parsed.netloc}")

    seen = {base.rstrip("/") for base in candidates}

    for item in service_classifications:
        if item.get("port") not in authorized_ports:
            continue
        if not looks_like_web_service(item):
            continue

        port = int(item["port"])
        if port == 80:
            base = f"http://{hostname or '127.0.0.1'}"
        elif port == 443:
            base = f"https://{hostname or '127.0.0.1'}"
        elif port in {8443, 8880, 9090, 10000, 2083, 2087}:
            base = f"https://{hostname or '127.0.0.1'}:{port}"
        else:
            base = f"http://{hostname or '127.0.0.1'}:{port}"

        if base.rstrip("/") not in seen:
            candidates.append(base)
            seen.add(base.rstrip("/"))

    return candidates


def build_probe_targets(
    web_candidates: list[dict[str, Any]],
    bases: list[str],
) -> list[str]:
    paths = {str(item.get("path", "/")) for item in web_candidates if item.get("path")}
    paths.update(STANDARD_MANAGEMENT_PATHS)

    targets: list[str] = []
    seen: set[str] = set()

    for base in bases:
        base_clean = base.rstrip("/")

        # Baseline root request is important for detecting generic 200/catch-all
        # responses from a front controller.
        base_target = base_clean + "/"
        key = base_target.lower()
        if key not in seen:
            seen.add(key)
            targets.append(base_target)

        for path in sorted(paths):
            target = f"{base_clean}{extract_path(path)}"
            key = target.lower()
            if key in seen:
                continue
            seen.add(key)
            targets.append(target)
            if len(targets) >= MAX_HTTP_PROBES:
                return targets

    return targets[:MAX_HTTP_PROBES]


def probe_http_url(url: str) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {
        "url": url,
        "method": "GET",
        "started_at": now_iso(),
        "status_code": None,
        "final_url": "",
        "redirect_chain": [],
        "headers": {},
        "content_length": None,
        "content_type": "",
        "title": "",
        "server": "",
        "location": "",
        "body_sha256": "",
        "body_sample_bytes": 0,
        "duration_ms": None,
        "error": "",
        "tool": "python-urllib",
    }

    request = Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5"},
        method="GET",
    )

    # The assessment already has certificate validation evidence in Recon.
    # For this evidence-gathering probe we keep default TLS validation enabled
    # first; an invalid cert is recorded as an error, not silently converted
    # into success.
    context = ssl.create_default_context()

    try:
        with urlopen(request, timeout=HTTP_TIMEOUT, context=context) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                body = body[:MAX_RESPONSE_BYTES]

            headers = {str(key): str(value) for key, value in response.headers.items()}
            result["status_code"] = int(response.status)
            result["final_url"] = str(response.geturl())
            result["headers"] = headers
            result["content_length"] = int(headers.get("Content-Length")) if headers.get("Content-Length", "").isdigit() else len(body)
            result["content_type"] = headers.get("Content-Type", "")
            result["title"] = html_title(body)
            result["server"] = headers.get("Server", "")
            result["location"] = headers.get("Location", "")
            result["body_sha256"] = sha256_bytes(body)
            result["body_sample_bytes"] = len(body)
            result["redirect_chain"] = [str(response.geturl())]

    except HTTPError as exc:
        body = b""
        try:
            body = exc.read(MAX_RESPONSE_BYTES)
        except Exception:
            pass

        result["status_code"] = int(exc.code)
        result["final_url"] = str(exc.geturl())
        result["headers"] = {str(key): str(value) for key, value in exc.headers.items()}
        result["content_type"] = result["headers"].get("Content-Type", "")
        result["title"] = html_title(body)
        result["server"] = result["headers"].get("Server", "")
        result["location"] = result["headers"].get("Location", "")
        result["body_sha256"] = sha256_bytes(body)
        result["body_sample_bytes"] = len(body)
        result["error"] = ""
    except (URLError, TimeoutError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    result["completed_at"] = now_iso()
    return result


def run_http_probes(targets: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for index, target in enumerate(targets):
        if index:
            time.sleep(HTTP_DELAY)
        result = probe_http_url(target)
        results.append(result)

    return results


def derive_probe_candidates(
    probe_results: list[dict[str, Any]],
    bases: list[str],
    authorized_ports: set[int],
) -> list[dict[str, Any]]:
    """Promote active probe results to web-management candidates.

    Current project rule:
        HTTP response status == 200 -> web-management candidate.

    No stronger semantic claim is made. A 200 response may still be a
    catch-all/front-controller response or an ordinary application page;
    determining the actual function belongs to later analysis/checklists.
    """
    results: dict[tuple[str, str], dict[str, Any]] = {}

    for probe in probe_results:
        status = probe.get("status_code")
        if status != 200:
            continue

        url = str(probe.get("url", "")).strip()
        parsed = urlparse(url)
        path = parsed.path or "/"
        normalized_path = path_token_text(path)
        if normalized_path == "/":
            continue

        rule = match_web_path_rule(normalized_path)
        if rule is None:
            continue

        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        scope_status, assessment, _ = scope_status_for_port(port, authorized_ports)

        key = (f"{parsed.scheme}://{parsed.netloc}".lower(), normalized_path)
        existing = results.get(key)

        candidate = {
            "path": normalized_path,
            "candidate_urls": [url],
            "sources": ["active-probe-standard-management-path"],
            "observed_status_codes": [200],
            "observed_content_lengths": [probe.get("content_length")] if isinstance(probe.get("content_length"), int) else [],
            "observed_redirects": [str(probe.get("location", ""))] if str(probe.get("location", "")).strip() else [],
            "matching_rules": [rule[0]],
            "category": rule[1],
            "confidence": rule[2],
            "scope_ports": {
                "in_scope": [port] if port in authorized_ports else [],
                "outside_scope": [port] if port not in authorized_ports else [],
            },
            "assessment": assessment,
            "requires_review": True,
            "classification": "web-management-candidate",
            "candidate_basis": "http-200",
            "rationale": (
                "Active HTTP GET menerima response status 200. Path dicatat "
                "sebagai web-management candidate berdasarkan rule project saat ini; "
                "response 200 tidak dengan sendirinya membuktikan fungsi administratif "
                "atau vulnerability."
            ),
            "active_probe": {
                "attempted": True,
                "results": [probe],
            },
            "active_assessment": "http-200-observed",
            "active_rationale": (
                "Active HTTP GET menghasilkan response status 200; hasil ini cukup "
                "untuk menjadikan path sebagai candidate pada versi toolkit ini."
            ),
            "observed_active_status_codes": [200],
            "observed_active_titles": [str(probe.get("title", "")).strip()] if str(probe.get("title", "")).strip() else [],
            "observed_active_servers": [str(probe.get("server", "")).strip()] if str(probe.get("server", "")).strip() else [],
            "probe_errors": [str(probe.get("error", "")).strip()] if str(probe.get("error", "")).strip() else [],
        }

        if existing is None:
            results[key] = candidate
        else:
            for field in ("candidate_urls", "sources", "observed_status_codes", "observed_content_lengths", "observed_redirects", "matching_rules", "observed_active_titles", "observed_active_servers", "probe_errors"):
                values = existing.get(field, [])
                for value in candidate.get(field, []):
                    if value not in values:
                        values.append(value)
                existing[field] = values

            existing["active_probe"]["results"].append(probe)

    return sorted(results.values(), key=lambda item: (item["category"], item["path"].lower()))


def enrich_web_candidates(
    candidates: list[dict[str, Any]],
    probe_targets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach passive endpoint/directory context to confirmed 200 candidates."""
    target_index: dict[str, list[dict[str, Any]]] = {}
    for target in probe_targets:
        path = path_token_text(str(target.get("path", "")))
        if path and path != "/":
            target_index.setdefault(path, []).append(target)

    enriched: list[dict[str, Any]] = []
    for candidate in candidates:
        path = path_token_text(str(candidate.get("path", "")))
        matches = target_index.get(path, [])
        candidate_copy = dict(candidate)

        passive_sources: set[str] = set(candidate_copy.get("sources", []))
        passive_statuses: set[int] = set(candidate_copy.get("observed_status_codes", []))
        passive_lengths: set[int] = set(candidate_copy.get("observed_content_lengths", []))
        passive_redirects: set[str] = set(candidate_copy.get("observed_redirects", []))
        matching_rules: set[str] = set(candidate_copy.get("matching_rules", []))

        for match in matches:
            passive_sources.update(str(value) for value in match.get("sources", []))
            passive_statuses.update(
                int(value) for value in match.get("observed_status_codes", [])
                if isinstance(value, int)
            )
            passive_lengths.update(
                int(value) for value in match.get("observed_content_lengths", [])
                if isinstance(value, int)
            )
            passive_redirects.update(
                str(value) for value in match.get("observed_redirects", [])
                if str(value).strip()
            )
            matching_rules.update(str(value) for value in match.get("matching_rules", []))

        candidate_copy["sources"] = sorted(passive_sources)
        candidate_copy["observed_status_codes"] = sorted(passive_statuses)
        candidate_copy["observed_content_lengths"] = sorted(passive_lengths)
        candidate_copy["observed_redirects"] = sorted(passive_redirects)
        candidate_copy["matching_rules"] = sorted(matching_rules)

        if matches:
            candidate_copy["discovery"] = {
                "observed": True,
                "sources": sorted(passive_sources.intersection({"endpoint.yaml", "directory.yaml"})),
            }
        else:
            candidate_copy["discovery"] = {
                "observed": False,
                "sources": [],
            }

        enriched.append(candidate_copy)

    return enriched


# ---------------------------------------------------------------------------
# Document construction
# ---------------------------------------------------------------------------


def build_document(
    network_data: dict[str, Any],
    scope_data: dict[str, Any],
    service_data: dict[str, Any],
    endpoint_data: dict[str, Any] | None,
    endpoint_status: str,
    directory_data: dict[str, Any] | None,
    directory_status: str,
    probe_results: list[dict[str, Any]],
    status: str,
) -> dict[str, Any]:
    target = target_metadata(network_data)
    authorized_ports, scope_refs = scope_port_set(scope_data)

    service_items = service_metadata_index(service_data)
    service_results = [
        classify_service(item, authorized_ports)
        for item in service_items
    ]

    probe_targets = correlate_web_candidates(
        endpoint_data=endpoint_data,
        directory_data=directory_data,
        authorized_ports=authorized_ports,
        target_url=target["target_url"],
    )

    bases = primary_web_bases(network_data, service_results, authorized_ports)

    # Only active HTTP 200 responses become web-management candidates.
    # Endpoint/directory evidence remains probe-target context unless a 200
    # response is actually observed.
    web_candidates = derive_probe_candidates(
        probe_results,
        bases,
        authorized_ports,
    )
    web_candidates = enrich_web_candidates(web_candidates, probe_targets)

    admin_services = [
        item for item in service_results
        if item["classification"]["type"] == "administrative"
    ]
    management_services = [
        item for item in service_results
        if item["classification"]["type"] == "management-capable"
    ]
    web_management = [item for item in web_candidates if item["classification"] == "web-management-candidate"]

    outside_scope_admin = [
        item for item in admin_services + management_services
        if item["scope_status"] == "outside-scope"
    ]
    requires_review = [
        item for item in service_results
        if item["requires_review"]
    ] + [
        item for item in web_management
        if item["requires_review"]
    ]

    notes: list[str] = []
    if endpoint_status not in {"completed", "in-progress"}:
        notes.append(f"Endpoint source status: {endpoint_status}.")
    if directory_status not in {"completed", "in-progress"}:
        notes.append(f"Directory source status: {directory_status}.")
    if not bases:
        notes.append("Tidak ada in-scope HTTP/HTTPS base yang dapat diprobe.")
    if not probe_results:
        notes.append("Tidak ada active HTTP probe yang berhasil dijalankan.")
    notes.append(
        "Administrative classification is evidence-based; classification alone "
        "is not a vulnerability finding."
    )
    notes.append(
        "Outside-scope administrative services are retained as review evidence and "
        "are not automatically considered vulnerabilities."
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "admin": {
            "status": status,
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": target["application"],
            "target_url": target["target_url"],
            "hostname": target["hostname"],
            "target_ip": target["target_ip"],
            "ipv4": target["ipv4"],
            "ipv6": target["ipv6"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_reference": target["scope_reference"],
            "method": "evidence correlation + controlled in-scope HTTP GET; candidate requires HTTP 200",
            "scope_items": scope_refs,
            "authorized_ports": sorted(authorized_ports),
            "primary_web_bases": bases,
            "source_status": {
                "network": "completed",
                "service": "completed",
                "endpoint": endpoint_status,
                "directory": directory_status,
            },
            "sources": {
                "network": "02-reconnaissance/network/network.yaml",
                "service": "03-infrastructure/service/service.yaml",
                "endpoint": "02-reconnaissance/endpoint/endpoint.yaml",
                "directory": "02-reconnaissance/directory/directory.yaml",
                "scope": "01-preparation/scope/scope.yaml",
                "http_probe_evidence": "03-infrastructure/admin/evidence/http-probes.json",
            },
            "classification_rules": {
                "administrative": "Direct remote/system/device/platform administration service.",
                "management-capable": "Management/monitoring protocol that may support administrative operations.",
                "web-management-candidate": "HTTP(S) path/interface that returned status 200 during active probing; path heuristics only select probe targets.",
                "non-administrative": "No current evidence of administrative function.",
                "unknown": "Insufficient evidence to classify.",
            },
            "services": service_results,
            "web_management": web_management,
            "summary": {
                "observed_services": len(service_results),
                "administrative_services": len(admin_services),
                "management_capable_services": len(management_services),
                "web_management_candidates": len(web_management),
                "non_administrative_services": sum(
                    1 for item in service_results
                    if item["classification"]["type"] == "non-administrative"
                ),
                "unknown_services": sum(
                    1 for item in service_results
                    if item["classification"]["type"] == "unknown"
                ),
                "outside_scope_administrative_or_management": len(outside_scope_admin),
                "requires_review": len(requires_review),
                "http_probes": len(probe_results),
                "http_probe_errors": sum(1 for item in probe_results if item.get("error")),
            },
            "notes": notes,
            "generated_at": now_iso(),
        },
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_document(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if str(data.get("schema_version", "")) != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai.")

    if str(data.get("project_id", "")).strip() != project_root().name:
        errors.append("project_id tidak sesuai active project.")

    admin = data.get("admin")
    if not isinstance(admin, dict):
        errors.append("Field admin harus berupa mapping/object.")
        return errors

    status = str(admin.get("status", "")).strip()
    if status not in VALID_STATUSES:
        errors.append(f"Status tidak valid: {status or '-'}")

    if str(admin.get("checklist_id", "")) != CHECKLIST_ID:
        errors.append("Checklist ID tidak sesuai.")

    services = admin.get("services")
    if not isinstance(services, list):
        errors.append("admin.services harus berupa list.")
    else:
        for index, item in enumerate(services, start=1):
            if not isinstance(item, dict):
                errors.append(f"Service #{index} bukan mapping.")
                continue

            try:
                port = int(item.get("port"))
                if not 1 <= port <= 65535:
                    errors.append(f"Service #{index} memiliki port di luar rentang.")
            except (TypeError, ValueError):
                errors.append(f"Service #{index} memiliki port tidak valid.")

            classification = item.get("classification")
            if not isinstance(classification, dict):
                errors.append(f"Service #{index} classification tidak valid.")
            else:
                if classification.get("type") not in VALID_TYPES:
                    errors.append(f"Service #{index} classification.type tidak valid.")

            if item.get("assessment") not in VALID_ASSESSMENTS:
                errors.append(f"Service #{index} assessment tidak valid.")

            if item.get("scope_status") not in {"in-scope", "outside-scope"}:
                errors.append(f"Service #{index} scope_status tidak valid.")

            if not isinstance(item.get("requires_review"), bool):
                errors.append(f"Service #{index} requires_review bukan boolean.")

    web = admin.get("web_management")
    if not isinstance(web, list):
        errors.append("admin.web_management harus berupa list.")
    else:
        for index, item in enumerate(web, start=1):
            if not isinstance(item, dict):
                errors.append(f"Web candidate #{index} bukan mapping.")
                continue
            if item.get("classification") != "web-management-candidate":
                errors.append(f"Web candidate #{index} classification tidak valid.")
            if item.get("candidate_basis") != "http-200":
                errors.append(f"Web candidate #{index} candidate_basis harus http-200.")
            observed = item.get("observed_active_status_codes")
            if not isinstance(observed, list) or 200 not in observed:
                errors.append(f"Web candidate #{index} harus memiliki observed_active_status_codes yang memuat 200.")
            if item.get("active_assessment") != "http-200-observed":
                errors.append(f"Web candidate #{index} active_assessment tidak valid.")
            if item.get("assessment") not in VALID_ASSESSMENTS:
                errors.append(f"Web candidate #{index} assessment tidak valid.")
            if not isinstance(item.get("requires_review"), bool):
                errors.append(f"Web candidate #{index} requires_review bukan boolean.")

    summary = admin.get("summary")
    if not isinstance(summary, dict):
        errors.append("admin.summary harus berupa mapping/object.")
    else:
        for key in (
            "observed_services",
            "administrative_services",
            "management_capable_services",
            "web_management_candidates",
            "non_administrative_services",
            "unknown_services",
            "outside_scope_administrative_or_management",
            "requires_review",
            "http_probes",
            "http_probe_errors",
        ):
            if not isinstance(summary.get(key), int):
                errors.append(f"summary.{key} harus berupa integer.")

    return errors


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init() -> int:
    scope_data = load_scope()
    network_data = load_network()
    service_data = load_service()

    endpoint_data, endpoint_status, endpoint_error = load_optional_source(
        endpoint_file(), "endpoint.yaml"
    )
    directory_data, directory_status, directory_error = load_optional_source(
        directory_file(), "directory.yaml"
    )

    target = target_metadata(network_data)
    authorized_ports, scope_refs = scope_port_set(scope_data)

    initial = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "admin": {
            "status": "not-started",
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": target["application"],
            "target_url": target["target_url"],
            "hostname": target["hostname"],
            "target_ip": target["target_ip"],
            "ipv4": target["ipv4"],
            "ipv6": target["ipv6"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_reference": target["scope_reference"],
            "method": "evidence correlation + controlled in-scope HTTP GET; candidate requires HTTP 200",
            "scope_items": scope_refs,
            "authorized_ports": sorted(authorized_ports),
            "primary_web_bases": [],
            "source_status": {
                "network": str(nested_payload(network_data, "network").get("status", "")).strip().lower(),
                "service": str(nested_payload(service_data, "service").get("status", "")).strip().lower(),
                "endpoint": endpoint_status,
                "directory": directory_status,
            },
            "sources": {
                "network": "02-reconnaissance/network/network.yaml",
                "service": "03-infrastructure/service/service.yaml",
                "endpoint": "02-reconnaissance/endpoint/endpoint.yaml",
                "directory": "02-reconnaissance/directory/directory.yaml",
                "scope": "01-preparation/scope/scope.yaml",
                "http_probe_evidence": "03-infrastructure/admin/evidence/http-probes.json",
            },
            "classification_rules": {
                "administrative": "Direct remote/system/device/platform administration service.",
                "management-capable": "Management/monitoring protocol that may support administrative operations.",
                "web-management-candidate": "HTTP(S) path/interface that returned status 200 during active probing; path heuristics only select probe targets.",
                "non-administrative": "No current evidence of administrative function.",
                "unknown": "Insufficient evidence to classify.",
            },
            "services": [],
            "web_management": [],
            "summary": {
                "observed_services": 0,
                "administrative_services": 0,
                "management_capable_services": 0,
                "web_management_candidates": 0,
                "non_administrative_services": 0,
                "unknown_services": 0,
                "outside_scope_administrative_or_management": 0,
                "requires_review": 0,
                "http_probes": 0,
                "http_probe_errors": 0,
            },
            "notes": [
                "Initialized; run analyze to collect classifications and active HTTP evidence.",
            ],
            "generated_at": now_iso(),
        },
    }

    if endpoint_error:
        initial["admin"]["notes"].append(endpoint_error)
    if directory_error:
        initial["admin"]["notes"].append(directory_error)

    save_yaml(admin_file(), initial)
    record("Administrative service exposure initialized", "in-progress")

    print("[PASS] Administrative Service Exposure initialized.")
    print(f"PROJECT          : {project_root().name}")
    print(f"TARGET           : {target['target_ip']}")
    print(f"AUTHORIZED PORTS : {len(authorized_ports)}")
    print(f"ENDPOINT SOURCE  : {endpoint_status}")
    print(f"DIRECTORY SOURCE : {directory_status}")
    print(f"FILE             : {admin_file()}")
    return 0


def cmd_analyze() -> int:
    scope_data = load_scope()
    network_data = load_network()
    service_data = load_service()

    endpoint_data, endpoint_status, endpoint_error = load_optional_source(
        endpoint_file(), "endpoint.yaml"
    )
    directory_data, directory_status, directory_error = load_optional_source(
        directory_file(), "directory.yaml"
    )

    authorized_ports, _ = scope_port_set(scope_data)
    service_items = service_metadata_index(service_data)
    service_results = [
        classify_service(item, authorized_ports)
        for item in service_items
    ]

    web_probe_targets = correlate_web_candidates(
        endpoint_data=endpoint_data,
        directory_data=directory_data,
        authorized_ports=authorized_ports,
        target_url=target_metadata(network_data)["target_url"],
    )
    bases = primary_web_bases(network_data, service_results, authorized_ports)
    probe_targets = build_probe_targets(web_probe_targets, bases)

    probe_results: list[dict[str, Any]] = []
    probe_notes: list[str] = []
    if probe_targets:
        print(f"[INFO] HTTP management probes: {len(probe_targets)} target(s)")
        probe_results = run_http_probes(probe_targets)
    else:
        probe_notes.append("Tidak ada HTTP/HTTPS management probe yang dijalankan.")

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "generated_at": now_iso(),
        "method": "controlled in-scope GET requests to observed/standard management paths",
        "candidate_rule": "HTTP status_code == 200",
        "bases": bases,
        "targets": probe_targets,
        "results": probe_results,
        "summary": {
            "attempted": len(probe_results),
            "successful_http_status": sum(
                1 for item in probe_results if item.get("status_code") is not None
            ),
            "errors": sum(1 for item in probe_results if item.get("error")),
            "status_200": sum(1 for item in probe_results if item.get("status_code") == 200),
            "status_401": sum(1 for item in probe_results if item.get("status_code") == 401),
            "status_403": sum(1 for item in probe_results if item.get("status_code") == 403),
            "status_3xx": sum(
                1 for item in probe_results
                if isinstance(item.get("status_code"), int) and 300 <= item["status_code"] < 400
            ),
        },
        "notes": probe_notes + [
            "Only active HTTP response status 200 is promoted to web-management candidate."
        ],
    }
    save_json(http_probe_file(), evidence)

    document = build_document(
        network_data=network_data,
        scope_data=scope_data,
        service_data=service_data,
        endpoint_data=endpoint_data,
        endpoint_status=endpoint_status,
        directory_data=directory_data,
        directory_status=directory_status,
        probe_results=probe_results,
        status="in-progress",
    )

    notes = list(document["admin"].get("notes", []))
    if endpoint_error:
        notes.append(endpoint_error)
    if directory_error:
        notes.append(directory_error)
    document["admin"]["notes"] = sorted(set(notes))

    save_yaml(admin_file(), document)
    record(
        (
            "Administrative service exposure analyzed: "
            f"{document['admin']['summary']['administrative_services']} administrative, "
            f"{document['admin']['summary']['management_capable_services']} management-capable, "
            f"{document['admin']['summary']['web_management_candidates']} web candidate(s)"
        ),
        "in-progress",
    )

    summary = document["admin"]["summary"]
    print("[PASS] Administrative Service Exposure analysis completed.")
    print(f"TARGET                  : {document['admin']['target_ip']}")
    print(f"OBSERVED SERVICES       : {summary['observed_services']}")
    print(f"ADMINISTRATIVE          : {summary['administrative_services']}")
    print(f"MANAGEMENT-CAPABLE      : {summary['management_capable_services']}")
    print(f"WEB MANAGEMENT          : {summary['web_management_candidates']}")
    print(f"REQUIRES REVIEW         : {summary['requires_review']}")
    print(f"HTTP PROBES             : {summary['http_probes']}")
    print(f"HTTP PROBE ERRORS       : {summary['http_probe_errors']}")
    print(f"FILE                    : {admin_file()}")
    print(f"HTTP EVIDENCE           : {http_probe_file()}")
    return 0


def cmd_list() -> int:
    path = admin_file()
    if not path.exists():
        print("[FAIL] admin.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "admin.yaml")
    require_project_id(data, "admin.yaml")
    admin = nested_payload(data, "admin")

    print(f"Project ID : {data.get('project_id', '-')}")
    print(f"Status     : {admin.get('status', '-')}")
    print(f"Target     : {admin.get('target_ip', '-')}")
    print()
    print("SERVICES:")

    services = admin.get("services") or []
    if not services:
        print("  [none]")
    else:
        for item in services:
            cls = item.get("classification") or {}
            print(
                f"  {int(item.get('port', 0)):5d}/{item.get('protocol', 'tcp'):3} "
                f"{item.get('service', '-'):16} "
                f"{cls.get('type', '-'):24} "
                f"scope={item.get('scope_status', '-'):13} "
                f"review={str(item.get('requires_review', False)).lower()}"
            )

    print()
    print("WEB MANAGEMENT CANDIDATES:")
    web = admin.get("web_management") or []
    if not web:
        print("  [none]")
    else:
        for item in web:
            active = item.get("active_assessment", "-")
            print(
                f"  {item.get('path', '/'):24} "
                f"{item.get('category', '-'):35} "
                f"confidence={item.get('confidence', '-'):6} "
                f"active={active}"
            )

    return 0


def cmd_show() -> int:
    path = admin_file()
    if not path.exists():
        print("[FAIL] admin.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "admin.yaml")
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


def cmd_verify() -> int:
    path = admin_file()
    if not path.exists():
        print("[FAIL] admin.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "admin.yaml")
    require_project_id(data, "admin.yaml")
    errors = validate_document(data)

    admin = data.get("admin") if isinstance(data.get("admin"), dict) else {}
    status = str(admin.get("status", "")).strip()
    if status not in {"in-progress", "completed"}:
        errors.append(f"Status tidak siap diverifikasi: {status or '-'}")

    probe_count = 0
    summary = admin.get("summary") if isinstance(admin.get("summary"), dict) else {}
    try:
        probe_count = int(summary.get("http_probes", 0))
    except (TypeError, ValueError):
        probe_count = 0

    if probe_count > 0 and not http_probe_file().exists():
        errors.append("HTTP probe summary menunjukkan probe tetapi evidence JSON tidak ditemukan.")

    if errors:
        print("[FAIL] Administrative Service Exposure verification gagal.")
        for error in errors:
            print(f"  - {error}")
        return 1

    if status == "in-progress":
        admin["status"] = "completed"
        data["updated_at"] = now_iso()
        save_yaml(path, data)
        status = "completed"

    print("[PASS] Administrative Service Exposure memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {status}")
    print(f"[PASS] Target    : {admin.get('target_ip', '-')}")
    print(f"[PASS] Services  : {summary.get('observed_services', 0)}")
    print(f"[PASS] Admin     : {summary.get('administrative_services', 0)}")
    print(f"[PASS] Web Mgmt  : {summary.get('web_management_candidates', 0)}")
    print(
        "[PASS] Assessment: administrative exposure dicatat sebagai evidence; "
        "tidak otomatis dianggap vulnerability."
    )

    record("Administrative service exposure verified", "completed")
    return 0


def cmd_status() -> int:
    path = admin_file()
    if not path.exists():
        print("[INFO] Administrative Service Exposure belum ada.")
        return 0

    data = load_yaml(path, "admin.yaml")
    require_project_id(data, "admin.yaml")
    admin = nested_payload(data, "admin")
    summary = admin.get("summary") or {}

    print(f"PROJECT                 : {data.get('project_id', '-')}")
    print(f"STATUS                  : {admin.get('status', '-')}")
    print(f"TARGET                  : {admin.get('target_ip', '-')}")
    print(f"AUTHORIZED PORTS        : {len(admin.get('authorized_ports') or [])}")
    print(f"OBSERVED SERVICES       : {summary.get('observed_services', 0)}")
    print(f"ADMINISTRATIVE          : {summary.get('administrative_services', 0)}")
    print(f"MANAGEMENT-CAPABLE      : {summary.get('management_capable_services', 0)}")
    print(f"WEB MANAGEMENT          : {summary.get('web_management_candidates', 0)}")
    print(f"REQUIRES REVIEW         : {summary.get('requires_review', 0)}")
    print(f"HTTP PROBES             : {summary.get('http_probes', 0)}")
    print(f"HTTP PROBE ERRORS       : {summary.get('http_probe_errors', 0)}")
    print(f"FILE                    : {path}")
    print(f"HTTP EVIDENCE           : {http_probe_file() if http_probe_file().exists() else '-'}")
    return 0


def cmd_remove() -> int:
    path = admin_dir()
    if not path.exists():
        print("[INFO] Administrative Service Exposure belum ada.")
        return 0

    confirm = input(
        "Hapus seluruh data Administrative Service Exposure untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(path)
    record("Administrative service exposure data removed", "completed")
    print("[PASS] Administrative Service Exposure berhasil dihapus.")
    return 0


def cmd_version() -> int:
    print(f"BrebesKab-CSIRT-Tools admin.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : Evidence correlation + controlled in-scope HTTP confirmation")
    print("Baseline : 02-reconnaissance/network/network.yaml")
    print("Service  : 03-infrastructure/service/service.yaml")
    print("Endpoint : 02-reconnaissance/endpoint/endpoint.yaml (optional correlation)")
    print("Directory: 02-reconnaissance/directory/directory.yaml (optional correlation)")
    print("Scope    : 01-preparation/scope/scope.yaml")
    print("Rule     : only HTTP 200 responses become web-management candidates")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Administrative Service Exposure\n"
        "\n"
        "Checklist:\n"
        "  3-004 Administrative service exposure\n"
        "\n"
        "Usage:\n"
        "  python scripts/infrastructure/admin.py init\n"
        "  python scripts/infrastructure/admin.py analyze\n"
        "  python scripts/infrastructure/admin.py list\n"
        "  python scripts/infrastructure/admin.py show\n"
        "  python scripts/infrastructure/admin.py verify\n"
        "  python scripts/infrastructure/admin.py status\n"
        "  python scripts/infrastructure/admin.py remove\n"
        "  python scripts/infrastructure/admin.py version\n"
        "\n"
        "Design:\n"
        "  - Reuses completed network.yaml and service.yaml as the baseline.\n"
        "  - Uses endpoint.yaml/directory.yaml and standard paths only as probe targets.\n"
        "  - Only HTTP response 200 is promoted to web-management candidate.\n"
        "  - Separates administrative classification from scope/authorization.\n"
        "  - Uses controlled GET probes only against in-scope web services.\n"
        "  - Does not perform login testing, brute force, credential guessing,\n"
        "    destructive methods, or exploitation.\n"
        "  - Outside-scope administrative exposure is retained as review evidence.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Infrastructure Administrative Service Exposure - checklist 3-004",
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
        raise AdministrativeServiceError(f"Command tidak dikenal: {args.command}")
    except AdministrativeServiceError as exc:
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
