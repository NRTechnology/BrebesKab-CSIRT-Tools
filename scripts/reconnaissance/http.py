#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - HTTP / HTTPS

Version: 1.0.0

Checklist mapping:
    02-005 - HTTP / HTTPS

Purpose:
    Record the observable HTTP / HTTPS behavior of the authorized web target
    during reconnaissance and store the evidence in http.yaml.

Design:
    - "init" reads the completed Technology Identification document once.
    - After "init", this module uses http.yaml as its own state file.
    - "inspect" performs controlled HTTP / HTTPS requests.
    - HTTP and HTTPS behavior are recorded separately.
    - Redirect behavior, response metadata, selected headers, TLS metadata,
      and response timing are recorded.
    - No vulnerability testing is performed.
    - No credentials or cookie values are stored.
    - No brute-force or aggressive enumeration is performed.

Storage:
    projects/<PROJECT-ID>/02-reconnaissance/http/http.yaml
"""

from __future__ import annotations

import re
import socket
import ssl
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

# This file is named http.py and lives beside the Python standard-library
# package named http. When executed directly, its directory becomes
# sys.path[0]. Remove it before importing third-party modules so urllib3
# cannot accidentally import reconnaissance/http.py as stdlib http.
script_dir_string = str(SCRIPT_DIR)
sys.path[:] = [entry for entry in sys.path if entry != script_dir_string]

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

import requests
import yaml

from activity import ActivityError, record_activity
from context import ContextError, ProjectContext, require_active_project


SCRIPT_VERSION = "1.0.0"

RECON_DIR_NAME = "02-reconnaissance"
TECHNOLOGY_DIR_NAME = "technology"
TECHNOLOGY_FILE_NAME = "technology.yaml"
HTTP_DIR_NAME = "http"
HTTP_FILE_NAME = "http.yaml"

REQUEST_TIMEOUT = 15

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
}

OBSERVED_HEADERS = (
    "server",
    "x-powered-by",
    "location",
    "content-type",
    "content-length",
    "cache-control",
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}


class HTTPReconError(RuntimeError):
    """Raised when HTTP / HTTPS reconnaissance cannot be completed."""


def technology_file(context: ProjectContext) -> Path:
    return (
        context.project_path
        / RECON_DIR_NAME
        / TECHNOLOGY_DIR_NAME
        / TECHNOLOGY_FILE_NAME
    )


def http_dir(context: ProjectContext) -> Path:
    return context.project_path / RECON_DIR_NAME / HTTP_DIR_NAME


def http_file(context: ProjectContext) -> Path:
    return http_dir(context) / HTTP_FILE_NAME


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "http": {
            "status": "not-started",
            "application": "",
            "target_url": "",
            "hostname": "",
            "environment": "",
            "assessment_type": "",
            "scope_reference": "01-preparation/scope/scope.yaml",
            "http": {
                "tested": False,
                "status_code": None,
                "final_url": "",
                "redirects": [],
                "content_type": "",
                "response_time_ms": None,
                "headers": {},
                "tls": {},
            },
            "https": {
                "tested": False,
                "status_code": None,
                "final_url": "",
                "redirects": [],
                "content_type": "",
                "response_time_ms": None,
                "headers": {},
                "tls": {},
            },
            "comparison": {
                "http_to_https_redirect": None,
                "http_final_url": "",
                "https_available": None,
                "same_target": None,
            },
            "notes": "",
            "inspected_at": "",
        },
    }


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise HTTPReconError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise HTTPReconError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise HTTPReconError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise HTTPReconError(
            f"Format {path.name} harus berupa mapping/object."
        )

    return data


def _load_technology_source(context: ProjectContext) -> dict[str, Any]:
    path = technology_file(context)
    data = _load_yaml(path, "Technology Identification")

    if data.get("project_id") != context.project_id:
        raise HTTPReconError(
            "Project ID pada technology.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    technology = data.get("technology")
    if not isinstance(technology, dict):
        raise HTTPReconError(
            "Field 'technology' pada technology.yaml harus berupa "
            "mapping/object."
        )

    status = str(technology.get("status", "")).strip().lower()
    if status != "completed":
        raise HTTPReconError(
            "Technology Identification belum completed.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/technology.py verify"
        )

    required_fields = {
        "application": technology.get("application"),
        "target_url": technology.get("target_url"),
        "hostname": technology.get("hostname"),
        "scheme": technology.get("scheme"),
        "environment": technology.get("environment"),
        "assessment_type": technology.get("assessment_type"),
        "scope_reference": technology.get("scope_reference"),
    }

    missing = [
        name
        for name, value in required_fields.items()
        if not isinstance(value, str) or not value.strip()
    ]

    if missing:
        raise HTTPReconError(
            "Technology Identification belum lengkap. Field kosong: "
            + ", ".join(missing)
        )

    return data


def _build_from_technology(
    context: ProjectContext,
    technology_data: dict[str, Any],
) -> dict[str, Any]:
    technology = technology_data["technology"]
    data = _empty_document(context)

    data["http"].update(
        {
            "status": "not-started",
            "application": str(technology["application"]).strip(),
            "target_url": str(technology["target_url"]).strip(),
            "hostname": str(technology["hostname"]).strip().rstrip("."),
            "environment": str(technology["environment"]).strip(),
            "assessment_type": str(technology["assessment_type"]).strip(),
            "scope_reference": str(
                technology["scope_reference"]
            ).strip(),
        }
    )

    return data


def _load_http(context: ProjectContext) -> dict[str, Any]:
    path = http_file(context)

    if not path.is_file():
        raise HTTPReconError(
            f"HTTP / HTTPS configuration belum tersedia: {path}\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/http.py init"
        )

    data = _load_yaml(path, "HTTP / HTTPS reconnaissance")

    if data.get("project_id") != context.project_id:
        raise HTTPReconError(
            "Project ID pada http.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    document = data.get("http")
    if not isinstance(document, dict):
        raise HTTPReconError(
            "Field 'http' pada http.yaml harus berupa "
            "mapping/object."
        )

    defaults = _empty_document(context)["http"]

    for key, value in defaults.items():
        if key not in document:
            document[key] = value

    for protocol in ("http", "https"):
        if not isinstance(document.get(protocol), dict):
            document[protocol] = defaults[protocol].copy()

    if not isinstance(document.get("comparison"), dict):
        document["comparison"] = defaults["comparison"].copy()

    status = str(document.get("status", "not-started")).strip().lower()
    if status not in VALID_STATUSES:
        raise HTTPReconError(
            f"Status HTTP / HTTPS tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data["http"] = document
    return data


def _save_http(
    context: ProjectContext,
    data: dict[str, Any],
) -> Path:
    directory = http_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = http_file(context)

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
        raise HTTPReconError(
            f"Gagal menulis: {path}\n{exc}"
        ) from exc

    return path


def initialize(
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    if context is None:
        context = require_active_project()

    technology_data = _load_technology_source(context)
    data = _build_from_technology(context, technology_data)

    return _save_http(context, data)


def _unique_strings(values: list[Any]) -> list[str]:
    result: list[str] = []

    for value in values:
        value = str(value).strip()
        if value and value not in result:
            result.append(value)

    return result


def _safe_headers(response: requests.Response) -> dict[str, str]:
    """
    Record selected HTTP headers only.

    Credential-bearing and cookie-bearing headers are deliberately excluded.
    """
    headers: dict[str, str] = {}

    for name in OBSERVED_HEADERS:
        value = response.headers.get(name)

        if value and name.lower() not in SENSITIVE_HEADERS:
            headers[name] = value[:1000]

    return headers


def _response_redirects(response: requests.Response) -> list[str]:
    return _unique_strings(
        [
            item.url
            for item in response.history
            if item.url
        ]
    )


def _request(
    url: str,
    *,
    allow_redirects: bool,
) -> tuple[requests.Response, float]:
    started = datetime.now().astimezone()

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=allow_redirects,
            headers={
                "User-Agent": (
                    "BrebesKab-CSIRT-Tools/"
                    f"{SCRIPT_VERSION} HTTP-Recon"
                )
            },
        )
    except requests.RequestException as exc:
        raise HTTPReconError(
            f"HTTP request gagal untuk {url}: {exc}"
        ) from exc

    completed = datetime.now().astimezone()

    elapsed_ms = round(
        (completed - started).total_seconds() * 1000,
        2,
    )

    return response, elapsed_ms


def _tls_metadata(url: str) -> dict[str, Any]:
    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        return {
            "enabled": False,
        }

    hostname = parsed.hostname
    if not hostname:
        return {
            "enabled": True,
            "error": "Hostname HTTPS tidak tersedia.",
        }

    port = parsed.port or 443

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port),
            timeout=REQUEST_TIMEOUT,
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket:
                certificate = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
                version = tls_socket.version()

                subject = _certificate_name(
                    certificate.get("subject", [])
                )
                issuer = _certificate_name(
                    certificate.get("issuer", [])
                )

                san = []
                for item in certificate.get("subjectAltName", []):
                    if len(item) == 2:
                        san.append(f"{item[0]}:{item[1]}")

                return {
                    "enabled": True,
                    "hostname": hostname,
                    "port": port,
                    "tls_version": version or "",
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": cipher[2] if cipher else None,
                    "certificate_subject": subject,
                    "certificate_issuer": issuer,
                    "certificate_san": san[:100],
                    "certificate_not_before": certificate.get(
                        "notBefore",
                        "",
                    ),
                    "certificate_not_after": certificate.get(
                        "notAfter",
                        "",
                    ),
                    "certificate_verified": True,
                }

    except ssl.SSLCertVerificationError as exc:
        return {
            "enabled": True,
            "hostname": hostname,
            "port": port,
            "certificate_verified": False,
            "error": f"TLS certificate verification failed: {exc}",
        }
    except (ssl.SSLError, OSError) as exc:
        return {
            "enabled": True,
            "hostname": hostname,
            "port": port,
            "certificate_verified": False,
            "error": str(exc),
        }


def _certificate_name(
    name_data: Any,
) -> str:
    parts: list[str] = []

    if not isinstance(name_data, tuple | list):
        return ""

    for relative_name in name_data:
        if not isinstance(relative_name, tuple | list):
            continue

        for key, value in relative_name:
            if key in {"commonName", "organizationName"}:
                value = str(value).strip()
                if value and value not in parts:
                    parts.append(value)

    return ", ".join(parts)


def _inspect_protocol(
    url: str,
    *,
    allow_redirects: bool,
) -> dict[str, Any]:
    response, elapsed_ms = _request(
        url,
        allow_redirects=allow_redirects,
    )

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).split(";", 1)[0].strip()

    result = {
        "tested": True,
        "status_code": response.status_code,
        "final_url": response.url,
        "redirects": _response_redirects(response),
        "content_type": content_type,
        "response_time_ms": elapsed_ms,
        "headers": _safe_headers(response),
        "tls": _tls_metadata(url),
    }

    return result


def inspect(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """
    Perform controlled HTTP / HTTPS reconnaissance.

    Both HTTP and HTTPS are tested when applicable. Redirects are followed
    to observe the normal application behavior, while the initial response
    is preserved in the redirect chain.
    """
    if context is None:
        context = require_active_project()

    data = _load_http(context)
    document = data["http"]

    target_url = str(document.get("target_url", "")).strip()

    if not target_url:
        raise HTTPReconError(
            "Target URL belum tersedia pada http.yaml.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/http.py init"
        )

    parsed = urlparse(target_url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPReconError(
            f"Target URL tidak valid: {target_url}"
        )

    # Test the explicitly scoped target first.
    if parsed.scheme == "https":
        https_url = target_url
        http_url = urlunparse_safe(
            parsed._replace(scheme="http")
        )
    else:
        http_url = target_url
        https_url = urlunparse_safe(
            parsed._replace(scheme="https")
        )

    http_result: dict[str, Any] = {
        "tested": False,
        "status_code": None,
        "final_url": "",
        "redirects": [],
        "content_type": "",
        "response_time_ms": None,
        "headers": {},
        "tls": {},
    }

    https_result: dict[str, Any] = {
        "tested": False,
        "status_code": None,
        "final_url": "",
        "redirects": [],
        "content_type": "",
        "response_time_ms": None,
        "headers": {},
        "tls": {},
    }

    errors: list[str] = []

    # HTTP probe.
    try:
        http_result = _inspect_protocol(
            http_url,
            allow_redirects=True,
        )
    except HTTPReconError as exc:
        errors.append(f"HTTP: {exc}")

    # HTTPS probe.
    try:
        https_result = _inspect_protocol(
            https_url,
            allow_redirects=True,
        )
    except HTTPReconError as exc:
        errors.append(f"HTTPS: {exc}")

    if not http_result["tested"] and not https_result["tested"]:
        raise HTTPReconError(
            "HTTP / HTTPS reconnaissance gagal.\n"
            + "\n".join(f"- {item}" for item in errors)
        )

    http_final_url = str(http_result.get("final_url", ""))

    comparison = {
        "http_to_https_redirect": None,
        "http_final_url": http_final_url,
        "https_available": bool(https_result.get("tested")),
        "same_target": None,
    }

    if http_result.get("tested"):
        http_redirects = http_result.get("redirects", [])
        final_scheme = urlparse(http_final_url).scheme.lower()

        comparison["http_to_https_redirect"] = (
            final_scheme == "https"
            or any(
                urlparse(item).scheme.lower() == "https"
                for item in http_redirects
            )
        )

    if (
        http_result.get("tested")
        and https_result.get("tested")
    ):
        http_host = urlparse(
            str(http_result.get("final_url", ""))
        ).hostname
        https_host = urlparse(
            str(https_result.get("final_url", ""))
        ).hostname

        comparison["same_target"] = (
            bool(http_host)
            and bool(https_host)
            and http_host.lower() == https_host.lower()
        )

    document["http"] = http_result
    document["https"] = https_result
    document["comparison"] = comparison
    document["inspected_at"] = _now()
    document["status"] = "in-progress"

    if errors:
        document["notes"] = (
            "Partial protocol results; "
            + " | ".join(errors)
        )
    else:
        document["notes"] = ""

    _save_http(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-005",
            action=(
                "HTTP / HTTPS reconnaissance recorded: "
                f"{target_url} "
                f"(HTTP tested={http_result['tested']}, "
                f"HTTPS tested={https_result['tested']})"
            ),
            status="in-progress",
            context=context,
        )
    except ActivityError as exc:
        raise HTTPReconError(
            "HTTP / HTTPS reconnaissance berhasil disimpan, "
            "tetapi activity gagal dicatat.\n"
            f"{exc}"
        ) from exc

    return data


def urlunparse_safe(parts: Any) -> str:
    """
    Rebuild a URL from ParseResult without importing urllib.parse.urlunparse
    under a module named http.py.
    """
    scheme = parts.scheme
    netloc = parts.netloc
    path = parts.path or ""
    query = parts.query
    fragment = parts.fragment

    result = f"{scheme}://{netloc}{path}"

    if query:
        result += f"?{query}"

    if fragment:
        result += f"#{fragment}"

    return result


def validate(
    *,
    context: Optional[ProjectContext] = None,
) -> list[str]:
    if context is None:
        context = require_active_project()

    data = _load_http(context)
    document = data["http"]
    errors: list[str] = []

    required_fields = {
        "application": document.get("application"),
        "target_url": document.get("target_url"),
        "hostname": document.get("hostname"),
        "environment": document.get("environment"),
        "assessment_type": document.get("assessment_type"),
        "scope_reference": document.get("scope_reference"),
        "inspected_at": document.get("inspected_at"),
    }

    for field, value in required_fields.items():
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} belum diisi.")

    parsed = urlparse(str(document.get("target_url", "")))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        errors.append("target_url harus berupa URL HTTP/HTTPS yang valid.")

    http_data = document.get("http")
    https_data = document.get("https")

    if not isinstance(http_data, dict):
        errors.append("http harus berupa mapping/object.")
    elif not http_data.get("tested"):
        errors.append("HTTP belum diuji.")

    if not isinstance(https_data, dict):
        errors.append("https harus berupa mapping/object.")
    elif not https_data.get("tested"):
        errors.append("HTTPS belum diuji.")

    comparison = document.get("comparison")
    if not isinstance(comparison, dict):
        errors.append("comparison harus berupa mapping/object.")
    else:
        if comparison.get("https_available") is not True:
            errors.append("HTTPS belum terkonfirmasi tersedia.")

    return errors


def verify(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    if context is None:
        context = require_active_project()

    errors = validate(context=context)

    if errors:
        raise HTTPReconError(
            "HTTP / HTTPS reconnaissance belum lengkap:\n"
            + "\n".join(f"- {error}" for error in errors)
        )

    data = _load_http(context)
    data["http"]["status"] = "completed"

    _save_http(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-005",
            action="HTTP / HTTPS reconnaissance verified",
            status="completed",
            context=context,
        )
    except ActivityError as exc:
        raise HTTPReconError(
            "HTTP / HTTPS berhasil diverifikasi, "
            "tetapi activity gagal dicatat.\n"
            f"{exc}"
        ) from exc

    return data


def remove(
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    if context is None:
        context = require_active_project()

    path = http_file(context)

    if not path.is_file():
        return False

    try:
        path.unlink()
    except OSError as exc:
        raise HTTPReconError(
            f"Gagal menghapus: {path}\n{exc}"
        ) from exc

    record_activity(
        phase="02-reconnaissance",
        item="02-005",
        action="HTTP / HTTPS reconnaissance removed",
        status="completed",
        context=context,
    )

    return True


def print_summary(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    data = _load_http(context)
    document = data["http"]
    http_data = document.get("http", {})
    https_data = document.get("https", {})
    comparison = document.get("comparison", {})

    print("=" * 72)
    print(
        " BrebesKab-CSIRT-Tools - "
        "Reconnaissance HTTP / HTTPS"
    )
    print("=" * 72)
    print(f"Project ID       : {context.project_id}")
    print(f"Status           : {document.get('status', '')}")
    print(f"Application      : {document.get('application', '')}")
    print(f"Target URL       : {document.get('target_url', '')}")
    print(f"Hostname         : {document.get('hostname', '')}")
    print(f"Environment      : {document.get('environment', '')}")
    print(f"Assessment Type  : {document.get('assessment_type', '')}")
    print()
    print(
        f"HTTP             : "
        f"{http_data.get('status_code', '-')}"
        f" | Final: {http_data.get('final_url') or '-'}"
    )
    print(
        f"HTTPS            : "
        f"{https_data.get('status_code', '-')}"
        f" | Final: {https_data.get('final_url') or '-'}"
    )
    print(
        "HTTP→HTTPS       : "
        f"{comparison.get('http_to_https_redirect')}"
    )
    print(
        "HTTPS Available   : "
        f"{comparison.get('https_available')}"
    )
    print(
        "HTTP Response     : "
        f"{http_data.get('response_time_ms', '-') } ms"
    )
    print(
        "HTTPS Response    : "
        f"{https_data.get('response_time_ms', '-') } ms"
    )
    print(
        "TLS Version       : "
        f"{https_data.get('tls', {}).get('tls_version') or '-'}"
    )
    print(
        "TLS Cipher        : "
        f"{https_data.get('tls', {}).get('cipher') or '-'}"
    )
    print(
        "Identified At     : "
        f"{document.get('inspected_at') or '-'}"
    )
    print(
        f"Scope Reference   : "
        f"{document.get('scope_reference', '')}"
    )
    print(f"File              : {http_file(context)}")


def print_full(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    data = _load_http(context)

    print(f"PROJECT: {context.project_id}")
    print(f"FILE   : {http_file(context)}")
    print()
    _print_value(data["http"])


def _print_value(value: Any, indent: int = 0) -> None:
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
    print(
        "Reconnaissance HTTP / HTTPS\n"
        "\n"
        "Usage:\n"
        "  python scripts/reconnaissance/http.py init\n"
        "  python scripts/reconnaissance/http.py inspect\n"
        "  python scripts/reconnaissance/http.py list\n"
        "  python scripts/reconnaissance/http.py show\n"
        "  python scripts/reconnaissance/http.py verify\n"
        "  python scripts/reconnaissance/http.py status\n"
        "  python scripts/reconnaissance/http.py remove\n"
        "  python scripts/reconnaissance/http.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
        "\n"
        "init      Read completed technology.yaml and create http.yaml.\n"
        "inspect   Perform controlled HTTP / HTTPS reconnaissance.\n"
        "list      Show a concise HTTP / HTTPS summary.\n"
        "show      Show the complete HTTP / HTTPS document.\n"
        "verify    Validate the reconnaissance and mark completed.\n"
        "status    Show the current lifecycle status.\n"
        "remove    Remove http.yaml.\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = args[0].lower()

    if command == "version":
        print(
            "BrebesKab-CSIRT-Tools "
            f"http.py v{SCRIPT_VERSION}"
        )
        return 0

    try:
        context = require_active_project()

        if command == "init":
            path = initialize(context=context)
            print(
                "[PASS] HTTP / HTTPS configuration siap "
                "dari Technology Identification."
            )
            print(f"File: {path}")
            return 0

        if command in ("inspect", "check"):
            data = inspect(context=context)
            document = data["http"]
            http_data = document["http"]
            https_data = document["https"]
            comparison = document["comparison"]

            print("[PASS] HTTP / HTTPS reconnaissance berhasil.")
            print(
                f"HTTP  : {http_data.get('status_code', '-')}"
                f" -> {http_data.get('final_url') or '-'}"
            )
            print(
                f"HTTPS : {https_data.get('status_code', '-')}"
                f" -> {https_data.get('final_url') or '-'}"
            )
            print(
                "HTTP->HTTPS : "
                f"{comparison.get('http_to_https_redirect')}"
            )
            print(
                "TLS         : "
                f"{https_data.get('tls', {}).get('tls_version') or '-'}"
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
            print("[PASS] HTTP / HTTPS memenuhi validasi.")
            print("[PASS] Status: completed")
            return 0

        if command == "status":
            data = _load_http(context)
            print(f"Project ID : {context.project_id}")
            print(
                "Status     : "
                f"{data['http'].get('status', '')}"
            )
            return 0

        if command == "remove":
            removed = remove(context=context)

            if not removed:
                print("[INFO] HTTP / HTTPS reconnaissance belum ada.")
                return 1

            print("[PASS] HTTP / HTTPS reconnaissance telah dihapus.")
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (
        ContextError,
        HTTPReconError,
        ActivityError,
    ) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
