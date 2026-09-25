#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Technology Identification

Version: 1.0.0

Checklist mapping:
    02-004 - Technology Identification

Purpose:
    Identify technologies exposed by the authorized web target during
    reconnaissance and store the observed evidence in technology.yaml.

Design:
    - "init" reads the completed Network reconnaissance document once.
    - After "init", this module uses technology.yaml as its own state file.
    - "identify" performs passive/basic HTTP technology identification.
    - The module records observable HTTP headers, cookie names, HTML
      clues, script sources, and technology candidates.
    - No vulnerability testing is performed.
    - No credentials or cookie values are stored.
    - No brute-force or aggressive technology enumeration is performed.

Storage:
    projects/<PROJECT-ID>/02-reconnaissance/technology/technology.yaml
"""

from __future__ import annotations

import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests
import yaml


SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from activity import ActivityError, record_activity
from context import ContextError, ProjectContext, require_active_project


SCRIPT_VERSION = "1.0.0"

RECON_DIR_NAME = "02-reconnaissance"
NETWORK_DIR_NAME = "network"
NETWORK_FILE_NAME = "network.yaml"
TECHNOLOGY_DIR_NAME = "technology"
TECHNOLOGY_FILE_NAME = "technology.yaml"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
}

REQUEST_TIMEOUT = 15

OBSERVED_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "via",
)

HEADER_TECHNOLOGY_RULES = {
    "server": {
        "nginx": "Nginx",
        "apache": "Apache HTTP Server",
        "microsoft-iis": "Microsoft IIS",
        "iis": "Microsoft IIS",
        "caddy": "Caddy",
        "openresty": "OpenResty",
        "cloudflare": "Cloudflare",
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Express",
    },
    "x-generator": {
        "drupal": "Drupal",
        "wordpress": "WordPress",
    },
}

HTML_TECHNOLOGY_PATTERNS = (
    (
        "WordPress",
        re.compile(r"/wp-content/|/wp-includes/|wp-json", re.I),
    ),
    (
        "Laravel",
        re.compile(r"laravel_session|csrf-token|XSRF-TOKEN", re.I),
    ),
    (
        "Django",
        re.compile(r"csrfmiddlewaretoken|__django", re.I),
    ),
    (
        "ASP.NET",
        re.compile(r"__VIEWSTATE|__EVENTVALIDATION|aspnet", re.I),
    ),
    (
        "Vue.js",
        re.compile(
            r"""(?:id|class)=["'][^"']*vue|data-v-[a-f0-9]+""",
            re.I,
        ),
    ),
    (
        "React",
        re.compile(r"data-reactroot|data-reactid|react-dom", re.I),
    ),
    (
        "Angular",
        re.compile(r"ng-version|_ngcontent-|angular", re.I),
    ),
    (
        "jQuery",
        re.compile(r"jquery(?:[-.]|\d)", re.I),
    ),
    (
        "Bootstrap",
        re.compile(r"bootstrap(?:[-.]|\d)", re.I),
    ),
)

SCRIPT_SOURCE_PATTERNS = (
    ("jQuery", re.compile(r"jquery(?:[-.]|\d)", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(?:[-.]|\d)", re.I)),
    ("React", re.compile(r"react(?:[-.]|\d)", re.I)),
    ("Vue.js", re.compile(r"(?:vue|vuejs)(?:[-.]|\d)", re.I)),
    ("Angular", re.compile(r"angular(?:[-.]|\d)", re.I)),
)

META_GENERATOR_RE = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""",
    re.I,
)

SERVER_VERSION_RE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9._-]*)/(?P<version>\d+(?:\.\d+){0,3})",
)


class TechnologyError(RuntimeError):
    """Raised when technology reconnaissance cannot be completed."""


def network_file(context: ProjectContext) -> Path:
    return (
        context.project_path
        / RECON_DIR_NAME
        / NETWORK_DIR_NAME
        / NETWORK_FILE_NAME
    )


def technology_dir(context: ProjectContext) -> Path:
    return (
        context.project_path
        / RECON_DIR_NAME
        / TECHNOLOGY_DIR_NAME
    )


def technology_file(context: ProjectContext) -> Path:
    return technology_dir(context) / TECHNOLOGY_FILE_NAME


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "technology": {
            "status": "not-started",
            "application": "",
            "target_url": "",
            "hostname": "",
            "scheme": "",
            "port": "",
            "environment": "",
            "assessment_type": "",
            "scope_reference": "01-preparation/scope/scope.yaml",
            "http": {
                "status_code": None,
                "final_url": "",
                "redirects": [],
                "content_type": "",
                "server": "",
                "powered_by": "",
                "headers": {},
                "cookies": [],
                "response_time_ms": None,
            },
            "technologies": [],
            "html_clues": [],
            "script_sources": [],
            "meta_generator": "",
            "notes": "",
            "identified_at": "",
        },
    }


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise TechnologyError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise TechnologyError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise TechnologyError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise TechnologyError(
            f"Format {path.name} harus berupa mapping/object."
        )

    return data


def _load_network_source(context: ProjectContext) -> dict[str, Any]:
    path = network_file(context)
    data = _load_yaml(path, "Network reconnaissance")

    if data.get("project_id") != context.project_id:
        raise TechnologyError(
            "Project ID pada network.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    network = data.get("network")

    if not isinstance(network, dict):
        raise TechnologyError(
            "Field 'network' pada network.yaml harus berupa mapping/object."
        )

    status = str(network.get("status", "")).strip().lower()

    if status != "completed":
        raise TechnologyError(
            "IP / Network belum completed.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/network.py verify"
        )

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

    missing = [
        name
        for name, value in required_fields.items()
        if not isinstance(value, str) or not value.strip()
    ]

    if missing:
        raise TechnologyError(
            "Network reconnaissance belum lengkap. Field kosong: "
            + ", ".join(missing)
        )

    return data


def _build_from_network(
    context: ProjectContext,
    network_data: dict[str, Any],
) -> dict[str, Any]:
    network = network_data["network"]
    data = _empty_document(context)

    data["technology"].update(
        {
            "status": "not-started",
            "application": str(network["application"]).strip(),
            "target_url": str(network["target_url"]).strip(),
            "hostname": str(network["hostname"]).strip().rstrip("."),
            "scheme": str(network["scheme"]).strip().lower(),
            "port": str(network["port"]).strip(),
            "environment": str(network["environment"]).strip(),
            "assessment_type": str(network["assessment_type"]).strip(),
            "scope_reference": str(network["scope_reference"]).strip(),
        }
    )

    return data


def _load_technology(context: ProjectContext) -> dict[str, Any]:
    path = technology_file(context)

    if not path.is_file():
        raise TechnologyError(
            f"Technology configuration belum tersedia: {path}\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/technology.py init"
        )

    data = _load_yaml(path, "Technology configuration")

    if data.get("project_id") != context.project_id:
        raise TechnologyError(
            "Project ID pada technology.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    technology = data.get("technology")

    if not isinstance(technology, dict):
        raise TechnologyError(
            "Field 'technology' pada technology.yaml harus berupa "
            "mapping/object."
        )

    defaults = _empty_document(context)["technology"]

    for key, value in defaults.items():
        if key not in technology:
            technology[key] = value

    if not isinstance(technology.get("http"), dict):
        technology["http"] = defaults["http"].copy()

    status = str(
        technology.get("status", "not-started")
    ).strip().lower()

    if status not in VALID_STATUSES:
        raise TechnologyError(
            f"Status technology tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data["technology"] = technology
    return data


def _save_technology(
    context: ProjectContext,
    data: dict[str, Any],
) -> Path:
    directory = technology_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = technology_file(context)

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
        raise TechnologyError(
            f"Gagal menulis: {path}\n{exc}"
        ) from exc

    return path


def initialize(
    *,
    context: Optional[ProjectContext] = None,
) -> Path:
    if context is None:
        context = require_active_project()

    network_data = _load_network_source(context)
    data = _build_from_network(context, network_data)

    return _save_technology(context, data)


def _unique_strings(values: list[Any]) -> list[str]:
    result: list[str] = []

    for value in values:
        value = str(value).strip()

        if value and value not in result:
            result.append(value)

    return result


def _add_technology(
    technologies: list[dict[str, Any]],
    name: str,
    source: str,
    detail: str = "",
) -> None:
    name = name.strip()

    if not name:
        return

    for item in technologies:
        if item.get("name") == name:
            sources = item.setdefault("sources", [])

            if source and source not in sources:
                sources.append(source)

            if detail and not item.get("detail"):
                item["detail"] = detail

            return

    technologies.append(
        {
            "name": name,
            "sources": [source] if source else [],
            "detail": detail,
        }
    )


def _safe_headers(
    response: requests.Response,
) -> dict[str, str]:
    """
    Return selected technology-relevant response headers.

    We deliberately do not store every HTTP header.
    """
    headers: dict[str, str] = {}

    for name in OBSERVED_HEADERS:
        value = response.headers.get(name)

        if value:
            headers[name] = value[:500]

    return headers


def _safe_cookie_names(
    response: requests.Response,
) -> list[str]:
    """Record cookie names only; never store cookie values."""
    names: list[str] = []

    for cookie in response.cookies:
        name = str(cookie.name).strip()

        if name:
            names.append(name)

    return _unique_strings(names)


def _extract_script_sources(
    html: str,
    base_url: str,
) -> list[str]:
    """Extract script source paths without storing inline script contents."""
    if not html:
        return []

    pattern = re.compile(
        r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)""",
        re.I,
    )

    result: list[str] = []

    for source in pattern.findall(html):
        source = source.strip()

        if not source:
            continue

        absolute = urljoin(base_url, source)
        parsed = urlparse(absolute)

        if parsed.scheme not in {"http", "https"}:
            continue

        safe_value = parsed.path

        if parsed.query:
            safe_value += "?" + parsed.query

        if safe_value not in result:
            result.append(safe_value)

    return result[:100]


def _extract_html_clues(html: str) -> list[str]:
    """Extract technology clues without storing page content."""
    if not html:
        return []

    clues: list[str] = []

    for technology_name, pattern in HTML_TECHNOLOGY_PATTERNS:
        if pattern.search(html):
            clues.append(technology_name)

    return _unique_strings(clues)


def _extract_meta_generator(html: str) -> str:
    if not html:
        return ""

    match = META_GENERATOR_RE.search(html)

    if not match:
        return ""

    return match.group(1).strip()[:300]


def _identify_from_headers(
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    technologies: list[dict[str, Any]] = []

    for header_name, value in headers.items():
        value_lower = value.lower()
        rules = HEADER_TECHNOLOGY_RULES.get(header_name, {})

        for marker, technology_name in rules.items():
            if marker in value_lower:
                _add_technology(
                    technologies,
                    technology_name,
                    f"HTTP header: {header_name}",
                    detail=value,
                )

        if header_name == "server":
            version_match = SERVER_VERSION_RE.search(value)

            if version_match:
                name = version_match.group("name")
                version = version_match.group("version")

                _add_technology(
                    technologies,
                    name,
                    "HTTP header: server",
                    detail=f"{name}/{version}",
                )

    return technologies


def _identify_from_html(
    html_clues: list[str],
) -> list[dict[str, Any]]:
    technologies: list[dict[str, Any]] = []

    for name in html_clues:
        _add_technology(
            technologies,
            name,
            "HTML content clue",
        )

    return technologies


def _identify_from_scripts(
    script_sources: list[str],
) -> list[dict[str, Any]]:
    technologies: list[dict[str, Any]] = []

    for source in script_sources:
        source_lower = source.lower()

        for technology_name, pattern in SCRIPT_SOURCE_PATTERNS:
            if pattern.search(source_lower):
                _add_technology(
                    technologies,
                    technology_name,
                    "Script source",
                    detail=source,
                )

    return technologies


def identify(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    """
    Perform passive/basic HTTP technology identification.

    The target URL comes only from technology.yaml.
    """
    if context is None:
        context = require_active_project()

    data = _load_technology(context)
    technology = data["technology"]

    target_url = str(technology.get("target_url", "")).strip()

    if not target_url:
        raise TechnologyError(
            "Target URL belum tersedia pada technology.yaml.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/technology.py init"
        )

    parsed = urlparse(target_url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TechnologyError(
            f"Target URL tidak valid: {target_url}"
        )

    started = datetime.now().astimezone()

    try:
        response = requests.get(
            target_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "BrebesKab-CSIRT-Tools/"
                    f"{SCRIPT_VERSION} Technology-Recon"
                )
            },
        )
    except requests.RequestException as exc:
        raise TechnologyError(
            f"HTTP technology identification gagal: {exc}"
        ) from exc

    completed = datetime.now().astimezone()

    elapsed_ms = round(
        (completed - started).total_seconds() * 1000,
        2,
    )

    safe_headers = _safe_headers(response)
    cookie_names = _safe_cookie_names(response)

    final_url = response.url
    redirect_urls = [
        item.url
        for item in response.history
        if item.url
    ]

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).split(";", 1)[0].strip()

    server = response.headers.get("Server", "").strip()
    powered_by = response.headers.get(
        "X-Powered-By",
        "",
    ).strip()

    content = response.content[:2_000_000]

    try:
        html = content.decode(
            response.encoding or "utf-8",
            errors="replace",
        )
    except (LookupError, UnicodeError):
        html = content.decode("utf-8", errors="replace")

    html_clues = _extract_html_clues(html)
    script_sources = _extract_script_sources(html, final_url)
    meta_generator = _extract_meta_generator(html)

    technologies: list[dict[str, Any]] = []

    for item in _identify_from_headers(safe_headers):
        _add_technology(
            technologies,
            item["name"],
            item["sources"][0] if item["sources"] else "",
            item.get("detail", ""),
        )

    for item in _identify_from_html(html_clues):
        _add_technology(
            technologies,
            item["name"],
            item["sources"][0] if item["sources"] else "",
            item.get("detail", ""),
        )

    for item in _identify_from_scripts(script_sources):
        _add_technology(
            technologies,
            item["name"],
            item["sources"][0] if item["sources"] else "",
            item.get("detail", ""),
        )

    if meta_generator:
        _add_technology(
            technologies,
            meta_generator.split()[0],
            "HTML meta generator",
            detail=meta_generator,
        )

    technologies.sort(
        key=lambda item: item.get("name", "").lower()
    )

    technology["http"] = {
        "status_code": response.status_code,
        "final_url": final_url,
        "redirects": _unique_strings(redirect_urls),
        "content_type": content_type,
        "server": server,
        "powered_by": powered_by,
        "headers": safe_headers,
        "cookies": cookie_names,
        "response_time_ms": elapsed_ms,
    }

    technology["technologies"] = technologies
    technology["html_clues"] = html_clues
    technology["script_sources"] = script_sources
    technology["meta_generator"] = meta_generator
    technology["identified_at"] = _now()
    technology["status"] = "in-progress"

    _save_technology(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-004",
            action=(
                "Technology identification recorded: "
                f"{target_url} "
                f"({len(technologies)} technology candidates)"
            ),
            status="in-progress",
            context=context,
        )
    except ActivityError as exc:
        raise TechnologyError(
            "Technology identification berhasil disimpan, "
            "tetapi activity gagal dicatat.\n"
            f"{exc}"
        ) from exc

    return data


def validate(
    *,
    context: Optional[ProjectContext] = None,
) -> list[str]:
    if context is None:
        context = require_active_project()

    data = _load_technology(context)
    technology = data["technology"]
    errors: list[str] = []

    required_fields = {
        "application": technology.get("application"),
        "target_url": technology.get("target_url"),
        "hostname": technology.get("hostname"),
        "scheme": technology.get("scheme"),
        "port": technology.get("port"),
        "environment": technology.get("environment"),
        "assessment_type": technology.get("assessment_type"),
        "scope_reference": technology.get("scope_reference"),
        "identified_at": technology.get("identified_at"),
    }

    for field, value in required_fields.items():
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} belum diisi.")

    if technology.get("scheme") not in {"http", "https"}:
        errors.append("scheme harus berupa http atau https.")

    if not str(technology.get("port", "")).isdigit():
        errors.append("port harus berupa angka.")

    http_data = technology.get("http")

    if not isinstance(http_data, dict):
        errors.append("http harus berupa mapping/object.")
    else:
        if not isinstance(http_data.get("status_code"), int):
            errors.append("HTTP status_code belum tersedia.")

        if not isinstance(
            http_data.get("final_url"),
            str,
        ) or not http_data.get("final_url").strip():
            errors.append("HTTP final_url belum tersedia.")

    if not isinstance(technology.get("technologies"), list):
        errors.append("technologies harus berupa list.")

    if not isinstance(technology.get("html_clues"), list):
        errors.append("html_clues harus berupa list.")

    if not isinstance(technology.get("script_sources"), list):
        errors.append("script_sources harus berupa list.")

    return errors


def verify(
    *,
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    if context is None:
        context = require_active_project()

    errors = validate(context=context)

    if errors:
        raise TechnologyError(
            "Technology Identification belum lengkap:\n"
            + "\n".join(f"- {error}" for error in errors)
        )

    data = _load_technology(context)
    data["technology"]["status"] = "completed"

    _save_technology(context, data)

    try:
        record_activity(
            phase="02-reconnaissance",
            item="02-004",
            action="Technology identification verified",
            status="completed",
            context=context,
        )
    except ActivityError as exc:
        raise TechnologyError(
            "Technology berhasil diverifikasi, "
            "tetapi activity gagal dicatat.\n"
            f"{exc}"
        ) from exc

    return data


def set_status(
    status: str,
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    normalized = status.strip().lower()

    if normalized not in VALID_STATUSES:
        raise TechnologyError(
            f"Status tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data = _load_technology(context)
    data["technology"]["status"] = normalized
    _save_technology(context, data)

    record_activity(
        phase="02-reconnaissance",
        item="02-004",
        action=(
            "Technology Identification status "
            f"changed to {normalized}"
        ),
        status=(
            "completed"
            if normalized == "completed"
            else "in-progress"
        ),
        context=context,
    )


def remove(
    *,
    context: Optional[ProjectContext] = None,
) -> bool:
    if context is None:
        context = require_active_project()

    path = technology_file(context)

    if not path.is_file():
        return False

    try:
        path.unlink()
    except OSError as exc:
        raise TechnologyError(
            f"Gagal menghapus: {path}\n{exc}"
        ) from exc

    record_activity(
        phase="02-reconnaissance",
        item="02-004",
        action="Technology Identification removed",
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

    data = _load_technology(context)
    technology = data["technology"]
    http_data = technology.get("http", {})

    print("=" * 72)
    print(
        " BrebesKab-CSIRT-Tools - "
        "Reconnaissance Technology Identification"
    )
    print("=" * 72)
    print(f"Project ID       : {context.project_id}")
    print(f"Status           : {technology.get('status', '')}")
    print(f"Application      : {technology.get('application', '')}")
    print(f"Target URL       : {technology.get('target_url', '')}")
    print(f"Hostname         : {technology.get('hostname', '')}")
    print(f"Scheme           : {technology.get('scheme', '')}")
    print(f"Port             : {technology.get('port', '')}")
    print(f"Environment      : {technology.get('environment', '')}")
    print(f"Assessment Type  : {technology.get('assessment_type', '')}")
    print(f"HTTP Status      : {http_data.get('status_code', '-')}")
    print(f"Final URL        : {http_data.get('final_url', '-')}")
    print(f"Content-Type     : {http_data.get('content_type', '-')}")
    print(f"Server           : {http_data.get('server', '-')}")
    print(f"X-Powered-By     : {http_data.get('powered_by', '-')}")
    print(
        "Technologies     : "
        f"{len(technology.get('technologies', []))}"
    )
    print(
        "HTML Clues       : "
        f"{len(technology.get('html_clues', []))}"
    )
    print(
        "Script Sources   : "
        f"{len(technology.get('script_sources', []))}"
    )
    print(
        "Meta Generator   : "
        f"{technology.get('meta_generator') or '-'}"
    )
    print(
        "Identified At    : "
        f"{technology.get('identified_at') or '-'}"
    )
    print(
        f"Scope Reference  : "
        f"{technology.get('scope_reference', '')}"
    )
    print(f"File             : {technology_file(context)}")


def print_full(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    data = _load_technology(context)

    print(f"PROJECT: {context.project_id}")
    print(f"FILE   : {technology_file(context)}")
    print()
    _print_value(data["technology"])


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
        "Reconnaissance Technology Identification\n"
        "\n"
        "Usage:\n"
        "  python scripts/reconnaissance/technology.py init\n"
        "  python scripts/reconnaissance/technology.py identify\n"
        "  python scripts/reconnaissance/technology.py list\n"
        "  python scripts/reconnaissance/technology.py show\n"
        "  python scripts/reconnaissance/technology.py verify\n"
        "  python scripts/reconnaissance/technology.py status\n"
        "  python scripts/reconnaissance/technology.py remove\n"
        "  python scripts/reconnaissance/technology.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
        "\n"
        "init      Read completed network.yaml and create technology.yaml.\n"
        "identify  Perform passive/basic HTTP technology identification.\n"
        "list      Show a concise technology summary.\n"
        "show      Show the complete technology reconnaissance document.\n"
        "verify    Validate the technology reconnaissance and mark completed.\n"
        "status    Show the current lifecycle status.\n"
        "remove    Remove technology.yaml.\n"
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
            f"technology.py v{SCRIPT_VERSION}"
        )
        return 0

    try:
        context = require_active_project()

        if command == "init":
            path = initialize(context=context)
            print(
                "[PASS] Technology configuration siap "
                "dari IP / Network."
            )
            print(f"File: {path}")
            return 0

        if command in ("identify", "detect"):
            data = identify(context=context)
            technology = data["technology"]
            http_data = technology["http"]

            print(
                "[PASS] Technology identification berhasil."
            )
            print(
                f"HTTP Status : "
                f"{http_data.get('status_code', '-')}"
            )
            print(
                f"Final URL   : "
                f"{http_data.get('final_url', '-')}"
            )

            names = [
                item.get("name", "")
                for item in technology.get("technologies", [])
                if item.get("name")
            ]

            print(
                "Technology  : "
                f"{', '.join(names) if names else '-'}"
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
            print(
                "[PASS] Technology Identification "
                "memenuhi validasi."
            )
            print("[PASS] Status: completed")
            return 0

        if command == "status":
            data = _load_technology(context)
            print(f"Project ID : {context.project_id}")
            print(
                f"Status     : "
                f"{data['technology'].get('status', '')}"
            )
            return 0

        if command == "remove":
            removed = remove(context=context)

            if not removed:
                print(
                    "[INFO] Technology Identification "
                    "belum ada."
                )
                return 1

            print(
                "[PASS] Technology Identification "
                "telah dihapus."
            )
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except (
        ContextError,
        TechnologyError,
        ActivityError,
    ) as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
