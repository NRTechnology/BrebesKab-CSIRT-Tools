#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Endpoint Discovery

Phase : 02 Reconnaissance
Item  : 02-006 Endpoint Discovery
Version: 1.0.0

This module performs controlled, passive endpoint discovery from:
- the target application's HTML
- links and form actions
- JavaScript source references
- robots.txt
- sitemap.xml

It does not perform fuzzing, brute-force discovery, authentication,
credential handling, or vulnerability testing.

The active project is resolved automatically through context.py.
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urldefrag

# Prevent scripts/reconnaissance/http.py from shadowing Python's stdlib http
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent
script_dir_string = str(SCRIPT_DIR)
sys.path[:] = [entry for entry in sys.path if entry != script_dir_string]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

import requests
import yaml

from context import require_active_project
from activity import record_activity


VERSION = "1.0.0"
TIMEOUT = 15
USER_AGENT = "BrebesKab-CSIRT-Tools/1.0 Endpoint-Reconnaissance"

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
}

SKIP_EXTENSIONS = {
    ".css",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".mp4",
    ".mp3",
    ".avi",
    ".mov",
}

HTTP_STATUS_LABELS = {
    "discovered": "discovered",
    "robots": "robots.txt",
    "sitemap": "sitemap.xml",
    "form": "form action",
    "link": "HTML link",
    "script": "JavaScript source",
}


def now_iso() -> str:
    jakarta = timezone(timedelta(hours=7))
    return datetime.now(jakarta).isoformat(timespec="seconds")


def project_context():
    return require_active_project()


def endpoint_file() -> Path:
    return project_context().project_path / "02-reconnaissance" / "endpoint" / "endpoint.yaml"


def technology_file() -> Path:
    return project_context().project_path / "02-reconnaissance" / "technology" / "technology.yaml"


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


def require_technology_completed() -> dict[str, Any]:
    """Load and validate the completed technology reconnaissance document.

    The project YAML convention keeps module state under a top-level
    module key, for example:

        technology:
          status: completed
          application: ...

    Therefore this function returns the nested ``technology`` mapping,
    not the complete top-level YAML document.
    """
    path = technology_file()
    data = load_yaml(path)

    ctx = project_context()

    project_id = str(data.get("project_id", "")).strip()
    if project_id != ctx.project_id:
        raise RuntimeError(
            "Project ID pada technology.yaml tidak sesuai active project. "
            f"Context: {ctx.project_id}; File: {project_id or '-'}"
        )

    technology = data.get("technology")

    if not isinstance(technology, dict):
        raise RuntimeError(
            "Field 'technology' pada technology.yaml tidak valid. "
            "Struktur YAML harus menggunakan mapping 'technology:'."
        )

    status = str(technology.get("status", "")).strip().lower()

    if status != "completed":
        raise RuntimeError(
            "Technology Identification belum completed. "
            "Jalankan technology.py verify terlebih dahulu."
        )

    required_fields = {
        "application": technology.get("application"),
        "target_url": technology.get("target_url"),
        "hostname": technology.get("hostname"),
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
        raise RuntimeError(
            "Technology Identification belum lengkap. "
            "Field kosong: " + ", ".join(missing)
        )

    return technology


def base_document(technology: dict[str, Any]) -> dict[str, Any]:
    """Build the standard reconnaissance YAML document."""
    ctx = project_context()
    target_url = str(technology.get("target_url", "")).strip()
    hostname = str(technology.get("hostname", "")).strip()
    return {
        "schema_version": "1.0",
        "project_id": ctx.project_id,
        "updated_at": now_iso(),
        "endpoint": {
            "status": "not-started",
            "application": technology.get("application", ""),
            "target_url": target_url,
            "hostname": hostname,
            "environment": technology.get("environment", ""),
            "assessment_type": technology.get("assessment_type", ""),
            "scope_reference": technology.get("scope_reference", "01-preparation/scope/scope.yaml"),
            "sources": {"html": False, "robots_txt": False, "sitemap_xml": False, "javascript": False},
            "endpoints": [],
            "summary": {"total": 0, "html_links": 0, "forms": 0, "javascript": 0, "robots": 0, "sitemap": 0, "same_host": 0, "external": 0},
            "notes": "",
            "discovered_at": "",
        },
    }


def require_endpoint(data: dict[str, Any]) -> dict[str, Any]:
    endpoint = data.get("endpoint")
    if not isinstance(endpoint, dict):
        raise RuntimeError(
            "Field 'endpoint' pada endpoint.yaml tidak valid. "
            "Struktur YAML harus menggunakan mapping 'endpoint:'."
        )
    return endpoint


def normalize_endpoint(base_url: str, value: str) -> str | None:
    value = value.strip()
    if not value:
        return None

    if value.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None

    absolute = urljoin(base_url, value)
    absolute, _fragment = urldefrag(absolute)

    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    return absolute


def is_same_host(target_hostname: str, url: str) -> bool:
    try:
        hostname = urlparse(url).hostname
        return hostname is not None and hostname.lower() == target_hostname.lower()
    except Exception:
        return False


def is_static_resource(url: str) -> bool:
    path = urlparse(url).path.lower()
    suffix = Path(path).suffix
    return suffix in SKIP_EXTENSIONS


def endpoint_key(url: str, method: str = "GET") -> tuple[str, str]:
    return method.upper(), url


def add_endpoint(
    endpoints: dict[tuple[str, str], dict[str, Any]],
    *,
    url: str,
    source: str,
    method: str = "GET",
    same_host: bool,
    detail: str = "",
) -> None:
    method = method.upper()
    key = endpoint_key(url, method)

    if key in endpoints:
        existing = endpoints[key]
        sources = existing.setdefault("sources", [])
        if source not in sources:
            sources.append(source)
        if detail and not existing.get("detail"):
            existing["detail"] = detail
        return

    endpoints[key] = {
        "method": method,
        "url": url,
        "same_host": same_host,
        "sources": [source],
        "detail": detail,
    }


def extract_html_endpoints(
    html: str,
    base_url: str,
    hostname: str,
    endpoints: dict[tuple[str, str], dict[str, Any]],
) -> tuple[int, int]:
    link_count = 0
    form_count = 0

    # href values
    for match in re.finditer(
        r"""(?is)<(?:a|link)\b[^>]*?\bhref\s*=\s*["']([^"']+)["']""",
        html,
    ):
        raw = match.group(1).strip()
        url = normalize_endpoint(base_url, raw)
        if not url or is_static_resource(url):
            continue
        add_endpoint(
            endpoints,
            url=url,
            source="HTML link",
            same_host=is_same_host(hostname, url),
        )
        link_count += 1

    # src values for script references
    for match in re.finditer(
        r"""(?is)<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']""",
        html,
    ):
        raw = match.group(1).strip()
        url = normalize_endpoint(base_url, raw)
        if not url:
            continue
        add_endpoint(
            endpoints,
            url=url,
            source="JavaScript source",
            same_host=is_same_host(hostname, url),
        )

    # form actions
    for match in re.finditer(
        r"""(?is)<form\b([^>]*)>""",
        html,
    ):
        attributes = match.group(1)
        action_match = re.search(
            r"""(?is)\baction\s*=\s*["']([^"']*)["']""",
            attributes,
        )
        method_match = re.search(
            r"""(?is)\bmethod\s*=\s*["']([^"']*)["']""",
            attributes,
        )

        raw_action = action_match.group(1).strip() if action_match else ""
        method = method_match.group(1).strip().upper() if method_match else "GET"

        if method not in HTTP_METHODS:
            method = "GET"

        url = normalize_endpoint(base_url, raw_action or base_url)
        if not url:
            continue

        add_endpoint(
            endpoints,
            url=url,
            source="form action",
            method=method,
            same_host=is_same_host(hostname, url),
        )
        form_count += 1

    return link_count, form_count


def extract_javascript_urls(
    html: str,
    base_url: str,
    hostname: str,
    endpoints: dict[tuple[str, str], dict[str, Any]],
) -> int:
    count = 0

    # Common absolute/root-relative URL literals found in inline JS.
    # This is intentionally conservative; it does not execute JavaScript.
    patterns = [
        r"""["']((?:https?://|/)[^"'<> ]+)["']""",
        r"""(?i)\b(?:url|endpoint|path|route)\s*[:=]\s*["']([^"']+)["']""",
    ]

    seen: set[str] = set()

    for pattern in patterns:
        for match in re.finditer(pattern, html):
            raw = match.group(1).strip()
            url = normalize_endpoint(base_url, raw)
            if not url or url in seen or is_static_resource(url):
                continue

            seen.add(url)
            add_endpoint(
                endpoints,
                url=url,
                source="JavaScript source",
                same_host=is_same_host(hostname, url),
            )
            count += 1

    return count


def extract_text_endpoints(
    text: str,
    base_url: str,
    hostname: str,
    source: str,
    endpoints: dict[tuple[str, str], dict[str, Any]],
) -> int:
    count = 0

    for raw in re.findall(
        r"""(?i)(?:https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+|/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+)""",
        text,
    ):
        url = normalize_endpoint(base_url, raw.rstrip(".,);]}"))
        if not url or is_static_resource(url):
            continue

        add_endpoint(
            endpoints,
            url=url,
            source=source,
            same_host=is_same_host(hostname, url),
        )
        count += 1

    return count


def fetch(
    session: requests.Session,
    url: str,
) -> tuple[requests.Response | None, str]:
    try:
        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        return response, ""
    except requests.RequestException as exc:
        return None, str(exc)


def inspect_document(data: dict[str, Any]) -> None:
    endpoint = require_endpoint(data)
    target_url = str(endpoint.get("target_url", "")).strip()
    hostname = str(endpoint.get("hostname", "")).strip()

    if not target_url or not hostname:
        raise RuntimeError("Target URL / hostname tidak tersedia di endpoint.yaml.")

    endpoints: dict[tuple[str, str], dict[str, Any]] = {}

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    html_response, html_error = fetch(session, target_url)

    if html_response is None:
        raise RuntimeError(f"Gagal mengambil target utama: {html_error}")

    content_type = html_response.headers.get("Content-Type", "")
    html = html_response.text if "text/html" in content_type.lower() else ""

    endpoint["sources"] = {
        "html": bool(html),
        "robots_txt": False,
        "sitemap_xml": False,
        "javascript": False,
    }

    if html:
        link_count, form_count = extract_html_endpoints(
            html,
            html_response.url,
            hostname,
            endpoints,
        )
        js_count = extract_javascript_urls(
            html,
            html_response.url,
            hostname,
            endpoints,
        )
        endpoint["sources"]["javascript"] = js_count > 0
    else:
        link_count = 0
        form_count = 0
        js_count = 0

    robots_url = urljoin(target_url, "/robots.txt")
    robots_response, robots_error = fetch(session, robots_url)

    if robots_response is not None and robots_response.status_code < 500:
        endpoint["sources"]["robots_txt"] = True
        extract_text_endpoints(
            robots_response.text,
            robots_response.url,
            hostname,
            "robots.txt",
            endpoints,
        )

    sitemap_url = urljoin(target_url, "/sitemap.xml")
    sitemap_response, sitemap_error = fetch(session, sitemap_url)

    if sitemap_response is not None and sitemap_response.status_code < 500:
        endpoint["sources"]["sitemap_xml"] = True
        extract_text_endpoints(
            sitemap_response.text,
            sitemap_response.url,
            hostname,
            "sitemap.xml",
            endpoints,
        )

    endpoint_list = list(endpoints.values())
    endpoint_list.sort(
        key=lambda item: (
            not item["same_host"],
            item["url"].lower(),
            item["method"],
        )
    )

    endpoint["endpoints"] = endpoint_list
    endpoint["summary"] = {
        "total": len(endpoint_list),
        "html_links": sum("HTML link" in e["sources"] for e in endpoint_list),
        "forms": sum("form action" in e["sources"] for e in endpoint_list),
        "javascript": sum("JavaScript source" in e["sources"] for e in endpoint_list),
        "robots": sum("robots.txt" in e["sources"] for e in endpoint_list),
        "sitemap": sum("sitemap.xml" in e["sources"] for e in endpoint_list),
        "same_host": sum(e["same_host"] for e in endpoint_list),
        "external": sum(not e["same_host"] for e in endpoint_list),
    }

    notes: list[str] = []

    if html_error:
        notes.append(f"HTML error: {html_error}")
    if robots_error:
        notes.append(f"robots.txt: {robots_error}")
    if sitemap_error:
        notes.append(f"sitemap.xml: {sitemap_error}")
    if not html:
        notes.append("Target response bukan HTML atau HTML kosong; HTML discovery dilewati.")

    endpoint["notes"] = "; ".join(notes)
    endpoint["status"] = "in-progress"
    endpoint["discovered_at"] = now_iso()
    data["updated_at"] = now_iso()

    save_yaml(endpoint_file(), data)

    record_activity(
        phase="02-reconnaissance",
        item="02-006",
        action=(
            f"Endpoint discovery recorded: {endpoint['summary']['total']} endpoints "
            f"(same-host={endpoint['summary']['same_host']}, "
            f"external={endpoint['summary']['external']})"
        ),
        status="in-progress",
    )


def validate(data: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    try:
        endpoint = require_endpoint(data)
    except RuntimeError as exc:
        return False, [str(exc)]

    if endpoint.get("status") not in {"in-progress", "completed"}:
        errors.append("endpoint.status harus in-progress atau completed.")
    if not data.get("project_id"):
        errors.append("project_id kosong.")
    for field in ("application", "target_url", "hostname", "environment", "assessment_type", "scope_reference"):
        if not str(endpoint.get(field, "")).strip():
            errors.append(f"endpoint.{field} kosong.")

    if not isinstance(endpoint.get("endpoints"), list):
        errors.append("endpoint.endpoints harus berupa list.")
    summary = endpoint.get("summary")
    if not isinstance(summary, dict):
        errors.append("endpoint.summary tidak tersedia.")
    else:
        total = summary.get("total")
        if not isinstance(total, int):
            errors.append("endpoint.summary.total tidak valid.")
        elif total != len(endpoint.get("endpoints", [])):
            errors.append("endpoint.summary.total tidak sesuai jumlah endpoints.")

    if endpoint.get("status") == "completed":
        if not endpoint.get("discovered_at"):
            errors.append("endpoint.discovered_at kosong.")
        if not isinstance(endpoint.get("sources"), dict):
            errors.append("endpoint.sources tidak tersedia.")

    return not errors, errors


def command_init() -> int:
    path = endpoint_file()

    if path.exists():
        print(f"[INFO] File sudah ada: {path}")
        print("[INFO] Gunakan 'remove' jika ingin membuat ulang.")
        return 1

    technology = require_technology_completed()
    data = base_document(technology)
    save_yaml(path, data)

    print("[PASS] Endpoint Discovery berhasil diinisialisasi.")
    print(f"PROJECT: {project_context().project_id}")
    print(f"FILE   : {path}")
    print(f"TARGET : {data['target_url']}")
    return 0


def command_inspect() -> int:
    path = endpoint_file()

    if not path.exists():
        print("[FAIL] endpoint.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path)

    try:
        inspect_document(data)
    except Exception as exc:
        print(f"[FAIL] Endpoint discovery gagal: {exc}")
        return 1

    summary = require_endpoint(data)["summary"]

    print("[PASS] Endpoint Discovery berhasil.")
    print(f"Target      : {require_endpoint(data)['target_url']}")
    print(f"Endpoints   : {summary['total']}")
    print(f"Same-host   : {summary['same_host']}")
    print(f"External    : {summary['external']}")
    print(f"HTML links  : {summary['html_links']}")
    print(f"Forms       : {summary['forms']}")
    print(f"JavaScript  : {summary['javascript']}")
    print(f"robots.txt  : {summary['robots']}")
    print(f"sitemap.xml : {summary['sitemap']}")
    return 0


def command_list() -> int:
    path = endpoint_file()

    if not path.exists():
        print("[FAIL] endpoint.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path)
    endpoint = require_endpoint(data)
    endpoints = endpoint.get("endpoints", [])

    print(f"Project ID : {project_context().project_id}")
    print(f"Status     : {endpoint.get('status', '-')}")
    print(f"Endpoints  : {len(endpoints)}")

    if not endpoints:
        print("  [none]")
        return 0

    for item in endpoints:
        host_label = "same-host" if item.get("same_host") else "external"
        sources = ", ".join(item.get("sources", []))
        print(
            f"  {item.get('method', 'GET'):6} "
            f"{item.get('url', '')} "
            f"[{host_label}] "
            f"({sources})"
        )

    return 0


def command_show() -> int:
    path = endpoint_file()

    if not path.exists():
        print("[FAIL] endpoint.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path)

    print(f"PROJECT: {project_context().project_id}")
    print(f"FILE   : {path}")
    print()

    print(yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    ).rstrip())

    return 0


def command_verify() -> int:
    path = endpoint_file()

    if not path.exists():
        print("[FAIL] endpoint.yaml belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path)

    endpoint = require_endpoint(data)

    if endpoint.get("status") != "in-progress":
        if endpoint.get("status") == "completed":
            print("[PASS] Endpoint Discovery sudah completed.")
            return 0
        print("[FAIL] Endpoint Discovery belum diinspeksi.")
        return 1

    valid, errors = validate(data)

    if not valid:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    endpoint["status"] = "completed"
    data["updated_at"] = now_iso()
    save_yaml(path, data)

    record_activity(
        phase="02-reconnaissance",
        item="02-006",
        action="Endpoint Discovery verified",
        status="completed",
    )

    print("[PASS] Endpoint Discovery memenuhi validasi.")
    print("[PASS] Status: completed")
    return 0


def command_status() -> int:
    path = endpoint_file()

    if not path.exists():
        print(f"Project ID : {project_context().project_id}")
        print("Status     : not-started")
        return 0

    data = load_yaml(path)
    print(f"Project ID : {project_context().project_id}")
    print(f"Status     : {require_endpoint(data).get('status', 'unknown')}")
    return 0


def command_remove() -> int:
    path = endpoint_file()

    if not path.exists():
        print("[INFO] endpoint.yaml tidak ditemukan.")
        return 0

    path.unlink()
    print(f"[PASS] File dihapus: {path}")
    return 0


def command_version() -> int:
    print(f"Endpoint Discovery v{VERSION}")
    return 0


def print_help() -> None:
    print(
        f"""Reconnaissance Endpoint Discovery v{VERSION}

Usage:
  python scripts/reconnaissance/endpoint.py init
  python scripts/reconnaissance/endpoint.py inspect
  python scripts/reconnaissance/endpoint.py list
  python scripts/reconnaissance/endpoint.py show
  python scripts/reconnaissance/endpoint.py verify
  python scripts/reconnaissance/endpoint.py status
  python scripts/reconnaissance/endpoint.py remove
  python scripts/reconnaissance/endpoint.py version

The active project is resolved automatically through context.py.
No --project argument is required.

init      Read completed technology.yaml and create endpoint.yaml.
inspect   Perform controlled endpoint discovery.
list      Show discovered endpoints.
show      Show the complete endpoint discovery document.
verify    Validate the discovery and mark completed.
status    Show the current lifecycle status.
remove    Remove endpoint.yaml.
version   Show the script version.

Discovery sources:
  - HTML links
  - form actions
  - JavaScript source references / URL literals
  - robots.txt
  - sitemap.xml

This module does not perform fuzzing or brute-force endpoint discovery.
"""
    )


def main() -> int:
    if len(sys.argv) < 2:
        print_help()
        return 1

    command = sys.argv[1].lower()

    commands = {
        "init": command_init,
        "inspect": command_inspect,
        "list": command_list,
        "show": command_show,
        "verify": command_verify,
        "status": command_status,
        "remove": command_remove,
        "version": command_version,
        "--help": lambda: (print_help() or 0),
        "-h": lambda: (print_help() or 0),
    }

    handler = commands.get(command)

    if handler is None:
        print(f"[FAIL] Command tidak dikenal: {command}")
        print()
        print_help()
        return 1

    try:
        return handler()
    except KeyboardInterrupt:
        print("\n[STOP] Dihentikan oleh operator.")
        return 130
    except Exception as exc:
        print(f"[FAIL] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
