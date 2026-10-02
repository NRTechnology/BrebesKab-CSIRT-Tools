#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - webserver/version.py

Checklist: 4-001 Server version disclosure

Purpose
-------
Collect public web-response technology/version disclosure from HTTP and HTTPS,
correlate observations with the existing service enumeration baseline, and
optionally correlate disclosed products/versions with NVD CVE applicability.

Important boundary
------------------
- This module performs controlled GET requests only.
- It does not exploit CVEs and does not create vulnerability findings.
- CVE correlation is review evidence only. A version match is not proof that a
  vulnerability is exploitable on the target.
- TLS protocol/cipher/certificate assessment remains in 3-008/3-009/3-010.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import requests
import typer
import yaml
from requests import Response
from urllib3.exceptions import InsecureRequestWarning

# ---------------------------------------------------------------------------
# Version / schema
# ---------------------------------------------------------------------------
APP_NAME = "BrebesKab-CSIRT-Tools version.py"
APP_VERSION = "1.0.3"
SCHEMA_VERSION = "1.3"
CHECKLIST_ID = "4-001"
CHECKLIST_NAME = "Server version disclosure"
PHASE_NAME = "04 Web Server Configuration"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_TIME = 45
NVD_PAGE_SIZE = 2000
NVD_PUBLIC_DELAY_SECONDS = 6.2

REQUEST_USER_AGENT = f"BrebesKab-CSIRT-Tools/{APP_VERSION} Server-Version"

TARGET_HEADER_RULES = {
    "server": "server",
    "x-powered-by": "x-powered-by",
    "x-aspnet-version": "x-aspnet-version",
    "x-aspnetmvc-version": "x-aspnetmvc-version",
    "x-generator": "x-generator",
    "x-runtime": "x-runtime",
}

# High-confidence product -> CPE mappings used by the current project.
# Unknown products stay unresolved rather than being assigned a speculative CPE.
CPE_PRODUCT_MAP: dict[str, tuple[str, str, str]] = {
    "apache": ("apache", "http_server", "Apache HTTP Server"),
    "apache httpd": ("apache", "http_server", "Apache HTTP Server"),
    "apache http server": ("apache", "http_server", "Apache HTTP Server"),
    "php": ("php", "php", "PHP"),
}

VERSION_PATTERNS = [
    re.compile(r"(?P<product>Apache(?:\s+HTTPD|\s+HTTP\s+Server|)?|httpd)[/\s_-]*(?P<version>\d+(?:\.\d+){1,3}(?:[._-][0-9A-Za-z]+)*)", re.I),
    re.compile(r"(?P<product>PHP)[/\s-]*(?P<version>\d+(?:\.\d+){1,3}(?:[._-][0-9A-Za-z]+)*)", re.I),
    re.compile(r"(?P<product>nginx)[/\s-]*(?P<version>\d+(?:\.\d+){1,3}(?:[._-][0-9A-Za-z]+)*)", re.I),
    re.compile(r"(?P<product>Microsoft-IIS|IIS)[/\s-]*(?P<version>\d+(?:\.\d+){1,3}(?:[._-][0-9A-Za-z]+)*)", re.I),
]

app = typer.Typer(add_completion=False, no_args_is_help=True)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def dump_yaml(data: dict[str, Any]) -> str:
    return yaml.safe_dump(
        data,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
    )


def run_version_command(path: str | None, args: list[str]) -> tuple[bool, str]:
    if not path:
        return False, ""
    try:
        proc = subprocess.run(
            [path, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False,
        )
        output = (proc.stdout or "").strip()
        return proc.returncode == 0, output
    except (OSError, subprocess.SubprocessError):
        return False, ""


def find_executable(name: str, candidates: Iterable[str] = ()) -> str | None:
    found = shutil.which(name)
    if found:
        return str(Path(found).resolve())
    for candidate in candidates:
        p = Path(candidate)
        if p.exists() and p.is_file():
            return str(p)
    return None


def discover_repo_root() -> Path:
    # scripts/webserver/version.py -> repo root is parents[2]
    return Path(__file__).resolve().parents[2]


def discover_project_id(repo_root: Path) -> str:
    network_path = repo_root / "projects"
    candidates = list(network_path.glob("*/02-reconnaissance/network/network.yaml"))
    if len(candidates) == 1:
        data = load_yaml(candidates[0])
        project_id = str(data.get("project_id") or data.get("network", {}).get("project_id") or "").strip()
        if project_id:
            return project_id

    active_candidates = list(network_path.glob("*/active-project.yaml"))
    if len(active_candidates) == 1:
        data = load_yaml(active_candidates[0])
        project_id = str(data.get("project_id") or "").strip()
        if project_id:
            return project_id

    if candidates:
        return candidates[0].parts[-4]
    raise RuntimeError("Tidak dapat menemukan active project di projects/.")


def project_root(repo_root: Path, project_id: str) -> Path:
    path = repo_root / "projects" / project_id
    if not path.exists():
        raise FileNotFoundError(f"Project path tidak ditemukan: {path}")
    return path


def artifact_root(repo_root: Path, project_id: str) -> Path:
    return project_root(repo_root, project_id) / "04-web-server-configuration" / "version"


def artifact_file(repo_root: Path, project_id: str) -> Path:
    return artifact_root(repo_root, project_id) / "version.yaml"


def evidence_root(repo_root: Path, project_id: str) -> Path:
    return artifact_root(repo_root, project_id) / "evidence"


def source_paths(repo_root: Path, project_id: str) -> dict[str, Path]:
    root = project_root(repo_root, project_id)
    return {
        "network": root / "02-reconnaissance" / "network" / "network.yaml",
        "scope": root / "01-preparation" / "scope" / "scope.yaml",
        "service": root / "03-infrastructure" / "service" / "service.yaml",
    }


# ---------------------------------------------------------------------------
# Target / scope loading
# ---------------------------------------------------------------------------
def load_context(repo_root: Path, project_id: str) -> dict[str, Any]:
    sources = source_paths(repo_root, project_id)
    network = load_yaml(sources["network"])
    scope = load_yaml(sources["scope"])
    service = load_yaml(sources["service"])
    n = network.get("network", {})

    hostname = str(n.get("hostname") or "").strip()
    target_url = str(n.get("target_url") or "").strip()
    environment = str(n.get("environment") or "").strip()
    assessment_type = str(n.get("assessment_type") or "").strip()
    ipv4 = list(n.get("ipv4") or [])

    if not hostname or not target_url:
        raise RuntimeError("network.yaml tidak menyediakan hostname/target_url yang valid.")

    authorized_ports: list[int] = []
    scope_items = scope.get("scope", {}).get("items") or scope.get("scope_items") or []
    for item in scope_items if isinstance(scope_items, list) else []:
        for port in item.get("ports", []) if isinstance(item, dict) else []:
            try:
                p = int(port)
                if p not in authorized_ports:
                    authorized_ports.append(p)
            except (TypeError, ValueError):
                continue

    if not authorized_ports:
        for port in n.get("authorized_ports", []) or []:
            try:
                p = int(port)
                if p not in authorized_ports:
                    authorized_ports.append(p)
            except (TypeError, ValueError):
                continue

    service_section = service.get("service", {}) if isinstance(service.get("service", {}), dict) else {}

    # Primary scope source remains scope.yaml. For compatibility with the
    # project's generated infrastructure artifacts, also accept the already
    # resolved authorized_tcp_ports from service.yaml when the raw scope
    # structure is not directly represented as scope.items.
    service_authorized_ports = service_section.get("authorized_tcp_ports") or []
    for port in service_authorized_ports if isinstance(service_authorized_ports, list) else []:
        try:
            p = int(port)
            if p not in authorized_ports:
                authorized_ports.append(p)
        except (TypeError, ValueError):
            continue

    service_results = service_section.get("results", [])
    baseline_services = []
    for result in service_results if isinstance(service_results, list) else []:
        if not isinstance(result, dict):
            continue
        baseline_services.append(
            {
                "port": result.get("port"),
                "service": result.get("service", ""),
                "product": result.get("product", ""),
                "version": result.get("version", ""),
                "extra_info": result.get("extra_info", ""),
            }
        )

    # Fallback to service-generated scope items when raw scope.yaml does not
    # expose a directly consumable items list. This is still evidence reuse,
    # not a new authorization decision.
    if not authorized_ports:
        for item in service_section.get("scope_items", []) if isinstance(service_section.get("scope_items", []), list) else []:
            for port in item.get("ports", []) if isinstance(item, dict) else []:
                try:
                    p = int(port)
                    if p not in authorized_ports:
                        authorized_ports.append(p)
                except (TypeError, ValueError):
                    continue

    return {
        "project_id": project_id,
        "application": str(n.get("application") or "").strip(),
        "target_url": target_url.rstrip("/"),
        "hostname": hostname,
        "environment": environment,
        "assessment_type": assessment_type,
        "ipv4": ipv4,
        "authorized_ports": sorted(set(authorized_ports)),
        "scope_reference": str(n.get("scope_reference") or "01-preparation/scope/scope.yaml"),
        "network_source": str(sources["network"].relative_to(repo_root)).replace("\\", "/"),
        "scope_source": str(sources["scope"].relative_to(repo_root)).replace("\\", "/"),
        "service_source": str(sources["service"].relative_to(repo_root)).replace("\\", "/"),
        "baseline_services": baseline_services,
    }


# ---------------------------------------------------------------------------
# HTTP probing
# ---------------------------------------------------------------------------
def normalize_headers(headers: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in headers.items()}


def extract_version_observations(headers: dict[str, str], source: str, url: str) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    lowered = {k.lower(): v for k, v in headers.items()}

    for key, rule_name in TARGET_HEADER_RULES.items():
        value = lowered.get(key)
        if not value:
            continue
        matched_any = False
        for pattern in VERSION_PATTERNS:
            for match in pattern.finditer(value):
                matched_any = True
                product_raw = (match.group("product") or "").strip()
                version = (match.group("version") or "").strip()
                product_key = normalize_product_name(product_raw)
                vendor, product, product_display = CPE_PRODUCT_MAP.get(
                    product_key, ("", "", product_raw)
                )
                observations.append(
                    {
                        "header": key,
                        "header_rule": rule_name,
                        "value": value,
                        "product": product_display,
                        "product_raw": product_raw,
                        "product_key": product_key,
                        "version": version,
                        "cpe_vendor": vendor,
                        "cpe_product": product,
                        "source": source,
                        "url": url,
                        "version_disclosed": True,
                        "cpe_resolved": bool(vendor and product),
                    }
                )
        if not matched_any:
            observations.append(
                {
                    "header": key,
                    "header_rule": rule_name,
                    "value": value,
                    "product": "",
                    "product_raw": "",
                    "product_key": "",
                    "version": "",
                    "cpe_vendor": "",
                    "cpe_product": "",
                    "source": source,
                    "url": url,
                    "version_disclosed": False,
                    "cpe_resolved": False,
                }
            )
    return observations


def normalize_product_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    if normalized in {"apache", "apache httpd", "httpd", "apache http server"}:
        return "apache http server"
    if normalized == "php":
        return "php"
    if normalized == "nginx":
        return "nginx"
    if normalized in {"microsoft iis", "iis"}:
        return "iis"
    return normalized


def get_target_urls(context: dict[str, Any]) -> list[str]:
    parts = urlsplit(context["target_url"])
    host = parts.hostname or context["hostname"]
    urls: list[str] = []
    # Only probe ports explicitly authorized and the normal HTTP/S schemes.
    if 80 in context["authorized_ports"]:
        urls.append(f"http://{host}/")
    if 443 in context["authorized_ports"]:
        urls.append(f"https://{host}/")
    if not urls:
        urls.append(context["target_url"] + ("/" if not context["target_url"].endswith("/") else ""))
    return urls


def probe_with_requests(url: str) -> dict[str, Any]:
    started = now_iso()
    verify = url.lower().startswith("https://")
    fallback = False
    error = ""
    response: Response | None = None
    try:
        response = requests.get(
            url,
            headers={"User-Agent": REQUEST_USER_AGENT, "Accept": "*/*"},
            allow_redirects=False,
            timeout=(10, DEFAULT_MAX_TIME),
            verify=verify,
        )
    except requests.exceptions.SSLError as exc:
        if verify:
            fallback = True
            with warnings_suppressed():
                try:
                    response = requests.get(
                        url,
                        headers={"User-Agent": REQUEST_USER_AGENT, "Accept": "*/*"},
                        allow_redirects=False,
                        timeout=(10, DEFAULT_MAX_TIME),
                        verify=False,
                    )
                except requests.RequestException as exc2:
                    error = f"HTTPS probe failed: {exc2}"
        else:
            error = f"Request failed: {exc}"
    except requests.RequestException as exc:
        error = f"Request failed: {exc}"

    completed = now_iso()
    result: dict[str, Any] = {
        "url": url,
        "method": "GET",
        "allow_redirects": False,
        "started_at": started,
        "completed_at": completed,
        "certificate_verification": "enabled" if verify and not fallback else ("disabled-fallback" if fallback else "not-applicable"),
        "status_code": None,
        "final_url": url,
        "headers": {},
        "redirect_location": "",
        "error": error,
        "tool": "python-requests",
    }
    if response is not None:
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["headers"] = normalize_headers(response.headers)
        result["redirect_location"] = response.headers.get("Location", "")
    return result


class _WarningsSuppressed:
    def __enter__(self):
        import warnings
        self._warnings = warnings
        warnings.simplefilter("ignore", InsecureRequestWarning)

    def __exit__(self, exc_type, exc, tb):
        self._warnings.resetwarnings()


def warnings_suppressed() -> _WarningsSuppressed:
    return _WarningsSuppressed()


def probe_with_curl(curl_path: str | None, url: str) -> dict[str, Any]:
    if not curl_path:
        return {"available": False, "url": url, "error": "curl.exe tidak ditemukan."}

    started = now_iso()
    cmd = [
        curl_path,
        "-sS",
        "-D",
        "-",
        "-o",
        "NUL",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "15",
        "--max-time",
        str(DEFAULT_MAX_TIME),
        "-A",
        REQUEST_USER_AGENT,
        url,
    ]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=DEFAULT_MAX_TIME + 10,
            check=False,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        status_code = None
        location = ""
        header_block = stdout
        m = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", header_block, re.I)
        if m:
            status_code = int(m.group(1))
        m = re.search(r"^Location:\s*(.+)$", header_block, re.I | re.M)
        if m:
            location = m.group(1).strip()
        headers: dict[str, str] = {}
        for line in header_block.splitlines():
            if ":" not in line or line.upper().startswith("HTTP/"):
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return {
            "available": True,
            "url": url,
            "command": cmd,
            "started_at": started,
            "completed_at": now_iso(),
            "returncode": proc.returncode,
            "status_code": status_code,
            "location": location,
            "headers": headers,
            "stdout": stdout,
            "stderr": stderr,
            "error": "" if proc.returncode == 0 else "curl returned non-zero exit code",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "available": True,
            "url": url,
            "command": cmd,
            "started_at": started,
            "completed_at": now_iso(),
            "returncode": None,
            "status_code": None,
            "location": "",
            "headers": {},
            "stdout": "",
            "stderr": "",
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Service baseline correlation
# ---------------------------------------------------------------------------
def correlate_service_baseline(observations: list[dict[str, Any]], baseline_services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for obs in observations:
        if not obs.get("version_disclosed"):
            continue
        product = str(obs.get("product") or "").lower()
        version = str(obs.get("version") or "")
        matches = []
        for svc in baseline_services:
            svc_text = " ".join(
                [
                    str(svc.get("product") or ""),
                    str(svc.get("service") or ""),
                ]
            ).lower()
            if product and product.lower().split()[0] in svc_text and version == str(svc.get("version") or ""):
                matches.append(svc)
        results.append(
            {
                "header": obs.get("header"),
                "product": obs.get("product"),
                "version": version,
                "source": obs.get("source"),
                "service_baseline_matches": matches,
                "corroborated_by_service": bool(matches),
            }
        )
    return results


# ---------------------------------------------------------------------------
# CPE / CVE correlation
# ---------------------------------------------------------------------------
def cpe_escape_component(value: str) -> str:
    # CPE 2.3 components use backslash escaping for punctuation that is
    # meaningful to the CPE binding. Versions in this module are expected to
    # be simple release strings; escape conservatively for robustness.
    replacements = {
        "\\": "\\\\",
        ":": "\\:",
        "/": "\\/",
        "?": "\\?",
        "*": "\\*",
        "!": "\\!",
        "\"": "\\\"",
        "'": "\\'",
        " ": "\\ ",
    }
    out = value
    for old, new in replacements.items():
        out = out.replace(old, new)
    return out


def build_cpe(vendor: str, product: str, version: str) -> str:
    parts = [
        "cpe",
        "2.3",
        "a",
        cpe_escape_component(vendor),
        cpe_escape_component(product),
        cpe_escape_component(version),
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
        "*",
    ]
    return ":".join(parts)


def extract_cvss(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics") or {}
    candidates: list[tuple[int, str, dict[str, Any]]] = []
    for rank, key in enumerate(("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        item = entries[0]
        data = item.get("cvssData") or {}
        score = data.get("baseScore")
        try:
            score_num = float(score)
        except (TypeError, ValueError):
            score_num = -1.0
        candidates.append((rank, key, {"score": score_num, "severity": data.get("baseSeverity"), "vector": data.get("vectorString")}))
    if not candidates:
        return {"version": "", "score": None, "severity": "", "vector": ""}
    candidates.sort(key=lambda x: (x[0], x[2]["score"]), reverse=False)
    # Prefer the newest supported metric family, then highest score in that family.
    best_rank = min(x[0] for x in candidates)
    best = [x for x in candidates if x[0] == best_rank]
    best.sort(key=lambda x: x[2]["score"], reverse=True)
    _, key, data = best[0]
    version = key.replace("cvssMetricV", "v")
    return {"version": version, **data}


def extract_descriptions(cve: dict[str, Any]) -> list[str]:
    descriptions = cve.get("descriptions") or []
    return [str(item.get("value")) for item in descriptions if isinstance(item, dict) and item.get("lang") == "en" and item.get("value")]


def extract_cwes(cve: dict[str, Any]) -> list[str]:
    result: list[str] = []
    for item in cve.get("weaknesses") or []:
        for desc in item.get("description") or []:
            value = desc.get("value")
            if value and value not in result:
                result.append(value)
    return result


def extract_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    refs = []
    for item in cve.get("references") or []:
        if not isinstance(item, dict) or not item.get("url"):
            continue
        refs.append(
            {
                "url": item.get("url"),
                "source": item.get("source"),
                "tags": item.get("tags") or [],
            }
        )
    return refs


def analyze_configuration_complexity(cve: dict[str, Any]) -> dict[str, Any]:
    configs = cve.get("configurations") or []
    nodes = 0
    cpe_matches = 0
    operators: list[str] = []
    for config in configs:
        for node in config.get("nodes") or []:
            nodes += 1
            if node.get("operator"):
                operators.append(str(node["operator"]))
            cpe_matches += len(node.get("cpeMatch") or [])
            for child in node.get("children") or []:
                if child.get("operator"):
                    operators.append(str(child["operator"]))
                cpe_matches += len(child.get("cpeMatch") or [])
    return {
        "nodes": nodes,
        "cpe_matches": cpe_matches,
        "operators": sorted(set(operators)),
        "complexity": "complex" if nodes > 1 or len(set(operators)) > 1 or cpe_matches > 1 else "simple",
    }


# ---------------------------------------------------------------------------
# CVE applicability classification
# ---------------------------------------------------------------------------
_ENVIRONMENT_RULES = (
    ("windows", ("windows", "win32", "iis")),
    ("linux", ("linux", "ubuntu", "debian", "rhel", "red hat", "fedora", "centos", "alpine")),
    ("unix", ("unix", "freebsd", "openbsd", "solaris", "aix", "unix-like")),
    ("macos", ("macos", "mac os", "darwin")),
)

_MODULE_PATTERNS = (
    r"\bmod_[a-z0-9_]+\b",
    r"\b(?:soap|cgi|cgid|proxy|proxy_ajp|dav|ldap|md|auth_[a-z0-9_]+)\b",
    r"\bextension\b",
)

_CONFIG_KEYWORDS = (
    "configuration", "configured", "config", "htaccess", "allowencodedslashes",
    "mergeslashes", "allowoverride", "proxypass", "proxypassreverse",
    "serversideincludes", "server side includes", "enabled", "disabled",
    "directive", "option", "setting", "settings", "specific configuration",
)

_CONDITION_KEYWORDS = (
    "when ", "if ", "only when", "only if", "provided that", "provided",
    "requires ", "required ", "under certain conditions", "when configured",
    "if enabled", "if disabled", "with ... enabled", "with ... off", "with ... on",
)

_CONDITION_REGEXES = (
    re.compile(r"\bwith\s+[^.]{0,180}\b(?:enabled|disabled|on|off|configured)\b", re.I),
    re.compile(r"\b(?:when|if|only if|only when)\b[^.]{0,180}\b(?:enabled|disabled|configured|requires?|needed)\b", re.I),
)

_BACKEND_KEYWORDS = (
    "backend", "upstream", "malicious server", "malicious backend",
    "untrusted backend", "ajp server", "proxy target", "remote server",
)


def classify_cve_applicability(cve: dict[str, Any]) -> dict[str, Any]:
    """
    Heuristic triage only. It does not decide vulnerability applicability.

    Classification is based on NVD description/configuration text and is meant
    to help later checklist phases filter the raw candidate set.
    """
    descriptions = extract_descriptions(cve)
    text_blob = "\n".join(descriptions).lower()
    configurations_blob = json.dumps(cve.get("configurations") or {}, ensure_ascii=False).lower()
    combined = f"{text_blob}\n{configurations_blob}"

    environment_hits: list[str] = []
    for label, tokens in _ENVIRONMENT_RULES:
        if any(token in combined for token in tokens):
            environment_hits.append(label)

    module_hits: list[str] = []
    for pattern in _MODULE_PATTERNS:
        for match in re.findall(pattern, combined, re.I):
            value = str(match).lower()
            if value not in module_hits:
                module_hits.append(value)

    config_hits: list[str] = []
    for token in _CONFIG_KEYWORDS:
        if token in combined:
            config_hits.append(token)

    condition_hits: list[str] = []
    for token in _CONDITION_KEYWORDS:
        if token in text_blob:
            condition_hits.append(token.strip())
    for pattern in _CONDITION_REGEXES:
        for match in pattern.findall(text_blob):
            value = re.sub(r"\s+", " ", str(match)).strip()
            if value:
                condition_hits.append(value[:180])

    backend_hits: list[str] = []
    for token in _BACKEND_KEYWORDS:
        if token in combined:
            backend_hits.append(token)

    classifications: list[str] = []
    if backend_hits:
        classifications.append("backend-dependent")
    if environment_hits:
        classifications.append("environment-dependent")
    if module_hits or config_hits:
        classifications.append("module/config-dependent")
    if condition_hits:
        classifications.append("condition-dependent")
    if not classifications:
        classifications.append("version-match")

    # Primary category is deliberately conservative and only used for triage.
    # Labels are intentionally aligned with the project's review language.
    if backend_hits and (module_hits or config_hits):
        primary = "module/config/backend-dependent"
    elif environment_hits and (module_hits or config_hits):
        primary = "environment/config-dependent"
    elif condition_hits and (module_hits or config_hits):
        primary = "condition-dependent"
    elif backend_hits:
        primary = "backend-dependent"
    elif environment_hits:
        primary = "environment-dependent"
    elif module_hits or config_hits:
        primary = "module/config-dependent"
    elif condition_hits:
        primary = "condition-dependent"
    else:
        primary = "version-match"

    return {
        "primary": primary,
        "classifications": classifications,
        "indicators": {
            "environment": sorted(environment_hits),
            "modules_or_extensions": sorted(module_hits),
            "configuration": sorted(set(config_hits)),
            "conditions": sorted(set(condition_hits)),
            "backend": sorted(set(backend_hits)),
        },
        "method": "heuristic-NVD-description-and-configuration",
        "requires_analyst_validation": True,
        "note": "Classification membantu triage candidate; tidak membuktikan applicability atau exploitability.",
    }


def summarize_cve(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve") or {}
    cve_id = str(cve.get("id") or "")
    cvss = extract_cvss(cve)
    descriptions = extract_descriptions(cve)
    config = analyze_configuration_complexity(cve)
    kev_date = cve.get("cisaExploitAdd")
    return {
        "cve": cve_id,
        "vuln_status": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": descriptions[0] if descriptions else "",
        "cwe": extract_cwes(cve),
        "cvss": cvss,
        "known_exploited_vulnerability": bool(kev_date),
        "kev_date_added": kev_date,
        "references": extract_references(cve),
        "applicability": {
            **config,
            "classification": classify_cve_applicability(cve),
        },
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
        "correlation_basis": "NVD cpeName + isVulnerable match",
        "requires_validation": True,
        "finding": False,
    }


def request_nvd_json(
    params: dict[str, Any],
    nvd_api_key: str | None,
    timeout: int = 30,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    headers = {
        "User-Agent": REQUEST_USER_AGENT,
        "Accept": "application/json",
    }
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return None, {"ok": False, "status_code": None, "error": str(exc), "url": ""}

    meta = {
        "ok": response.ok,
        "status_code": response.status_code,
        "error": "" if response.ok else response.text[:1000],
        "url": response.url,
        "retrieved_at": now_iso(),
    }
    if not response.ok:
        return None, meta
    try:
        return response.json(), meta
    except ValueError as exc:
        meta["ok"] = False
        meta["error"] = f"Invalid JSON: {exc}"
        return None, meta


def correlate_cve_for_product(
    observation: dict[str, Any],
    nvd_api_key: str | None,
    max_results: int,
    public_delay: float,
    reuse_cache: dict[str, Any] | None = None,
) -> dict[str, Any]:
    vendor = str(observation.get("cpe_vendor") or "")
    product = str(observation.get("cpe_product") or "")
    version = str(observation.get("version") or "")
    cpe = build_cpe(vendor, product, version) if vendor and product and version else ""

    result: dict[str, Any] = {
        "product": observation.get("product"),
        "version": version,
        "source": observation.get("source"),
        "cpe": cpe,
        "cpe_resolved": bool(cpe),
        "status": "not-correlated",
        "query": {},
        "total_results": 0,
        "returned_results": 0,
        "cves": [],
        "notes": [],
    }

    if not cpe:
        result["status"] = "cpe-unresolved"
        result["notes"].append("Tidak ada mapping CPE tepercaya untuk produk yang terdeteksi.")
        return result

    cache_key = cpe
    if reuse_cache and cache_key in reuse_cache:
        cached = reuse_cache[cache_key]
        result.update(cached)
        result["notes"] = list(result.get("notes") or [])
        result["notes"].append("Hasil CVE correlation direuse dari evidence cache sebelumnya.")
        return result

    params: dict[str, Any] = {
        "cpeName": cpe,
        "isVulnerable": "",
        "noRejected": "",
        "resultsPerPage": min(max_results, NVD_PAGE_SIZE),
        "startIndex": 0,
    }
    data, meta = request_nvd_json(params, nvd_api_key)
    result["query"] = {
        "api": NVD_API_URL,
        "parameters": params,
        "metadata": meta,
    }
    if data is None:
        result["status"] = "query-error"
        result["notes"].append("NVD query gagal; hasil correlation tidak dapat dipakai sebagai vulnerability finding.")
        return result

    total = int(data.get("totalResults") or 0)
    vulnerabilities = data.get("vulnerabilities") or []
    if len(vulnerabilities) > max_results:
        vulnerabilities = vulnerabilities[:max_results]
        result["notes"].append(f"Hasil dibatasi menjadi {max_results} CVE untuk evidence.")
    result["total_results"] = total
    result["returned_results"] = len(vulnerabilities)
    result["cves"] = [summarize_cve(item) for item in vulnerabilities]
    result["status"] = "version-match-review" if total > 0 else "no-cve-correlated"
    if total > len(vulnerabilities):
        result["notes"].append("Tidak semua hasil NVD disimpan; NVD pagination tersedia.")

    if not nvd_api_key:
        result["notes"].append("Tanpa NVD API key; request rate dibatasi untuk menjaga penggunaan API tetap moderat.")
        if public_delay > 0:
            time.sleep(public_delay)
    return result


def build_unique_disclosed_versions(version_disclosures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Build unique logical product/version identities from raw disclosure
    observations.

    HTTP/HTTPS, URL, header name, and collection source are observation
    dimensions and are intentionally excluded from the identity key.

    Preferred identity:
        resolved CPE vendor + CPE product + version

    Fallback identity:
        normalized product_key + version

    This means the same Apache 2.4.65 observed over HTTP and HTTPS becomes
    one unique disclosed version while retaining all observation metadata.
    """
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}

    for obs in version_disclosures:
        version = str(obs.get("version") or "").strip()
        if not version:
            continue

        cpe_vendor = str(obs.get("cpe_vendor") or "").strip()
        cpe_product = str(obs.get("cpe_product") or "").strip()
        product_key = str(obs.get("product_key") or "").strip()
        product = str(obs.get("product") or "").strip()

        if cpe_vendor and cpe_product:
            identity = (
                "cpe",
                cpe_vendor.lower(),
                f"{cpe_product.lower()}:{version.lower()}",
            )
        elif product_key:
            identity = ("product", product_key.lower(), version.lower())
        else:
            identity = ("product", product.lower(), version.lower())

        if identity not in unique:
            unique[identity] = {
                "product": product,
                "version": version,
                "product_key": product_key,
                "cpe_vendor": cpe_vendor,
                "cpe_product": cpe_product,
                "cpe": build_cpe(cpe_vendor, cpe_product, version)
                if cpe_vendor and cpe_product
                else "",
                "cpe_resolved": bool(cpe_vendor and cpe_product),
                "observation_count": 0,
                "headers": [],
                "schemes": [],
                "urls": [],
                "sources": [],
            }

        item = unique[identity]
        item["observation_count"] += 1

        header = str(obs.get("header") or "").strip()
        if header and header.lower() not in {
            str(x).lower() for x in item["headers"]
        }:
            item["headers"].append(header)

        url = str(obs.get("url") or "").strip()
        if url:
            if url not in item["urls"]:
                item["urls"].append(url)

            scheme = urlsplit(url).scheme.lower()
            if scheme and scheme not in item["schemes"]:
                item["schemes"].append(scheme)

        source_values = obs.get("sources") or [obs.get("source")]
        for source in source_values:
            source_value = str(source or "").strip()
            if source_value and source_value not in item["sources"]:
                item["sources"].append(source_value)

    result = list(unique.values())
    result.sort(
        key=lambda x: (
            str(x.get("product") or "").lower(),
            str(x.get("version") or "").lower(),
        )
    )
    return result


# ---------------------------------------------------------------------------
# Artifact generation
# ---------------------------------------------------------------------------
def initial_artifact(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": context["project_id"],
        "updated_at": now_iso(),
        "webserver_version": {
            "status": "initialized",
            "checklist": {
                "id": CHECKLIST_ID,
                "name": CHECKLIST_NAME,
                "focus": "Public disclosure of web server and technology versions",
            },
            "application": context["application"],
            "hostname": context["hostname"],
            "environment": context["environment"],
            "assessment_type": context["assessment_type"],
            "target_url": context["target_url"],
            "authorized_ports": context["authorized_ports"],
            "scope_reference": context["scope_reference"],
            "method": "controlled HTTP/HTTPS GET + curl corroboration + service baseline + optional NVD CVE correlation",
            "baseline": {
                "network": context["network_source"],
                "service": context["service_source"],
                "scope": context["scope_source"],
            },
            "toolchain": {},
            "probe": {"targets": [], "started_at": None, "completed_at": None},
            "disclosures": [],
            "service_correlation": [],
            "cve_correlation": {
                "source": "NVD CVE API 2.0",
                "api": NVD_API_URL,
                "status": "not-run",
                "products": [],
            },
            "assessment": {
                "result": "not-analyzed",
                "requires_review": False,
                "disclosure_observations": 0,
                "disclosed_versions": 0,
                "disclosed_version_details": [],
                "cve_candidates": 0,
                "issues": [],
            },
            "evidence": {},
            "errors": [],
            "notes": [
                "Version disclosure is evidence; it is not an automatic vulnerability finding.",
                "CVE correlation uses NVD CPE applicability and is review evidence only.",
                "A version match does not establish exploitability or applicability of all CVE preconditions.",
                "CVE applicability classification is heuristic triage evidence; later checklist phases may filter candidates using additional target evidence.",
                "disclosed_versions counts unique product/version identities across HTTP/HTTPS observations; disclosure_observations counts raw disclosure observations.",
                "TLS protocol/cipher and certificate validation remain in 3-008/3-009/3-010.",
            ],
            "generated_at": now_iso(),
        },
    }


def detect_toolchain() -> dict[str, Any]:
    curl = find_executable(
        "curl.exe",
        (
            r"C:\Windows\System32\curl.exe",
            r"C:\WINDOWS\system32\curl.exe",
        ),
    )
    curl_ok, curl_version = run_version_command(curl, ["--version"])
    return {
        "python": {"available": True, "version": sys.version.splitlines()[0]},
        "requests": {"available": True, "version": requests.__version__},
        "curl": {"available": bool(curl), "path": curl or "", "version": curl_version.splitlines()[0] if curl_ok and curl_version else ""},
        "nvd": {"available": True, "api": NVD_API_URL},
    }


def analyze_project(repo_root: Path, project_id: str, no_cve: bool, max_cves: int, reuse_cve: bool) -> dict[str, Any]:
    context = load_context(repo_root, project_id)
    root = artifact_root(repo_root, project_id)
    evidence = evidence_root(repo_root, project_id)
    evidence.mkdir(parents=True, exist_ok=True)

    started = now_iso()
    targets = get_target_urls(context)
    all_probes: list[dict[str, Any]] = []
    all_disclosures: list[dict[str, Any]] = []
    curl_results: list[dict[str, Any]] = []
    errors: list[str] = []

    curl_path = detect_toolchain()["curl"]["path"] or None
    if not curl_path:
        errors.append("curl.exe tidak ditemukan; independent corroboration tidak tersedia.")

    for url in targets:
        probe = probe_with_requests(url)
        all_probes.append(probe)
        if probe.get("error"):
            errors.append(f"{url}: {probe['error']}")
        if probe.get("headers"):
            all_disclosures.extend(extract_version_observations(probe["headers"], "python-requests", url))
        curl_result = probe_with_curl(curl_path, url)
        curl_results.append(curl_result)
        if curl_result.get("headers"):
            all_disclosures.extend(extract_version_observations(curl_result["headers"], "curl.exe", url))
        if curl_result.get("error") and curl_result.get("available"):
            errors.append(f"{url} curl: {curl_result['error']}")

    # De-duplicate equivalent disclosure observations while preserving source set.
    dedup: dict[tuple[Any, ...], dict[str, Any]] = {}
    for obs in all_disclosures:
        key = (
            obs.get("header"),
            obs.get("value"),
            obs.get("product"),
            obs.get("version"),
            obs.get("url"),
        )
        if key not in dedup:
            obs = dict(obs)
            obs["sources"] = [obs.get("source")]
            dedup[key] = obs
        else:
            src = obs.get("source")
            if src and src not in dedup[key]["sources"]:
                dedup[key]["sources"].append(src)

    disclosure_list = list(dedup.values())
    version_disclosures = [x for x in disclosure_list if x.get("version_disclosed")]

    baseline = correlate_service_baseline(version_disclosures, context["baseline_services"])

    nvd_cache: dict[str, Any] | None = None
    if reuse_cve:
        previous = artifact_file(repo_root, project_id)
        if previous.exists():
            try:
                previous_data = load_yaml(previous)
                previous_products = previous_data.get("webserver_version", {}).get("cve_correlation", {}).get("products", [])
                nvd_cache = {item.get("cpe"): item for item in previous_products if item.get("cpe")}
            except Exception:
                nvd_cache = None

    cve_products: list[dict[str, Any]] = []
    nvd_api_key = os.getenv("NVD_API_KEY", "").strip() or None
    unique_products: dict[tuple[str, str, str], dict[str, Any]] = {}
    for obs in version_disclosures:
        key = (
            str(obs.get("cpe_vendor") or ""),
            str(obs.get("cpe_product") or ""),
            str(obs.get("version") or ""),
        )
        if key[0] and key[1] and key[2]:
            unique_products[key] = obs

    if no_cve:
        cve_status = "skipped-by-option"
    elif unique_products:
        cve_status = "completed"
        for index, obs in enumerate(unique_products.values()):
            if index > 0 and not nvd_api_key and not reuse_cve:
                time.sleep(NVD_PUBLIC_DELAY_SECONDS)
            cve_products.append(
                correlate_cve_for_product(
                    obs,
                    nvd_api_key=nvd_api_key,
                    max_results=max_cves,
                    public_delay=0,
                    reuse_cache=nvd_cache,
                )
            )
    else:
        cve_status = "no-version-cpe-candidate"

    cve_candidates = sum(int(item.get("total_results") or 0) for item in cve_products)

    disclosure_observation_count = len(version_disclosures)
    unique_disclosures = build_unique_disclosed_versions(version_disclosures)
    disclosed_count = len(unique_disclosures)

    result = (
        "version-disclosed"
        if disclosure_observation_count
        else ("no-version-observed" if not errors else "probe-error")
    )
    requires_review = bool(disclosed_count or cve_candidates)
    issues: list[str] = []
    if disclosed_count:
        issues.append("Public HTTP response discloses product/version information.")
    if cve_candidates:
        issues.append("NVD returned CVE applicability matches for at least one disclosed product/version; applicability requires analyst validation.")
    if errors:
        issues.append("One or more probes/tools reported errors; review evidence completeness.")

    evidence_paths: dict[str, str] = {}
    for scheme in ("http", "https"):
        probe_entries = [x for x in all_probes if x["url"].startswith(f"{scheme}://")]
        path = evidence / f"{scheme}-headers.json"
        atomic_write_text(path, json.dumps(probe_entries, indent=2, ensure_ascii=False))
        evidence_paths[f"{scheme}_headers"] = str(path.relative_to(repo_root)).replace("\\", "/")
    curl_path_file = evidence / "curl-version.txt"
    curl_details = detect_toolchain()["curl"]
    atomic_write_text(curl_path_file, json.dumps({"toolchain": curl_details, "results": curl_results}, indent=2, ensure_ascii=False))
    evidence_paths["curl_version"] = str(curl_path_file.relative_to(repo_root)).replace("\\", "/")
    cve_path = evidence / "cve-correlation.json"
    cve_json = {
        "retrieved_at": now_iso(),
        "api": NVD_API_URL,
        "api_key_used": bool(nvd_api_key),
        "products": cve_products,
    }
    atomic_write_text(cve_path, json.dumps(cve_json, indent=2, ensure_ascii=False))
    evidence_paths["cve_correlation"] = str(cve_path.relative_to(repo_root)).replace("\\", "/")

    completed = now_iso()
    artifact = initial_artifact(context)
    ws = artifact["webserver_version"]
    ws["status"] = "completed"
    ws["toolchain"] = detect_toolchain()
    ws["probe"] = {
        "targets": targets,
        "started_at": started,
        "completed_at": completed,
        "request_count": len(all_probes),
        "expected_http_probe": 80 in context["authorized_ports"],
        "expected_https_probe": 443 in context["authorized_ports"],
    }
    ws["disclosures"] = disclosure_list
    ws["service_correlation"] = baseline
    ws["cve_correlation"] = {
        "source": "NVD CVE API 2.0",
        "api": NVD_API_URL,
        "status": cve_status,
        "api_key_used": bool(nvd_api_key),
        "products": cve_products,
        "candidate_count": cve_candidates,
    }
    ws["assessment"] = {
        "result": result,
        "requires_review": requires_review,
        "disclosure_observations": disclosure_observation_count,
        "disclosed_versions": disclosed_count,
        "disclosed_version_details": unique_disclosures,
        "cve_candidates": cve_candidates,
        "issues": issues,
        "finding": False,
        "note": "disclosed_versions is the unique product/version count across HTTP/HTTPS observations; disclosure_observations counts individual disclosure observations.",
    }
    ws["evidence"] = evidence_paths
    ws["errors"] = errors
    ws["generated_at"] = completed
    return artifact


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------
def print_version() -> None:
    print(f"{APP_NAME} v{APP_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Primary  : controlled HTTP/HTTPS GET header disclosure")
    print("Correlate: service.yaml baseline + NVD CVE API 2.0/CPE")
    print("Validate : curl.exe independent header corroboration")
    print("Baseline : 02-reconnaissance/network/network.yaml")
    print("Scope    : 01-preparation/scope/scope.yaml")
    print("Identity  : unique disclosure count uses product/version (or resolved CPE), independent of HTTP/HTTPS/source")
    print("Boundary : no exploitation; CVE match is review evidence only")


@app.command("version")
def version_cmd() -> None:
    print_version()


@app.command("init")
def init_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    context = load_context(repo_root, project_id)
    path = artifact_file(repo_root, project_id)
    if path.exists():
        print(f"[WARN] Artifact sudah ada: {path}")
        raise typer.Exit(code=0)
    atomic_write_text(path, dump_yaml(initial_artifact(context)))
    print("[PASS] Server version disclosure initialized.")
    print(f"PROJECT           : {project_id}")
    print(f"TARGET            : {context['hostname']}")
    print(f"CHECKLIST         : {CHECKLIST_ID}")
    print(f"FILE              : {path}")


@app.command("analyze")
def analyze_cmd(
    no_cve: bool = typer.Option(False, "--no-cve", help="Lewati CVE correlation NVD."),
    max_cves: int = typer.Option(100, "--max-cves", min=1, max=2000, help="Maksimum CVE yang disimpan per product/version."),
    reuse_cve: bool = typer.Option(False, "--reuse-cve-cache", help="Gunakan CVE correlation dari artifact sebelumnya bila CPE sama."),
) -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    print(f"[INFO] Version disclosure target: {project_id}")
    try:
        artifact = analyze_project(repo_root, project_id, no_cve=no_cve, max_cves=max_cves, reuse_cve=reuse_cve)
        path = artifact_file(repo_root, project_id)
        atomic_write_text(path, dump_yaml(artifact))
        ws = artifact["webserver_version"]
        print("[PASS] Server version disclosure analysis completed.")
        print(f"HOSTNAME                 : {ws['hostname']}")
        print(f"DISCLOSURE OBSERVATIONS : {ws['assessment'].get('disclosure_observations', 0)}")
        print(f"UNIQUE VERSIONS         : {ws['assessment']['disclosed_versions']}")
        print(f"4-001 RESULT             : {ws['assessment']['result']}")
        print(f"CVE CANDIDATES           : {ws['assessment']['cve_candidates']}")
        print(f"REQUIRES REVIEW          : {int(bool(ws['assessment']['requires_review']))}")
        print(f"CVE STATUS               : {ws['cve_correlation']['status']}")
        print(f"FILE                     : {path}")
        for key, value in ws["evidence"].items():
            print(f"{key.upper():24} : {repo_root / value}")
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        raise typer.Exit(code=1)


@app.command("show")
def show_cmd() -> None:
    repo_root = discover_repo_root()
    project_id = discover_project_id(repo_root)
    path = artifact_file(repo_root, project_id)
    if not path.exists():
        print(f"[ERROR] Artifact belum ada: {path}", file=sys.stderr)
        raise typer.Exit(code=1)
    print(f"PROJECT: {project_id}")
    print(f"FILE   : {path}")
    print()
    print(path.read_text(encoding="utf-8"), end="")


@app.command("verify")
def verify_cmd() -> None:
    try:
        repo_root = discover_repo_root()
        project_id = discover_project_id(repo_root)
        path = artifact_file(repo_root, project_id)
        data = load_yaml(path)
        ws = data.get("webserver_version", {})
        assessment = ws.get("assessment", {})
        errors: list[str] = []

        if data.get("schema_version") != SCHEMA_VERSION:
            errors.append(f"Schema tidak sesuai: {data.get('schema_version')}")
        if data.get("project_id") != project_id:
            errors.append("project_id tidak konsisten.")
        if ws.get("status") != "completed":
            errors.append(f"Status harus completed, sekarang {ws.get('status')!r}.")
        if ws.get("checklist", {}).get("id") != CHECKLIST_ID:
            errors.append("Checklist ID tidak sesuai.")
        if not ws.get("hostname"):
            errors.append("Hostname tidak tersedia.")
        authorized_ports = {int(p) for p in (ws.get("authorized_ports") or []) if str(p).isdigit()}
        targets = set(ws.get("probe", {}).get("targets") or [])
        if not authorized_ports:
            errors.append("authorized_ports kosong; scope/service baseline belum berhasil direuse.")
        if 80 in authorized_ports and not any(str(t).lower().startswith("http://") for t in targets):
            errors.append("Port 80 in-scope tetapi target HTTP tidak diprobe.")
        if 443 in authorized_ports and not any(str(t).lower().startswith("https://") for t in targets):
            errors.append("Port 443 in-scope tetapi target HTTPS tidak diprobe.")
        disclosure_observations = int(assessment.get("disclosure_observations") or 0)
        disclosed_versions = int(assessment.get("disclosed_versions") or 0)
        disclosed_details = assessment.get("disclosed_version_details") or []

        if disclosure_observations < disclosed_versions:
            errors.append("disclosure_observations tidak boleh lebih kecil dari disclosed_versions.")
        if disclosed_versions != len(disclosed_details):
            errors.append("disclosed_versions tidak sama dengan jumlah disclosed_version_details.")
        if assessment.get("result") == "version-disclosed" and disclosed_versions == 0:
            errors.append("Result/version disclosure count tidak konsisten.")

        if int(assessment.get("cve_candidates") or 0) > 0 and ws.get("cve_correlation", {}).get("status") == "no-cve-correlated":
            errors.append("CVE candidate count dan status correlation tidak konsisten.")
        if ws.get("errors") is None:
            errors.append("errors field tidak tersedia.")

        if errors:
            print("[FAIL] Server version disclosure tidak memenuhi validasi.")
            for err in errors:
                print(f"[FAIL] {err}")
            raise typer.Exit(code=1)

        print("[PASS] Server version disclosure memenuhi validasi.")
        print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
        print(f"[PASS] Status    : {ws.get('status')}")
        print(f"[PASS] Target    : {ws.get('hostname')}")
        print(f"[PASS] 4-001     : {assessment.get('result')}")
        print(f"[PASS] Observed  : {assessment.get('disclosure_observations', 0)} disclosure observation(s)")
        print(f"[PASS] Versions  : {assessment.get('disclosed_versions', 0)} unique product/version(s)")
        print(f"[PASS] CVE       : {assessment.get('cve_candidates', 0)} candidate(s)")
        print(f"[PASS] Review    : {int(bool(assessment.get('requires_review')))}")
        print(f"[PASS] HTTP/S   : {len(targets)} target probe(s)")
        print("[PASS] CVE Triage: candidate classification is heuristic evidence for later filtering; no automatic finding.")
        print("[PASS] Assessment: version disclosure/CVE correlation dicatat sebagai evidence; finding keamanan tidak dibuat otomatis.")
    except typer.Exit:
        raise
    except Exception as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
