#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Infrastructure - HTTPS Configuration

Version: 1.0.1

Checklist mapping:
    3-007 - HTTPS configuration

Purpose:
    Assess the behavior of the in-scope HTTPS service without repeating the
    reconnaissance port scan. The module records the initial HTTPS response
    before redirects, follows redirects for final-state evidence, and
    determines whether HTTPS serves content, remains within HTTPS, or
    downgrades to HTTP.

Design principles:
    - Reuse completed reconnaissance/network evidence and active scope.
    - Does NOT repeat TCP port scanning.
    - Uses controlled HTTPS GET requests only.
    - Preserves the initial HTTPS response before redirect following.
    - Certificate validation is intentionally disabled in this checklist;
      certificate validation belongs to checklist 3-010.
    - TLS protocol/cipher security is not assessed here; those belong to
      3-008 and 3-009.
    - Separates HTTPS configuration evidence from vulnerability conclusions.
    - Does not perform authentication testing, brute force, exploitation,
      destructive methods, or HTTP-method fuzzing.
    - HTTP headers are recorded selectively; Set-Cookie headers are retained as
      evidence, but cookie values are redacted in stored evidence.
    - Optional curl confirmation is used when curl.exe/curl is available.

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
    projects/<PROJECT-ID>/03-infrastructure/https/https.yaml
    projects/<PROJECT-ID>/03-infrastructure/https/evidence/https-config.json
    projects/<PROJECT-ID>/03-infrastructure/https/evidence/curl-https.txt
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
import warnings
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# Import bootstrap
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

# The repository contains other scripts with common module names. Remove this
# directory before importing third-party packages to avoid local-module
# shadowing when this script is executed directly.
for _entry in (str(SCRIPT_DIR),):
    while _entry in sys.path:
        sys.path.remove(_entry)

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

import requests
import yaml
from urllib3.exceptions import InsecureRequestWarning

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

warnings.simplefilter("ignore", InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "1.0.1"
SCHEMA_VERSION = "1.1"

CHECKLIST_ID = "3-007"
CHECKLIST_NAME = "HTTPS configuration"

PREPARATION_DIR = "01-preparation"
RECON_DIR = "02-reconnaissance"
INFRASTRUCTURE_DIR = "03-infrastructure"

SCOPE_DIR = "scope"
SCOPE_FILE = "scope.yaml"

NETWORK_DIR = "network"
NETWORK_FILE = "network.yaml"

HTTPS_DIR = "https"
HTTPS_FILE = "https.yaml"
EVIDENCE_DIR = "evidence"
HTTPS_EVIDENCE_FILE = "https-config.json"
CURL_EVIDENCE_FILE = "curl-https.txt"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
    "skipped",
    "failed",
    "blocked",
}

REQUEST_TIMEOUT = 15
MAX_BODY_BYTES = 262_144
USER_AGENT = f"BrebesKab-CSIRT-Tools/{SCRIPT_VERSION} HTTPS-Config"

OBSERVED_HEADERS = (
    "Date",
    "Server",
    "Location",
    "Set-Cookie",
    "Content-Type",
    "Content-Length",
    "Content-Encoding",
    "Transfer-Encoding",
    "Cache-Control",
    "Pragma",
    "Expires",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
)

SENSITIVE_HEADER_NAMES = {
    "cookie",
    "authorization",
    "proxy-authorization",
}


class HTTPSConfigurationError(RuntimeError):
    """Raised when HTTPS configuration assessment cannot continue safely."""


# ---------------------------------------------------------------------------
# Generic helpers
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


def https_dir() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / HTTPS_DIR


def https_file() -> Path:
    return https_dir() / HTTPS_FILE


def evidence_dir() -> Path:
    return https_dir() / EVIDENCE_DIR


def https_evidence_file() -> Path:
    return evidence_dir() / HTTPS_EVIDENCE_FILE


def curl_evidence_file() -> Path:
    return evidence_dir() / CURL_EVIDENCE_FILE


def save_yaml(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(
            document,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise HTTPSConfigurationError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise HTTPSConfigurationError(f"Gagal membaca {label}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise HTTPSConfigurationError(f"YAML {label} tidak valid: {exc}") from exc

    if not isinstance(data, dict):
        raise HTTPSConfigurationError(f"Format {label} harus berupa mapping/object.")

    return data


def save_json(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


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


def require_project_id(data: dict[str, Any], label: str) -> None:
    expected = project_root().name
    actual = str(data.get("project_id", "")).strip()
    if actual != expected:
        raise HTTPSConfigurationError(
            f"Project ID pada {label} tidak sesuai active project. "
            f"Expected: {expected}; Found: {actual or '-'}"
        )


def nested_payload(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise HTTPSConfigurationError(f"Field '{name}' pada dokumen tidak valid.")
    return value


# ---------------------------------------------------------------------------
# Source loading / normalization
# ---------------------------------------------------------------------------


def load_network() -> dict[str, Any]:
    data = load_yaml(network_file(), "network.yaml")
    require_project_id(data, "network.yaml")
    network = nested_payload(data, "network")

    if str(network.get("status", "")).strip().lower() != "completed":
        raise HTTPSConfigurationError(
            "Reconnaissance network belum completed. "
            "Jalankan network.py verify terlebih dahulu."
        )

    if not isinstance(network.get("ports"), list):
        raise HTTPSConfigurationError(
            "Field network.ports pada network.yaml harus berupa list."
        )

    return data


def load_scope() -> dict[str, Any]:
    data = load_yaml(scope_file(), "scope.yaml")
    require_project_id(data, "scope.yaml")
    scope = nested_payload(data, "scope")

    if not isinstance(scope.get("in_scope"), list):
        raise HTTPSConfigurationError(
            "Field scope.in_scope pada scope.yaml harus berupa list."
        )
    if not isinstance(scope.get("out_of_scope"), list):
        raise HTTPSConfigurationError(
            "Field scope.out_of_scope pada scope.yaml harus berupa list."
        )

    return data


def normalize_ports(value: Any) -> set[int]:
    if not isinstance(value, list):
        return set()

    result: set[int] = set()
    for raw in value:
        try:
            port = int(raw)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            result.add(port)
    return result


def authorized_ports(scope_data: dict[str, Any]) -> set[int]:
    scope = nested_payload(scope_data, "scope")
    ports: set[int] = set()

    for item in scope.get("in_scope", []):
        if not isinstance(item, dict):
            continue
        ports.update(normalize_ports(item.get("ports")))

    return ports


def target_metadata(network_data: dict[str, Any]) -> dict[str, Any]:
    network = nested_payload(network_data, "network")

    hostname = str(network.get("hostname", "")).strip().rstrip(".")
    target_url = str(network.get("target_url", "")).strip()
    application = str(network.get("application", "")).strip()
    environment = str(network.get("environment", "")).strip()
    assessment_type = str(network.get("assessment_type", "")).strip()
    scope_reference = str(network.get("scope_reference", "")).strip()

    ipv4 = network.get("ipv4") or []
    if not isinstance(ipv4, list):
        ipv4 = []
    ipv4 = [str(value).strip() for value in ipv4 if str(value).strip()]

    if not hostname:
        raise HTTPSConfigurationError("network.yaml tidak memiliki hostname target.")

    return {
        "application": application,
        "target_url": target_url,
        "hostname": hostname,
        "ipv4": ipv4,
        "environment": environment,
        "assessment_type": assessment_type,
        "scope_reference": scope_reference,
    }


def build_https_url(hostname: str) -> str:
    return f"https://{hostname}/"


# ---------------------------------------------------------------------------
# HTTPS probing
# ---------------------------------------------------------------------------


def redacted_set_cookie_headers(response: requests.Response) -> str:
    """Return Set-Cookie evidence with cookie values redacted."""
    values: list[str] = []

    try:
        raw_headers = getattr(response.raw, "headers", None)
        getlist = getattr(raw_headers, "getlist", None)
        if callable(getlist):
            values.extend(str(item) for item in getlist("Set-Cookie"))
    except Exception:
        values = []

    if not values:
        value = response.headers.get("Set-Cookie")
        if value:
            values = [str(value)]

    redacted: list[str] = []
    for value in values:
        first, sep, rest = value.partition(";")
        if "=" in first:
            name, _cookie_value = first.split("=", 1)
            first = f"{name}=[REDACTED]"
        if sep:
            redacted.append(first + ";" + rest)
        else:
            redacted.append(first)

    return " | ".join(redacted)[:2000]


def response_headers(response: requests.Response) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name in OBSERVED_HEADERS:
        lower_name = name.lower()
        if lower_name in SENSITIVE_HEADER_NAMES:
            continue

        if lower_name == "set-cookie":
            cookie_evidence = redacted_set_cookie_headers(response)
            if cookie_evidence:
                result["Set-Cookie"] = cookie_evidence
            continue

        value = response.headers.get(name)
        if value:
            result[name] = str(value)[:1000]
    return result


def body_metadata(response: requests.Response) -> dict[str, Any]:
    try:
        decoded_content = response.content
    except requests.RequestException:
        decoded_content = b""

    sample = decoded_content[:MAX_BODY_BYTES]
    text_sample = sample.decode("utf-8", errors="replace")
    title = ""
    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        text_sample,
        re.IGNORECASE | re.DOTALL,
    )
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()[:500]

    decoded_bytes = len(decoded_content)
    sample_bytes = len(sample)

    return {
        "body_sha256": hashlib.sha256(decoded_content).hexdigest()
        if decoded_content
        else "",
        "body_sample_sha256": hashlib.sha256(sample).hexdigest() if sample else "",
        "decoded_body_bytes": decoded_bytes,
        "body_sample_bytes": sample_bytes,
        "body_sample_truncated": decoded_bytes > MAX_BODY_BYTES,
        "title": title,
    }


def redirect_chain(response: requests.Response) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    for item in response.history:
        chain.append(
            {
                "url": str(item.url),
                "status_code": int(item.status_code),
                "location": str(item.headers.get("Location", "")),
            }
        )
    return chain


def request_once(
    url: str,
    *,
    allow_redirects: bool,
) -> dict[str, Any]:
    started = dt.datetime.now().astimezone()
    result: dict[str, Any] = {
        "url": url,
        "method": "GET",
        "allow_redirects": allow_redirects,
        "certificate_verification": "disabled; deferred to 3-010",
        "started_at": started.isoformat(timespec="seconds"),
        "status_code": None,
        "final_url": "",
        "redirect_chain": [],
        "headers": {},
        "content_length_header": None,
        "content_encoding": "",
        "transfer_encoding": "",
        "content_type": "",
        "title": "",
        "body_sha256": "",
        "body_sample_sha256": "",
        "decoded_body_bytes": 0,
        "body_sample_bytes": 0,
        "body_sample_truncated": False,
        "response_time_ms": None,
        "error": "",
        "tool": "python-requests",
    }

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=allow_redirects,
            verify=False,
            headers={"User-Agent": USER_AGENT},
        )

        elapsed = (dt.datetime.now().astimezone() - started).total_seconds() * 1000
        result["response_time_ms"] = round(elapsed, 2)
        result["status_code"] = int(response.status_code)
        result["final_url"] = str(response.url)
        result["redirect_chain"] = redirect_chain(response)
        result["headers"] = response_headers(response)
        result["content_length_header"] = response.headers.get("Content-Length")
        result["content_encoding"] = str(response.headers.get("Content-Encoding", ""))
        result["transfer_encoding"] = str(response.headers.get("Transfer-Encoding", ""))
        result["content_type"] = str(response.headers.get("Content-Type", ""))

        body = body_metadata(response)
        result.update(body)

    except requests.RequestException as exc:
        elapsed = (dt.datetime.now().astimezone() - started).total_seconds() * 1000
        result["response_time_ms"] = round(elapsed, 2)
        result["error"] = f"{type(exc).__name__}: {exc}"

    result["completed_at"] = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    return result


def redact_curl_headers(text: str) -> str:
    """Retain useful headers while redacting sensitive cookie values."""
    output: list[str] = []
    for line in text.splitlines():
        if re.match(r"^Set-Cookie:\s*", line, re.IGNORECASE):
            prefix, _, value = line.partition(":")
            first, sep, rest = value.strip().partition(";")
            if "=" in first:
                cookie_name, _cookie_value = first.split("=", 1)
                first = f"{cookie_name}=[REDACTED]"
            sanitized = first + ((";" + rest) if sep else "")
            output.append(f"{prefix}: {sanitized}")
        elif re.match(
            r"^(Cookie|Authorization|Proxy-Authorization):\s*",
            line,
            re.IGNORECASE,
        ):
            name = line.split(":", 1)[0]
            output.append(f"{name}: [REDACTED]")
        else:
            output.append(line)
    return "\n".join(output) + ("\n" if text.endswith("\n") else "")


def run_curl(url: str) -> dict[str, Any]:
    executable = shutil.which("curl.exe") or shutil.which("curl")
    result: dict[str, Any] = {
        "available": bool(executable),
        "executable": executable or "",
        "url": url,
        "certificate_verification": "disabled with -k; deferred to 3-010",
        "command": [],
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "status_code": None,
        "location": "",
        "error": "",
    }

    if not executable:
        result["error"] = "curl executable not found; optional confirmation skipped."
        return result

    command = [
        executable,
        "-k",
        "-sS",
        "-D",
        "-",
        "-o",
        "NUL" if sys.platform.startswith("win") else "/dev/null",
        "--max-redirs",
        "0",
        "--connect-timeout",
        str(REQUEST_TIMEOUT),
        "--max-time",
        str(REQUEST_TIMEOUT),
        "-A",
        USER_AGENT,
        url,
    ]

    result["command"] = command

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=REQUEST_TIMEOUT + 5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    result["returncode"] = completed.returncode
    result["stdout"] = redact_curl_headers(completed.stdout)
    result["stderr"] = redact_curl_headers(completed.stderr)

    header_text = result["stdout"]
    status_match = re.search(r"HTTP/\S+\s+(\d{3})", header_text)
    if status_match:
        result["status_code"] = int(status_match.group(1))

    location_match = re.search(
        r"^Location:\s*(.+?)\s*$",
        header_text,
        re.IGNORECASE | re.MULTILINE,
    )
    if location_match:
        result["location"] = location_match.group(1).strip()

    return result


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


def initial_location(result: dict[str, Any]) -> str:
    headers = result.get("headers")
    if isinstance(headers, dict):
        return str(headers.get("Location", ""))
    return ""


def same_hostname(url: str, hostname: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return (parsed.hostname or "").lower() == hostname.lower()


def classify_https(
    initial: dict[str, Any],
    followed: dict[str, Any],
    hostname: str,
) -> dict[str, Any]:
    initial_status = initial.get("status_code")
    location = initial_location(initial)
    final_url = followed.get("final_url") or initial.get("final_url", "")
    final_scheme = urlparse(final_url).scheme.lower() if final_url else ""

    if initial.get("error"):
        result = "probe-error"
        rationale = (
            "HTTPS initial request failed; HTTPS configuration could not be fully assessed."
        )
        requires_review = True
    elif isinstance(initial_status, int) and 200 <= initial_status < 300:
        result = "content-served-over-https"
        rationale = (
            "Initial HTTPS response returned a successful 2xx status, indicating "
            "content or an HTTPS response is served directly over HTTPS."
        )
        requires_review = False
    elif isinstance(initial_status, int) and 300 <= initial_status < 400:
        if final_scheme == "https":
            result = "redirects-within-https"
            rationale = (
                "Initial HTTPS response redirects, and the followed final URL remains HTTPS."
            )
            requires_review = False
        elif final_scheme == "http" and same_hostname(final_url, hostname):
            result = "redirects-to-http"
            rationale = (
                "Initial HTTPS response redirects to HTTP on the same host, indicating "
                "a transport downgrade in the observed redirect flow."
            )
            requires_review = True
        else:
            result = "https-redirect-observed"
            rationale = (
                "Initial HTTPS response returned a redirect; the final destination is "
                "retained as evidence for review."
            )
            requires_review = True
    else:
        result = "https-response-non-success"
        rationale = (
            "HTTPS responded without a successful 2xx response. The exact behavior is "
            "retained as evidence for review."
        )
        requires_review = True

    return {
        "https_available": not bool(initial.get("error")),
        "initial_status_code": initial_status,
        "initial_location": location,
        "redirects_within_https": bool(
            isinstance(initial_status, int)
            and 300 <= initial_status < 400
            and final_scheme == "https"
        ),
        "redirects_to_http": bool(
            isinstance(initial_status, int)
            and 300 <= initial_status < 400
            and final_scheme == "http"
        ),
        "served_over_https": bool(
            isinstance(initial_status, int) and 200 <= initial_status < 300
        ),
        "final_url": final_url,
        "result": result,
        "requires_review": requires_review,
        "rationale": rationale,
        "certificate_validation": "deferred to 3-010",
        "tls_assessment": "deferred to 3-008 and 3-009",
    }


# ---------------------------------------------------------------------------
# Document construction
# ---------------------------------------------------------------------------


def empty_document(
    network_data: dict[str, Any],
    scope_ports: set[int],
) -> dict[str, Any]:
    target = target_metadata(network_data)
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "https": {
            "status": "not-started",
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": target["application"],
            "target_url": target["target_url"],
            "hostname": target["hostname"],
            "ipv4": target["ipv4"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_reference": target["scope_reference"],
            "method": "controlled HTTPS GET with initial-response and final-response evidence",
            "authorized_ports": sorted(scope_ports),
            "sources": {
                "network": "02-reconnaissance/network/network.yaml",
                "scope": "01-preparation/scope/scope.yaml",
                "https_evidence": (
                    "03-infrastructure/https/evidence/https-config.json"
                ),
                "curl_evidence": (
                    "03-infrastructure/https/evidence/curl-https.txt"
                ),
            },
            "rules": {
                "initial_response": "Record HTTPS response before redirect following.",
                "content_over_https": "HTTPS initial response status in the 2xx range.",
                "redirect_within_https": "HTTPS 3xx followed by a final HTTPS URL.",
                "redirect_to_http": "HTTPS 3xx followed by an HTTP URL on the same host.",
                "certificate_validation": (
                    "Certificate validation is intentionally deferred to checklist 3-010."
                ),
                "tls_assessment": (
                    "TLS protocol and cipher assessment is handled by checklists 3-008 and 3-009."
                ),
                "vulnerability_rule": (
                    "HTTPS configuration is evidence; it is not automatically a vulnerability."
                ),
                "cookie_evidence": (
                    "Set-Cookie headers are retained as evidence with cookie values redacted."
                ),
                "body_size_semantics": (
                    "Content-Length is the response header value; decoded_body_bytes is the full decoded body size observed by the client; body_sample_bytes is the retained evidence sample size; body_sha256 hashes the full decoded body and body_sample_sha256 hashes the retained sample."
                ),
            },
            "https": {},
            "assessment": {},
            "curl": {},
            "summary": {
                "https_available": False,
                "initial_status_code": None,
                "redirects_within_https": False,
                "redirects_to_http": False,
                "served_over_https": False,
                "final_url": "",
                "requires_review": 0,
                "errors": 0,
            },
            "notes": [
                "Certificate validation is handled by infrastructure checklist 3-010.",
                "TLS protocol and cipher assessment is handled by infrastructure checklists 3-008 and 3-009.",
                "Set-Cookie headers are retained as evidence with cookie values redacted; authorization and Cookie headers are excluded.",
                "Content-Length is preserved as the response header value; decoded body size and transfer/content encoding are reported separately to avoid ambiguity caused by chunking, content encoding, or client-side decompression.",
                "HTTPS probes disable certificate verification so HTTPS behavior can be captured independently of certificate validation; certificate validation is assessed separately in 3-010.",
            ],
            "generated_at": now_iso(),
        },
    }


def build_document(
    network_data: dict[str, Any],
    scope_ports: set[int],
    initial: dict[str, Any],
    followed: dict[str, Any],
    curl_result: dict[str, Any],
) -> dict[str, Any]:
    document = empty_document(network_data, scope_ports)
    target = target_metadata(network_data)
    assessment = classify_https(initial, followed, target["hostname"])
    https = document["https"]

    https["status"] = "in-progress"
    https["https"] = {
        "url": build_https_url(target["hostname"]),
        "initial_response": initial,
        "followed_response": followed,
    }
    https["assessment"] = assessment
    https["curl"] = curl_result
    https["summary"] = {
        "https_available": assessment["https_available"],
        "initial_status_code": assessment["initial_status_code"],
        "redirects_within_https": assessment["redirects_within_https"],
        "redirects_to_http": assessment["redirects_to_http"],
        "served_over_https": assessment["served_over_https"],
        "final_url": assessment["final_url"],
        "requires_review": int(bool(assessment["requires_review"])),
        "errors": int(bool(initial.get("error"))),
    }
    https["generated_at"] = now_iso()

    return document


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init() -> int:
    network_data = load_network()
    scope_data = load_scope()
    ports = authorized_ports(scope_data)
    target = target_metadata(network_data)

    if 443 not in ports:
        raise HTTPSConfigurationError(
            "Port 443 tidak tercantum pada active in-scope ports. "
            "3-007 tidak akan melakukan HTTPS request di luar scope."
        )

    document = empty_document(network_data, ports)
    save_yaml(https_file(), document)
    record("HTTPS configuration initialized", "in-progress")

    print("[PASS] HTTPS Configuration initialized.")
    print(f"PROJECT           : {project_root().name}")
    print(f"TARGET            : {target['hostname']}")
    print(f"AUTHORIZED PORTS  : {len(ports)}")
    print(f"HTTPS PORT 443    : {'authorized' if 443 in ports else 'not-authorized'}")
    print(f"FILE              : {https_file()}")
    return 0


def cmd_analyze() -> int:
    network_data = load_network()
    scope_data = load_scope()
    ports = authorized_ports(scope_data)
    target = target_metadata(network_data)

    if 443 not in ports:
        raise HTTPSConfigurationError(
            "Port 443 tidak tercantum pada active in-scope ports; HTTPS probe diblokir oleh scope."
        )

    https_url = build_https_url(target["hostname"])
    print(f"[INFO] HTTPS configuration probe: {https_url}")

    initial = request_once(
        https_url,
        allow_redirects=False,
    )

    followed = request_once(
        https_url,
        allow_redirects=True,
    )

    curl_result = run_curl(https_url)

    document = build_document(
        network_data,
        ports,
        initial,
        followed,
        curl_result,
    )

    save_json(
        https_evidence_file(),
        {
            "schema_version": SCHEMA_VERSION,
            "project_id": project_root().name,
            "generated_at": now_iso(),
            "method": "controlled GET; initial response captured before redirect following; certificate verification disabled",
            "https": initial,
            "followed": followed,
            "curl": curl_result,
        },
    )

    evidence_dir().mkdir(parents=True, exist_ok=True)
    curl_text = [
        f"URL: {curl_result.get('url', '')}",
        f"Executable: {curl_result.get('executable', '')}",
        f"Available: {curl_result.get('available', False)}",
        f"Certificate verification: {curl_result.get('certificate_verification', '')}",
        f"Return code: {curl_result.get('returncode')}",
        "",
        curl_result.get("stdout", ""),
    ]
    if curl_result.get("stderr"):
        curl_text.extend(["\n--- STDERR ---", curl_result["stderr"]])
    if curl_result.get("error"):
        curl_text.extend(["\n--- ERROR ---", curl_result["error"]])

    with curl_evidence_file().open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(curl_text).rstrip() + "\n")

    save_yaml(https_file(), document)
    record("HTTPS configuration analyzed", "in-progress")

    summary = document["https"]["summary"]
    print("[PASS] HTTPS Configuration analysis completed.")
    print(f"HOSTNAME                 : {target['hostname']}")
    print(f"HTTPS STATUS             : {summary['initial_status_code']}")
    print(f"HTTPS AVAILABLE          : {summary['https_available']}")
    print(f"REDIRECTS WITHIN HTTPS   : {summary['redirects_within_https']}")
    print(f"REDIRECTS TO HTTP        : {summary['redirects_to_http']}")
    print(f"CONTENT SERVED OVER HTTPS: {summary['served_over_https']}")
    print(f"FINAL URL                : {summary['final_url'] or '-'}")
    print(f"REQUIRES REVIEW          : {summary['requires_review']}")
    print(f"ERRORS                   : {summary['errors']}")
    print(f"CURL AVAILABLE           : {bool(curl_result.get('available'))}")
    print(f"FILE                     : {https_file()}")
    print(f"HTTPS EVIDENCE           : {https_evidence_file()}")
    print(f"CURL EVIDENCE            : {curl_evidence_file()}")
    return 0


def cmd_list() -> int:
    path = https_file()
    if not path.exists():
        print("[FAIL] HTTPS Configuration belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "https.yaml")
    require_project_id(data, "https.yaml")
    https = nested_payload(data, "https")
    assessment = https.get("assessment") or {}
    summary = https.get("summary") or {}

    print(f"PROJECT        : {data.get('project_id', '-')}")
    print(f"STATUS         : {https.get('status', '-')}")
    print(f"TARGET         : {https.get('hostname', '-')}")
    print(f"HTTPS STATUS   : {summary.get('initial_status_code', '-')}")
    print(f"HTTPS AVAILABLE: {summary.get('https_available', False)}")
    print(f"HTTPS→HTTPS    : {summary.get('redirects_within_https', False)}")
    print(f"HTTPS→HTTP     : {summary.get('redirects_to_http', False)}")
    print(f"HTTPS CONTENT  : {summary.get('served_over_https', False)}")
    print(f"ASSESSMENT     : {assessment.get('result', '-')}")
    print(f"REVIEW         : {summary.get('requires_review', 0)}")
    return 0


def cmd_show() -> int:
    path = https_file()
    if not path.exists():
        print("[FAIL] HTTPS Configuration belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "https.yaml")
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
    require_project_id(data, "https.yaml")

    https = nested_payload(data, "https")
    status = str(https.get("status", "")).strip().lower()
    if status not in VALID_STATUSES:
        errors.append(f"Status HTTPS Configuration tidak valid: {status or '-'}")

    for field in ("checklist_id", "checklist_name", "hostname", "method"):
        value = https.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"Field https.{field} kosong.")

    summary = https.get("summary")
    if not isinstance(summary, dict):
        errors.append("Field https.summary tidak valid.")
    else:
        if summary.get("errors", 0):
            errors.append("HTTPS configuration masih memiliki probe error.")

    evidence = https_evidence_file()
    if not evidence.exists():
        errors.append("Evidence HTTPS tidak ditemukan.")

    return errors


def cmd_verify() -> int:
    path = https_file()
    if not path.exists():
        print("[FAIL] HTTPS Configuration belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data: dict[str, Any] = {}
    try:
        data = load_yaml(path, "https.yaml")
        errors = validate_document(data)
    except HTTPSConfigurationError as exc:
        errors = [str(exc)]

    https = data.get("https") if isinstance(data, dict) else {}
    if not isinstance(https, dict):
        https = {}

    if str(https.get("status", "")).strip().lower() not in {"in-progress", "completed"}:
        errors.append(
            f"Status belum siap diverifikasi: {https.get('status', '-') or '-'}"
        )

    if errors:
        print("[FAIL] HTTPS Configuration verification gagal.")
        for error in errors:
            print(f"  - {error}")
        return 1

    if str(https.get("status", "")).strip().lower() == "in-progress":
        https["status"] = "completed"
        data["updated_at"] = now_iso()
        save_yaml(path, data)

    summary = https.get("summary") or {}
    assessment = https.get("assessment") or {}

    print("[PASS] HTTPS Configuration memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {https.get('status', '-')}")
    print(f"[PASS] Target    : {https.get('hostname', '-')}")
    print(f"[PASS] HTTPS     : {summary.get('initial_status_code', '-')}")
    print(f"[PASS] Available : {summary.get('https_available', False)}")
    print(f"[PASS] HTTPS→HTTPS: {summary.get('redirects_within_https', False)}")
    print(f"[PASS] HTTPS→HTTP : {summary.get('redirects_to_http', False)}")
    print(f"[PASS] Content   : {summary.get('served_over_https', False)}")
    print(f"[PASS] Result    : {assessment.get('result', '-')}")
    print(
        "[PASS] Assessment: HTTPS configuration dicatat sebagai evidence; "
        "certificate/TLS security dinilai pada checklist 3-008 s.d. 3-010."
    )

    record("HTTPS configuration verified", "completed")
    return 0


def cmd_status() -> int:
    path = https_file()
    if not path.exists():
        print("[INFO] HTTPS Configuration belum ada.")
        return 0

    data = load_yaml(path, "https.yaml")
    require_project_id(data, "https.yaml")
    https = nested_payload(data, "https")
    summary = https.get("summary") or {}

    print(f"PROJECT            : {data.get('project_id', '-')}")
    print(f"STATUS             : {https.get('status', '-')}")
    print(f"TARGET             : {https.get('hostname', '-')}")
    print(f"HTTPS STATUS       : {summary.get('initial_status_code', '-')}")
    print(f"HTTPS AVAILABLE    : {summary.get('https_available', False)}")
    print(f"HTTPS→HTTPS        : {summary.get('redirects_within_https', False)}")
    print(f"HTTPS→HTTP         : {summary.get('redirects_to_http', False)}")
    print(f"CONTENT HTTPS      : {summary.get('served_over_https', False)}")
    print(f"REQUIRES REVIEW    : {summary.get('requires_review', 0)}")
    print(f"ERRORS             : {summary.get('errors', 0)}")
    print(f"FILE               : {path}")
    return 0


def cmd_remove() -> int:
    path = https_dir()
    if not path.exists():
        print("[INFO] HTTPS Configuration belum ada.")
        return 0

    confirm = input(
        "Hapus seluruh data HTTPS Configuration untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(path)
    record("HTTPS configuration data removed", "completed")
    print("[PASS] HTTPS Configuration berhasil dihapus.")
    return 0


def cmd_version() -> int:
    print(f"BrebesKab-CSIRT-Tools https.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : Controlled HTTPS GET with pre-redirect response capture")
    print("Baseline : 02-reconnaissance/network/network.yaml")
    print("Scope    : 01-preparation/scope/scope.yaml")
    print("Tool     : Python requests; optional curl confirmation")
    print("Rule     : HTTPS 2xx = content-served-over-https; HTTPS 3xx final HTTPS = redirects-within-https; same-host final HTTP = redirects-to-http")
    print("Evidence : Certificate validation deferred to 3-010; Set-Cookie retained with values redacted; body size semantics are explicit")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Infrastructure HTTPS Configuration\n"
        "\n"
        "Checklist:\n"
        "  3-007 HTTPS configuration\n"
        "\n"
        "Usage:\n"
        "  python scripts/infrastructure/https.py init\n"
        "  python scripts/infrastructure/https.py analyze\n"
        "  python scripts/infrastructure/https.py list\n"
        "  python scripts/infrastructure/https.py show\n"
        "  python scripts/infrastructure/https.py verify\n"
        "  python scripts/infrastructure/https.py status\n"
        "  python scripts/infrastructure/https.py remove\n"
        "  python scripts/infrastructure/https.py version\n"
        "\n"
        "Design:\n"
        "  - Reuses completed network.yaml and scope.yaml.\n"
        "  - Captures the initial HTTPS response before redirect following.\n"
        "  - Records final URL and redirect chain as supporting evidence.\n"
        "  - Certificate validation is intentionally deferred to 3-010.\n"
        "  - TLS protocol and cipher security belong to 3-008 and 3-009.\n"
        "  - Does not perform authentication testing, brute force, exploitation,\n"
        "    destructive requests, or HTTP-method fuzzing.\n"
        "  - Optional curl confirmation is retained when available.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Infrastructure HTTPS Configuration - checklist 3-007",
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
        raise HTTPSConfigurationError(f"Command tidak dikenal: {args.command}")

    except HTTPSConfigurationError as exc:
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
