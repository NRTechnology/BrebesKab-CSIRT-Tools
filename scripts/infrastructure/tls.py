#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Infrastructure - TLS Protocol & Cipher Assessment

Version: 1.0.0
Schema: 1.0

Checklist mapping:
    3-008 - TLS protocol
    3-009 - TLS cipher

Purpose:
    Assess the TLS protocol versions and cipher suites accepted by the
    in-scope HTTPS service without repeating reconnaissance or service scans.

Design principles:
    - Reuse completed reconnaissance/network evidence and active scope.
    - Require TCP/443 to be both observed open and explicitly authorized.
    - Use Nmap ssl-enum-ciphers as the primary TLS enumeration engine.
    - Preserve raw Nmap XML as technical evidence.
    - Treat accepted protocol versions as positive observations.
    - A protocol that is not reported by ssl-enum-ciphers is recorded as
      "not-observed", not incorrectly asserted as "rejected".
    - Optional OpenSSL corroboration is used only when OpenSSL is available;
      it is not a mandatory dependency for the module.
    - Certificate validation, hostname verification, trust chain and expiry
      remain exclusively in checklist 3-010.
    - Do not perform authentication testing, brute force, exploitation,
      destructive methods, or unrelated port scanning.
    - Legacy/unknown cipher observations require review; they are not
      automatically converted into vulnerability findings.

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
    projects/<PROJECT-ID>/03-infrastructure/tls/tls.yaml
    projects/<PROJECT-ID>/03-infrastructure/tls/evidence/tls-enum-ciphers.xml
    projects/<PROJECT-ID>/03-infrastructure/tls/evidence/tls-enum-ciphers.stderr.txt
    projects/<PROJECT-ID>/03-infrastructure/tls/evidence/openssl-probes.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Import bootstrap
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

# Prevent local infrastructure modules such as http.py from shadowing
# standard-library/third-party modules when a script is executed directly.
for _entry in (str(SCRIPT_DIR),):
    while _entry in sys.path:
        sys.path.remove(_entry)

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

try:
    import yaml
except ImportError as exc:
    raise RuntimeError(
        "PyYAML tidak tersedia. Jalankan install-requirements.ps1 terlebih dahulu."
    ) from exc

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

SCRIPT_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"

CHECKLIST_PROTOCOL = "3-008"
CHECKLIST_PROTOCOL_NAME = "TLS protocol"
CHECKLIST_CIPHER = "3-009"
CHECKLIST_CIPHER_NAME = "TLS cipher"

PREPARATION_DIR = "01-preparation"
RECON_DIR = "02-reconnaissance"
INFRASTRUCTURE_DIR = "03-infrastructure"

SCOPE_DIR = "scope"
SCOPE_FILE = "scope.yaml"
NETWORK_DIR = "network"
NETWORK_FILE = "network.yaml"

TLS_DIR = "tls"
TLS_FILE = "tls.yaml"
EVIDENCE_DIR = "evidence"
NMAP_XML_FILE = "tls-enum-ciphers.xml"
NMAP_STDERR_FILE = "tls-enum-ciphers.stderr.txt"
OPENSSL_EVIDENCE_FILE = "openssl-probes.json"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
    "skipped",
    "failed",
    "blocked",
}

TARGET_PORT = 443
NMAP_EXECUTABLE = "nmap"
OPENSSL_EXECUTABLE = "openssl"
NMAP_TIMEOUT = 180
OPENSSL_TIMEOUT = 30

TLS_PROTOCOLS = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
LEGACY_PROTOCOLS = {"TLSv1.0", "TLSv1.1"}
MODERN_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}

# Cipher families/patterns that should trigger review rather than be treated as
# automatically vulnerable. This deliberately favors evidence preservation and
# human review over aggressive automated conclusions.
LEGACY_CIPHER_PATTERNS = (
    re.compile(r"(?:^|[_-])RC4(?:[_-]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[_-])3DES(?:[_-]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[_-])DES(?:[_-]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[_-])NULL(?:[_-]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[_-])EXPORT(?:[_-]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[_-])ANON(?:[_-]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[_-])MD5(?:[_-]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[_-])IDEA(?:[_-]|$)", re.IGNORECASE),
    re.compile(r"(?:^|[_-])SEED(?:[_-]|$)", re.IGNORECASE),
)

CIPHER_STRENGTH_PATTERNS = (
    re.compile(r"AES(?:256|_256)", re.IGNORECASE),
    re.compile(r"AES(?:128|_128)", re.IGNORECASE),
    re.compile(r"CHACHA20", re.IGNORECASE),
    re.compile(r"ARIA", re.IGNORECASE),
    re.compile(r"CAMELLIA", re.IGNORECASE),
    re.compile(r"CCM", re.IGNORECASE),
    re.compile(r"GCM", re.IGNORECASE),
    re.compile(r"POLY1305", re.IGNORECASE),
)

CIPHER_NAME_PATTERN = re.compile(
    r"^(?:"
    r"TLS_|"
    r"SSL_"
    r")?[A-Za-z0-9][A-Za-z0-9_\-]*$"
)

GENERIC_CIPHER_TABLE_KEYS = {
    "ciphers",
    "cipher",
    "preferred",
    "strength",
    "strength_bits",
    "kex",
    "authentication",
    "mac",
    "compression",
    "warnings",
}


class TLSError(RuntimeError):
    """Raised when TLS assessment cannot continue safely."""


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


def tls_dir() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / TLS_DIR


def tls_file() -> Path:
    return tls_dir() / TLS_FILE


def evidence_dir() -> Path:
    return tls_dir() / EVIDENCE_DIR


def nmap_xml_file() -> Path:
    return evidence_dir() / NMAP_XML_FILE


def nmap_stderr_file() -> Path:
    return evidence_dir() / NMAP_STDERR_FILE


def openssl_evidence_file() -> Path:
    return evidence_dir() / OPENSSL_EVIDENCE_FILE


def save_yaml(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump(
                document,
                handle,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except OSError as exc:
        raise TLSError(f"Gagal menulis YAML: {path}\n{exc}") from exc


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise TLSError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise TLSError(f"Gagal membaca {label}: {path}\n{exc}") from exc
    except yaml.YAMLError as exc:
        raise TLSError(f"YAML {label} tidak valid: {path}\n{exc}") from exc

    if not isinstance(data, dict):
        raise TLSError(f"Format {label} tidak valid: root harus mapping/object.")

    return data


def save_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise TLSError(f"Gagal menulis evidence: {path}\n{exc}") from exc


def save_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import json

        path.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise TLSError(f"Gagal menulis JSON: {path}\n{exc}") from exc


def record(action: str, status: str) -> None:
    if record_activity is None:
        return

    try:
        record_activity(
            phase="03-infrastructure",
            item=f"{CHECKLIST_PROTOCOL},{CHECKLIST_CIPHER}",
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
            item=f"{CHECKLIST_PROTOCOL},{CHECKLIST_CIPHER}",
            action=action,
            status=status,
        )
    except Exception:
        pass


def require_project_id(data: dict[str, Any], label: str) -> None:
    expected = project_root().name
    actual = str(data.get("project_id", "")).strip()
    if actual != expected:
        raise TLSError(
            f"Project ID pada {label} tidak sesuai active project. "
            f"Expected: {expected}; Found: {actual or '-'}"
        )


def nested_payload(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise TLSError(f"Field '{name}' pada dokumen tidak valid.")
    return value


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


def network_open_ports(network_data: dict[str, Any]) -> set[int]:
    network = nested_payload(network_data, "network")
    result: set[int] = set()
    for item in network.get("ports", []):
        if not isinstance(item, dict):
            continue
        try:
            if str(item.get("protocol", "tcp")).lower() != "tcp":
                continue
            if str(item.get("state", "")).lower() != "open":
                continue
            result.add(int(item.get("port")))
        except (TypeError, ValueError):
            continue
    return result


def load_network() -> dict[str, Any]:
    data = load_yaml(network_file(), "network.yaml")
    require_project_id(data, "network.yaml")
    network = nested_payload(data, "network")

    if str(network.get("status", "")).strip().lower() != "completed":
        raise TLSError(
            "Reconnaissance network belum completed. "
            "Jalankan network.py verify terlebih dahulu."
        )
    if not isinstance(network.get("ports"), list):
        raise TLSError("Field network.ports pada network.yaml harus berupa list.")

    return data


def load_scope() -> dict[str, Any]:
    data = load_yaml(scope_file(), "scope.yaml")
    require_project_id(data, "scope.yaml")
    scope = nested_payload(data, "scope")

    if not isinstance(scope.get("in_scope"), list):
        raise TLSError("Field scope.in_scope pada scope.yaml harus berupa list.")
    if not isinstance(scope.get("out_of_scope"), list):
        raise TLSError("Field scope.out_of_scope pada scope.yaml harus berupa list.")

    return data


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
        raise TLSError("network.yaml tidak memiliki hostname target.")

    return {
        "application": application,
        "target_url": target_url,
        "hostname": hostname,
        "ipv4": ipv4,
        "environment": environment,
        "assessment_type": assessment_type,
        "scope_reference": scope_reference,
    }


def require_authorized_https_target(
    network_data: dict[str, Any],
    scope_data: dict[str, Any],
) -> tuple[dict[str, Any], set[int]]:
    target = target_metadata(network_data)
    authorized = authorized_ports(scope_data)
    observed_open = network_open_ports(network_data)

    if TARGET_PORT not in authorized:
        raise TLSError(
            "Port 443 tidak tercantum pada active in-scope ports. "
            "TLS probe diblokir oleh scope."
        )

    if TARGET_PORT not in observed_open:
        raise TLSError(
            "Port 443 tidak tercatat open pada network.yaml. "
            "TLS probe tidak diizinkan tanpa baseline network yang sesuai."
        )

    return target, authorized


def empty_document(
    network_data: dict[str, Any],
    scope_ports: set[int],
) -> dict[str, Any]:
    target = target_metadata(network_data)

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "tls": {
            "status": "not-started",
            "checklists": [
                {
                    "id": CHECKLIST_PROTOCOL,
                    "name": CHECKLIST_PROTOCOL_NAME,
                    "focus": "Accepted TLS protocol versions",
                },
                {
                    "id": CHECKLIST_CIPHER,
                    "name": CHECKLIST_CIPHER_NAME,
                    "focus": "Accepted TLS cipher suites",
                },
            ],
            "hostname": target["hostname"],
            "application": target["application"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "target_port": TARGET_PORT,
            "target_scheme": "https",
            "scope_reference": target["scope_reference"],
            "scope_authorized_ports": sorted(scope_ports),
            "network_observed_open_ports": sorted(network_open_ports(network_data)),
            "method": "Nmap ssl-enum-ciphers primary; optional OpenSSL corroboration",
            "toolchain": {
                "nmap": {
                    "available": False,
                    "path": "",
                    "version": "",
                    "script": "ssl-enum-ciphers",
                },
                "openssl": {
                    "available": False,
                    "path": "",
                    "version": "",
                    "role": "optional corroboration",
                },
            },
            "probe": {
                "target": f"{target['hostname']}:{TARGET_PORT}",
                "started_at": "",
                "completed_at": "",
                "command": [],
                "returncode": None,
                "timed_out": False,
                "xml_sha256": "",
                "stderr_sha256": "",
            },
            "protocols": [
                {
                    "name": protocol,
                    "status": "not-observed",
                    "source": "ssl-enum-ciphers",
                    "evidence": "",
                }
                for protocol in TLS_PROTOCOLS
            ],
            "ciphers": [],
            "assessment": {
                "protocol": {
                    "result": "not-assessed",
                    "requires_review": False,
                    "accepted_legacy": [],
                    "accepted_modern": [],
                },
                "cipher": {
                    "result": "not-assessed",
                    "requires_review": False,
                    "legacy_observed": [],
                    "unknown_observed": [],
                    "modern_observed": [],
                },
                "overall_requires_review": False,
            },
            "openssl_corroboration": {
                "available": False,
                "status": "not-run",
                "protocols": [],
                "notes": "Optional; Nmap remains the primary evidence source.",
            },
            "evidence": {
                "nmap_xml": str(nmap_xml_file()),
                "nmap_stderr": str(nmap_stderr_file()),
                "openssl_json": str(openssl_evidence_file()),
            },
            "errors": [],
            "notes": [
                "Accepted protocols are positive observations from ssl-enum-ciphers.",
                "A protocol absent from Nmap enumeration is recorded as not-observed, not as an asserted rejection.",
                "Certificate validation is deferred to checklist 3-010.",
                "TLS protocol and cipher evidence are kept separate from vulnerability findings.",
            ],
            "generated_at": "",
        },
    }


# ---------------------------------------------------------------------------
# Executable discovery
# ---------------------------------------------------------------------------


def find_executable(name: str) -> str:
    path = shutil.which(name)
    return path or ""


def command_output_version(executable: str, args: list[str]) -> str:
    if not executable:
        return ""
    try:
        result = subprocess.run(
            [executable, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""

    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return lines[0] if lines else ""


def ensure_nmap() -> tuple[str, str]:
    executable = find_executable(NMAP_EXECUTABLE)
    if not executable:
        raise TLSError(
            "nmap.exe tidak ditemukan. Jalankan install-requirements.ps1 terlebih dahulu."
        )
    version = command_output_version(executable, ["--version"])
    return executable, version


def discover_openssl() -> tuple[str, str]:
    executable = find_executable(OPENSSL_EXECUTABLE)
    if not executable:
        return "", ""
    version = command_output_version(executable, ["version"])
    return executable, version


# ---------------------------------------------------------------------------
# Nmap probing
# ---------------------------------------------------------------------------


def run_nmap_tls_probe(hostname: str) -> dict[str, Any]:
    executable, version = ensure_nmap()

    command = [
        executable,
        "-Pn",
        "-p",
        str(TARGET_PORT),
        "--script",
        "ssl-enum-ciphers",
        "--script-args",
        f"tls.servername={hostname}",
        "--script-timeout",
        "90s",
        "--host-timeout",
        "120s",
        "-oX",
        "-",
        hostname,
    ]

    started = dt.datetime.now().astimezone()
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=NMAP_TIMEOUT,
            check=False,
        )
        timed_out = False
        returncode = result.returncode
        stdout = result.stdout or ""
        stderr = result.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
    except OSError as exc:
        raise TLSError(f"Gagal menjalankan Nmap: {exc}") from exc

    completed = dt.datetime.now().astimezone()

    if timed_out:
        raise TLSError(
            f"Nmap TLS probe timeout setelah {NMAP_TIMEOUT} detik. "
            f"Stderr: {stderr[:1000]}"
        )

    if not stdout.strip():
        raise TLSError(
            "Nmap tidak menghasilkan XML output. "
            f"Return code: {returncode}; stderr: {stderr[:1000]}"
        )

    try:
        ET.fromstring(stdout)
    except ET.ParseError as exc:
        raise TLSError(
            "Output Nmap bukan XML yang valid. "
            f"Return code: {returncode}; error: {exc}"
        ) from exc

    return {
        "executable": executable,
        "version": version,
        "command": command,
        "started_at": started.isoformat(timespec="seconds"),
        "completed_at": completed.isoformat(timespec="seconds"),
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
    }


def write_nmap_evidence(result: dict[str, Any]) -> tuple[str, str]:
    xml_text = result["stdout"]
    stderr_text = result.get("stderr", "")

    save_text(nmap_xml_file(), xml_text.rstrip() + "\n")
    save_text(
        nmap_stderr_file(),
        stderr_text.rstrip() + ("\n" if stderr_text.strip() else ""),
    )

    xml_hash = hashlib.sha256(xml_text.encode("utf-8")).hexdigest()
    stderr_hash = hashlib.sha256(stderr_text.encode("utf-8")).hexdigest()
    return xml_hash, stderr_hash


# ---------------------------------------------------------------------------
# Nmap XML parsing
# ---------------------------------------------------------------------------


def script_elements(root: ET.Element) -> list[ET.Element]:
    return [
        elem
        for elem in root.iter("script")
        if elem.get("id", "").strip().lower() == "ssl-enum-ciphers"
    ]


def looks_like_protocol(value: str) -> bool:
    return value in TLS_PROTOCOLS or value.upper() == "SSLV3"


def find_protocol_tables(script: ET.Element) -> dict[str, ET.Element]:
    result: dict[str, ET.Element] = {}
    for table in script.iter("table"):
        key = str(table.get("key", "")).strip()
        if looks_like_protocol(key):
            if key not in result:
                result[key] = table
    return result


def direct_or_nested_elem(table: ET.Element, key: str) -> str:
    wanted = key.lower()
    for elem in table.iter("elem"):
        elem_key = str(elem.get("key", "")).strip().lower()
        if elem_key == wanted:
            return (elem.text or "").strip()
    return ""


def parse_int(value: str) -> int | None:
    match = re.search(r"\d+", value or "")
    if not match:
        return None
    try:
        return int(match.group(0))
    except ValueError:
        return None


def classify_cipher(name: str, protocol: str, strength_bits: int | None) -> str:
    for pattern in LEGACY_CIPHER_PATTERNS:
        if pattern.search(name):
            return "legacy-review"

    if not name or not CIPHER_NAME_PATTERN.match(name):
        return "unknown"

    # TLS 1.3 AES-GCM/ChaCha20 suites and common AEAD families are treated as
    # modern observations. This remains an evidence classifier, not a finding.
    if any(pattern.search(name) for pattern in CIPHER_STRENGTH_PATTERNS):
        return "modern"

    if strength_bits is not None and strength_bits >= 128:
        return "modern"

    return "unknown"


def collect_cipher_tables(protocol_table: ET.Element, protocol: str) -> list[dict[str, Any]]:
    candidates: list[ET.Element] = []

    for table in protocol_table.iter("table"):
        key = str(table.get("key", "")).strip()
        if not key or key.lower() in GENERIC_CIPHER_TABLE_KEYS:
            continue
        if looks_like_protocol(key):
            continue
        if CIPHER_NAME_PATTERN.match(key):
            candidates.append(table)

    # De-duplicate by cipher name while keeping first evidence occurrence.
    found: dict[str, dict[str, Any]] = {}

    for table in candidates:
        name = str(table.get("key", "")).strip()
        if not name or name in found:
            continue

        strength_raw = (
            direct_or_nested_elem(table, "strength_bits")
            or direct_or_nested_elem(table, "strength")
        )
        strength_bits = parse_int(strength_raw)

        kex = direct_or_nested_elem(table, "kex")
        auth = direct_or_nested_elem(table, "authentication")
        mac = direct_or_nested_elem(table, "mac")

        found[name] = {
            "protocol": protocol,
            "name": name,
            "strength_bits": strength_bits,
            "kex": kex,
            "authentication": auth,
            "mac": mac,
            "classification": classify_cipher(name, protocol, strength_bits),
        }

    return list(found.values())


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise TLSError(f"Nmap XML tidak dapat diparse: {exc}") from exc

    scripts = script_elements(root)
    if not scripts:
        raise TLSError(
            "Nmap XML tidak mengandung script result ssl-enum-ciphers. "
            "Pastikan NSE script tersedia dan target port 443 dapat diprobe."
        )

    protocol_tables: dict[str, ET.Element] = {}
    for script in scripts:
        for name, table in find_protocol_tables(script).items():
            protocol_tables.setdefault(name, table)

    protocols: list[dict[str, Any]] = []
    for protocol in TLS_PROTOCOLS:
        if protocol in protocol_tables:
            protocols.append(
                {
                    "name": protocol,
                    "status": "accepted",
                    "source": "ssl-enum-ciphers",
                    "evidence": "protocol table observed",
                }
            )
        else:
            protocols.append(
                {
                    "name": protocol,
                    "status": "not-observed",
                    "source": "ssl-enum-ciphers",
                    "evidence": "protocol table not present in NSE output; not asserted as rejected",
                }
            )

    ciphers: list[dict[str, Any]] = []
    for protocol in TLS_PROTOCOLS:
        table = protocol_tables.get(protocol)
        if table is None:
            continue
        ciphers.extend(collect_cipher_tables(table, protocol))

    # A server offering SSLv3 is important evidence, even though 3-008 focuses
    # on TLS 1.0-1.3. Keep it in a separate field so it is not lost.
    sslv3_observed = "SSLv3" in protocol_tables or "SSLV3" in protocol_tables

    return {
        "protocols": protocols,
        "ciphers": ciphers,
        "sslv3_observed": sslv3_observed,
        "script_count": len(scripts),
    }


# ---------------------------------------------------------------------------
# Optional OpenSSL corroboration
# ---------------------------------------------------------------------------


def openssl_protocol_argument(protocol: str) -> str:
    return {
        "TLSv1.0": "-tls1",
        "TLSv1.1": "-tls1_1",
        "TLSv1.2": "-tls1_2",
        "TLSv1.3": "-tls1_3",
    }[protocol]


def run_openssl_probe(hostname: str, protocol: str) -> dict[str, Any]:
    executable, version = discover_openssl()
    if not executable:
        return {
            "protocol": protocol,
            "status": "not-run",
            "reason": "openssl.exe tidak tersedia",
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "negotiated_protocol": "",
            "version": "",
            "executable": "",
        }

    command = [
        executable,
        "s_client",
        "-connect",
        f"{hostname}:{TARGET_PORT}",
        "-servername",
        hostname,
        openssl_protocol_argument(protocol),
        "-brief",
        "-no_ticket",
    ]

    try:
        result = subprocess.run(
            command,
            input="",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=OPENSSL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "protocol": protocol,
            "status": "timeout",
            "reason": f"timeout {OPENSSL_TIMEOUT}s",
            "returncode": None,
            "stdout": str(exc.stdout or ""),
            "stderr": str(exc.stderr or ""),
            "negotiated_protocol": "",
            "version": version,
            "executable": executable,
        }
    except OSError as exc:
        return {
            "protocol": protocol,
            "status": "error",
            "reason": str(exc),
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "negotiated_protocol": "",
            "version": version,
            "executable": executable,
        }

    combined = "\n".join((result.stdout or "", result.stderr or ""))
    negotiated = ""
    match = re.search(r"Protocol version:\s*(TLSv\d(?:\.\d)?)", combined)
    if match:
        negotiated = match.group(1)

    status = "accepted" if result.returncode == 0 and negotiated else "rejected-or-error"

    return {
        "protocol": protocol,
        "status": status,
        "reason": "handshake succeeded" if status == "accepted" else "OpenSSL handshake did not complete",
        "returncode": result.returncode,
        "stdout": result.stdout or "",
        "stderr": result.stderr or "",
        "negotiated_protocol": negotiated,
        "version": version,
        "executable": executable,
    }


def run_optional_openssl(hostname: str) -> dict[str, Any]:
    executable, version = discover_openssl()
    if not executable:
        return {
            "available": False,
            "status": "not-run",
            "executable": "",
            "version": "",
            "protocols": [],
            "notes": "OpenSSL tidak tersedia; Nmap ssl-enum-ciphers menjadi evidence utama.",
        }

    results = [run_openssl_probe(hostname, protocol) for protocol in TLS_PROTOCOLS]
    return {
        "available": True,
        "status": "completed",
        "executable": executable,
        "version": version,
        "protocols": results,
        "notes": "OpenSSL digunakan sebagai corroboration opsional; tidak menggantikan evidence Nmap.",
    }


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


def assess_protocol(protocols: list[dict[str, Any]], sslv3_observed: bool) -> dict[str, Any]:
    accepted = {
        str(item.get("name")): str(item.get("status"))
        for item in protocols
        if isinstance(item, dict)
    }

    accepted_legacy = [
        protocol for protocol in TLS_PROTOCOLS
        if protocol in LEGACY_PROTOCOLS and accepted.get(protocol) == "accepted"
    ]
    accepted_modern = [
        protocol for protocol in TLS_PROTOCOLS
        if protocol in MODERN_PROTOCOLS and accepted.get(protocol) == "accepted"
    ]

    if accepted_legacy:
        result = "legacy-protocol-observed"
        requires_review = True
    elif accepted_modern:
        result = "modern-protocols-observed"
        requires_review = False
    else:
        result = "no-accepted-tls-protocol-observed"
        requires_review = True

    return {
        "result": result,
        "requires_review": requires_review,
        "accepted_legacy": accepted_legacy,
        "accepted_modern": accepted_modern,
        "sslv3_observed": sslv3_observed,
        "note": (
            "not-observed is not equivalent to cryptographic rejection; "
            "it reflects the Nmap enumeration evidence."
        ),
    }


def assess_cipher(ciphers: list[dict[str, Any]]) -> dict[str, Any]:
    legacy = sorted({str(item.get("name")) for item in ciphers if item.get("classification") == "legacy-review"})
    unknown = sorted({str(item.get("name")) for item in ciphers if item.get("classification") == "unknown"})
    modern = sorted({str(item.get("name")) for item in ciphers if item.get("classification") == "modern"})

    if legacy:
        result = "legacy-cipher-observed"
        requires_review = True
    elif unknown:
        result = "unknown-cipher-observed"
        requires_review = True
    elif modern:
        result = "no-legacy-observed"
        requires_review = False
    else:
        result = "no-cipher-observed"
        requires_review = True

    return {
        "result": result,
        "requires_review": requires_review,
        "legacy_observed": legacy,
        "unknown_observed": unknown,
        "modern_observed": modern,
    }


def build_document(
    network_data: dict[str, Any],
    scope_ports: set[int],
    nmap_result: dict[str, Any],
    openssl_result: dict[str, Any],
) -> dict[str, Any]:
    parsed = parse_nmap_xml(nmap_result["stdout"])
    protocol_assessment = assess_protocol(
        parsed["protocols"],
        parsed["sslv3_observed"],
    )
    cipher_assessment = assess_cipher(parsed["ciphers"])
    overall_review = bool(
        protocol_assessment["requires_review"]
        or cipher_assessment["requires_review"]
        or parsed["sslv3_observed"]
    )

    document = empty_document(network_data, scope_ports)
    tls = document["tls"]

    xml_hash, stderr_hash = write_nmap_evidence(nmap_result)

    tls["status"] = "completed"
    tls["toolchain"] = {
        "nmap": {
            "available": True,
            "path": nmap_result["executable"],
            "version": nmap_result["version"],
            "script": "ssl-enum-ciphers",
        },
        "openssl": {
            "available": bool(openssl_result.get("available")),
            "path": openssl_result.get("executable", ""),
            "version": openssl_result.get("version", ""),
            "role": "optional corroboration",
        },
    }
    tls["probe"] = {
        "target": f"{tls['hostname']}:{TARGET_PORT}",
        "started_at": nmap_result["started_at"],
        "completed_at": nmap_result["completed_at"],
        "command": nmap_result["command"],
        "returncode": nmap_result["returncode"],
        "timed_out": nmap_result["timed_out"],
        "xml_sha256": xml_hash,
        "stderr_sha256": stderr_hash,
    }
    tls["protocols"] = parsed["protocols"]
    tls["ciphers"] = parsed["ciphers"]
    tls["assessment"] = {
        "protocol": protocol_assessment,
        "cipher": cipher_assessment,
        "overall_requires_review": overall_review,
    }
    tls["openssl_corroboration"] = openssl_result
    tls["generated_at"] = now_iso()
    tls["errors"] = []

    return document


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init() -> int:
    network_data = load_network()
    scope_data = load_scope()
    target, authorized = require_authorized_https_target(network_data, scope_data)

    document = empty_document(network_data, authorized)
    save_yaml(tls_file(), document)
    record("TLS protocol/cipher initialized", "in-progress")

    print("[PASS] TLS Protocol/Cipher initialized.")
    print(f"PROJECT           : {project_root().name}")
    print(f"TARGET            : {target['hostname']}")
    print(f"CHECKLISTS        : {CHECKLIST_PROTOCOL}, {CHECKLIST_CIPHER}")
    print(f"AUTHORIZED PORT   : {TARGET_PORT}")
    print(f"FILE              : {tls_file()}")
    return 0


def cmd_analyze() -> int:
    network_data = load_network()
    scope_data = load_scope()
    target, authorized = require_authorized_https_target(network_data, scope_data)

    print(f"[INFO] TLS probe target: {target['hostname']}:{TARGET_PORT}")
    print("[INFO] Primary tool: Nmap NSE ssl-enum-ciphers")

    nmap_result = run_nmap_tls_probe(target["hostname"])
    if nmap_result.get("returncode") not in (0, None):
        # Nmap can still provide valid NSE evidence with a non-zero return code,
        # but retain the condition explicitly in YAML. Parsing decides whether
        # usable TLS evidence exists.
        print(
            f"[WARN] Nmap return code: {nmap_result.get('returncode')}. "
            "Evidence akan divalidasi melalui XML parser."
        )

    openssl_result = run_optional_openssl(target["hostname"])
    document = build_document(
        network_data,
        authorized,
        nmap_result,
        openssl_result,
    )

    save_json(
        openssl_evidence_file(),
        openssl_result,
    )
    save_yaml(tls_file(), document)
    record("TLS protocol/cipher analyzed", "completed")

    tls = document["tls"]
    protocol_assessment = tls["assessment"]["protocol"]
    cipher_assessment = tls["assessment"]["cipher"]

    accepted = [
        item["name"]
        for item in tls["protocols"]
        if item.get("status") == "accepted"
    ]

    print("[PASS] TLS Protocol/Cipher analysis completed.")
    print(f"HOSTNAME                 : {target['hostname']}")
    print(f"TLS ACCEPTED             : {', '.join(accepted) if accepted else '-'}")
    print(f"TLS LEGACY ACCEPTED      : {', '.join(protocol_assessment['accepted_legacy']) if protocol_assessment['accepted_legacy'] else '-'}")
    print(f"TLS 3-008 RESULT         : {protocol_assessment['result']}")
    print(f"CIPHER COUNT             : {len(tls['ciphers'])}")
    print(f"CIPHER 3-009 RESULT      : {cipher_assessment['result']}")
    print(f"LEGACY CIPHERS           : {len(cipher_assessment['legacy_observed'])}")
    print(f"UNKNOWN CIPHERS          : {len(cipher_assessment['unknown_observed'])}")
    print(f"REQUIRES REVIEW          : {int(bool(tls['assessment']['overall_requires_review']))}")
    print(f"OPENSSL AVAILABLE        : {bool(openssl_result.get('available'))}")
    print(f"FILE                     : {tls_file()}")
    print(f"NMAP XML EVIDENCE        : {nmap_xml_file()}")
    print(f"NMAP STDERR EVIDENCE     : {nmap_stderr_file()}")
    print(f"OPENSSL EVIDENCE         : {openssl_evidence_file()}")
    return 0


def cmd_list() -> int:
    path = tls_file()
    if not path.exists():
        print("[FAIL] TLS assessment belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "tls.yaml")
    require_project_id(data, "tls.yaml")
    tls = nested_payload(data, "tls")
    assessment = nested_payload(tls, "assessment")
    protocol = assessment.get("protocol") or {}
    cipher = assessment.get("cipher") or {}

    accepted = [
        item.get("name")
        for item in tls.get("protocols", [])
        if isinstance(item, dict) and item.get("status") == "accepted"
    ]

    print(f"PROJECT             : {data.get('project_id', '-')}")
    print(f"STATUS              : {tls.get('status', '-')}")
    print(f"TARGET              : {tls.get('hostname', '-')}")
    print(f"TLS ACCEPTED        : {', '.join(accepted) if accepted else '-'}")
    print(f"3-008 RESULT        : {protocol.get('result', '-')}")
    print(f"3-009 RESULT        : {cipher.get('result', '-')}")
    print(f"CIPHERS             : {len(tls.get('ciphers', []))}")
    print(f"REQUIRES REVIEW     : {int(bool(assessment.get('overall_requires_review')))}")
    return 0


def cmd_show() -> int:
    path = tls_file()
    if not path.exists():
        print("[FAIL] TLS assessment belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    data = load_yaml(path, "tls.yaml")
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

    require_project_id(data, "tls.yaml")

    if str(data.get("schema_version", "")).strip() != SCHEMA_VERSION:
        errors.append(
            f"Schema version tidak sesuai: {data.get('schema_version', '-')}; expected {SCHEMA_VERSION}"
        )

    tls = data.get("tls")
    if not isinstance(tls, dict):
        return ["Field tls tidak valid."]

    status = str(tls.get("status", "")).strip().lower()
    if status not in VALID_STATUSES:
        errors.append(f"Status TLS tidak valid: {status or '-'}")

    for field in ("hostname", "method"):
        value = tls.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"Field tls.{field} kosong.")

    checklists = tls.get("checklists")
    checklist_ids = {
        item.get("id")
        for item in checklists
        if isinstance(item, dict)
    } if isinstance(checklists, list) else set()
    if CHECKLIST_PROTOCOL not in checklist_ids:
        errors.append(f"Checklist {CHECKLIST_PROTOCOL} tidak ada di tls.checklists.")
    if CHECKLIST_CIPHER not in checklist_ids:
        errors.append(f"Checklist {CHECKLIST_CIPHER} tidak ada di tls.checklists.")

    if int(tls.get("target_port", 0) or 0) != TARGET_PORT:
        errors.append(f"tls.target_port harus {TARGET_PORT}.")

    protocols = tls.get("protocols")
    if not isinstance(protocols, list):
        errors.append("Field tls.protocols tidak valid.")
    else:
        observed_names = {
            item.get("name")
            for item in protocols
            if isinstance(item, dict)
        }
        for protocol in TLS_PROTOCOLS:
            if protocol not in observed_names:
                errors.append(f"Protocol {protocol} tidak ditemukan dalam evidence.")

        for item in protocols:
            if not isinstance(item, dict):
                errors.append("Item tls.protocols bukan mapping.")
                continue
            status_value = str(item.get("status", "")).strip()
            if status_value not in {"accepted", "not-observed"}:
                errors.append(
                    f"Status protocol {item.get('name', '-')} tidak valid: {status_value or '-'}"
                )

    ciphers = tls.get("ciphers")
    if not isinstance(ciphers, list):
        errors.append("Field tls.ciphers tidak valid.")
    else:
        for item in ciphers:
            if not isinstance(item, dict):
                errors.append("Item tls.ciphers bukan mapping.")
                continue
            if not str(item.get("name", "")).strip():
                errors.append("Cipher tanpa nama ditemukan.")
            if str(item.get("classification", "")) not in {
                "modern",
                "legacy-review",
                "unknown",
            }:
                errors.append(
                    f"Klasifikasi cipher tidak valid: {item.get('classification', '-')}."
                )

    assessment = tls.get("assessment")
    if not isinstance(assessment, dict):
        errors.append("Field tls.assessment tidak valid.")
    else:
        for section in ("protocol", "cipher"):
            if not isinstance(assessment.get(section), dict):
                errors.append(f"Assessment section '{section}' tidak valid.")

    evidence = tls.get("evidence")
    if not isinstance(evidence, dict):
        errors.append("Field tls.evidence tidak valid.")
    else:
        if not nmap_xml_file().exists():
            errors.append("Evidence Nmap XML tidak ditemukan.")

    errors_field = tls.get("errors")
    if not isinstance(errors_field, list):
        errors.append("Field tls.errors tidak valid.")
    elif errors_field:
        errors.append("TLS assessment menyimpan probe errors.")

    return errors


def cmd_verify() -> int:
    path = tls_file()
    if not path.exists():
        print("[FAIL] TLS assessment belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    try:
        data = load_yaml(path, "tls.yaml")
        errors = validate_document(data)
    except TLSError as exc:
        errors = [str(exc)]

    tls = data.get("tls") if isinstance(data, dict) else {}
    if not isinstance(tls, dict):
        tls = {}

    status = str(tls.get("status", "")).strip().lower()
    if status not in {"in-progress", "completed"}:
        errors.append(f"Status belum siap diverifikasi: {status or '-'}")

    if errors:
        print("[FAIL] TLS Protocol/Cipher verification gagal.")
        for error in errors:
            print(f"  - {error}")
        return 1

    if status == "in-progress":
        tls["status"] = "completed"
        data["updated_at"] = now_iso()
        save_yaml(path, data)

    assessment = tls.get("assessment") or {}
    protocol = assessment.get("protocol") or {}
    cipher = assessment.get("cipher") or {}
    accepted = [
        item.get("name")
        for item in tls.get("protocols", [])
        if isinstance(item, dict) and item.get("status") == "accepted"
    ]

    print("[PASS] TLS Protocol/Cipher memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_PROTOCOL} {CHECKLIST_PROTOCOL_NAME}")
    print(f"[PASS] Checklist : {CHECKLIST_CIPHER} {CHECKLIST_CIPHER_NAME}")
    print(f"[PASS] Status    : {tls.get('status', '-')}")
    print(f"[PASS] Target    : {tls.get('hostname', '-')}")
    print(f"[PASS] TLS       : {', '.join(accepted) if accepted else '-'}")
    print(f"[PASS] 3-008     : {protocol.get('result', '-')}")
    print(f"[PASS] 3-009     : {cipher.get('result', '-')}")
    print(f"[PASS] Ciphers   : {len(tls.get('ciphers', []))}")
    print(f"[PASS] Review    : {int(bool(assessment.get('overall_requires_review')))}")
    print(
        "[PASS] Assessment: TLS protocol/cipher dicatat sebagai evidence; "
        "certificate validation dinilai pada checklist 3-010."
    )

    record("TLS protocol/cipher verified", "completed")
    return 0


def cmd_status() -> int:
    path = tls_file()
    if not path.exists():
        print("[INFO] TLS assessment belum ada.")
        return 0

    data = load_yaml(path, "tls.yaml")
    require_project_id(data, "tls.yaml")
    tls = nested_payload(data, "tls")
    assessment = tls.get("assessment") or {}
    protocol = assessment.get("protocol") or {}
    cipher = assessment.get("cipher") or {}

    accepted = [
        item.get("name")
        for item in tls.get("protocols", [])
        if isinstance(item, dict) and item.get("status") == "accepted"
    ]

    print(f"PROJECT             : {data.get('project_id', '-')}")
    print(f"STATUS              : {tls.get('status', '-')}")
    print(f"TARGET              : {tls.get('hostname', '-')}")
    print(f"TLS ACCEPTED        : {', '.join(accepted) if accepted else '-'}")
    print(f"3-008 RESULT        : {protocol.get('result', '-')}")
    print(f"3-009 RESULT        : {cipher.get('result', '-')}")
    print(f"CIPHERS             : {len(tls.get('ciphers', []))}")
    print(f"REQUIRES REVIEW     : {int(bool(assessment.get('overall_requires_review')))}")
    print(f"ERRORS              : {len(tls.get('errors', [])) if isinstance(tls.get('errors'), list) else '-'}")
    print(f"FILE                : {path}")
    return 0


def cmd_remove() -> int:
    path = tls_dir()
    if not path.exists():
        print("[INFO] TLS assessment belum ada.")
        return 0

    confirm = input(
        "Hapus seluruh data TLS Protocol/Cipher untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(path)
    record("TLS protocol/cipher data removed", "completed")
    print("[PASS] TLS Protocol/Cipher berhasil dihapus.")
    return 0


def cmd_version() -> int:
    print(f"BrebesKab-CSIRT-Tools tls.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_PROTOCOL} {CHECKLIST_PROTOCOL_NAME}")
    print(f"Checklist: {CHECKLIST_CIPHER} {CHECKLIST_CIPHER_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Primary  : Nmap NSE ssl-enum-ciphers")
    print("Optional : OpenSSL s_client corroboration")
    print("Baseline : 02-reconnaissance/network/network.yaml")
    print("Scope    : 01-preparation/scope/scope.yaml")
    print("Rule     : accepted TLS 1.0/1.1 = REVIEW; modern TLS 1.2/1.3 observations = acceptable evidence")
    print("Cipher   : legacy/unknown observations = REVIEW; no automatic vulnerability finding")
    print("Boundary : certificate validation is deferred to 3-010")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Infrastructure TLS Protocol & Cipher\n"
        "\n"
        "Checklist:\n"
        "  3-008 TLS protocol\n"
        "  3-009 TLS cipher\n"
        "\n"
        "Usage:\n"
        "  python scripts/infrastructure/tls.py init\n"
        "  python scripts/infrastructure/tls.py analyze\n"
        "  python scripts/infrastructure/tls.py list\n"
        "  python scripts/infrastructure/tls.py show\n"
        "  python scripts/infrastructure/tls.py verify\n"
        "  python scripts/infrastructure/tls.py status\n"
        "  python scripts/infrastructure/tls.py remove\n"
        "  python scripts/infrastructure/tls.py version\n"
        "\n"
        "Design:\n"
        "  - Reuses completed network.yaml and scope.yaml.\n"
        "  - Requires TCP/443 to be observed open and explicitly in scope.\n"
        "  - Uses Nmap ssl-enum-ciphers as the primary evidence source.\n"
        "  - Keeps raw Nmap XML and stderr as evidence.\n"
        "  - Optional OpenSSL corroboration is used when available.\n"
        "  - Not-observed is not reported as cryptographic rejection.\n"
        "  - Certificate validation is deferred to checklist 3-010.\n"
        "  - No authentication testing, brute force, exploitation, or destructive methods.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Infrastructure TLS Protocol & Cipher - checklists 3-008 and 3-009",
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
        raise TLSError(f"Command tidak dikenal: {args.command}")

    except TLSError as exc:
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
