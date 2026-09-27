#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Infrastructure - Certificate Validation Assessment

Version: 1.0.0
Schema: 1.0

Checklist mapping:
    3-010 - Certificate validation

Purpose:
    Validate the TLS certificate presented by the in-scope HTTPS service,
    focusing on hostname identity, certificate validity period, and trust
    validation while preserving the presented certificate chain as evidence.

Design principles:
    - Reuse completed reconnaissance/network evidence and active scope.
    - Require TCP/443 to be both observed open and explicitly authorized.
    - Do not repeat TCP scanning, service enumeration, TLS protocol or cipher
      enumeration.
    - Use OpenSSL s_client to retrieve and preserve the presented chain.
    - Use Python cryptography to parse certificate fields and fingerprints.
    - Use curl.exe on Windows as an independent trust/hostname validation
      probe. The installed curl uses Schannel and therefore validates against
      the Windows trust environment without requiring OpenSSL's CA store.
    - Do not disable certificate verification in the validation probe.
    - Preserve OpenSSL verification messages as evidence, but do not treat
      OpenSSL trust-store limitations alone as proof that the certificate is
      invalid.
    - Certificate details are evidence; a security finding is not created
      automatically by this module.
    - No authentication testing, brute force, exploitation, destructive
      methods, or unrelated port scanning.

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
    projects/<PROJECT-ID>/03-infrastructure/certificate/certificate.yaml
    projects/<PROJECT-ID>/03-infrastructure/certificate/evidence/
        openssl-s_client.txt
        certificate-chain.pem
        curl-validation.json
        certificates.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import re
import shutil
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Import bootstrap
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

# Prevent local infrastructure modules such as http.py from shadowing
# standard-library/third-party modules when this script is executed directly.
while str(SCRIPT_DIR) in sys.path:
    sys.path.remove(str(SCRIPT_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

try:
    import yaml
except ImportError as exc:
    raise RuntimeError(
        "PyYAML tidak tersedia. Jalankan install-requirements.ps1 terlebih dahulu."
    ) from exc

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa, dsa
except ImportError as exc:
    raise RuntimeError(
        "cryptography tidak tersedia. Jalankan install-requirements.ps1 terlebih dahulu."
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

CHECKLIST_ID = "3-010"
CHECKLIST_NAME = "Certificate validation"

PREPARATION_DIR = "01-preparation"
RECON_DIR = "02-reconnaissance"
INFRASTRUCTURE_DIR = "03-infrastructure"
SCOPE_DIR = "scope"
SCOPE_FILE = "scope.yaml"
NETWORK_DIR = "network"
NETWORK_FILE = "network.yaml"
CERTIFICATE_DIR = "certificate"
CERTIFICATE_FILE = "certificate.yaml"
EVIDENCE_DIR = "evidence"
OPENSSL_RAW_FILE = "openssl-s_client.txt"
CHAIN_PEM_FILE = "certificate-chain.pem"
CURL_JSON_FILE = "curl-validation.json"
CERTIFICATES_JSON_FILE = "certificates.json"

TARGET_PORT = 443
OPENSSL_EXECUTABLE = "openssl"
CURL_EXECUTABLE = "curl.exe"
OPENSSL_TIMEOUT = 45
CURL_TIMEOUT = 45

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
    "skipped",
    "failed",
    "blocked",
}

TLS_CERT_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)

CURL_CERT_ERROR_CODES = {
    35: "tls-handshake-error",
    51: "certificate-hostname-or-identity-error",
    60: "certificate-trust-or-verification-error",
    77: "certificate-ca-store-error",
    90: "certificate-status-error",
}

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CertificateError(RuntimeError):
    """Raised when certificate assessment cannot safely continue."""


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


def certificate_dir() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / CERTIFICATE_DIR


def certificate_file() -> Path:
    return certificate_dir() / CERTIFICATE_FILE


def evidence_dir() -> Path:
    return certificate_dir() / EVIDENCE_DIR


def openssl_raw_file() -> Path:
    return evidence_dir() / OPENSSL_RAW_FILE


def chain_pem_file() -> Path:
    return evidence_dir() / CHAIN_PEM_FILE


def curl_json_file() -> Path:
    return evidence_dir() / CURL_JSON_FILE


def certificates_json_file() -> Path:
    return evidence_dir() / CERTIFICATES_JSON_FILE


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8", errors="replace"))


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
        raise CertificateError(f"Gagal menulis YAML: {path}\n{exc}") from exc


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise CertificateError(f"{label} tidak ditemukan: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise CertificateError(f"Gagal membaca {label}: {path}\n{exc}") from exc
    except yaml.YAMLError as exc:
        raise CertificateError(f"YAML {label} tidak valid: {path}\n{exc}") from exc

    if not isinstance(data, dict):
        raise CertificateError(f"Format {label} tidak valid: root harus mapping/object.")
    return data


def save_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(content, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise CertificateError(f"Gagal menulis evidence: {path}\n{exc}") from exc


def save_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except OSError as exc:
        raise CertificateError(f"Gagal menulis JSON evidence: {path}\n{exc}") from exc


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
        raise CertificateError(
            f"Project ID pada {label} tidak sesuai active project. "
            f"Expected: {expected}; Found: {actual or '-'}"
        )


def nested_payload(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise CertificateError(f"Field '{name}' pada dokumen tidak valid.")
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
        raise CertificateError(
            "Reconnaissance network belum completed. "
            "Jalankan network.py verify terlebih dahulu."
        )
    if not isinstance(network.get("ports"), list):
        raise CertificateError("Field network.ports pada network.yaml harus list.")
    return data


def load_scope() -> dict[str, Any]:
    data = load_yaml(scope_file(), "scope.yaml")
    require_project_id(data, "scope.yaml")
    scope = nested_payload(data, "scope")
    if not isinstance(scope.get("in_scope"), list):
        raise CertificateError("Field scope.in_scope pada scope.yaml harus list.")
    return data


def target_metadata(network_data: dict[str, Any]) -> dict[str, Any]:
    network = nested_payload(network_data, "network")
    hostname = str(network.get("hostname", "")).strip().rstrip(".")
    application = str(network.get("application", "")).strip()
    environment = str(network.get("environment", "")).strip()
    assessment_type = str(network.get("assessment_type", "")).strip()
    scope_reference = str(network.get("scope_reference", "")).strip()
    ipv4 = network.get("ipv4") or []
    if not isinstance(ipv4, list):
        ipv4 = []
    ipv4 = [str(value).strip() for value in ipv4 if str(value).strip()]

    if not hostname:
        raise CertificateError("network.yaml tidak memiliki hostname target.")

    return {
        "hostname": hostname,
        "application": application,
        "environment": environment,
        "assessment_type": assessment_type,
        "scope_reference": scope_reference,
        "ipv4": ipv4,
    }


def require_authorized_target(
    network_data: dict[str, Any], scope_data: dict[str, Any]
) -> tuple[dict[str, Any], set[int]]:
    target = target_metadata(network_data)
    authorized = authorized_ports(scope_data)
    observed_open = network_open_ports(network_data)

    if TARGET_PORT not in authorized:
        raise CertificateError(
            "Port 443 tidak tercantum pada active in-scope ports. "
            "Certificate probe diblokir oleh scope."
        )
    if TARGET_PORT not in observed_open:
        raise CertificateError(
            "Port 443 tidak tercatat open pada network.yaml. "
            "Certificate probe tidak diizinkan tanpa baseline network."
        )
    return target, authorized


def find_executable(*names: str) -> str:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return ""


def tool_version(executable: str) -> str:
    if not executable:
        return ""
    candidates = [["version"], ["--version"], ["-version"]]
    for args in candidates:
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
            continue
        value = result.stdout.strip()
        if value:
            return value.splitlines()[0].strip()
    return ""


def iso_utc(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def cert_name(name: x509.Name) -> str:
    return ", ".join(
        f"{attr.oid._name or attr.oid.dotted_string}={attr.value}"
        for attr in name
    )


def serial_hex(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "X")


def public_key_info(cert: x509.Certificate) -> dict[str, Any]:
    key = cert.public_key()
    info: dict[str, Any] = {"type": type(key).__name__, "size_bits": None}
    if isinstance(key, rsa.RSAPublicKey):
        info["type"] = "RSA"
        info["size_bits"] = key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        info["type"] = "EC"
        info["size_bits"] = key.key_size
        info["curve"] = key.curve.name
    elif isinstance(key, ed25519.Ed25519PublicKey):
        info["type"] = "Ed25519"
        info["size_bits"] = 256
    elif isinstance(key, ed448.Ed448PublicKey):
        info["type"] = "Ed448"
        info["size_bits"] = 448
    elif isinstance(key, dsa.DSAPublicKey):
        info["type"] = "DSA"
        info["size_bits"] = key.key_size
    return info


def extension_value(cert: x509.Certificate, extension_type: Any) -> Any:
    try:
        return cert.extensions.get_extension_for_class(extension_type).value
    except x509.ExtensionNotFound:
        return None


def parse_certificate(cert: x509.Certificate, index: int) -> dict[str, Any]:
    san_dns: list[str] = []
    san_ips: list[str] = []
    san_uris: list[str] = []
    san = extension_value(cert, x509.SubjectAlternativeName)
    if san is not None:
        for value in san:
            if isinstance(value, x509.DNSName):
                san_dns.append(value.value)
            elif isinstance(value, x509.IPAddress):
                san_ips.append(str(value.value))
            elif isinstance(value, x509.UniformResourceIdentifier):
                san_uris.append(value.value)

    basic = extension_value(cert, x509.BasicConstraints)
    key_usage = extension_value(cert, x509.KeyUsage)
    aki = extension_value(cert, x509.AuthorityKeyIdentifier)
    ski = extension_value(cert, x509.SubjectKeyIdentifier)

    try:
        sig_name = cert.signature_hash_algorithm.name
    except Exception:
        sig_name = "unknown"

    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)

    return {
        "index": index,
        "is_leaf": index == 0,
        "subject": cert_name(cert.subject),
        "issuer": cert_name(cert.issuer),
        "serial_number_hex": serial_hex(cert),
        "version": cert.version.name,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "not_before": iso_utc(not_before),
        "not_after": iso_utc(not_after),
        "signature_hash_algorithm": sig_name,
        "signature_oid": cert.signature_algorithm_oid.dotted_string,
        "public_key": public_key_info(cert),
        "subject_alternative_names": {
            "dns": san_dns,
            "ip": san_ips,
            "uri": san_uris,
        },
        "basic_constraints": (
            {"ca": basic.ca, "path_length": basic.path_length}
            if basic is not None
            else None
        ),
        "subject_key_identifier": ski.digest.hex() if ski else None,
        "authority_key_identifier": aki.key_identifier.hex() if aki and aki.key_identifier else None,
        "key_usage": (
            {
                "digital_signature": key_usage.digital_signature,
                "key_encipherment": key_usage.key_encipherment,
                "key_agreement": key_usage.key_agreement,
                "key_cert_sign": key_usage.key_cert_sign,
                "crl_sign": key_usage.crl_sign,
            }
            if key_usage is not None
            else None
        ),
    }


def parse_pem_certificates(pem_text: str) -> tuple[list[x509.Certificate], list[str]]:
    blocks = TLS_CERT_PEM_RE.findall(pem_text)
    certificates: list[x509.Certificate] = []
    errors: list[str] = []
    for index, block in enumerate(blocks):
        try:
            certificates.append(
                x509.load_pem_x509_certificate(block.encode("ascii"))
            )
        except Exception as exc:
            errors.append(f"certificate[{index}]: {type(exc).__name__}: {exc}")
    return certificates, errors


def hostname_matches_leaf(cert: x509.Certificate, hostname: str) -> tuple[bool, str]:
    # Prefer SAN and only use CN as a fallback for evidence. curl/Schannel is
    # the independent final hostname-validation authority for this module.
    san = extension_value(cert, x509.SubjectAlternativeName)
    dns_names: list[str] = []
    ip_names: list[str] = []
    if san is not None:
        for value in san:
            if isinstance(value, x509.DNSName):
                dns_names.append(value.value)
            elif isinstance(value, x509.IPAddress):
                ip_names.append(str(value.value))

    target_is_ip = False
    try:
        ipaddress.ip_address(hostname)
        target_is_ip = True
    except ValueError:
        pass

    presented = ip_names if target_is_ip else dns_names
    if not presented:
        common_names = [
            attr.value
            for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        ]
        presented = [str(value) for value in common_names]
        source = "common-name-fallback"
    else:
        source = "subject-alternative-name"

    try:
        if target_is_ip:
            target_ip = ipaddress.ip_address(hostname)
            for candidate in presented:
                try:
                    if ipaddress.ip_address(candidate) == target_ip:
                        return True, source
                except ValueError:
                    continue
        else:
            # Let Python's hostname matcher apply standard wildcard rules.
            cert_dict = {"subjectAltName": [("DNS", value) for value in presented]}
            try:
                ssl.match_hostname(cert_dict, hostname)
                return True, source
            except ssl.CertificateError:
                # Python's matcher does not accept CN fallback through SAN.
                pass
    except Exception:
        pass

    return False, source


def validity_result(cert: x509.Certificate) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before)
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after)
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=dt.timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=dt.timezone.utc)

    return {
        "status": "valid" if not_before <= now <= not_after else "invalid",
        "checked_at": now.astimezone().isoformat(timespec="seconds"),
        "not_before": iso_utc(not_before),
        "not_after": iso_utc(not_after),
        "seconds_until_expiry": int((not_after - now).total_seconds()),
    }


def chain_structure(certificates: list[x509.Certificate]) -> dict[str, Any]:
    if not certificates:
        return {
            "status": "not-observed",
            "presented_count": 0,
            "adjacent_issuer_subject_matches": [],
            "last_subject_equals_issuer": None,
            "notes": "No certificate chain was parsed.",
        }

    adjacent: list[bool] = []
    for current, nxt in zip(certificates, certificates[1:]):
        adjacent.append(current.issuer == nxt.subject)

    last_subject_equals_issuer = False
    if certificates:
        last_subject_equals_issuer = certificates[-1].subject == certificates[-1].issuer

    if len(certificates) == 1:
        status = "leaf-only-observed"
    elif all(adjacent):
        status = "presented-chain-structurally-consistent"
    else:
        status = "presented-chain-structure-review"

    return {
        "status": status,
        "presented_count": len(certificates),
        "adjacent_issuer_subject_matches": adjacent,
        "last_subject_equals_issuer": last_subject_equals_issuer,
        "notes": (
            "This describes the certificates presented by the server; subject=issuer is not by itself proof of a valid self-signature or trust."
        ),
    }


def curl_probe(executable: str, hostname: str) -> dict[str, Any]:
    url = f"https://{hostname}/"
    command = [
        executable,
        "--silent",
        "--show-error",
        "--output",
        "NUL" if sys.platform.startswith("win") else "/dev/null",
        "--connect-timeout",
        "10",
        "--max-time",
        str(CURL_TIMEOUT),
        "--url",
        url,
        "--write-out",
        "%{http_code}\\t%{ssl_verify_result}\\n",
    ]
    started = now_iso()
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CURL_TIMEOUT + 5,
            check=False,
        )
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "error",
            "result": "timeout",
            "returncode": None,
            "timed_out": True,
            "stdout": str(exc.stdout or ""),
            "stderr": str(exc.stderr or ""),
            "http_code": None,
            "ssl_verify_result": None,
            "command": command,
            "started_at": started,
            "completed_at": now_iso(),
        }
    except OSError as exc:
        return {
            "status": "error",
            "result": "execution-error",
            "returncode": None,
            "timed_out": False,
            "stdout": "",
            "stderr": str(exc),
            "http_code": None,
            "ssl_verify_result": None,
            "command": command,
            "started_at": started,
            "completed_at": now_iso(),
        }

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    http_code = None
    ssl_verify_result = None
    if stdout:
        parts = stdout.splitlines()[-1].split("\t")
        if parts:
            try:
                http_code = int(parts[0]) if parts[0] else None
            except ValueError:
                http_code = None
        if len(parts) > 1:
            try:
                ssl_verify_result = int(parts[1]) if parts[1] else None
            except ValueError:
                ssl_verify_result = None

    if result.returncode == 0 and ssl_verify_result == 0:
        status = "validated"
        result_name = "certificate-validated-by-curl"
    elif result.returncode in CURL_CERT_ERROR_CODES:
        status = "validation-failed"
        result_name = CURL_CERT_ERROR_CODES[result.returncode]
    else:
        status = "indeterminate"
        result_name = "transport-or-client-error"

    return {
        "status": status,
        "result": result_name,
        "returncode": result.returncode,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "http_code": http_code,
        "ssl_verify_result": ssl_verify_result,
        "command": command,
        "started_at": started,
        "completed_at": now_iso(),
        "verification": {
            "certificate_verification_enabled": True,
            "hostname_verification_enabled": True,
            "system_trust_environment": "Windows Schannel via curl.exe",
        },
    }


def openssl_probe(executable: str, hostname: str) -> dict[str, Any]:
    command = [
        executable,
        "s_client",
        "-connect",
        f"{hostname}:{TARGET_PORT}",
        "-servername",
        hostname,
        "-showcerts",
        "-verify_hostname",
        hostname,
    ]
    started = now_iso()
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
            "status": "timeout",
            "returncode": None,
            "stdout": str(exc.stdout or ""),
            "stderr": str(exc.stderr or ""),
            "command": command,
            "started_at": started,
            "completed_at": now_iso(),
            "timed_out": True,
            "certificates_found": 0,
        }
    except OSError as exc:
        return {
            "status": "execution-error",
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "command": command,
            "started_at": started,
            "completed_at": now_iso(),
            "timed_out": False,
            "certificates_found": 0,
        }

    combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
    pem_blocks = TLS_CERT_PEM_RE.findall(combined)
    combined_sha256 = sha256_text(combined)
    status = "completed" if pem_blocks else "no-certificates-parsed"

    return {
        "status": status,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "combined_sha256": combined_sha256,
        "command": command,
        "started_at": started,
        "completed_at": now_iso(),
        "timed_out": False,
        "certificates_found": len(pem_blocks),
        "verify_messages": parse_openssl_verify_messages(combined),
    }


def parse_openssl_verify_messages(text: str) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for match in re.finditer(r"verify (error|return):([^\n]+)", text, re.IGNORECASE):
        messages.append(
            {
                "type": match.group(1).lower(),
                "message": match.group(2).strip(),
            }
        )
    if re.search(r"Verify return code:\s*0\s*\(ok\)", text, re.IGNORECASE):
        messages.append({"type": "return-code", "message": "0 (ok)"})
    return messages


def merge_validation(
    leaf: x509.Certificate,
    target: dict[str, Any],
    curl_result: dict[str, Any],
    chain_result: dict[str, Any],
) -> dict[str, Any]:
    hostname_ok, hostname_source = hostname_matches_leaf(leaf, target["hostname"])
    validity = validity_result(leaf)

    curl_status = curl_result.get("status")
    if curl_status == "validated":
        trust_status = "trusted-by-system-validation"
        hostname_final = "validated-by-system"
    elif curl_status == "validation-failed":
        trust_status = "validation-failed"
        hostname_final = "validation-failed-or-untrusted"
    else:
        trust_status = "indeterminate"
        hostname_final = "indeterminate"

    requires_review = False
    issues: list[str] = []

    if not hostname_ok:
        requires_review = True
        issues.append("leaf-hostname-mismatch-or-unconfirmed")
    if validity["status"] != "valid":
        requires_review = True
        issues.append("leaf-certificate-outside-validity-period")
    if trust_status != "trusted-by-system-validation":
        requires_review = True
        issues.append("system-trust-validation-not-confirmed")

    if curl_status == "validated" and hostname_ok and validity["status"] == "valid":
        result = "certificate-valid"
    elif issues:
        result = "certificate-validation-review"
    else:
        result = "certificate-validation-incomplete"

    return {
        "result": result,
        "requires_review": requires_review,
        "hostname": {
            "target": target["hostname"],
            "parsed_match": hostname_ok,
            "parsed_match_source": hostname_source,
            "system_validation": hostname_final,
        },
        "validity": validity,
        "trust": {
            "status": trust_status,
            "system_validation_tool": "curl.exe/Schannel",
            "curl_result": curl_result.get("result", ""),
        },
        "chain": chain_result,
        "issues": issues,
        "note": (
            "Certificate validation is evidence-based. A review state does not itself create a vulnerability finding."
        ),
    }


def empty_document(network_data: dict[str, Any], scope_ports: set[int]) -> dict[str, Any]:
    target = target_metadata(network_data)
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "certificate": {
            "status": "not-started",
            "checklist": {
                "id": CHECKLIST_ID,
                "name": CHECKLIST_NAME,
                "focus": "Certificate validation",
            },
            "hostname": target["hostname"],
            "application": target["application"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "target_port": TARGET_PORT,
            "target_scheme": "https",
            "scope_reference": target["scope_reference"],
            "scope_authorized_ports": sorted(scope_ports),
            "network_observed_open_ports": sorted(network_open_ports(network_data)),
            "method": "OpenSSL s_client chain retrieval; Python cryptography parsing; curl.exe/Schannel system trust and hostname validation",
            "toolchain": {
                "openssl": {
                    "available": False,
                    "path": "",
                    "version": "",
                    "role": "certificate-chain retrieval and raw evidence",
                },
                "curl": {
                    "available": False,
                    "path": "",
                    "version": "",
                    "role": "independent certificate/trust/hostname validation via Windows Schannel",
                },
                "python_cryptography": {
                    "available": True,
                    "version": getattr(__import__("cryptography"), "__version__", ""),
                    "role": "certificate field parsing and fingerprinting",
                },
            },
            "probe": {
                "target": f"{target['hostname']}:{TARGET_PORT}",
                "started_at": "",
                "completed_at": "",
                "openssl_command": [],
                "curl_command": [],
            },
            "leaf_certificate": None,
            "chain": {
                "status": "not-observed",
                "presented_count": 0,
                "adjacent_issuer_subject_matches": [],
                "last_subject_equals_issuer": None,
                "notes": "No certificate chain was analyzed.",
            },
            "assessment": {
                "result": "not-assessed",
                "requires_review": False,
                "hostname": {
                    "target": target["hostname"],
                    "parsed_match": None,
                    "parsed_match_source": None,
                    "system_validation": "not-run",
                },
                "validity": {},
                "trust": {
                    "status": "not-run",
                    "system_validation_tool": "curl.exe/Schannel",
                    "curl_result": "",
                },
                "issues": [],
                "note": "Certificate validation is not assessed before analyze.",
            },
            "evidence": {
                "openssl_raw": str(openssl_raw_file()),
                "certificate_chain_pem": str(chain_pem_file()),
                "curl_validation": str(curl_json_file()),
                "certificates_json": str(certificates_json_file()),
            },
            "errors": [],
            "notes": [
                "3-010 owns hostname, validity, trust and certificate-chain validation.",
                "OpenSSL raw verification output is preserved as evidence but is not the sole trust authority.",
                "curl.exe with Schannel is used without -k/--insecure for independent system trust and hostname validation.",
                "TLS protocol and cipher assessment remains in checklist 3-008/3-009.",
                "No automatic vulnerability finding is created by this module.",
            ],
            "generated_at": "",
        },
    }


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def command_version(_args: argparse.Namespace) -> int:
    print(f"BrebesKab-CSIRT-Tools certificate.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Primary  : OpenSSL s_client certificate-chain retrieval")
    print("Validate : curl.exe/Schannel trust + hostname validation")
    print("Parser   : Python cryptography")
    print("Baseline : 02-reconnaissance/network/network.yaml")
    print("Scope    : 01-preparation/scope/scope.yaml")
    print("Boundary : TLS protocol/cipher remain 3-008 / 3-009")
    print("Finding  : evidence only; no automatic vulnerability finding")
    return 0


def command_init(_args: argparse.Namespace) -> int:
    network_data = load_network()
    scope_data = load_scope()
    target, authorized = require_authorized_target(network_data, scope_data)

    document = empty_document(network_data, authorized)
    document["certificate"]["status"] = "in-progress"
    save_yaml(certificate_file(), document)
    record("init", "in-progress")

    print("[PASS] Certificate validation initialized.")
    print(f"PROJECT           : {project_root().name}")
    print(f"TARGET            : {target['hostname']}")
    print(f"CHECKLIST         : {CHECKLIST_ID}")
    print(f"AUTHORIZED PORT   : {TARGET_PORT}")
    print(f"FILE              : {certificate_file()}")
    return 0


def command_analyze(_args: argparse.Namespace) -> int:
    started = now_iso()
    network_data = load_network()
    scope_data = load_scope()
    target, authorized = require_authorized_target(network_data, scope_data)

    cert_doc = empty_document(network_data, authorized)
    cert_doc["certificate"]["status"] = "in-progress"
    cert_doc["certificate"]["probe"]["started_at"] = started

    openssl_path = find_executable(OPENSSL_EXECUTABLE)
    curl_path = find_executable(CURL_EXECUTABLE, "curl")

    cert_doc["certificate"]["toolchain"]["openssl"].update(
        {
            "available": bool(openssl_path),
            "path": openssl_path,
            "version": tool_version(openssl_path),
        }
    )
    cert_doc["certificate"]["toolchain"]["curl"].update(
        {
            "available": bool(curl_path),
            "path": curl_path,
            "version": tool_version(curl_path),
        }
    )

    if not openssl_path:
        cert_doc["certificate"]["errors"].append(
            "openssl.exe tidak ditemukan; chain retrieval tidak dapat dilakukan."
        )
    if not curl_path:
        cert_doc["certificate"]["errors"].append(
            "curl.exe tidak ditemukan; system trust/hostname validation tidak dapat dilakukan."
        )

    openssl_result: dict[str, Any] = {}
    certificates: list[x509.Certificate] = []
    parse_errors: list[str] = []

    if openssl_path:
        openssl_result = openssl_probe(openssl_path, target["hostname"])
        combined = "\n".join(
            part for part in (openssl_result.get("stdout", ""), openssl_result.get("stderr", "")) if part
        )
        save_text(openssl_raw_file(), combined)
        pem_blocks = TLS_CERT_PEM_RE.findall(combined)
        save_text(chain_pem_file(), "\n\n".join(pem_blocks) + ("\n" if pem_blocks else ""))
        certificates, parse_errors = parse_pem_certificates(combined)

        cert_doc["certificate"]["probe"]["openssl_command"] = openssl_result.get("command", [])
        cert_doc["certificate"]["errors"].extend(parse_errors)

    certificate_records = [parse_certificate(cert, index) for index, cert in enumerate(certificates)]
    if certificates:
        save_json(certificates_json_file(), certificate_records)
    else:
        save_json(certificates_json_file(), [])

    curl_result: dict[str, Any] = {}
    if curl_path:
        curl_result = curl_probe(curl_path, target["hostname"])
        save_json(curl_json_file(), curl_result)
        cert_doc["certificate"]["probe"]["curl_command"] = curl_result.get("command", [])
    else:
        curl_result = {
            "status": "not-run",
            "result": "curl-unavailable",
            "returncode": None,
            "timed_out": False,
            "stdout": "",
            "stderr": "",
            "http_code": None,
            "ssl_verify_result": None,
            "command": [],
        }
        save_json(curl_json_file(), curl_result)

    if certificates:
        chain = chain_structure(certificates)
        leaf = certificates[0]
        assessment = merge_validation(leaf, target, curl_result, chain)
        cert_doc["certificate"]["leaf_certificate"] = certificate_records[0]
    else:
        chain = {
            "status": "not-observed",
            "presented_count": 0,
            "adjacent_issuer_subject_matches": [],
            "last_subject_equals_issuer": None,
            "notes": "OpenSSL did not provide a parsable certificate chain.",
        }
        assessment = {
            "result": "certificate-validation-incomplete",
            "requires_review": True,
            "hostname": {
                "target": target["hostname"],
                "parsed_match": None,
                "parsed_match_source": None,
                "system_validation": (
                    "not-confirmed" if curl_result.get("status") != "validated" else "validated-by-system"
                ),
            },
            "validity": {},
            "trust": {
                "status": (
                    "trusted-by-system-validation"
                    if curl_result.get("status") == "validated"
                    else "indeterminate"
                ),
                "system_validation_tool": "curl.exe/Schannel",
                "curl_result": curl_result.get("result", ""),
            },
            "chain": chain,
            "issues": ["certificate-chain-not-parsed"],
            "note": "Certificate evidence incomplete because no parsable chain was retrieved.",
        }
        cert_doc["certificate"]["leaf_certificate"] = None

    cert_doc["certificate"]["chain"] = chain
    cert_doc["certificate"]["assessment"] = assessment
    cert_doc["certificate"]["probe"]["completed_at"] = now_iso()
    cert_doc["certificate"]["status"] = "completed"
    cert_doc["certificate"]["generated_at"] = now_iso()
    cert_doc["certificate"]["evidence"] = {
        "openssl_raw": str(openssl_raw_file()),
        "certificate_chain_pem": str(chain_pem_file()),
        "curl_validation": str(curl_json_file()),
        "certificates_json": str(certificates_json_file()),
        "openssl_raw_sha256": sha256_bytes(openssl_raw_file().read_bytes()) if openssl_raw_file().exists() else "",
        "certificate_chain_sha256": sha256_bytes(chain_pem_file().read_bytes()) if chain_pem_file().exists() else "",
        "curl_json_sha256": sha256_bytes(curl_json_file().read_bytes()) if curl_json_file().exists() else "",
        "certificates_json_sha256": sha256_bytes(certificates_json_file().read_bytes()) if certificates_json_file().exists() else "",
    }

    # Keep project-level updated_at aligned with the top-level schema.
    outer = empty_document(network_data, authorized)
    cert_doc["updated_at"] = now_iso()
    save_yaml(certificate_file(), cert_doc)
    record("analyze", "completed")

    print("[PASS] Certificate validation analysis completed.")
    print(f"HOSTNAME                 : {target['hostname']}")
    print(f"CERTIFICATES PRESENTED   : {len(certificates)}")
    if certificates:
        leaf_record = certificate_records[0]
        print(f"LEAF SUBJECT             : {leaf_record['subject']}")
        print(f"LEAF ISSUER              : {leaf_record['issuer']}")
        print(f"LEAF SHA256              : {leaf_record['fingerprint_sha256']}")
        print(f"VALIDITY                 : {assessment['validity'].get('status', '-')}")
    else:
        print("LEAF SUBJECT             : -")
        print("LEAF ISSUER              : -")
        print("LEAF SHA256              : -")
        print("VALIDITY                 : -")
    print(f"HOSTNAME CHECK           : {assessment['hostname'].get('system_validation', '-')}")
    print(f"TRUST CHECK              : {assessment['trust'].get('status', '-')}")
    print(f"3-010 RESULT             : {assessment['result']}")
    print(f"REQUIRES REVIEW          : {1 if assessment['requires_review'] else 0}")
    print(f"OPENSSL AVAILABLE        : {str(bool(openssl_path))}")
    print(f"CURL AVAILABLE           : {str(bool(curl_path))}")
    print(f"FILE                     : {certificate_file()}")
    print(f"OPENSSL EVIDENCE         : {openssl_raw_file()}")
    print(f"CERTIFICATE CHAIN        : {chain_pem_file()}")
    print(f"CURL VALIDATION          : {curl_json_file()}")
    return 0


def command_show(_args: argparse.Namespace) -> int:
    data = load_yaml(certificate_file(), "certificate.yaml")
    require_project_id(data, "certificate.yaml")
    print(f"PROJECT: {project_root().name}")
    print(f"FILE   : {certificate_file()}")
    print()
    print(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False).rstrip())
    return 0


def verify_document(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if str(data.get("schema_version", "")) != SCHEMA_VERSION:
        errors.append(
            f"schema_version harus {SCHEMA_VERSION}, ditemukan {data.get('schema_version')!r}."
        )
    require_project_id(data, "certificate.yaml")

    cert = nested_payload(data, "certificate")
    if str(cert.get("status", "")) not in VALID_STATUSES:
        errors.append("certificate.status tidak valid.")

    checklist = cert.get("checklist")
    if not isinstance(checklist, dict):
        errors.append("certificate.checklist harus mapping.")
    else:
        if str(checklist.get("id", "")) != CHECKLIST_ID:
            errors.append("checklist.id tidak sesuai 3-010.")
        if str(checklist.get("name", "")) != CHECKLIST_NAME:
            errors.append("checklist.name tidak sesuai Certificate validation.")

    if int(cert.get("target_port", 0) or 0) != TARGET_PORT:
        errors.append("target_port harus 443.")

    protocols = cert.get("leaf_certificate")
    if protocols is not None and not isinstance(protocols, dict):
        errors.append("leaf_certificate harus mapping atau null.")

    assessment = cert.get("assessment")
    if not isinstance(assessment, dict):
        errors.append("assessment harus mapping.")
    else:
        result = str(assessment.get("result", ""))
        if cert.get("status") == "completed" and not result:
            errors.append("assessment.result wajib diisi saat status completed.")

    toolchain = cert.get("toolchain")
    if not isinstance(toolchain, dict):
        errors.append("toolchain harus mapping.")

    evidence = cert.get("evidence")
    if not isinstance(evidence, dict):
        errors.append("evidence harus mapping.")

    return errors


def command_verify(_args: argparse.Namespace) -> int:
    try:
        data = load_yaml(certificate_file(), "certificate.yaml")
        errors = verify_document(data)
    except CertificateError as exc:
        print(f"[FAIL] {exc}")
        return 1

    if errors:
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    cert = data["certificate"]
    assessment = cert.get("assessment", {})
    hostname = cert.get("hostname", "-")
    leaf = cert.get("leaf_certificate") or {}
    count = cert.get("chain", {}).get("presented_count", 0)

    print("[PASS] Certificate validation memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {cert.get('status')}")
    print(f"[PASS] Target    : {hostname}")
    print(f"[PASS] Chain     : {count} certificate(s) presented")
    print(f"[PASS] Subject   : {leaf.get('subject', '-')}")
    print(f"[PASS] Validity  : {assessment.get('validity', {}).get('status', '-')}")
    print(f"[PASS] Hostname  : {assessment.get('hostname', {}).get('system_validation', '-')}")
    print(f"[PASS] Trust     : {assessment.get('trust', {}).get('status', '-')}")
    print(f"[PASS] 3-010     : {assessment.get('result', '-')}")
    print(f"[PASS] Review    : {1 if assessment.get('requires_review') else 0}")
    print(
        "[PASS] Assessment: certificate validation dicatat sebagai evidence; "
        "finding keamanan tidak dibuat otomatis."
    )
    return 0


def command_status(_args: argparse.Namespace) -> int:
    try:
        data = load_yaml(certificate_file(), "certificate.yaml")
    except CertificateError as exc:
        print(f"[FAIL] {exc}")
        return 1
    cert = nested_payload(data, "certificate")
    print(f"PROJECT    : {project_root().name}")
    print(f"CHECKLIST  : {CHECKLIST_ID}")
    print(f"STATUS     : {cert.get('status', '-')}")
    print(f"TARGET     : {cert.get('hostname', '-')}")
    print(f"RESULT     : {cert.get('assessment', {}).get('result', '-')}")
    print(f"REVIEW     : {1 if cert.get('assessment', {}).get('requires_review') else 0}")
    return 0


def command_list(_args: argparse.Namespace) -> int:
    path = certificate_file()
    if not path.exists():
        print(f"[INFO] {CHECKLIST_ID} belum diinisialisasi.")
        return 0
    try:
        data = load_yaml(path, "certificate.yaml")
    except CertificateError as exc:
        print(f"[FAIL] {exc}")
        return 1
    cert = nested_payload(data, "certificate")
    print(f"CHECKLIST : {CHECKLIST_ID}")
    print(f"NAME      : {CHECKLIST_NAME}")
    print(f"STATUS    : {cert.get('status', '-')}")
    print(f"TARGET    : {cert.get('hostname', '-')}")
    print(f"RESULT    : {cert.get('assessment', {}).get('result', '-')}")
    return 0


def command_remove(_args: argparse.Namespace) -> int:
    target = certificate_dir()
    if not target.exists():
        print(f"[INFO] Tidak ada artifact: {target}")
        return 0
    import shutil as _shutil

    _shutil.rmtree(target)
    record("remove", "removed")
    print(f"[PASS] Artifact removed: {target}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools certificate.py - checklist 3-010"
    )
    subparsers = parser.add_subparsers(dest="command")

    for name, function, help_text in (
        ("version", command_version, "Tampilkan informasi versi dan desain modul."),
        ("init", command_init, "Inisialisasi artifact certificate.yaml."),
        ("analyze", command_analyze, "Jalankan validasi certificate pada HTTPS/443."),
        ("list", command_list, "Tampilkan ringkasan checklist."),
        ("show", command_show, "Tampilkan seluruh certificate.yaml."),
        ("verify", command_verify, "Validasi struktur dan status artifact."),
        ("status", command_status, "Tampilkan status singkat checklist."),
        ("remove", command_remove, "Hapus artifact certificate module."),
    ):
        child = subparsers.add_parser(name, help=help_text)
        child.set_defaults(handler=function)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "handler"):
        parser.print_help()
        return 2

    try:
        return int(args.handler(args))
    except CertificateError as exc:
        print(f"[FAIL] {exc}")
        record("error", "failed")
        return 1
    except KeyboardInterrupt:
        print("[FAIL] Operasi dibatalkan oleh pengguna.")
        record("interrupt", "failed")
        return 130
    except Exception as exc:
        print(f"[FAIL] Error tak terduga: {type(exc).__name__}: {exc}")
        record("error", "failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
