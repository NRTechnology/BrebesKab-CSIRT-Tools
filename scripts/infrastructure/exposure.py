#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Infrastructure - Unnecessary Port Exposure Analysis

Version: 1.0.0

Checklist mapping:
    3-003 - Unnecessary port exposure

Purpose:
    Analyze ports observed open by completed Reconnaissance and classify them
    against the explicit assessment scope and available service metadata.

Design:
    - Does NOT perform network scanning.
    - Reads 02-reconnaissance/network/network.yaml as the observed-open baseline.
    - Reads 01-preparation/scope/scope.yaml as the authorization boundary.
    - Reads 03-infrastructure/service/service.yaml for service metadata when
      available.
    - Does NOT treat an out-of-scope port as an automatic vulnerability or as
      proof that the port is unnecessary.
    - Produces evidence for review: authorized, outside-scope, or
      requires-review classification.
    - Does not perform exploitation, brute force, or vulnerability scanning.
    - Maintains its own lifecycle state in exposure.yaml.

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
    projects/<PROJECT-ID>/03-infrastructure/exposure/exposure.yaml
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Import bootstrap
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

for _entry in (str(SCRIPT_DIR), str(SCRIPTS_DIR)):
    while _entry in sys.path:
        sys.path.remove(_entry)

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

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

CHECKLIST_ID = "3-003"
CHECKLIST_NAME = "Unnecessary port exposure"

PREPARATION_DIR = "01-preparation"
RECON_DIR = "02-reconnaissance"
INFRASTRUCTURE_DIR = "03-infrastructure"

SCOPE_DIR = "scope"
SCOPE_FILE = "scope.yaml"

NETWORK_DIR = "network"
NETWORK_FILE = "network.yaml"

SERVICE_DIR = "service"
SERVICE_FILE = "service.yaml"

EXPOSURE_DIR = "exposure"
EXPOSURE_FILE = "exposure.yaml"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
    "skipped",
    "failed",
    "blocked",
}

VALID_CLASSIFICATIONS = {
    "authorized",
    "outside-scope",
}

VALID_ASSESSMENTS = {
    "authorized",
    "outside-scope",
    "requires-review",
}


class ExposureAnalysisError(RuntimeError):
    """Raised when unnecessary-port-exposure analysis cannot be completed safely."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    """Return current local time as ISO-8601 with seconds."""
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def project_context():
    """Return the active project context."""
    return require_active_project()


def project_root() -> Path:
    """Return the active project directory."""
    return Path(project_context().project_path)


def scope_file() -> Path:
    return project_root() / PREPARATION_DIR / SCOPE_DIR / SCOPE_FILE


def network_file() -> Path:
    return project_root() / RECON_DIR / NETWORK_DIR / NETWORK_FILE


def service_file() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / SERVICE_DIR / SERVICE_FILE


def exposure_dir() -> Path:
    return project_root() / INFRASTRUCTURE_DIR / EXPOSURE_DIR


def exposure_file() -> Path:
    return exposure_dir() / EXPOSURE_FILE


def load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.exists():
        raise ExposureAnalysisError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise ExposureAnalysisError(
            f"Gagal membaca {label}: {path}\n{exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ExposureAnalysisError(
            f"YAML {label} tidak valid: {path}\n{exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ExposureAnalysisError(
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
        raise ExposureAnalysisError(f"Gagal menulis: {path}\n{exc}") from exc


def record(action: str, status: str) -> None:
    """Write activity without making activity logging a hard dependency."""
    if record_activity is None:
        return

    context = project_context()

    try:
        record_activity(
            phase="03-infrastructure",
            item=CHECKLIST_ID,
            action=action,
            status=status,
            context=context,
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
        raise ExposureAnalysisError(
            f"Project ID pada {label} tidak sesuai active project. "
            f"Expected: {expected}; Found: {actual or '-'}"
        )


def nested_payload(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name)
    if not isinstance(value, dict):
        raise ExposureAnalysisError(
            f"Field '{name}' pada dokumen tidak valid."
        )
    return value


# ---------------------------------------------------------------------------
# Source loading
# ---------------------------------------------------------------------------


def load_scope() -> dict[str, Any]:
    data = load_yaml(scope_file(), "scope.yaml")
    require_project_id(data, "scope.yaml")

    scope = nested_payload(data, "scope")
    in_scope = scope.get("in_scope")

    if not isinstance(in_scope, list):
        raise ExposureAnalysisError(
            "Field scope.in_scope pada scope.yaml harus berupa list."
        )

    return data


def load_network() -> dict[str, Any]:
    data = load_yaml(network_file(), "network.yaml")
    require_project_id(data, "network.yaml")

    network = nested_payload(data, "network")
    status = str(network.get("status", "")).strip().lower()

    if status != "completed":
        raise ExposureAnalysisError(
            "Reconnaissance network belum completed. "
            "Jalankan network.py terlebih dahulu."
        )

    ports = network.get("ports")
    if not isinstance(ports, list):
        raise ExposureAnalysisError(
            "Field network.ports pada network.yaml harus berupa list."
        )

    return data


def load_service_optional() -> dict[str, Any] | None:
    path = service_file()
    if not path.exists():
        return None

    data = load_yaml(path, "service.yaml")
    require_project_id(data, "service.yaml")

    service = nested_payload(data, "service")
    status = str(service.get("status", "")).strip().lower()

    if status not in VALID_STATUSES:
        raise ExposureAnalysisError(
            f"Status service tidak valid: {status or '-'}"
        )

    return data


# ---------------------------------------------------------------------------
# Scope normalization
# ---------------------------------------------------------------------------


def normalize_ports(value: Any) -> list[int]:
    if value is None:
        return []

    if not isinstance(value, list):
        raise ExposureAnalysisError(
            "Field scope item 'ports' harus berupa list."
        )

    ports: set[int] = set()

    for raw in value:
        try:
            port = int(raw)
        except (TypeError, ValueError) as exc:
            raise ExposureAnalysisError(
                f"Port scope tidak valid: {raw!r}"
            ) from exc

        if not 1 <= port <= 65535:
            raise ExposureAnalysisError(
                f"Port scope di luar rentang 1-65535: {port}"
            )

        ports.add(port)

    return sorted(ports)


def normalize_protocols(value: Any) -> list[str]:
    if value is None:
        return []

    if not isinstance(value, list):
        raise ExposureAnalysisError(
            "Field scope item 'protocols' harus berupa list."
        )

    return sorted(
        {
            str(item).strip().lower()
            for item in value
            if str(item).strip()
        }
    )


def get_scope_ports(scope_data: dict[str, Any]) -> tuple[set[int], list[dict[str, Any]]]:
    scope = nested_payload(scope_data, "scope")
    items = scope["in_scope"]

    authorized_ports: set[int] = set()
    scope_items: list[dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue

        ports = normalize_ports(item.get("ports"))
        protocols = normalize_protocols(item.get("protocols"))

        for port in ports:
            authorized_ports.add(port)

        if ports:
            scope_items.append(
                {
                    "scope_id": str(item.get("scope_id", "")).strip(),
                    "type": str(item.get("type", "")).strip(),
                    "value": str(item.get("value", "")).strip(),
                    "ports": ports,
                    "protocols": protocols,
                }
            )

    return authorized_ports, scope_items


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------


def get_target_metadata(network_data: dict[str, Any]) -> dict[str, str]:
    network = nested_payload(network_data, "network")

    ipv4 = network.get("ipv4") or []
    if not isinstance(ipv4, list):
        ipv4 = []

    target_ip = next(
        (str(item).strip() for item in ipv4 if str(item).strip()),
        "",
    )

    return {
        "application": str(network.get("application", "")).strip(),
        "target_url": str(network.get("target_url", "")).strip(),
        "hostname": str(network.get("hostname", "")).strip(),
        "target_ip": target_ip,
        "environment": str(network.get("environment", "")).strip(),
        "assessment_type": str(network.get("assessment_type", "")).strip(),
        "scope_reference": str(network.get("scope_reference", "")).strip(),
    }


def collect_service_index(
    service_data: dict[str, Any] | None,
) -> dict[tuple[int, str], dict[str, Any]]:
    if service_data is None:
        return {}

    service = nested_payload(service_data, "service")
    results = service.get("results")

    if not isinstance(results, list):
        return {}

    index: dict[tuple[int, str], dict[str, Any]] = {}

    for item in results:
        if not isinstance(item, dict):
            continue

        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue

        protocol = str(item.get("protocol", "")).strip().lower()
        if not protocol:
            protocol = "tcp"

        index[(port, protocol)] = item

    return index


def collect_open_ports(network_data: dict[str, Any]) -> list[dict[str, Any]]:
    network = nested_payload(network_data, "network")
    ports = network.get("ports")

    if not isinstance(ports, list):
        raise ExposureAnalysisError("network.ports harus berupa list.")

    results: list[dict[str, Any]] = []

    for item in ports:
        if not isinstance(item, dict):
            continue

        state = str(item.get("state", "")).strip().lower()
        if state != "open":
            continue

        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue

        if not 1 <= port <= 65535:
            continue

        protocol = str(item.get("protocol", "")).strip().lower() or "tcp"
        service = str(item.get("service", "")).strip()

        results.append(
            {
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
            }
        )

    return sorted(
        results,
        key=lambda item: (int(item["port"]), str(item["protocol"])),
    )


def classify_port(
    port_data: dict[str, Any],
    authorized_ports: set[int],
    service_index: dict[tuple[int, str], dict[str, Any]],
) -> dict[str, Any]:
    port = int(port_data["port"])
    protocol = str(port_data["protocol"]).strip().lower()
    observed_service = str(port_data.get("service", "")).strip()

    service_meta = service_index.get((port, protocol), {})

    product = str(service_meta.get("product", "")).strip()
    version = str(service_meta.get("version", "")).strip()
    detected_service = str(service_meta.get("service", "")).strip()

    service_name = detected_service or observed_service

    in_scope = port in authorized_ports

    if in_scope:
        assessment = "authorized"
        scope_status = "in-scope"
        requires_review = False
        rationale = (
            "Port terobservasi open dan secara eksplisit tercantum dalam "
            "scope assessment."
        )
    else:
        assessment = "requires-review"
        scope_status = "outside-scope"
        requires_review = True
        rationale = (
            "Port terobservasi open tetapi tidak tercantum dalam port "
            "in-scope. Kondisi ini bukan bukti bahwa port tidak diperlukan; "
            "dibutuhkan review kebutuhan exposure dan authorization."
        )

    result = {
        "port": port,
        "protocol": protocol,
        "state": str(port_data["state"]),
        "observed_service": observed_service,
        "detected_service": service_name,
        "product": product,
        "version": version,
        "scope_status": scope_status,
        "assessment": assessment,
        "requires_review": requires_review,
        "rationale": rationale,
    }

    return result


# ---------------------------------------------------------------------------
# Document handling
# ---------------------------------------------------------------------------


def build_document(
    network_data: dict[str, Any],
    scope_data: dict[str, Any],
    service_data: dict[str, Any] | None,
    status: str,
) -> dict[str, Any]:
    target = get_target_metadata(network_data)
    authorized_ports, scope_items = get_scope_ports(scope_data)
    open_ports = collect_open_ports(network_data)
    service_index = collect_service_index(service_data)

    results = [
        classify_port(item, authorized_ports, service_index)
        for item in open_ports
    ]

    authorized_count = sum(
        1 for item in results if item["assessment"] == "authorized"
    )
    outside_scope_count = sum(
        1 for item in results if item["scope_status"] == "outside-scope"
    )
    review_count = sum(
        1 for item in results if item["requires_review"]
    )

    source_service_status = "not-available"
    if service_data is not None:
        source_service_status = str(
            nested_payload(service_data, "service").get("status", "")
        ).strip().lower() or "unknown"

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "exposure": {
            "status": status,
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": target["application"],
            "target_url": target["target_url"],
            "hostname": target["hostname"],
            "target_ip": target["target_ip"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_reference": target["scope_reference"],
            "method": "evidence correlation: network + scope + service",
            "source_network": "02-reconnaissance/network/network.yaml",
            "source_scope": "01-preparation/scope/scope.yaml",
            "source_service": "03-infrastructure/service/service.yaml",
            "source_status": {
                "network": str(
                    nested_payload(network_data, "network").get(
                        "status", ""
                    )
                ).strip().lower(),
                "service": source_service_status,
            },
            "scope_items": scope_items,
            "authorized_ports": sorted(authorized_ports),
            "results": results,
            "summary": {
                "observed_open_ports": len(results),
                "authorized_ports": authorized_count,
                "outside_scope_ports": outside_scope_count,
                "requires_review": review_count,
            },
            "assessment_note": (
                "Outside-scope ports are observations requiring review; "
                "they are not automatically classified as unnecessary, "
                "vulnerable, or unauthorized."
            ),
            "analyzed_at": now_iso() if status == "completed" else "",
            "notes": "",
        },
    }


def load_exposure() -> dict[str, Any]:
    data = load_yaml(exposure_file(), "exposure.yaml")
    require_project_id(data, "exposure.yaml")

    exposure = nested_payload(data, "exposure")
    status = str(exposure.get("status", "")).strip().lower()

    if status not in VALID_STATUSES:
        raise ExposureAnalysisError(
            f"Status exposure tidak valid: {status or '-'}"
        )

    return data


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init() -> int:
    network_data = load_network()
    scope_data = load_scope()
    service_data = load_service_optional()

    exposure_dir().mkdir(parents=True, exist_ok=True)
    data = build_document(
        network_data=network_data,
        scope_data=scope_data,
        service_data=service_data,
        status="not-started",
    )

    save_yaml(exposure_file(), data)
    record("Unnecessary port exposure analysis initialized", "in-progress")

    exposure = data["exposure"]
    summary = exposure["summary"]

    print("[PASS] Unnecessary Port Exposure berhasil diinisialisasi.")
    print(f"PROJECT        : {project_root().name}")
    print(f"TARGET         : {exposure['target_ip']}")
    print(f"OPEN PORTS     : {summary['observed_open_ports']}")
    print(
        "AUTHORIZED     : "
        + ", ".join(map(str, exposure["authorized_ports"]))
        if exposure["authorized_ports"]
        else "AUTHORIZED     : -"
    )
    print(f"FILE           : {exposure_file()}")

    return 0


def cmd_analyze() -> int:
    network_data = load_network()
    scope_data = load_scope()
    service_data = load_service_optional()

    data = load_exposure()
    exposure = data["exposure"]

    new_document = build_document(
        network_data=network_data,
        scope_data=scope_data,
        service_data=service_data,
        status="completed",
    )

    new_exposure = new_document["exposure"]
    new_exposure["updated_at"] = now_iso()

    exposure.clear()
    exposure.update(new_exposure)
    data["updated_at"] = now_iso()

    save_yaml(exposure_file(), data)
    record("Unnecessary port exposure analysis completed", "completed")

    summary = exposure["summary"]

    print("[PASS] Unnecessary Port Exposure berhasil dianalisis.")
    print(f"PROJECT            : {project_root().name}")
    print(f"TARGET             : {exposure['target_ip']}")
    print(f"OBSERVED OPEN      : {summary['observed_open_ports']}")
    print(f"AUTHORIZED         : {summary['authorized_ports']}")
    print(f"OUTSIDE SCOPE      : {summary['outside_scope_ports']}")
    print(f"REQUIRES REVIEW    : {summary['requires_review']}")
    print(f"STATUS             : {exposure['status']}")
    print(f"FILE               : {exposure_file()}")

    return 0


def cmd_list() -> int:
    data = load_exposure()
    exposure = data["exposure"]
    results = exposure.get("results") or []

    print(f"PROJECT: {data.get('project_id', '-')}")
    print(f"STATUS : {exposure.get('status', '-')}")
    print(f"TARGET : {exposure.get('target_ip', '-')}")
    print()

    if not results:
        print("[none]")
        return 0

    print(
        f"{'PORT':<7}"
        f"{'PROTO':<8}"
        f"{'SERVICE':<18}"
        f"{'SCOPE':<16}"
        f"{'ASSESSMENT':<18}"
        f"{'REVIEW':<8}"
    )
    print("-" * 90)

    for item in results:
        print(
            f"{str(item.get('port', '-')):<7}"
            f"{str(item.get('protocol', '-')):<8}"
            f"{str(item.get('detected_service') or item.get('observed_service') or '-'):<18}"
            f"{str(item.get('scope_status', '-')):<16}"
            f"{str(item.get('assessment', '-')):<18}"
            f"{str(item.get('requires_review', False)):<8}"
        )

    return 0


def cmd_show() -> int:
    data = load_exposure()

    print(f"PROJECT: {data.get('project_id', '-')}")
    print(f"FILE   : {exposure_file()}")
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


def cmd_status() -> int:
    data = load_exposure()
    exposure = data["exposure"]
    summary = exposure.get("summary") or {}

    print(f"Project ID        : {data.get('project_id', '-')}")
    print(f"Status             : {exposure.get('status', '-')}")
    print(f"Target IP          : {exposure.get('target_ip', '-')}")
    print(f"Hostname           : {exposure.get('hostname', '-')}")
    print(f"Observed open      : {summary.get('observed_open_ports', 0)}")
    print(f"Authorized         : {summary.get('authorized_ports', 0)}")
    print(f"Outside scope      : {summary.get('outside_scope_ports', 0)}")
    print(f"Requires review    : {summary.get('requires_review', 0)}")
    print(f"File               : {exposure_file()}")

    return 0


def cmd_verify() -> int:
    data = load_exposure()
    exposure = data["exposure"]
    errors: list[str] = []

    if exposure.get("checklist_id") != CHECKLIST_ID:
        errors.append("Checklist ID tidak sesuai 3-003.")

    status = str(exposure.get("status", "")).strip().lower()
    if status != "completed":
        errors.append(
            f"Status exposure belum completed: {status or '-'}"
        )

    for field in (
        "application",
        "target_url",
        "hostname",
        "target_ip",
        "scope_reference",
    ):
        if not str(exposure.get(field, "")).strip():
            errors.append(f"Field '{field}' kosong.")

    authorized_ports = exposure.get("authorized_ports")
    if not isinstance(authorized_ports, list):
        errors.append("authorized_ports harus berupa list.")
    else:
        for value in authorized_ports:
            try:
                port = int(value)
            except (TypeError, ValueError):
                errors.append(f"Authorized port tidak valid: {value!r}")
                continue
            if not 1 <= port <= 65535:
                errors.append(f"Authorized port di luar rentang: {port}")

    results = exposure.get("results")
    if not isinstance(results, list):
        errors.append("results harus berupa list.")
        results = []

    for index, item in enumerate(results, start=1):
        if not isinstance(item, dict):
            errors.append(f"Result #{index} bukan mapping.")
            continue

        required = (
            "port",
            "protocol",
            "state",
            "scope_status",
            "assessment",
            "requires_review",
        )
        for field in required:
            if field not in item:
                errors.append(
                    f"Result #{index} tidak memiliki field '{field}'."
                )

        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            errors.append(f"Result #{index} memiliki port tidak valid.")
        else:
            if not 1 <= port <= 65535:
                errors.append(
                    f"Result #{index} memiliki port di luar rentang."
                )

        protocol = str(item.get("protocol", "")).strip().lower()
        if not protocol:
            errors.append(f"Result #{index} memiliki protocol kosong.")

        if str(item.get("scope_status", "")) not in {
            "in-scope",
            "outside-scope",
        }:
            errors.append(
                f"Result #{index} memiliki scope_status tidak valid."
            )

        if str(item.get("assessment", "")) not in VALID_ASSESSMENTS:
            errors.append(
                f"Result #{index} memiliki assessment tidak valid."
            )

        if not isinstance(item.get("requires_review"), bool):
            errors.append(
                f"Result #{index} memiliki requires_review bukan boolean."
            )

    summary = exposure.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary harus berupa mapping/object.")
    else:
        for key in (
            "observed_open_ports",
            "authorized_ports",
            "outside_scope_ports",
            "requires_review",
        ):
            if not isinstance(summary.get(key), int):
                errors.append(f"summary.{key} harus berupa integer.")

    if errors:
        print("[FAIL] Unnecessary Port Exposure verification gagal.")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("[PASS] Unnecessary Port Exposure memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status    : {status}")
    print(f"[PASS] Target    : {exposure.get('target_ip', '-')}")
    print(
        f"[PASS] Open ports: "
        f"{summary.get('observed_open_ports', 0) if isinstance(summary, dict) else 0}"
    )
    print(
        f"[PASS] Outside-scope: "
        f"{summary.get('outside_scope_ports', 0) if isinstance(summary, dict) else 0}"
    )
    print(
        "[PASS] Assessment: outside-scope tidak otomatis dianggap unnecessary/vulnerability."
    )

    record("Unnecessary port exposure analysis verified", "completed")
    return 0


def cmd_remove() -> int:
    path = exposure_dir()

    if not path.exists():
        print("[INFO] Unnecessary Port Exposure belum ada.")
        return 0

    confirm = input(
        "Hapus seluruh data Unnecessary Port Exposure untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(path)
    record("Unnecessary port exposure data removed", "completed")

    print("[PASS] Unnecessary Port Exposure berhasil dihapus.")
    return 0


def cmd_version() -> int:
    print(f"BrebesKab-CSIRT-Tools exposure.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : Evidence correlation only")
    print("Baseline : 02-reconnaissance/network/network.yaml")
    print("Scope    : 01-preparation/scope/scope.yaml")
    print("Service  : 03-infrastructure/service/service.yaml")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Unnecessary Port Exposure\n"
        "\n"
        "Checklist:\n"
        "  3-003 Unnecessary port exposure\n"
        "\n"
        "Usage:\n"
        "  python scripts/infrastructure/exposure.py init\n"
        "  python scripts/infrastructure/exposure.py analyze\n"
        "  python scripts/infrastructure/exposure.py list\n"
        "  python scripts/infrastructure/exposure.py show\n"
        "  python scripts/infrastructure/exposure.py verify\n"
        "  python scripts/infrastructure/exposure.py status\n"
        "  python scripts/infrastructure/exposure.py remove\n"
        "  python scripts/infrastructure/exposure.py version\n"
        "\n"
        "Design:\n"
        "  - Uses completed Recon network.yaml as the observed-open baseline.\n"
        "  - Uses preparation scope.yaml as the authorization boundary.\n"
        "  - Uses service.yaml as service metadata when available.\n"
        "  - Does not perform scanning or exploitation.\n"
        "  - Outside-scope ports are not automatically vulnerabilities.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Infrastructure Unnecessary Port Exposure - checklist 3-003",
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

        raise ExposureAnalysisError(f"Command tidak dikenal: {args.command}")

    except ExposureAnalysisError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Dibatalkan oleh pengguna.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
