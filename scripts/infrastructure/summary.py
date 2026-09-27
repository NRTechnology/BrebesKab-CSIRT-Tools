#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Infrastructure - Infrastructure Summary

Phase : 03 Infrastructure
Item  : 03-011 Infrastructure Summary
Version: 1.0.0

Purpose:
    Consolidate the completed infrastructure assessment results into one
    summary document for the current pentest project.

Design:
    - "init" creates the summary document structure.
    - "generate" reads the infrastructure and reconnaissance source documents
      and updates summary.yaml.
    - "show" displays the generated summary.
    - "verify" validates the summary and marks it completed.
    - No network requests are performed by this module.
    - No vulnerability testing is performed.
    - No credentials, tokens, cookie values, response bodies, or raw probe
      payloads are copied into the summary.
    - Existing assessment documents remain the source of truth.
    - The summary is an aggregation layer, not a replacement for evidence.

Infrastructure checklists:
    3-001 TCP port scanning
    3-002 Service enumeration
    3-003 Unnecessary port exposure
    3-004 Administrative service exposure
    3-005 IPv6 exposure
    3-006 HTTP configuration
    3-007 HTTPS configuration
    3-008 TLS protocol
    3-009 TLS cipher
    3-010 Certificate validation

Input documents:
    02-reconnaissance/network/network.yaml
    03-infrastructure/service/service.yaml
    03-infrastructure/exposure/exposure.yaml
    03-infrastructure/admin/admin.yaml
    03-infrastructure/ipv6/ipv6.yaml
    03-infrastructure/http/http.yaml
    03-infrastructure/https/https.yaml
    03-infrastructure/tls/tls.yaml
    03-infrastructure/certificate/certificate.yaml

Output:
    03-infrastructure/summary/summary.yaml
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

# Prevent local script names from shadowing Python standard-library modules.
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent
script_dir_string = str(SCRIPT_DIR)

sys.path[:] = [
    entry for entry in sys.path
    if entry != script_dir_string
]

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

import yaml

from activity import record_activity
from context import require_active_project


VERSION = "1.0.0"

RECON_DIR_NAME = "02-reconnaissance"
INFRA_DIR_NAME = "03-infrastructure"
SUMMARY_DIR_NAME = "summary"
SUMMARY_FILE_NAME = "summary.yaml"

VALID_STATUSES = {
    "not-started",
    "in-progress",
    "completed",
}

CHECKLISTS = (
    {
        "id": "3-001",
        "name": "TCP port scanning",
        "source_key": "network",
        "relative_path": Path(RECON_DIR_NAME) / "network" / "network.yaml",
        "root_key": "network",
    },
    {
        "id": "3-002",
        "name": "Service enumeration",
        "source_key": "service",
        "relative_path": Path(INFRA_DIR_NAME) / "service" / "service.yaml",
        "root_key": "service",
    },
    {
        "id": "3-003",
        "name": "Unnecessary port exposure",
        "source_key": "exposure",
        "relative_path": Path(INFRA_DIR_NAME) / "exposure" / "exposure.yaml",
        "root_key": "exposure",
    },
    {
        "id": "3-004",
        "name": "Administrative service exposure",
        "source_key": "admin",
        "relative_path": Path(INFRA_DIR_NAME) / "admin" / "admin.yaml",
        "root_key": "admin",
    },
    {
        "id": "3-005",
        "name": "IPv6 exposure",
        "source_key": "ipv6",
        "relative_path": Path(INFRA_DIR_NAME) / "ipv6" / "ipv6.yaml",
        "root_key": "ipv6",
    },
    {
        "id": "3-006",
        "name": "HTTP configuration",
        "source_key": "http",
        "relative_path": Path(INFRA_DIR_NAME) / "http" / "http.yaml",
        "root_key": "http",
    },
    {
        "id": "3-007",
        "name": "HTTPS configuration",
        "source_key": "https",
        "relative_path": Path(INFRA_DIR_NAME) / "https" / "https.yaml",
        "root_key": "https",
    },
    {
        "id": "3-008",
        "name": "TLS protocol",
        "source_key": "tls",
        "relative_path": Path(INFRA_DIR_NAME) / "tls" / "tls.yaml",
        "root_key": "tls",
    },
    {
        "id": "3-009",
        "name": "TLS cipher",
        "source_key": "tls",
        "relative_path": Path(INFRA_DIR_NAME) / "tls" / "tls.yaml",
        "root_key": "tls",
    },
    {
        "id": "3-010",
        "name": "Certificate validation",
        "source_key": "certificate",
        "relative_path": Path(INFRA_DIR_NAME) / "certificate" / "certificate.yaml",
        "root_key": "certificate",
    },
)

UNIQUE_SOURCE_KEYS = (
    "network",
    "service",
    "exposure",
    "admin",
    "ipv6",
    "http",
    "https",
    "tls",
    "certificate",
)


def now_iso() -> str:
    jakarta = timezone(timedelta(hours=7))
    return datetime.now(jakarta).isoformat(timespec="seconds")


def project_context():
    return require_active_project()


def infra_root() -> Path:
    return project_context().project_path / INFRA_DIR_NAME


def summary_file() -> Path:
    return infra_root() / SUMMARY_DIR_NAME / SUMMARY_FILE_NAME


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


def source_path(source_key: str) -> Path:
    config = next(
        item for item in CHECKLISTS
        if item["source_key"] == source_key
    )
    return project_context().project_path / config["relative_path"]


def source_config(source_key: str) -> dict[str, Any]:
    for item in CHECKLISTS:
        if item["source_key"] == source_key:
            return item
    raise ValueError(f"Source key tidak dikenal: {source_key}")


def load_source_documents() -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}

    for source_key in UNIQUE_SOURCE_KEYS:
        documents[source_key] = load_yaml(source_path(source_key))

    return documents


def get_module_payload(name: str, data: dict[str, Any]) -> dict[str, Any]:
    nested = data.get(name)

    if isinstance(nested, dict):
        return nested

    return data


def module_status(name: str, data: dict[str, Any]) -> str:
    payload = get_module_payload(name, data)
    status = payload.get("status")

    if isinstance(status, str):
        return status.strip().lower()

    status = data.get("status")
    if isinstance(status, str):
        return status.strip().lower()

    return ""


def require_project_id(
    data: dict[str, Any],
    name: str,
) -> None:
    ctx = project_context()
    project_id = str(data.get("project_id", "")).strip()

    if project_id != ctx.project_id:
        raise RuntimeError(
            f"Project ID pada {name}.yaml tidak sesuai active project. "
            f"Context: {ctx.project_id}; File: {project_id or '-'}"
        )


def validate_source_documents(
    documents: dict[str, dict[str, Any]],
) -> dict[str, str]:
    statuses: dict[str, str] = {}

    for source_key, data in documents.items():
        require_project_id(data, source_key)

        status = module_status(source_key, data)
        statuses[source_key] = status

        if status not in VALID_STATUSES:
            raise RuntimeError(
                f"Status {source_key} tidak valid: {status or '-'}"
            )

    return statuses


def require_completed_sources(
    statuses: dict[str, str],
) -> None:
    incomplete = [
        source_key
        for source_key in UNIQUE_SOURCE_KEYS
        if statuses.get(source_key) != "completed"
    ]

    if incomplete:
        raise RuntimeError(
            "Infrastructure belum lengkap. Source yang belum completed: "
            + ", ".join(incomplete)
        )


def value_from_first(
    documents: dict[str, dict[str, Any]],
    field: str,
) -> str:
    for source_key in UNIQUE_SOURCE_KEYS:
        data = documents.get(source_key, {})
        value = data.get(field)

        if value is not None:
            value_string = str(value).strip()
            if value_string:
                return value_string

        payload = get_module_payload(source_key, data)
        value = payload.get(field)

        if value is not None:
            value_string = str(value).strip()
            if value_string:
                return value_string

    return ""


def normalize_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def unique_strings(values: list[Any]) -> list[str]:
    result: list[str] = []

    for value in values:
        item = str(value).strip()
        if item and item not in result:
            result.append(item)

    return result


def assessment_for(
    source_key: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    payload = get_module_payload(source_key, data)
    assessment = payload.get("assessment")

    if isinstance(assessment, dict):
        return assessment

    return {}


def requires_review_for(
    source_key: str,
    data: dict[str, Any],
    checklist_id: str | None = None,
) -> bool:
    payload = get_module_payload(source_key, data)

    if source_key == "tls" and checklist_id in {"3-008", "3-009"}:
        assessment = payload.get("assessment")
        if isinstance(assessment, dict):
            section_name = "protocol" if checklist_id == "3-008" else "cipher"
            section = assessment.get(section_name)
            if isinstance(section, dict):
                value = section.get("requires_review")
                if isinstance(value, bool):
                    return value
                if isinstance(value, (int, float)):
                    return value > 0
        return False

    summary = payload.get("summary")
    if isinstance(summary, dict):
        value = summary.get("requires_review")

        if isinstance(value, bool):
            return value

        if isinstance(value, (int, float)):
            return value > 0

    assessment = payload.get("assessment")
    if isinstance(assessment, dict):
        for field in ("requires_review", "overall_requires_review"):
            value = assessment.get(field)

            if isinstance(value, bool):
                return value

            if isinstance(value, (int, float)):
                return value > 0

    return False


def result_for(
    source_key: str,
    data: dict[str, Any],
    checklist_id: str | None = None,
) -> str:
    payload = get_module_payload(source_key, data)

    if source_key == "tls" and checklist_id in {"3-008", "3-009"}:
        assessment = payload.get("assessment")
        if isinstance(assessment, dict):
            section_name = "protocol" if checklist_id == "3-008" else "cipher"
            section = assessment.get(section_name)
            if isinstance(section, dict):
                result = section.get("result")
                if isinstance(result, str) and result.strip():
                    return result.strip()
        return ""

    assessment = payload.get("assessment")
    if isinstance(assessment, dict):
        result = assessment.get("result")

        if isinstance(result, str) and result.strip():
            return result.strip()

        result = assessment.get("overall_result")
        if isinstance(result, str) and result.strip():
            return result.strip()

    summary = payload.get("summary")
    if isinstance(summary, dict):
        result = summary.get("result")

        if isinstance(result, str) and result.strip():
            return result.strip()

    return ""


def build_checklist_records(
    documents: dict[str, dict[str, Any]],
    statuses: dict[str, str],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for checklist in CHECKLISTS:
        source_key = checklist["source_key"]
        data = documents[source_key]

        assessment = assessment_for(source_key, data)
        payload = get_module_payload(source_key, data)

        record: dict[str, Any] = {
            "id": checklist["id"],
            "name": checklist["name"],
            "source": str(checklist["relative_path"]).replace("\\", "/"),
            "source_key": source_key,
            "status": statuses[source_key],
            "result": result_for(
                source_key,
                data,
                checklist["id"],
            ),
            "requires_review": requires_review_for(
                source_key,
                data,
                checklist["id"],
            ),
        }

        if checklist["id"] in {"3-008", "3-009"}:
            record["focus"] = (
                "Accepted TLS protocol versions"
                if checklist["id"] == "3-008"
                else "Accepted TLS cipher suites"
            )

            if checklist["id"] == "3-008":
                protocol = assessment.get("protocol", {})
                if isinstance(protocol, dict):
                    record["accepted"] = normalize_list(
                        protocol.get("accepted_modern")
                    )
                    record["rejected_legacy"] = normalize_list(
                        protocol.get("rejected_legacy")
                    )

            if checklist["id"] == "3-009":
                cipher = assessment.get("cipher", {})
                if isinstance(cipher, dict):
                    record["coverage"] = cipher.get("coverage")
                    record["enumeration_complete"] = cipher.get(
                        "enumeration_complete"
                    )
                    record["observed_ciphers"] = unique_strings(
                        normalize_list(cipher.get("modern_observed"))
                        + normalize_list(cipher.get("legacy_observed"))
                        + normalize_list(cipher.get("unknown_observed"))
                    )

        if checklist["id"] == "3-003":
            summary = payload.get("summary", {})
            if isinstance(summary, dict):
                record["observed_open_ports"] = summary.get(
                    "observed_open_ports"
                )
                record["authorized_ports"] = summary.get(
                    "authorized_ports"
                )
                record["outside_scope_ports"] = summary.get(
                    "outside_scope_ports"
                )
                record["review_count"] = summary.get("requires_review")

        if checklist["id"] == "3-004":
            summary = payload.get("summary", {})
            if isinstance(summary, dict):
                record["web_management_candidates"] = summary.get(
                    "web_management_candidates"
                )
                record["administrative_services"] = summary.get(
                    "administrative_services"
                )
                record["review_count"] = summary.get("requires_review")

        if checklist["id"] == "3-005":
            summary = payload.get("summary", {})
            if isinstance(summary, dict):
                record["ipv6_addresses"] = summary.get(
                    "confirmed_ipv6_addresses"
                )
                record["open_ipv6_services"] = summary.get(
                    "open_ipv6_services"
                )

        if checklist["id"] == "3-006":
            record["initial_status_code"] = assessment.get(
                "initial_status_code"
            )
            record["redirects_to_https"] = assessment.get(
                "redirects_to_https"
            )
            record["served_over_http"] = assessment.get(
                "served_over_http"
            )

        if checklist["id"] == "3-007":
            record["initial_status_code"] = assessment.get(
                "initial_status_code"
            )
            record["https_available"] = assessment.get(
                "https_available"
            )
            record["served_over_https"] = assessment.get(
                "served_over_https"
            )
            record["redirects_within_https"] = assessment.get(
                "redirects_within_https"
            )
            record["redirects_to_http"] = assessment.get(
                "redirects_to_http"
            )

        if checklist["id"] == "3-010":
            record["hostname"] = (
                assessment.get("hostname", {})
                if isinstance(assessment.get("hostname"), dict)
                else {}
            )
            record["validity"] = (
                assessment.get("validity", {})
                if isinstance(assessment.get("validity"), dict)
                else {}
            )
            record["trust"] = (
                assessment.get("trust", {})
                if isinstance(assessment.get("trust"), dict)
                else {}
            )

        records.append(record)

    return records


def build_review_items(
    documents: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []

    # 3-003
    exposure = documents["exposure"].get("exposure", documents["exposure"])
    exposure_summary = (
        exposure.get("summary", {})
        if isinstance(exposure, dict)
        else {}
    )

    if isinstance(exposure_summary, dict):
        count = exposure_summary.get("requires_review", 0)
        if isinstance(count, (int, float)) and count > 0:
            items.append(
                {
                    "checklist": "3-003",
                    "name": "Unnecessary port exposure",
                    "result": "requires-review",
                    "requires_review": True,
                    "detail": (
                        f"{int(count)} observed open port(s) are outside the "
                        "authorized port scope and require review. This is "
                        "an observation, not an automatic vulnerability finding."
                    ),
                }
            )

    # 3-004
    admin = documents["admin"].get("admin", documents["admin"])
    admin_summary = (
        admin.get("summary", {})
        if isinstance(admin, dict)
        else {}
    )

    if isinstance(admin_summary, dict):
        count = admin_summary.get("requires_review", 0)
        if isinstance(count, (int, float)) and count > 0:
            candidates = admin_summary.get(
                "web_management_candidates",
                0,
            )
            items.append(
                {
                    "checklist": "3-004",
                    "name": "Administrative service exposure",
                    "result": "requires-review",
                    "requires_review": True,
                    "detail": (
                        f"{int(candidates or 0)} web-management candidate(s) "
                        f"and {int(count)} review condition(s) were recorded. "
                        "HTTP 200 candidate classification does not itself "
                        "prove administrative function or vulnerability."
                    ),
                }
            )

    # 3-006
    http = documents["http"].get("http", documents["http"])
    http_assessment = (
        http.get("assessment", {})
        if isinstance(http, dict)
        else {}
    )

    if (
        isinstance(http_assessment, dict)
        and http_assessment.get("requires_review") is True
    ):
        result = str(
            http_assessment.get("result", "requires-review")
        ).strip()

        items.append(
            {
                "checklist": "3-006",
                "name": "HTTP configuration",
                "result": result,
                "requires_review": True,
                "detail": (
                    "HTTP behavior requires review according to the "
                    "3-006 assessment evidence."
                ),
            }
        )

    # 3-009
    tls = documents["tls"].get("tls", documents["tls"])
    tls_assessment = (
        tls.get("assessment", {})
        if isinstance(tls, dict)
        else {}
    )
    cipher = (
        tls_assessment.get("cipher", {})
        if isinstance(tls_assessment, dict)
        else {}
    )

    if isinstance(cipher, dict) and cipher.get("requires_review") is True:
        items.append(
            {
                "checklist": "3-009",
                "name": "TLS cipher",
                "result": str(
                    cipher.get(
                        "result",
                        "requires-review",
                    )
                ).strip(),
                "requires_review": True,
                "detail": (
                    "Cipher evidence coverage is partial. OpenSSL "
                    "s_client negotiated ciphers are observations and do "
                    "not constitute complete cipher enumeration."
                ),
            }
        )

    # Generic fallback for any future completed source with an explicit
    # requires_review state that is not already represented above.
    represented = {
        item["checklist"]
        for item in items
    }

    for checklist in CHECKLISTS:
        if checklist["id"] in represented:
            continue

        source_key = checklist["source_key"]
        if requires_review_for(
            source_key,
            documents[source_key],
            checklist["id"],
        ):
            items.append(
                {
                    "checklist": checklist["id"],
                    "name": checklist["name"],
                    "result": result_for(
                        source_key,
                        documents[source_key],
                        checklist["id"],
                    ) or "requires-review",
                    "requires_review": True,
                    "detail": (
                        "Source module reports requires_review=true."
                    ),
                }
            )

    return items


def build_highlights(
    documents: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    network = documents["network"].get(
        "network",
        documents["network"],
    )
    service = documents["service"].get(
        "service",
        documents["service"],
    )
    exposure = documents["exposure"].get(
        "exposure",
        documents["exposure"],
    )
    admin = documents["admin"].get(
        "admin",
        documents["admin"],
    )
    ipv6 = documents["ipv6"].get(
        "ipv6",
        documents["ipv6"],
    )
    http = documents["http"].get(
        "http",
        documents["http"],
    )
    https = documents["https"].get(
        "https",
        documents["https"],
    )
    tls = documents["tls"].get(
        "tls",
        documents["tls"],
    )
    certificate = documents["certificate"].get(
        "certificate",
        documents["certificate"],
    )

    network_summary = (
        network.get("summary", {})
        if isinstance(network, dict)
        else {}
    )
    exposure_summary = (
        exposure.get("summary", {})
        if isinstance(exposure, dict)
        else {}
    )
    service_summary = (
        service.get("summary", {})
        if isinstance(service, dict)
        else {}
    )
    admin_summary = (
        admin.get("summary", {})
        if isinstance(admin, dict)
        else {}
    )
    ipv6_summary = (
        ipv6.get("summary", {})
        if isinstance(ipv6, dict)
        else {}
    )
    http_assessment = (
        http.get("assessment", {})
        if isinstance(http, dict)
        else {}
    )
    https_assessment = (
        https.get("assessment", {})
        if isinstance(https, dict)
        else {}
    )
    tls_assessment = (
        tls.get("assessment", {})
        if isinstance(tls, dict)
        else {}
    )
    tls_protocol = (
        tls_assessment.get("protocol", {})
        if isinstance(tls_assessment, dict)
        else {}
    )
    tls_cipher = (
        tls_assessment.get("cipher", {})
        if isinstance(tls_assessment, dict)
        else {}
    )
    cert_assessment = (
        certificate.get("assessment", {})
        if isinstance(certificate, dict)
        else {}
    )

    return {
        "network": {
            "observed_open_ports": (
                network_summary.get("open_ports")
                or network_summary.get("observed_open_ports")
            ),
            "ports": network.get("ports", [])
            if isinstance(network, dict)
            else [],
        },
        "service": {
            "ports_enumerated": service_summary.get("ports_enumerated"),
            "services_found": service_summary.get("services_found"),
            "open_services": service_summary.get("open_services"),
        },
        "exposure": {
            "observed_open_ports": exposure_summary.get(
                "observed_open_ports"
            ),
            "authorized_ports": exposure_summary.get(
                "authorized_ports"
            ),
            "outside_scope_ports": exposure_summary.get(
                "outside_scope_ports"
            ),
            "requires_review": exposure_summary.get(
                "requires_review"
            ),
        },
        "administrative": {
            "administrative_services": admin_summary.get(
                "administrative_services"
            ),
            "management_capable_services": admin_summary.get(
                "management_capable_services"
            ),
            "web_management_candidates": admin_summary.get(
                "web_management_candidates"
            ),
            "requires_review": admin_summary.get("requires_review"),
        },
        "ipv6": {
            "baseline_addresses": ipv6_summary.get(
                "baseline_ipv6_addresses"
            ),
            "dns_addresses": ipv6_summary.get(
                "dns_ipv6_addresses"
            ),
            "confirmed_addresses": ipv6_summary.get(
                "confirmed_ipv6_addresses"
            ),
            "open_services": ipv6_summary.get(
                "open_ipv6_services"
            ),
            "requires_review": ipv6_summary.get(
                "requires_review"
            ),
        },
        "http": {
            "status_code": http_assessment.get(
                "initial_status_code"
            ),
            "served_over_http": http_assessment.get(
                "served_over_http"
            ),
            "redirects_to_https": http_assessment.get(
                "redirects_to_https"
            ),
            "result": http_assessment.get("result"),
            "requires_review": http_assessment.get(
                "requires_review"
            ),
        },
        "https": {
            "status_code": https_assessment.get(
                "initial_status_code"
            ),
            "https_available": https_assessment.get(
                "https_available"
            ),
            "served_over_https": https_assessment.get(
                "served_over_https"
            ),
            "redirects_within_https": https_assessment.get(
                "redirects_within_https"
            ),
            "redirects_to_http": https_assessment.get(
                "redirects_to_http"
            ),
            "result": https_assessment.get("result"),
            "requires_review": https_assessment.get(
                "requires_review"
            ),
        },
        "tls": {
            "accepted_modern": normalize_list(
                tls_protocol.get("accepted_modern")
            ),
            "rejected_legacy": normalize_list(
                tls_protocol.get("rejected_legacy")
            ),
            "protocol_result": tls_protocol.get("result"),
            "cipher_result": tls_cipher.get("result"),
            "ciphers_observed": unique_strings(
                normalize_list(tls_cipher.get("modern_observed"))
                + normalize_list(tls_cipher.get("legacy_observed"))
                + normalize_list(tls_cipher.get("unknown_observed"))
            ),
            "cipher_enumeration_complete": tls_cipher.get(
                "enumeration_complete"
            ),
            "cipher_coverage": tls_cipher.get("coverage"),
            "requires_review": tls_assessment.get(
                "overall_requires_review"
            ),
        },
        "certificate": {
            "result": cert_assessment.get("result"),
            "requires_review": cert_assessment.get(
                "requires_review"
            ),
            "hostname": (
                cert_assessment.get("hostname", {})
                if isinstance(
                    cert_assessment.get("hostname"),
                    dict,
                )
                else {}
            ),
            "validity": (
                cert_assessment.get("validity", {})
                if isinstance(
                    cert_assessment.get("validity"),
                    dict,
                )
                else {}
            ),
            "trust": (
                cert_assessment.get("trust", {})
                if isinstance(
                    cert_assessment.get("trust"),
                    dict,
                )
                else {}
            ),
        },
    }


def build_summary(
    documents: dict[str, dict[str, Any]],
    statuses: dict[str, str],
) -> dict[str, Any]:
    ctx = project_context()

    application = value_from_first(
        documents,
        "application",
    )

    target_url = value_from_first(
        documents,
        "target_url",
    )

    hostname = value_from_first(
        documents,
        "hostname",
    )

    environment = value_from_first(
        documents,
        "environment",
    )

    assessment_type = value_from_first(
        documents,
        "assessment_type",
    )

    scope_reference = value_from_first(
        documents,
        "scope_reference",
    )

    checklist_records = build_checklist_records(
        documents,
        statuses,
    )

    review_items = build_review_items(documents)

    completed_count = sum(
        1
        for record in checklist_records
        if record["status"] == "completed"
    )
    review_count = sum(
        1
        for record in checklist_records
        if record["requires_review"] is True
    )

    summary_status = (
        "in-progress"
        if completed_count != len(CHECKLISTS)
        else "in-progress"
    )

    return {
        "schema_version": "1.0",
        "project_id": ctx.project_id,
        "status": summary_status,
        "application": application,
        "target_url": target_url,
        "hostname": hostname,
        "environment": environment,
        "assessment_type": assessment_type,
        "scope_reference": scope_reference,
        "infrastructure": {
            "checklists": {
                "total": len(CHECKLISTS),
                "completed": completed_count,
                "with_requires_review": review_count,
            },
            "status": (
                "completed"
                if completed_count == len(CHECKLISTS)
                else "incomplete"
            ),
            "modules": checklist_records,
            "assessment": {
                "requires_review": bool(review_items),
                "review_count": len(review_items),
                "review_items": review_items,
            },
            "highlights": build_highlights(documents),
        },
        "sources": {
            checklist["id"]: str(checklist["relative_path"]).replace(
                "\\",
                "/",
            )
            for checklist in CHECKLISTS
        },
        "notes": [
            "Summary is an aggregation layer; source YAML files remain authoritative.",
            "No network requests or active probes are performed by summary.py.",
            "requires_review indicates an assessment condition requiring analyst review; it is not an automatic vulnerability finding.",
            "TLS cipher coverage remains partial when enumeration_complete=false.",
            "Certificate validation remains owned by checklist 3-010.",
        ],
        "generated_at": now_iso(),
    }


def cmd_init() -> int:
    ctx = project_context()
    path = summary_file()

    if path.exists():
        raise RuntimeError(
            f"Summary sudah ada: {path}\n"
            "Gunakan 'generate' untuk memperbarui hasil summary."
        )

    data = {
        "schema_version": "1.0",
        "project_id": ctx.project_id,
        "status": "not-started",
        "application": "",
        "target_url": "",
        "hostname": "",
        "environment": "",
        "assessment_type": "",
        "scope_reference": "",
        "infrastructure": {
            "checklists": {
                "total": len(CHECKLISTS),
                "completed": 0,
                "with_requires_review": 0,
            },
            "status": "incomplete",
            "modules": [],
            "assessment": {
                "requires_review": False,
                "review_count": 0,
                "review_items": [],
            },
            "highlights": {},
        },
        "sources": {},
        "notes": [],
        "generated_at": "",
    }

    save_yaml(path, data)

    print("[PASS] Infrastructure Summary berhasil diinisialisasi.")
    print(f"PROJECT: {ctx.project_id}")
    print(f"FILE   : {path}")

    return 0


def cmd_generate() -> int:
    ctx = project_context()

    documents = load_source_documents()
    statuses = validate_source_documents(documents)
    require_completed_sources(statuses)

    summary = build_summary(documents, statuses)
    save_yaml(summary_file(), summary)

    record_activity(
        phase="03-infrastructure",
        item="03-011",
        action="Infrastructure summary generated",
        status="in-progress",
    )

    checklist_count = summary["infrastructure"]["checklists"]["completed"]
    review_count = summary["infrastructure"]["assessment"]["review_count"]

    print("[PASS] Infrastructure Summary berhasil dibuat.")
    print(f"PROJECT       : {ctx.project_id}")
    print(f"FILE          : {summary_file()}")
    print(f"CHECKLISTS    : {checklist_count}/{len(CHECKLISTS)} completed")
    print(f"REQUIRES REVIEW: {review_count}")

    return 0


def cmd_show() -> int:
    ctx = project_context()
    path = summary_file()

    data = load_yaml(path)

    print(f"PROJECT: {ctx.project_id}")
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


def validate_summary(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    ctx = project_context()

    if str(data.get("project_id", "")).strip() != ctx.project_id:
        errors.append("Project ID tidak sesuai active project.")

    status = str(data.get("status", "")).strip().lower()
    if status not in VALID_STATUSES:
        errors.append("Status summary tidak valid.")

    required_top_level = (
        "application",
        "target_url",
        "hostname",
        "environment",
        "assessment_type",
        "scope_reference",
        "infrastructure",
        "sources",
    )

    for field in required_top_level:
        if field not in data:
            errors.append(
                f"Field wajib tidak ditemukan: {field}"
            )

    infrastructure = data.get("infrastructure")
    if not isinstance(infrastructure, dict):
        errors.append("Field infrastructure tidak valid.")
        return errors

    checklists = infrastructure.get("checklists")
    if not isinstance(checklists, dict):
        errors.append("Field infrastructure.checklists tidak valid.")
    else:
        total = checklists.get("total")
        completed = checklists.get("completed")

        if total != len(CHECKLISTS):
            errors.append(
                f"Total checklist harus {len(CHECKLISTS)}."
            )

        if completed != len(CHECKLISTS):
            errors.append(
                "Belum semua checklist infrastructure completed."
            )

    modules = infrastructure.get("modules")
    if not isinstance(modules, list):
        errors.append("Field infrastructure.modules tidak valid.")
    else:
        ids = {
            str(item.get("id", "")).strip()
            for item in modules
            if isinstance(item, dict)
        }

        missing = [
            checklist["id"]
            for checklist in CHECKLISTS
            if checklist["id"] not in ids
        ]

        if missing:
            errors.append(
                "Checklist belum terwakili: "
                + ", ".join(missing)
            )

        incomplete = [
            str(item.get("id", ""))
            for item in modules
            if isinstance(item, dict)
            and str(item.get("status", "")).strip().lower()
            != "completed"
        ]

        if incomplete:
            errors.append(
                "Checklist belum completed: "
                + ", ".join(incomplete)
            )

    assessment = infrastructure.get("assessment")
    if not isinstance(assessment, dict):
        errors.append(
            "Field infrastructure.assessment tidak valid."
        )

    sources = data.get("sources")
    if not isinstance(sources, dict):
        errors.append("Field sources tidak valid.")

    return errors


def cmd_verify() -> int:
    ctx = project_context()
    path = summary_file()

    data = load_yaml(path)
    errors = validate_summary(data)

    if errors:
        print("[FAIL] Infrastructure Summary belum memenuhi validasi.")
        for error in errors:
            print(f"  - {error}")
        return 1

    data["status"] = "completed"
    data["verified_at"] = now_iso()
    save_yaml(path, data)

    record_activity(
        phase="03-infrastructure",
        item="03-011",
        action="Infrastructure summary verified",
        status="completed",
    )

    infrastructure = data["infrastructure"]
    checklist_data = infrastructure["checklists"]
    review_data = infrastructure["assessment"]

    print("[PASS] Infrastructure Summary memenuhi validasi.")
    print("[PASS] Status       : completed")
    print(f"[PASS] Project      : {ctx.project_id}")
    print(
        "[PASS] Checklists   : "
        f"{checklist_data['completed']}/{checklist_data['total']}"
    )
    print(
        "[PASS] Review       : "
        f"{review_data['review_count']}"
    )

    return 0


def cmd_status() -> int:
    ctx = project_context()
    path = summary_file()

    if not path.exists():
        print(f"Project ID : {ctx.project_id}")
        print("Status     : not-initialized")
        return 0

    data = load_yaml(path)
    status = str(data.get("status", "unknown")).strip().lower()

    print(f"Project ID : {ctx.project_id}")
    print(f"Status     : {status}")

    return 0


def cmd_remove() -> int:
    ctx = project_context()
    path = summary_file()

    if not path.exists():
        print("[INFO] Infrastructure Summary belum ada.")
        return 0

    path.unlink()

    print("[PASS] Infrastructure Summary berhasil dihapus.")
    print(f"PROJECT: {ctx.project_id}")
    print(f"FILE   : {path}")

    return 0


def print_help() -> None:
    print(
        f"""BrebesKab-CSIRT-Tools
Infrastructure Summary v{VERSION}

Usage:
  python scripts/infrastructure/summary.py init
  python scripts/infrastructure/summary.py generate
  python scripts/infrastructure/summary.py show
  python scripts/infrastructure/summary.py verify
  python scripts/infrastructure/summary.py status
  python scripts/infrastructure/summary.py remove
  python scripts/infrastructure/summary.py version

Commands:
  init      Create summary.yaml.
  generate  Aggregate completed infrastructure documents.
  show      Show the complete summary document.
  verify    Validate the summary and mark completed.
  status    Show the current lifecycle status.
  remove    Remove summary.yaml.
  version   Show script version.

Aggregation:
  3-001  TCP port scanning
  3-002  Service enumeration
  3-003  Unnecessary port exposure
  3-004  Administrative service exposure
  3-005  IPv6 exposure
  3-006  HTTP configuration
  3-007  HTTPS configuration
  3-008  TLS protocol
  3-009  TLS cipher
  3-010  Certificate validation

No network requests or active probes are performed by this module.
"""
    )


def main() -> int:
    command = (
        sys.argv[1].strip().lower()
        if len(sys.argv) > 1
        else "help"
    )

    if command == "version":
        print(f"BrebesKab-CSIRT-Tools Infrastructure summary.py v{VERSION}")
        print("Phase    : 03 Infrastructure")
        print("Item     : 03-011 Infrastructure Summary")
        print("Schema   : 1.0")
        print("Sources  : 3-001 through 3-010")
        print("Boundary : aggregation only; no active probing")
        return 0

    try:
        if command == "init":
            return cmd_init()

        if command == "generate":
            return cmd_generate()

        if command == "show":
            return cmd_show()

        if command == "verify":
            return cmd_verify()

        if command == "status":
            return cmd_status()

        if command == "remove":
            return cmd_remove()

        if command in {"help", "-h", "--help"}:
            print_help()
            return 0

        print(f"[ERROR] Command tidak dikenal: {command}")
        print_help()
        return 2

    except (
        FileNotFoundError,
        RuntimeError,
        ValueError,
        yaml.YAMLError,
    ) as exc:
        print(f"[ERROR] {exc}")
        return 1
    except Exception as exc:
        print(
            "[ERROR] Unexpected failure: "
            f"{type(exc).__name__}: {exc}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
