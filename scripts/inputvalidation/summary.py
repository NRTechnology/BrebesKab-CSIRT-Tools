#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Input Validation Summary

Checklist:
    7-001 SQL Injection
    7-002 Cross-Site Scripting (XSS)
    7-003 Command Injection
    7-004 Path Traversal
    7-005 Expression / Template / Parser Injection
    7-006 HTTP Parameter Pollution
    7-007 Input Validation Summary

Design:
    - Aggregation only.
    - No network requests or active probes.
    - Reads input-validation checklist artifacts from the active project.
    - Does not create or infer new findings.
    - Preserves source assessment states and forensic signals.
    - Missing artifacts require an explicit operator status and reason.
    - CVE correlation is secondary metadata only.
    - Raw evidence remains untouched.
    - Report redaction belongs to the report-generation layer.

This script is intentionally independent from the individual assessment tools.
It discovers and aggregates their YAML artifacts; it does not rerun them.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("[FAIL] Dependency PyYAML tidak tersedia.")
    sys.exit(1)


VERSION = "1.0.1"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "7-007"
CHECKLIST_NAME = "Input Validation Summary"
PHASE = "07 Input Validation"

CHECKLISTS = [
    {
        "id": "7-001",
        "name": "SQL Injection",
        "directory": "sqli",
        "filename": "sqli.yaml",
        "expected_state": "completed",
    },
    {
        "id": "7-002",
        "name": "Cross-Site Scripting (XSS)",
        "directory": "xss",
        "filename": "xss.yaml",
        "expected_state": "completed",
    },
    {
        "id": "7-003",
        "name": "Command Injection",
        "directory": "command",
        "filename": "command.yaml",
        "expected_state": "completed",
    },
    {
        "id": "7-004",
        "name": "Path Traversal",
        "directory": "traversal",
        "filename": "traversal.yaml",
        "expected_state": "completed",
    },
    {
        "id": "7-005",
        "name": "Expression / Template / Parser Injection",
        "directory": "injection",
        "filename": "injection.yaml",
        "expected_state": "completed",
    },
    {
        "id": "7-006",
        "name": "HTTP Parameter Pollution",
        "directory": "parameter",
        "filename": "parameter.yaml",
        "expected_state": "completed",
    },
]

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def repo_root() -> Path:
    # scripts/inputvalidation/summary.py -> inputvalidation -> scripts -> repo
    return Path(__file__).resolve().parents[2]


def runtime_root() -> Path:
    return repo_root() / ".runtime"


def active_project_file() -> Path:
    return runtime_root() / "active-project.yaml"


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


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


def load_active_project() -> dict[str, Any]:
    path = active_project_file()
    if not path.exists():
        raise FileNotFoundError(f"Active project file tidak ditemukan: {path}")

    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ValueError("Active project file memiliki format yang tidak valid.")

    project_id = str(data.get("project_id", "")).strip()
    project_path = str(data.get("project_path", "")).strip()
    if not project_id:
        raise ValueError("project_id tidak ditemukan pada active-project.yaml.")
    if not project_path:
        raise ValueError("project_path tidak ditemukan pada active-project.yaml.")
    return data


def active_project_path(active_project: dict[str, Any]) -> Path:
    raw = str(active_project.get("project_path", "")).strip()
    path = Path(raw)
    if not path.is_absolute():
        path = repo_root() / path
    return path.resolve()


def summary_file() -> Path:
    active_project = load_active_project()
    return active_project_path(active_project) / "07-input-validation" / "summary" / "summary.yaml"


def checklist_file(project_path: Path, item: dict[str, str]) -> Path:
    return project_path / "07-input-validation" / item["directory"] / item["filename"]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "y", "1", "pass"}
    return False


def normalize_status(data: dict[str, Any]) -> str:
    """Read completion state across the two artifact schemas used in phase 07.

    Older 7-001/7-002/7-003/7-004 artifacts keep status in
    checklist.status, while newer 7-005/7-006 artifacts keep it in
    results.status.  The summary must treat both as authoritative source
    states rather than marking the latter as incomplete.
    """
    checklist = as_dict(data.get("checklist"))
    status = str(checklist.get("status", "")).strip().lower()
    if status:
        return status

    script = as_dict(data.get("script"))
    status = str(script.get("status", "")).strip().lower()
    if status:
        return status

    results = as_dict(data.get("results"))
    status = str(results.get("status", "")).strip().lower()
    if status:
        return status

    status = str(data.get("status", "")).strip().lower()
    return status or "unknown"


def assessment_result(data: dict[str, Any]) -> str:
    assessment = as_dict(data.get("assessment"))
    result = str(assessment.get("result", "")).strip().lower()
    if result:
        return result

    summary = as_dict(data.get("summary"))
    result = str(summary.get("result", "")).strip().lower()
    if result:
        return result

    # Newer phase-07 artifacts may omit a top-level assessment/summary and
    # expose only results.findings + results.requires_review.
    results = as_dict(data.get("results"))
    finding = results.get("findings")
    review = results.get("requires_review")

    try:
        if int(finding or 0) > 0:
            return "finding"
    except (TypeError, ValueError):
        if normalize_bool(finding):
            return "finding"

    try:
        if int(review or 0) > 0:
            return "requires_review"
    except (TypeError, ValueError):
        if normalize_bool(review):
            return "requires_review"

    if str(results.get("status", "")).strip().lower() == "completed":
        return "pass"

    return "unknown"


def assessment_finding(data: dict[str, Any]) -> bool:
    assessment = as_dict(data.get("assessment"))
    if "finding" in assessment:
        return normalize_bool(assessment.get("finding"))
    if "finding" in data:
        return normalize_bool(data.get("finding"))
    results = as_dict(data.get("results"))
    if "findings" in results:
        try:
            return int(results.get("findings", 0)) > 0
        except (TypeError, ValueError):
            return normalize_bool(results.get("findings"))
    return False


def assessment_review(data: dict[str, Any]) -> bool:
    assessment = as_dict(data.get("assessment"))
    if "requires_review" in assessment:
        return normalize_bool(assessment.get("requires_review"))
    if "requires_review" in data:
        return normalize_bool(data.get("requires_review"))
    results = as_dict(data.get("results"))
    if "requires_review" in results:
        try:
            return int(results.get("requires_review", 0)) > 0
        except (TypeError, ValueError):
            return normalize_bool(results.get("requires_review"))
    return False


def source_identity(data: dict[str, Any]) -> dict[str, Any]:
    tool = as_dict(data.get("tool"))
    script = as_dict(data.get("script"))
    checklist = as_dict(data.get("checklist"))
    target = as_dict(data.get("target"))

    script_name = str(tool.get("script", "") or script.get("script", "")).strip()
    version = str(tool.get("version", "") or script.get("version", "")).strip()
    checklist_id = str(checklist.get("id", "")).strip()
    checklist_name = str(checklist.get("name", "") or checklist.get("checklist", "")).strip()
    assessment_type = str(target.get("assessment_type", "") or target.get("mode", "")).strip()

    return {
        "script": script_name,
        "version": version,
        "checklist_id": checklist_id,
        "checklist_name": checklist_name,
        "assessment_type": assessment_type,
    }


def collect_cves(value: Any, found: set[str]) -> None:
    if isinstance(value, str):
        for match in CVE_RE.findall(value):
            found.add(match.upper())
        return
    if isinstance(value, dict):
        for child in value.values():
            collect_cves(child, found)
        return
    if isinstance(value, list):
        for child in value:
            collect_cves(child, found)


def cves_from_artifact(data: dict[str, Any]) -> list[str]:
    found: set[str] = set()
    collect_cves(data, found)
    return sorted(found)


def numeric_result(data: dict[str, Any], keys: tuple[str, ...]) -> int:
    containers = [
        as_dict(data.get("results")),
        as_dict(data.get("analysis")),
        as_dict(data.get("assessment")),
    ]
    for container in containers:
        for key in keys:
            if key in container:
                try:
                    return int(container[key])
                except (TypeError, ValueError):
                    pass
    return 0


def build_metrics(data: dict[str, Any]) -> dict[str, int]:
    """Collect common forensic/assessment counters without changing source data."""
    return {
        "links": numeric_result(data, ("links", "links_discovered", "same_origin_links")),
        "query_candidates": numeric_result(data, ("query_candidates", "query_parameter_candidates")),
        "get_forms": numeric_result(data, ("get_forms", "get_form_candidates")),
        "candidates": numeric_result(data, ("candidates", "candidate_count")),
        "tested": numeric_result(data, ("tested", "tested_parameters")),
        "probes": numeric_result(data, ("probes", "probes_sent", "probe_count")),
        "findings": numeric_result(data, ("findings", "finding_count")),
        "requires_review": numeric_result(data, ("requires_review", "review_count")),
        "request_errors": numeric_result(data, ("request_errors",)),
        "http_errors": numeric_result(data, ("http_errors",)),
    }


def build_checklist_entry(project_path: Path, item: dict[str, str]) -> dict[str, Any]:
    path = checklist_file(project_path, item)
    relative = path.relative_to(repo_root()).as_posix()

    entry: dict[str, Any] = {
        "id": item["id"],
        "name": item["name"],
        "source": relative,
        "source_exists": path.exists(),
        "expected_state": item["expected_state"],
    }

    if not path.exists():
        # Do not invent a finding or assessment state for a missing artifact.
        entry["status"] = "missing"
        entry["assessment_result"] = "missing"
        entry["finding"] = False
        entry["requires_review"] = False
        entry["cve_candidate_count"] = 0
        entry["cves"] = []
        entry["reason"] = "Checklist artifact tidak tersedia; status dan alasan harus ditetapkan secara eksplisit oleh operator."
        return entry

    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ValueError(f"Artifact {path} memiliki format YAML yang tidak valid.")

    status = normalize_status(data)
    result = assessment_result(data)
    finding = assessment_finding(data)
    review = assessment_review(data)
    cves = cves_from_artifact(data)

    entry.update(
        {
            "status": status,
            "assessment_result": result,
            "finding": finding,
            "requires_review": review,
            "cve_candidate_count": len(cves),
            "cves": cves,
            "source_identity": source_identity(data),
            "metrics": build_metrics(data),
        }
    )

    # Preserve useful high-level signals, without copying raw evidence into summary.
    methodology = as_dict(data.get("methodology"))
    if methodology:
        entry["methodology_flags"] = {
            key: methodology[key]
            for key in (
                "same_origin_only",
                "redirect_following",
                "get_only_probe_engine",
                "non_destructive_payloads_only",
                "automatic_finding",
                "order_sensitivity_requires_manual_review",
                "security_impact_required_for_finding",
                "forensic_evidence_preserved",
            )
            if key in methodology
        }

    return entry


def build_initial_document(active_project: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": str(active_project["project_id"]).strip(),
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "summary.py",
            "version": VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE,
            "focus": "Aggregation of Input Validation assessment checklists without active probing.",
            "status": "initialized",
        },
        "target": {
            "application": str(active_project.get("application", "")).strip(),
            "target": str(active_project.get("target", "")).strip(),
            "environment": str(active_project.get("environment", "")).strip(),
            "assessment_type": str(active_project.get("assessment_type", "")).strip(),
        },
        "methodology": {
            "description": "Aggregation-only summary of Input Validation checklists 7-001 through 7-006.",
            "active_project_source": ".runtime/active-project.yaml",
            "source_artifacts_authoritative": True,
            "network_requests": False,
            "active_probing": False,
            "automatic_finding": False,
            "finding_inference": False,
            "preserve_source_assessment_state": True,
            "preserve_forensic_signals": True,
            "cve_correlation": "Source-artifact aggregation only; version match != vulnerability.",
            "raw_evidence_modified": False,
            "report_redaction_separate": True,
        },
        "toolchain": {
            "mandatory": ["Python", "PyYAML", "scripts.context", "active project artifacts"],
            "optional": [],
            "not_required": ["requests", "Playwright", "Nmap", "ffuf", "Gobuster", "Nuclei", "sqlmap", "commix", "ZAP", "Hydra"],
        },
        "source_status": {
            "active_project": "completed",
            "checklists": {},
        },
        "input_validation": {
            "checklists": [],
        },
        "assessment": {
            "result": "pending",
            "finding": False,
            "finding_count": 0,
            "requires_review": False,
            "review_count": 0,
            "missing_count": 0,
            "incomplete_count": 0,
            "completed_count": 0,
            "cve_count": 0,
            "cves": [],
        },
        "generated_at": None,
    }


def aggregate(active_project: dict[str, Any]) -> dict[str, Any]:
    project_path = active_project_path(active_project)
    data = build_initial_document(active_project)

    entries: list[dict[str, Any]] = []
    statuses: dict[str, str] = {}
    cves: set[str] = set()
    finding_count = 0
    review_count = 0
    completed_count = 0
    missing_count = 0
    incomplete_count = 0

    for item in CHECKLISTS:
        entry = build_checklist_entry(project_path, item)
        entries.append(entry)
        statuses[item["id"]] = str(entry.get("status", "unknown"))
        cves.update(entry.get("cves", []))

        if entry.get("finding"):
            finding_count += 1
        if entry.get("requires_review"):
            review_count += 1

        status = str(entry.get("status", "unknown")).lower()
        if status == "completed":
            completed_count += 1
        elif status in {"missing", "not_found"}:
            missing_count += 1
        elif status not in {"deferred", "skipped", "not_applicable"}:
            incomplete_count += 1

    source_status = {"active_project": "completed", **statuses}
    all_assessments_available = missing_count == 0 and incomplete_count == 0

    if finding_count > 0:
        overall_result = "finding"
    elif review_count > 0:
        overall_result = "review"
    elif not all_assessments_available:
        overall_result = "incomplete"
    else:
        overall_result = "pass"

    data["checklist"]["status"] = "generated"
    data["source_status"] = {
        "active_project": "completed",
        "checklists": source_status,
    }
    # Keep the same compact top-level status map for easy machine consumption.
    for key, value in statuses.items():
        data["source_status"][key] = value

    data["input_validation"]["checklists"] = entries
    data["assessment"] = {
        "result": overall_result,
        "finding": finding_count > 0,
        "finding_count": finding_count,
        "requires_review": review_count > 0,
        "review_count": review_count,
        "missing_count": missing_count,
        "incomplete_count": incomplete_count,
        "completed_count": completed_count,
        "total_checklists": len(CHECKLISTS),
        "cve_count": len(cves),
        "cves": sorted(cves),
    }
    data["generated_at"] = now_iso()
    return data


def cmd_version() -> int:
    print("BrebesKab-CSIRT-Tools Input Validation Summary")
    print(f"Version   : {VERSION}")
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Phase     : {PHASE}")
    print(f"Schema    : {SCHEMA_VERSION}")
    print("Sources   : 7-001 through 7-006")
    print("Boundary  : aggregation only; no active probing")
    return 0


def cmd_init() -> int:
    active_project = load_active_project()
    path = summary_file()

    if path.exists():
        print("[INFO] Input Validation Summary sudah ada.")
        print(f"[INFO] File : {path}")
        return 0

    save_yaml(path, build_initial_document(active_project))
    print("[PASS] Input Validation Summary artifact siap.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {active_project['project_id']}")
    print(f"[PASS] File      : {path}")
    return 0


def cmd_generate() -> int:
    active_project = load_active_project()
    path = summary_file()
    data = aggregate(active_project)
    save_yaml(path, data)

    assessment = data["assessment"]
    entries = data["input_validation"]["checklists"]

    print("[PASS] Input Validation Summary generate selesai.")
    print(f"[PASS] Project     : {active_project['project_id']}")
    print(f"[PASS] Checklists  : {len(entries)}")
    print(f"[PASS] Completed   : {assessment['completed_count']}")
    print(f"[PASS] Missing     : {assessment['missing_count']}")
    print(f"[PASS] Incomplete  : {assessment['incomplete_count']}")
    print(f"[PASS] Findings    : {assessment['finding_count']}")
    print(f"[PASS] Review      : {assessment['review_count']}")
    print(f"[PASS] CVEs        : {assessment['cve_count']}")
    print(f"[PASS] Assessment  : {assessment['result']}")
    print(f"[PASS] File        : {path}")
    return 0


def cmd_show() -> int:
    path = summary_file()
    if not path.exists():
        print("[FAIL] Input Validation Summary belum diinisialisasi.")
        return 1

    data = load_yaml(path)
    print(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False), end="")
    return 0


def cmd_status() -> int:
    active_project = load_active_project()
    path = summary_file()

    if not path.exists():
        print(f"Project ID : {active_project['project_id']}")
        print("Status     : not-initialized")
        return 0

    data = load_yaml(path)
    checklist = as_dict(data.get("checklist"))
    assessment = as_dict(data.get("assessment"))
    print(f"Project ID : {active_project['project_id']}")
    print(f"Status     : {checklist.get('status', 'unknown')}")
    print(f"Assessment : {assessment.get('result', 'unknown')}")
    print(f"Findings   : {assessment.get('finding_count', 0)}")
    print(f"Review     : {assessment.get('review_count', 0)}")
    print(f"Missing    : {assessment.get('missing_count', 0)}")
    return 0


def cmd_verify() -> int:
    path = summary_file()
    if not path.exists():
        print("[FAIL] Input Validation Summary belum diinisialisasi.")
        return 1

    data = load_yaml(path)
    errors: list[str] = []

    if not isinstance(data, dict):
        print("[FAIL] Summary memiliki format YAML yang tidak valid.")
        return 1

    if str(data.get("schema_version", "")) != SCHEMA_VERSION:
        errors.append(f"Schema version harus {SCHEMA_VERSION}.")

    tool = as_dict(data.get("tool"))
    if tool.get("script") != "summary.py":
        errors.append("Tool script harus summary.py.")
    if str(tool.get("version", "")) != VERSION:
        errors.append(f"Tool version harus {VERSION}.")

    checklist = as_dict(data.get("checklist"))
    if checklist.get("id") != CHECKLIST_ID:
        errors.append(f"Checklist ID harus {CHECKLIST_ID}.")
    if checklist.get("name") != CHECKLIST_NAME:
        errors.append(f"Checklist name harus {CHECKLIST_NAME}.")
    if checklist.get("phase") != PHASE:
        errors.append(f"Checklist phase harus {PHASE}.")

    methodology = as_dict(data.get("methodology"))
    required_true = [
        "source_artifacts_authoritative",
        "preserve_source_assessment_state",
        "preserve_forensic_signals",
        "report_redaction_separate",
    ]
    required_false = [
        "network_requests",
        "active_probing",
        "automatic_finding",
        "finding_inference",
        "raw_evidence_modified",
    ]

    for key in required_true:
        if methodology.get(key) is not True:
            errors.append(f"Methodology {key} harus true.")
    for key in required_false:
        if methodology.get(key) is not False:
            errors.append(f"Methodology {key} harus false.")

    entries = as_list(as_dict(data.get("input_validation")).get("checklists"))
    if len(entries) != len(CHECKLISTS):
        errors.append(f"Jumlah checklist harus {len(CHECKLISTS)}.")

    expected_ids = [item["id"] for item in CHECKLISTS]
    actual_ids = [str(as_dict(item).get("id", "")) for item in entries]
    if actual_ids != expected_ids:
        errors.append("Urutan/ID checklist tidak sesuai 7-001 sampai 7-006.")

    for item in entries:
        entry = as_dict(item)
        if not entry.get("source"):
            errors.append(f"Source kosong untuk {entry.get('id', '?')}.")
        if "source_exists" not in entry:
            errors.append(f"source_exists tidak ada untuk {entry.get('id', '?')}.")
        if not entry.get("source_exists"):
            if not entry.get("reason"):
                errors.append(f"Artifact {entry.get('id', '?')} hilang tetapi reason tidak ada.")
            if entry.get("finding") is not False:
                errors.append(f"Artifact {entry.get('id', '?')} yang hilang tidak boleh menjadi finding otomatis.")
        if not isinstance(entry.get("finding"), bool):
            errors.append(f"finding harus boolean untuk {entry.get('id', '?')}.")
        if not isinstance(entry.get("requires_review"), bool):
            errors.append(f"requires_review harus boolean untuk {entry.get('id', '?')}.")

    assessment = as_dict(data.get("assessment"))
    for key in ("finding_count", "review_count", "missing_count", "incomplete_count", "completed_count", "cve_count"):
        if not isinstance(assessment.get(key), int):
            errors.append(f"Assessment {key} harus integer.")

    if errors:
        print("[FAIL] Input Validation Summary tidak memenuhi validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    # Verify does not recalculate or mutate source artifacts. It only marks the
    # already-generated summary as completed after structural validation.
    checklist["status"] = "completed"
    data["checklist"] = checklist
    save_yaml(path, data)

    raw = path.read_bytes()
    encoding_ok = not raw.startswith(b"\xef\xbb\xbf")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        encoding_ok = False

    assessment = as_dict(data.get("assessment"))
    print("[PASS] Input Validation Summary memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {data.get('project_id')}")
    print(f"[PASS] File      : {path}")
    print(f"[PASS] Checklists: {len(entries)}")
    print(f"[PASS] Findings  : {assessment.get('finding_count', 0)}")
    print(f"[PASS] Review    : {assessment.get('review_count', 0)}")
    print(f"[PASS] Encoding  : {'UTF-8 tanpa BOM' if encoding_ok else 'INVALID'}")
    return 0 if encoding_ok else 1


def cmd_remove() -> int:
    path = summary_file()
    if not path.exists():
        print("[INFO] Input Validation Summary belum ada.")
        return 0
    path.unlink()
    print("[PASS] Input Validation Summary berhasil dihapus.")
    print(f"FILE   : {path}")
    return 0


def print_help() -> None:
    print(
        f"""BrebesKab-CSIRT-Tools
Input Validation Summary v{VERSION}

Usage:
  python scripts/inputvalidation/summary.py init
  python scripts/inputvalidation/summary.py generate
  python scripts/inputvalidation/summary.py show
  python scripts/inputvalidation/summary.py verify
  python scripts/inputvalidation/summary.py status
  python scripts/inputvalidation/summary.py remove
  python scripts/inputvalidation/summary.py version

Commands:
  init      Create summary.yaml.
  generate  Aggregate 7-001 through 7-006 artifacts.
  show      Show the complete summary document.
  verify    Validate the summary and mark completed.
  status    Show lifecycle and aggregate assessment status.
  remove    Remove summary.yaml.
  version   Show script version.

Aggregation:
  7-001  SQL Injection
  7-002  Cross-Site Scripting (XSS)
  7-003  Command Injection
  7-004  Path Traversal
  7-005  Expression / Template / Parser Injection
  7-006  HTTP Parameter Pollution

Boundary:
  Aggregation only.
  No network requests.
  No active probing.
  No new findings inferred.
  Source assessment states remain authoritative.
  CVE correlation is secondary metadata only.
"""
    )


def main() -> int:
    command = sys.argv[1].strip().lower() if len(sys.argv) > 1 else "help"

    if command == "version":
        return cmd_version()

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

    except (FileNotFoundError, RuntimeError, ValueError, yaml.YAMLError) as exc:
        print(f"[ERROR] {exc}")
        return 1
    except Exception as exc:
        print(f"[ERROR] Unexpected failure: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
