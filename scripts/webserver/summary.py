#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Web Server Configuration Summary

Checklist:
    4-001 Server Version Disclosure
    4-002 Directory Listing / Indexing
    4-003 Default Virtual Host / Host Handling
    4-004 Backup File Exposure
    4-005 Web Server Configuration
    4-006 Environment File Exposure
    4-007 Git Exposure
    4-008 Debug Exposure
    4-009 HTTP Methods
    4-010 Errors / Error Information Disclosure

Design:
    - Aggregation only. No network requests or active probes.
    - Reads completed checklist artifacts from the active project.
    - Does not create or infer new findings.
    - Preserves checklist terminology and assessment states.
    - Deduplicates CVE IDs for the summary.
    - Raw evidence remains untouched; report redaction belongs elsewhere.
"""

from __future__ import annotations

import argparse
import json
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
CHECKLIST_ID = "WEB-SERVER-SUMMARY"

CHECKLISTS = [
    ("4-001", "Server Version Disclosure", "version", "version.yaml"),
    ("4-002", "Directory Listing / Indexing", "directory", "directory.yaml"),
    ("4-003", "Default Virtual Host / Host Handling", "default", "default.yaml"),
    ("4-004", "Backup File Exposure", "backup", "backup.yaml"),
    ("4-005", "Web Server Configuration", "config", "config.yaml"),
    ("4-006", "Environment File Exposure", "env", "env.yaml"),
    ("4-007", "Git Exposure", "git", "git.yaml"),
    ("4-008", "Debug Exposure", "debug", "debug.yaml"),
    ("4-009", "HTTP Methods", "methods", "methods.yaml"),
    ("4-010", "Errors / Error Information Disclosure", "errors", "errors.yaml"),
]

STATUS_COMPLETED = {"completed"}
REVIEW_TRUE_VALUES = {True, "true", "True", 1, "1", "yes", "Yes"}
FINDING_TRUE_VALUES = {True, "true", "True", 1, "1", "yes", "Yes"}

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def repo_root() -> Path:
    # scripts/webserver/summary.py -> repository root is parents[2]
    return Path(__file__).resolve().parents[2]


def active_project_file() -> Path:
    return repo_root() / ".runtime" / "active-project.yaml"


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


def load_active_project() -> tuple[Path, dict[str, Any]]:
    active_file = active_project_file()
    if not active_file.exists():
        raise FileNotFoundError(
            f"Active project file tidak ditemukan: {active_file}"
        )

    data = load_yaml(active_file)
    if not isinstance(data, dict):
        raise ValueError("active-project.yaml harus berupa mapping.")

    project_id = str(data.get("project_id", "")).strip()
    raw_project_path = str(data.get("project_path", "")).strip()

    if not project_id:
        raise ValueError("project_id tidak ditemukan pada active-project.yaml.")
    if not raw_project_path:
        raise ValueError("project_path tidak ditemukan pada active-project.yaml.")

    project_path = Path(raw_project_path)
    if not project_path.is_absolute():
        project_path = repo_root() / project_path

    project_path = project_path.resolve()

    if not project_path.exists() or not project_path.is_dir():
        raise FileNotFoundError(
            f"Active project tidak ditemukan: {project_path}"
        )

    if project_path.name != project_id:
        raise ValueError(
            f"project_id/path tidak konsisten: {project_id} != {project_path.name}"
        )

    return project_path, data


def artifact_path(project_root: Path, folder: str, filename: str) -> Path:
    return project_root / "04-web-server-configuration" / folder / filename


def output_path(project_root: Path) -> Path:
    return project_root / "04-web-server-configuration" / "summary" / "webserver-summary.yaml"


def read_artifact(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "missing"

    try:
        data = load_yaml(path)
    except Exception as exc:
        return None, f"parse-error: {exc}"

    if not isinstance(data, dict):
        return None, "invalid-root"

    return data, None


def first_value(data: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return default


def bool_value(value: Any) -> bool:
    return value in REVIEW_TRUE_VALUES


def collect_cve_ids(value: Any, output: set[str]) -> None:
    if isinstance(value, str):
        for match in CVE_RE.findall(value):
            output.add(match.upper())
        return

    if isinstance(value, dict):
        for key, item in value.items():
            # Keep scanning the full artifact because different checklist
            # versions may store CVE data under different keys.
            collect_cve_ids(key, output)
            collect_cve_ids(item, output)
        return

    if isinstance(value, list):
        for item in value:
            collect_cve_ids(item, output)


def count_nested_items(data: dict[str, Any], keys: list[str]) -> int | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict):
            # Common pattern: observations/results/items as nested mapping.
            for nested in ("items", "results", "observations", "probes"):
                nested_value = value.get(nested)
                if isinstance(nested_value, list):
                    return len(nested_value)
    return None


def extract_counts(data: dict[str, Any]) -> dict[str, int]:
    """
    Prefer explicit summary counters used by individual checklist scripts.
    This function intentionally does not invent counts when the source
    artifact does not expose them.
    """
    aliases = {
        "probes": ["probes", "probe_count"],
        "candidates": ["candidates", "candidate_count"],
        "observations": ["observations", "observation_count"],
        "review": ["requires_review_count", "review_count"],
    }

    result: dict[str, int] = {}

    for name, keys in aliases.items():
        value = first_value(data, keys)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            result[name] = value
        elif isinstance(value, str) and value.isdigit():
            result[name] = int(value)

    if "probes" not in result:
        nested = count_nested_items(data, ["probes", "probe_results"])
        if nested is not None:
            result["probes"] = nested

    if "observations" not in result:
        nested = count_nested_items(data, ["observations", "results"])
        if nested is not None:
            result["observations"] = nested

    return result


def extract_checklist_summary(
    project_root: Path,
    checklist_id: str,
    name: str,
    folder: str,
    filename: str,
) -> dict[str, Any]:
    path = artifact_path(project_root, folder, filename)
    data, error = read_artifact(path)

    item: dict[str, Any] = {
        "id": checklist_id,
        "name": name,
        "artifact": str(
            path.relative_to(project_root)
        ).replace("\\", "/"),
        "artifact_exists": error is None,
        "artifact_status": "available" if error is None else error,
        "status": None,
        "target": None,
        "requires_review": False,
        "finding": False,
        "cve_candidates": 0,
        "cve_ids": [],
        "counts": {},
    }

    if data is None:
        return item

    checklist = data.get("checklist")
    if not isinstance(checklist, dict):
        checklist = {}

    assessment = data.get("assessment")
    if not isinstance(assessment, dict):
        assessment = {}

    summary = data.get("summary")
    if not isinstance(summary, dict):
        summary = {}

    cve_correlation = data.get("cve_correlation")
    if not isinstance(cve_correlation, dict):
        cve_correlation = {}

    item["status"] = first_value(
        checklist,
        ["status", "assessment_status"],
        first_value(data, ["status", "assessment_status"]),
    )
    item["target"] = first_value(
        data,
        ["target", "target_url", "domain"],
    )
    if isinstance(item["target"], dict):
        item["target"] = first_value(
            item["target"],
            ["url", "hostname", "value"],
        )

    review_value = first_value(
        assessment,
        ["requires_review", "review_required", "review"],
        first_value(
            data,
            ["requires_review", "review_required", "review"],
            False,
        ),
    )
    item["requires_review"] = bool_value(review_value)

    finding_value = first_value(
        assessment,
        ["finding", "confirmed_finding", "vulnerability_confirmed"],
        first_value(
            data,
            ["finding", "confirmed_finding", "vulnerability_confirmed"],
            False,
        ),
    )
    item["finding"] = finding_value in FINDING_TRUE_VALUES

    counts = extract_counts(data)
    for name, aliases in {
        "probes": ["probes", "probe_count"],
        "candidates": ["candidates", "candidate_count"],
        "observations": ["observations", "observation_count"],
        "review": ["requires_review_count", "review_count"],
    }.items():
        if name not in counts:
            value = first_value(summary, aliases)
            if isinstance(value, int) and not isinstance(value, bool):
                counts[name] = value
            elif isinstance(value, str) and value.isdigit():
                counts[name] = int(value)
    item["counts"] = counts

    cve_ids: set[str] = set()
    collect_cve_ids(data, cve_ids)

    explicit_cve_count = first_value(
        cve_correlation,
        ["candidate_count", "cve_candidates", "cve_candidate_count"],
        first_value(
            data,
            ["cve_candidates", "cve_candidate_count"],
            None,
        ),
    )
    if isinstance(explicit_cve_count, int):
        item["cve_candidates"] = explicit_cve_count
    elif isinstance(explicit_cve_count, str) and explicit_cve_count.isdigit():
        item["cve_candidates"] = int(explicit_cve_count)
    else:
        item["cve_candidates"] = len(cve_ids)

    item["cve_ids"] = sorted(cve_ids)

    return item


def build_summary(project_root: Path, active_data: dict[str, Any]) -> dict[str, Any]:
    items = [
        extract_checklist_summary(
            project_root,
            checklist_id,
            name,
            folder,
            filename,
        )
        for checklist_id, name, folder, filename in CHECKLISTS
    ]

    completed = sum(
        1 for item in items if item["status"] in STATUS_COMPLETED
    )
    incomplete = len(items) - completed
    review_count = sum(1 for item in items if item["requires_review"])
    finding_count = sum(1 for item in items if item["finding"])

    unique_cves: set[str] = set()
    for item in items:
        unique_cves.update(item["cve_ids"])

    total_cve_observations = sum(
        int(item["cve_candidates"] or 0) for item in items
    )

    status_counts = Counter(
        str(item["status"] or "unknown")
        for item in items
    )

    project_id = str(
        active_data.get("project_id", project_root.name)
    ).strip()

    targets = sorted(
        {
            str(item["target"]).strip()
            for item in items
            if item["target"]
        }
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "summary_version": VERSION,
        "checklist_id": CHECKLIST_ID,
        "project_id": project_id,
        "generated_at": now_iso(),
        "source": {
            "type": "artifact-aggregation",
            "network_requests": False,
            "active_project_file": ".runtime/active-project.yaml",
            "phase": "04-web-server-configuration",
        },
        "assessment": {
            "checklists_total": len(items),
            "completed": completed,
            "incomplete": incomplete,
            "requires_review": review_count,
            "confirmed_findings": finding_count,
            "observations": sum(
                int(item["counts"].get("observations", 0))
                for item in items
            ),
            "cve_candidate_observations": total_cve_observations,
            "unique_cve_ids": len(unique_cves),
            "cve_triage": (
                "CVE candidates are aggregated evidence only; "
                "no automatic vulnerability finding is created."
            ),
        },
        "target": {
            "values": targets,
            "primary": targets[0] if len(targets) == 1 else None,
        },
        "checklists": items,
        "status_distribution": dict(sorted(status_counts.items())),
        "cve": {
            "unique_ids": sorted(unique_cves),
            "unique_count": len(unique_cves),
        },
        "rules": {
            "summary_creates_findings": False,
            "requires_review_is_not_finding": True,
            "cve_candidate_is_not_vulnerability": True,
            "missing_artifact_is_not_assumed_completed": True,
            "raw_evidence_redaction": (
                "handled by report-generation layer; source artifacts are untouched"
            ),
        },
    }


def command_version() -> int:
    print(f"summary.py v{VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")
    print("Checklist: Web Server Configuration Summary")
    print("Scope: 4-001 through 4-010")
    print("Mode: artifact aggregation only")
    print("Network requests: disabled")
    print("Active project: .runtime/active-project.yaml")
    print("Output: 04-web-server-configuration/summary/webserver-summary.yaml")
    print("Finding creation: disabled")
    print("CVE deduplication: enabled by CVE ID")
    print("Report redaction: separate report-generation layer")
    return 0


def command_init() -> int:
    project_root, active_data = load_active_project()
    out = output_path(project_root)

    # Init creates a deterministic skeleton from the active project.
    # It does not probe the target.
    data = {
        "schema_version": SCHEMA_VERSION,
        "summary_version": VERSION,
        "checklist_id": CHECKLIST_ID,
        "project_id": str(active_data.get("project_id", project_root.name)),
        "generated_at": now_iso(),
        "source": {
            "type": "artifact-aggregation",
            "network_requests": False,
            "phase": "04-web-server-configuration",
        },
        "assessment": {
            "checklists_total": len(CHECKLISTS),
            "completed": 0,
            "incomplete": len(CHECKLISTS),
            "requires_review": 0,
            "confirmed_findings": 0,
            "observations": 0,
            "cve_candidate_observations": 0,
            "unique_cve_ids": 0,
            "cve_triage": (
                "CVE candidates are aggregated evidence only; "
                "no automatic vulnerability finding is created."
            ),
        },
        "target": {
            "values": [],
            "primary": None,
        },
        "checklists": [
            {
                "id": checklist_id,
                "name": name,
                "artifact": str(
                    artifact_path(project_root, folder, filename)
                    .relative_to(project_root)
                ).replace("\\", "/"),
                "artifact_exists": False,
                "artifact_status": "not-analyzed",
                "status": None,
                "target": None,
                "requires_review": False,
                "finding": False,
                "cve_candidates": 0,
                "cve_ids": [],
                "counts": {},
            }
            for checklist_id, name, folder, filename in CHECKLISTS
        ],
        "status_distribution": {},
        "cve": {
            "unique_ids": [],
            "unique_count": 0,
        },
        "rules": {
            "summary_creates_findings": False,
            "requires_review_is_not_finding": True,
            "cve_candidate_is_not_vulnerability": True,
            "missing_artifact_is_not_assumed_completed": True,
            "raw_evidence_redaction": (
                "handled by report-generation layer; source artifacts are untouched"
            ),
        },
    }

    save_yaml(out, data)

    print("[PASS] Web Server Summary berhasil diinisialisasi.")
    print(f"PROJECT         : {data['project_id']}")
    print(f"CHECKLISTS      : {len(CHECKLISTS)}")
    print("NETWORK         : disabled")
    print(f"FILE            : {out}")
    return 0


def command_analyze() -> int:
    project_root, active_data = load_active_project()
    data = build_summary(project_root, active_data)
    out = output_path(project_root)
    save_yaml(out, data)

    assessment = data["assessment"]

    print("[PASS] Web Server Summary berhasil dianalisis.")
    print(f"PROJECT              : {data['project_id']}")
    print(f"CHECKLISTS           : {assessment['checklists_total']}")
    print(f"COMPLETED            : {assessment['completed']}")
    print(f"INCOMPLETE           : {assessment['incomplete']}")
    print(f"REQUIRES REVIEW      : {assessment['requires_review']}")
    print(f"CONFIRMED FINDINGS   : {assessment['confirmed_findings']}")
    print(f"OBSERVATIONS         : {assessment['observations']}")
    print(
        f"CVE CANDIDATE OBS.   : {assessment['cve_candidate_observations']}"
    )
    print(f"UNIQUE CVE IDS       : {assessment['unique_cve_ids']}")
    print(f"FILE                 : {out}")

    if assessment["incomplete"]:
        print(
            "[INFO] Beberapa checklist belum memiliki artifact completed; "
            "summary tidak menganggapnya selesai."
        )

    return 0


def command_list() -> int:
    project_root, _ = load_active_project()
    out = output_path(project_root)

    if not out.exists():
        print("[FAIL] Summary artifact belum tersedia. Jalankan analyze terlebih dahulu.")
        return 1

    data, error = read_artifact(out)
    if error or data is None:
        print(f"[FAIL] Summary artifact tidak dapat dibaca: {error}")
        return 1

    items = data.get("checklists", [])
    if not isinstance(items, list):
        print("[FAIL] Struktur checklists pada summary tidak valid.")
        return 1

    print("Web Server Configuration Summary")
    print("=" * 78)

    for item in items:
        if not isinstance(item, dict):
            continue

        checklist_id = item.get("id", "?")
        name = item.get("name", "?")
        status = item.get("status") or "not-analyzed"
        review = "YES" if item.get("requires_review") else "NO"
        finding = "YES" if item.get("finding") else "NO"
        cve = item.get("cve_candidates", 0)

        print(
            f"{checklist_id:<7} "
            f"{status:<24} "
            f"review={review:<3} "
            f"finding={finding:<3} "
            f"cve={cve:<4} "
            f"{name}"
        )

    assessment = data.get("assessment", {})
    print("-" * 78)
    print(
        f"COMPLETED={assessment.get('completed', 0)}  "
        f"INCOMPLETE={assessment.get('incomplete', 0)}  "
        f"REVIEW={assessment.get('requires_review', 0)}  "
        f"FINDINGS={assessment.get('confirmed_findings', 0)}  "
        f"UNIQUE_CVE={assessment.get('unique_cve_ids', 0)}"
    )

    return 0


def command_verify() -> int:
    project_root, _ = load_active_project()
    out = output_path(project_root)

    if not out.exists():
        print("[FAIL] Summary artifact belum tersedia.")
        return 1

    data, error = read_artifact(out)
    if error or data is None:
        print(f"[FAIL] Summary artifact tidak valid: {error}")
        return 1

    errors: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai.")

    if data.get("summary_version") != VERSION:
        errors.append("summary_version tidak sesuai.")

    if data.get("checklist_id") != CHECKLIST_ID:
        errors.append("checklist_id tidak sesuai.")

    if data.get("project_id") != project_root.name:
        errors.append("project_id tidak konsisten dengan active project.")

    if data.get("source", {}).get("network_requests") is not False:
        errors.append("summary harus menyatakan network_requests=false.")

    items = data.get("checklists")
    if not isinstance(items, list):
        errors.append("checklists harus berupa list.")
        items = []

    expected_ids = [item[0] for item in CHECKLISTS]
    actual_ids = [
        item.get("id")
        for item in items
        if isinstance(item, dict)
    ]

    if actual_ids != expected_ids:
        errors.append(
            f"urutan/ID checklist tidak sesuai: expected={expected_ids}, actual={actual_ids}"
        )

    if len(items) != len(CHECKLISTS):
        errors.append(
            f"jumlah checklist tidak sesuai: expected={len(CHECKLISTS)}, actual={len(items)}"
        )

    expected_completed = sum(
        1 for item in items
        if isinstance(item, dict) and item.get("status") in STATUS_COMPLETED
    )
    expected_incomplete = len(items) - expected_completed
    expected_review = sum(
        1 for item in items
        if isinstance(item, dict) and item.get("requires_review")
    )
    expected_findings = sum(
        1 for item in items
        if isinstance(item, dict) and item.get("finding")
    )
    expected_cve_observations = sum(
        int(item.get("cve_candidates", 0) or 0)
        for item in items
        if isinstance(item, dict)
    )

    for item in items:
        if not isinstance(item, dict):
            errors.append("item checklist bukan mapping.")
            continue

        if item.get("finding") and not item.get("requires_review"):
            errors.append(
                f"{item.get('id')}: finding=true tetapi requires_review=false."
            )

        if item.get("cve_candidates", 0) < 0:
            errors.append(
                f"{item.get('id')}: cve_candidates bernilai negatif."
            )

    if assessment.get("checklists_total") != len(items):
        errors.append("checklists_total tidak konsisten dengan jumlah checklist.")

    if assessment.get("completed") != expected_completed:
        errors.append(
            f"completed tidak konsisten: expected={expected_completed}, "
            f"actual={assessment.get('completed')}"
        )

    if assessment.get("incomplete") != expected_incomplete:
        errors.append(
            f"incomplete tidak konsisten: expected={expected_incomplete}, "
            f"actual={assessment.get('incomplete')}"
        )

    if assessment.get("requires_review") != expected_review:
        errors.append(
            f"requires_review tidak konsisten: expected={expected_review}, "
            f"actual={assessment.get('requires_review')}"
        )

    if assessment.get("cve_candidate_observations") != expected_cve_observations:
        errors.append(
            "cve_candidate_observations tidak konsisten dengan checklist."
        )

    assessment = data.get("assessment", {})
    if assessment.get("confirmed_findings") != expected_findings:
        errors.append(
            f"confirmed_findings tidak konsisten: expected={expected_findings}, "
            f"actual={assessment.get('confirmed_findings')}"
        )

    if errors:
        print("[FAIL] Web Server Summary gagal validasi.")
        for error_text in errors:
            print(f"[FAIL] {error_text}")
        return 1

    print("[PASS] Web Server Summary memenuhi validasi.")
    print(f"[PASS] Checklist       : {CHECKLIST_ID}")
    print(f"[PASS] Status           : summary")
    print(f"[PASS] Project          : {data.get('project_id')}")
    print(
        f"[PASS] Checklists       : "
        f"{assessment.get('checklists_total', 0)}"
    )
    print(f"[PASS] Completed        : {assessment.get('completed', 0)}")
    print(f"[PASS] Incomplete       : {assessment.get('incomplete', 0)}")
    print(
        f"[PASS] Requires Review  : "
        f"{assessment.get('requires_review', 0)}"
    )
    print(
        f"[PASS] Confirmed Finding: "
        f"{assessment.get('confirmed_findings', 0)}"
    )
    print(
        f"[PASS] CVE Candidates   : "
        f"{assessment.get('cve_candidate_observations', 0)} observation(s)"
    )
    print(
        f"[PASS] Unique CVE IDs   : "
        f"{assessment.get('unique_cve_ids', 0)}"
    )
    print("[PASS] Network probes   : disabled")
    print("[PASS] Finding creation : disabled")
    print(
        "[PASS] CVE Triage       : "
        "candidate evidence only; no automatic vulnerability finding."
    )
    print(
        "[PASS] Assessment       : "
        "summary aggregates source artifacts without creating new findings."
    )

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Web Server Configuration artifact summary."
    )
    parser.add_argument(
        "command",
        choices=("version", "init", "analyze", "list", "verify"),
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "version":
            return command_version()
        if args.command == "init":
            return command_init()
        if args.command == "analyze":
            return command_analyze()
        if args.command == "list":
            return command_list()
        if args.command == "verify":
            return command_verify()
    except Exception as exc:
        print(f"[FAIL] {exc}")
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
