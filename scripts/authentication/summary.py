#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Authentication Summary

Checklist:
    5-001 Authentication Login
    5-002 Session Management
    5-003 Logout / Session Invalidation
    5-004 Password Policy
    5-005 Password Recovery
    5-006 Brute-Force / Rate-Limit Protection
    5-007 MFA
    5-008 Authentication Summary

Design:
    - Aggregation only.
    - No network requests or active probes.
    - Reads authentication checklist artifacts from the active project.
    - Does not create or infer new findings.
    - Preserves source assessment states.
    - Distinguishes completed, deferred, and skipped/not-applicable items.
    - Deduplicates CVE IDs from source artifacts.
    - Raw evidence remains untouched.
    - Report redaction belongs to the report-generation layer.
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


VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "5-008"
CHECKLIST_NAME = "Authentication Summary"
PHASE = "05 Authentication"

CHECKLISTS = [
    {
        "id": "5-001",
        "name": "Authentication Login",
        "directory": "login",
        "filename": "login.yaml",
        "expected_state": "completed",
    },
    {
        "id": "5-002",
        "name": "Session Management",
        "directory": "session",
        "filename": "session.yaml",
        "expected_state": "completed",
    },
    {
        "id": "5-003",
        "name": "Logout / Session Invalidation",
        "directory": "logout",
        "filename": "logout.yaml",
        "expected_state": "completed",
    },
    {
        "id": "5-004",
        "name": "Password Policy",
        "directory": "password",
        "filename": "password.yaml",
        "expected_state": "deferred",
    },
    {
        "id": "5-005",
        "name": "Password Recovery",
        "directory": "recovery",
        "filename": "recovery.yaml",
        "expected_state": "deferred",
    },
    {
        "id": "5-006",
        "name": "Brute-Force / Rate-Limit Protection",
        "directory": "bruteforce",
        "filename": "bruteforce.yaml",
        "expected_state": "completed",
    },
    {
        "id": "5-007",
        "name": "MFA",
        "directory": "mfa",
        "filename": "mfa.yaml",
        "expected_state": "skipped",
    },
]

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(
        timespec="seconds"
    )


def repo_root() -> Path:
    """
    scripts/authentication/summary.py
    parents[0] = authentication
    parents[1] = scripts
    parents[2] = repository root
    """
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

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
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
        raise FileNotFoundError(
            f"Active project file tidak ditemukan: {path}"
        )

    data = load_yaml(path)

    if not isinstance(data, dict):
        raise ValueError(
            "Active project file memiliki format yang tidak valid."
        )

    project_id = str(data.get("project_id", "")).strip()
    project_path = str(data.get("project_path", "")).strip()

    if not project_id:
        raise ValueError(
            "project_id tidak ditemukan pada active-project.yaml."
        )

    if not project_path:
        raise ValueError(
            "project_path tidak ditemukan pada active-project.yaml."
        )

    return data


def active_project_path(
    active_project: dict[str, Any],
) -> Path:
    raw = str(
        active_project.get("project_path", "")
    ).strip()

    path = Path(raw)

    if not path.is_absolute():
        path = repo_root() / path

    return path.resolve()


def summary_file() -> Path:
    active_project = load_active_project()
    project_path = active_project_path(active_project)

    return (
        project_path
        / "05-authentication"
        / "summary"
        / "summary.yaml"
    )


def checklist_file(
    project_path: Path,
    item: dict[str, str],
) -> Path:
    return (
        project_path
        / "05-authentication"
        / item["directory"]
        / item["filename"]
    )


def normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        return value == 1

    if isinstance(value, str):
        return value.strip().lower() in {
            "true",
            "yes",
            "y",
            "1",
            "pass",
        }

    return False


def normalize_status(
    data: dict[str, Any],
) -> str:
    checklist = data.get("checklist", {})

    if isinstance(checklist, dict):
        status = str(
            checklist.get("status", "")
        ).strip().lower()

        if status:
            return status

    status = str(
        data.get("status", "")
    ).strip().lower()

    return status or "unknown"


def assessment_result(
    data: dict[str, Any],
) -> str:
    assessment = data.get("assessment", {})

    if isinstance(assessment, dict):
        result = str(
            assessment.get("result", "")
        ).strip().lower()

        if result:
            return result

    summary = data.get("summary", {})

    if isinstance(summary, dict):
        result = str(
            summary.get("result", "")
        ).strip().lower()

        if result:
            return result

    return "unknown"


def source_finding(
    data: dict[str, Any],
) -> bool:
    assessment = data.get("assessment", {})

    if isinstance(assessment, dict):
        if "finding" in assessment:
            return normalize_bool(
                assessment.get("finding")
            )

    summary = data.get("summary", {})

    if isinstance(summary, dict):
        if "finding" in summary:
            return normalize_bool(
                summary.get("finding")
            )

    return False


def source_requires_review(
    data: dict[str, Any],
) -> bool:
    assessment = data.get("assessment", {})

    if isinstance(assessment, dict):
        if "requires_review" in assessment:
            return normalize_bool(
                assessment.get("requires_review")
            )

    summary = data.get("summary", {})

    if isinstance(summary, dict):
        if "requires_review" in summary:
            return normalize_bool(
                summary.get("requires_review")
            )

    return False


def source_cve_candidates(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    correlation = data.get(
        "cve_correlation",
        {},
    )

    if not isinstance(correlation, dict):
        return []

    candidates = correlation.get(
        "candidates",
        [],
    )

    if not isinstance(candidates, list):
        return []

    return [
        item
        for item in candidates
        if isinstance(item, dict)
    ]


def extract_cve_ids(
    data: dict[str, Any],
) -> list[str]:
    found: set[str] = set()

    for candidate in source_cve_candidates(data):
        cve_id = str(
            candidate.get("cve_id", "")
        ).strip().upper()

        if cve_id and CVE_RE.fullmatch(cve_id):
            found.add(cve_id)

    correlation = data.get(
        "cve_correlation",
        {},
    )

    if isinstance(correlation, dict):
        raw_text = str(correlation)

        for match in CVE_RE.findall(raw_text):
            found.add(match.upper())

    return sorted(found)


def extract_source_identity(
    data: dict[str, Any],
) -> dict[str, Any]:
    tool = data.get("tool", {})
    checklist = data.get("checklist", {})
    target = data.get("target", {})

    if not isinstance(tool, dict):
        tool = {}

    if not isinstance(checklist, dict):
        checklist = {}

    if not isinstance(target, dict):
        target = {}

    return {
        "script": str(
            tool.get("script", "")
        ).strip(),
        "version": str(
            tool.get("version", "")
        ).strip(),
        "checklist_id": str(
            checklist.get("id", "")
        ).strip(),
        "checklist_name": str(
            checklist.get("name", "")
        ).strip(),
        "assessment_type": str(
            target.get("assessment_type", "")
        ).strip(),
    }


def build_initial_document(
    active_project: dict[str, Any],
) -> dict[str, Any]:
    project_id = str(
        active_project["project_id"]
    ).strip()

    application = str(
        active_project.get(
            "application",
            "",
        )
    ).strip()

    target = str(
        active_project.get(
            "target",
            "",
        )
    ).strip()

    environment = str(
        active_project.get(
            "environment",
            "",
        )
    ).strip()

    assessment_type = str(
        active_project.get(
            "assessment_type",
            "",
        )
    ).strip()

    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "summary.py",
            "version": VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE,
            "focus": (
                "Aggregation of authentication assessment "
                "checklists without active probing."
            ),
            "status": "initialized",
        },
        "target": {
            "application": application,
            "target": target,
            "environment": environment,
            "assessment_type": assessment_type,
        },
        "methodology": {
            "description": (
                "Aggregation-only summary of Authentication "
                "checklists 5-001 through 5-007."
            ),
            "active_project_source": (
                ".runtime/active-project.yaml"
            ),
            "source_artifacts_authoritative": True,
            "network_requests": False,
            "active_probing": False,
            "automatic_finding": False,
            "finding_inference": False,
            "cve_correlation": (
                "Source-artifact aggregation only; "
                "version match != vulnerability."
            ),
            "raw_evidence_modified": False,
            "report_redaction_separate": True,
        },
        "toolchain": {
            "mandatory": [
                "Python",
                "PyYAML",
                "scripts.context",
                "active project artifacts",
            ],
            "optional": [],
            "not_required": [
                "requests",
                "BeautifulSoup",
                "Playwright",
                "curl",
                "Nmap",
                "ffuf",
                "Gobuster",
                "Nuclei",
                "Hydra",
                "ZAP",
            ],
        },
        "source_status": {
            "active_project": "completed",
            "checklists": {},
        },
        "authentication": {
            "checklists": [],
            "counts": {
                "total": len(CHECKLISTS),
                "completed": 0,
                "deferred": 0,
                "skipped": 0,
                "not_applicable": 0,
                "missing": 0,
                "incomplete": 0,
            },
            "assessment": {
                "finding_count": 0,
                "review_count": 0,
                "finding": False,
                "requires_review": False,
            },
            "cve_correlation": {
                "candidate_count": 0,
                "unique_cve_count": 0,
                "cves": [],
            },
        },
        "assessment": {
            "result": "not_tested",
            "finding": False,
            "requires_review": False,
            "automatic_finding": False,
            "reason": (
                "Summary belum digenerate dari source artifacts."
            ),
        },
        "evidence": {
            "raw_evidence_modified": False,
            "source_artifacts": [],
        },
        "errors": [],
        "notes": [
            (
                "Summary hanya melakukan aggregation; "
                "tidak melakukan network request atau active probe."
            ),
            (
                "Source checklist artifacts tetap authoritative "
                "untuk assessment masing-masing checklist."
            ),
            (
                "Finding tidak dibuat atau diinferensikan oleh summary."
            ),
            (
                "requires_review bukan otomatis vulnerability."
            ),
            (
                "CVE/version correlation hanya secondary metadata."
            ),
            (
                "5-004 Password Policy berstatus deferred "
                "sesuai assessment plan."
            ),
            (
                "5-005 Password Recovery berstatus deferred "
                "sesuai assessment plan."
            ),
            (
                "5-007 MFA berstatus skipped/not_applicable "
                "karena aplikasi tidak memiliki MFA."
            ),
            (
                "Raw evidence tidak diubah; report redaction "
                "dilakukan pada report-generation layer."
            ),
        ],
        "generated_at": now_iso(),
        "updated_at": now_iso(),
    }


def aggregate(
    data: dict[str, Any],
    active_project: dict[str, Any],
    project_path: Path,
) -> dict[str, Any]:
    project_id = str(
        active_project["project_id"]
    ).strip()

    expected_application = str(
        active_project.get(
            "application",
            "",
        )
    ).strip()

    expected_target = str(
        active_project.get(
            "target",
            "",
        )
    ).strip()

    expected_environment = str(
        active_project.get(
            "environment",
            "",
        )
    ).strip()

    expected_assessment_type = str(
        active_project.get(
            "assessment_type",
            "",
        )
    ).strip()

    data["project_id"] = project_id

    data["target"] = {
        "application": expected_application,
        "target": expected_target,
        "environment": expected_environment,
        "assessment_type": expected_assessment_type,
    }

    source_status: dict[str, str] = {
        "active_project": "completed",
        "checklists": {},
    }

    checklist_records: list[dict[str, Any]] = []
    source_artifacts: list[str] = []

    counts = Counter()
    finding_count = 0
    review_count = 0

    cve_ids: set[str] = set()
    cve_candidate_count = 0

    errors: list[str] = []

    for item in CHECKLISTS:
        path = checklist_file(
            project_path,
            item,
        )

        relative_path = path.relative_to(
            repo_root()
        ).as_posix()

        expected = item["expected_state"]

        if not path.exists():
            source_status[
                item["id"]
            ] = "missing"

            counts["missing"] += 1

            if expected == "deferred":
                counts["deferred"] += 1
                source_status[
                    item["id"]
                ] = "deferred"

                checklist_records.append(
                    {
                        "id": item["id"],
                        "name": item["name"],
                        "status": "deferred",
                        "source": relative_path,
                        "source_exists": False,
                        "expected_state": "deferred",
                        "assessment_result": "deferred",
                        "finding": False,
                        "requires_review": False,
                        "cve_candidate_count": 0,
                        "cves": [],
                        "note": (
                            "Checklist deferred by assessment plan; "
                            "source artifact is not required."
                        ),
                    }
                )
                continue

            if expected == "skipped":
                counts["skipped"] += 1
                source_status[
                    item["id"]
                ] = "skipped"

                checklist_records.append(
                    {
                        "id": item["id"],
                        "name": item["name"],
                        "status": "skipped",
                        "source": relative_path,
                        "source_exists": False,
                        "expected_state": "skipped",
                        "assessment_result": "not_applicable",
                        "finding": False,
                        "requires_review": False,
                        "cve_candidate_count": 0,
                        "cves": [],
                        "note": (
                            "Checklist skipped/not applicable; "
                            "MFA tidak tersedia pada aplikasi."
                        ),
                    }
                )
                continue

            errors.append(
                f"{item['id']} source artifact missing: "
                f"{relative_path}"
            )

            checklist_records.append(
                {
                    "id": item["id"],
                    "name": item["name"],
                    "status": "missing",
                    "source": relative_path,
                    "source_exists": False,
                    "expected_state": expected,
                    "assessment_result": "missing",
                    "finding": False,
                    "requires_review": True,
                    "cve_candidate_count": 0,
                    "cves": [],
                    "note": (
                        "Required checklist artifact tidak ditemukan."
                    ),
                }
            )

            counts["incomplete"] += 1
            continue

        try:
            source = load_yaml(path)
        except Exception as exc:
            message = (
                f"{item['id']} source artifact gagal dibaca: "
                f"{relative_path}: {type(exc).__name__}: {exc}"
            )

            errors.append(message)
            source_status[
                item["id"]
            ] = "error"

            counts["incomplete"] += 1

            checklist_records.append(
                {
                    "id": item["id"],
                    "name": item["name"],
                    "status": "error",
                    "source": relative_path,
                    "source_exists": True,
                    "expected_state": expected,
                    "assessment_result": "error",
                    "finding": False,
                    "requires_review": True,
                    "cve_candidate_count": 0,
                    "cves": [],
                    "note": message,
                }
            )

            continue

        if not isinstance(source, dict):
            message = (
                f"{item['id']} source artifact bukan mapping YAML: "
                f"{relative_path}"
            )

            errors.append(message)
            source_status[
                item["id"]
            ] = "invalid"

            counts["incomplete"] += 1

            checklist_records.append(
                {
                    "id": item["id"],
                    "name": item["name"],
                    "status": "invalid",
                    "source": relative_path,
                    "source_exists": True,
                    "expected_state": expected,
                    "assessment_result": "invalid",
                    "finding": False,
                    "requires_review": True,
                    "cve_candidate_count": 0,
                    "cves": [],
                    "note": message,
                }
            )

            continue

        actual_status = normalize_status(source)

        if actual_status == "completed":
            source_status[
                item["id"]
            ] = "completed"
            counts["completed"] += 1
        elif actual_status in {
            "deferred",
            "skipped",
            "not_applicable",
            "not-applicable",
        }:
            source_status[
                item["id"]
            ] = actual_status

            if actual_status == "deferred":
                counts["deferred"] += 1
            else:
                counts["skipped"] += 1
        else:
            source_status[
                item["id"]
            ] = actual_status or "unknown"
            counts["incomplete"] += 1

        finding = source_finding(source)
        requires_review = source_requires_review(source)

        if finding:
            finding_count += 1

        if requires_review:
            review_count += 1

        candidates = source_cve_candidates(source)
        cve_candidate_count += len(candidates)

        source_cves = extract_cve_ids(source)
        cve_ids.update(source_cves)

        identity = extract_source_identity(source)

        checklist_records.append(
            {
                "id": item["id"],
                "name": item["name"],
                "status": actual_status,
                "source": relative_path,
                "source_exists": True,
                "expected_state": expected,
                "assessment_result": assessment_result(source),
                "finding": finding,
                "requires_review": requires_review,
                "cve_candidate_count": len(candidates),
                "cves": source_cves,
                "source_identity": identity,
            }
        )

        source_artifacts.append(
            relative_path
        )

    # Fixed assessment semantics:
    # source findings are aggregated, not inferred.
    overall_finding = finding_count > 0
    overall_review = review_count > 0

    if errors:
        overall_review = True

    if counts["completed"] == len(CHECKLISTS):
        overall_result = "pass"
    elif errors:
        overall_result = "incomplete"
    else:
        overall_result = "completed_with_deferred_or_skipped"

    authentication = data.setdefault(
        "authentication",
        {},
    )

    authentication["checklists"] = checklist_records

    authentication["counts"] = {
        "total": len(CHECKLISTS),
        "completed": counts["completed"],
        "deferred": counts["deferred"],
        "skipped": counts["skipped"],
        "not_applicable": counts["not_applicable"],
        "missing": counts["missing"],
        "incomplete": counts["incomplete"],
    }

    authentication["assessment"] = {
        "finding_count": finding_count,
        "review_count": review_count,
        "finding": overall_finding,
        "requires_review": overall_review,
    }

    authentication["cve_correlation"] = {
        "candidate_count": cve_candidate_count,
        "unique_cve_count": len(cve_ids),
        "cves": sorted(cve_ids),
    }

    data["source_status"] = source_status

    data["assessment"] = {
        "result": overall_result,
        "finding": overall_finding,
        "requires_review": overall_review,
        "automatic_finding": False,
        "reason": (
            "Aggregated source checklist assessment states. "
            "No new finding was inferred by summary."
        ),
    }

    data["evidence"] = {
        "raw_evidence_modified": False,
        "source_artifacts": sorted(
            source_artifacts
        ),
    }

    data["errors"] = errors
    data["checklist"]["status"] = "completed"

    data["generated_at"] = data.get(
        "generated_at",
        now_iso(),
    )
    data["updated_at"] = now_iso()

    return data


def validate_document(
    data: dict[str, Any],
    active_project: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            "schema_version harus 1.0."
        )

    if data.get("project_id") != active_project.get(
        "project_id"
    ):
        errors.append(
            "project_id tidak sesuai active project."
        )

    checklist = data.get(
        "checklist",
        {},
    )

    if not isinstance(checklist, dict):
        errors.append(
            "checklist harus berupa mapping."
        )
    else:
        if checklist.get("id") != CHECKLIST_ID:
            errors.append(
                f"checklist.id harus {CHECKLIST_ID}."
            )

        if checklist.get("name") != CHECKLIST_NAME:
            errors.append(
                "checklist.name tidak sesuai."
            )

        if checklist.get("phase") != PHASE:
            errors.append(
                "checklist.phase tidak sesuai."
            )

    target = data.get(
        "target",
        {},
    )

    if not isinstance(target, dict):
        errors.append(
            "target harus berupa mapping."
        )
    else:
        expected_type = str(
            active_project.get(
                "assessment_type",
                "",
            )
        ).strip()

        actual_type = str(
            target.get(
                "assessment_type",
                "",
            )
        ).strip()

        if expected_type and actual_type != expected_type:
            errors.append(
                "assessment_type tidak sesuai active project: "
                f"{actual_type!r} != {expected_type!r}"
            )

    authentication = data.get(
        "authentication",
        {},
    )

    if not isinstance(authentication, dict):
        errors.append(
            "authentication harus berupa mapping."
        )
        return errors

    records = authentication.get(
        "checklists",
        [],
    )

    if not isinstance(records, list):
        errors.append(
            "authentication.checklists harus berupa list."
        )
        return errors

    record_ids = {
        str(record.get("id", "")).strip()
        for record in records
        if isinstance(record, dict)
    }

    expected_ids = {
        item["id"]
        for item in CHECKLISTS
    }

    missing_ids = expected_ids - record_ids

    if missing_ids:
        errors.append(
            "Checklist records missing: "
            + ", ".join(sorted(missing_ids))
        )

    counts = authentication.get(
        "counts",
        {},
    )

    if not isinstance(counts, dict):
        errors.append(
            "authentication.counts harus berupa mapping."
        )
    else:
        total = counts.get("total")

        if total != len(CHECKLISTS):
            errors.append(
                "authentication.counts.total tidak sesuai."
            )

    assessment = data.get(
        "assessment",
        {},
    )

    if not isinstance(assessment, dict):
        errors.append(
            "assessment harus berupa mapping."
        )
    else:
        if "finding" not in assessment:
            errors.append(
                "assessment.finding tidak tersedia."
            )

        if "requires_review" not in assessment:
            errors.append(
                "assessment.requires_review tidak tersedia."
            )

        if assessment.get("automatic_finding") is not False:
            errors.append(
                "assessment.automatic_finding harus false."
            )

    evidence = data.get(
        "evidence",
        {},
    )

    if not isinstance(evidence, dict):
        errors.append(
            "evidence harus berupa mapping."
        )
    elif evidence.get(
        "raw_evidence_modified"
    ) is not False:
        errors.append(
            "evidence.raw_evidence_modified harus false."
        )

    return errors


def cmd_init() -> int:
    active_project = load_active_project()
    path = summary_file()

    if path.exists():
        print(
            "[INFO] Authentication Summary sudah ada:"
        )
        print(path)
        return 0

    data = build_initial_document(
        active_project
    )

    save_yaml(path, data)

    print(
        "[PASS] Authentication Summary "
        "berhasil diinisialisasi:"
    )
    print(path)

    return 0


def cmd_generate() -> int:
    active_project = load_active_project()
    project_path = active_project_path(
        active_project
    )
    path = summary_file()

    if not project_path.exists():
        raise FileNotFoundError(
            f"Project path tidak ditemukan: {project_path}"
        )

    if path.exists():
        data = load_yaml(path)

        if not isinstance(data, dict):
            raise ValueError(
                "summary.yaml bukan mapping YAML yang valid."
            )
    else:
        data = build_initial_document(
            active_project
        )

    data = aggregate(
        data,
        active_project,
        project_path,
    )

    save_yaml(path, data)

    authentication = data["authentication"]
    counts = authentication["counts"]
    assessment = authentication["assessment"]

    print(
        "[PASS] Authentication Summary "
        "berhasil digenerate."
    )
    print(
        f"[PASS] Project      : "
        f"{active_project['project_id']}"
    )
    print(
        "[PASS] Checklists   : "
        f"{counts['completed']}/{counts['total']} completed"
    )
    print(
        "[INFO] Deferred     : "
        f"{counts['deferred']}"
    )
    print(
        "[INFO] Skipped/N/A  : "
        f"{counts['skipped']}"
    )
    print(
        "[INFO] Findings     : "
        f"{assessment['finding_count']}"
    )
    print(
        "[INFO] Review       : "
        f"{assessment['review_count']}"
    )
    print(
        "[INFO] Unique CVEs  : "
        f"{authentication['cve_correlation']['unique_cve_count']}"
    )
    print(
        f"[INFO] Assessment   : "
        f"{data['assessment']['result']}"
    )
    print(
        f"[INFO] Finding      : "
        f"{data['assessment']['finding']}"
    )
    print(
        f"[INFO] Review req.  : "
        f"{data['assessment']['requires_review']}"
    )

    if data.get("errors"):
        print(
            "[WARN] Terdapat error pada source artifact."
        )
        for error in data["errors"]:
            print(f"       - {error}")

    return 0


def cmd_show() -> int:
    path = summary_file()

    if not path.exists():
        print(
            "[INFO] Authentication Summary belum ada."
        )
        return 0

    data = load_yaml(path)

    if not isinstance(data, dict):
        raise ValueError(
            "summary.yaml bukan mapping YAML yang valid."
        )

    print(
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        ).rstrip()
    )

    return 0


def cmd_verify() -> int:
    active_project = load_active_project()
    path = summary_file()

    if not path.exists():
        print(
            "[ERROR] Authentication Summary "
            "belum ada. Jalankan init/generate."
        )
        return 1

    data = load_yaml(path)

    if not isinstance(data, dict):
        print(
            "[ERROR] summary.yaml bukan mapping YAML."
        )
        return 1

    errors = validate_document(
        data,
        active_project,
    )

    if errors:
        print(
            "[FAIL] Authentication Summary "
            "gagal validasi."
        )

        for error in errors:
            print(f"[FAIL] {error}")

        return 1

    data["checklist"]["status"] = "completed"
    data["verified_at"] = now_iso()
    data["updated_at"] = now_iso()

    save_yaml(path, data)

    authentication = data["authentication"]
    counts = authentication["counts"]
    assessment = authentication["assessment"]

    print(
        "[PASS] Authentication Summary "
        "memenuhi validasi."
    )
    print(
        "[PASS] Status       : completed"
    )
    print(
        f"[PASS] Project      : "
        f"{active_project['project_id']}"
    )
    print(
        "[PASS] Checklists   : "
        f"{counts['completed']}/{counts['total']} completed"
    )
    print(
        "[PASS] Deferred     : "
        f"{counts['deferred']}"
    )
    print(
        "[PASS] Skipped/N/A  : "
        f"{counts['skipped']}"
    )
    print(
        "[PASS] Findings     : "
        f"{assessment['finding_count']}"
    )
    print(
        "[PASS] Review       : "
        f"{assessment['review_count']}"
    )
    print(
        "[PASS] Assessment   : "
        f"{data['assessment']['result']}"
    )
    print(
        "[PASS] Finding      : "
        f"{data['assessment']['finding']}"
    )
    print(
        "[PASS] Review req.  : "
        f"{data['assessment']['requires_review']}"
    )

    return 0


def cmd_status() -> int:
    path = summary_file()

    if not path.exists():
        active_project = load_active_project()

        print(
            f"Project ID : "
            f"{active_project['project_id']}"
        )
        print(
            "Status     : not-initialized"
        )
        return 0

    data = load_yaml(path)

    status = "unknown"

    if isinstance(data, dict):
        checklist = data.get(
            "checklist",
            {},
        )

        if isinstance(checklist, dict):
            status = str(
                checklist.get(
                    "status",
                    "unknown",
                )
            ).strip().lower()

    print(
        f"Project ID : "
        f"{load_active_project()['project_id']}"
    )
    print(
        f"Status     : {status}"
    )

    return 0


def cmd_remove() -> int:
    path = summary_file()

    if not path.exists():
        print(
            "[INFO] Authentication Summary "
            "belum ada."
        )
        return 0

    path.unlink()

    print(
        "[PASS] Authentication Summary "
        "berhasil dihapus."
    )
    print(
        f"FILE   : {path}"
    )

    return 0


def print_help() -> None:
    print(
        f"""BrebesKab-CSIRT-Tools
Authentication Summary v{VERSION}

Usage:
  python scripts/authentication/summary.py init
  python scripts/authentication/summary.py generate
  python scripts/authentication/summary.py show
  python scripts/authentication/summary.py verify
  python scripts/authentication/summary.py status
  python scripts/authentication/summary.py remove
  python scripts/authentication/summary.py version

Commands:
  init      Create summary.yaml.
  generate  Aggregate authentication checklist artifacts.
  show      Show the complete summary document.
  verify    Validate the summary and mark completed.
  status    Show the current lifecycle status.
  remove    Remove summary.yaml.
  version   Show script version.

Aggregation:
  5-001  Authentication Login
  5-002  Session Management
  5-003  Logout / Session Invalidation
  5-004  Password Policy
  5-005  Password Recovery
  5-006  Brute-Force / Rate-Limit Protection
  5-007  MFA

State handling:
  completed
  deferred
  skipped / not_applicable
  missing / incomplete

Boundary:
  Aggregation only.
  No network requests.
  No active probing.
  No new findings inferred.
  CVE correlation is secondary metadata only.
"""
    )


def main() -> int:
    command = (
        sys.argv[1].strip().lower()
        if len(sys.argv) > 1
        else "help"
    )

    if command == "version":
        print(
            f"BrebesKab-CSIRT-Tools "
            f"authentication summary.py v{VERSION}"
        )
        print(
            "Phase    : 05 Authentication"
        )
        print(
            "Item     : 5-008 Authentication Summary"
        )
        print(
            "Schema   : 1.0"
        )
        print(
            "Sources  : 5-001 through 5-007"
        )
        print(
            "Boundary : aggregation only; no active probing"
        )
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

        if command in {
            "help",
            "-h",
            "--help",
        }:
            print_help()
            return 0

        print(
            f"[ERROR] Command tidak dikenal: {command}"
        )
        print_help()
        return 2

    except (
        FileNotFoundError,
        RuntimeError,
        ValueError,
        yaml.YAMLError,
    ) as exc:
        print(
            f"[ERROR] {exc}"
        )
        return 1

    except Exception as exc:
        print(
            "[ERROR] Unexpected failure: "
            f"{type(exc).__name__}: {exc}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())