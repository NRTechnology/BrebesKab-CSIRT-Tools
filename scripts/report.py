#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools — Deterministic Penetration Test Report Generator

Generates:
    <project_root>/23-final-sign-off/penetration-test-report.docx

Template:
    <repo_root>/reports/templates/template.docx

Template tags:
    {{BODYREPORT}}       → isi laporan utama
    {{LAMPIRANREPORT}}   → isi seluruh lampiran

Primary inputs:
    .runtime/active-project.yaml
    <project_root>/23-final-sign-off/evidence.json
    <project_root>/23-final-sign-off/evidence.yaml   (fallback)
    <project_root>/23-final-sign-off/report-prompt.md
    <project_root>/23-final-sign-off/chatgpt-recommendation.yaml (optional)

Design principles:
- Evidence is the source of truth.
- This script never changes finding/checklist status in evidence.
- ChatGPT recommendations are optional expert-review material.
- Recommendations are validated before inclusion.
- Missing recommendation file does not prevent report generation.
- Dates/statuses are not invented from the report generation timestamp.
- The report is deterministic and suitable for repeatable generation.

Requirements:
    Python 3.10+
    PyYAML
    python-docx

Example:
    python scripts/report.py

Optional:
    python scripts/report.py --project-root C:\\...\\projects\\PENTEST-2026-002
    python scripts/report.py --recommendation-file C:\\...\\chatgpt-recommendation.yaml
    python scripts/report.py --output C:\\...\\penetration-test-report.docx
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML is required. Install with: pip install pyyaml")
    raise SystemExit(2)

try:
    from docx import Document
    from docx.enum.section import WD_SECTION
    from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.style import WD_STYLE_TYPE
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor
except ImportError:
    print("[ERROR] python-docx is required. Install with: pip install python-docx")
    raise SystemExit(2)


SCRIPT_VERSION = "1.2.1"

ACTIVE_PROJECT_RELATIVE = Path(".runtime") / "active-project.yaml"
FINAL_DIRNAME = "23-final-sign-off"

EVIDENCE_JSON = "evidence.json"
EVIDENCE_YAML = "evidence.yaml"
REPORT_PROMPT = "report-prompt.md"
RECOMMENDATION_FILE = "chatgpt-recommendation.yaml"
OUTPUT_DOCX = "penetration-test-report.docx"
TEMPLATE_RELATIVE = Path("reports") / "templates" / "template.docx"
BODYREPORT_TAG = "{{BODYREPORT}}"
LAMPIRANREPORT_TAG = "{{LAMPIRANREPORT}}"

RECOMMENDATION_SCHEMA = "brebeskab-csirt-chatgpt-recommendation/v1"

VALID_PRIORITIES = {"Critical", "High", "Medium", "Low", "Informational"}
VALID_RECOMMENDATION_TYPES = {"finding", "hardening", "review", "observation", "process"}
VALID_RECOMMENDATION_STATUSES = {
    "recommended",
    "requires_validation",
    "informational",
    "accepted",
    "completed",
}

# Word-safe display widths.
TABLE_FONT_SIZE = 8
BODY_FONT_SIZE = 9.5
SMALL_FONT_SIZE = 8
TITLE_FONT_SIZE = 25
H1_FONT_SIZE = 17
H2_FONT_SIZE = 13
H3_FONT_SIZE = 11

# Conservative page margins.
MARGIN_TOP = 0.72
MARGIN_BOTTOM = 0.65
MARGIN_LEFT = 0.72
MARGIN_RIGHT = 0.72


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any, default: str = "—") -> str:
    if value is None:
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = str(value).strip()
    return text if text else default


def clean_multiline(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(safe_text(x, "") for x in value if safe_text(x, ""))
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    return str(value).strip()


def first_nonempty(*values: Any, default: str = "—") -> str:
    for value in values:
        if value is None:
            continue
        text = safe_text(value, "")
        if text:
            return text
    return default


def normalize_relpath(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("\\", "/").lstrip("./")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return data if isinstance(data, dict) else {}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def deep_get(data: Any, *paths: str, default: Any = None) -> Any:
    """Return the first non-empty dotted path."""
    for path in paths:
        current = data
        ok = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                ok = False
                break
        if ok and current not in (None, "", [], {}):
            return current
    return default


def listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Active project
# ---------------------------------------------------------------------------

def find_repo_root(start: Path) -> Path:
    start = start.resolve()
    candidates = [start] + list(start.parents)
    for candidate in candidates:
        if (candidate / ACTIVE_PROJECT_RELATIVE).is_file():
            return candidate
    # Fallback: preserve the old "repo root" behavior.
    return start


def load_active_project(repo_root: Path) -> dict[str, Any]:
    path = repo_root / ACTIVE_PROJECT_RELATIVE
    if not path.is_file():
        raise FileNotFoundError(
            f"Active project file not found: {path}"
        )

    data = load_yaml(path)
    if not data:
        raise ValueError(f"Active project file is empty: {path}")

    project = data.get("project")
    nested = project if isinstance(project, dict) else {}

    project_id = first_nonempty(
        data.get("project_id"),
        data.get("id"),
        nested.get("project_id"),
        nested.get("id"),
        default="",
    )

    project_path = first_nonempty(
        data.get("project_path"),
        data.get("path"),
        data.get("root"),
        data.get("project_root"),
        nested.get("project_path"),
        nested.get("path"),
        nested.get("root"),
        nested.get("project_root"),
        default="",
    )

    return {
        "path": path,
        "raw": data,
        "project_id": project_id,
        "project_path": project_path,
    }


def resolve_project_root(
    repo_root: Path,
    active: dict[str, Any],
    explicit_project_root: str | None = None,
) -> Path:
    if explicit_project_root:
        candidate = Path(explicit_project_root).expanduser()
        if not candidate.is_absolute():
            candidate = repo_root / candidate
        return candidate.resolve()

    project_path = active.get("project_path", "")
    if project_path:
        candidate = Path(project_path).expanduser()
        if not candidate.is_absolute():
            candidate = repo_root / candidate
        return candidate.resolve()

    project_id = active.get("project_id", "")
    if project_id:
        return (repo_root / "projects" / project_id).resolve()

    raise ValueError(
        "active-project.yaml must contain project_id or project_path."
    )


# ---------------------------------------------------------------------------
# Evidence loading / normalization
# ---------------------------------------------------------------------------

def load_evidence(project_root: Path) -> tuple[dict[str, Any], Path]:
    final_dir = project_root / FINAL_DIRNAME
    json_path = final_dir / EVIDENCE_JSON
    yaml_path = final_dir / EVIDENCE_YAML

    if json_path.is_file():
        data = load_json(json_path)
        if not isinstance(data, dict):
            raise ValueError(f"Evidence JSON is not an object: {json_path}")
        return data, json_path

    if yaml_path.is_file():
        data = load_yaml(yaml_path)
        if not isinstance(data, dict):
            raise ValueError(f"Evidence YAML is not an object: {yaml_path}")
        return data, yaml_path

    raise FileNotFoundError(
        f"Neither {json_path} nor {yaml_path} exists."
    )


def _bool_any(values: Any) -> bool:
    return any(
        value is True or str(value).strip().lower() == "true"
        for value in listify(values)
    )


def _first_status(values: Any) -> str:
    vals = [str(x).strip() for x in listify(values) if str(x).strip()]
    if not vals:
        return "—"
    preferred = (
        "completed", "complete", "passed", "pass", "closed",
        "partial", "incomplete", "in-progress", "in_progress",
        "failed", "review", "requires_review",
    )
    lowered = {x.lower(): x for x in vals}
    for wanted in preferred:
        if wanted in lowered:
            return lowered[wanted]
    return vals[0]


def _first_assessment_result(values: Any) -> Any:
    vals = [x for x in listify(values) if x not in (None, "", [])]
    if not vals:
        return ""
    for value in vals:
        if isinstance(value, dict):
            return value
    return vals[0]


def load_checklist_title_map(project_root: Path | None) -> dict[str, str]:
    if project_root is None:
        return {}
    path = project_root / "checklist.yaml"
    if not path.is_file():
        return {}
    try:
        data = load_yaml(path)
    except Exception:
        return {}

    result: dict[str, str] = {}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            cid = first_nonempty(
                value.get("id"),
                value.get("checklist_id"),
                default="",
            )
            name = first_nonempty(
                value.get("name"),
                value.get("title"),
                value.get("checklist_name"),
                default="",
            )
            if cid and name and re.fullmatch(r"\d{1,2}-\d{3}", str(cid)):
                result[str(cid)] = name
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return result


def _normalize_checklist_record(
    record: dict[str, Any],
    title_map: dict[str, str],
) -> dict[str, Any]:
    cid = first_nonempty(
        record.get("checklist_id"),
        record.get("id"),
        default="",
    )
    statuses = listify(record.get("statuses"))
    assessment_results = listify(record.get("assessment_results"))
    findings = listify(record.get("findings"))
    reviews = listify(record.get("requires_review"))
    metrics = record.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}

    result = _first_assessment_result(assessment_results)
    if isinstance(result, dict):
        observation = json.dumps(result, ensure_ascii=False, sort_keys=True)
    else:
        observation = safe_text(result, "")

    normalized = dict(record)
    normalized.update({
        "id": cid,
        "checklist_id": cid,
        "title": first_nonempty(
            record.get("title"),
            record.get("name"),
            title_map.get(cid),
            default=f"Checklist {cid}",
        ),
        "name": first_nonempty(
            record.get("name"),
            title_map.get(cid),
            default=f"Checklist {cid}",
        ),
        "status": _first_status(statuses),
        "assessment_result": result,
        "observation": observation,
        "finding": _bool_any(findings),
        "requires_review": _bool_any(reviews),
        "metrics": metrics,
    })
    return normalized


def extract_checklists(
    evidence: dict[str, Any],
    project_root: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Evidence schema brebeskab-csirt-final-report-source/v1 stores the
    authoritative checklist index under aggregate.checklists as a mapping:
        {"3-006": {...}, "10-001": {...}, ...}
    """
    title_map = load_checklist_title_map(project_root)

    aggregate = evidence.get("aggregate")
    if isinstance(aggregate, dict):
        candidate = aggregate.get("checklists")
        if isinstance(candidate, dict):
            records = []
            for key, value in candidate.items():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("checklist_id", key)
                    records.append(_normalize_checklist_record(item, title_map))
            if records:
                return records
        elif isinstance(candidate, list):
            return [
                _normalize_checklist_record(x, title_map)
                for x in candidate
                if isinstance(x, dict)
            ]

    candidates = [
        evidence.get("checklists"),
        evidence.get("checklist"),
        deep_get(evidence, "assessment.checklists"),
        deep_get(evidence, "results.checklists"),
        deep_get(evidence, "data.checklists"),
    ]

    for candidate in candidates:
        if isinstance(candidate, list):
            return [
                _normalize_checklist_record(x, title_map)
                for x in candidate
                if isinstance(x, dict)
            ]
        if isinstance(candidate, dict):
            result = []
            for key, value in candidate.items():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("checklist_id", key)
                    result.append(_normalize_checklist_record(item, title_map))
            if result:
                return result

    return []

def extract_source_files(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    for path in (
        "source_files",
        "sources",
        "evidence_index",
        "files",
        "source_inventory",
    ):
        candidate = evidence.get(path)
        if isinstance(candidate, list):
            return [x for x in candidate if isinstance(x, dict)]

        if isinstance(candidate, dict):
            result: list[dict[str, Any]] = []
            for key, value in candidate.items():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("path", key)
                    result.append(item)
                else:
                    result.append({"path": key, "value": value})
            if result:
                return result
    return []


def extract_findings(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    aggregate = evidence.get("aggregate")
    candidates = []
    if isinstance(aggregate, dict):
        candidates.append(aggregate.get("findings"))
    candidates.extend([
        evidence.get("findings"),
        evidence.get("confirmed_findings"),
        evidence.get("security_findings"),
    ])

    for candidate in candidates:
        if isinstance(candidate, list):
            return [x for x in candidate if isinstance(x, dict)]
        if isinstance(candidate, dict):
            result = []
            for key, value in candidate.items():
                if isinstance(value, dict):
                    item = dict(value)
                    item.setdefault("id", key)
                    result.append(item)
                elif value:
                    result.append({"id": key, "detail": value})
            if result:
                return result
    return []

def extract_project_metadata(
    evidence: dict[str, Any],
    active: dict[str, Any],
) -> dict[str, Any]:
    project = evidence.get("project")
    if not isinstance(project, dict):
        project = {}

    metadata = evidence.get("project_metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    assessment = metadata.get("assessment.yaml")
    if not isinstance(assessment, dict):
        assessment = {}

    target_file = metadata.get("target.yaml")
    if not isinstance(target_file, dict):
        target_file = {}
    target = target_file.get("target")
    if not isinstance(target, dict):
        target = {}

    return {
        "project_id": first_nonempty(
            assessment.get("project_id"),
            project.get("project_id"),
            active.get("project_id"),
            default="—",
        ),
        "application": first_nonempty(
            assessment.get("application"),
            target.get("application"),
            default="—",
        ),
        "target": first_nonempty(
            assessment.get("target"),
            target.get("target_url"),
            target.get("target"),
            default="—",
        ),
        "tester": first_nonempty(
            assessment.get("tester"),
            default="—",
        ),
        "reviewer": first_nonempty(
            assessment.get("reviewer"),
            default="—",
        ),
        "environment": first_nonempty(
            assessment.get("environment"),
            target.get("environment"),
            default="—",
        ),
        "assessment_type": first_nonempty(
            assessment.get("assessment_type"),
            target.get("assessment_type"),
            default="—",
        ),
        "assessment_status": first_nonempty(
            assessment.get("status"),
            default="—",
        ),
        "created_at": assessment.get("created_at"),
        "started_at": assessment.get("started_at"),
        "completed_at": assessment.get("completed_at"),
        "generated_at": first_nonempty(
            evidence.get("generated_at"),
            default="—",
        ),
        "scope": metadata.get("scope.yaml"),
        "roe": metadata.get("rules-of-engagement.yaml")
            or metadata.get("roe.yaml"),
    }

def extract_metrics(
    evidence: dict[str, Any],
    checklists: list[dict[str, Any]],
    source_files: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    aggregate = evidence.get("aggregate")
    counts = aggregate.get("high_level_counts") if isinstance(aggregate, dict) else {}
    if not isinstance(counts, dict):
        counts = {}

    return {
        "source_files": first_nonempty(
            counts.get("file_count"),
            len(source_files),
            default="0",
        ),
        "checklists": first_nonempty(
            counts.get("checklist_count"),
            len(checklists),
            default="0",
        ),
        "completed": first_nonempty(
            counts.get("completed_checklists"),
            sum(checklist_status(x).lower() in {
                "completed", "complete", "passed", "pass", "closed"
            } for x in checklists),
            default="0",
        ),
        "incomplete": first_nonempty(
            counts.get("incomplete_checklists"),
            sum(checklist_status(x).lower() in {
                "incomplete", "partial", "in-progress", "in_progress"
            } for x in checklists),
            default="0",
        ),
        "findings": first_nonempty(
            counts.get("checklists_with_finding_true"),
            sum(checklist_finding(x) for x in checklists),
            default="0",
        ),
        "review": first_nonempty(
            counts.get("checklists_with_review_true"),
            sum(checklist_review(x) for x in checklists),
            default="0",
        ),
        "parse_errors": len(
            aggregate.get("parse_errors", [])
            if isinstance(aggregate, dict) and isinstance(aggregate.get("parse_errors", []), list)
            else []
        ),
    }

def resolve_evidence_ref(
    project_root: Path,
    ref: str,
    source_files: list[dict[str, Any]],
) -> bool:
    normalized = normalize_relpath(ref)
    if not normalized:
        return False

    # First trust the evidence inventory.
    inventory = {
        normalize_relpath(
            first_nonempty(
                item.get("path"),
                item.get("relative_path"),
                item.get("file"),
                default="",
            )
        )
        for item in source_files
        if isinstance(item, dict)
    }
    if normalized in inventory:
        return True

    # Also accept a directly existing project-relative path.
    candidate = project_root / normalized
    return candidate.is_file()


def validate_recommendations(
    data: dict[str, Any],
    project_id: str,
    checklists: list[dict[str, Any]],
    source_files: list[dict[str, Any]],
    project_root: Path | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []

    if data.get("schema") != RECOMMENDATION_SCHEMA:
        errors.append(
            f"schema must be {RECOMMENDATION_SCHEMA!r}, got {data.get('schema')!r}"
        )

    rec_project_id = deep_get(data, "project.project_id")
    if rec_project_id != project_id:
        errors.append(
            f"project.project_id mismatch: evidence={project_id!r}, "
            f"recommendation={rec_project_id!r}"
        )

    recommendations = data.get("recommendations")
    if not isinstance(recommendations, list):
        errors.append("recommendations must be a list.")
        return [], errors

    valid_checklist_ids: set[str] = set()
    for item in checklists:
        cid = first_nonempty(
            item.get("checklist_id"),
            item.get("id"),
            default="",
        )
        if cid:
            valid_checklist_ids.add(cid)

    seen_ids: set[str] = set()
    valid: list[dict[str, Any]] = []

    required = {
        "id",
        "title",
        "category",
        "priority",
        "checklist_ids",
        "type",
        "status",
        "evidence_refs",
        "observation",
        "recommendation",
        "rationale",
        "requires_manual_validation",
    }

    for index, rec in enumerate(recommendations, start=1):
        if not isinstance(rec, dict):
            errors.append(f"recommendations[{index}] is not an object.")
            continue

        missing = sorted(required - set(rec.keys()))
        if missing:
            errors.append(
                f"recommendations[{index}] missing fields: {', '.join(missing)}"
            )
            continue

        rid = safe_text(rec.get("id"), "")
        if not rid:
            errors.append(f"recommendations[{index}] has empty id.")
        elif rid in seen_ids:
            errors.append(f"duplicate recommendation id: {rid}")
        else:
            seen_ids.add(rid)

        priority = safe_text(rec.get("priority"), "")
        if priority not in VALID_PRIORITIES:
            errors.append(
                f"{rid}: invalid priority {priority!r}; "
                f"allowed={sorted(VALID_PRIORITIES)}"
            )

        rtype = safe_text(rec.get("type"), "")
        if rtype not in VALID_RECOMMENDATION_TYPES:
            errors.append(
                f"{rid}: invalid type {rtype!r}; "
                f"allowed={sorted(VALID_RECOMMENDATION_TYPES)}"
            )

        status = safe_text(rec.get("status"), "")
        if status not in VALID_RECOMMENDATION_STATUSES:
            errors.append(
                f"{rid}: invalid status {status!r}; "
                f"allowed={sorted(VALID_RECOMMENDATION_STATUSES)}"
            )

        checklist_ids = rec.get("checklist_ids")
        if not isinstance(checklist_ids, list) or not checklist_ids:
            errors.append(f"{rid}: checklist_ids must be a non-empty list.")
        else:
            for cid in checklist_ids:
                if str(cid) not in valid_checklist_ids:
                    errors.append(
                        f"{rid}: checklist id {cid!r} not found in evidence."
                    )

        evidence_refs = rec.get("evidence_refs")
        if not isinstance(evidence_refs, list) or not evidence_refs:
            errors.append(f"{rid}: evidence_refs must be a non-empty list.")
        else:
            for ref in evidence_refs:
                if not resolve_evidence_ref(
                    project_root=project_root or Path("."),
                    ref=str(ref),
                    source_files=source_files,
                ):
                    # Do a second check only against inventory; actual path is
                    # intentionally not required here because evidence may
                    # contain normalized source paths from another platform.
                    inventory = {
                        normalize_relpath(
                            first_nonempty(
                                x.get("path"),
                                x.get("relative_path"),
                                x.get("file"),
                                default="",
                            )
                        )
                        for x in source_files
                        if isinstance(x, dict)
                    }
                    if normalize_relpath(ref) not in inventory:
                        errors.append(
                            f"{rid}: evidence ref not found in source inventory: {ref}"
                        )

        if not isinstance(rec.get("requires_manual_validation"), bool):
            errors.append(
                f"{rid}: requires_manual_validation must be boolean."
            )

        valid.append(rec)

    # A structurally valid recommendation can be included only if there are
    # no validation errors. This prevents partial/ambiguous AI output from
    # silently entering the final report.
    if errors:
        return [], errors

    return valid, []


def load_optional_recommendations(
    project_root: Path,
    project_id: str,
    checklists: list[dict[str, Any]],
    source_files: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str], Path | None]:
    path = project_root / FINAL_DIRNAME / RECOMMENDATION_FILE
    if not path.is_file():
        return [], [], None

    try:
        data = load_yaml(path)
    except Exception as exc:
        return [], [f"Cannot parse recommendation file: {exc}"], path

    recs, errors = validate_recommendations(
        data=data,
        project_id=project_id,
        checklists=checklists,
        source_files=source_files,
        project_root=project_root,
    )
    return recs, errors, path


# ---------------------------------------------------------------------------
# Word helpers
# ---------------------------------------------------------------------------

def set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = tc_pr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tc_pr.append(shd)
    shd.set(qn("w:fill"), fill)


def set_cell_margins(cell, top=80, start=80, bottom=80, end=80) -> None:
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    tc_mar = tc_pr.first_child_found_in("w:tcMar")
    if tc_mar is None:
        tc_mar = OxmlElement("w:tcMar")
        tc_pr.append(tc_mar)

    for margin, value in (
        ("top", top),
        ("start", start),
        ("bottom", bottom),
        ("end", end),
    ):
        node = tc_mar.find(qn(f"w:{margin}"))
        if node is None:
            node = OxmlElement(f"w:{margin}")
            tc_mar.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def set_repeat_table_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


def set_keep_with_next(paragraph) -> None:
    p_pr = paragraph._p.get_or_add_pPr()
    keep = OxmlElement("w:keepNext")
    p_pr.append(keep)


def set_page_break_before(paragraph) -> None:
    p_pr = paragraph._p.get_or_add_pPr()
    node = OxmlElement("w:pageBreakBefore")
    p_pr.append(node)


def add_hyperlink(paragraph, text: str, url: str) -> None:
    part = paragraph.part
    r_id = part.relate_to(
        url,
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
        is_external=True,
    )

    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), r_id)

    new_run = OxmlElement("w:r")
    r_pr = OxmlElement("w:rPr")

    color = OxmlElement("w:color")
    color.set(qn("w:val"), "0563C1")
    r_pr.append(color)

    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    r_pr.append(underline)

    new_run.append(r_pr)
    text_node = OxmlElement("w:t")
    text_node.text = text
    new_run.append(text_node)
    hyperlink.append(new_run)
    paragraph._p.append(hyperlink)


def add_field(run, field: str) -> None:
    fld_char1 = OxmlElement("w:fldChar")
    fld_char1.set(qn("w:fldCharType"), "begin")

    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = field

    fld_char2 = OxmlElement("w:fldChar")
    fld_char2.set(qn("w:fldCharType"), "end")

    run._r.append(fld_char1)
    run._r.append(instr)
    run._r.append(fld_char2)


def set_run_font(run, size: float | None = None, bold=False, italic=False):
    run.font.name = "Aptos"
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "Aptos")
    if size:
        run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic


def style_document(doc: Document) -> None:
    section = doc.sections[0]
    section.top_margin = Inches(MARGIN_TOP)
    section.bottom_margin = Inches(MARGIN_BOTTOM)
    section.left_margin = Inches(MARGIN_LEFT)
    section.right_margin = Inches(MARGIN_RIGHT)

    styles = doc.styles

    normal = styles["Normal"]
    normal.font.name = "Aptos"
    normal._element.rPr.rFonts.set(qn("w:eastAsia"), "Aptos")
    normal.font.size = Pt(BODY_FONT_SIZE)
    normal.paragraph_format.space_after = Pt(5)
    normal.paragraph_format.line_spacing = 1.08

    for style_name, size, color, before, after in (
        ("Title", TITLE_FONT_SIZE, "1F2937", 0, 12),
        ("Heading 1", H1_FONT_SIZE, "17365D", 12, 7),
        ("Heading 2", H2_FONT_SIZE, "24527A", 9, 5),
        ("Heading 3", H3_FONT_SIZE, "365F91", 7, 4),
    ):
        style = styles[style_name]
        style.font.name = "Aptos Display" if style_name != "Title" else "Aptos Display"
        style._element.rPr.rFonts.set(qn("w:eastAsia"), style.font.name)
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor.from_string(color)
        style.font.bold = True
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)

    if "Caption" in styles:
        styles["Caption"].font.name = "Aptos"
        styles["Caption"].font.size = Pt(SMALL_FONT_SIZE)
        styles["Caption"].font.italic = True

    # Custom small styles.
    for name, base, size in (
        ("Report Small", "Normal", SMALL_FONT_SIZE),
        ("Report Table", "Normal", TABLE_FONT_SIZE),
    ):
        if name not in styles:
            style = styles.add_style(name, WD_STYLE_TYPE.PARAGRAPH)
            style.base_style = styles[base]
        else:
            style = styles[name]
        style.font.name = "Aptos"
        style._element.rPr.rFonts.set(qn("w:eastAsia"), "Aptos")
        style.font.size = Pt(size)
        style.paragraph_format.space_after = Pt(2)

    # Footer.
    footer = section.footer
    p = footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("BrebesKab-CSIRT-Tools  •  Penetration Test Report  •  Page ")
    set_run_font(r, 8, italic=False)
    r2 = p.add_run()
    add_field(r2, "PAGE")
    set_run_font(r2, 8)


def add_title(doc: Document, text: str, subtitle: str | None = None):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(50)
    p.paragraph_format.space_after = Pt(15)
    r = p.add_run(text)
    set_run_font(r, TITLE_FONT_SIZE, bold=True)

    if subtitle:
        p2 = doc.add_paragraph()
        p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r2 = p2.add_run(subtitle)
        set_run_font(r2, 12, italic=True)


def add_horizontal_rule(paragraph):
    p_pr = paragraph._p.get_or_add_pPr()
    p_bdr = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "8")
    bottom.set(qn("w:space"), "1")
    bottom.set(qn("w:color"), "B7C9D6")
    p_bdr.append(bottom)
    p_pr.append(p_bdr)


def add_label_value(doc: Document, label: str, value: Any):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(2)
    r1 = p.add_run(f"{label}: ")
    set_run_font(r1, BODY_FONT_SIZE, bold=True)
    r2 = p.add_run(safe_text(value))
    set_run_font(r2, BODY_FONT_SIZE)


def add_bullet(doc: Document, text: str, level: int = 0):
    # Do not depend on Word built-in list styles because the supplied template
    # intentionally contains a minimal/custom style set.
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.22 + (0.22 * level))
    p.paragraph_format.first_line_indent = Inches(-0.16)
    p.paragraph_format.space_after = Pt(2)
    r = p.add_run("• ")
    set_run_font(r, BODY_FONT_SIZE, bold=False)
    r2 = p.add_run(text)
    set_run_font(r2, BODY_FONT_SIZE)
    return p


def add_numbered(doc: Document, text: str, number: int | None = None):
    # Manual numbering avoids dependence on the template's list styles.
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.22)
    p.paragraph_format.first_line_indent = Inches(-0.22)
    p.paragraph_format.space_after = Pt(2)
    prefix = f"{number}. " if number is not None else "• "
    r = p.add_run(prefix)
    set_run_font(r, BODY_FONT_SIZE, bold=False)
    r2 = p.add_run(text)
    set_run_font(r2, BODY_FONT_SIZE)
    return p


def add_note_box(doc: Document, title: str, body: str, fill="EAF2F8"):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.cell(0, 0)
    set_cell_shading(cell, fill)
    set_cell_margins(cell, 130, 150, 130, 150)

    p = cell.paragraphs[0]
    r = p.add_run(title)
    set_run_font(r, 9, bold=True)
    p2 = cell.add_paragraph()
    r2 = p2.add_run(body)
    set_run_font(r2, 8.5)
    doc.add_paragraph().paragraph_format.space_after = Pt(0)


def add_table(
    doc: Document,
    headers: list[str],
    rows: list[list[Any]],
    widths: list[float] | None = None,
    header_fill="17365D",
    font_size=TABLE_FONT_SIZE,
):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True

    header = table.rows[0]
    set_repeat_table_header(header)

    for i, label in enumerate(headers):
        cell = header.cells[i]
        set_cell_shading(cell, header_fill)
        set_cell_margins(cell)
        cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(str(label))
        set_run_font(r, font_size, bold=True)
        r.font.color.rgb = RGBColor(255, 255, 255)

    for row_index, row in enumerate(rows):
        cells = table.add_row().cells
        for i, value in enumerate(row):
            cell = cells[i]
            set_cell_margins(cell)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            text = safe_text(value)
            # Preserve deliberate newlines.
            parts = text.split("\n")
            for j, part in enumerate(parts):
                if j:
                    p.add_run().add_break()
                r = p.add_run(part)
                set_run_font(r, font_size)

            if row_index % 2 == 1:
                set_cell_shading(cell, "F6F8FA")

    if widths:
        for row in table.rows:
            for idx, width in enumerate(widths):
                if idx < len(row.cells):
                    row.cells[idx].width = Inches(width)

    doc.add_paragraph().paragraph_format.space_after = Pt(0)
    return table


def add_status_badge(paragraph, status: str):
    normalized = status.lower()
    mapping = {
        "completed": "2E7D32",
        "complete": "2E7D32",
        "pass": "2E7D32",
        "passed": "2E7D32",
        "incomplete": "C62828",
        "partial": "EF6C00",
        "review": "EF6C00",
        "requires_review": "EF6C00",
        "requires_validation": "EF6C00",
        "recommended": "1565C0",
        "informational": "546E7A",
    }
    fill = mapping.get(normalized, "607D8B")

    r = paragraph.add_run(f" {status} ")
    set_run_font(r, 8, bold=True)
    r.font.color.rgb = RGBColor(255, 255, 255)

    rpr = r._element.get_or_add_rPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    rpr.append(shd)


# ---------------------------------------------------------------------------
# Evidence extraction for report sections
# ---------------------------------------------------------------------------

def checklist_id(item: dict[str, Any]) -> str:
    return first_nonempty(
        item.get("checklist_id"),
        item.get("id"),
        default="—",
    )


def checklist_title(item: dict[str, Any]) -> str:
    return first_nonempty(
        item.get("title"),
        item.get("name"),
        item.get("checklist"),
        item.get("description"),
        default="—",
    )


def checklist_status(item: dict[str, Any]) -> str:
    return first_nonempty(
        item.get("status"),
        item.get("assessment_status"),
        item.get("result"),
        default="—",
    )


def checklist_review(item: dict[str, Any]) -> bool:
    value = item.get("requires_review")
    return value is True or str(value).lower() == "true"


def checklist_finding(item: dict[str, Any]) -> bool:
    value = item.get("finding")
    return value is True or str(value).lower() == "true"


def checklist_observation(item: dict[str, Any]) -> str:
    return first_nonempty(
        item.get("observation"),
        item.get("summary"),
        item.get("result_summary"),
        item.get("details"),
        item.get("assessment"),
        default="",
    )


def sort_checklists(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(item):
        cid = checklist_id(item)
        nums = [int(x) for x in re.findall(r"\d+", cid)]
        return (nums, cid)
    return sorted(items, key=key)


def status_summary(checklists: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter()
    for item in checklists:
        status = checklist_status(item).lower()
        counter[status] += 1
    return dict(counter)


def build_review_items(checklists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item for item in checklists
        if checklist_review(item)
        or checklist_status(item).lower() in {
            "review", "requires_review", "partial", "incomplete"
        }
    ]


def build_incomplete_items(checklists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item for item in checklists
        if checklist_status(item).lower() in {
            "incomplete", "partial", "in-progress", "in_progress"
        }
    ]


def recommendation_priority_counts(recs: list[dict[str, Any]]) -> Counter:
    return Counter(safe_text(x.get("priority")) for x in recs)


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def add_cover(
    doc: Document,
    meta: dict[str, Any],
    evidence_path: Path,
    recommendation_path: Path | None,
):
    add_title(
        doc,
        "PENETRATION TEST REPORT",
        "BrebesKab-CSIRT-Tools — Evidence-Driven Assessment",
    )

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(meta["application"])
    set_run_font(r, 18, bold=True)

    p2 = doc.add_paragraph()
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r2 = p2.add_run(meta["target"])
    set_run_font(r2, 11)

    doc.add_paragraph()
    add_table(
        doc,
        ["Assessment Attribute", "Value"],
        [
            ["Project ID", meta["project_id"]],
            ["Assessment Type", meta["assessment_type"]],
            ["Environment", meta["environment"]],
            ["Tester", meta["tester"]],
            ["Reviewer", meta["reviewer"]],
            ["Evidence Generated", meta["generated_at"]],
            ["Evidence Source", evidence_path.name],
            [
                "AI-Assisted Review",
                "Included" if recommendation_path else "Not provided",
            ],
        ],
        widths=[2.0, 4.7],
    )

    add_note_box(
        doc,
        "Important report principle",
        "This report is generated from collected evidence. "
        "Absence of confirmed findings does not mean the target is guaranteed secure. "
        "Items marked for review require human validation before final security conclusions.",
    )

    p3 = doc.add_paragraph()
    p3.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p3.paragraph_format.space_before = Pt(35)
    r3 = p3.add_run("Generated by BrebesKab-CSIRT-Tools")
    set_run_font(r3, 9, italic=True)


def add_executive_summary(
    doc: Document,
    meta: dict[str, Any],
    metrics: dict[str, Any],
    checklists: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
):
    doc.add_heading("1. Executive Summary", level=1)

    if findings:
        summary = (
            f"The assessment evidence contains {len(findings)} confirmed finding record(s). "
            "The findings section below is the authoritative presentation of those records."
        )
    else:
        summary = (
            "Berdasarkan evidence yang dikumpulkan, tidak terdapat security finding "
            "yang terkonfirmasi secara otomatis. Evidence tetap memuat item yang memerlukan "
            "manual review dan satu atau lebih checklist yang belum lengkap."
        )

    doc.add_paragraph(summary)

    p = doc.add_paragraph()
    p.add_run("Coverage: ").bold = True
    p.add_run(
        f"{metrics['checklists']} checklist; {metrics['completed']} completed; "
        f"{metrics['incomplete']} incomplete; {metrics['review']} review item(s); "
        f"{metrics['findings']} finding record(s); {metrics['parse_errors']} parse error(s)."
    )

    if recommendations:
        counts = recommendation_priority_counts(recommendations)
        priority_text = ", ".join(
            f"{k}: {counts[k]}"
            for k in ("Critical", "High", "Medium", "Low", "Informational")
            if counts.get(k)
        )
        p2 = doc.add_paragraph()
        p2.add_run("Expert review: ").bold = True
        p2.add_run(
            f"{len(recommendations)} recommendation(s) were supplied in the optional "
            f"ChatGPT review file. Priority distribution: {priority_text or 'none'}."
        )

    add_note_box(
        doc,
        "Interpretation boundary",
        "Evidence such as HTTP 200 responses, reflection, accepted uploads, disclosed versions, "
        "accepted HTTP methods, or replay behavior is presented as observed evidence. "
        "It is not automatically converted into a vulnerability unless the evidence explicitly "
        "records a confirmed finding.",
        fill="FFF8E1",
    )


def add_scope_roe(
    doc: Document,
    meta: dict[str, Any],
    evidence: dict[str, Any],
):
    """Render explicit target/port boundaries without inventing missing ROE terms."""
    from urllib.parse import urlsplit

    doc.add_heading("2. Ruang Lingkup & Aturan Pelaksanaan Pengujian", level=1)

    add_label_value(doc, "ID Proyek", meta["project_id"])
    add_label_value(doc, "Aplikasi", meta["application"])
    add_label_value(doc, "Target", meta["target"])
    add_label_value(doc, "Jenis Pengujian", meta["assessment_type"])
    add_label_value(doc, "Lingkungan", meta["environment"])

    # Scope boundary confirmed by the project owner: web ports 80 and 443 only.
    # This explicit project constraint takes precedence over missing/incomplete
    # scope metadata; the original metadata is still shown below for traceability.
    target_url = safe_text(meta.get("target"), "")
    parsed_target = urlsplit(
        target_url if "://" in target_url else f"https://{target_url}"
    )
    target_host = parsed_target.hostname or target_url or "target yang tercantum"
    scope = meta.get("scope")
    roe = meta.get("roe")

    doc.add_heading("2.1 Ruang Lingkup Pengujian", level=2)
    doc.add_paragraph(
        "Pengujian dibatasi pada aplikasi web yang menjadi target penilaian. "
        "Batas port yang diizinkan adalah TCP/80 (HTTP) dan TCP/443 (HTTPS) saja. "
        "Batas ini berlaku untuk aktivitas pengujian dan enumerasi layanan; "
        "port lain tidak termasuk dalam ruang lingkup."
    )
    add_bullet(doc, f"Target host: {target_host}. URL target: {target_url or 'tidak tercantum'}.")
    add_bullet(doc, "Port yang termasuk scope: TCP/80 untuk HTTP dan TCP/443 untuk HTTPS.")
    add_bullet(
        doc,
        "Aktivitas yang termasuk scope: pemeriksaan aplikasi web dan konfigurasi "
        "web yang dapat diamati melalui target pada port 80/443, termasuk endpoint "
        "yang ditemukan selama pengujian pada host target yang sama."
    )
    add_bullet(
        doc,
        "Di luar scope: port TCP/UDP selain 80 dan 443, layanan non-web pada port lain, "
        "serta host, subdomain, alamat IP, atau aplikasi lain yang tidak dinyatakan "
        "secara eksplisit sebagai target."
    )
    add_bullet(
        doc,
        "Temuan atau sinyal yang muncul dari respons aplikasi dicatat sebagai evidence; "
        "respons tersebut tidak otomatis dianggap sebagai kerentanan terkonfirmasi."
    )

    if isinstance(scope, dict) and scope:
        doc.add_paragraph(
            "Metadata scope yang tersedia pada paket evidence ditampilkan berikut "
            "sebagai informasi tambahan. Batas port TCP/80 dan TCP/443 di atas tetap "
            "menjadi batas operasional pengujian."
        )
        for key, value in scope.items():
            add_label_value(doc, str(key), value)
    elif scope:
        doc.add_paragraph("Metadata scope tambahan:")
        doc.add_paragraph(clean_multiline(scope))
    else:
        doc.add_paragraph(
            "Rincian scope operasional pada metadata evidence tidak terisi secara "
            "terpisah. Karena itu, laporan ini menyatakan batas yang telah ditetapkan "
            "secara eksplisit: host target aplikasi web dan hanya port TCP/80 serta "
            "TCP/443."
        )

    doc.add_heading("2.2 Aturan Pelaksanaan Pengujian", level=2)
    doc.add_paragraph(
        "Aturan pelaksanaan berikut menjabarkan batas operasional yang dapat "
        "dipastikan dari scope penilaian. Aturan ini tidak memperluas otorisasi "
        "ke aset atau port lain."
    )
    for rule in [
        "Pengujian hanya diarahkan ke host target yang tercantum dalam laporan dan "
        "layanan web pada TCP/80 atau TCP/443.",
        "Tidak melakukan pemindaian atau pengujian layanan pada port selain TCP/80 "
        "dan TCP/443, sekalipun layanan tersebut terlihat dari hasil observasi.",
        "Penemuan tautan atau endpoint baru tidak memperluas scope ke host, subdomain, "
        "alamat IP, atau aplikasi lain; endpoint hanya diuji jika masih berada pada "
        "host target yang sama.",
        "Status HTTP seperti 200, 302, 403, atau 500, refleksi payload, pesan error, "
        "atau respons upload yang diterima dicatat sebagai observasi. Status tersebut "
        "bukan bukti tunggal bahwa eksploitasi berhasil atau kerentanan telah terkonfirmasi.",
        "Pengujian lanjutan yang berpotensi mengganggu ketersediaan layanan, mengubah "
        "atau menghapus data, mempertahankan akses, atau mengakses data di luar kebutuhan "
        "validasi tidak dianggap otomatis diizinkan oleh scope ini; diperlukan otorisasi "
        "terpisah yang eksplisit.",
    ]:
        add_bullet(doc, rule)

    if isinstance(roe, dict) and roe:
        doc.add_paragraph(
            "Metadata Rules of Engagement yang tersedia pada paket evidence:"
        )
        for key, value in roe.items():
            add_label_value(doc, str(key), value)
    elif roe:
        doc.add_paragraph("Metadata Rules of Engagement tambahan:")
        doc.add_paragraph(clean_multiline(roe))
    else:
        add_note_box(
            doc,
            "Catatan kelengkapan Rules of Engagement",
            "Paket evidence tidak memuat blok Rules of Engagement terpisah. "
            "Karena itu, laporan ini tidak mengarang jadwal pengujian, batas laju request, "
            "kontak eskalasi, prosedur penghentian, atau ketentuan penanganan data yang "
            "belum terdokumentasi. Ketentuan tersebut perlu dikonfirmasi pada dokumen "
            "otorisasi/ROE proyek jika diperlukan.",
            fill="FFF8E1",
        )


def add_methodology(
    doc: Document,
    evidence: dict[str, Any],
    checklists: list[dict[str, Any]],
):
    doc.add_heading("3. Methodology", level=1)

    methodology = deep_get(
        evidence,
        "methodology",
        "assessment.methodology",
        "method.methodology",
    )

    if methodology:
        doc.add_paragraph(clean_multiline(methodology))
    else:
        doc.add_paragraph(
            "The assessment was executed using the checklist structure represented by "
            "BrebesKab-CSIRT-Tools. Evidence was collected by checklist-specific tooling, "
            "then aggregated into an evidence bundle for final reporting."
        )

    steps = [
        "Preparation and scope confirmation.",
        "Reconnaissance and attack-surface mapping.",
        "Infrastructure and web-server configuration assessment.",
        "Security-header, session, authentication and authorization checks.",
        "Input-validation, file-upload and application-security checks.",
        "Evidence aggregation and consistency review.",
        "Final report generation from the evidence bundle.",
    ]
    doc.add_heading("Assessment flow", level=2)
    for index, step in enumerate(steps, start=1):
        add_numbered(doc, step, index)

    doc.add_heading("Evidence handling principle", level=2)
    doc.add_paragraph(
        "The report generator does not reinterpret raw probe output into a finding. "
        "It reports the status and observations recorded by the evidence collector. "
        "Manual review recommendations are separated from confirmed findings."
    )


def add_coverage(
    doc: Document,
    checklists: list[dict[str, Any]],
):
    doc.add_heading("4. Assessment Coverage", level=1)

    rows = []
    for item in sort_checklists(checklists):
        rows.append([
            checklist_id(item),
            checklist_title(item),
            checklist_status(item),
            "Yes" if checklist_review(item) else "No",
            "Yes" if checklist_finding(item) else "No",
        ])

    if not rows:
        doc.add_paragraph("No checklist records were present in the evidence bundle.")
        return

    add_table(
        doc,
        ["Checklist", "Title", "Status", "Review", "Finding"],
        rows,
        widths=[0.75, 3.35, 1.05, 0.75, 0.75],
    )


def add_detailed_results(
    doc: Document,
    checklists: list[dict[str, Any]],
):
    doc.add_heading("5. Detailed Technical Results", level=1)

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in sort_checklists(checklists):
        cid = checklist_id(item)
        prefix = cid.split("-")[0] if "-" in cid else cid
        grouped[prefix].append(item)

    for prefix in sorted(
        grouped,
        key=lambda x: [int(n) for n in re.findall(r"\d+", x)] or [999],
    ):
        doc.add_heading(f"Checklist Group {prefix}", level=2)

        for item in grouped[prefix]:
            p = doc.add_paragraph()
            set_keep_with_next(p)
            r = p.add_run(
                f"{checklist_id(item)} — {checklist_title(item)}"
            )
            set_run_font(r, H3_FONT_SIZE, bold=True)

            p2 = doc.add_paragraph()
            p2.add_run("Status: ").bold = True
            add_status_badge(p2, checklist_status(item))

            if checklist_review(item):
                p2.add_run("  Manual review required.")

            observation = checklist_observation(item)
            if observation:
                p3 = doc.add_paragraph()
                p3.add_run("Observation: ").bold = True
                p3.add_run(observation)

            # Include compact, useful evidence counters if available.
            compact_fields = []
            for key in (
                "candidate_count",
                "tested",
                "tests",
                "probes",
                "accepted",
                "blocked",
                "findings",
                "finding_count",
                "review",
                "requires_review",
                "http_errors",
                "request_errors",
                "files_executed",
            ):
                if key in item:
                    compact_fields.append(f"{key}={safe_text(item[key])}")

            if compact_fields:
                p4 = doc.add_paragraph()
                r4 = p4.add_run("Metrics: " + "; ".join(compact_fields))
                set_run_font(r4, SMALL_FONT_SIZE, italic=True)


def add_findings(
    doc: Document,
    findings: list[dict[str, Any]],
):
    doc.add_heading("6. Findings", level=1)

    if not findings:
        add_note_box(
            doc,
            "No confirmed findings recorded",
            "The evidence bundle contains zero confirmed finding records. "
            "This is not equivalent to a guarantee that the target is secure; "
            "manual-review items are documented separately.",
            fill="E8F5E9",
        )
        return

    for index, finding in enumerate(findings, start=1):
        title = first_nonempty(
            finding.get("title"),
            finding.get("name"),
            finding.get("finding"),
            default=f"Finding {index}",
        )
        doc.add_heading(f"{index}. {title}", level=2)

        add_label_value(doc, "ID", first_nonempty(
            finding.get("id"),
            finding.get("finding_id"),
            default=f"F-{index:03d}",
        ))
        add_label_value(doc, "Severity", first_nonempty(
            finding.get("severity"),
            finding.get("priority"),
            default="—",
        ))
        add_label_value(doc, "Status", first_nonempty(
            finding.get("status"),
            default="confirmed",
        ))

        for label, keys in (
            ("Description", ("description", "observation", "summary")),
            ("Impact", ("impact",)),
            ("Evidence", ("evidence", "evidence_refs")),
            ("Recommendation", ("recommendation", "remediation")),
        ):
            value = first_nonempty(
                *(finding.get(k) for k in keys),
                default="",
            )
            if value:
                p = doc.add_paragraph()
                p.add_run(f"{label}: ").bold = True
                p.add_run(clean_multiline(value))


def add_manual_review(
    doc: Document,
    checklists: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
):
    doc.add_heading("7. Items Requiring Manual Review", level=1)

    review_items = build_review_items(checklists)
    incomplete = build_incomplete_items(checklists)

    if review_items:
        rows = []
        for item in review_items:
            rows.append([
                checklist_id(item),
                checklist_title(item),
                checklist_status(item),
                "Yes" if checklist_finding(item) else "No",
                checklist_observation(item)[:350] or "—",
            ])
        add_table(
            doc,
            ["Checklist", "Title", "Status", "Finding", "Evidence / Observation"],
            rows,
            widths=[0.75, 2.1, 0.9, 0.65, 3.0],
        )
    else:
        doc.add_paragraph("No checklist-level manual-review items were recorded.")

    if incomplete:
        doc.add_heading("Incomplete coverage", level=2)
        for item in incomplete:
            add_bullet(
                doc,
                f"{checklist_id(item)} — {checklist_title(item)} "
                f"(status: {checklist_status(item)})"
            )

    if recommendations:
        doc.add_heading("Expert review recommendations", level=2)
        doc.add_paragraph(
            "The following items come from the optional ChatGPT expert-review file. "
            "They do not change the underlying evidence status or create a finding."
        )

        for rec in recommendations:
            p = doc.add_paragraph()
            r = p.add_run(
                f"{rec['id']} — {rec['title']} "
                f"[{rec['priority']}]"
            )
            set_run_font(r, H3_FONT_SIZE, bold=True)

            add_label_value(doc, "Category", rec["category"])
            add_label_value(doc, "Type", rec["type"])
            add_label_value(doc, "Status", rec["status"])
            add_label_value(
                doc,
                "Checklist IDs",
                ", ".join(str(x) for x in rec["checklist_ids"]),
            )

            for label in ("observation", "recommendation", "rationale"):
                p2 = doc.add_paragraph()
                p2.add_run(f"{label.title()}: ").bold = True
                p2.add_run(clean_multiline(rec[label]))

            add_label_value(
                doc,
                "Evidence refs",
                "\n".join(str(x) for x in rec["evidence_refs"]),
            )
            add_label_value(
                doc,
                "Requires manual validation",
                rec["requires_manual_validation"],
            )


def add_security_observations(
    doc: Document,
    checklists: list[dict[str, Any]],
):
    doc.add_heading("8. Security Observations / Forensic Signals", level=1)

    # The generator intentionally uses only evidence-recorded observations.
    observations = []
    for item in sort_checklists(checklists):
        obs = checklist_observation(item)
        if obs:
            observations.append(
                (
                    checklist_id(item),
                    checklist_title(item),
                    obs,
                )
            )

    if not observations:
        doc.add_paragraph(
            "No standalone observation text was available in checklist records."
        )
        return

    # Keep this section readable: use all observations, but truncate very long
    # fields to avoid turning the report into a raw evidence dump.
    for cid, title, obs in observations:
        p = doc.add_paragraph()
        r = p.add_run(f"{cid} — {title}")
        set_run_font(r, 9, bold=True)

        p2 = doc.add_paragraph()
        text = obs if len(obs) <= 1200 else obs[:1200] + " …"
        p2.add_run(text)


def add_limitations(
    doc: Document,
    evidence: dict[str, Any],
    checklists: list[dict[str, Any]],
):
    doc.add_heading("9. Limitations", level=1)

    limitations = []

    explicit = deep_get(
        evidence,
        "limitations",
        "assessment.limitations",
        "constraints",
    )
    if explicit:
        if isinstance(explicit, list):
            limitations.extend(clean_multiline(x) for x in explicit)
        else:
            limitations.append(clean_multiline(explicit))

    incomplete = build_incomplete_items(checklists)
    if incomplete:
        limitations.append(
            "One or more checklist areas remain incomplete. "
            "Those areas should be completed or explicitly accepted before final sign-off."
        )

    limitations.extend([
        "Evidence is limited to what was observed and captured during the assessment.",
        "A response that is accepted or reflected is not, by itself, proof of exploitability.",
        "CVE candidate correlation requires manual applicability validation.",
        "File-upload acceptance does not by itself prove persistence, storage location, overwrite, or code execution.",
        "Manual-review items are not automatically classified as vulnerabilities.",
    ])

    seen = set()
    for item in limitations:
        normalized = item.strip()
        if normalized and normalized not in seen:
            add_bullet(doc, normalized)
            seen.add(normalized)


def add_recommendations(
    doc: Document,
    recommendations: list[dict[str, Any]],
):
    doc.add_heading("10. Recommendations", level=1)

    if not recommendations:
        doc.add_paragraph(
            "No external recommendation file was supplied. "
            "The report therefore contains evidence-derived observations only."
        )
        return

    doc.add_paragraph(
        "Recommendations below are imported from the optional ChatGPT expert-review "
        "file and are presented as advisory material. They do not alter evidence "
        "status, finding state, or checklist completion state."
    )

    grouped = defaultdict(list)
    for rec in recommendations:
        grouped[rec["priority"]].append(rec)

    for priority in ("Critical", "High", "Medium", "Low", "Informational"):
        items = grouped.get(priority, [])
        if not items:
            continue

        doc.add_heading(f"{priority} Priority", level=2)

        for rec in items:
            doc.add_heading(f"{rec['id']} — {rec['title']}", level=3)
            add_label_value(doc, "Category", rec["category"])
            add_label_value(doc, "Type", rec["type"])
            add_label_value(
                doc,
                "Checklist IDs",
                ", ".join(str(x) for x in rec["checklist_ids"]),
            )

            p = doc.add_paragraph()
            p.add_run("Recommendation: ").bold = True
            p.add_run(clean_multiline(rec["recommendation"]))

            p2 = doc.add_paragraph()
            p2.add_run("Rationale: ").bold = True
            p2.add_run(clean_multiline(rec["rationale"]))

            if rec.get("requires_manual_validation") is True:
                add_note_box(
                    doc,
                    "Manual validation required",
                    "This recommendation must be verified by an authorized human reviewer "
                    "before it is treated as a confirmed security conclusion.",
                    fill="FFF8E1",
                )

    add_note_box(
        doc,
        "AI-assisted review disclaimer",
        "ChatGPT recommendations are advisory. They are generated from the supplied "
        "evidence and must not be treated as independent proof of a vulnerability. "
        "The evidence bundle remains authoritative for checklist status and finding state.",
        fill="F3E5F5",
    )


def add_retest(
    doc: Document,
    evidence: dict[str, Any],
):
    doc.add_heading("11. Retest / Verification Status", level=1)

    retest = deep_get(
        evidence,
        "retest",
        "assessment.retest",
        "verification",
    )

    if retest:
        if isinstance(retest, dict):
            for key, value in retest.items():
                add_label_value(doc, str(key), value)
        else:
            doc.add_paragraph(clean_multiline(retest))
    else:
        doc.add_paragraph(
            "No separate retest dataset was present in the evidence bundle. "
            "The current document should therefore be interpreted as the initial "
            "assessment report unless a subsequent retest record is supplied."
        )


def add_conclusion(
    doc: Document,
    metrics: dict[str, Any],
    findings: list[dict[str, Any]],
    checklists: list[dict[str, Any]],
):
    doc.add_heading("12. Overall Conclusion", level=1)

    if findings:
        doc.add_paragraph(
            f"The evidence bundle records {len(findings)} confirmed finding(s). "
            "These findings should be addressed according to their recorded severity "
            "and verified through remediation/retest activities."
        )
    else:
        doc.add_paragraph(
            "The evidence bundle records no confirmed security findings. "
            "However, this conclusion must be read together with the manual-review "
            f"items ({metrics['review']}) and incomplete coverage ({metrics['incomplete']}). "
            "The assessment therefore should not be interpreted as a blanket statement "
            "that the target is secure."
        )

    if build_incomplete_items(checklists):
        add_note_box(
            doc,
            "Final sign-off consideration",
            "Resolve or explicitly accept the incomplete checklist coverage before "
            "declaring the assessment fully complete.",
            fill="FFF8E1",
        )


def add_consistency_notes(
    doc: Document,
    evidence: dict[str, Any],
    metrics: dict[str, Any],
    recommendation_errors: list[str],
):
    doc.add_heading("13. Evidence / Data Consistency Notes", level=1)

    assessment_status = deep_get(
        evidence,
        "assessment.status",
        "assessment_status",
        default=None,
    )
    if assessment_status:
        add_label_value(doc, "Assessment status recorded in evidence", assessment_status)

    started = deep_get(
        evidence,
        "assessment.started_at",
        "started_at",
        default=None,
    )
    completed = deep_get(
        evidence,
        "assessment.completed_at",
        "completed_at",
        default=None,
    )

    if started is not None:
        add_label_value(doc, "Assessment started_at", started)
    if completed is not None:
        add_label_value(doc, "Assessment completed_at", completed)

    doc.add_paragraph(
        "The report generator does not derive assessment start/end dates from "
        "the evidence generation timestamp. If the assessment metadata records "
        "null or not-started values, those values are preserved."
    )

    if recommendation_errors:
        add_note_box(
            doc,
            "Recommendation file was not included",
            "The optional ChatGPT recommendation file failed validation. "
            "The evidence-based report remains usable, but the invalid recommendations "
            "were intentionally excluded:\n\n" + "\n".join(
                f"• {x}" for x in recommendation_errors
            ),
            fill="FFEBEE",
        )


def add_signoff(
    doc: Document,
    meta: dict[str, Any],
    metrics: dict[str, Any],
):
    doc.add_heading("14. Final Sign-off Checklist", level=1)

    rows = [
        ["Evidence bundle generated", "Yes"],
        ["Confirmed findings recorded", "Yes" if int(str(metrics["findings"])) > 0 else "No"],
        ["Manual-review items documented", "Yes" if int(str(metrics["review"])) > 0 else "No"],
        ["Incomplete checklist coverage", "Yes" if int(str(metrics["incomplete"])) > 0 else "No"],
        ["Final report generated from evidence", "Yes"],
        ["Human final review required", "Yes"],
    ]

    add_table(
        doc,
        ["Control", "Status"],
        rows,
        widths=[4.8, 1.5],
    )

    doc.add_paragraph()
    add_label_value(doc, "Reviewer", meta["reviewer"])
    add_label_value(doc, "Generated report time", utc_now_iso())

    add_note_box(
        doc,
        "Sign-off statement",
        "Final acceptance, risk acceptance, and declaration of assessment completeness "
        "remain human responsibilities. This document is a deterministic presentation "
        "of the collected evidence and validated advisory recommendations.",
    )


def add_appendix_checklist_matrix(
    doc: Document,
    checklists: list[dict[str, Any]],
):
    doc.add_heading("Appendix A — Checklist Matrix", level=1)

    rows = []
    for item in sort_checklists(checklists):
        rows.append([
            checklist_id(item),
            checklist_title(item),
            checklist_status(item),
            "Yes" if checklist_review(item) else "No",
            "Yes" if checklist_finding(item) else "No",
            checklist_observation(item)[:500] or "—",
        ])

    add_table(
        doc,
        ["ID", "Title", "Status", "Review", "Finding", "Observation"],
        rows,
        widths=[0.65, 2.0, 0.85, 0.55, 0.55, 3.0],
    )


def add_appendix_evidence_index(
    doc: Document,
    source_files: list[dict[str, Any]],
):
    doc.add_heading("Appendix B — Evidence Index", level=1)

    if not source_files:
        doc.add_paragraph("No source-file inventory was present.")
        return

    rows = []
    for item in sorted(
        source_files,
        key=lambda x: normalize_relpath(
            first_nonempty(
                x.get("path"),
                x.get("relative_path"),
                x.get("file"),
                default="",
            )
        ).lower(),
    ):
        path = normalize_relpath(
            first_nonempty(
                item.get("path"),
                item.get("relative_path"),
                item.get("file"),
                default="—",
            )
        )
        category = first_nonempty(
            item.get("category"),
            item.get("type"),
            default="—",
        )
        size = first_nonempty(
            item.get("size"),
            item.get("bytes"),
            default="—",
        )
        digest = first_nonempty(
            item.get("sha256"),
            item.get("hash"),
            default="—",
        )
        rows.append([path, category, size, digest])

    add_table(
        doc,
        ["Source File", "Category", "Size", "SHA-256"],
        rows,
        widths=[4.0, 1.2, 0.8, 2.0],
        font_size=7.2,
    )


def add_appendix_metrics(
    doc: Document,
    metrics: dict[str, Any],
    recommendations: list[dict[str, Any]],
):
    doc.add_heading("Appendix C — Important Metrics", level=1)

    rows = [
        ["Source files", metrics["source_files"]],
        ["Checklists", metrics["checklists"]],
        ["Completed", metrics["completed"]],
        ["Incomplete", metrics["incomplete"]],
        ["Confirmed findings", metrics["findings"]],
        ["Review items", metrics["review"]],
        ["Parse errors", metrics["parse_errors"]],
        ["ChatGPT recommendations", len(recommendations)],
    ]
    add_table(doc, ["Metric", "Value"], rows, widths=[4.8, 1.5])

    if recommendations:
        doc.add_heading("Recommendation priority distribution", level=2)
        counts = recommendation_priority_counts(recommendations)
        rows2 = [
            [priority, counts.get(priority, 0)]
            for priority in (
                "Critical", "High", "Medium", "Low", "Informational"
            )
            if counts.get(priority, 0)
        ]
        add_table(doc, ["Priority", "Count"], rows2, widths=[4.8, 1.5])


def add_appendix_review_items(
    doc: Document,
    checklists: list[dict[str, Any]],
):
    doc.add_heading("Appendix D — Review Items", level=1)

    review_items = build_review_items(checklists)
    if not review_items:
        doc.add_paragraph("No review items recorded.")
        return

    rows = []
    for item in review_items:
        rows.append([
            checklist_id(item),
            checklist_title(item),
            checklist_status(item),
            checklist_observation(item)[:800] or "—",
        ])

    add_table(
        doc,
        ["Checklist", "Title", "Status", "Observation"],
        rows,
        widths=[0.8, 2.0, 1.0, 3.5],
    )


def add_appendix_recommendations(
    doc: Document,
    recommendations: list[dict[str, Any]],
):
    doc.add_heading("Appendix E — Expert Review Recommendation Index", level=1)

    if not recommendations:
        doc.add_paragraph("No validated ChatGPT recommendation file was included.")
        return

    rows = []
    for rec in recommendations:
        rows.append([
            rec["id"],
            rec["title"],
            rec["priority"],
            rec["type"],
            ", ".join(str(x) for x in rec["checklist_ids"]),
            rec["status"],
        ])

    add_table(
        doc,
        ["ID", "Title", "Priority", "Type", "Checklist", "Status"],
        rows,
        widths=[0.55, 2.55, 0.8, 0.8, 1.1, 1.0],
    )


# ---------------------------------------------------------------------------
# Indonesian presentation layer
# ---------------------------------------------------------------------------

REPORT_TRANSLATIONS = {
    "PENETRATION TEST REPORT": "LAPORAN UJI PENETRASI",
    "BrebesKab-CSIRT-Tools — Evidence-Driven Assessment":
        "BrebesKab-CSIRT-Tools — Pengujian Berbasis Evidence",
    "Assessment Attribute": "Atribut Pengujian",
    "Project ID": "ID Proyek",
    "Assessment Type": "Jenis Pengujian",
    "Environment": "Lingkungan",
    "Tester": "Penguji",
    "Reviewer": "Peninjau",
    "Evidence Generated": "Evidence Dibuat",
    "Evidence Source": "Sumber Evidence",
    "AI-Assisted Review": "Tinjauan Berbantuan AI",
    "Included": "Disertakan",
    "Not provided": "Tidak disediakan",
    "Important report principle": "Prinsip Penting Laporan",
    "This report is generated from collected evidence. ":
        "Laporan ini dibuat berdasarkan evidence yang dikumpulkan. ",
    "Absence of confirmed findings does not mean the target is guaranteed secure. ":
        "Tidak adanya temuan terkonfirmasi bukan berarti target dijamin aman. ",
    "Items marked for review require human validation before final security conclusions.":
        "Item yang ditandai untuk ditinjau memerlukan validasi manusia sebelum kesimpulan keamanan akhir ditetapkan.",
    "Generated by BrebesKab-CSIRT-Tools": "Dibuat oleh BrebesKab-CSIRT-Tools",
    "Executive Summary": "Ringkasan Eksekutif",
    "Scope & Rules of Engagement": "Ruang Lingkup & Aturan Pelaksanaan Pengujian",
    "Scope": "Ruang Lingkup",
    "Rules of Engagement": "Aturan Pelaksanaan Pengujian",
    "Methodology": "Metodologi",
    "Assessment flow": "Alur Pengujian",
    "Evidence handling principle": "Prinsip Pengelolaan Evidence",
    "Assessment Coverage": "Cakupan Pengujian",
    "Detailed Technical Results": "Hasil Teknis Terperinci",
    "Findings": "Temuan",
    "Items Requiring Manual Review": "Item yang Memerlukan Tinjauan Manual",
    "Security Observations / Forensic Signals":
        "Observasi Keamanan / Sinyal Forensik",
    "Limitations": "Keterbatasan",
    "Recommendations": "Rekomendasi",
    "Retest / Verification Status": "Status Retest / Verifikasi",
    "Overall Conclusion": "Kesimpulan Umum",
    "Evidence / Data Consistency Notes": "Catatan Konsistensi Evidence / Data",
    "Final Sign-off Checklist": "Daftar Periksa Sign-off Akhir",
    "Appendix A — Checklist Matrix": "Lampiran A — Matriks Daftar Periksa",
    "Appendix B — Evidence Index": "Lampiran B — Indeks Evidence",
    "Appendix C — Important Metrics": "Lampiran C — Metrik Penting",
    "Appendix D — Review Items": "Lampiran D — Item Tinjauan",
    "Appendix E — Expert Review Recommendation Index":
        "Lampiran E — Indeks Rekomendasi Tinjauan Ahli",
    "Evidence is the source of truth.": "Evidence merupakan sumber kebenaran utama.",
    "Expert review recommendations": "Rekomendasi Tinjauan Ahli",
    "Incomplete coverage": "Cakupan Belum Lengkap",
    "Recommendation priority distribution": "Distribusi Prioritas Rekomendasi",
    "No confirmed findings recorded": "Tidak Terdapat Temuan Terkonfirmasi yang Tercatat",
    "No checklist-level manual-review items were recorded.":
        "Tidak terdapat item tinjauan manual pada tingkat daftar periksa.",
    "No standalone observation text was available in checklist records.":
        "Tidak tersedia teks observasi tersendiri pada catatan daftar periksa.",
    "No review items recorded.": "Tidak terdapat item tinjauan yang tercatat.",
    "No source-file inventory was present.": "Tidak terdapat inventaris berkas sumber.",
    "No validated ChatGPT recommendation file was included.":
        "Tidak ada berkas rekomendasi ChatGPT yang tervalidasi yang disertakan.",
    "Assessment status recorded in evidence":
        "Status pengujian yang tercatat pada evidence",
    "Assessment started_at": "Waktu Mulai Pengujian",
    "Assessment completed_at": "Waktu Selesai Pengujian",
    "Evidence bundle generated": "Paket Evidence Dibuat",
    "Confirmed findings recorded": "Temuan Terkonfirmasi Tercatat",
    "Manual-review items documented": "Item Tinjauan Manual Terdokumentasi",
    "Incomplete checklist coverage": "Cakupan Daftar Periksa Belum Lengkap",
    "Final report generated from evidence": "Laporan Akhir Dibuat dari Evidence",
    "Human final review required": "Tinjauan Akhir oleh Manusia Diperlukan",
    "Control": "Kontrol",
    "Status": "Status",
    "Metric": "Metrik",
    "Value": "Nilai",
    "Priority": "Prioritas",
    "Count": "Jumlah",
    "Source File": "Berkas Sumber",
    "Category": "Kategori",
    "Size": "Ukuran",
    "Title": "Judul",
    "Finding": "Temuan",
    "Review": "Tinjauan",
    "Observation": "Observasi",
    "Checklist": "Daftar Periksa",
    "ID": "ID",
    "Type": "Jenis",
    "Checklist IDs": "ID Daftar Periksa",
    "Evidence refs": "Referensi Evidence",
    "Requires manual validation": "Memerlukan Validasi Manual",
    "Recommendation": "Rekomendasi",
    "Rationale": "Alasan",
    "Manual validation required": "Validasi Manual Diperlukan",
    "AI-assisted review disclaimer": "Penafian Tinjauan Berbantuan AI",
    "Final sign-off consideration": "Pertimbangan Sign-off Akhir",
    "Recommendation file was not included": "Berkas Rekomendasi Tidak Disertakan",
    "Sign-off statement": "Pernyataan Sign-off",
    "CVE candidate correlation requires manual applicability validation.":
        "Korelasi kandidat CVE memerlukan validasi manual terhadap keterterapan.",
    "Manual-review items are not automatically classified as vulnerabilities.":
        "Item tinjauan manual tidak otomatis diklasifikasikan sebagai kerentanan.",
    "Evidence such as HTTP 200 responses, reflection, accepted uploads, disclosed versions, accepted HTTP methods, or replay behavior is presented as observed evidence.":
        "Evidence seperti respons HTTP 200, refleksi payload, unggahan yang diterima, versi yang terungkap, metode HTTP yang diterima, atau perilaku replay disajikan sebagai evidence yang teramati.",
    "It is not automatically converted into a vulnerability unless the evidence explicitly records a confirmed finding.":
        "Evidence tersebut tidak otomatis diklasifikasikan sebagai kerentanan kecuali evidence secara eksplisit mencatat temuan terkonfirmasi.",
    "No standalone rules-of-engagement block was present in the evidence bundle.":
        "Tidak terdapat blok aturan pelaksanaan pengujian yang berdiri sendiri pada paket evidence.",
    "No separate retest dataset was present in the evidence bundle.":
        "Tidak terdapat dataset retest terpisah dalam paket evidence.",
    "Manual review required.": "Memerlukan tinjauan manual.",
    "Recommendation": "Rekomendasi",
    "Rationale": "Alasan",
    "Evidence / Observation": "Evidence / Observasi",
    "The report generator does not reinterpret raw probe output into a finding.":
        "Generator laporan tidak menafsirkan ulang keluaran probe mentah menjadi temuan.",
    "It reports the status and observations recorded by the evidence collector.":
        "Generator hanya melaporkan status dan observasi yang dicatat oleh pengumpul evidence.",
    "Manual review recommendations are separated from confirmed findings.":
        "Rekomendasi tinjauan manual dipisahkan dari temuan terkonfirmasi.",
    "This is not equivalent to a guarantee that the target is secure; manual-review items are documented separately.":
        "Hal ini bukan berarti target dijamin aman; item tinjauan manual didokumentasikan secara terpisah.",
    "This recommendation must be verified by an authorized human reviewer before it is treated as a confirmed security conclusion.":
        "Rekomendasi ini harus diverifikasi oleh peninjau manusia yang berwenang sebelum diperlakukan sebagai kesimpulan keamanan terkonfirmasi.",
    "ChatGPT recommendations are advisory. They are generated from the supplied evidence and must not be treated as independent proof of a vulnerability. The evidence bundle remains authoritative for checklist status and finding state.":
        "Rekomendasi ChatGPT bersifat advisori. Rekomendasi dibuat berdasarkan evidence yang disediakan dan tidak boleh diperlakukan sebagai bukti independen adanya kerentanan. Paket evidence tetap menjadi sumber otoritatif untuk status daftar periksa dan status temuan.",
    "No external recommendation file was supplied. The report therefore contains evidence-derived observations only.":
        "Tidak ada berkas rekomendasi eksternal yang disediakan. Laporan hanya memuat observasi yang berasal dari evidence.",
    "Recommendations below are imported from the optional ChatGPT expert-review file and are presented as advisory material. They do not alter evidence status, finding state, or checklist completion state.":
        "Rekomendasi berikut diimpor dari berkas opsional tinjauan ahli ChatGPT dan disajikan sebagai bahan advisori. Rekomendasi tidak mengubah status evidence, status temuan, maupun status penyelesaian daftar periksa.",
    "No checklist records were present in the evidence bundle.":
        "Tidak terdapat catatan daftar periksa dalam paket evidence.",
    "One or more checklist areas remain incomplete. Those areas should be completed or explicitly accepted before final sign-off.":
        "Satu atau lebih area daftar periksa masih belum lengkap. Area tersebut harus diselesaikan atau diterima secara eksplisit sebelum sign-off akhir.",
    "Evidence is limited to what was observed and captured during the assessment.":
        "Evidence terbatas pada hal-hal yang diamati dan direkam selama pengujian.",
    "A response that is accepted or reflected is not, by itself, proof of exploitability.":
        "Respons yang diterima atau merefleksikan payload bukan dengan sendirinya bukti bahwa sistem dapat dieksploitasi.",
    "File-upload acceptance does not by itself prove persistence, storage location, overwrite, or code execution.":
        "Penerimaan unggahan berkas bukan dengan sendirinya membuktikan persistence, lokasi penyimpanan, overwrite, atau eksekusi kode.",
}

# Translate only report presentation text. Raw evidence observations are intentionally
# preserved because they are source evidence and must not be silently rewritten.
def localize_report_document(doc: Document) -> None:
    """
    Translate report presentation text to Indonesian.

    Paragraph-level replacement is intentional: it handles text split across
    multiple Word runs. Evidence JSON/technical observation blocks are skipped
    so the source evidence is not silently rewritten.
    """
    translations = dict(REPORT_TRANSLATIONS)
    translations.update({
        "Executive Summary": "Ringkasan Eksekutif",
        "Scope & Rules of Engagement": "Ruang Lingkup & Aturan Pelaksanaan Pengujian",
        "Methodology": "Metodologi",
        "Assessment Coverage": "Cakupan Pengujian",
        "Detailed Technical Results": "Hasil Teknis Terperinci",
        "Findings": "Temuan",
        "Items Requiring Manual Review": "Item yang Memerlukan Tinjauan Manual",
        "Security Observations / Forensic Signals":
            "Observasi Keamanan / Sinyal Forensik",
        "Limitations": "Keterbatasan",
        "Recommendations": "Rekomendasi",
        "Retest / Verification Status": "Status Retest / Verifikasi",
        "Overall Conclusion": "Kesimpulan Umum",
        "Evidence / Data Consistency Notes": "Catatan Konsistensi Evidence / Data",
        "Final Sign-off Checklist": "Daftar Periksa Sign-off Akhir",
        "Coverage:": "Cakupan:",
        "Expert review:": "Tinjauan ahli:",
        "Assessment Attribute": "Atribut Pengujian",
        "Project ID": "ID Proyek",
        "Assessment Type": "Jenis Pengujian",
        "Environment": "Lingkungan",
        "Tester": "Penguji",
        "Reviewer": "Peninjau",
        "Evidence Generated": "Evidence Dibuat",
        "Evidence Source": "Sumber Evidence",
        "AI-Assisted Review": "Tinjauan Berbantuan AI",
        "Included": "Disertakan",
        "Not provided": "Tidak disediakan",
        "Scope details were not separately populated in the evidence metadata. Refer to the assessment and checklist evidence for the operational scope.":
            "Rincian ruang lingkup tidak diisi secara terpisah pada metadata evidence. Lihat evidence pengujian dan daftar periksa untuk mengetahui ruang lingkup operasional.",
        "The assessment was executed using the checklist structure represented by BrebesKab-CSIRT-Tools. Evidence was collected by checklist-specific tooling, then aggregated into an evidence bundle for final reporting.":
            "Pengujian dilaksanakan menggunakan struktur daftar periksa yang direpresentasikan oleh BrebesKab-CSIRT-Tools. Evidence dikumpulkan oleh alat yang spesifik terhadap setiap daftar periksa, kemudian diagregasikan menjadi paket evidence untuk penyusunan laporan akhir.",
        "Preparation and scope confirmation.": "Persiapan dan konfirmasi ruang lingkup.",
        "Reconnaissance and attack-surface mapping.": "Reconnaissance dan pemetaan permukaan serangan.",
        "Infrastructure and web-server configuration assessment.": "Pengujian infrastruktur dan konfigurasi web server.",
        "Security-header, session, authentication and authorization checks.": "Pemeriksaan security header, sesi, autentikasi, dan otorisasi.",
        "Input-validation, file-upload and application-security checks.": "Pemeriksaan validasi input, unggah berkas, dan keamanan aplikasi.",
        "Evidence aggregation and consistency review.": "Agregasi evidence dan pemeriksaan konsistensi.",
        "Final report generation from the evidence bundle.": "Pembuatan laporan akhir dari paket evidence.",
        "The report generator does not reinterpret raw probe output into a finding. It reports the status and observations recorded by the evidence collector. Manual review recommendations are separated from confirmed findings.":
            "Generator laporan tidak menafsirkan ulang keluaran probe mentah menjadi temuan. Generator hanya melaporkan status dan observasi yang dicatat oleh pengumpul evidence. Rekomendasi tinjauan manual dipisahkan dari temuan terkonfirmasi.",
        "The assessment evidence contains 0 confirmed finding record(s). The findings section below is the authoritative presentation of those records.":
            "Evidence pengujian berisi 0 catatan temuan terkonfirmasi. Bagian temuan di bawah merupakan penyajian otoritatif atas catatan tersebut.",
        "No checklist records were present in the evidence bundle.":
            "Tidak terdapat catatan daftar periksa dalam paket evidence.",
        "No confirmed findings recorded":
            "Tidak terdapat temuan terkonfirmasi yang tercatat",
        "The evidence bundle contains zero confirmed finding records. This is not equivalent to a guarantee that the target is secure; manual-review items are documented separately.":
            "Paket evidence tidak berisi catatan temuan terkonfirmasi. Hal ini bukan berarti target dijamin aman; item tinjauan manual didokumentasikan secara terpisah.",
        "Incomplete coverage": "Cakupan Belum Lengkap",
        "No standalone observation text was available in checklist records.":
            "Tidak tersedia teks observasi tersendiri pada catatan daftar periksa.",
        "One or more checklist areas remain incomplete. Those areas should be completed or explicitly accepted before final sign-off.":
            "Satu atau lebih area daftar periksa masih belum lengkap. Area tersebut harus diselesaikan atau diterima secara eksplisit sebelum sign-off akhir.",
        "Evidence is limited to what was observed and captured during the assessment.":
            "Evidence terbatas pada hal-hal yang diamati dan direkam selama pengujian.",
        "A response that is accepted or reflected is not, by itself, proof of exploitability.":
            "Respons yang diterima atau merefleksikan payload bukan dengan sendirinya bukti bahwa sistem dapat dieksploitasi.",
        "CVE candidate correlation requires manual applicability validation.":
            "Korelasi kandidat CVE memerlukan validasi manual terhadap keterterapan.",
        "File-upload acceptance does not by itself prove persistence, storage location, overwrite, or code execution.":
            "Penerimaan unggahan berkas bukan dengan sendirinya membuktikan persistence, lokasi penyimpanan, overwrite, atau eksekusi kode.",
        "Manual-review items are not automatically classified as vulnerabilities.":
            "Item tinjauan manual tidak otomatis diklasifikasikan sebagai kerentanan.",
        "No external recommendation file was supplied. The report therefore contains evidence-derived observations only.":
            "Tidak ada berkas rekomendasi eksternal yang disediakan. Laporan hanya memuat observasi yang berasal dari evidence.",
        "Recommendations below are imported from the optional ChatGPT expert-review file and are presented as advisory material. They do not alter evidence status, finding state, or checklist completion state.":
            "Rekomendasi berikut diimpor dari berkas opsional tinjauan ahli ChatGPT dan disajikan sebagai bahan advisori. Rekomendasi tidak mengubah status evidence, status temuan, maupun status penyelesaian daftar periksa.",
        "Manual validation required":
            "Validasi manual diperlukan",
        "AI-assisted review disclaimer":
            "Penafian tinjauan berbantuan AI",
        "Final sign-off consideration":
            "Pertimbangan Sign-off Akhir",
        "No separate retest dataset was present in the evidence bundle. The current document should therefore be interpreted as the initial assessment report unless a subsequent retest record is supplied.":
            "Tidak terdapat dataset retest terpisah dalam paket evidence. Dokumen ini harus dipahami sebagai laporan pengujian awal kecuali tersedia catatan retest berikutnya.",
        "The report generator does not derive assessment start/end dates from the evidence generation timestamp. If the assessment metadata records null or not-started values, those values are preserved.":
            "Generator laporan tidak menentukan tanggal mulai/selesai pengujian berdasarkan waktu pembuatan evidence. Jika metadata pengujian mencatat nilai null atau not-started, nilai tersebut dipertahankan.",
        "Recommendation file was not included":
            "Berkas Rekomendasi Tidak Disertakan",
        "Final acceptance, risk acceptance, and declaration of assessment completeness remain human responsibilities. This document is a deterministic presentation of the collected evidence and validated advisory recommendations.":
            "Penerimaan akhir, penerimaan risiko, dan pernyataan bahwa pengujian telah lengkap tetap merupakan tanggung jawab manusia. Dokumen ini merupakan penyajian deterministik dari evidence yang dikumpulkan dan rekomendasi advisori yang telah divalidasi.",
        "Recommendation priority distribution": "Distribusi Prioritas Rekomendasi",
        "No review items recorded.": "Tidak terdapat item tinjauan yang tercatat.",
        "No source-file inventory was present.": "Tidak terdapat inventaris berkas sumber.",
        "No validated ChatGPT recommendation file was included.":
            "Tidak ada berkas rekomendasi ChatGPT yang tervalidasi yang disertakan.",
        "Evidence / Observation": "Evidence / Observasi",
        "Source File": "Berkas Sumber",
        "Priority": "Prioritas",
        "Count": "Jumlah",
        "Metric": "Metrik",
        "Value": "Nilai",
        "Category": "Kategori",
        "Type": "Jenis",
        "Title": "Judul",
        "Finding": "Temuan",
        "Review": "Tinjauan",
        "Observation": "Observasi",
        "Checklist": "Daftar Periksa",
        "Status": "Status",
        "ID": "ID",
        "Recommendation": "Rekomendasi",
        "Rationale": "Alasan",
        "Checklist IDs": "ID Daftar Periksa",
        "Evidence refs": "Referensi Evidence",
        "Requires manual validation": "Memerlukan validasi manual",
        "Project ID:": "ID Proyek:",
        "Application:": "Aplikasi:",
        "Target:": "Target:",
        "Assessment Type:": "Jenis Pengujian:",
        "Environment:": "Lingkungan:",
        "Black Box": "Black Box",
        "Production": "Produksi",
        "Penetration Test Report": "Laporan Uji Penetrasi",
        "Page ": "Halaman ",
    })

    def is_raw_evidence(value: str) -> bool:
        return (
            value.lstrip().startswith("{")
            or '"requires_review"' in value
            or '"http_available"' in value
            or '"initial_status_code"' in value
            or '"served_over_http"' in value
        )

    def translate(value: str) -> str:
        result = value
        for src_text, dst_text in sorted(
            translations.items(), key=lambda item: len(item[0]), reverse=True
        ):
            result = result.replace(src_text, dst_text)

        result = re.sub(
            r"\bChecklist Group\s+(\d+)\b",
            r"Kelompok Daftar Periksa \1",
            result,
        )
        result = re.sub(
            r"\bChecklist\s+(\d{1,2}-\d{3})\b",
            r"Daftar Periksa \1",
            result,
        )
        result = result.replace("High Priority", "Prioritas Tinggi")
        result = result.replace("Medium Priority", "Prioritas Sedang")
        result = result.replace("Low Priority", "Prioritas Rendah")
        result = result.replace("Critical Priority", "Prioritas Kritis")
        result = result.replace("Informational Priority", "Prioritas Informasional")

        # Translate status only when presented as a report status, not inside
        # evidence JSON.
        if "Status:" in result:
            for src_status, dst_status in (
                ("completed", "selesai"),
                ("partial", "sebagian"),
                ("incomplete", "belum lengkap"),
                ("requires_review", "memerlukan tinjauan"),
                ("review", "perlu ditinjau"),
            ):
                result = result.replace(src_status, dst_status)

        # Translate the executive-summary coverage sentence.
        if result.startswith("Coverage:"):
            result = result.replace("Coverage:", "Cakupan:")
            result = result.replace("completed", "selesai")
            result = result.replace("incomplete", "belum lengkap")
            result = result.replace("review item(s)", "item tinjauan")
            result = result.replace("finding record(s)", "catatan temuan")
            result = result.replace("parse error(s)", "kesalahan parsing")

        if result.startswith("Expert review:") or result.startswith("Tinjauan ahli:"):
            result = re.sub(
                r"Expert review:\s*(\d+)\s*recommendation\(s\) were supplied in the optional ChatGPT review file\. Priority distribution:\s*",
                r"Tinjauan ahli: \1 rekomendasi disediakan dalam berkas tinjauan ChatGPT opsional. Distribusi prioritas: ",
                result,
            )
            result = result.replace("High:", "Tinggi:")
            result = result.replace("Medium:", "Sedang:")
            result = result.replace("Low:", "Rendah:")
            result = result.replace("Critical:", "Kritis:")
            result = result.replace("Informational:", "Informasional:")
            result = result.replace("Priority distribution:", "Distribusi prioritas:")

        # Handle the dynamic coverage sentence generated by the report.
        result = re.sub(
            r"^Coverage:\s*(\d+)\s*checklist;\s*(\d+)\s*completed;\s*"
            r"(\d+)\s*incomplete;\s*(\d+)\s*review item\(s\);\s*"
            r"(\d+)\s*finding record\(s\);\s*(\d+)\s*parse error\(s\)\.?$",
            r"Cakupan: \1 daftar periksa; \2 selesai; \3 belum lengkap; "
            r"\4 item tinjauan; \5 catatan temuan; \6 kesalahan parsing.",
            result,
        )
        result = re.sub(
            r"^Cakupan:\s*(\d+)\s*checklist;\s*(\d+)\s*completed;\s*"
            r"(\d+)\s*incomplete;\s*(\d+)\s*review item\(s\);\s*"
            r"(\d+)\s*finding record\(s\);\s*(\d+)\s*parse error\(s\)\.?$",
            r"Cakupan: \1 daftar periksa; \2 selesai; \3 belum lengkap; "
            r"\4 item tinjauan; \5 catatan temuan; \6 kesalahan parsing.",
            result,
        )
        result = result.replace("Daftar Periksa Group ", "Kelompok Daftar Periksa ")
        result = result.replace("Kelompok Daftar Periksa Group ", "Kelompok Daftar Periksa ")
        if result.startswith("Metrik:"):
            result = result.replace("findings", "temuan")
            result = result.replace("requires_review", "perlu_tinjauan")

        # Common mixed-language phrases from the evidence-derived prose.
        result = result.replace("security finding", "temuan keamanan")
        result = result.replace("manual review", "tinjauan manual")
        result = result.replace("manual-review", "tinjauan-manual")
        result = result.replace("checklist", "daftar periksa")
        result = result.replace("recommendation(s)", "rekomendasi")
        result = result.replace("recommendation", "rekomendasi")
        result = result.replace("were supplied in the optional ChatGPT review file.",
                                "disediakan dalam berkas tinjauan ChatGPT opsional.")
        result = result.replace("Priority distribution:", "Distribusi prioritas:")
        result = result.replace("Priority distribution", "Distribusi prioritas")
        result = result.replace("Prioritas distribution", "Distribusi prioritas")
        result = result.replace("Metriks:", "Metrik:")
        result = result.replace("High:", "Tinggi:")
        result = result.replace("Medium:", "Sedang:")
        result = result.replace("Low:", "Rendah:")
        result = result.replace("Critical:", "Kritis:")
        result = result.replace("Informational:", "Informasional:")

        return result

    def localize_paragraph(paragraph):
        if is_raw_evidence(paragraph.text):
            return
        current = paragraph.text
        translated = translate(current)
        if translated != current:
            paragraph.text = translated

    for paragraph in doc.paragraphs:
        localize_paragraph(paragraph)

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                if is_raw_evidence(cell.text):
                    continue
                for paragraph in cell.paragraphs:
                    localize_paragraph(paragraph)

    for section in doc.sections:
        for paragraph in section.footer.paragraphs:
            localize_paragraph(paragraph)


# ---------------------------------------------------------------------------
# Template handling
# ---------------------------------------------------------------------------

def find_placeholder_paragraph(doc: Document, tag: str):
    """
    Find a top-level or table-cell paragraph containing the exact template tag.
    The current template uses top-level paragraphs, but table support is kept
    so future templates do not require a report.py change.
    """
    for paragraph in doc.paragraphs:
        if tag in paragraph.text:
            return paragraph

    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for paragraph in cell.paragraphs:
                    if tag in paragraph.text:
                        return paragraph

    return None


def clear_document_body(doc: Document) -> None:
    """Remove all body blocks while retaining the document section properties."""
    body = doc._body._body
    for child in list(body):
        if child.tag == qn("w:sectPr"):
            continue
        body.remove(child)


def iter_report_blocks(doc: Document):
    """
    Yield generated body blocks excluding the document-level sectPr.

    Paragraphs and tables are copied as XML so formatting created by the
    report generator is preserved when inserted into the user's template.
    """
    body = doc._body._body
    for child in list(body):
        if child.tag == qn("w:sectPr"):
            continue
        yield child


def insert_blocks_at_placeholder(
    target_doc: Document,
    tag: str,
    source_doc: Document,
) -> None:
    """
    Replace one placeholder paragraph with all generated blocks.

    The placeholder itself is removed. The surrounding template content
    (signature, letterhead, headers/footers, etc.) remains untouched.
    """
    from copy import deepcopy

    placeholder = find_placeholder_paragraph(target_doc, tag)
    if placeholder is None:
        raise ValueError(
            f"Template tag {tag!r} tidak ditemukan di template.docx."
        )

    placeholder_element = placeholder._p

    for block in iter_report_blocks(source_doc):
        placeholder_element.addprevious(deepcopy(block))

    parent = placeholder_element.getparent()
    parent.remove(placeholder_element)


def build_body_document(
    template_path: Path,
    meta: dict[str, Any],
    metrics: dict[str, Any],
    checklists: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
    evidence: dict[str, Any],
    evidence_path: Path,
    recommendation_path: Path | None,
    recommendation_errors: list[str],
) -> Document:
    """
    Build only the main report content.

    The document starts from the same template so custom styles available in
    template.docx are also available to generated paragraphs/tables.
    """
    doc = Document(template_path)
    clear_document_body(doc)

    add_cover(
        doc,
        meta=meta,
        evidence_path=evidence_path,
        recommendation_path=recommendation_path if recommendations else None,
    )
    doc.add_page_break()

    add_executive_summary(
        doc, meta, metrics, checklists, findings, recommendations
    )
    add_scope_roe(doc, meta, evidence)
    add_methodology(doc, evidence, checklists)
    add_coverage(doc, checklists)
    add_detailed_results(doc, checklists)
    add_findings(doc, findings)
    add_manual_review(doc, checklists, recommendations)
    add_security_observations(doc, checklists)
    add_limitations(doc, evidence, checklists)
    add_recommendations(doc, recommendations)
    add_retest(doc, evidence)
    add_conclusion(doc, metrics, findings, checklists)
    add_consistency_notes(
        doc, evidence, metrics, recommendation_errors
    )
    add_signoff(doc, meta, metrics)

    # Translate presentation text to Bahasa Indonesia while preserving
    # source/evidence JSON-like content.
    localize_report_document(doc)
    return doc


def build_appendix_document(
    template_path: Path,
    checklists: list[dict[str, Any]],
    source_files: list[dict[str, Any]],
    metrics: dict[str, Any],
    recommendations: list[dict[str, Any]],
) -> Document:
    """Build only the appendix content for {{LAMPIRANREPORT}}."""
    doc = Document(template_path)
    clear_document_body(doc)

    # Ensure the appendices start on a fresh page after the template's
    # signature/approval block.
    doc.add_page_break()

    add_appendix_checklist_matrix(doc, checklists)
    add_appendix_evidence_index(doc, source_files)
    add_appendix_metrics(doc, metrics, recommendations)
    add_appendix_review_items(doc, checklists)
    add_appendix_recommendations(doc, recommendations)

    localize_report_document(doc)
    return doc


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(
    project_root: Path,
    active: dict[str, Any],
    evidence: dict[str, Any],
    evidence_path: Path,
    recommendations: list[dict[str, Any]],
    recommendation_errors: list[str],
    recommendation_path: Path | None,
    output_path: Path,
    template_path: Path,
) -> None:
    checklists = extract_checklists(evidence, project_root=project_root)
    source_files = extract_source_files(evidence)
    findings = extract_findings(evidence)

    meta = extract_project_metadata(evidence, active)
    metrics = extract_metrics(evidence, checklists, source_files, findings)

    # Generate the two logical parts separately.
    body_doc = build_body_document(
        template_path=template_path,
        meta=meta,
        metrics=metrics,
        checklists=checklists,
        findings=findings,
        recommendations=recommendations,
        evidence=evidence,
        evidence_path=evidence_path,
        recommendation_path=recommendation_path,
        recommendation_errors=recommendation_errors,
    )

    appendix_doc = build_appendix_document(
        template_path=template_path,
        checklists=checklists,
        source_files=source_files,
        metrics=metrics,
        recommendations=recommendations,
    )

    # Start from the user's template. Everything outside the two tags is
    # preserved, including letterhead, signature/approval block, headers,
    # footers, page numbering, margins, and template-specific formatting.
    final_doc = Document(template_path)

    insert_blocks_at_placeholder(
        target_doc=final_doc,
        tag=BODYREPORT_TAG,
        source_doc=body_doc,
    )
    insert_blocks_at_placeholder(
        target_doc=final_doc,
        tag=LAMPIRANREPORT_TAG,
        source_doc=appendix_doc,
    )

    # Fail closed if either tag somehow remains in the final document.
    remaining = []
    for paragraph in final_doc.paragraphs:
        if BODYREPORT_TAG in paragraph.text:
            remaining.append(BODYREPORT_TAG)
        if LAMPIRANREPORT_TAG in paragraph.text:
            remaining.append(LAMPIRANREPORT_TAG)
    for table in final_doc.tables:
        for row in table.rows:
            for cell in row.cells:
                if BODYREPORT_TAG in cell.text:
                    remaining.append(BODYREPORT_TAG)
                if LAMPIRANREPORT_TAG in cell.text:
                    remaining.append(LAMPIRANREPORT_TAG)

    if remaining:
        raise RuntimeError(
            "Template tag masih tersisa setelah proses generate: "
            + ", ".join(sorted(set(remaining)))
        )

    ensure_dir(output_path.parent)
    final_doc.save(output_path)



# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate deterministic penetration-test Word report."
    )
    parser.add_argument(
        "--project-root",
        default=None,
        help="Explicit project root. Normally resolved from .runtime/active-project.yaml.",
    )
    parser.add_argument(
        "--recommendation-file",
        default=None,
        help="Optional ChatGPT recommendation YAML. Defaults to "
             "<project_root>/23-final-sign-off/chatgpt-recommendation.yaml.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output DOCX path. Defaults to "
             "<project_root>/23-final-sign-off/penetration-test-report.docx.",
    )
    parser.add_argument(
        "--template",
        default=None,
        help="Template DOCX. Defaults to "
             "<repo_root>/reports/templates/template.docx.",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root. Normally auto-detected by finding .runtime/active-project.yaml.",
    )
    parser.add_argument(
        "--no-recommendations",
        action="store_true",
        help="Ignore the optional ChatGPT recommendation file.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {SCRIPT_VERSION}",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        if args.repo_root:
            repo_root = Path(args.repo_root).expanduser().resolve()
        else:
            repo_root = find_repo_root(Path(__file__).resolve().parent)

        active = load_active_project(repo_root)
        project_root = resolve_project_root(
            repo_root=repo_root,
            active=active,
            explicit_project_root=args.project_root,
        )

        evidence, evidence_path = load_evidence(project_root)

        checklists = extract_checklists(evidence, project_root=project_root)
        source_files = extract_source_files(evidence)

        recommendation_errors: list[str] = []
        recommendation_path: Path | None = None
        recommendations: list[dict[str, Any]] = []

        if not args.no_recommendations:
            if args.recommendation_file:
                recommendation_path = Path(args.recommendation_file).expanduser()
                if not recommendation_path.is_absolute():
                    recommendation_path = repo_root / recommendation_path

                if recommendation_path.is_file():
                    rec_data = load_yaml(recommendation_path)
                    recommendations, recommendation_errors = (
                        validate_recommendations(
                            data=rec_data,
                            project_id=first_nonempty(
                                deep_get(evidence, "project.project_id"),
                                evidence.get("project_id"),
                                active.get("project_id"),
                                default="",
                            ),
                            checklists=checklists,
                            source_files=source_files,
                            project_root=project_root,
                        )
                    )
                else:
                    recommendation_errors.append(
                        f"Recommendation file not found: {recommendation_path}"
                    )
            else:
                (
                    recommendations,
                    recommendation_errors,
                    recommendation_path,
                ) = load_optional_recommendations(
                    project_root=project_root,
                    project_id=first_nonempty(
                        deep_get(evidence, "project.project_id"),
                        evidence.get("project_id"),
                        active.get("project_id"),
                        default="",
                    ),
                    checklists=checklists,
                    source_files=source_files,
                )

        output_path = (
            Path(args.output).expanduser()
            if args.output
            else project_root / FINAL_DIRNAME / OUTPUT_DOCX
        )
        if not output_path.is_absolute():
            output_path = project_root / output_path

        template_path = (
            Path(args.template).expanduser()
            if args.template
            else repo_root / TEMPLATE_RELATIVE
        )
        if not template_path.is_absolute():
            template_path = repo_root / template_path
        template_path = template_path.resolve()

        if not template_path.is_file():
            raise FileNotFoundError(
                f"Template report tidak ditemukan: {template_path}"
            )

        print("BrebesKab-CSIRT-Tools — Penetration Test Report Generator")
        print(f"Version             : {SCRIPT_VERSION}")
        print(f"Repository root     : {repo_root}")
        print(f"Project root        : {project_root}")
        print(f"Project             : {active.get('project_id') or '—'}")
        print(f"Evidence            : {evidence_path}")
        print(f"Template            : {template_path}")
        print(
            "Recommendations     : "
            + (
                f"{recommendation_path} ({len(recommendations)} valid)"
                if recommendation_path
                else "not provided"
            )
        )

        if recommendation_errors:
            print(
                f"[WARN] Recommendation validation failed "
                f"({len(recommendation_errors)} issue(s)); "
                "recommendations will NOT be included."
            )
            for error in recommendation_errors:
                print(f"       - {error}")

        generate_report(
            project_root=project_root,
            active=active,
            evidence=evidence,
            evidence_path=evidence_path,
            recommendations=recommendations,
            recommendation_errors=recommendation_errors,
            recommendation_path=recommendation_path,
            output_path=output_path,
            template_path=template_path,
        )

        print(f"[PASS] Word report generated: {output_path}")
        return 0

    except KeyboardInterrupt:
        print("\n[ABORT] Interrupted.")
        return 130
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
