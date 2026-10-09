#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Final Report Evidence Collector / ChatGPT Prompt Generator

Purpose
-------
Read the complete PENTEST project evidence set, normalize and aggregate the
information needed for the final penetration-test report, preserve provenance,
redact obvious secrets, and generate a ready-to-use ChatGPT report prompt.

Default project:
    projects/PENTEST-2026-002

Default outputs:
    23-final-sign-off/evidence.json
    23-final-sign-off/evidence.yaml
    23-final-sign-off/report-prompt.md

The collector is READ-ONLY with respect to existing assessment artifacts.
It does not execute scans, alter evidence, or modify checklist results.

Dependencies:
    Python 3.10+
    PyYAML

Install if necessary:
    python -m pip install pyyaml
"""

from __future__ import annotations

import argparse
import csv
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
    print("[ERROR] PyYAML is required. Install with: python -m pip install pyyaml")
    raise SystemExit(2)


SCRIPT_VERSION = "1.0.0"

DEFAULT_PROJECT_ID = "PENTEST-2026-002"
DEFAULT_PROJECT_RELATIVE = Path("projects") / DEFAULT_PROJECT_ID

TEXT_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".txt", ".md", ".log", ".csv",
    ".xml", ".html", ".htm", ".ini", ".cfg", ".conf",
}

# Only these formats are parsed as structured data. Other text evidence is
# preserved as text and is not treated as a parse error.
STRUCTURED_EXTENSIONS = {".json", ".yaml", ".yml", ".csv"}

SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv",
    "node_modules", ".pytest_cache",
}

# Obvious credential/session material. These are redacted in the report bundle.
SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|token|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|authorization|cookie|session[_-]?(id|token|key)?|"
    r"csrf[_-]?(token|secret)|private[_-]?key|client[_-]?secret)",
    re.I,
)

SECRET_VALUE_RE = re.compile(
    r"^(?:Bearer\s+|Basic\s+)?[A-Za-z0-9+/=_\-.]{24,}$"
)

# Keep report text useful while avoiding accidental credential disclosure.
INLINE_SECRET_RE = re.compile(
    r"(?i)\b(?:authorization|cookie|set-cookie|x-api-key|api-key|"
    r"access-token|refresh-token|session(?:-id|-token)?|csrf-token)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)

CHECKLIST_ID_RE = re.compile(r"\b(\d{1,2}-\d{3})\b")

STATUS_VALUES = {
    "completed", "complete", "pass", "passed", "closed",
    "review", "in-progress", "in_progress", "pending",
    "failed", "error", "crawled",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def repo_root() -> Path:
    """
    Find repository root from this script location.

    Typical placement:
        <repo>/scripts/final_report/final_report_prompt.py
    """
    here = Path(__file__).resolve()
    for candidate in [here.parent, *here.parents]:
        if (candidate / "projects").is_dir():
            return candidate
    return Path.cwd().resolve()


def resolve_project_root(explicit: str | None, project_id: str) -> Path:
    if explicit:
        root = Path(explicit).expanduser().resolve()
    else:
        root = (repo_root() / "projects" / project_id).resolve()

        # Useful when the script is copied directly into the project.
        if not root.is_dir():
            cwd = Path.cwd().resolve()
            candidates = [
                cwd / "projects" / project_id,
                cwd / project_id,
                cwd,
            ]
            for candidate in candidates:
                if (candidate / "assessment.yaml").is_file() and (
                    candidate / "checklist.yaml"
                ).is_file():
                    root = candidate
                    break

    if not root.is_dir():
        raise FileNotFoundError(f"Project directory not found: {root}")

    return root


def is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS


def safe_rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def redact_value(value: Any, key: str | None = None) -> Any:
    """
    Recursively redact obvious credential/session values.

    This is deliberately conservative: only obvious secret-bearing keys and
    obvious token-shaped strings are redacted. Evidence semantics are kept.
    """
    if key and SECRET_KEY_RE.search(key):
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return "[REDACTED]"
        return "[REDACTED]"

    if isinstance(value, dict):
        return {
            str(k): redact_value(v, str(k))
            for k, v in value.items()
        }

    if isinstance(value, list):
        return [redact_value(v, key) for v in value]

    if isinstance(value, str):
        return INLINE_SECRET_RE.sub(r"\1[REDACTED]", value)

    return value


def redact_text(text: str) -> str:
    return INLINE_SECRET_RE.sub(r"\1[REDACTED]", text)


def load_structured(path: Path) -> tuple[Any, str]:
    """
    Return (parsed_object, parser_type).
    """
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8", errors="replace")

    if suffix == ".json":
        return json.loads(text), "json"

    if suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(text)
        return ({} if data is None else data), "yaml"

    if suffix == ".csv":
        rows = []
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            rows.extend(reader)
        return rows, "csv"

    raise ValueError("not structured")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def extract_checklist_ids(obj: Any) -> list[str]:
    found: set[str] = set()

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if isinstance(v, str) and (
                    "checklist" in k.lower()
                    or k.lower() in {"id", "checklist_id", "checklistid"}
                ):
                    for match in CHECKLIST_ID_RE.findall(v):
                        found.add(match)
                walk(v)
        elif isinstance(x, list):
            for item in x:
                walk(item)
        elif isinstance(x, str):
            # Do not aggressively treat arbitrary prose as checklist IDs,
            # but retaining an ID found in a structured artifact is useful.
            for match in CHECKLIST_ID_RE.findall(x):
                found.add(match)

    walk(obj)
    return sorted(found)


def find_values(obj: Any, keys: set[str]) -> list[Any]:
    values: list[Any] = []

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                if str(k).lower() in keys:
                    values.append(v)
                walk(v)
        elif isinstance(x, list):
            for item in x:
                walk(item)

    walk(obj)
    return values


def first_value(obj: Any, keys: set[str], default: Any = None) -> Any:
    values = find_values(obj, keys)
    return values[0] if values else default


def boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        s = value.strip().lower()
        if s in {"true", "yes", "y", "1", "pass", "passed"}:
            return True
        if s in {"false", "no", "n", "0", "fail", "failed"}:
            return False
    return None


def flatten_metrics(obj: Any) -> dict[str, Any]:
    """
    Collect the most report-useful metrics without changing source semantics.
    If the same metric key appears in multiple nested structures, the first
    occurrence wins and the complete source remains available in raw_data.
    """
    result: dict[str, Any] = {}

    def walk(x: Any) -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                lk = str(k).lower()
                if (
                    lk in {
                        "candidate_count", "candidates", "tests", "completed",
                        "findings", "requires_review", "review",
                        "request_errors", "executed_files", "executed",
                        "accepted", "blocked", "boundary_accepted",
                        "storage_proven", "overwrite_proven",
                        "reflected", "evaluated", "parser_errors",
                        "challenge", "http_errors", "upload_performed",
                        "links", "pages", "upload_forms", "hidden_endpoints",
                        "js_signals", "probes", "files_executed",
                        "mismatch_accepted",
                    }
                    and lk not in result
                    and isinstance(v, (int, float, bool, str))
                ):
                    result[str(k)] = v
                walk(v)
        elif isinstance(x, list):
            for item in x:
                walk(item)

    walk(obj)
    return result


def extract_summary(obj: Any) -> dict[str, Any]:
    checklist_ids = extract_checklist_ids(obj)

    status = first_value(
        obj,
        {"status", "results_status", "assessment_status", "lifecycle_status"},
    )

    assessment_result = first_value(
        obj,
        {"assessment_result", "result", "assessment"},
    )

    finding = first_value(
        obj,
        {"finding", "has_finding", "finding_present"},
    )

    review = first_value(
        obj,
        {"requires_review", "review_required", "manual_review"},
    )

    summary = {
        "checklist_ids": checklist_ids,
        "status": status,
        "assessment_result": assessment_result,
        "finding": boolish(finding),
        "requires_review": boolish(review),
        "metrics": flatten_metrics(obj),
    }

    return summary


def should_skip(path: Path, root: Path, output_root: Path | None) -> bool:
    parts = set(path.relative_to(root).parts)
    if parts & SKIP_DIR_NAMES:
        return True

    if output_root is not None:
        try:
            path.resolve().relative_to(output_root.resolve())
            return True
        except ValueError:
            pass

    return False


def collect_files(root: Path, output_root: Path | None) -> list[Path]:
    files: list[Path] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if should_skip(path, root, output_root):
            continue
        if not is_text_file(path):
            continue
        files.append(path)

    return files


def classify_path(rel: str) -> str:
    p = rel.lower()
    if "/evidence/" in f"/{p}/" or p.startswith("evidence/"):
        return "evidence"
    if p.startswith("findings/"):
        return "findings"
    if p.startswith("retest/") or "/retest/" in p:
        return "retest"
    if p.startswith("scans/") or "/scans/" in p:
        return "scans"
    if p.startswith("scoring/") or "/scoring/" in p:
        return "scoring"
    if p.startswith("timeline/") or "/timeline/" in p:
        return "timeline"
    if p.startswith("report/") or "/report/" in p:
        return "report"
    if p.startswith("01-preparation/"):
        return "preparation"
    return "project_artifact"


def is_artifact_yaml(rel: str) -> bool:
    p = rel.lower()
    if not (p.endswith(".yaml") or p.endswith(".yml")):
        return False

    # Exclude general README/config style files from checklist artifact
    # aggregation unless they explicitly contain a checklist ID.
    name = Path(p).name
    return (
        name.endswith(".yaml")
        or name.endswith(".yml")
    )


def build_file_record(path: Path, root: Path) -> dict[str, Any]:
    rel = safe_rel(path, root)
    size = path.stat().st_size
    record: dict[str, Any] = {
        "path": rel,
        "category": classify_path(rel),
        "extension": path.suffix.lower(),
        "size_bytes": size,
        "sha256": sha256_file(path),
    }

    if is_text_file(path):
        text = read_text(path)
        record["line_count"] = text.count("\n") + (1 if text else 0)

        # README, logs, command output, XML/HTML and config snippets are valid
        # evidence. Only formats explicitly supported as structured data are
        # parsed below.
        if path.suffix.lower() not in STRUCTURED_EXTENSIONS:
            record["format"] = "text"
            record["structured"] = False
            record["text"] = redact_text(text[:250_000])
            record["truncated"] = len(text) > 250_000
        else:
            try:
                obj, parser = load_structured(path)
                redacted = redact_value(obj)
                record["format"] = parser
                record["structured"] = True
                record["summary"] = extract_summary(redacted)
                record["data"] = redacted
            except Exception as exc:
                # Parse errors remain meaningful for files that are expected
                # to be JSON/YAML/CSV. Keep their raw content as fallback.
                record["format"] = path.suffix.lower().lstrip(".") or "text"
                record["structured"] = False
                record["parse_error"] = f"{type(exc).__name__}: {exc}"
                record["text"] = redact_text(text[:250_000])
                record["truncated"] = len(text) > 250_000

    return record


def derive_checklist_records(file_records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}

    for rec in file_records:
        for cid in rec.get("summary", {}).get("checklist_ids", []):
            item = grouped.setdefault(
                cid,
                {
                    "checklist_id": cid,
                    "source_files": [],
                    "statuses": [],
                    "assessment_results": [],
                    "findings": [],
                    "requires_review": [],
                    "metrics": {},
                },
            )

            item["source_files"].append(rec["path"])

            s = rec.get("summary", {})
            if s.get("status") is not None:
                item["statuses"].append(s["status"])
            if s.get("assessment_result") is not None:
                item["assessment_results"].append(s["assessment_result"])
            if s.get("finding") is not None:
                item["findings"].append(s["finding"])
            if s.get("requires_review") is not None:
                item["requires_review"].append(s["requires_review"])

            for key, value in s.get("metrics", {}).items():
                item["metrics"].setdefault(key, value)

    # Stable de-duplication.
    for item in grouped.values():
        for key in (
            "source_files", "statuses", "assessment_results",
            "findings", "requires_review",
        ):
            seen = []
            for value in item[key]:
                if value not in seen:
                    seen.append(value)
            item[key] = seen

    return dict(sorted(grouped.items()))


def aggregate_findings(file_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Extract likely finding records while preserving the source file and exact
    source object. This does not invent severity or classify a finding.
    """
    findings: list[dict[str, Any]] = []

    def walk(obj: Any, path: str = "") -> Iterable[tuple[str, Any]]:
        if isinstance(obj, dict):
            for k, v in obj.items():
                current = f"{path}.{k}" if path else str(k)
                if str(k).lower() in {
                    "findings", "finding", "vulnerabilities", "vulnerability",
                }:
                    yield current, v
                yield from walk(v, current)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from walk(v, f"{path}[{i}]")

    for rec in file_records:
        if "data" not in rec:
            continue
        for location, value in walk(rec["data"]):
            if value in (False, None, 0, "", [], {}):
                continue

            # Boolean "finding: true" is useful context but not a complete
            # finding object. Keep it separately.
            if isinstance(value, bool):
                findings.append({
                    "source_file": rec["path"],
                    "location": location,
                    "value": value,
                })
            else:
                findings.append({
                    "source_file": rec["path"],
                    "location": location,
                    "value": value,
                })

    return findings


def extract_reviews(file_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []

    def walk(obj: Any, path: str = "") -> Iterable[tuple[str, Any]]:
        if isinstance(obj, dict):
            for k, v in obj.items():
                current = f"{path}.{k}" if path else str(k)
                lk = str(k).lower()
                if lk in {
                    "review", "reviews", "review_items", "manual_review",
                    "requires_review", "review_reason", "review_notes",
                    "notes", "manual_review_reason",
                }:
                    yield current, v
                yield from walk(v, current)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from walk(v, f"{path}[{i}]")

    for rec in file_records:
        if "data" not in rec:
            continue
        for location, value in walk(rec["data"]):
            if value in (False, None, 0, "", [], {}):
                continue
            reviews.append({
                "source_file": rec["path"],
                "location": location,
                "value": value,
            })

    return reviews


def read_project_metadata(root: Path) -> dict[str, Any]:
    metadata: dict[str, Any] = {}

    for name in ("assessment.yaml", "checklist.yaml"):
        path = root / name
        if not path.is_file():
            continue
        try:
            obj, _ = load_structured(path)
            metadata[name] = redact_value(obj)
        except Exception as exc:
            metadata[name] = {
                "_parse_error": f"{type(exc).__name__}: {exc}",
                "_text": redact_text(read_text(path)),
            }

    return metadata


def calculate_high_level_counts(
    checklist_records: dict[str, dict[str, Any]],
    file_records: list[dict[str, Any]],
) -> dict[str, Any]:
    completed = 0
    incomplete = 0
    findings = 0
    reviews = 0

    for item in checklist_records.values():
        statuses = {str(x).lower() for x in item["statuses"]}
        results = {str(x).lower() for x in item["assessment_results"]}

        is_completed = bool(
            statuses & {"completed", "complete", "passed", "pass", "closed"}
            or results & {"completed", "complete", "passed", "pass", "closed"}
        )

        if is_completed:
            completed += 1
        else:
            incomplete += 1

        if True in item["findings"]:
            findings += 1
        if True in item["requires_review"]:
            reviews += 1

    category_counts = Counter(rec["category"] for rec in file_records)

    return {
        "checklist_count": len(checklist_records),
        "completed_checklists": completed,
        "incomplete_checklists": incomplete,
        "checklists_with_finding_true": findings,
        "checklists_with_review_true": reviews,
        "file_count": len(file_records),
        "files_by_category": dict(sorted(category_counts.items())),
    }


def make_prompt(bundle: dict[str, Any]) -> str:
    """
    Build a prompt that tells ChatGPT to write the final report from the
    collected evidence without inventing facts.
    """
    project = bundle["project"]
    counts = bundle["aggregate"]["high_level_counts"]

    return f"""# PROMPT — FINAL PENETRATION TEST REPORT
## BrebesKab-CSIRT-Tools / {project["project_id"]}

Anda adalah **penyusun laporan akhir penetration test** untuk proyek
**{project["project_id"]}**.

Gunakan **hanya data yang tersedia pada SOURCE BUNDLE** di bagian bawah prompt
dan data sumber yang dilampirkan/tersedia bersama prompt ini. Jangan mengarang,
menebak, mengisi kekosongan dengan asumsi, atau mengubah hasil pengujian.

### 1. Aturan utama

1. Perlakukan evidence sebagai sumber kebenaran utama.
2. Pertahankan istilah, checklist ID, status, metrics, wording teknis, URL,
   endpoint, HTTP status, dan angka yang tercatat di evidence.
3. Jangan menyimpulkan vulnerability hanya karena:
   - HTTP 200/201/302/303;
   - upload `accepted_or_processed`;
   - file dianggap diterima oleh form;
   - reflection ditemukan;
   - HTTP 500/error page muncul;
   - session identifier tidak berubah;
   - sebuah payload diterima.
   Semua harus ditafsirkan sesuai evidence dan aturan pengujian masing-masing.
4. Bedakan secara tegas:
   - **Finding**: evidence mendukung adanya security finding.
   - **Requires review**: evidence belum cukup untuk menetapkan finding dan perlu
     verifikasi/manual review.
   - **Pass/Completed**: checklist selesai tanpa finding yang dikonfirmasi.
   - **Not tested / incomplete**: pengujian belum selesai.
5. Jangan mengubah `requires_review` menjadi vulnerability secara otomatis.
6. Jangan mengubah sinyal forensic menjadi finding tanpa bukti yang memadai.
7. Jika evidence saling berbeda, tampilkan perbedaannya dan sebutkan sumbernya.
   Jangan diam-diam melakukan rekonsiliasi.
8. Jika suatu data tidak tersedia, tulis **"tidak tersedia pada evidence"**.
9. Jangan menampilkan credential, cookie, bearer token, CSRF token, session
   secret, API key, password, atau material autentikasi lainnya. Source bundle
   sudah melakukan redaksi terhadap data yang teridentifikasi sebagai secret.
10. Jangan mengarang CVE/CWE/CVSS. Jika klasifikasi tersebut belum ditentukan
    oleh evidence, tandai sebagai **perlu review**.
11. Jangan menyatakan exploitability, impact, persistence, RCE, overwrite,
    storage, execution, atau data disclosure bila evidence belum membuktikannya.
12. Untuk setiap kesimpulan penting, cantumkan sumber evidence:
    `source_file` dan, bila tersedia, checklist ID / lokasi data.

### 2. Konteks proyek

Project ID: {project["project_id"]}
Generated at: {bundle["generated_at"]}

Ringkasan koleksi:
- Total checklist yang teridentifikasi: {counts["checklist_count"]}
- Checklist completed/pass/closed: {counts["completed_checklists"]}
- Checklist belum dapat dikategorikan completed: {counts["incomplete_checklists"]}
- Checklist yang memiliki `finding: true`: {counts["checklists_with_finding_true"]}
- Checklist yang memiliki `requires_review: true`: {counts["checklists_with_review_true"]}
- Total source files yang dikumpulkan: {counts["file_count"]}

### 3. Tugas Anda

Buat **Laporan Akhir Penetration Test** yang profesional, audit-ready, dan
berbasis evidence dengan struktur minimal berikut:

1. **Halaman Judul**
   - Project ID
   - Target / scope yang tersedia
   - Environment
   - Assessment type / methodology yang tersedia
   - Tanggal assessment yang tersedia
   - Penyusun, jika tersedia pada source

2. **Executive Summary**
   - tujuan assessment
   - scope
   - pendekatan
   - status keseluruhan
   - jumlah checklist completed
   - jumlah finding yang benar-benar didukung evidence
   - jumlah item requires review
   - keterbatasan penting

3. **Scope & Rules of Engagement**
   - target
   - authorized ports
   - environment
   - black/gray/white box jika tersedia
   - batasan pengujian
   - safety constraints
   - authenticated/unauthenticated context

4. **Methodology**
   - struktur checklist
   - discovery/recon
   - infrastructure
   - web/server/security controls
   - authentication/session
   - input validation
   - file upload
   - authorization/API/SSRF/CSRF/CORS/client-side/sensitive-data/
     business-logic/dependency/logging jika evidence tersedia
   - evidence validation, finding review, retest, final sign-off jika tersedia

5. **Assessment Coverage**
   Buat tabel:
   | Checklist | Nama | Status | Result | Finding | Review | Metrics | Evidence |
   Jangan menghilangkan checklist yang belum lengkap.

6. **Detailed Technical Results**
   Untuk setiap checklist yang mempunyai evidence:
   - tujuan pengujian
   - metode
   - test matrix / candidate / probes jika tersedia
   - request/response penting
   - hasil
   - interpretation
   - finding atau review status
   - evidence source
   Jangan mengarang detail yang tidak ada.

7. **Findings**
   Hanya masukkan finding yang didukung evidence.
   Untuk setiap finding:
   - Finding ID (buat ID laporan hanya jika perlu, dan jelaskan bahwa ID
     tersebut adalah ID laporan, bukan ID evidence)
   - title
   - affected component
   - description
   - evidence
   - impact
   - risk/severity hanya jika didukung atau sudah ditentukan
   - recommendation
   - source evidence
   Jika tidak ada finding yang terkonfirmasi, nyatakan dengan jelas bahwa
   evidence yang terkumpul tidak menunjukkan finding yang terkonfirmasi.

8. **Items Requiring Manual Review**
   Buat daftar seluruh item `requires_review` yang relevan.
   Untuk setiap item:
   - checklist
   - source
   - observed signal
   - why it is not yet a confirmed finding
   - what manual verification is needed
   Jangan menaikkan statusnya menjadi vulnerability.

9. **Security Observations / Forensic Signals**
   Pisahkan observation dari finding.
   Contoh: HTTP 500, framework/debug disclosure, reflection, accepted upload,
   session reuse, atau response behavior hanya ditulis sebagai observation
   jika evidence mendukung dan belum cukup untuk finding.

10. **Limitations**
    Ambil hanya dari evidence:
    - authentication/challenge limitations
    - browser/Turnstile limitations
    - unavailable storage disclosure
    - incomplete checklist
    - network/VPN/interface limitations
    - blocked testing
    - deadline-related limitations
    - lainnya yang tercatat

11. **Recommendations**
    Prioritaskan recommendation berdasarkan finding yang benar-benar terbukti.
    Untuk review item, berikan rekomendasi verifikasi atau hardening yang
    proporsional tanpa menyebutnya sebagai confirmed vulnerability.

12. **Retest / Verification Status**
    Gunakan hanya evidence pada fase retest/verification bila tersedia.

13. **Overall Conclusion**
    Berikan kesimpulan yang proporsional terhadap evidence.
    Jangan mengatakan "secure", "100% aman", atau "tidak ada vulnerability"
    hanya karena finding count nol jika masih ada review/incomplete items.

14. **Appendix A — Checklist Matrix**
15. **Appendix B — Evidence Index**
16. **Appendix C — Important Metrics**
17. **Appendix D — Review Items**
18. **Appendix E — Source File Inventory**

### 4. Gaya laporan

- Bahasa Indonesia formal dan teknis.
- Gunakan istilah keamanan yang tepat.
- Jangan berlebihan dalam klaim.
- Jangan menghapus hasil negatif hanya karena tidak menarik.
- Jangan menyembunyikan HTTP error, reflection, accepted upload, session
  behavior, atau signal lain yang mungkin penting untuk manual review.
- Bedakan "observed", "indicated", "confirmed", dan "not proven".
- Semua angka harus berasal dari source bundle.
- Gunakan tabel untuk checklist, findings, review items, dan evidence index.
- Gunakan kode/fenced block hanya untuk request/response atau artefak teknis
  yang memang perlu ditampilkan.
- Jangan tampilkan secret yang sudah direda ksi.

### 5. Validasi internal sebelum finalisasi

Sebelum menghasilkan laporan final, lakukan pemeriksaan internal:

- Apakah semua checklist yang ditemukan tercantum?
- Apakah status setiap checklist sama dengan evidence?
- Apakah finding hanya berasal dari evidence yang mendukung?
- Apakah review item tetap review?
- Apakah angka metrics konsisten dengan source?
- Apakah ada evidence penting yang hilang?
- Apakah ada klaim yang tidak memiliki source?
- Apakah ada credential/session secret yang ikut tertulis?
- Apakah keterbatasan assessment dicantumkan?
- Apakah kesimpulan tidak lebih kuat daripada evidence?

Jika ada konflik data, jangan memilih secara diam-diam. Tampilkan konflik
tersebut pada bagian "Evidence/Data Consistency Notes" dan sebutkan kedua
sumbernya.

---

# SOURCE BUNDLE

Source bundle berikut dibuat otomatis oleh BrebesKab-CSIRT-Tools.
Jangan menganggap field yang tidak ada sebagai fakta.

```json
{json.dumps(bundle, ensure_ascii=False, indent=2)}
```

---

# OUTPUT YANG DIMINTA

Keluarkan **Laporan Akhir Penetration Test lengkap** dalam Bahasa Indonesia,
siap dipindahkan ke dokumen resmi.

Setelah laporan, buat bagian terpisah:

## Evidence/Data Consistency Notes
Daftarkan konflik, data ambigu, atau kekurangan evidence yang harus diperiksa
manusia sebelum laporan ditandatangani.

## Final Sign-off Checklist
- Scope verified
- Checklist coverage verified
- Findings verified
- Review items verified
- Evidence references verified
- Sensitive data redaction verified
- Recommendations verified
- Retest status verified
- Final conclusion verified
"""


def build_bundle(root: Path, project_id: str) -> dict[str, Any]:
    output_root = root / "23-final-sign-off"

    paths = collect_files(root, output_root if output_root.exists() else None)

    records: list[dict[str, Any]] = []
    parse_errors: list[dict[str, str]] = []

    for path in paths:
        try:
            rec = build_file_record(path, root)
            records.append(rec)
            if rec.get("parse_error"):
                parse_errors.append({
                    "path": rec["path"],
                    "error": rec["parse_error"],
                })
        except Exception as exc:
            parse_errors.append({
                "path": safe_rel(path, root),
                "error": f"{type(exc).__name__}: {exc}",
            })

    checklist_records = derive_checklist_records(records)

    bundle = {
        "schema": "brebeskab-csirt-final-report-source/v1",
        "tool": "BrebesKab-CSIRT-Tools",
        "script": {
            "name": Path(__file__).name,
            "version": SCRIPT_VERSION,
        },
        "generated_at": utc_now(),
        "project": {
            "project_id": project_id,
            "project_root": str(root),
        },
        "project_metadata": read_project_metadata(root),
        "aggregate": {
            "high_level_counts": calculate_high_level_counts(
                checklist_records, records
            ),
            "checklists": checklist_records,
            "findings": aggregate_findings(records),
            "reviews": extract_reviews(records),
            "parse_errors": parse_errors,
        },
        "files": records,
    }

    return bundle


def write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_outputs(root: Path, bundle: dict[str, Any]) -> dict[str, Path]:
    outdir = root / "23-final-sign-off"
    outdir.mkdir(parents=True, exist_ok=True)

    evidence_json_path = outdir / "evidence.json"
    evidence_yaml_path = outdir / "evidence.yaml"
    prompt_path = outdir / "report-prompt.md"

    write_json(evidence_json_path, bundle)

    index = {
        "schema": "brebeskab-csirt-final-report-index/v1",
        "generated_at": bundle["generated_at"],
        "project": bundle["project"],
        "summary": bundle["aggregate"]["high_level_counts"],
        "checklists": bundle["aggregate"]["checklists"],
        "parse_errors": bundle["aggregate"]["parse_errors"],
        "source_file_count": len(bundle["files"]),
        "source_files": [
            {
                "path": x["path"],
                "category": x["category"],
                "sha256": x["sha256"],
                "size_bytes": x["size_bytes"],
            }
            for x in bundle["files"]
        ],
    }
    write_yaml(evidence_yaml_path, index)

    prompt = make_prompt(bundle)
    prompt_path.write_text(prompt, encoding="utf-8")

    return {
        "evidence_json": evidence_json_path,
        "evidence_yaml": evidence_yaml_path,
        "prompt": prompt_path,
    }


def print_status(bundle: dict[str, Any]) -> None:
    counts = bundle["aggregate"]["high_level_counts"]

    print("=" * 72)
    print("BrebesKab-CSIRT-Tools — Final Report Evidence Collector")
    print(f"Version     : {SCRIPT_VERSION}")
    print(f"Project     : {bundle['project']['project_id']}")
    print(f"Generated   : {bundle['generated_at']}")
    print("-" * 72)
    print(f"Source files: {counts['file_count']}")
    print(f"Checklists  : {counts['checklist_count']}")
    print(f"Completed   : {counts['completed_checklists']}")
    print(f"Incomplete  : {counts['incomplete_checklists']}")
    print(f"Findings    : {counts['checklists_with_finding_true']}")
    print(f"Review      : {counts['checklists_with_review_true']}")
    print("-" * 72)

    if bundle["aggregate"]["parse_errors"]:
        print("Parse errors:")
        for item in bundle["aggregate"]["parse_errors"]:
            print(f"  - {item['path']}: {item['error']}")
    else:
        print("Parse errors: 0")

    print("=" * 72)


def verify_bundle(bundle: dict[str, Any]) -> bool:
    ok = True

    project_id = bundle["project"]["project_id"]
    if not project_id:
        print("[FAIL] Project ID kosong.")
        ok = False

    files = bundle.get("files", [])
    if not files:
        print("[FAIL] Tidak ada source file yang dikumpulkan.")
        ok = False

    if bundle["aggregate"]["parse_errors"]:
        for item in bundle["aggregate"]["parse_errors"]:
            print(f"[WARN] Structured parse error: {item['path']} -> {item['error']}")

    for rec in files:
        if not rec.get("path"):
            print("[FAIL] Source record tanpa path.")
            ok = False
        if not rec.get("sha256"):
            print(f"[FAIL] SHA256 hilang: {rec.get('path')}")
            ok = False

    print(f"[{'PASS' if ok else 'FAIL'}] Final report evidence bundle validation.")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Collect all project evidence and generate a ChatGPT prompt "
            "for the final penetration-test report."
        )
    )
    parser.add_argument(
        "command",
        choices={"generate", "status", "verify"},
        nargs="?",
        default="generate",
    )
    parser.add_argument(
        "--project",
        default=DEFAULT_PROJECT_ID,
        help=f"Project ID (default: {DEFAULT_PROJECT_ID})",
    )
    parser.add_argument(
        "--project-root",
        default=None,
        help="Explicit project root path.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="For generate: also print the generated prompt to stdout.",
    )

    args = parser.parse_args()

    try:
        root = resolve_project_root(args.project_root, args.project)
        bundle = build_bundle(root, args.project)

        if args.command == "status":
            print_status(bundle)
            return 0

        if args.command == "verify":
            print_status(bundle)
            return 0 if verify_bundle(bundle) else 1

        outputs = write_outputs(root, bundle)
        print_status(bundle)
        print()
        print("[PASS] Evidence bundle generated.")
        print(f"[PASS] Evidence JSON : {outputs['evidence_json']}")
        print(f"[PASS] Evidence YAML : {outputs['evidence_yaml']}")
        print(f"[PASS] Prompt        : {outputs['prompt']}")

        if args.stdout:
            print()
            print("=" * 72)
            print("GENERATED CHATGPT PROMPT")
            print("=" * 72)
            print(outputs["prompt"].read_text(encoding="utf-8"))

        return 0

    except Exception as exc:
        print(f"[ERROR] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
