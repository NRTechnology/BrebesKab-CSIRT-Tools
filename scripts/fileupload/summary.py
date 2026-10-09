#!/usr/bin/env python3
"""BrebesKab-CSIRT-Tools - Checklist 10 File Upload Summary.

Aggregation-only summary for 10-001 through 10-007. No network requests.
"""
from __future__ import annotations
import argparse, sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import yaml

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
try:
    from context import load_active_context, get_active_project_path
except ImportError as exc:
    raise SystemExit(f"[ERROR] Modul context tidak dapat dimuat: {exc}")

SCRIPT_NAME = "summary.py"
VERSION = "1.0.0"
CHECKLIST_ID = "10-008"
CHECKLIST_NAME = "File Upload Summary"
PHASE = "10 File Upload"
SCHEMA_VERSION = "1.0"

ITEMS = [
    ("10-001", "File Upload Discovery", "discovery", "discovery.yaml", "evidence/discovery-evidence.json"),
    ("10-002", "File Upload Extension Validation", "extension", "extension.yaml", "evidence/extension-evidence.json"),
    ("10-003", "File Upload Filename Validation", "filename", "filename.yaml", "evidence/filename-evidence.json"),
    ("10-004", "File Upload Overwrite Validation", "overwrite", "overwrite.yaml", "evidence/overwrite-evidence.json"),
    ("10-005", "File Upload Size Validation", "size", "size.yaml", "evidence/size-evidence.json"),
    ("10-006", "File Upload Storage Validation", "storage", "storage.yaml", "evidence/storage-evidence.json"),
    ("10-007", "File Upload Content Validation", "validation", "validation.yaml", "evidence/validation-evidence.json"),
]


def now():
    return datetime.now(timezone.utc).astimezone().isoformat()


def project():
    ctx = load_active_context()
    root = Path(get_active_project_path()).resolve()
    pid = str(getattr(ctx, "project_id", "") or "").strip()
    if not pid:
        raise RuntimeError("Project ID aktif tidak ditemukan.")
    return root, pid


def root10(root):
    return root / "10-file-upload"


def summary_path(root):
    return root10(root) / "summary" / "summary.yaml"


def item_paths(root, item):
    cid, name, directory, artifact, evidence = item
    base = root10(root) / directory
    return base / artifact, base / evidence


def load_yaml(path):
    with path.open("r", encoding="utf-8-sig") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise RuntimeError(f"Artifact bukan mapping YAML: {path}")
    return data


def save_yaml(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False,
                                    default_flow_style=False, width=120), encoding="utf-8")


def d(value):
    return value if isinstance(value, dict) else {}


def lst(value):
    return value if isinstance(value, list) else []


def integer(value):
    if isinstance(value, bool): return int(value)
    try: return int(value)
    except (TypeError, ValueError): return 0


def first_int(data, keys):
    for key in keys:
        if key in data: return integer(data[key])
    return 0


def status(data):
    r, c = d(data.get("results")), d(data.get("checklist"))
    for value in (data.get("status"), r.get("status"), c.get("status")):
        if str(value or "").strip(): return str(value).strip().lower()
    return "unknown"


def metrics(data):
    r = d(data.get("results"))
    candidates = data.get("candidates")
    candidate_count = first_int(r, ("candidate_count", "upload_candidates"))
    if isinstance(r.get("candidates"), list): candidate_count = len(r["candidates"])
    elif candidate_count == 0 and isinstance(candidates, list): candidate_count = len(candidates)
    tests = first_int(r, ("tests", "test_count", "tested"))
    if tests == 0 and isinstance(data.get("test_matrix"), list): tests = len(data["test_matrix"])
    out = {
        "candidate_count": candidate_count,
        "tests": tests,
        "completed": first_int(r, ("completed", "tests_completed")),
        "findings": first_int(r, ("findings", "finding_count", "automatic_findings", "confirmed_findings")),
        "requires_review": first_int(r, ("requires_review", "review_count", "manual_review", "manual_review_count")),
        "request_errors": first_int(r, ("request_errors", "request_error_count")),
        "executed_files": first_int(r, ("executed_files", "files_executed", "automatic_execution")),
    }
    for key in ("accepted_indicators", "blocked_indicators", "mismatch_accepted",
                "collision_accepted_indicators", "overwrite_proven_tests", "storage_proven_tests",
                "application_disclosed_storage_urls", "tests_with_disclosed_storage_url",
                "boundary_accepted_indicators", "human_interaction_not_completed", "automatic_execution"):
        if key in r: out[key] = integer(r[key])
    return out


def assessment_result(data):
    for container in (d(data.get("assessment")), d(data.get("results")), d(data.get("checklist")), data):
        for key in ("assessment_result", "result", "overall_result"):
            if isinstance(container.get(key), str) and container[key].strip():
                return container[key].strip().lower()
    s = status(data)
    return "completed" if s in ("completed", "complete", "pass", "passed") else s


def method_flags(data):
    m = d(data.get("methodology"))
    wanted = ("source_candidates_only", "same_origin_only", "authenticated_session_required",
              "multipart_post_allowed", "browser_simulator", "human_interaction_supported",
              "manual_challenge_solve_allowed", "automatic_finding", "uploaded_file_execution",
              "file_execution", "webshell", "reverse_shell", "command_execution", "persistence",
              "external_callbacks", "no_storage_path_guessing", "application_disclosed_storage_only",
              "forensic_evidence_preserved")
    return {k: m[k] for k in wanted if k in m}


def relative(root, path):
    try: return path.relative_to(root.parent.parent).as_posix()
    except ValueError: return path.as_posix()


def entry(root, item):
    cid, name, directory, artifact, evidence = item
    ap, ep = item_paths(root, item)
    base = {"id": cid, "name": name, "source": relative(root, ap),
            "source_exists": ap.exists(), "evidence": relative(root, ep),
            "evidence_exists": ep.exists(), "expected_state": "completed"}
    if not ap.exists():
        base.update({"status": "missing", "assessment_result": "missing", "finding": False,
                     "requires_review": False, "metrics": {"candidate_count": 0, "tests": 0,
                     "completed": 0, "findings": 0, "requires_review": 0, "request_errors": 0,
                     "executed_files": 0}, "reason": "Checklist artifact tidak tersedia; tidak dibuat menjadi finding otomatis."})
        return base
    data = load_yaml(ap)
    m = metrics(data)
    ident = d(data.get("tool")), d(data.get("checklist"))
    source_id = str(ident[1].get("id") or data.get("checklist_id") or cid)
    base.update({"status": status(data), "assessment_result": assessment_result(data),
                 "finding": m["findings"] > 0, "requires_review": m["requires_review"] > 0,
                 "metrics": m, "source_identity": {"script": str(ident[0].get("script") or data.get("script") or ""),
                 "version": str(ident[0].get("version") or data.get("version") or ""),
                 "checklist_id": source_id, "checklist_name": str(ident[1].get("name") or name)},
                 "methodology_flags": method_flags(data)})
    if source_id != cid:
        base["identity_warning"] = f"Artifact menyatakan {source_id}; file diharapkan {cid}."
    return base


def aggregate(entries):
    a = {"checklists_total": len(entries), "completed_count": 0, "missing_count": 0,
         "incomplete_count": 0, "finding_count": 0, "review_count": 0, "candidate_count": 0,
         "tests": 0, "tests_completed": 0, "request_errors": 0, "executed_files": 0,
         "automatic_execution": 0}
    for e in entries:
        s = str(e.get("status", "")).lower(); r = str(e.get("assessment_result", "")).lower()
        if s == "missing": a["missing_count"] += 1
        elif s in ("completed", "complete", "pass", "passed"): a["completed_count"] += 1
        elif r not in ("completed", "complete", "pass", "passed"): a["incomplete_count"] += 1
        m = d(e.get("metrics"))
        for k in ("findings", "requires_review", "candidate_count", "tests", "completed",
                  "request_errors", "executed_files", "automatic_execution"):
            dest = "tests_completed" if k == "completed" else ("finding_count" if k == "findings" else ("review_count" if k == "requires_review" else k))
            a[dest] += integer(m.get(k))
    return a


def initial(root, pid):
    return {"schema_version": SCHEMA_VERSION, "project_id": pid,
            "tool": {"name": "BrebesKab-CSIRT-Tools", "script": SCRIPT_NAME,
                     "version": VERSION, "method": "aggregation-only"},
            "checklist": {"id": CHECKLIST_ID, "name": CHECKLIST_NAME, "phase": PHASE,
                          "status": "initialized", "focus": "Aggregation 10-001 through 10-007 without active probing."},
            "methodology": {"aggregation_only": True, "active_probing": False, "network_requests": False,
                            "source_artifacts_read_only": True, "missing_artifact_is_not_finding": True,
                            "preserve_source_findings": True, "preserve_source_review_flags": True,
                            "do_not_infer_storage_from_http_status": True, "do_not_infer_execution_from_acceptance": True,
                            "uploaded_file_execution": False, "automatic_finding": False},
            "sources": {i[0]: relative(root, item_paths(root, i)[0]) for i in ITEMS},
            "checklists": [], "assessment": {}, "generated_at": now()}


def generate(root, pid):
    data = initial(root, pid)
    data["checklists"] = [entry(root, i) for i in ITEMS]
    data["assessment"] = aggregate(data["checklists"])
    data["generated_at"] = now()
    return data


def validate(data, pid):
    errors = []
    if data.get("schema_version") != SCHEMA_VERSION: errors.append("schema_version tidak valid.")
    if str(data.get("project_id", "")).strip() != pid: errors.append("project_id tidak sama dengan project aktif.")
    if d(data.get("checklist")).get("id") != CHECKLIST_ID: errors.append(f"Checklist ID harus {CHECKLIST_ID}.")
    entries = lst(data.get("checklists")); expected = [i[0] for i in ITEMS]
    actual = [str(d(e).get("id", "")) for e in entries]
    if actual != expected: errors.append("Urutan checklist harus 10-001 sampai 10-007.")
    if len(entries) != 7: errors.append("Jumlah checklist summary harus 7.")
    for e0 in entries:
        e = d(e0); cid = e.get("id", "?")
        for k in ("source", "source_exists", "status", "assessment_result", "finding", "requires_review", "metrics"):
            if k not in e: errors.append(f"{k} tidak ada untuk {cid}.")
        if not isinstance(e.get("source_exists"), bool): errors.append(f"source_exists harus boolean untuk {cid}.")
        if not isinstance(e.get("finding"), bool): errors.append(f"finding harus boolean untuk {cid}.")
        if not isinstance(e.get("requires_review"), bool): errors.append(f"requires_review harus boolean untuk {cid}.")
        m = d(e.get("metrics"))
        for k in ("candidate_count", "tests", "completed", "findings", "requires_review", "request_errors", "executed_files"):
            if not isinstance(m.get(k), int): errors.append(f"metrics.{k} harus integer untuk {cid}.")
        if e.get("source_exists") is False and e.get("finding") is not False:
            errors.append(f"Artifact hilang {cid} tidak boleh menjadi finding.")
    a = d(data.get("assessment"))
    for k in ("checklists_total", "completed_count", "missing_count", "incomplete_count", "finding_count", "review_count",
              "candidate_count", "tests", "tests_completed", "request_errors", "executed_files", "automatic_execution"):
        if not isinstance(a.get(k), int): errors.append(f"Assessment {k} harus integer.")
    return errors


def version():
    print("BrebesKab-CSIRT-Tools summary.py")
    print(f"Version   : {VERSION}")
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Phase     : {PHASE}")
    return 0


def main():
    p = argparse.ArgumentParser(description="File Upload Summary - aggregation only")
    p.add_argument("command", nargs="?", choices=("init", "generate", "show", "verify", "status", "remove", "version"))
    args = p.parse_args()
    if args.command == "version": return version()
    root, pid = project()
    sp = summary_path(root)
    if args.command == "init":
        if sp.exists(): print(f"[INFO] File Upload Summary sudah ada.\n[INFO] Artifact : {sp}"); return 0
        save_yaml(sp, initial(root, pid)); print("[PASS] File Upload Summary init selesai."); print(f"[PASS] Project     : {pid}"); print(f"[PASS] Checklists  : 7"); print(f"[PASS] Artifact    : {sp}"); return 0
    if args.command == "generate":
        data = generate(root, pid); save_yaml(sp, data); a = data["assessment"]
        print("[PASS] File Upload Summary generate selesai.")
        for label, key in (("Project", None), ("Checklists", "checklists_total"), ("Completed", "completed_count"), ("Missing", "missing_count"), ("Incomplete", "incomplete_count"), ("Findings", "finding_count"), ("Review", "review_count"), ("Executed", "executed_files")):
            print(f"[PASS] {label:<11}: {pid if key is None else a[key]}")
        print(f"[PASS] Artifact    : {sp}"); return 0
    if args.command in ("show", "verify", "status"):
        if not sp.exists(): print("[FAIL] File Upload Summary belum ada."); print(f"[INFO] Jalankan: python {SCRIPT_NAME} generate"); return 1
        data = load_yaml(sp)
        if args.command == "show": print(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=120).rstrip()); return 0
        if args.command == "status":
            c, a = d(data.get("checklist")), d(data.get("assessment")); print("BrebesKab-CSIRT-Tools File Upload Summary"); print(f"Project     : {pid}"); print(f"Checklist   : {CHECKLIST_ID} {CHECKLIST_NAME}"); print(f"Status      : {c.get('status', 'unknown')}"); print(f"Checklists  : {a.get('checklists_total', 0)}"); print(f"Completed   : {a.get('completed_count', 0)}"); print(f"Missing     : {a.get('missing_count', 0)}"); print(f"Incomplete  : {a.get('incomplete_count', 0)}"); print(f"Findings    : {a.get('finding_count', 0)}"); print(f"Review      : {a.get('review_count', 0)}"); print(f"Executed    : {a.get('executed_files', 0)}"); print(f"Artifact    : {sp}"); return 0
        errors = validate(data, pid)
        if errors:
            print("[FAIL] File Upload Summary tidak memenuhi verify.")
            for e in errors: print(f"[FAIL] {e}")
            return 1
        data.setdefault("checklist", {})["status"] = "completed"; data["verified_at"] = now(); save_yaml(sp, data)
        raw = sp.read_bytes(); encoding_ok = not raw.startswith(b"\xef\xbb\xbf")
        try: raw.decode("utf-8")
        except UnicodeDecodeError: encoding_ok = False
        a = d(data.get("assessment")); print("[PASS] File Upload Summary memenuhi verify."); print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}"); print(f"[PASS] Project   : {pid}"); print(f"[PASS] Checklists: {a.get('checklists_total', 0)}"); print(f"[PASS] Completed : {a.get('completed_count', 0)}"); print(f"[PASS] Findings  : {a.get('finding_count', 0)}"); print(f"[PASS] Review    : {a.get('review_count', 0)}"); print(f"[PASS] Executed  : {a.get('executed_files', 0)}"); print(f"[PASS] Encoding  : {'UTF-8 tanpa BOM' if encoding_ok else 'INVALID'}"); print(f"[PASS] Artifact  : {sp}"); return 0 if encoding_ok else 1
    if args.command == "remove":
        if not sp.exists(): print("[INFO] File Upload Summary belum ada."); return 0
        sp.unlink(); print("[PASS] File Upload Summary berhasil dihapus."); print(f"FILE : {sp}"); return 0
    print("BrebesKab-CSIRT-Tools File Upload Summary")
    print(f"Version : {VERSION}")
    print(f"Usage   : python {SCRIPT_NAME} init|generate|show|verify|status|remove|version")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[FAIL] Dibatalkan oleh operator.")
        raise SystemExit(130)
    except Exception as exc:
        print(f"[FAIL] Unexpected error: {exc}")
        raise SystemExit(1)
