#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Checklist 10-002 - File Upload Execution / Extension Acceptance

Purpose
-------
Validate the discovered file-upload surfaces from 10-001 by uploading
BENIGN test artifacts with different extensions and observing whether the
application accepts, rejects, renames, stores, or exposes them.

This script does NOT execute uploaded files.

Safety boundary
---------------
- Same-origin only.
- Uses candidates produced by discovery.py; it does not crawl for new
  candidates.
- Reuses the existing authenticated session artifact.
- Multipart POST is limited to discovered upload candidates.
- Test artifacts are generated locally and are benign.
- PHP test content is marker-only and is never requested for execution.
- Executable formats are never executed.
- No webshell, reverse shell, persistence, command execution, callback,
  credential collection, overwrite, or deletion is performed.
- Automatic findings are conservative. Acceptance of an extension is
  recorded as evidence and normally requires review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import yaml

try:
    SCRIPTS_DIR = Path(__file__).resolve().parents[1]
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    from context import load_active_context, get_active_project_path
    from secrets import decrypt
except ImportError as exc:
    raise SystemExit(f"[ERROR] Modul context/secrets tidak dapat dimuat: {exc}")


SCRIPT_NAME = "execution.py"
SCRIPT_VERSION = "1.0.3"
CHECKLIST_ID = "10-002"
CHECKLIST_NAME = "File Upload Extension Validation"
PHASE_NAME = "10 File Upload"
SCHEMA_VERSION = "1.0"

DEFAULT_TIMEOUT = 20
DEFAULT_MAX_BODY = 16000
USER_AGENT = "BrebesKab-CSIRT-Tools/10-002-file-upload-validation"

# The test set is intentionally limited to acceptance/handling checks.
TEST_MATRIX: List[Dict[str, Any]] = [
    {
        "id": "normal-txt",
        "extension": ".txt",
        "category": "normal",
        "mime": "text/plain",
        "content_type": "text/plain",
        "payload": b"BREBES_UPLOAD_TEST_TEXT\n",
    },
    {
        "id": "normal-jpg",
        "extension": ".jpg",
        "category": "normal",
        "mime": "image/jpeg",
        "content_type": "image/jpeg",
        # Not an image parser exploit; only a benign JPEG-like marker.
        "payload": b"\xff\xd8\xff\xe0BREBES_UPLOAD_TEST_JPEG\xff\xd9",
    },
    {
        "id": "php",
        "extension": ".php",
        "category": "php",
        "mime": "application/x-php",
        "content_type": "application/x-php",
        "payload": b'<?php echo "BREBES_UPLOAD_PHP_MARKER"; ?>\n',
    },
    {
        "id": "phtml",
        "extension": ".phtml",
        "category": "php",
        "mime": "application/x-httpd-php",
        "content_type": "application/x-httpd-php",
        "payload": b'<?php echo "BREBES_UPLOAD_PHTML_MARKER"; ?>\n',
    },
    {
        "id": "php5",
        "extension": ".php5",
        "category": "php",
        "mime": "application/x-httpd-php",
        "content_type": "application/x-httpd-php",
        "payload": b'<?php echo "BREBES_UPLOAD_PHP5_MARKER"; ?>\n',
    },
    {
        "id": "phar",
        "extension": ".phar",
        "category": "php_related",
        "mime": "application/octet-stream",
        "content_type": "application/octet-stream",
        "payload": b"BREBES_UPLOAD_PHAR_MARKER\n",
    },
    {
        "id": "double-jpg-php",
        "extension": ".jpg.php",
        "category": "double_extension",
        "mime": "application/x-php",
        "content_type": "application/x-php",
        "payload": b'<?php echo "BREBES_UPLOAD_DOUBLE_EXTENSION_MARKER"; ?>\n',
    },
    {
        "id": "double-txt-php",
        "extension": ".txt.php",
        "category": "double_extension",
        "mime": "application/x-php",
        "content_type": "application/x-php",
        "payload": b'<?php echo "BREBES_UPLOAD_DOUBLE_EXTENSION_MARKER_2"; ?>\n',
    },
    {
        "id": "exe",
        "extension": ".exe",
        "category": "windows_executable",
        "mime": "application/vnd.microsoft.portable-executable",
        "content_type": "application/vnd.microsoft.portable-executable",
        "payload": b"MZBREBES_UPLOAD_EXE_MARKER\n",
    },
    {
        "id": "dll",
        "extension": ".dll",
        "category": "windows_binary",
        "mime": "application/octet-stream",
        "content_type": "application/octet-stream",
        "payload": b"MZBREBES_UPLOAD_DLL_MARKER\n",
    },
    {
        "id": "elf",
        "extension": ".elf",
        "category": "linux_executable",
        "mime": "application/x-elf",
        "content_type": "application/x-elf",
        "payload": b"\x7fELFBREBES_UPLOAD_ELF_MARKER\n",
    },
    {
        "id": "bin",
        "extension": ".bin",
        "category": "binary",
        "mime": "application/octet-stream",
        "content_type": "application/octet-stream",
        "payload": b"BREBES_UPLOAD_BINARY_MARKER\n",
    },
    {
        "id": "sh",
        "extension": ".sh",
        "category": "script",
        "mime": "text/x-shellscript",
        "content_type": "text/x-shellscript",
        "payload": b"#!/bin/sh\nprintf '%s\\n' 'BREBES_UPLOAD_SH_MARKER'\n",
    },
    {
        "id": "cgi",
        "extension": ".cgi",
        "category": "script",
        "mime": "application/x-httpd-cgi",
        "content_type": "application/x-httpd-cgi",
        "payload": b"BREBES_UPLOAD_CGI_MARKER\n",
    },
    {
        "id": "zip",
        "extension": ".zip",
        "category": "archive",
        "mime": "application/zip",
        "content_type": "application/zip",
        "payload": b"PK\x03\x04BREBES_UPLOAD_ZIP_MARKER",
    },
]


class ExecutionError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def active_context() -> Any:
    return load_active_context()


def project_root() -> Path:
    return Path(get_active_project_path()).resolve()


def project_context() -> Tuple[Any, Path, str]:
    context = active_context()
    project_path = project_root()
    project_id = str(getattr(context, "project_id", "") or "").strip()
    if not project_id:
        raise ExecutionError("Project ID aktif tidak ditemukan.")
    return context, project_path, project_id


def execution_dir(project_path: Path) -> Path:
    return project_path / "10-file-upload" / "execution"


def artifact_path(project_path: Path) -> Path:
    return execution_dir(project_path) / "execution.yaml"


def evidence_dir(project_path: Path) -> Path:
    return execution_dir(project_path) / "evidence"


def evidence_path(project_path: Path) -> Path:
    return evidence_dir(project_path) / "execution-evidence.json"


def discovery_path(project_path: Path) -> Path:
    return project_path / "10-file-upload" / "discovery" / "discovery.yaml"


def discovery_evidence_path(project_path: Path) -> Path:
    return project_path / "10-file-upload" / "discovery" / "evidence" / "discovery-evidence.json"


def session_path(project_path: Path) -> Path:
    return project_path / "07-authentication" / "session" / "session.yaml"


def load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as fh:
        return yaml.safe_load(fh)


def save_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        yaml.safe_dump(data, fh, allow_unicode=True, sort_keys=False)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def same_origin(url: str, target_url: str) -> bool:
    a = urlparse(url)
    b = urlparse(target_url)
    return (
        (a.scheme or "").lower() == (b.scheme or "").lower()
        and (a.hostname or "").lower() == (b.hostname or "").lower()
        and (a.port or default_port(a.scheme)) == (b.port or default_port(b.scheme))
    )


def default_port(scheme: str) -> int:
    return 443 if str(scheme).lower() == "https" else 80


def redacted_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    sensitive = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
    return {
        str(k): "[REDACTED]" if str(k).lower() in sensitive else str(v)
        for k, v in headers.items()
    }


def response_info(response: requests.Response) -> Dict[str, Any]:
    body = response.content
    sample = body[:DEFAULT_MAX_BODY]
    try:
        text = sample.decode(response.encoding or "utf-8", errors="replace")
    except Exception:
        text = sample.decode("utf-8", errors="replace")

    return {
        "status": response.status_code,
        "reason": response.reason,
        "url": response.url,
        "content_type": response.headers.get("Content-Type", ""),
        "content_length": len(body),
        "body_sha256": sha256_bytes(body),
        "body_sample": text,
        "location": response.headers.get("Location", ""),
        "content_disposition": response.headers.get("Content-Disposition", ""),
        "headers": redacted_headers(dict(response.headers)),
    }


def load_discovery(project_path: Path) -> Dict[str, Any]:
    path = discovery_path(project_path)
    if not path.exists():
        raise ExecutionError(
            f"Discovery artifact tidak ditemukan: {path}\n"
            "Jalankan discovery.py terlebih dahulu."
        )

    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ExecutionError("discovery.yaml bukan object YAML yang valid.")

    checklist = data.get("checklist") or {}
    if str(checklist.get("id", "")) != "10-001":
        raise ExecutionError("Discovery checklist_id bukan 10-001.")

    results = data.get("results") or {}
    if results.get("upload_performed") is not False:
        raise ExecutionError("Discovery artifact tidak valid: upload_performed bukan false.")

    candidates = data.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ExecutionError("Tidak ada candidate upload dari discovery.py.")

    return data


def load_session_data(project_path: Path) -> Dict[str, Any]:
    path = session_path(project_path)
    if not path.exists():
        raise ExecutionError(f"Session artifact tidak ditemukan: {path}")
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ExecutionError("session.yaml bukan object YAML yang valid.")
    return data


def decrypt_session_candidates(session_data: Dict[str, Any], project_id: str, target_url: str) -> List[Dict[str, str]]:
    records = session_data.get("sessions")
    if not isinstance(records, list):
        raise ExecutionError("Field sessions pada session.yaml tidak valid.")

    target_host = (urlparse(target_url).hostname or "").lower()
    usable: List[Dict[str, str]] = []

    for record in records:
        if not isinstance(record, dict):
            continue

        outcome = str(
            record.get("authentication_outcome")
            or record.get("outcome")
            or ""
        ).upper()
        status = str(record.get("status") or "").lower()

        if outcome and outcome != "SUCCESS":
            continue
        if status and status not in {"completed", "active", "valid", "success"}:
            continue

        target = record.get("target") or {}
        record_url = str(target.get("url") or "").strip()
        if record_url:
            record_host = (urlparse(record_url).hostname or "").lower()
            if record_host and record_host != target_host:
                continue

        auth = record.get("authentication") or {}
        if not isinstance(auth, dict):
            continue

        name = str(auth.get("name") or "").strip()
        encrypted = str(auth.get("value_encrypted") or "").strip()
        auth_type = str(auth.get("type") or "cookie").lower()
        header_name = str(auth.get("header_name") or "Authorization")

        if not name or not encrypted:
            continue

        try:
            value = decrypt(encrypted, project_id=project_id)
        except Exception:
            continue

        usable.append(
            {
                "name": name,
                "value": value,
                "type": auth_type,
                "header_name": header_name,
                "path": str(auth.get("path") or "/"),
            }
        )

    if not usable:
        raise ExecutionError(
            "Tidak ditemukan authenticated session SUCCESS yang dapat digunakan "
            "untuk target discovery."
        )

    return usable


def build_session(
    session_records: List[Dict[str, str]],
    target_url: str,
) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    target_host = (urlparse(target_url).hostname or "").lower()

    for item in session_records:
        if item.get("type") == "cookie":
            session.cookies.set(
                item["name"],
                item["value"],
                domain=target_host or None,
                path=item.get("path") or "/",
            )
        elif item.get("type") in {"header", "authorization", "bearer"}:
            session.headers[item.get("header_name") or "Authorization"] = item["value"]

    return session


def candidate_identity(candidate: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(candidate.get("page_url") or ""),
        str(candidate.get("action_url") or ""),
        str(candidate.get("method") or "").upper(),
    )


def usable_candidates(
    discovery: Dict[str, Any],
    target_url: str,
) -> List[Dict[str, Any]]:
    candidates = discovery.get("candidates") or []
    result: List[Dict[str, Any]] = []
    seen = set()

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue

        action = str(candidate.get("action_url") or "").strip()
        page = str(candidate.get("page_url") or "").strip()
        method = str(candidate.get("method") or "").upper()

        if not action or not page:
            continue
        if not same_origin(action, target_url):
            continue
        if method not in {"POST", "PUT", "PATCH", "UNKNOWN", ""}:
            continue

        file_inputs = candidate.get("file_inputs") or []
        has_file_input = any(
            isinstance(item, dict) and str(item.get("name") or "").strip()
            for item in file_inputs
        )

        # Browser/JS-only signals are not enough to construct a safe multipart
        # request because their field name is unknown. Keep them in evidence,
        # but only execute candidates with a known file input.
        if not has_file_input:
            continue

        key = candidate_identity(candidate)
        if key in seen:
            continue
        seen.add(key)
        result.append(candidate)

    return result


def choose_field(candidate: Dict[str, Any]) -> Optional[str]:
    for item in candidate.get("file_inputs") or []:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            if name:
                return name
    return None


def choose_text_fields(candidate: Dict[str, Any]) -> Dict[str, str]:
    """
    Provide only benign defaults for required/non-file form fields when they
    are explicitly present in discovery evidence. Unknown fields are not
    guessed. The upload candidate can still be tested with only the file part.
    """
    fields: Dict[str, str] = {}
    for item in candidate.get("inputs") or candidate.get("form_inputs") or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        input_type = str(item.get("type") or "text").lower()
        value = item.get("value")
        if not name or input_type == "file":
            continue
        if value is not None and str(value) != "":
            fields[name] = str(value)
    return fields


def make_test_file(tmp: Path, test: Dict[str, Any]) -> Path:
    filename = f"brebes-upload-{test['id']}{test['extension']}"
    path = tmp / filename
    path.write_bytes(test["payload"])
    return path


def infer_accept(candidate: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    for item in candidate.get("file_inputs") or []:
        if not isinstance(item, dict):
            continue
        accept = item.get("accept")
        if isinstance(accept, str):
            values.extend(
                part.strip().lower()
                for part in accept.split(",")
                if part.strip()
            )
    return sorted(set(values))


def upload_one(
    session: requests.Session,
    candidate: Dict[str, Any],
    test: Dict[str, Any],
    timeout: int,
    tmp: Path,
) -> Dict[str, Any]:
    action_url = str(candidate["action_url"])
    page_url = str(candidate["page_url"])
    field_name = choose_field(candidate)

    if not field_name:
        return {
            "status": "skipped",
            "reason": "file_field_name_not_known",
        }

    if not same_origin(action_url, page_url):
        return {
            "status": "skipped",
            "reason": "candidate_not_same_origin",
        }

    path = make_test_file(tmp, test)
    content = path.read_bytes()

    print(f"[FILE] Dummy file      : {path}", flush=True)
    print(f"[FILE] Filename         : {path.name}", flush=True)
    print(f"[FILE] Extension        : {test["extension"]}", flush=True)
    print(f"[FILE] Category         : {test["category"]}", flush=True)
    print(f"[FILE] MIME             : {test["mime"]}", flush=True)
    print(f"[FILE] Size             : {len(content)} bytes", flush=True)
    print(f"[FILE] SHA256           : {sha256_bytes(content)}", flush=True)

    text_fields = choose_text_fields(candidate)

    # requests will build multipart/form-data. This is the only write request
    # performed by this script.
    files = {
        field_name: (
            path.name,
            content,
            test["content_type"],
        )
    }

    print(f"[UPLOAD] POST           : {action_url}", flush=True)
    print(f"[UPLOAD] Field            : {field_name}", flush=True)
    print(f"[UPLOAD] File             : {path.name}", flush=True)

    try:
        response = session.post(
            action_url,
            data=text_fields,
            files=files,
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return {
            "status": "request_error",
            "error": f"{type(exc).__name__}: {exc}",
            "request": {
                "method": "POST",
                "url": action_url,
                "field_name": field_name,
                "filename": path.name,
                "sha256": sha256_bytes(content),
            },
        }

    info = response_info(response)

    accepted = 200 <= response.status_code < 400
    blocked = response.status_code in {400, 401, 403, 405, 406, 409, 415, 422}

    return {
        "status": "completed",
        "accepted_indicator": accepted,
        "blocked_indicator": blocked,
        "request": {
            "method": "POST",
            "url": action_url,
            "page_url": page_url,
            "field_name": field_name,
            "filename": path.name,
            "extension": test["extension"],
            "category": test["category"],
            "declared_mime": test["mime"],
            "content_type": test["content_type"],
            "size_bytes": len(content),
            "sha256": sha256_bytes(content),
        },
        "response": info,
        "interpretation": classify_response(response, test),
    }


def classify_response(
    response: requests.Response,
    test: Dict[str, Any],
) -> Dict[str, Any]:
    status = response.status_code
    location = response.headers.get("Location", "")
    body = response.content[:DEFAULT_MAX_BODY].decode(
        response.encoding or "utf-8",
        errors="replace",
    )

    markers = [
        "upload",
        "uploaded",
        "berhasil",
        "success",
        "sukses",
        "invalid",
        "tidak diizinkan",
        "not allowed",
        "file type",
        "filetype",
        "extension",
        "ekstensi",
        "format",
    ]

    matched = [m for m in markers if m.lower() in body.lower()]

    if status in {400, 403, 406, 415, 422}:
        disposition = "rejected_or_blocked"
    elif 200 <= status < 400:
        disposition = "accepted_or_processed"
    elif status in {401, 302, 303, 307, 308}:
        disposition = "authentication_or_redirect"
    else:
        disposition = "server_error_or_unknown"

    return {
        "disposition": disposition,
        "http_status": status,
        "redirect": bool(location),
        "response_keyword_signals": matched,
        "automatic_finding": False,
        "requires_review": bool(
            test["category"] in {
                "php",
                "php_related",
                "double_extension",
                "windows_executable",
                "windows_binary",
                "linux_executable",
                "binary",
                "script",
            }
            and 200 <= status < 400
        ),
        "note": (
            "Acceptance is evidence of extension handling only; it is not "
            "automatically classified as a vulnerability."
        ),
    }


def summarize(results: List[Dict[str, Any]]) -> Dict[str, int]:
    completed = [x for x in results if x.get("status") == "completed"]
    accepted = [
        x for x in completed if x.get("accepted_indicator") is True
    ]
    blocked = [
        x for x in completed if x.get("blocked_indicator") is True
    ]
    request_errors = [x for x in results if x.get("status") == "request_error"]
    review = [
        x for x in results
        if (x.get("interpretation") or {}).get("requires_review") is True
    ]

    return {
        "tests": len(results),
        "completed": len(completed),
        "accepted_indicators": len(accepted),
        "blocked_indicators": len(blocked),
        "request_errors": len(request_errors),
        "requires_review": len(review),
        "findings": 0,
        "executed_files": 0,
        "automatic_execution": 0,
    }


def cmd_version(_: argparse.Namespace) -> int:
    print(f"BrebesKab-CSIRT-Tools {SCRIPT_NAME}")
    print(f"Version   : {SCRIPT_VERSION}")
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Phase     : {PHASE_NAME}")
    return 0


def cmd_init(_: argparse.Namespace) -> int:
    _, project_path, project_id = project_context()
    discovery = load_discovery(project_path)
    target = str((discovery.get("target") or {}).get("url") or "").strip()

    if not target:
        raise ExecutionError("Target URL tidak ditemukan di discovery.yaml.")

    session_data = load_session_data(project_path)
    session_records = decrypt_session_candidates(session_data, project_id, target)
    candidates = usable_candidates(discovery, target)

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": SCRIPT_NAME,
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "status": "initialized",
        },
        "target": {
            "application": project_id,
            "url": target,
        },
        "sources": {
            "discovery": str(discovery_path(project_path)),
            "discovery_evidence": str(discovery_evidence_path(project_path)),
            "session": str(session_path(project_path)),
            "session_records_available": len(session_records),
        },
        "methodology": {
            "source_candidates_only": True,
            "same_origin_only": True,
            "authenticated_session_required": True,
            "multipart_post_allowed": True,
            "file_execution": False,
            "uploaded_file_execution": False,
            "webshell": False,
            "reverse_shell": False,
            "command_execution": False,
            "persistence": False,
            "external_callbacks": False,
            "automatic_finding": False,
            "forensic_evidence_preserved": True,
        },
        "toolchain": {
            "mandatory": ["Python", "requests", "PyYAML"],
            "external_scanners": [],
            "not_required": [
                "Nmap",
                "ffuf",
                "Gobuster",
                "Nuclei",
                "sqlmap",
                "ZAP",
                "Hydra",
                "Playwright",
                "Chromium",
            ],
        },
        "test_matrix": [
            {
                "id": x["id"],
                "extension": x["extension"],
                "category": x["category"],
                "mime": x["mime"],
            }
            for x in TEST_MATRIX
        ],
        "results": {
            "status": "initialized",
            "discovery_candidates": len(discovery.get("candidates") or []),
            "executable_candidates": len(candidates),
            "tests": 0,
            "completed": 0,
            "accepted_indicators": 0,
            "blocked_indicators": 0,
            "request_errors": 0,
            "requires_review": 0,
            "findings": 0,
            "executed_files": 0,
            "automatic_execution": 0,
        },
        "notes": [
            "Candidate discovery is performed only by 10-001 discovery.py.",
            "Only same-origin candidates with a known file field are executed.",
            "Test files are benign and generated locally.",
            "PHP files contain only marker output and are never requested for execution.",
            "Executable files are never executed.",
            "Acceptance does not by itself prove a vulnerability.",
        ],
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }

    save_yaml(artifact_path(project_path), artifact)

    print("[PASS] File Upload Execution/Validation init selesai.")
    print(f"[PASS] Project              : {project_id}")
    print(f"[PASS] Target               : {target}")
    print(f"[PASS] Discovery candidates : {len(discovery.get('candidates') or [])}")
    print(f"[PASS] Executable candidates: {len(candidates)}")
    print(f"[PASS] Session records      : {len(session_records)}")
    print(f"[PASS] Test matrix          : {len(TEST_MATRIX)}")
    print(f"[PASS] Artifact             : {artifact_path(project_path)}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    _, project_path, project_id = project_context()
    discovery = load_discovery(project_path)
    target = str((discovery.get("target") or {}).get("url") or "").strip()
    if not target:
        raise ExecutionError("Target URL tidak ditemukan.")

    session_data = load_session_data(project_path)
    session_records = decrypt_session_candidates(session_data, project_id, target)
    candidates = usable_candidates(discovery, target)

    if args.candidate:
        selected = []
        for index in args.candidate:
            if index < 1 or index > len(candidates):
                raise ExecutionError(
                    f"Candidate index {index} di luar range 1..{len(candidates)}."
                )
            selected.append(candidates[index - 1])
        candidates = selected

    if not candidates:
        raise ExecutionError("Tidak ada candidate yang aman untuk dieksekusi.")

    selected_tests = TEST_MATRIX
    if args.extensions:
        wanted = {
            x.strip().lower()
            for x in args.extensions.split(",")
            if x.strip()
        }
        selected_tests = [
            item for item in TEST_MATRIX
            if item["extension"].lower() in wanted
            or item["id"].lower() in wanted
        ]
        if not selected_tests:
            raise ExecutionError(
                "Tidak ada extension/id test yang cocok dengan --extensions."
            )

    http = build_session(session_records, target)

    results: List[Dict[str, Any]] = []
    candidate_results: List[Dict[str, Any]] = []

    print(f"[INFO] Project     : {project_id}")
    print(f"[INFO] Target      : {target}")
    print(f"[INFO] Candidates  : {len(candidates)}")
    print(f"[INFO] Test cases  : {len(selected_tests)}")
    print("[INFO] Uploaded files will NOT be executed.")

    with tempfile.TemporaryDirectory(prefix="brebes-fileupload-") as temp_dir:
        tmp = Path(temp_dir)

        for cidx, candidate in enumerate(candidates, 1):
            field = choose_field(candidate)
            print(
                f"\n[STEP] Candidate {cidx}/{len(candidates)} "
                f"{candidate.get('action_url')}"
            )
            print(f"[INFO] File field : {field or '-'}")
            print(f"[INFO] Accept     : {', '.join(infer_accept(candidate)) or '-'}")

            candidate_items: List[Dict[str, Any]] = []

            for tidx, test in enumerate(selected_tests, 1):
                print(
                    f"[TEST] {tidx}/{len(selected_tests)} "
                    f"{test['extension']} ({test['category']})",
                    flush=True,
                )

                item = upload_one(
                    http,
                    candidate,
                    test,
                    args.timeout,
                    tmp,
                )

                item["candidate_index"] = cidx
                item["test"] = {
                    "id": test["id"],
                    "extension": test["extension"],
                    "category": test["category"],
                    "declared_mime": test["mime"],
                }
                candidate_items.append(item)
                results.append(item)

                if item.get("status") == "completed":
                    response = item.get("response") or {}
                    print(
                        f"[INFO] HTTP {response.get('status')} "
                        f"-> {(item.get('interpretation') or {}).get('disposition', '-')}"
                    )
                else:
                    print(
                        f"[INFO] {item.get('status')} "
                        f"{item.get('error', item.get('reason', ''))}"
                    )

            candidate_results.append(
                {
                    "candidate_index": cidx,
                    "page_url": candidate.get("page_url"),
                    "action_url": candidate.get("action_url"),
                    "method": candidate.get("method"),
                    "file_field": field,
                    "tests": candidate_items,
                }
            )

    summary = summarize(results)

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": SCRIPT_NAME,
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "status": "completed",
        },
        "target": {
            "application": project_id,
            "url": target,
        },
        "sources": {
            "discovery": str(discovery_path(project_path)),
            "discovery_evidence": str(discovery_evidence_path(project_path)),
            "session": str(session_path(project_path)),
        },
        "methodology": {
            "source_candidates_only": True,
            "same_origin_only": True,
            "authenticated_session_required": True,
            "multipart_post_performed": True,
            "file_execution": False,
            "uploaded_file_execution": False,
            "webshell": False,
            "reverse_shell": False,
            "command_execution": False,
            "persistence": False,
            "external_callbacks": False,
            "automatic_finding": False,
            "forensic_evidence_preserved": True,
        },
        "test_matrix": [
            {
                "id": x["id"],
                "extension": x["extension"],
                "category": x["category"],
                "mime": x["mime"],
            }
            for x in selected_tests
        ],
        "results": {
            **summary,
            "candidate_count": len(candidates),
        },
        "candidates": candidate_results,
        "notes": [
            "Execution means upload/validation execution stage, not execution of uploaded files.",
            "No uploaded file was executed by this tool.",
            "Acceptance is not automatically classified as a vulnerability.",
            "Review is required for accepted dangerous/executable extensions.",
        ],
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }

    save_yaml(artifact_path(project_path), artifact)

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "checklist_id": CHECKLIST_ID,
        "target": target,
        "results": summary,
        "candidates": candidate_results,
        "created_at": utc_now(),
    }
    save_json(evidence_path(project_path), evidence)

    print("\n[PASS] File Upload validation selesai.")
    print(f"[PASS] Candidates           : {len(candidates)}")
    print(f"[PASS] Tests                : {summary['tests']}")
    print(f"[PASS] Completed            : {summary['completed']}")
    print(f"[PASS] Accepted indicators : {summary['accepted_indicators']}")
    print(f"[PASS] Blocked indicators  : {summary['blocked_indicators']}")
    print(f"[PASS] Request errors      : {summary['request_errors']}")
    print(f"[PASS] Manual review       : {summary['requires_review']}")
    print("[PASS] Findings            : 0")
    print("[PASS] Files executed      : 0")
    print(f"[PASS] Artifact            : {artifact_path(project_path)}")
    print(f"[PASS] Evidence            : {evidence_path(project_path)}")
    return 0


def cmd_show(_: argparse.Namespace) -> int:
    _, project_path, _ = project_context()
    path = artifact_path(project_path)
    if not path.exists():
        print("[INFO] Artifact execution.py belum ada.")
        return 0

    data = load_yaml(path)
    results = data.get("results") or {}
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Version   : {SCRIPT_VERSION}")
    print(f"Status    : {(data.get('checklist') or {}).get('status', '-')}")
    print(f"Candidates: {results.get('candidate_count', results.get('executable_candidates', 0))}")
    print(f"Tests     : {results.get('tests', 0)}")
    print(f"Accepted  : {results.get('accepted_indicators', 0)}")
    print(f"Blocked   : {results.get('blocked_indicators', 0)}")
    print(f"Review    : {results.get('requires_review', 0)}")
    print(f"Findings  : {results.get('findings', 0)}")
    print(f"Executed  : {results.get('executed_files', 0)}")
    print(f"Artifact  : {path}")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    return cmd_show(_)


def cmd_verify(_: argparse.Namespace) -> int:
    _, project_path, project_id = project_context()
    path = artifact_path(project_path)
    evidence = evidence_path(project_path)

    errors: List[str] = []

    if not path.exists():
        errors.append(f"Artifact tidak ditemukan: {path}")
    else:
        try:
            data = load_yaml(path)
        except Exception as exc:
            errors.append(f"Artifact tidak dapat dibaca: {exc}")
            data = {}

        if data.get("project_id") != project_id:
            errors.append("project_id tidak sesuai.")

        if (data.get("checklist") or {}).get("id") != CHECKLIST_ID:
            errors.append("checklist.id tidak sesuai.")

        methodology = data.get("methodology") or {}
        for key in (
            "source_candidates_only",
            "same_origin_only",
            "authenticated_session_required",
        ):
            if methodology.get(key) is not True:
                errors.append(f"methodology.{key} harus true.")

        for key in (
            "file_execution",
            "uploaded_file_execution",
            "webshell",
            "reverse_shell",
            "command_execution",
            "persistence",
            "external_callbacks",
            "automatic_finding",
        ):
            if methodology.get(key) is not False:
                errors.append(f"methodology.{key} harus false.")

        results = data.get("results") or {}
        if results.get("findings") != 0:
            errors.append("findings harus 0.")
        if results.get("executed_files") != 0:
            errors.append("executed_files harus 0.")
        if results.get("automatic_execution") != 0:
            errors.append("automatic_execution harus 0.")

        for key in (
            "tests",
            "completed",
            "accepted_indicators",
            "blocked_indicators",
            "request_errors",
            "requires_review",
            "findings",
            "executed_files",
            "automatic_execution",
        ):
            if not isinstance(results.get(key), int) or results.get(key) < 0:
                errors.append(f"results.{key} harus integer >= 0.")

    if not evidence.exists():
        errors.append(f"Evidence tidak ditemukan: {evidence}")
    else:
        try:
            ev = load_yaml(evidence) if evidence.suffix in {".yaml", ".yml"} else json.loads(
                evidence.read_text(encoding="utf-8-sig")
            )
            if ev.get("project_id") != project_id:
                errors.append("Evidence project_id tidak sesuai.")
            if ev.get("checklist_id") != CHECKLIST_ID:
                errors.append("Evidence checklist_id tidak sesuai.")
        except Exception as exc:
            errors.append(f"Evidence tidak dapat dibaca: {exc}")

    if errors:
        print("[FAIL] File Upload validation tidak memenuhi verify.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] File Upload validation memenuhi verify.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {project_id}")
    print(f"[PASS] Artifact  : {path}")
    print("[PASS] Uploaded files executed : 0")
    print("[PASS] Automatic findings      : 0")
    print("[PASS] Encoding                : UTF-8 tanpa BOM")
    return 0


def cmd_remove(_: argparse.Namespace) -> int:
    _, project_path, _ = project_context()
    directory = execution_dir(project_path)

    if not directory.exists():
        print("[INFO] Artifact execution.py belum ada.")
        return 0

    import shutil
    shutil.rmtree(directory)
    print("[PASS] Artifact File Upload execution dihapus.")
    print(f"[PASS] Directory: {directory}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools File Upload Validation (10-002)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("version")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("init")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("run")
    p.add_argument(
        "--candidate",
        type=int,
        action="append",
        help="Candidate number from discovery; repeat for multiple candidates.",
    )
    p.add_argument(
        "--extensions",
        help="Comma-separated extensions or test IDs, e.g. .php,.exe,.elf",
    )
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("show")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("verify")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("remove")
    p.set_defaults(func=cmd_remove)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("[FAIL] Dibatalkan oleh pengguna.")
        return 130
    except ExecutionError as exc:
        print(f"[FAIL] {exc}")
        return 1
    except Exception as exc:
        print(f"[FAIL] {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
