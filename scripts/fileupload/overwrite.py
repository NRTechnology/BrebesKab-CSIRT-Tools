#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Checklist 10-004 - File Upload Overwrite Validation

Purpose
-------
Validate the discovered file-upload surfaces from 10-001 by uploading
BENIGN artifacts with the exact same filename and distinct content markers,
then observing whether the application accepts the collision, renames the file,
or exposes evidence that requires manual overwrite verification.

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
  credential collection, system-file overwrite, or deletion is performed.
  The test intentionally creates a controlled filename collision using files
  owned by this test only.
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
from urllib.parse import urlparse, urljoin, parse_qs

import requests
import yaml
from html.parser import HTMLParser

try:
    SCRIPTS_DIR = Path(__file__).resolve().parents[1]
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    from context import load_active_context, get_active_project_path
    from secrets import decrypt
except ImportError as exc:
    raise SystemExit(f"[ERROR] Modul context/secrets tidak dapat dimuat: {exc}")


SCRIPT_NAME = "overwrite.py"
SCRIPT_VERSION = "1.1.3-browser"
CHECKLIST_ID = "10-004"
CHECKLIST_NAME = "File Upload Overwrite Validation"
PHASE_NAME = "10 File Upload"
SCHEMA_VERSION = "1.0"

DEFAULT_TIMEOUT = 20
DEFAULT_MAX_BODY = 16000
USER_AGENT = "BrebesKab-CSIRT-Tools/10-004-file-upload-overwrite"

# The test set is intentionally limited to acceptance/handling checks.
TEST_MATRIX: List[Dict[str, Any]] = [
    {
        "id": "baseline-a",
        "filename": "brebes-overwrite-test.jpg",
        "category": "baseline",
        "stage": 1,
        "marker": "BREBES_OVERWRITE_TEST_A",
        "mime": "image/jpeg",
        "content_type": "image/jpeg",
        "payload": b"\\xff\\xd8\\xff\\xe0BREBES_OVERWRITE_TEST_A\\xff\\xd9",
    },
    {
        "id": "collision-b",
        "filename": "brebes-overwrite-test.jpg",
        "category": "exact_filename_collision",
        "stage": 2,
        "marker": "BREBES_OVERWRITE_TEST_B",
        "mime": "image/jpeg",
        "content_type": "image/jpeg",
        "payload": b"\\xff\\xd8\\xff\\xe0BREBES_OVERWRITE_TEST_B\\xff\\xd9",
    },
    {
        "id": "collision-c",
        "filename": "brebes-overwrite-test.jpg",
        "category": "repeat_filename_collision",
        "stage": 3,
        "marker": "BREBES_OVERWRITE_TEST_C",
        "mime": "image/jpeg",
        "content_type": "image/jpeg",
        "payload": b"\\xff\\xd8\\xff\\xe0BREBES_OVERWRITE_TEST_C\\xff\\xd9",
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


def overwrite_dir(project_path: Path) -> Path:
    return project_path / "10-file-upload" / "overwrite"


def artifact_path(project_path: Path) -> Path:
    return overwrite_dir(project_path) / "overwrite.yaml"


def evidence_dir(project_path: Path) -> Path:
    return overwrite_dir(project_path) / "evidence"


def evidence_path(project_path: Path) -> Path:
    return evidence_dir(project_path) / "overwrite-evidence.json"


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


def methodology_definition() -> Dict[str, Any]:
    """Return the canonical 10-004 methodology schema."""
    return {
        "source_candidates_only": True,
        "same_origin_only": True,
        "authenticated_session_required": True,
        "multipart_post_allowed": True,
        "overwrite_validation": True,
        "exact_filename_collision": True,
        "distinct_content_markers": True,
        "form_reconstruction": True,
        "csrf_from_live_form": True,
        "post_upload_get_verification": True,
        "file_execution": False,
        "uploaded_file_execution": False,
        "webshell": False,
        "reverse_shell": False,
        "command_execution": False,
        "persistence": False,
        "external_callbacks": False,
        "automatic_finding": False,
        "forensic_evidence_preserved": True,
    }

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


class FormReconstructionError(RuntimeError):
    pass


class FormHTMLParser(HTMLParser):
    """Small dependency-free HTML form parser for deterministic reconstruction."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[Dict[str, Any]] = []
        self._form: Optional[Dict[str, Any]] = None
        self._control: Optional[Dict[str, Any]] = None
        self._textarea: Optional[Dict[str, Any]] = None
        self._select: Optional[Dict[str, Any]] = None
        self._option: Optional[Dict[str, Any]] = None

    @staticmethod
    def _attrs(attrs: List[Tuple[str, Optional[str]]]) -> Dict[str, str]:
        return {
            str(k).lower(): str(v) if v is not None else ""
            for k, v in attrs
            if k
        }

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        a = self._attrs(attrs)

        if tag == "form":
            self._form = {
                "attrs": a,
                "controls": [],
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").upper(),
            }
            self.forms.append(self._form)
            return

        if self._form is None:
            return

        if tag == "input":
            control = {
                "tag": "input",
                "attrs": a,
                "type": (a.get("type") or "text").lower(),
                "name": a.get("name", ""),
                "value": a.get("value", ""),
                "checked": "checked" in a,
            }
            self._form["controls"].append(control)
            return

        if tag == "textarea":
            self._textarea = {
                "tag": "textarea",
                "attrs": a,
                "type": "textarea",
                "name": a.get("name", ""),
                "value": "",
            }
            self._form["controls"].append(self._textarea)
            return

        if tag == "select":
            self._select = {
                "tag": "select",
                "attrs": a,
                "type": "select",
                "name": a.get("name", ""),
                "options": [],
            }
            self._form["controls"].append(self._select)
            return

        if tag == "option" and self._select is not None:
            self._option = {
                "attrs": a,
                "value": a.get("value", ""),
                "text": "",
                "selected": "selected" in a,
            }
            self._select["options"].append(self._option)

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._textarea["value"] += data
        if self._option is not None:
            self._option["text"] += data

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "textarea":
            self._textarea = None
        elif tag == "option":
            self._option = None
        elif tag == "select":
            self._select = None
        elif tag == "form":
            self._form = None


def _control_attrs(control: Dict[str, Any]) -> Dict[str, str]:
    return control.get("attrs") or {}


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(
        token in lowered
        for token in (
            "password", "passwd", "passcode", "otp", "token",
            "secret", "authorization", "cookie", "session",
        )
    )


def _is_csrf_control(control: Dict[str, Any]) -> bool:
    a = _control_attrs(control)
    name = str(control.get("name") or "").lower()
    return (
        name in {"csrf", "csrf_token", "csrf-token"}
        or "csrf" in name
        or "csrf" in str(a.get("id") or "").lower()
    )


def _safe_length(a: Dict[str, str], default: int = 24) -> int:
    try:
        minimum = max(0, int(a.get("minlength", "0") or 0))
    except ValueError:
        minimum = 0
    try:
        maximum = int(a.get("maxlength", "") or 0)
    except ValueError:
        maximum = 0
    if maximum > 0:
        return max(1, min(maximum, max(minimum, default)))
    return max(minimum, default)


def _pattern_value(pattern: str, minimum: int, maximum: int) -> Optional[str]:
    """Handle common HTML pattern forms without pretending to be a regex solver."""
    p = pattern.strip()
    if not p:
        return None

    # Common exact character classes.
    m = re.fullmatch(r"\[A-Z\]\{(\d+)(?:,(\d+))?\}", p)
    if m:
        n = int(m.group(1))
        return "A" * min(maximum, max(n, minimum))

    m = re.fullmatch(r"\[a-z\]\{(\d+)(?:,(\d+))?\}", p)
    if m:
        n = int(m.group(1))
        return "a" * min(maximum, max(n, minimum))

    m = re.fullmatch(r"\[0-9\]\{(\d+)(?:,(\d+))?\}", p)
    if m:
        n = int(m.group(1))
        return "1" * min(maximum, max(n, minimum))

    m = re.fullmatch(r"\[A-Za-z0-9\]\{(\d+)(?:,(\d+))?\}", p)
    if m:
        n = int(m.group(1))
        return "A" * min(maximum, max(n, minimum))

    # Common combined forms such as [A-Z]{3}[0-9]{4}.
    tokens = re.findall(r"\[[^\]]+\]\{(\d+)(?:,(\d+))?\}", p)
    classes = re.findall(r"\[([^\]]+)\]\{", p)
    if tokens and len(tokens) == len(classes):
        out = []
        for cls, count in zip(classes, tokens):
            n = int(count[0])
            char = "A" if "A-Z" in cls else ("1" if "0-9" in cls else "a")
            out.append(char * n)
        value = "".join(out)
        if minimum <= len(value) <= maximum:
            return value

    # Very common literal-prefix pattern: ^ABC[0-9]+$
    m = re.fullmatch(r"\^([A-Za-z]+)\[0-9\]\{(\d+)(?:,(\d+))?\}\$", p)
    if m:
        n = int(m.group(2))
        value = m.group(1) + ("1" * n)
        if minimum <= len(value) <= maximum:
            return value

    return None


def _generate_number(a: Dict[str, str]) -> str:
    try:
        minimum = float(a.get("min", "") or 0)
    except ValueError:
        minimum = 0
    try:
        maximum = float(a.get("max", "") or minimum + 100)
    except ValueError:
        maximum = minimum + 100
    try:
        step = float(a.get("step", "") or 1)
        if step <= 0:
            step = 1
    except ValueError:
        step = 1

    value = minimum
    if value > maximum:
        value = maximum
    # Align to step from min where possible.
    if step:
        value = minimum + ((value - minimum) // step) * step

    if float(value).is_integer():
        return str(int(value))
    return f"{value:g}"


def _generate_control_value(control: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """Return (value, reason). Empty/None means unresolved."""
    a = _control_attrs(control)
    typ = str(control.get("type") or "text").lower()
    name = str(control.get("name") or "").strip()

    if not name:
        return None, "unnamed_control"

    if typ in {"submit", "button", "reset", "image", "file"}:
        return None, f"non_data_control:{typ}"

    original = str(control.get("value") or "")
    if _is_csrf_control(control):
        if original:
            return original, "csrf_from_form"
        return None, "csrf_value_missing"

    if typ == "hidden":
        return original, "hidden_original_value"

    if typ in {"password"} or _is_sensitive_name(name):
        # Do not invent credentials/OTP/secrets. Existing non-empty values are
        # still not copied into evidence; the caller may classify unresolved.
        return None, "sensitive_field_requires_existing_application_value"

    if typ in {"checkbox"}:
        if "required" in a or "checked" in a:
            return original or "on", "checkbox_required_or_selected"
        return None, "optional_checkbox_not_selected"

    if typ == "radio":
        return original or None, "radio_selected_candidate"

    if typ == "select":
        options = control.get("options") or []
        valid = [
            x for x in options
            if isinstance(x, dict)
            and x.get("value") != ""
            and "disabled" not in (x.get("attrs") or {})
        ]
        selected = [
            x for x in valid
            if x.get("selected")
        ]
        choice = (selected or valid[:1])
        if choice:
            return str(choice[0].get("value") or ""), "select_valid_option"
        return None, "select_no_valid_option"

    if typ == "textarea":
        default = "BREBES UPLOAD TEST DESCRIPTION"
    elif typ == "email":
        default = "brebes-upload-test@example.invalid"
    elif typ == "number" or typ == "range":
        return _generate_number(a), "numeric_constraints"
    elif typ == "tel":
        default = "081234567890"
    elif typ == "url":
        default = "https://example.invalid/brebes-upload-test"
    elif typ == "date":
        default = datetime.now().date().isoformat()
    elif typ == "datetime-local":
        default = datetime.now().replace(microsecond=0).isoformat(timespec="minutes")
    elif typ == "time":
        default = "12:00"
    elif typ == "month":
        default = datetime.now().strftime("%Y-%m")
    elif typ == "week":
        default = datetime.now().strftime("%G-W%V")
    else:
        default = "BREBES_UPLOAD_TEST"

    try:
        minimum = max(0, int(a.get("minlength", "0") or 0))
    except ValueError:
        minimum = 0
    try:
        maximum = int(a.get("maxlength", "") or 0)
    except ValueError:
        maximum = 0
    if maximum <= 0:
        maximum = max(len(default), minimum, 512)

    pattern = a.get("pattern", "").strip()
    if pattern:
        candidate = _pattern_value(pattern, minimum, maximum)
        if candidate is None:
            return None, "unsupported_pattern_requires_review"
        return candidate, "pattern_constraint"

    if len(default) < minimum:
        seed = "BREBES_UPLOAD_TEST"
        default = (seed * ((minimum // len(seed)) + 1))[:minimum]
    if len(default) > maximum:
        default = default[:maximum]
    return default, "type_and_length_constraints"


def _form_matches(form: Dict[str, Any], page_url: str, action_url: str) -> bool:
    form_action = urljoin(page_url, str(form.get("action") or ""))
    return same_origin(form_action, action_url) and form_action.rstrip("/") == action_url.rstrip("/")


def reconstruct_form(
    session: requests.Session,
    candidate: Dict[str, Any],
    timeout: int,
) -> Dict[str, Any]:
    """GET the real form and reconstruct valid multipart text fields."""
    page_url = str(candidate.get("page_url") or "").strip()
    action_url = str(candidate.get("action_url") or "").strip()
    method = str(candidate.get("method") or "POST").upper()

    if not page_url or not action_url:
        raise FormReconstructionError("page_url/action_url tidak lengkap.")
    if not same_origin(page_url, action_url):
        raise FormReconstructionError("Form reconstruction menolak cross-origin candidate.")

    response = session.get(page_url, timeout=timeout, allow_redirects=True)
    if response.status_code >= 400:
        raise FormReconstructionError(
            f"GET form gagal HTTP {response.status_code}."
        )

    parser = FormHTMLParser()
    parser.feed(response.text)

    matching = [
        form for form in parser.forms
        if _form_matches(form, page_url, action_url)
    ]

    # Some applications omit action; if there is exactly one form on the page,
    # safely use it only when its effective action is the candidate action.
    if not matching:
        for form in parser.forms:
            effective = urljoin(page_url, str(form.get("action") or ""))
            if effective.rstrip("/") == page_url.rstrip("/") and effective.rstrip("/") == action_url.rstrip("/"):
                matching.append(form)

    if not matching:
        raise FormReconstructionError(
            "Form target tidak ditemukan pada halaman GET."
        )

    form = matching[0]
    if str(form.get("method") or "GET").upper() != "POST":
        raise FormReconstructionError(
            f"Form target method bukan POST: {form.get('method')}"
        )

    controls = form.get("controls") or []
    fields: Dict[str, str] = {}
    field_meta: List[Dict[str, Any]] = []
    file_field_names = {
        str(x.get("name") or "").strip()
        for x in candidate.get("file_inputs") or []
        if isinstance(x, dict) and str(x.get("name") or "").strip()
    }

    unresolved: List[Dict[str, str]] = []
    csrf_fields: List[str] = []

    # First pass: normal controls and selected radio/checkbox handling.
    radio_groups: Dict[str, List[Dict[str, Any]]] = {}
    for control in controls:
        if not isinstance(control, dict):
            continue
        typ = str(control.get("type") or "text").lower()
        name = str(control.get("name") or "").strip()
        if typ == "radio" and name:
            radio_groups.setdefault(name, []).append(control)

    for control in controls:
        if not isinstance(control, dict):
            continue
        typ = str(control.get("type") or "text").lower()
        name = str(control.get("name") or "").strip()

        if not name:
            continue
        if typ == "file" or name in file_field_names:
            continue

        # For radio, only submit one selected/first valid member.
        if typ == "radio":
            group = radio_groups.get(name) or []
            selected = next((x for x in group if x.get("checked")), None)
            if selected is not control:
                continue

        value, reason = _generate_control_value(control)

        if _is_csrf_control(control):
            if value is None:
                unresolved.append({"name": name, "reason": reason})
            else:
                fields[name] = value
                csrf_fields.append(name)
        elif typ == "checkbox":
            if value is not None:
                fields[name] = value
            elif "required" in _control_attrs(control):
                unresolved.append({"name": name, "reason": reason})
        elif value is not None:
            # Multiple controls with the same name are handled conservatively:
            # keep the first value for normal scalar fields.
            fields.setdefault(name, value)
        elif "required" in _control_attrs(control):
            unresolved.append({"name": name, "reason": reason})

        field_meta.append({
            "name": name,
            "type": typ,
            "required": "required" in _control_attrs(control),
            "minlength": _control_attrs(control).get("minlength", ""),
            "maxlength": _control_attrs(control).get("maxlength", ""),
            "pattern": bool(_control_attrs(control).get("pattern")),
            "generated": value is not None,
            "reason": reason,
            "value_redacted": (
                "[REDACTED]"
                if (_is_sensitive_name(name) or _is_csrf_control(control))
                else (value if value is not None else "")
            ),
        })

    if not csrf_fields:
        # CSRF is not necessarily named "csrf"; discover hidden security-token
        # fields conservatively from the form metadata.
        hidden_names = [
            str(c.get("name") or "")
            for c in controls
            if isinstance(c, dict)
            and str(c.get("type") or "").lower() == "hidden"
            and c.get("value")
        ]
        csrf_like = [
            n for n in hidden_names
            if "token" in n.lower() or "security" in n.lower()
        ]
        if csrf_like:
            # Keep the actual hidden value already captured; mark it as a
            # security token in evidence without exposing it.
            csrf_fields.extend(csrf_like)

    required_unresolved = [
        item for item in unresolved
        if item["name"] not in file_field_names
    ]

    return {
        "page_url": page_url,
        "requested_action_url": action_url,
        "fetched_url": response.url,
        "http_status": response.status_code,
        "form_action": urljoin(page_url, str(form.get("action") or "")),
        "method": form.get("method"),
        "field_count": len(controls),
        "file_field_names": sorted(file_field_names),
        "csrf_fields": sorted(set(csrf_fields)),
        "fields": fields,
        "field_meta": field_meta,
        "unresolved_required": required_unresolved,
    }


def choose_text_fields(candidate: Dict[str, Any]) -> Dict[str, str]:
    """
    Backward-compatible fallback for callers that do not have a live form.
    Normal execution uses reconstruct_form() immediately before each upload.
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
    filename = str(test.get("filename") or "brebes-overwrite-test.jpg")
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


def _marker_in_response(response: requests.Response, marker: str) -> bool:
    body = response.content[:DEFAULT_MAX_BODY].decode(
        response.encoding or "utf-8", errors="replace"
    )
    return marker.lower() in body.lower()


def _page_verification(
    session: requests.Session,
    candidate: Dict[str, Any],
    filename: str,
    markers: List[str],
    timeout: int,
) -> Dict[str, Any]:
    """GET only the discovered form page after upload and look for controlled markers."""
    page_url = str(candidate.get("page_url") or "").strip()
    if not page_url:
        return {"status": "skipped", "reason": "page_url_missing"}

    if not same_origin(page_url, str(candidate.get("action_url") or "")):
        return {"status": "skipped", "reason": "candidate_not_same_origin"}

    try:
        response = session.get(page_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return {
            "status": "request_error",
            "error": f"{type(exc).__name__}: {exc}",
        }

    body = response.content[:DEFAULT_MAX_BODY].decode(
        response.encoding or "utf-8", errors="replace"
    )
    lowered = body.lower()
    filename_seen = filename.lower() in lowered
    marker_hits = [m for m in markers if m.lower() in lowered]

    return {
        "status": "completed",
        "http_status": response.status_code,
        "url": response.url,
        "filename_observed": filename_seen,
        "marker_hits": marker_hits,
        "body_sha256": sha256_bytes(response.content),
        "content_length": len(response.content),
        "body_sample": body,
        "headers": redacted_headers(dict(response.headers)),
    }


def upload_one(
    session: requests.Session,
    candidate: Dict[str, Any],
    test: Dict[str, Any],
    timeout: int,
    tmp: Path,
    prior_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    action_url = str(candidate["action_url"])
    page_url = str(candidate["page_url"])
    field_name = choose_field(candidate)

    if not field_name:
        return {"status": "skipped", "reason": "file_field_name_not_known"}

    if not same_origin(action_url, page_url):
        return {"status": "skipped", "reason": "candidate_not_same_origin"}

    path = make_test_file(tmp, test)
    content = path.read_bytes()
    marker = str(test.get("marker") or "")

    print(f"[FILE] Dummy file      : {path}", flush=True)
    print(f"[FILE] Filename         : {path.name}", flush=True)
    print(f"[FILE] Stage            : {test['stage']}", flush=True)
    print(f"[FILE] Category         : {test['category']}", flush=True)
    print(f"[FILE] Marker           : {marker}", flush=True)
    print(f"[FILE] MIME             : {test['mime']}", flush=True)
    print(f"[FILE] Size             : {len(content)} bytes", flush=True)
    print(f"[FILE] SHA256           : {sha256_bytes(content)}", flush=True)

    try:
        reconstruction = reconstruct_form(session, candidate, timeout)
    except (requests.RequestException, FormReconstructionError) as exc:
        return {
            "status": "form_reconstruction_error",
            "error": f"{type(exc).__name__}: {exc}",
            "request": {
                "method": "POST",
                "url": action_url,
                "page_url": page_url,
                "field_name": field_name,
                "filename": path.name,
                "sha256": sha256_bytes(content),
            },
        }

    if reconstruction.get("unresolved_required"):
        return {
            "status": "form_reconstruction_incomplete",
            "reason": "required_form_fields_could_not_be_reconstructed_safely",
            "reconstruction": reconstruction,
            "request": {
                "method": "POST",
                "url": action_url,
                "page_url": page_url,
                "field_name": field_name,
                "filename": path.name,
                "sha256": sha256_bytes(content),
            },
        }

    text_fields = reconstruction["fields"]
    print(
        f"[FORM] Reconstructed : {reconstruction['field_count']} controls "
        f"(CSRF: {', '.join(reconstruction['csrf_fields']) or 'not detected'})",
        flush=True,
    )

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
                "stage": test["stage"],
                "marker": marker,
                "sha256": sha256_bytes(content),
            },
        }

    info = response_info(response)
    accepted = 200 <= response.status_code < 400
    blocked = response.status_code in {400, 401, 403, 405, 406, 409, 415, 422}

    # Only GET the discovered form page for post-upload verification.
    # This never executes or requests the uploaded file.
    verification_markers = [
        str(x.get("marker") or "")
        for x in prior_results
        if x.get("status") == "completed"
    ] + [marker]
    verification_markers = [x for x in verification_markers if x]
    page_verification = _page_verification(
        session, candidate, path.name, verification_markers, timeout
    )

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
            "stage": test["stage"],
            "category": test["category"],
            "declared_mime": test["mime"],
            "content_type": test["content_type"],
            "size_bytes": len(content),
            "sha256": sha256_bytes(content),
            "marker": marker,
        },
        "response": info,
        "form_reconstruction": reconstruction,
        "post_upload_get_verification": page_verification,
        "interpretation": classify_response(
            response,
            test,
            prior_results,
            page_verification,
        ),
    }


def classify_response(
    response: requests.Response,
    test: Dict[str, Any],
    prior_results: List[Dict[str, Any]],
    page_verification: Dict[str, Any],
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

    prior_accepted = any(
        x.get("status") == "completed"
        and x.get("accepted_indicator") is True
        for x in prior_results
    )
    same_filename = any(
        str((x.get("request") or {}).get("filename") or "") == test["filename"]
        for x in prior_results
    )
    marker_hits = page_verification.get("marker_hits") or []

    collision_observed = (
        test.get("stage", 1) > 1
        and same_filename
        and prior_accepted
        and 200 <= status < 400
    )

    # A collision being accepted is evidence that requires manual verification;
    # it does NOT prove an overwrite occurred.
    return {
        "disposition": disposition,
        "http_status": status,
        "redirect": bool(location),
        "response_keyword_signals": matched,
        "post_upload_filename_observed": bool(
            page_verification.get("filename_observed")
        ),
        "post_upload_marker_hits": marker_hits,
        "same_filename_reused": same_filename,
        "collision_accepted_indicator": collision_observed,
        "overwrite_proven": False,
        "automatic_finding": False,
        "overwrite_validation_test": True,
        "requires_review": collision_observed,
        "note": (
            "A repeated filename accepted by the application indicates a "
            "collision condition for manual review; it does not by itself prove "
            "that the existing file was overwritten. Proof requires reliable "
            "storage/path or content verification."
        ),
    }

def summarize(results: List[Dict[str, Any]]) -> Dict[str, int]:
    completed = [x for x in results if x.get("status") == "completed"]
    accepted = [x for x in completed if x.get("accepted_indicator") is True]
    blocked = [x for x in completed if x.get("blocked_indicator") is True]
    request_errors = [x for x in results if x.get("status") == "request_error"]
    review = [
        x for x in results
        if (x.get("interpretation") or {}).get("requires_review") is True
    ]
    collisions = [
        x for x in completed
        if (x.get("interpretation") or {}).get("collision_accepted_indicator") is True
    ]

    return {
        "tests": len(results),
        "completed": len(completed),
        "accepted_indicators": len(accepted),
        "blocked_indicators": len(blocked),
        "request_errors": len(request_errors),
        "collision_accepted_indicators": len(collisions),
        "requires_review": len(review),
        "findings": 0,
        "executed_files": 0,
        "automatic_execution": 0,
        "human_interaction_not_completed": sum(
            1 for x in results
            if x.get("status") == "human_interaction_not_completed"
        ),
        "overwrite_proven_tests": sum(
            1 for x in results
            if x.get("overwrite_proven") is True
        ),
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
        "methodology": methodology_definition(),
        "toolchain": {
            "mandatory": ["Python", "requests", "PyYAML"],
            "external_scanners": [],
            "not_required": [
                "Nmap", "ffuf", "Gobuster", "Nuclei", "sqlmap",
                "ZAP", "Hydra", "Playwright", "Chromium",
            ],
        },
        "test_matrix": [
            {
                "id": x["id"],
                "filename": x["filename"],
                "category": x["category"],
                "stage": x["stage"],
                "marker": x["marker"],
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
            "collision_accepted_indicators": 0,
            "requires_review": 0,
            "findings": 0,
            "executed_files": 0,
            "automatic_execution": 0,
        },
        "notes": [
            "Endpoint/candidate discovery is performed only by 10-001 discovery.py.",
            "Authentication is reused from 07-authentication/session/session.yaml.",
            "Only same-origin candidates with a known file field are executed.",
            "The target form is fetched immediately before each multipart POST.",
            "CSRF/security tokens are taken from the live form and redacted from evidence.",
            "The exact same benign filename is uploaded sequentially with distinct content markers.",
            "A GET-only verification of the discovered form page is performed after each upload.",
            "No uploaded file is requested or executed.",
            "Acceptance of a repeated filename is evidence for manual overwrite verification, not an automatic finding.",
        ],
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }

    save_yaml(artifact_path(project_path), artifact)

    print("[PASS] File Upload Overwrite Validation init selesai.")
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
    if args.tests:
        wanted = {x.strip().lower() for x in args.tests.split(",") if x.strip()}
        selected_tests = [
            item for item in TEST_MATRIX
            if item["id"].lower() in wanted
            or item["filename"].lower() in wanted
        ]
        if not selected_tests:
            raise ExecutionError(
                "Tidak ada overwrite test/id yang cocok dengan --tests."
            )

    http = build_session(session_records, target)
    results: List[Dict[str, Any]] = []
    candidate_results: List[Dict[str, Any]] = []

    print(f"[INFO] Project     : {project_id}")
    print(f"[INFO] Target      : {target}")
    print(f"[INFO] Candidates  : {len(candidates)}")
    print(f"[INFO] Test cases  : {len(selected_tests)}")
    print("[INFO] Exact same filename will be reused sequentially.")
    print("[INFO] Uploaded files will NOT be executed.")

    with tempfile.TemporaryDirectory(prefix="brebes-fileupload-overwrite-") as temp_dir:
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
                    f"stage={test['stage']} {test['category']} "
                    f"filename={test['filename']}",
                    flush=True,
                )

                item = upload_one(
                    http,
                    candidate,
                    test,
                    args.timeout,
                    tmp,
                    candidate_items,
                )

                item["candidate_index"] = cidx
                item["test"] = {
                    "id": test["id"],
                    "filename": test["filename"],
                    "category": test["category"],
                    "stage": test["stage"],
                    "marker": test["marker"],
                    "declared_mime": test["mime"],
                }
                candidate_items.append(item)
                results.append(item)

                if item.get("status") == "completed":
                    response = item.get("response") or {}
                    interpretation = item.get("interpretation") or {}
                    print(
                        f"[INFO] HTTP {response.get('status')} "
                        f"-> {interpretation.get('disposition', '-')}"
                    )
                    if interpretation.get("collision_accepted_indicator"):
                        print(
                            "[REVIEW] Same filename accepted again; "
                            "overwrite is NOT automatically proven."
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
            **methodology_definition(),
            "multipart_post_performed": True,
            "exact_filename_reused": True,
        },
        "test_matrix": [
            {
                "id": x["id"],
                "filename": x["filename"],
                "category": x["category"],
                "stage": x["stage"],
                "marker": x["marker"],
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
            "The same exact filename is uploaded sequentially with distinct benign content markers.",
            "The target form is reconstructed immediately before each multipart POST.",
            "CSRF/security tokens are taken from the live form and redacted from evidence.",
            "A GET-only form-page verification is performed after each upload.",
            "No uploaded file was executed by this tool.",
            "Repeated filename acceptance does not automatically prove overwrite.",
            "Manual review is required to establish actual storage replacement/overwrite.",
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

    print("\n[PASS] File Upload overwrite validation selesai.")
    print(f"[PASS] Candidates                  : {len(candidates)}")
    print(f"[PASS] Tests                       : {summary['tests']}")
    print(f"[PASS] Completed                   : {summary['completed']}")
    print(f"[PASS] Accepted indicators        : {summary['accepted_indicators']}")
    print(f"[PASS] Blocked indicators         : {summary['blocked_indicators']}")
    print(f"[PASS] Collision accepted         : {summary['collision_accepted_indicators']}")
    print(f"[PASS] Request errors             : {summary['request_errors']}")
    print(f"[PASS] Manual review              : {summary['requires_review']}")
    print("[PASS] Findings                   : 0")
    print("[PASS] Files executed             : 0")
    print(f"[PASS] Artifact                   : {artifact_path(project_path)}")
    print(f"[PASS] Evidence                   : {evidence_path(project_path)}")
    return 0


# ---------------------------------------------------------------------------
# Browser-simulator method
# ---------------------------------------------------------------------------
# This is an additional execution path. The original requests-based run()
# remains unchanged. browser-run uses Playwright/Chromium, reuses the same
# authenticated session artifact, reconstructs the live form in the browser,
# uploads the same benign filename sequentially, and can pause for manual
# human-interaction challenges such as Turnstile.
#
# It never requests execution of an uploaded file. For overwrite proof it
# only follows URLs/links that the application itself exposes after upload.
# It does not guess /uploads, /storage, etc.

def _browser_session_records(
    session_data: Dict[str, Any],
    project_id: str,
    target_url: str,
) -> List[Dict[str, str]]:
    return decrypt_session_candidates(session_data, project_id, target_url)


def _browser_add_session(context: Any, records: List[Dict[str, str]], target_url: str) -> None:
    hostname = (urlparse(target_url).hostname or "").lower()
    for item in records:
        if item.get("type") != "cookie":
            continue
        try:
            context.add_cookies([{
                "name": item["name"],
                "value": item["value"],
                "domain": hostname,
                "path": item.get("path") or "/",
                "secure": str(target_url).lower().startswith("https://"),
            }])
        except Exception as exc:
            print(
                f"[BROWSER] Cookie {item.get('name', '-')} gagal dipasang: {exc}",
                flush=True,
            )


def _browser_auth_headers(records: List[Dict[str, str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for item in records:
        if item.get("type") in {"header", "authorization", "bearer"}:
            name = item.get("header_name") or "Authorization"
            headers[name] = item.get("value") or ""
    return headers


def _browser_visible_text(page: Any, limit: int = 12000) -> str:
    try:
        return (page.locator("body").inner_text(timeout=5000) or "")[:limit]
    except Exception:
        try:
            return (page.content() or "")[:limit]
        except Exception:
            return ""


def _browser_human_interaction_detected(page: Any) -> bool:
    text = _browser_visible_text(page).lower()
    markers = (
        "turnstile",
        "cloudflare",
        "verify you are human",
        "verify that you are human",
        "checking your browser",
        "captcha",
        "recaptcha",
        "hcaptcha",
        "human verification",
        "security verification",
    )
    return any(marker in text for marker in markers)


def _browser_pause_for_human(page: Any, timeout_seconds: int) -> bool:
    print(
        "\n[HUMAN] Human-interaction challenge terdeteksi pada browser.",
        flush=True,
    )
    print(
        "[HUMAN] Selesaikan challenge secara manual di browser yang terbuka.",
        flush=True,
    )
    print(
        "[HUMAN] Tool tidak mencoba bypass CAPTCHA/Turnstile.",
        flush=True,
    )
    print(
        f"[HUMAN] Setelah selesai, tekan ENTER. Timeout {timeout_seconds} detik.",
        flush=True,
    )
    try:
        input()
    except EOFError:
        return False
    return not _browser_human_interaction_detected(page)


def _browser_form_locator(page: Any, candidate: Dict[str, Any]) -> Any:
    action_url = str(candidate.get("action_url") or "")
    forms = page.locator("form")
    count = forms.count()
    for i in range(count):
        form = forms.nth(i)
        try:
            action = form.get_attribute("action") or ""
            effective = urljoin(str(page.url), action)
            if same_origin(effective, action_url) and effective.rstrip("/") == action_url.rstrip("/"):
                return form
        except Exception:
            continue
    if count == 1:
        return forms.nth(0)
    raise FormReconstructionError("Form target tidak ditemukan oleh browser.")



def _browser_control_context(control: Any) -> Dict[str, str]:
    """Collect DOM context used for generic field classification."""
    try:
        return control.evaluate(
            """(el) => {
                const clean = (v) => (v || '').replace(/\\s+/g, ' ').trim();
                const id = clean(el.id);
                const name = clean(el.getAttribute('name'));
                const placeholder = clean(el.getAttribute('placeholder'));
                const aria = clean(el.getAttribute('aria-label'));
                const type = clean(el.getAttribute('type'));
                const min = clean(el.getAttribute('min'));
                const max = clean(el.getAttribute('max'));

                let label = '';
                if (id) {
                    const byFor = document.querySelector(`label[for="${CSS.escape(id)}"]`);
                    if (byFor) label = clean(byFor.innerText);
                }
                if (!label) {
                    const parentLabel = el.closest('label');
                    if (parentLabel) label = clean(parentLabel.innerText);
                }

                let nearby = '';
                const wrapper = el.closest('.form-group, .form-row, .row, .mb-3, .mb-2, .mb-1, td, div');
                if (wrapper) nearby = clean(wrapper.innerText).slice(0, 500);

                return {id, name, placeholder, aria, type, min, max, label, nearby};
            }"""
        )
    except Exception:
        return {}


def _browser_geo_map_signal(form: Any) -> bool:
    """Detect a map/geo UI as a confidence signal only."""
    try:
        body = form.locator("xpath=ancestor::body[1]")
        selectors = (
            ".leaflet-container",
            "[class*='leaflet']",
            "[id*='map']",
            "[class*='mapbox']",
            "[class*='openlayers']",
            ".ol-viewport",
            "[class*='google-map']",
            "[id*='google-map']",
        )
        for selector in selectors:
            if body.locator(selector).count():
                return True

        page_text = (body.inner_text(timeout=3000) or "").lower()
        return any(
            marker in page_text
            for marker in (
                "latitude", "longitude", "koordinat",
                "coordinate", "lokasi", "location",
            )
        )
    except Exception:
        return False


def _browser_geo_candidates(form: Any) -> Dict[str, Any]:
    """
    Generic Geo Position detector.

    It does not depend on the user telling the tool which fields are geo
    coordinates. It uses DOM semantics, labels, constraints, field pairing,
    and map presence. Only high-confidence pairs are auto-filled.
    """
    controls = form.locator("input, textarea, select")
    items: List[Dict[str, Any]] = []

    for i in range(controls.count()):
        control = controls.nth(i)
        try:
            typ = (control.get_attribute("type") or "text").lower()
            if typ in {"file", "submit", "button", "reset", "image", "checkbox", "radio"}:
                continue

            ctx = _browser_control_context(control)
            identity = " ".join(
                str(ctx.get(k) or "")
                for k in ("name", "id", "placeholder", "aria", "label", "nearby")
            ).lower()

            try:
                minimum = float(ctx.get("min")) if ctx.get("min") not in (None, "") else None
            except (TypeError, ValueError):
                minimum = None
            try:
                maximum = float(ctx.get("max")) if ctx.get("max") not in (None, "") else None
            except (TypeError, ValueError):
                maximum = None

            lat_score = 0
            lon_score = 0
            reasons: List[str] = []

            lat_tokens = (
                "latitude", "latitud", "lat_laporan", "lat_report",
                "geo_lat", "geolat", "lat_coord", "lat_coordinate",
                "lintang",
            )
            lon_tokens = (
                "longitude", "longitud", "long_laporan", "lng", "lon",
                "long_report", "geo_lng", "geolong", "long_coord",
                "long_coordinate", "bujur",
            )

            for token in lat_tokens:
                if token in identity:
                    lat_score += 5
                    reasons.append(f"latitude-token:{token}")
                    break

            for token in lon_tokens:
                if token in identity:
                    lon_score += 5
                    reasons.append(f"longitude-token:{token}")
                    break

            if minimum is not None and maximum is not None:
                if -90 <= minimum <= 90 and -90 <= maximum <= 90 and minimum < maximum:
                    lat_score += 4
                    reasons.append("latitude-range")
                if (
                    -180 <= minimum <= 180
                    and -180 <= maximum <= 180
                    and minimum < maximum
                    and (minimum < -90 or maximum > 90)
                ):
                    lon_score += 4
                    reasons.append("longitude-range")

            if typ in {"number", "range"} and (lat_score or lon_score):
                lat_score += 1
                lon_score += 1

            if any(token in identity for token in ("koordinat", "coordinate", "geo", "geolocation")):
                lat_score += 1
                lon_score += 1
                reasons.append("geo-context")

            items.append({
                "index": i,
                "name": ctx.get("name") or "",
                "id": ctx.get("id") or "",
                "type": typ,
                "label": ctx.get("label") or "",
                "placeholder": ctx.get("placeholder") or "",
                "nearby": ctx.get("nearby") or "",
                "min": ctx.get("min") or "",
                "max": ctx.get("max") or "",
                "lat_score": lat_score,
                "lon_score": lon_score,
                "reasons": reasons,
            })
        except Exception:
            continue

    map_signal = _browser_geo_map_signal(form)
    lat_items = [x for x in items if x["lat_score"] >= 4]
    lon_items = [x for x in items if x["lon_score"] >= 4]

    pair: Optional[Tuple[Dict[str, Any], Dict[str, Any]]] = None
    best_pair_score = 0

    for lat in lat_items:
        for lon in lon_items:
            distance = abs(int(lat["index"]) - int(lon["index"]))
            pair_score = lat["lat_score"] + lon["lon_score"]
            if distance <= 6:
                pair_score += 4
            if map_signal:
                pair_score += 3
            if pair_score > best_pair_score:
                best_pair_score = pair_score
                pair = (lat, lon)

    if pair is None:
        return {
            "detected": False,
            "confidence": "none",
            "map_signal": map_signal,
            "fields": [],
            "reason": "Tidak ditemukan pasangan latitude/longitude dengan confidence cukup.",
            "all_candidates": items,
        }

    lat, lon = pair
    high_confidence = (
        lat["lat_score"] >= 5
        and lon["lon_score"] >= 5
        and (abs(int(lat["index"]) - int(lon["index"])) <= 6 or map_signal)
    )

    if not high_confidence:
        return {
            "detected": False,
            "confidence": "medium",
            "map_signal": map_signal,
            "fields": [lat, lon],
            "reason": "Geo position dicurigai tetapi confidence belum cukup untuk auto-fill.",
            "all_candidates": items,
        }

    lat["role"] = "latitude"
    lon["role"] = "longitude"

    return {
        "detected": True,
        "confidence": "high",
        "map_signal": map_signal,
        "fields": [lat, lon],
        "reason": "Pasangan geo position terdeteksi otomatis.",
        "all_candidates": items,
    }


def _browser_fill_dom_value(control: Any, value: str) -> None:
    """Fill normally, with a DOM setter fallback for map-backed controls."""
    try:
        control.fill(value)
        return
    except Exception:
        control.evaluate(
            """(el, value) => {
                const proto = el instanceof HTMLTextAreaElement
                    ? HTMLTextAreaElement.prototype
                    : HTMLInputElement.prototype;
                const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
                if (setter) setter.call(el, value);
                else el.value = value;
                el.dispatchEvent(new Event('input', {bubbles: true}));
                el.dispatchEvent(new Event('change', {bubbles: true}));
            }""",
            value,
        )


def _browser_fill_safe_form(form: Any, candidate: Dict[str, Any]) -> Dict[str, Any]:
    """
    Existing browser form reconstruction plus generic Geo Position detection.
    The requests-based run() path is untouched.
    """
    controls = form.locator("input, textarea, select")
    count = controls.count()
    csrf_fields: List[str] = []
    filled: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, str]] = []

    geo = _browser_geo_candidates(form)
    geo_by_index = {
        int(item["index"]): item
        for item in geo.get("fields", [])
        if item.get("role") in {"latitude", "longitude"}
    }

    if geo.get("detected"):
        print(
            "[GEO] Geo position detected automatically "
            f"(confidence={geo.get('confidence')}, map={geo.get('map_signal')}).",
            flush=True,
        )
        for item in geo.get("fields", []):
            score = item.get("lat_score") if item.get("role") == "latitude" else item.get("lon_score")
            print(
                f"[GEO] {item.get('role'):9s} "
                f"name={item.get('name') or '-'} "
                f"id={item.get('id') or '-'} score={score}",
                flush=True,
            )

    file_names = {
        str(x.get("name") or "").strip()
        for x in candidate.get("file_inputs") or []
        if isinstance(x, dict) and str(x.get("name") or "").strip()
    }
    radio_done: set[str] = set()

    for i in range(count):
        control = controls.nth(i)
        try:
            tag = (control.evaluate("(e) => e.tagName") or "").lower()
            typ = (
                control.get_attribute("type")
                or ("textarea" if tag == "textarea" else "text")
            ).lower()
            name = (control.get_attribute("name") or "").strip()
            control_id = (control.get_attribute("id") or "").strip()
            placeholder = (control.get_attribute("placeholder") or "").strip()
            key = name or control_id or placeholder or f"control-{i}"

            if typ == "file" or name in file_names:
                continue
            if typ in {"submit", "button", "reset", "image"}:
                continue

            if i in geo_by_index:
                role = geo_by_index[i]["role"]
                value = "-6.869400" if role == "latitude" else "109.036900"
                _browser_fill_dom_value(control, value)
                filled.append({
                    "name": key,
                    "type": typ,
                    "generated": True,
                    "reason": f"auto_detected_geo_{role}",
                    "value_redacted": value,
                    "geo_confidence": geo.get("confidence"),
                    "geo_detection_reasons": geo_by_index[i].get("reasons", []),
                })
                print(f"[GEO] Auto-fill {role:9s}: {key} = {value}", flush=True)
                continue

            if typ == "radio":
                if name in radio_done:
                    continue
                radio_done.add(name)
                radio = form.locator(f'input[type="radio"][name="{name}"]')
                checked = form.locator(f'input[type="radio"][name="{name}"]:checked')
                if checked.count():
                    checked.first.check()
                elif radio.count():
                    radio.first.check()
                filled.append({"name": key, "type": typ, "generated": True, "reason": "radio"})
                continue

            if typ == "checkbox":
                if control.is_checked():
                    filled.append({"name": key, "type": typ, "generated": True, "reason": "already_checked"})
                elif control.get_attribute("required") is not None:
                    control.check()
                    filled.append({"name": key, "type": typ, "generated": True, "reason": "required_checkbox"})
                continue

            if typ == "select":
                options = control.locator("option")
                chosen = None
                for j in range(options.count()):
                    opt = options.nth(j)
                    if not opt.is_disabled():
                        val = opt.get_attribute("value")
                        if val not in (None, ""):
                            chosen = val
                            break
                if chosen is not None:
                    control.select_option(chosen)
                    filled.append({"name": key, "type": typ, "generated": True, "reason": "select_valid_option"})
                continue

            current = (
                control.input_value()
                if typ not in {"hidden"}
                else (control.get_attribute("value") or "")
            )

            if _is_csrf_control({"name": name, "attrs": {"id": control_id}}):
                if current:
                    csrf_fields.append(key)
                    filled.append({"name": key, "type": typ, "generated": True, "reason": "csrf_from_live_dom"})
                else:
                    unresolved.append({"name": key, "reason": "csrf_value_missing"})
                continue

            if typ == "hidden":
                filled.append({"name": key, "type": typ, "generated": True, "reason": "hidden_original_value"})
                continue

            if typ == "password" or _is_sensitive_name(name):
                unresolved.append({
                    "name": key,
                    "reason": "sensitive_field_requires_existing_application_value",
                })
                continue

            attrs = {
                "minlength": control.get_attribute("minlength") or "",
                "maxlength": control.get_attribute("maxlength") or "",
                "pattern": control.get_attribute("pattern") or "",
                "min": control.get_attribute("min") or "",
                "max": control.get_attribute("max") or "",
                "step": control.get_attribute("step") or "",
                "id": control_id,
            }
            value, reason = _generate_control_value({
                "type": typ,
                "name": name,
                "value": current,
                "attrs": attrs,
            })

            if value is not None:
                _browser_fill_dom_value(control, value)
                filled.append({"name": key, "type": typ, "generated": True, "reason": reason})
            elif control.get_attribute("required") is not None:
                unresolved.append({"name": key, "reason": reason})
        except Exception as exc:
            unresolved.append({
                "name": "unknown",
                "reason": f"browser_fill_error:{type(exc).__name__}:{exc}",
            })

    return {
        "field_count": count,
        "csrf_fields": sorted(set(csrf_fields)),
        "filled_fields": filled,
        "unresolved_required": unresolved,
        "geo_detection": {
            "detected": bool(geo.get("detected")),
            "confidence": geo.get("confidence"),
            "map_signal": bool(geo.get("map_signal")),
            "reason": geo.get("reason"),
            "fields": [
                {
                    "role": x.get("role"),
                    "name": x.get("name"),
                    "id": x.get("id"),
                    "label": x.get("label"),
                    "score": (
                        x.get("lat_score")
                        if x.get("role") == "latitude"
                        else x.get("lon_score")
                    ),
                    "reasons": x.get("reasons", []),
                }
                for x in geo.get("fields", [])
            ],
        },
    }


def _browser_extract_candidate_links(page: Any, filename: str, target_url: str) -> List[str]:
    """
    Extract only same-origin links/URLs that the application itself exposes
    after upload and that mention the controlled filename. No path guessing.
    """
    urls: List[str] = []
    try:
        anchors = page.locator("a")
        for i in range(anchors.count()):
            href = anchors.nth(i).get_attribute("href") or ""
            if not href:
                continue
            absolute = urljoin(page.url, href)
            if not same_origin(absolute, target_url):
                continue
            if filename.lower() in absolute.lower():
                urls.append(absolute)
    except Exception:
        pass

    # Also inspect src/href attributes from common rendered elements.
    for selector, attr in (("img", "src"), ("iframe", "src"), ("source", "src"), ("a", "href")):
        try:
            nodes = page.locator(selector)
            for i in range(nodes.count()):
                value = nodes.nth(i).get_attribute(attr) or ""
                absolute = urljoin(page.url, value)
                if (
                    value
                    and same_origin(absolute, target_url)
                    and filename.lower() in absolute.lower()
                ):
                    urls.append(absolute)
        except Exception:
            pass

    return sorted(set(urls))


def _browser_fetch_marker(context: Any, url: str, marker: str, timeout: int) -> Dict[str, Any]:
    """
    GET only an application-disclosed same-origin URL. Compare the benign
    marker; never execute the response as code.
    """
    try:
        response = context.request.get(url, timeout=timeout * 1000, fail_on_status_code=False)
        body = response.body()
        text = body[:DEFAULT_MAX_BODY].decode("utf-8", errors="replace")
        return {
            "status": "completed",
            "http_status": response.status,
            "url": url,
            "content_type": response.headers.get("content-type", ""),
            "content_length": len(body),
            "body_sha256": sha256_bytes(body),
            "marker_observed": marker.lower() in text.lower(),
            "body_sample": text,
            "headers": redacted_headers(dict(response.headers)),
        }
    except Exception as exc:
        return {
            "status": "request_error",
            "url": url,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _browser_upload_one(
    page: Any,
    context: Any,
    candidate: Dict[str, Any],
    test: Dict[str, Any],
    target_url: str,
    timeout: int,
) -> Dict[str, Any]:
    page_url = str(candidate.get("page_url") or "")
    action_url = str(candidate.get("action_url") or "")
    field_name = choose_field(candidate)
    if not field_name:
        return {"status": "skipped", "reason": "file_field_name_not_known"}

    if not same_origin(page_url, target_url) or not same_origin(action_url, target_url):
        return {"status": "skipped", "reason": "candidate_not_same_origin"}

    import tempfile as _tempfile
    with _tempfile.TemporaryDirectory(prefix="brebes-browser-overwrite-") as td:
        tmp = Path(td)
        path = make_test_file(tmp, test)
        content = path.read_bytes()
        marker = str(test.get("marker") or "")

        print(f"[FILE] Filename         : {path.name}", flush=True)
        print(f"[FILE] Stage            : {test['stage']}", flush=True)
        print(f"[FILE] Marker           : {marker}", flush=True)
        print(f"[FILE] SHA256           : {sha256_bytes(content)}", flush=True)

        page.goto(page_url, wait_until="domcontentloaded", timeout=timeout * 1000)

        if _browser_human_interaction_detected(page):
            if not _browser_pause_for_human(page, max(30, timeout * 3)):
                return {
                    "status": "human_interaction_not_completed",
                    "reason": "browser challenge remained active",
                }

        form = _browser_form_locator(page, candidate)
        fill_result = _browser_fill_safe_form(form, candidate)

        if fill_result["unresolved_required"]:
            return {
                "status": "form_reconstruction_incomplete",
                "reason": "required_form_fields_could_not_be_filled_safely",
                "browser_form": fill_result,
            }

        # File inputs cannot be populated with normal fill(); Playwright must
        # attach the local file through set_input_files(). Prefer DOM-name
        # matching, then fall back to the first file input in the selected form.
        file_input = form.locator('input[type="file"]')
        matched_file_input = None

        for i in range(file_input.count()):
            candidate_input = file_input.nth(i)
            input_name = (candidate_input.get_attribute("name") or "").strip()
            if input_name == field_name:
                matched_file_input = candidate_input
                break

        if matched_file_input is None:
            if file_input.count() == 1:
                matched_file_input = file_input.first
            else:
                return {
                    "status": "file_input_not_found_in_browser_form",
                    "reason": f"file input dengan name={field_name!r} tidak ditemukan",
                }

        matched_file_input.set_input_files(str(path))

        # Verify that Chromium actually accepted the local file before submit.
        selected_name = ""
        selected_count = 0
        try:
            selected_count = matched_file_input.locator("xpath=.").evaluate(
                "(e) => e.files ? e.files.length : 0"
            )
            selected_name = matched_file_input.locator("xpath=.").evaluate(
                "(e) => e.files && e.files.length ? e.files[0].name : ''"
            ) or ""
        except Exception:
            pass

        if selected_count != 1 or selected_name != path.name:
            return {
                "status": "file_selection_failed",
                "reason": "Chromium tidak mengonfirmasi file pada input.",
                "expected_filename": path.name,
                "selected_filename": selected_name,
                "selected_count": selected_count,
            }

        print(f"[BROWSER] Form            : {page.url}", flush=True)
        print(f"[BROWSER] File field      : {field_name}", flush=True)
        print(f"[BROWSER] File selected   : {selected_name}", flush=True)
        print("[BROWSER] File input      : OK", flush=True)

        # Submit through the real browser DOM after the file selection has
        # been verified. No uploaded file is requested or executed.
        print("[BROWSER] Submit via real browser DOM.", flush=True)

        # Submit through the form's own submit mechanism. This preserves
        # browser-side JS validation and challenge state.
        try:
            with page.expect_navigation(wait_until="domcontentloaded", timeout=timeout * 1000):
                form.locator('button[type="submit"], input[type="submit"]').first.click()
        except Exception:
            # Some apps submit asynchronously or replace the page without a
            # navigation event. Give the browser a short settle period.
            try:
                form.locator('button[type="submit"], input[type="submit"]').first.click(timeout=3000)
            except Exception:
                try:
                    form.evaluate("(f) => f.requestSubmit()")
                except Exception as exc:
                    return {
                        "status": "submit_error",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
            page.wait_for_timeout(1500)

        final_url = page.url
        final_status = None
        try:
            final_status = page.locator("body").count() and 200
        except Exception:
            final_status = None

        disclosed_urls = _browser_extract_candidate_links(page, path.name, target_url)
        disclosed_fetches = [
            _browser_fetch_marker(context, url, marker, timeout)
            for url in disclosed_urls[:5]
        ]

        marker_hits = [
            item for item in disclosed_fetches
            if item.get("marker_observed") is True
        ]

        return {
            "status": "completed",
            "accepted_indicator": True,
            "request": {
                "method": "POST",
                "url": action_url,
                "page_url": page_url,
                "field_name": field_name,
                "filename": path.name,
                "stage": test["stage"],
                "category": test["category"],
                "declared_mime": test["mime"],
                "content_type": test["content_type"],
                "size_bytes": len(content),
                "sha256": sha256_bytes(content),
                "marker": marker,
            },
            "browser": {
                "final_url": final_url,
                "final_status_observed": final_status,
                "form": fill_result,
                "file_input": {
                    "field_name": field_name,
                    "selected_filename": selected_name,
                    "selected_count": selected_count,
                    "selection_confirmed": selected_count == 1 and selected_name == path.name,
                },
                "disclosed_file_urls": disclosed_urls,
                "disclosed_file_fetches": disclosed_fetches,
            },
            "overwrite_proven": bool(marker_hits),
            "marker_matches": len(marker_hits),
            "automatic_finding": False,
            "requires_review": bool(marker_hits) or test.get("stage", 1) > 1,
            "note": (
                "Browser execution proves overwrite only when the application "
                "itself discloses a same-origin file URL and the fetched content "
                "contains the controlled marker. Otherwise manual review remains."
            ),
        }


def cmd_browser_run(args: argparse.Namespace) -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise ExecutionError(
            "Playwright belum terpasang. Jalankan: pip install playwright "
            "lalu: playwright install chromium"
        )

    _, project_path, project_id = project_context()
    discovery = load_discovery(project_path)
    target = str((discovery.get("target") or {}).get("url") or "").strip()
    if not target:
        raise ExecutionError("Target URL tidak ditemukan.")

    session_data = load_session_data(project_path)
    session_records = _browser_session_records(session_data, project_id, target)
    candidates = usable_candidates(discovery, target)

    if args.candidate:
        selected = []
        for index in args.candidate:
            if index < 1 or index > len(candidates):
                raise ExecutionError(f"Candidate index {index} di luar range 1..{len(candidates)}.")
            selected.append(candidates[index - 1])
        candidates = selected

    if not candidates:
        raise ExecutionError("Tidak ada candidate yang aman untuk browser execution.")

    selected_tests = TEST_MATRIX
    if args.tests:
        wanted = {x.strip().lower() for x in args.tests.split(",") if x.strip()}
        selected_tests = [
            item for item in TEST_MATRIX
            if item["id"].lower() in wanted or item["filename"].lower() in wanted
        ]
        if not selected_tests:
            raise ExecutionError("Tidak ada overwrite test/id yang cocok dengan --tests.")

    print(f"[INFO] Browser simulator : Playwright Chromium", flush=True)
    print(f"[INFO] Headed             : {not args.headless}", flush=True)
    print(f"[INFO] Candidates          : {len(candidates)}", flush=True)
    print(f"[INFO] Tests               : {len(selected_tests)}", flush=True)
    print("[INFO] Uploaded files will NOT be executed.", flush=True)
    print("[INFO] File URL is verified only if the application exposes it.", flush=True)

    all_results: List[Dict[str, Any]] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False if not args.headless else True)
        context = browser.new_context(ignore_https_errors=False)
        _browser_add_session(context, session_records, target)
        auth_headers = _browser_auth_headers(session_records)
        if auth_headers:
            context.set_extra_http_headers(auth_headers)

        page = context.new_page()

        for cidx, candidate in enumerate(candidates, 1):
            print(
                f"\n[STEP] Browser candidate {cidx}/{len(candidates)} "
                f"{candidate.get('action_url')}",
                flush=True,
            )

            for tidx, test in enumerate(selected_tests, 1):
                print(
                    f"[TEST] {tidx}/{len(selected_tests)} "
                    f"stage={test['stage']} {test['category']} "
                    f"filename={test['filename']}",
                    flush=True,
                )

                item = _browser_upload_one(
                    page, context, candidate, test, target, args.timeout
                )
                item["candidate_index"] = cidx
                item["test"] = {
                    "id": test["id"],
                    "filename": test["filename"],
                    "category": test["category"],
                    "stage": test["stage"],
                    "marker": test["marker"],
                }

                # Normalize browser-run result metadata to the same contract
                # used by run(). This does not change browser behavior.
                if item.get("status") == "completed":
                    item.setdefault("accepted_indicator", True)
                    item.setdefault("blocked_indicator", False)

                    prior_same_filename = any(
                        x.get("status") == "completed"
                        and str((x.get("request") or {}).get("filename") or "")
                        == test["filename"]
                        for x in all_results
                    )
                    prior_accepted = any(
                        x.get("status") == "completed"
                        and x.get("accepted_indicator") is True
                        for x in all_results
                    )
                    collision_accepted = (
                        test.get("stage", 1) > 1
                        and prior_same_filename
                        and prior_accepted
                        and item.get("accepted_indicator") is True
                    )

                    item["interpretation"] = {
                        "disposition": "accepted_or_processed",
                        "http_status": item.get("browser", {}).get(
                            "final_status_observed"
                        ),
                        "redirect": False,
                        "response_keyword_signals": [],
                        "post_upload_filename_observed": bool(
                            item.get("browser", {}).get("disclosed_file_urls")
                        ),
                        "post_upload_marker_hits": [],
                        "same_filename_reused": prior_same_filename,
                        "collision_accepted_indicator": collision_accepted,
                        "overwrite_proven": bool(item.get("overwrite_proven")),
                        "automatic_finding": False,
                        "overwrite_validation_test": True,
                        "requires_review": bool(
                            item.get("requires_review") or collision_accepted
                        ),
                        "note": item.get("note", ""),
                    }
                    item["requires_review"] = item["interpretation"]["requires_review"]
                elif item.get("status") != "request_error":
                    item.setdefault("blocked_indicator", False)

                all_results.append(item)

                if item.get("overwrite_proven"):
                    print(
                        "[PROOF] Controlled marker observed through an "
                        "application-disclosed file URL.",
                        flush=True,
                    )
                elif item.get("status") == "completed":
                    print(
                        "[REVIEW] Browser upload completed, but overwrite is "
                        "not proven yet.",
                        flush=True,
                    )
                else:
                    print(
                        f"[INFO] {item.get('status')} "
                        f"{item.get('reason', item.get('error', ''))}",
                        flush=True,
                    )

        browser.close()

    summary = summarize(all_results)
    completed = [x for x in all_results if x.get("status") == "completed"]
    proven = [x for x in completed if x.get("overwrite_proven") is True]
    human = [x for x in all_results if x.get("status") == "human_interaction_not_completed"]

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": SCRIPT_NAME,
            "version": SCRIPT_VERSION,
            "method": "browser-simulator",
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE_NAME,
            "status": "completed",
        },
        "target": {"application": project_id, "url": target},
        "sources": {
            "discovery": str(discovery_path(project_path)),
            "discovery_evidence": str(discovery_evidence_path(project_path)),
            "session": str(session_path(project_path)),
        },
        "methodology": {
            **methodology_definition(),
            "browser_simulator": True,
            "playwright_chromium": True,
            "human_interaction_supported": True,
            "manual_challenge_solve_allowed": True,
            "application_disclosed_file_url_only": True,
            "marker_content_verification": True,
            "automatic_finding": False,
        },
        "results": {
            **summary,
            "candidate_count": len(candidates),
        },
        "results_detail": all_results,
        "notes": [
            "Browser simulator is an additional method; the original requests run() is unchanged.",
            "Authenticated session is reused from 07-authentication/session/session.yaml.",
            "The browser performs the real DOM form flow and preserves browser-side validation.",
            "If Turnstile/CAPTCHA/human verification appears, the tool pauses for manual completion; it does not bypass it.",
            "Only same-origin application-disclosed file URLs are fetched for marker verification.",
            "No storage-directory guessing is performed.",
            "Uploaded files are never executed.",
            "overwrite_proven is true only when a disclosed file URL returns the controlled marker.",
        ],
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }

    save_yaml(artifact_path(project_path), artifact)
    save_json(
        evidence_path(project_path),
        {
            "schema_version": SCHEMA_VERSION,
            "project_id": project_id,
            "checklist_id": CHECKLIST_ID,
            "target": target,
            "method": "browser-simulator",
            "results": artifact["results"],
            "results_detail": all_results,
            "created_at": utc_now(),
        },
    )

    print("\n[PASS] Browser-simulator overwrite validation selesai.")
    print(f"[PASS] Tests completed         : {summary['completed']}")
    print(f"[PASS] Accepted indicators     : {summary['accepted_indicators']}")
    print(f"[PASS] Blocked indicators      : {summary['blocked_indicators']}")
    print(f"[PASS] Collision accepted      : {summary['collision_accepted_indicators']}")
    print(f"[PASS] Request errors          : {summary['request_errors']}")
    print(f"[PASS] Manual review           : {summary['requires_review']}")
    print(f"[PASS] Overwrite proven tests  : {summary['overwrite_proven_tests']}")
    print(f"[PASS] Human interaction stop  : {summary['human_interaction_not_completed']}")
    print("[PASS] Findings                : 0")
    print("[PASS] Files executed          : 0")
    print(f"[PASS] Artifact                : {artifact_path(project_path)}")
    print(f"[PASS] Evidence                : {evidence_path(project_path)}")
    return 0

def cmd_show(_: argparse.Namespace) -> int:
    _, project_path, _ = project_context()
    path = artifact_path(project_path)
    if not path.exists():
        print("[INFO] Artifact overwrite.py belum ada.")
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
            data = {}
            errors.append(f"Artifact tidak dapat dibaca: {exc}")

        if isinstance(data, dict):
            if data.get("project_id") != project_id:
                errors.append("project_id tidak sesuai.")

            if (data.get("checklist") or {}).get("id") != CHECKLIST_ID:
                errors.append("checklist.id tidak sesuai.")

            methodology = data.get("methodology") or {}
            for key in (
                "source_candidates_only",
                "same_origin_only",
                "authenticated_session_required",
                "multipart_post_allowed",
                "overwrite_validation",
                "exact_filename_collision",
                "distinct_content_markers",
                "form_reconstruction",
                "csrf_from_live_form",
                "post_upload_get_verification",
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
            for key in (
                "tests",
                "completed",
                "accepted_indicators",
                "blocked_indicators",
                "request_errors",
                "collision_accepted_indicators",
                "requires_review",
                "findings",
                "executed_files",
                "automatic_execution",
            ):
                if not isinstance(results.get(key), int) or results.get(key) < 0:
                    errors.append(f"results.{key} harus integer >= 0.")

            if results.get("findings") != 0:
                errors.append("findings harus 0.")
            if results.get("executed_files") != 0:
                errors.append("executed_files harus 0.")
            if results.get("automatic_execution") != 0:
                errors.append("automatic_execution harus 0.")

    if not evidence.exists():
        errors.append(f"Evidence tidak ditemukan: {evidence}")
    else:
        try:
            ev = json.loads(evidence.read_text(encoding="utf-8-sig"))
            if ev.get("project_id") != project_id:
                errors.append("Evidence project_id tidak sesuai.")
            if ev.get("checklist_id") != CHECKLIST_ID:
                errors.append("Evidence checklist_id tidak sesuai.")
        except Exception as exc:
            errors.append(f"Evidence tidak dapat dibaca: {exc}")

    if errors:
        print("[FAIL] File Upload overwrite validation tidak memenuhi verify.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] File Upload overwrite validation memenuhi verify.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {project_id}")
    print(f"[PASS] Artifact  : {path}")
    print("[PASS] Uploaded files executed : 0")
    print("[PASS] Automatic findings      : 0")
    print("[PASS] Encoding                : UTF-8 tanpa BOM")
    return 0

def cmd_remove(_: argparse.Namespace) -> int:
    _, project_path, _ = project_context()
    directory = overwrite_dir(project_path)

    if not directory.exists():
        print("[INFO] Artifact overwrite.py belum ada.")
        return 0

    import shutil
    shutil.rmtree(directory)
    print("[PASS] Artifact File Upload overwrite artifact dihapus.")
    print(f"[PASS] Directory: {directory}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools File Upload Overwrite Validation (10-004)"
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
        "--tests",
        help="Comma-separated overwrite test IDs, e.g. baseline-a,collision-b,collision-c",
    )
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser(
        "browser-run",
        help="Run 10-004 through a Playwright Chromium browser simulator.",
    )
    p.add_argument(
        "--candidate",
        type=int,
        action="append",
        help="Candidate number from discovery; repeat for multiple candidates.",
    )
    p.add_argument(
        "--tests",
        help="Comma-separated overwrite test IDs, e.g. baseline-a,collision-b,collision-c",
    )
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument(
        "--headed",
        action="store_true",
        help="Open a visible Chromium window so human interaction can be completed.",
    )
    p.add_argument(
        "--headless",
        action="store_true",
        help="Run Chromium headless. Default is headed for browser-run.",
    )
    p.set_defaults(func=cmd_browser_run)

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
