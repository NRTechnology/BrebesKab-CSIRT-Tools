#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Checklist 10-001 - File Upload Discovery

Purpose
-------
Discover and inventory potential file-upload attack surfaces without
performing any upload operation.

Safety boundary
---------------
- Same-origin only.
- Authenticated session from the existing project session artifact.
- GET-only discovery.
- No multipart POST/PUT/PATCH upload.
- No file creation, overwrite, deletion, execution, callback, or persistence.
- Discovery evidence is preserved; discovery alone is never a finding.
- HTTP errors and reflected upload-related strings are forensic signals only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import (
    parse_qsl,
    urljoin,
    urlparse,
    urlunparse,
)

import requests
import yaml

# Canonical project/session APIs used by authentication/session.py.
try:
    SCRIPTS_DIR = Path(__file__).resolve().parents[1]
    if str(SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPTS_DIR))
    from context import load_active_context, get_active_project_path
    from secrets import decrypt
except ImportError as exc:
    raise SystemExit(f"[ERROR] Modul context/secrets tidak dapat dimuat: {exc}")


SCRIPT_NAME = "discovery.py"
SCRIPT_VERSION = "1.0.1"
CHECKLIST_ID = "10-001"
CHECKLIST_NAME = "File Upload Discovery"
PHASE_NAME = "10 File Upload"
SCHEMA_VERSION = "1.0"

DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_LINKS = 0
DEFAULT_MAX_CANDIDATES = 200
DEFAULT_MAX_PARAMS_PER_URL = 5
DEFAULT_TIMEOUT = 20
BODY_SAMPLE_LIMIT = 12000
USER_AGENT = "BrebesKab-CSIRT-Tools/10-001-file-upload-discovery"

UPLOAD_INPUT_RE = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*["']?file["']?[^>]*>""",
    re.I | re.S,
)

FORM_RE = re.compile(r"<form\b[^>]*>.*?</form\s*>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>", re.S)

ATTR_RE = re.compile(
    r"""(?P<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*
        (?P<quote>["'])(?P<value>.*?)(?P=quote)""",
    re.I | re.S | re.X,
)

ACTION_RE = re.compile(
    r"""\baction\s*=\s*["']([^"']*)["']""",
    re.I,
)

ENCTYPE_RE = re.compile(
    r"""\benctype\s*=\s*["']([^"']*)["']""",
    re.I,
)

METHOD_RE = re.compile(
    r"""\bmethod\s*=\s*["']([^"']*)["']""",
    re.I,
)

INPUT_FILE_NAME_RE = re.compile(
    r"""<input\b[^>]*\btype\s*=\s*["']?file["']?[^>]*\bname\s*=\s*
        ["']([^"']+)["']""",
    re.I | re.S | re.X,
)

NAME_RE = re.compile(
    r"""\bname\s*=\s*["']([^"']+)["']""",
    re.I,
)

UPLOAD_KEYWORD_RE = re.compile(
    r"""(?ix)
    \b(?:upload|fileupload|file_upload|attachment|attach|document|dokumen|
       lampiran|berkas|file|image|images|gambar|photo|foto|media|import|
       impor|bulk[_-]?upload|unggah|unduh)\b
    """
)

UPLOAD_URL_RE = re.compile(
    r"""(?ix)
    (?:^|[/_.-])
    (?:upload|fileupload|file_upload|attachment|attach|document|dokumen|
       lampiran|berkas|file|image|images|gambar|photo|foto|media|import|
       impor|bulk-upload|bulk_upload|unggah)
    (?:[/_.?&=-]|$)
    """
)

UPLOAD_ACTION_HINT_RE = re.compile(
    r"""(?ix)
    \b(?:upload|fileupload|file_upload|attachment|attach|document|dokumen|
       lampiran|berkas|unggah|import|impor)\b
    """
)

COMMON_UPLOAD_PATH_RE = re.compile(
    r"""(?ix)
    (?:^|/)
    (?:upload|uploads|file|files|attachment|attachments|document|documents|
       dokumen|lampiran|media|images|image|foto|photos|storage)
    (?:/|$)
    """
)


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def repo_root() -> Path:
    # scripts/fileupload/discovery.py -> repository root
    return Path(__file__).resolve().parents[2]


def runtime_dir() -> Path:
    return repo_root() / ".runtime"


def active_project_file() -> Path:
    """Return the canonical runtime active-project.yaml file."""
    return runtime_dir() / "active-project.yaml"


def load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(str(path))
    with path.open("r", encoding="utf-8-sig") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root harus object: {path}")
    return data


def save_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        yaml.safe_dump(
            data,
            fh,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def body_sample(body: str) -> str:
    if len(body) <= BODY_SAMPLE_LIMIT:
        return body
    return body[:BODY_SAMPLE_LIMIT] + "\n...[truncated]"


def normalize_url(url: str, base: Optional[str] = None) -> Optional[str]:
    if not url:
        return None

    candidate = urljoin(base or "", url.strip())
    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in {"http", "https"}:
        return None

    fragment_removed = parsed._replace(fragment="")
    return urlunparse(fragment_removed)


def origin_tuple(url: str) -> Tuple[str, str, Optional[int]]:
    p = urlparse(url)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()

    # urlparse().port raises ValueError for malformed ports such as
    # "https://example.test:blank/". A malformed discovered URL must
    # not terminate the discovery crawl.
    try:
        explicit_port = p.port
    except ValueError:
        return scheme, host, None

    if explicit_port is not None:
        port = explicit_port
    elif scheme == "https":
        port = 443
    else:
        port = 80

    return scheme, host, port


def same_origin(url: str, target: str) -> bool:
    left = origin_tuple(url)
    right = origin_tuple(target)

    # Treat malformed/unknown ports as out-of-scope rather than allowing
    # them to match the target or abort the crawl.
    if left[2] is None or right[2] is None:
        return False

    return left == right


def active_context() -> Any:
    return load_active_context()


def project_root() -> Path:
    """Return the canonical active project directory."""
    return Path(get_active_project_path()).resolve()


def project_id_from_active(active: Dict[str, Any]) -> str:
    try:
        return str(active_context().project_id)
    except Exception:
        for key in ("project_id", "id", "project"):
            value = active.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        raise ValueError("project_id tidak ditemukan di active project context.")


def project_path_from_active(active: Dict[str, Any]) -> Path:
    # active-project.yaml is authoritative for project identity; the
    # canonical context API resolves the corresponding project directory.
    configured = active.get("project_path")
    if isinstance(configured, str) and configured.strip():
        candidate = Path(configured.strip())
        if not candidate.is_absolute():
            candidate = repo_root() / candidate
        return candidate.resolve()
    return project_root()


def artifact_dir(project_path: Path) -> Path:
    return project_path / "10-file-upload" / "discovery"


def artifact_path(project_path: Path) -> Path:
    return artifact_dir(project_path) / "discovery.yaml"


def evidence_path(project_path: Path) -> Path:
    return artifact_dir(project_path) / "evidence" / "discovery-evidence.json"


def load_scope(project_path: Path) -> Dict[str, Any]:
    data = load_yaml(project_path / "01-preparation" / "scope" / "scope.yaml")
    active = active_context()
    active_project_id = str(getattr(active, "project_id", "") or "").strip()
    scope_project_id = str(data.get("project_id", "")).strip()
    if active_project_id and scope_project_id and scope_project_id != active_project_id:
        raise ValueError(
            f"scope.yaml project_id ({scope_project_id}) tidak sama dengan "
            f"active project ({active_project_id})"
        )
    return data


def load_session(project_path: Path) -> Dict[str, Any]:
    return load_yaml(
        project_path / "07-authentication" / "session" / "session.yaml"
    )


def session_source_ok(session: Dict[str, Any]) -> bool:
    if not isinstance(session, dict):
        return False

    status = session.get("status")
    if isinstance(status, str) and status.lower() in {"completed", "active", "valid"}:
        return True

    if isinstance(session.get("session"), dict):
        nested = session["session"]
        nested_status = nested.get("status")
        if isinstance(nested_status, str) and nested_status.lower() in {
            "completed",
            "active",
            "valid",
        }:
            return True

    # Existing toolkit session artifacts may use source_status rather than
    # a top-level status. Do not inspect or persist plaintext credentials.
    source_status = session.get("source_status")
    if isinstance(source_status, dict):
        value = source_status.get("status") or source_status.get("session")
        if isinstance(value, str) and value.lower() in {
            "completed",
            "active",
            "valid",
        }:
            return True

    return True


def scope_target(scope: Dict[str, Any]) -> Dict[str, Any]:
    scope_block = scope.get("scope")
    if not isinstance(scope_block, dict):
        raise ValueError("scope.yaml: field 'scope' tidak valid.")
    in_scope = scope_block.get("in_scope")
    if not isinstance(in_scope, list) or not in_scope:
        raise ValueError("scope.yaml: scope.in_scope tidak tersedia.")
    for item in in_scope:
        if not isinstance(item, dict):
            continue
        if str(item.get("type", "")).strip().lower() == "domain" and str(item.get("value", "")).strip():
            return item
        for key in ("hostname", "domain", "host", "url", "target"):
            if str(item.get(key, "")).strip():
                return item
    raise ValueError("scope.in_scope tidak memiliki target domain/hostname.")


def target_from_scope(scope: Dict[str, Any]) -> str:
    item = scope_target(scope)
    hostname = str(item.get("value", "")).strip() if str(item.get("type", "")).lower() == "domain" else ""
    if not hostname:
        for key in ("hostname", "domain", "host"):
            if str(item.get(key, "")).strip():
                hostname = str(item[key]).strip()
                break
    explicit_url = ""
    for key in ("url", "target"):
        if str(item.get(key, "")).strip():
            explicit_url = str(item[key]).strip()
            break
    if not hostname and explicit_url:
        hostname = urlparse(explicit_url).hostname or ""
    if not hostname:
        raise ValueError("Hostname/domain pada scope.yaml tidak dapat ditentukan.")
    ports = item.get("ports") if isinstance(item.get("ports"), list) else []
    normalized_ports = []
    for port in ports:
        try:
            normalized_ports.append(int(port))
        except (TypeError, ValueError):
            pass
    if explicit_url:
        return normalize_url(explicit_url) or explicit_url
    if 443 in normalized_ports:
        return f"https://{hostname}"
    if 80 in normalized_ports:
        return f"http://{hostname}"
    raise ValueError("Target HTTP/HTTPS pada scope.yaml tidak dapat ditentukan. Pastikan port 80 atau 443 authorized.")


def determine_target(scope: Dict[str, Any], active: Dict[str, Any]) -> str:
    return target_from_scope(scope)


def extract_links(html: str, base_url: str) -> List[str]:
    links: List[str] = []

    for match in re.finditer(
        r"""<(?:a|area|link|script|img|iframe|source|video|audio|form)\b[^>]*>""",
        html,
        re.I | re.S,
    ):
        tag = match.group(0)

        href_match = re.search(
            r"""\b(?:href|src|action)\s*=\s*["']([^"']+)["']""",
            tag,
            re.I | re.S,
        )
        if not href_match:
            continue

        normalized = normalize_url(href_match.group(1), base_url)
        if normalized:
            links.append(normalized)

    result = []
    seen = set()
    for link in links:
        if same_origin(link, base_url) and link not in seen:
            seen.add(link)
            result.append(link)

    return result


def tag_attributes(tag: str) -> Dict[str, str]:
    attrs: Dict[str, str] = {}
    for match in ATTR_RE.finditer(tag):
        attrs[match.group("name").lower()] = match.group("value")
    return attrs


def detect_file_inputs(form_html: str) -> List[Dict[str, Any]]:
    inputs: List[Dict[str, Any]] = []

    for match in UPLOAD_INPUT_RE.finditer(form_html):
        tag = match.group(0)
        attrs = tag_attributes(tag)

        inputs.append(
            {
                "type": attrs.get("type", "file"),
                "name": attrs.get("name", ""),
                "id": attrs.get("id", ""),
                "accept": attrs.get("accept", ""),
                "multiple": "multiple" in attrs,
                "required": "required" in attrs,
                "name_hint": bool(
                    UPLOAD_KEYWORD_RE.search(attrs.get("name", ""))
                ),
                "tag_sha256": sha256_text(tag),
            }
        )

    return inputs


def classify_upload_surface(
    form_html: str,
    action_url: str,
    file_inputs: List[Dict[str, Any]],
) -> List[str]:
    signals: List[str] = []

    enctype_match = ENCTYPE_RE.search(form_html)
    if enctype_match:
        enctype = enctype_match.group(1).lower()
        if "multipart/form-data" in enctype:
            signals.append("multipart_form")

    if file_inputs:
        signals.append("file_input")

    if UPLOAD_ACTION_HINT_RE.search(action_url):
        signals.append("upload_related_action")

    if UPLOAD_KEYWORD_RE.search(form_html):
        signals.append("upload_keyword")

    return sorted(set(signals))


def discover_forms(html: str, page_url: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for index, match in enumerate(FORM_RE.finditer(html), start=1):
        form_html = match.group(0)
        attrs_match = re.match(r"<form\b[^>]*>", form_html, re.I | re.S)
        form_tag = attrs_match.group(0) if attrs_match else "<form>"

        attrs = tag_attributes(form_tag)
        raw_action = attrs.get("action", "")
        action_url = normalize_url(raw_action, page_url) if raw_action else page_url

        if not action_url:
            action_url = page_url

        method = attrs.get("method", "get").upper()
        enctype = attrs.get("enctype", "").lower()
        file_inputs = detect_file_inputs(form_html)
        signals = classify_upload_surface(form_html, action_url, file_inputs)

        if not file_inputs and "multipart_form" not in signals:
            continue

        same_origin_action = same_origin(action_url, page_url)

        results.append(
            {
                "form_index": index,
                "page_url": page_url,
                "action_url": action_url,
                "method": method,
                "enctype": enctype,
                "same_origin_action": same_origin_action,
                "file_inputs": file_inputs,
                "signals": signals,
                "form_sha256": sha256_text(form_html),
                "form_length": len(form_html),
            }
        )

    return results


def discover_upload_related_links(
    html: str,
    page_url: str,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for url in extract_links(html, page_url):
        parsed = urlparse(url)
        path_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path

        keyword_match = UPLOAD_URL_RE.search(path_query)
        common_path_match = COMMON_UPLOAD_PATH_RE.search(parsed.path)

        if not keyword_match and not common_path_match:
            continue

        findings.append(
            {
                "url": url,
                "path": parsed.path,
                "query": parsed.query,
                "signal": (
                    "upload_keyword_in_url"
                    if keyword_match
                    else "common_upload_storage_path_hint"
                ),
                "url_sha256": sha256_text(url),
            }
        )

    return findings


def discover_upload_keywords(
    html: str,
    page_url: str,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for match in UPLOAD_KEYWORD_RE.finditer(html):
        start = max(0, match.start() - 120)
        end = min(len(html), match.end() + 120)
        context = TAG_RE.sub(" ", html[start:end])
        context = re.sub(r"\s+", " ", context).strip()

        findings.append(
            {
                "page_url": page_url,
                "keyword": match.group(0),
                "context": context[:500],
                "context_sha256": sha256_text(context),
            }
        )

        if len(findings) >= 50:
            break

    return findings


def request_snapshot(
    session: requests.Session,
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
        )

        content_type = response.headers.get("Content-Type", "")
        try:
            body = response.text
        except Exception:
            body = response.content.decode("utf-8", errors="replace")

        return {
            "ok": True,
            "request": {
                "method": "GET",
                "url": url,
                "redirect_following": False,
            },
            "response": {
                "status": response.status_code,
                "url": response.url,
                "content_type": content_type,
                "content_length": len(response.content),
                "body_sha256": sha256_bytes(response.content),
                "body_sample": body_sample(body),
                "headers": {
                    key: value
                    for key, value in response.headers.items()
                    if key.lower()
                    not in {"set-cookie", "authorization", "proxy-authorization"}
                },
            },
            "_body": body,
        }

    except requests.RequestException as exc:
        return {
            "ok": False,
            "request": {
                "method": "GET",
                "url": url,
                "redirect_following": False,
            },
            "error": type(exc).__name__,
            "error_message": str(exc)[:500],
            "_body": "",
        }


def candidate_score(
    surface: Dict[str, Any],
) -> int:
    score = 0
    signals = set(surface.get("signals", []))

    if "file_input" in signals:
        score += 50
    if "multipart_form" in signals:
        score += 30
    if "upload_related_action" in signals:
        score += 20
    if "upload_keyword" in signals:
        score += 10

    for item in surface.get("file_inputs", []):
        if item.get("name_hint"):
            score += 5
        if item.get("accept"):
            score += 5

    return min(score, 100)


def build_candidate(surface: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": "form",
        "page_url": surface["page_url"],
        "action_url": surface["action_url"],
        "method": surface["method"],
        "enctype": surface["enctype"],
        "same_origin_action": surface["same_origin_action"],
        "file_inputs": surface["file_inputs"],
        "signals": surface["signals"],
        "priority_score": candidate_score(surface),
        "discovery_only": True,
        "upload_performed": False,
        "finding": False,
        "requires_review": False,
    }


def build_artifact(
    project_id: str,
    target_url: str,
    results: Dict[str, Any],
    source_status: Dict[str, Any],
) -> Dict[str, Any]:
    return {
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
            "focus": (
                "Discover potential file-upload attack surfaces from same-origin "
                "pages and forms without performing uploads."
            ),
            "status": "completed",
        },
        "target": {
            "application": project_id,
            "url": target_url,
            "environment": "Production",
            "assessment_type": "Black Box",
        },
        "methodology": {
            "description": (
                "Same-origin authenticated GET crawl to identify file inputs, "
                "multipart forms, upload-related actions and upload-related URL hints."
            ),
            "authenticated_session_required": True,
            "same_origin_only": True,
            "redirect_following": False,
            "get_only_discovery": True,
            "upload_performed": False,
            "multipart_post_performed": False,
            "file_creation": False,
            "file_overwrite": False,
            "file_deletion": False,
            "file_execution": False,
            "external_callbacks": False,
            "persistence": False,
            "automatic_finding": False,
            "discovery_is_finding": False,
            "forensic_evidence_preserved": True,
        },
        "baseline": {
            "active_project": ".runtime/active-project.yaml",
            "project_path_source": "active-project.yaml:project_path",
            "scope_source": "01-preparation/scope/scope.yaml",
            "session_source": "07-authentication/session/session.yaml",
        },
        "toolchain": {
            "mandatory": [
                "Python",
                "requests",
                "PyYAML",
            ],
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
        "discovery_policy": {
            "crawl": {
                "max_links": DEFAULT_MAX_LINKS,
                "max_depth": DEFAULT_MAX_DEPTH,
                "max_candidates": DEFAULT_MAX_CANDIDATES,
                "max_params_per_url": DEFAULT_MAX_PARAMS_PER_URL,
            },
            "detect": [
                "input_type_file",
                "multipart_form",
                "upload_related_action",
                "upload_related_url",
                "upload_related_keyword",
            ],
            "finding_policy": (
                "Discovery signal alone is never a vulnerability finding."
            ),
        },
        "source_status": source_status,
        "results": results,
        "notes": [
            "Discovery does not perform any file upload.",
            "A file input or multipart form is an attack-surface signal, not a finding.",
            "Upload-related URL or keyword matches are forensic/discovery signals only.",
            "GET requests are used only to retrieve pages for passive discovery.",
            "Redirect following is disabled.",
            "External-origin forms are recorded but are not treated as in-scope upload targets.",
            "No executable, web-shell, callback, overwrite, delete, or persistence payload is used.",
            "Manual review is required before treating a discovered endpoint as an upload vulnerability.",
        ],
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }


def cmd_version(_: argparse.Namespace) -> int:
    print("BrebesKab-CSIRT-Tools File Upload Discovery")
    print(f"Version   : {SCRIPT_VERSION}")
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Phase     : {PHASE_NAME}")
    print(f"Schema    : {SCHEMA_VERSION}")
    print("Boundary  : discovery only; no upload operation")
    return 0


def get_project_context() -> Tuple[str, Path, Dict[str, Any], Dict[str, Any], str]:
    # Read .runtime/active-project.yaml first.  It identifies the active
    # project; the project_path field is used as the artifact root.
    active = load_yaml(active_project_file())
    project_id = project_id_from_active(active)
    project_path = project_path_from_active(active)
    scope = load_scope(project_path)
    session = load_session(project_path)
    target_url = determine_target(scope, active)
    return project_id, project_path, scope, session, target_url


def cmd_init(_: argparse.Namespace) -> int:
    project_id, project_path, scope, session, target_url = get_project_context()

    if not session_source_ok(session):
        raise ValueError("Session artifact tidak valid atau belum siap.")

    path = artifact_path(project_path)
    evidence = evidence_path(project_path)

    artifact = build_artifact(
        project_id=project_id,
        target_url=target_url,
        results={
            "status": "initialized",
            "pages_requested": 0,
            "pages_completed": 0,
            "links_discovered": 0,
            "same_origin_links": 0,
            "upload_forms": 0,
            "file_inputs": 0,
            "multipart_forms": 0,
            "upload_related_urls": 0,
            "upload_keyword_signals": 0,
            "candidates": 0,
            "request_errors": 0,
            "http_errors": 0,
            "findings": 0,
            "requires_review": 0,
        },
        source_status={
            "active_project": "completed",
            "scope": "completed",
            "session": "completed",
        },
    )

    save_yaml(path, artifact)
    save_json(
        evidence,
        {
            "schema_version": SCHEMA_VERSION,
            "project_id": project_id,
            "checklist_id": CHECKLIST_ID,
            "status": "initialized",
            "pages": [],
            "forms": [],
            "upload_related_urls": [],
            "upload_keyword_signals": [],
            "created_at": utc_now(),
        },
    )

    print("[PASS] File Upload Discovery artifact siap.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {project_id}")
    print(f"[PASS] File      : {path}")
    return 0


def cmd_crawl(args: argparse.Namespace) -> int:
    project_id, project_path, scope, session_data, target_url = get_project_context()

    if not same_origin(target_url, target_url):
        raise ValueError("Target URL tidak valid.")

    # Session artifacts are deliberately handled through the toolkit's
    # established authenticated session mechanism. This script supports
    # cookie-bearing session artifacts when cookies are available, while
    # never printing or persisting credential values.
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )

    if not apply_authenticated_session(session, session_data, target_url):
        raise ValueError(
            "Session artifact tidak memiliki sesi SUCCESS yang dapat digunakan "
            "untuk target aktif."
        )

    max_depth = args.max_depth
    max_links = args.max_links
    max_candidates = args.max_candidates

    queue: List[Tuple[str, int]] = [(target_url, 0)]
    visited = set()
    discovered_links = set()
    pages: List[Dict[str, Any]] = []
    forms: List[Dict[str, Any]] = []
    upload_related_urls: List[Dict[str, Any]] = []
    keyword_signals: List[Dict[str, Any]] = []

    request_errors = 0
    http_errors = 0

    while queue:
        current_url, depth = queue.pop(0)

        if current_url in visited:
            continue

        if depth > max_depth:
            continue

        if not same_origin(current_url, target_url):
            continue

        visited.add(current_url)

        if max_links and len(visited) > max_links:
            break

        snapshot = request_snapshot(session, current_url, args.timeout)

        if not snapshot["ok"]:
            request_errors += 1
            pages.append(
                {
                    "url": current_url,
                    "depth": depth,
                    "status": "request_error",
                    "error": snapshot.get("error"),
                    "error_message": snapshot.get("error_message"),
                }
            )
            continue

        response = snapshot["response"]
        body = snapshot.get("_body", "")
        status_code = int(response["status"])

        if status_code >= 400:
            http_errors += 1

        page_record = {
            "url": current_url,
            "depth": depth,
            "status": status_code,
            "content_type": response.get("content_type", ""),
            "content_length": response.get("content_length", 0),
            "body_sha256": response.get("body_sha256"),
            "upload_surface": False,
        }

        page_forms = discover_forms(body, current_url)

        for form in page_forms:
            if not form["same_origin_action"]:
                form["scope_note"] = (
                    "External-origin action; recorded as discovery signal only."
                )

            forms.append(form)

        related_urls = discover_upload_related_links(body, current_url)
        upload_related_urls.extend(related_urls)

        page_keywords = discover_upload_keywords(body, current_url)
        keyword_signals.extend(page_keywords)

        if page_forms:
            page_record["upload_surface"] = True

        pages.append(page_record)

        for link in extract_links(body, current_url):
            if not same_origin(link, target_url):
                continue

            if link not in discovered_links:
                discovered_links.add(link)
                if len(discovered_links) <= max_candidates:
                    queue.append((link, depth + 1))

    # De-duplicate forms and URL signals deterministically.
    forms = dedupe_dicts(
        forms,
        keys=("page_url", "action_url", "form_sha256"),
    )

    upload_related_urls = dedupe_dicts(
        upload_related_urls,
        keys=("url", "signal"),
    )

    keyword_signals = dedupe_dicts(
        keyword_signals,
        keys=("page_url", "keyword", "context_sha256"),
    )

    file_input_count = sum(
        len(form.get("file_inputs", []))
        for form in forms
    )

    multipart_count = sum(
        1
        for form in forms
        if "multipart_form" in form.get("signals", [])
    )

    candidates = [
        build_candidate(form)
        for form in forms
        if form.get("same_origin_action")
    ]

    candidates.sort(
        key=lambda item: (
            -int(item.get("priority_score", 0)),
            item.get("page_url", ""),
            item.get("action_url", ""),
        )
    )

    candidates = candidates[:max_candidates]

    results = {
        "status": "crawled",
        "pages_requested": len(visited),
        "pages_completed": len(
            [item for item in pages if item.get("status") != "request_error"]
        ),
        "links_discovered": len(discovered_links),
        "same_origin_links": len(
            [url for url in discovered_links if same_origin(url, target_url)]
        ),
        "upload_forms": len(forms),
        "file_inputs": file_input_count,
        "multipart_forms": multipart_count,
        "upload_related_urls": len(upload_related_urls),
        "upload_keyword_signals": len(keyword_signals),
        "candidates": len(candidates),
        "request_errors": request_errors,
        "http_errors": http_errors,
        "findings": 0,
        "requires_review": 0,
        "upload_performed": False,
    }

    source_status = {
        "active_project": "completed",
        "scope": "completed",
        "session": "completed",
    }

    artifact = build_artifact(
        project_id=project_id,
        target_url=target_url,
        results=results,
        source_status=source_status,
    )

    artifact["crawl"] = {
        "seed": target_url,
        "visited": sorted(visited),
        "links": sorted(discovered_links),
    }

    artifact["candidates"] = candidates

    save_yaml(artifact_path(project_path), artifact)

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "checklist_id": CHECKLIST_ID,
        "target": target_url,
        "pages": pages,
        "forms": forms,
        "upload_related_urls": upload_related_urls,
        "upload_keyword_signals": keyword_signals,
        "candidates": candidates,
        "created_at": utc_now(),
    }

    save_json(evidence_path(project_path), evidence)

    print("[PASS] File Upload Discovery crawl selesai.")
    print(f"[PASS] Project            : {project_id}")
    print(f"[PASS] Pages              : {len(visited)}")
    print(f"[PASS] Links              : {len(discovered_links)}")
    print(f"[PASS] Upload forms       : {len(forms)}")
    print(f"[PASS] File inputs        : {file_input_count}")
    print(f"[PASS] Multipart forms    : {multipart_count}")
    print(f"[PASS] Upload URL signals : {len(upload_related_urls)}")
    print(f"[PASS] Candidates         : {len(candidates)}")
    print(f"[PASS] Request errors     : {request_errors}")
    print(f"[PASS] HTTP errors        : {http_errors}")
    print("[PASS] Upload performed   : 0")
    print(f"[PASS] Evidence           : {evidence_path(project_path)}")
    return 0


def apply_authenticated_session(
    session: requests.Session,
    session_data: Dict[str, Any],
    target_url: str,
) -> bool:
    """Apply the canonical successful encrypted session in memory.

    The session artifact may contain either a cookie or an authorization
    header.  Decrypted credential material is never printed or persisted.
    """
    records = session_data.get("sessions")
    if not isinstance(records, list):
        return False

    target_host = (urlparse(target_url).hostname or "").lower()

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

        target = record.get("target")
        record_url = (
            str(target.get("url") or "").strip()
            if isinstance(target, dict)
            else ""
        )
        if record_url:
            record_host = (urlparse(record_url).hostname or "").lower()
            if record_host and record_host != target_host:
                continue

        auth = record.get("authentication")
        if not isinstance(auth, dict):
            continue

        encrypted = str(auth.get("value_encrypted") or "").strip()
        if not encrypted:
            continue

        try:
            value = decrypt(
                encrypted,
                project_id=active_context().project_id,
            )
        except Exception:
            continue

        auth_type = str(auth.get("type") or "cookie").strip().lower()

        try:
            if auth_type == "cookie":
                name = str(auth.get("name") or "").strip()
                if not name:
                    continue

                domain = str(auth.get("domain") or "").strip() or None
                path = str(auth.get("path") or "/").strip() or "/"

                if domain:
                    session.cookies.set(
                        name,
                        value,
                        domain=domain,
                        path=path,
                    )
                else:
                    session.cookies.set(name, value, path=path)
            else:
                header_name = (
                    str(auth.get("header_name") or "Authorization").strip()
                    or "Authorization"
                )
                session.headers.update({header_name: value})
        finally:
            # Drop our local plaintext reference as soon as it is applied.
            value = None

        return True

    return False


def dedupe_dicts(
    items: Iterable[Dict[str, Any]],
    keys: Tuple[str, ...],
) -> List[Dict[str, Any]]:
    result = []
    seen = set()

    for item in items:
        identity = tuple(
            json.dumps(item.get(key), sort_keys=True, ensure_ascii=False)
            for key in keys
        )

        if identity in seen:
            continue

        seen.add(identity)
        result.append(item)

    return result


def load_artifact_for_project(project_path: Path) -> Dict[str, Any]:
    path = artifact_path(project_path)
    return load_yaml(path)


def cmd_show(_: argparse.Namespace) -> int:
    _, project_path, _, _, _ = get_project_context()
    artifact = load_artifact_for_project(project_path)

    print(yaml.safe_dump(
        artifact,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    ).rstrip())

    return 0


def cmd_status(_: argparse.Namespace) -> int:
    _, project_path, _, _, _ = get_project_context()
    path = artifact_path(project_path)

    if not path.exists():
        print("[INFO] File Upload Discovery artifact belum ada.")
        return 0

    artifact = load_yaml(path)
    checklist = artifact.get("checklist", {})
    results = artifact.get("results", {})

    print("BrebesKab-CSIRT-Tools File Upload Discovery")
    print(f"Version   : {artifact.get('tool', {}).get('version', SCRIPT_VERSION)}")
    print(
        f"Checklist : {checklist.get('id', CHECKLIST_ID)} "
        f"{checklist.get('name', CHECKLIST_NAME)}"
    )
    print(f"Status    : {checklist.get('status', 'unknown')}")
    print(f"Results   : {results.get('status', 'unknown')}")
    print(f"Candidates: {results.get('candidates', 0)}")
    print(f"Findings  : {results.get('findings', 0)}")
    print(f"Review    : {results.get('requires_review', 0)}")
    print(f"Upload    : {'yes' if results.get('upload_performed') else 'no'}")
    return 0


def cmd_verify(_: argparse.Namespace) -> int:
    project_id, project_path, _, _, target_url = get_project_context()
    path = artifact_path(project_path)
    evidence = evidence_path(project_path)

    if not path.exists():
        raise ValueError(f"Artifact tidak ditemukan: {path}")

    artifact = load_yaml(path)

    errors: List[str] = []

    if artifact.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai")

    tool = artifact.get("tool", {})
    if tool.get("name") != "BrebesKab-CSIRT-Tools":
        errors.append("tool.name tidak sesuai")
    if tool.get("script") != SCRIPT_NAME:
        errors.append("tool.script tidak sesuai")
    if tool.get("version") != SCRIPT_VERSION:
        errors.append("tool.version tidak sesuai")

    checklist = artifact.get("checklist", {})
    if checklist.get("id") != CHECKLIST_ID:
        errors.append("checklist.id tidak sesuai")
    if checklist.get("name") != CHECKLIST_NAME:
        errors.append("checklist.name tidak sesuai")
    if checklist.get("phase") != PHASE_NAME:
        errors.append("checklist.phase tidak sesuai")

    if artifact.get("project_id") != project_id:
        errors.append("project_id tidak sesuai")

    methodology = artifact.get("methodology", {})
    required_true = [
        "authenticated_session_required",
        "same_origin_only",
        "get_only_discovery",
        "forensic_evidence_preserved",
    ]
    required_false = [
        "redirect_following",
        "upload_performed",
        "multipart_post_performed",
        "file_creation",
        "file_overwrite",
        "file_deletion",
        "file_execution",
        "external_callbacks",
        "persistence",
        "automatic_finding",
        "discovery_is_finding",
    ]

    for key in required_true:
        if methodology.get(key) is not True:
            errors.append(f"methodology.{key} harus true")

    for key in required_false:
        if methodology.get(key) is not False:
            errors.append(f"methodology.{key} harus false")

    baseline = artifact.get("baseline", {})
    if baseline.get("active_project") != ".runtime/active-project.yaml":
        errors.append("baseline.active_project tidak sesuai")
    if baseline.get("scope_source") != "01-preparation/scope/scope.yaml":
        errors.append("baseline.scope_source tidak sesuai")
    if baseline.get("session_source") != "07-authentication/session/session.yaml":
        errors.append("baseline.session_source tidak sesuai")

    target = artifact.get("target", {})
    if target.get("url") != target_url:
        errors.append("target.url tidak sesuai active scope")

    source_status = artifact.get("source_status", {})
    for key in ("active_project", "scope", "session"):
        if source_status.get(key) != "completed":
            errors.append(f"source_status.{key} harus completed")

    results = artifact.get("results", {})
    numeric_fields = [
        "pages_requested",
        "pages_completed",
        "links_discovered",
        "same_origin_links",
        "upload_forms",
        "file_inputs",
        "multipart_forms",
        "upload_related_urls",
        "upload_keyword_signals",
        "candidates",
        "request_errors",
        "http_errors",
        "findings",
        "requires_review",
    ]

    for key in numeric_fields:
        if not isinstance(results.get(key), int):
            errors.append(f"results.{key} harus integer")
        elif results.get(key) < 0:
            errors.append(f"results.{key} tidak boleh negatif")

    if results.get("findings") != 0:
        errors.append("Discovery tidak boleh menghasilkan finding otomatis")

    if results.get("requires_review") != 0:
        errors.append("Discovery tidak boleh menetapkan manual review otomatis")

    if results.get("upload_performed") is not False:
        errors.append("results.upload_performed harus false")

    candidates = artifact.get("candidates", [])
    if not isinstance(candidates, list):
        errors.append("candidates harus list")
    else:
        for index, candidate in enumerate(candidates):
            if candidate.get("discovery_only") is not True:
                errors.append(
                    f"candidate[{index}].discovery_only harus true"
                )
            if candidate.get("upload_performed") is not False:
                errors.append(
                    f"candidate[{index}].upload_performed harus false"
                )
            if candidate.get("finding") is not False:
                errors.append(
                    f"candidate[{index}].finding harus false"
                )
            if candidate.get("requires_review") is not False:
                errors.append(
                    f"candidate[{index}].requires_review harus false"
                )

    if not evidence.exists():
        errors.append(f"Evidence tidak ditemukan: {evidence}")
    else:
        try:
            evidence_data = load_json(evidence)
            if evidence_data.get("checklist_id") != CHECKLIST_ID:
                errors.append("Evidence checklist_id tidak sesuai")
            if evidence_data.get("project_id") != project_id:
                errors.append("Evidence project_id tidak sesuai")
        except Exception as exc:
            errors.append(f"Evidence tidak dapat dibaca: {exc}")

    if errors:
        print("[FAIL] File Upload Discovery tidak memenuhi validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    print("[PASS] File Upload Discovery memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {project_id}")
    print(f"[PASS] File      : {path}")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(f"[PASS] Findings  : {results.get('findings', 0)}")
    print(f"[PASS] Review    : {results.get('requires_review', 0)}")
    print("[PASS] Upload    : 0")
    print("[PASS] Encoding  : UTF-8 tanpa BOM")
    return 0


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def cmd_remove(_: argparse.Namespace) -> int:
    _, project_path, _, _, _ = get_project_context()
    directory = artifact_dir(project_path)

    if not directory.exists():
        print("[INFO] Artifact File Upload Discovery belum ada.")
        return 0

    # Remove only this checklist's artifact directory.
    import shutil
    shutil.rmtree(directory)

    print("[PASS] File Upload Discovery artifact dihapus.")
    print(f"[PASS] Directory : {directory}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools File Upload Discovery (10-001)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_version = subparsers.add_parser("version")
    p_version.set_defaults(func=cmd_version)

    p_init = subparsers.add_parser("init")
    p_init.set_defaults(func=cmd_init)

    p_crawl = subparsers.add_parser("crawl")
    p_crawl.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    p_crawl.add_argument("--max-links", type=int, default=DEFAULT_MAX_LINKS)
    p_crawl.add_argument(
        "--max-candidates",
        type=int,
        default=DEFAULT_MAX_CANDIDATES,
    )
    p_crawl.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p_crawl.set_defaults(func=cmd_crawl)

    p_show = subparsers.add_parser("show")
    p_show.set_defaults(func=cmd_show)

    p_status = subparsers.add_parser("status")
    p_status.set_defaults(func=cmd_status)

    p_verify = subparsers.add_parser("verify")
    p_verify.set_defaults(func=cmd_verify)

    p_remove = subparsers.add_parser("remove")
    p_remove.set_defaults(func=cmd_remove)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("[FAIL] Dibatalkan oleh pengguna.")
        return 130
    except Exception as exc:
        print(f"[FAIL] {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
