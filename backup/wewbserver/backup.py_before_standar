#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Checklist 4-004 - Backup File Exposure

Controlled backup/configuration artifact exposure assessment.

Design principles:
- Scope is authoritative from the project scope artifact.
- Recon directory.yaml is used as supporting candidate evidence.
- Built-in bounded backup candidates are always tested.
- Optional external discovery can use ffuf (preferred) or gobuster.
- Discovery is disabled by default for safety/reproducibility and must be
  explicitly enabled with --discover.
- No brute-force beyond the supplied wordlist.
- No mutation, archive extraction, Git clone, database import, or destructive
  action.
- Redirect following is disabled.
- Large responses are streamed and capped.
- Raw evidence is retained. Report redaction is a separate layer.
- Automatic vulnerability finding is disabled.

Commands:
    python backup.py version
    python backup.py init
    python backup.py analyze
    python backup.py analyze --discover
    python backup.py list
    python backup.py verify

Optional discovery:
    --discover
        Run ffuf if available, otherwise gobuster if available.

    --engine ffuf|gobuster
        Force a discovery engine. Without this option, ffuf is preferred.

    --wordlist PATH
        Use a custom discovery wordlist.

Discovery output is normalized into the checklist evidence artifact. The
discovery engine is a candidate generator only; Python re-probes and
classifies every discovered candidate before assessment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import requests
except ImportError:
    print("[ERROR] Python package 'requests' tidak tersedia.")
    print("[HINT] Install dengan: python -m pip install requests")
    sys.exit(1)


APP_NAME = "BrebesKab-CSIRT-Tools"
APP_VERSION = "1.0.1"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "4-004"
CHECKLIST_NAME = "Backup File Exposure"

METHODS = ["GET", "HEAD"]
DEFAULT_TIMEOUT = 15
MAX_CAPTURE_BYTES = 1024 * 1024  # 1 MiB
MAX_DISCOVERY_CANDIDATES = 500
MAX_DISCOVERY_WORDLIST_BYTES = 10 * 1024 * 1024

ROOT_CANDIDATE_PATHS = [
    "/config.php.bak",
    "/config.php.backup",
    "/config.php.old",
    "/config.php.orig",
    "/config.php.save",
    "/config.php~",
    "/index.php.bak",
    "/index.php.backup",
    "/index.php.old",
    "/index.php~",
    "/.env.bak",
    "/.env.backup",
    "/.env.old",
    "/backup.sql",
    "/backup.sql.gz",
    "/database.sql",
    "/database.sql.gz",
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.tgz",
    "/source.zip",
]

BACKUP_SUFFIXES = (
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".save",
    ".sav",
    ".copy",
    ".tmp",
    ".temp",
    "~",
)

ARCHIVE_SUFFIXES = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".gz",
    ".7z",
    ".rar",
)

DATABASE_SUFFIXES = (
    ".sql",
    ".sql.gz",
    ".sql.zip",
    ".dump",
    ".dump.gz",
)

CONFIG_NAMES = (
    "config",
    "configuration",
    "settings",
    "database",
    "db",
    ".env",
    "env",
)

SOURCE_NAMES = (
    "index.php",
    "config.php",
    "database.php",
    "autoload.php",
    "bootstrap.php",
)

GIT_STYLE_PREFIX = "/.git"

ENV_STYLE_PREFIX = "/.env"

MAGIC_SIGNATURES = {
    b"PK\x03\x04": "zip",
    b"PK\x05\x06": "zip-empty",
    b"PK\x07\x08": "zip-spanned",
    b"\x1f\x8b": "gzip",
    b"Rar!\x1a\x07": "rar",
    b"7z\xbc\xaf'\x1c": "7z",
}

PHP_MARKERS = (
    "<?php",
    "<?=",
    "declare(strict_types",
    "namespace ",
    "use codeigniter\\",
)

SQL_MARKERS = (
    "CREATE TABLE",
    "CREATE DATABASE",
    "INSERT INTO",
    "ALTER TABLE",
    "DROP TABLE",
    "-- MySQL dump",
    "-- MariaDB dump",
)

ENV_MARKERS = (
    "APP_ENV=",
    "APP_DEBUG=",
    "APP_URL=",
    "DB_HOST=",
    "DB_PORT=",
    "DB_DATABASE=",
    "DB_USERNAME=",
    "DB_PASSWORD=",
    "DATABASE_URL=",
    "API_KEY=",
    "SECRET_KEY=",
    "ENCRYPTION_KEY=",
    "JWT_SECRET=",
)

HTML_APPLICATION_MARKERS = (
    "<html",
    "<!doctype",
    "codeigniter",
    "debugbar",
    "kint",
)

ROOT_NAMES = (
    "backup",
    "backups",
    "backup-db",
    "backup_database",
    "database-backup",
    "db-backup",
    "archive",
    "archives",
    "source",
    "source-code",
)

TOOL_TIMEOUT = 120


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm_path(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return "/"
    if not value.startswith("/"):
        value = "/" + value
    value = re.sub(r"/+", "/", value)
    if value != "/" and value.endswith("/"):
        value = value[:-1]
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def body_fingerprint(data: bytes) -> str:
    normalized = re.sub(rb"\s+", b" ", data[:MAX_CAPTURE_BYTES]).strip()
    return sha256_bytes(normalized)


def find_project_root() -> Path:
    """
    Resolve the active pentest project from the canonical project context.

    Repository layout:
        <repository>/
        ├── .runtime/
        │   └── active-project.yaml
        ├── projects/
        │   └── PENTEST-2026-002/
        └── scripts/
            └── webserver/
                └── backup.py

    The active-project.yaml is stored under .runtime, not in the project
    directory itself. Its project_path is relative to the repository root,
    for example:
        projects/PENTEST-2026-002

    This prevents checklist artifacts such as backup.yaml from being
    accidentally written to the repository root.
    """
    import yaml

    script_path = Path(__file__).resolve()
    repository_root = script_path.parents[2]
    active_context = repository_root / ".runtime" / "active-project.yaml"

    if not active_context.is_file():
        raise FileNotFoundError(
            f"Active project context tidak ditemukan: {active_context}"
        )

    try:
        with active_context.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise ValueError(
            f"YAML active-project.yaml tidak valid: {active_context}\n{exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            f"Format active-project.yaml harus berupa mapping/object: "
            f"{active_context}"
        )

    project_id = str(data.get("project_id", "")).strip()
    raw_project_path = str(data.get("project_path", "")).strip()

    if not project_id:
        raise ValueError(
            f"project_id tidak ditemukan pada active project: {active_context}"
        )

    if not raw_project_path:
        raise ValueError(
            f"project_path tidak ditemukan pada active project: {active_context}"
        )

    raw_path = Path(raw_project_path)
    project_root = (
        raw_path.resolve()
        if raw_path.is_absolute()
        else (repository_root / raw_path).resolve()
    )

    if not project_root.is_dir():
        raise FileNotFoundError(
            f"Project aktif tidak ditemukan: {project_root}"
        )

    if project_root.name != project_id:
        raise ValueError(
            "Project ID dan project_path tidak konsisten pada active project. "
            f"project_id={project_id!r}, project_path={raw_project_path!r}"
        )

    return project_root


def load_yaml(path: Path) -> Dict[str, Any]:
    try:
        import yaml
    except ImportError:
        print("[ERROR] Python package 'PyYAML' tidak tersedia.")
        print("[HINT] Install dengan: python -m pip install pyyaml")
        raise SystemExit(1)

    if not path.exists():
        raise FileNotFoundError(str(path))

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    if not isinstance(data, dict):
        raise ValueError(f"YAML root bukan object: {path}")

    return data


def save_yaml(path: Path, data: Dict[str, Any]) -> None:
    try:
        import yaml
    except ImportError:
        print("[ERROR] Python package 'PyYAML' tidak tersedia.")
        print("[HINT] Install dengan: python -m pip install pyyaml")
        raise SystemExit(1)

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(
            data,
            fh,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def locate_scope(project_root: Path) -> Path:
    candidates = [
        project_root / "01-preparation" / "scope" / "scope.yaml",
        project_root / "scope" / "scope.yaml",
    ]

    for path in candidates:
        if path.exists():
            return path

    for path in project_root.rglob("scope.yaml"):
        if "01-preparation" in path.parts or path.parent.name == "scope":
            return path

    raise FileNotFoundError("scope.yaml tidak ditemukan.")


def locate_recon_directory(project_root: Path) -> Path:
    candidates = [
        project_root / "02-reconnaissance" / "directory" / "directory.yaml",
    ]

    for path in candidates:
        if path.exists():
            return path

    for path in project_root.rglob("directory.yaml"):
        if "02-reconnaissance" in path.parts:
            return path

    raise FileNotFoundError("directory.yaml Recon tidak ditemukan.")


def locate_version_artifact(project_root: Path) -> Optional[Path]:
    candidates = [
        project_root
        / "04-web-server-configuration"
        / "version"
        / "version.yaml",
    ]

    for path in candidates:
        if path.exists():
            return path

    return None


def locate_errors_artifact(project_root: Path) -> Optional[Path]:
    candidates = [
        project_root
        / "04-web-server-configuration"
        / "errors"
        / "errors.yaml",
    ]

    for path in candidates:
        if path.exists():
            return path

    return None


def locate_git_artifact(project_root: Path) -> Optional[Path]:
    candidates = [
        project_root
        / "04-web-server-configuration"
        / "git"
        / "git.yaml",
    ]

    for path in candidates:
        if path.exists():
            return path

    return None


def extract_in_scope(scope: Dict[str, Any]) -> List[Dict[str, Any]]:
    root = scope.get("scope")
    if isinstance(root, dict):
        items = root.get("in_scope")
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]

    items = scope.get("in_scope")
    if isinstance(items, list):
        return [item for item in items if isinstance(item, dict)]

    return []


def resolve_target(project_root: Path) -> Tuple[str, List[int], str, Dict[str, Any]]:
    scope_path = locate_scope(project_root)
    scope = load_yaml(scope_path)
    items = extract_in_scope(scope)

    domain_items = [
        item for item in items if str(item.get("type", "")).lower() == "domain"
    ]

    if not domain_items:
        raise ValueError("Domain target tidak ditemukan pada scope.")

    item = domain_items[0]
    target = str(item.get("value", "")).strip()
    ports = item.get("ports") or [80, 443]
    ports = [int(p) for p in ports]

    return target, ports, str(item.get("scope_id", "IN-001")), item


def extract_recon_paths(data: Dict[str, Any]) -> List[str]:
    root = data.get("directory")
    if isinstance(root, dict):
        results = root.get("results")
        if isinstance(results, list):
            return [
                norm_path(item.get("path"))
                for item in results
                if isinstance(item, dict) and item.get("path")
            ]

    for key in ("results", "paths", "directories"):
        results = data.get(key)
        if isinstance(results, list):
            paths = []
            for item in results:
                if isinstance(item, str):
                    paths.append(norm_path(item))
                elif isinstance(item, dict) and item.get("path"):
                    paths.append(norm_path(item["path"]))
            if paths:
                return paths

    return []


def is_backup_style_path(path: str) -> bool:
    p = norm_path(path).lower()
    base = p.rstrip("/").split("/")[-1]

    if p in {norm_path(x) for x in ROOT_CANDIDATE_PATHS}:
        return True

    if p.startswith("/.git"):
        return False

    if p.startswith("/.env"):
        return True

    if base in ROOT_NAMES:
        return True

    if any(base.endswith(suffix) for suffix in BACKUP_SUFFIXES):
        return True

    if any(base.endswith(suffix) for suffix in ARCHIVE_SUFFIXES):
        return True

    if any(base.endswith(suffix) for suffix in DATABASE_SUFFIXES):
        return True

    return False


def merge_candidates(recon_paths: Iterable[str]) -> Tuple[List[str], Dict[str, str]]:
    candidates: Dict[str, str] = {}

    for raw in ROOT_CANDIDATE_PATHS:
        candidates[norm_path(raw)] = "bounded"

    for raw in recon_paths:
        path = norm_path(raw)
        if is_backup_style_path(path):
            candidates.setdefault(path, "recon")

    ordered = sorted(candidates.keys())
    return ordered, candidates


def resolve_artifact_paths(project_root: Path) -> Tuple[Path, Path]:
    base = project_root / "04-web-server-configuration" / "backup"
    return base / "backup.yaml", base / "evidence"


def build_initial_artifact(
    project_root: Path,
    target: str,
    ports: List[int],
    scope_id: str,
    recon_path: Path,
    recon_count: int,
    candidates: List[str],
    candidate_sources: Dict[str, str],
) -> Dict[str, Any]:
    errors_path = locate_errors_artifact(project_root)
    version_path = locate_version_artifact(project_root)

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": APP_NAME,
            "script": "backup.py",
            "version": APP_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "methods": METHODS,
            "automatic_finding": False,
            "redirect_following": False,
            "mutation": False,
            "discovery_bruteforce": False,
            "repository_clone": False,
            "archive_extraction": False,
            "max_capture_bytes": MAX_CAPTURE_BYTES,
        },
        "project": project_root.name,
        "target": {
            "scope_id": scope_id,
            "value": target,
            "ports": ports,
            "protocols": ["http", "https"],
        },
        "recon": {
            "source": str(recon_path.relative_to(project_root)).replace("\\", "/"),
            "path_count": recon_count,
            "candidate_source": (
                "Bounded backup/configuration/archive paths; Recon used only "
                "to retain discovered backup-style paths"
            ),
        },
        "supporting_evidence": {
            "errors_4_010": (
                str(errors_path.relative_to(project_root)).replace("\\", "/")
                if errors_path and errors_path.exists()
                else None
            ),
            "version_4_001": (
                str(version_path.relative_to(project_root)).replace("\\", "/")
                if version_path and version_path.exists()
                else None
            ),
        },
        "discovery": {
            "enabled": False,
            "engine": None,
            "wordlist": None,
            "command": None,
            "status": "not-run",
            "candidate_count": 0,
        },
        "candidates": [
            {"path": path, "source": candidate_sources.get(path, "bounded")}
            for path in candidates
        ],
        "probes": [],
        "assessment": {
            "finding": False,
            "requires_review": False,
            "classification": "initialized",
        },
        "cve": {
            "candidate_count": 0,
            "candidates": [],
        },
        "generated_at": utc_now(),
    }


def candidate_is_backup_path(path: str) -> bool:
    p = norm_path(path).lower()
    base = p.rstrip("/").split("/")[-1]

    if p.startswith("/.git"):
        return False

    if p.startswith("/.env"):
        return True

    if any(base.endswith(x) for x in BACKUP_SUFFIXES):
        return True

    if any(base.endswith(x) for x in ARCHIVE_SUFFIXES):
        return True

    if any(base.endswith(x) for x in DATABASE_SUFFIXES):
        return True

    if base in ROOT_NAMES:
        return True

    if base in {x.lower() for x in CONFIG_NAMES}:
        return True

    return False


def normalize_discovery_word(value: str) -> Optional[str]:
    value = value.strip()
    if not value or value.startswith("#"):
        return None

    if value.startswith("http://") or value.startswith("https://"):
        return None

    value = value.replace("\\", "/")
    value = value.split("?", 1)[0].split("#", 1)[0]
    value = value.strip("/")

    if not value:
        return None

    # Only retain backup-like words/paths. This prevents an unrestricted
    # generic web-content wordlist from turning this checklist into broad
    # discovery.
    lower = value.lower()
    backupish = (
        any(token in lower for token in ("backup", "bak", "old", "orig", "save"))
        or any(lower.endswith(s) for s in BACKUP_SUFFIXES + ARCHIVE_SUFFIXES + DATABASE_SUFFIXES)
        or lower in ROOT_NAMES
    )

    if not backupish:
        return None

    return "/" + value


def load_wordlist(path: Path) -> List[str]:
    if not path.exists():
        raise FileNotFoundError(str(path))

    if path.stat().st_size > MAX_DISCOVERY_WORDLIST_BYTES:
        raise ValueError(
            f"Wordlist terlalu besar: {path.stat().st_size} bytes; "
            f"maksimum {MAX_DISCOVERY_WORDLIST_BYTES} bytes."
        )

    words: List[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            candidate = normalize_discovery_word(line)
            if candidate:
                words.append(candidate)
            if len(words) >= MAX_DISCOVERY_CANDIDATES:
                break

    return sorted(set(words))


def locate_default_wordlist(project_root: Path) -> Optional[Path]:
    candidates = [
        project_root / "wordlists" / "web" / "backup-files.txt",
        project_root / "wordlists" / "backup-files.txt",
        project_root / "wordlists" / "web" / "backup.txt",
    ]

    for path in candidates:
        if path.exists():
            return path

    return None


def find_engine(preferred: Optional[str] = None) -> Optional[str]:
    if preferred:
        if shutil.which(preferred):
            return preferred
        return None

    if shutil.which("ffuf"):
        return "ffuf"

    if shutil.which("gobuster"):
        return "gobuster"

    return None


def discovery_url(target: str, port: int) -> str:
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{target}"


def run_ffuf(
    target: str,
    port: int,
    wordlist: Path,
) -> Tuple[Dict[str, Any], List[str]]:
    base = discovery_url(target, port)
    output_path = wordlist.parent / (
        f".brebes-backup-ffuf-{target.replace('.', '_')}-{port}.json"
    )

    cmd = [
        "ffuf",
        "-u",
        f"{base}/FUZZ",
        "-w",
        str(wordlist),
        "-of",
        "json",
        "-o",
        str(output_path),
        "-ac",
        "-t",
        "10",
        "-timeout",
        "10",
        "-noninteractive",
        "-s",
    ]

    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (
            {
                "engine": "ffuf",
                "status": "timeout",
                "command": cmd,
                "duration_seconds": round(time.time() - started, 3),
                "returncode": None,
                "output_file": None,
            },
            [],
        )

    candidates: List[str] = []

    if output_path.exists():
        try:
            data = json.loads(output_path.read_text(encoding="utf-8"))
            for result in data.get("results", []):
                url = str(result.get("url", ""))
                marker = f"{base}/"
                if url.startswith(marker):
                    path = "/" + url[len(marker):].lstrip("/")
                    if candidate_is_backup_path(path):
                        candidates.append(norm_path(path))
        except Exception:
            pass

    try:
        output_path.unlink(missing_ok=True)
    except Exception:
        pass

    return (
        {
            "engine": "ffuf",
            "status": "completed" if proc.returncode == 0 else "nonzero-exit",
            "command": cmd,
            "duration_seconds": round(time.time() - started, 3),
            "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-2000:],
        },
        sorted(set(candidates)),
    )


def run_gobuster(
    target: str,
    port: int,
    wordlist: Path,
) -> Tuple[Dict[str, Any], List[str]]:
    base = discovery_url(target, port)
    cmd = [
        "gobuster",
        "dir",
        "-u",
        base,
        "-w",
        str(wordlist),
        "-q",
        "--no-error",
        "-t",
        "10",
        "--timeout",
        "10s",
    ]

    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (
            {
                "engine": "gobuster",
                "status": "timeout",
                "command": cmd,
                "duration_seconds": round(time.time() - started, 3),
                "returncode": None,
            },
            [],
        )

    candidates: List[str] = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("/"):
            continue

        path = line.split()[0]
        path = norm_path(path)

        if candidate_is_backup_path(path):
            candidates.append(path)

    return (
        {
            "engine": "gobuster",
            "status": "completed" if proc.returncode == 0 else "nonzero-exit",
            "command": cmd,
            "duration_seconds": round(time.time() - started, 3),
            "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-2000:],
        },
        sorted(set(candidates)),
    )


def run_discovery(
    target: str,
    ports: Sequence[int],
    engine: str,
    wordlist: Path,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    runs = []
    discovered: Dict[str, Dict[str, Any]] = {}

    for port in ports:
        if port not in (80, 443):
            continue

        if engine == "ffuf":
            run_info, paths = run_ffuf(target, port, wordlist)
        else:
            run_info, paths = run_gobuster(target, port, wordlist)

        run_info["port"] = port
        run_info["base_url"] = discovery_url(target, port)
        runs.append(run_info)

        for path in paths:
            discovered.setdefault(
                path,
                {
                    "path": path,
                    "source": "discovery",
                    "engine": engine,
                    "ports": [],
                },
            )
            discovered[path]["ports"].append(port)

    return (
        {
            "enabled": True,
            "engine": engine,
            "wordlist": str(wordlist),
            "runs": runs,
            "candidate_count": len(discovered),
        },
        list(discovered.values()),
    )


def read_response_body(response: requests.Response) -> Tuple[bytes, bool]:
    captured = bytearray()
    truncated = False

    try:
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue

            remaining = MAX_CAPTURE_BYTES - len(captured)
            if remaining <= 0:
                truncated = True
                break

            if len(chunk) > remaining:
                captured.extend(chunk[:remaining])
                truncated = True
                break

            captured.extend(chunk)
    except requests.RequestException:
        pass

    return bytes(captured), truncated


def safe_text(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def classify_content(
    path: str,
    content_type: str,
    body: bytes,
    truncated: bool,
    status_code: int,
) -> Tuple[str, List[str]]:
    if status_code in (301, 302, 303, 307, 308):
        return "redirected", ["http-redirect"]

    if status_code == 403:
        return "access-controlled", ["http-403"]

    if status_code == 404:
        return "not-found", ["http-404"]

    if status_code >= 500:
        return "server-error", [f"http-{status_code}"]

    if status_code < 200 or status_code >= 300:
        return "application-response", [f"http-{status_code}"]

    lower_path = path.lower()
    lower_ct = (content_type or "").lower()
    text = safe_text(body)
    upper_text = text.upper()
    lower_text = text.lower()
    indicators: List[str] = []

    for signature, name in MAGIC_SIGNATURES.items():
        if body.startswith(signature):
            indicators.append(f"magic:{name}")

    if any(marker.lower() in lower_text for marker in PHP_MARKERS):
        indicators.append("php-source-marker")

    if any(marker in upper_text for marker in SQL_MARKERS):
        indicators.append("sql-content-marker")

    if any(marker.lower() in lower_text for marker in ENV_MARKERS):
        indicators.append("environment-assignment-marker")

    if "zip" in lower_ct or lower_path.endswith(".zip"):
        if any(x.startswith("magic:zip") for x in indicators):
            return "backup-archive-exposed", indicators
        if "application/zip" in lower_ct:
            return "backup-archive-exposed", indicators + ["content-type:zip"]

    if "gzip" in lower_ct or lower_path.endswith((".gz", ".tgz")):
        if "magic:gzip" in indicators or "gzip" in lower_ct:
            return "backup-archive-exposed", indicators + ["content-type:gzip"]

    if any(marker in indicators for marker in ("php-source-marker",)):
        return "backup-config-exposed", indicators

    if "sql-content-marker" in indicators:
        return "backup-database-exposed", indicators

    if "environment-assignment-marker" in indicators:
        return "backup-config-exposed", indicators

    if any(marker in lower_path for marker in (".bak", ".backup", ".old", ".orig", ".save", "~")):
        if body and "text/html" not in lower_ct:
            indicators.append("backup-suffix-with-non-html-body")
            return "backup-file-exposed", indicators

    # A 2xx HTML response matching known application markers is treated as
    # application-response rather than backup exposure.
    if "html" in lower_ct or any(marker in lower_text for marker in HTML_APPLICATION_MARKERS):
        indicators.append("application-html")
        return "application-response", indicators

    if truncated:
        indicators.append("capture-truncated")

    if body:
        return "backup-candidate", indicators + ["2xx-nonempty-response"]

    return "application-response", indicators + ["2xx-empty-response"]


def make_url(scheme: str, target: str, port: int, path: str) -> str:
    return f"{scheme}://{target}:{port}{norm_path(path)}"


def probe_one(
    session: requests.Session,
    target: str,
    port: int,
    scheme: str,
    method: str,
    path: str,
) -> Dict[str, Any]:
    url = make_url(scheme, target, port, path)

    started = time.time()
    common = {
        "scheme": scheme,
        "port": port,
        "method": method,
        "path": norm_path(path),
        "url": url,
    }

    try:
        response = session.request(
            method,
            url,
            allow_redirects=False,
            timeout=DEFAULT_TIMEOUT,
            stream=True,
            headers={
                "User-Agent": "BrebesKab-CSIRT-Tools/4-004",
                "Accept": "*/*",
            },
        )

        elapsed = round(time.time() - started, 3)
        body = b""
        truncated = False

        if method == "GET":
            body, truncated = read_response_body(response)

        content_type = response.headers.get("Content-Type", "")
        content_length = response.headers.get("Content-Length")

        classification, indicators = classify_content(
            norm_path(path),
            content_type,
            body,
            truncated,
            response.status_code,
        )

        record = {
            **common,
            "status_code": response.status_code,
            "reason": response.reason,
            "content_type": content_type,
            "content_length": content_length,
            "location": response.headers.get("Location"),
            "server": response.headers.get("Server"),
            "response_time_seconds": elapsed,
            "body_length_captured": len(body),
            "capture_truncated": truncated,
            "body_sha256": sha256_bytes(body) if body else None,
            "body_fingerprint": body_fingerprint(body) if body else None,
            "classification": classification,
            "indicators": indicators,
            "headers": dict(response.headers),
        }

        # Raw body is retained for evidence, but cap it.
        if method == "GET" and body:
            record["body"] = safe_text(body)

        response.close()
        return record

    except requests.RequestException as exc:
        return {
            **common,
            "status_code": None,
            "reason": None,
            "content_type": None,
            "content_length": None,
            "location": None,
            "server": None,
            "response_time_seconds": round(time.time() - started, 3),
            "body_length_captured": 0,
            "capture_truncated": False,
            "body_sha256": None,
            "body_fingerprint": None,
            "classification": "probe-error",
            "indicators": [type(exc).__name__],
            "error": str(exc),
        }


def summarize_probes(probes: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = {
        "backup_exposed": 0,
        "archive_exposed": 0,
        "config_exposed": 0,
        "database_exposed": 0,
        "candidate": 0,
        "access_control": 0,
        "redirected": 0,
        "not_found": 0,
        "application": 0,
        "server_errors": 0,
        "probe_errors": 0,
    }

    for probe in probes:
        classification = probe.get("classification")

        if classification == "backup-file-exposed":
            counts["backup_exposed"] += 1
        elif classification == "backup-archive-exposed":
            counts["archive_exposed"] += 1
        elif classification == "backup-config-exposed":
            counts["config_exposed"] += 1
        elif classification == "backup-database-exposed":
            counts["database_exposed"] += 1
        elif classification == "backup-candidate":
            counts["candidate"] += 1
        elif classification == "access-controlled":
            counts["access_control"] += 1
        elif classification == "redirected":
            counts["redirected"] += 1
        elif classification == "not-found":
            counts["not_found"] += 1
        elif classification == "server-error":
            counts["server_errors"] += 1
        elif classification == "probe-error":
            counts["probe_errors"] += 1
        elif classification == "application-response":
            counts["application"] += 1

    return counts


def update_cve_candidates(
    artifact: Dict[str, Any],
    project_root: Path,
) -> None:
    version_path = locate_version_artifact(project_root)
    if not version_path:
        artifact["cve"] = {
            "candidate_count": 0,
            "candidates": [],
            "source": None,
        }
        return

    try:
        version_data = load_yaml(version_path)
    except Exception:
        artifact["cve"] = {
            "candidate_count": 0,
            "candidates": [],
            "source": str(version_path.relative_to(project_root)).replace("\\", "/"),
        }
        return

    candidates = version_data.get("cve", {}).get("candidates", [])
    if not isinstance(candidates, list):
        candidates = []

    # Preserve the candidate evidence but do not claim applicability.
    artifact["cve"] = {
        "candidate_count": len(candidates),
        "candidates": candidates,
        "source": str(version_path.relative_to(project_root)).replace("\\", "/"),
        "triage_note": (
            "CVE candidates are inherited supporting evidence only; "
            "no automatic vulnerability finding is created."
        ),
    }


def command_version() -> int:
    print(f"{Path(__file__).name} v{APP_VERSION}")
    print(f"Schema: {SCHEMA_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("Methods:")
    for method in METHODS:
        print(f"  - {method}")
    print("Endpoint source: Recon directory.yaml + bounded backup candidates")
    print("Optional discovery: ffuf preferred, gobuster fallback")
    print("Supporting evidence: 4-010 errors.yaml")
    print("CVE source: 4-001 version.yaml")
    print("Redirect following: disabled")
    print("Mutation payload: none")
    print("Discovery: optional, explicit --discover only")
    print("Repository clone: disabled")
    print("Archive extraction: disabled")
    print(f"Max body capture: {MAX_CAPTURE_BYTES} bytes")
    print("Automatic finding: disabled")
    print("Raw evidence: retained")
    print("Report redaction: separate report-generation layer")
    return 0


def command_init(project_root: Path) -> int:
    target, ports, scope_id, _ = resolve_target(project_root)
    recon_path = locate_recon_directory(project_root)
    recon = load_yaml(recon_path)
    recon_paths = extract_recon_paths(recon)

    candidates, sources = merge_candidates(recon_paths)
    artifact_path, evidence_dir = resolve_artifact_paths(project_root)

    artifact = build_initial_artifact(
        project_root,
        target,
        ports,
        scope_id,
        recon_path,
        len(recon_paths),
        candidates,
        sources,
    )

    save_yaml(artifact_path, artifact)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    print("[PASS] Backup File Exposure berhasil diinisialisasi.")
    print(f"PROJECT         : {project_root.name}")
    print(f"TARGET          : {target}")
    print(f"PORTS           : {', '.join(map(str, ports))}")
    print(f"METHODS         : {', '.join(METHODS)}")
    print(f"RECON PATHS     : {len(recon_paths)}")
    print(f"CANDIDATES      : {len(candidates)}")
    print("DISCOVERY       : optional (--discover)")
    print(f"SOURCE          : {recon_path.relative_to(project_root)}")
    print(f"FILE            : {artifact_path}")

    return 0


def command_analyze(
    project_root: Path,
    discover: bool,
    engine_arg: Optional[str],
    wordlist_arg: Optional[str],
) -> int:
    artifact_path, evidence_dir = resolve_artifact_paths(project_root)

    if not artifact_path.exists():
        print("[ERROR] Artifact belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    artifact = load_yaml(artifact_path)
    target = artifact["target"]["value"]
    ports = [int(p) for p in artifact["target"]["ports"]]

    candidates = artifact.get("candidates", [])
    normalized_candidates: Dict[str, Dict[str, Any]] = {}

    for item in candidates:
        if isinstance(item, str):
            path = norm_path(item)
            source = "bounded"
        else:
            path = norm_path(item.get("path", ""))
            source = item.get("source", "bounded")

        if path:
            normalized_candidates[path] = {
                "path": path,
                "source": source,
            }

    discovery_info = {
        "enabled": False,
        "engine": None,
        "wordlist": None,
        "runs": [],
        "candidate_count": 0,
    }

    if discover:
        wordlist = Path(wordlist_arg).resolve() if wordlist_arg else locate_default_wordlist(project_root)

        if not wordlist:
            print(
                "[ERROR] --discover membutuhkan wordlist. "
                "Gunakan --wordlist PATH atau buat "
                "wordlists/web/backup-files.txt."
            )
            return 1

        engine = find_engine(engine_arg)
        if not engine:
            if engine_arg:
                print(f"[ERROR] Discovery engine tidak tersedia: {engine_arg}")
            else:
                print("[ERROR] ffuf/gobuster tidak ditemukan.")
                print("[HINT] Install ffuf atau gobuster, atau jalankan tanpa --discover.")
            return 1

        try:
            discovery_info, discovered = run_discovery(
                target,
                ports,
                engine,
                wordlist,
            )
        except Exception as exc:
            print(f"[ERROR] Discovery gagal: {exc}")
            return 1

        for item in discovered:
            path = norm_path(item["path"])
            if path not in normalized_candidates:
                normalized_candidates[path] = {
                    "path": path,
                    "source": "discovery",
                    "engine": engine,
                    "discovery_ports": item.get("ports", []),
                }

    candidate_items = sorted(
        normalized_candidates.values(),
        key=lambda x: x["path"],
    )

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "BrebesKab-CSIRT-Tools/4-004",
            "Accept": "*/*",
        }
    )

    probes: List[Dict[str, Any]] = []

    for item in candidate_items:
        path = item["path"]

        for port in ports:
            if port not in (80, 443):
                continue

            scheme = "https" if port == 443 else "http"

            for method in METHODS:
                probe = probe_one(
                    session,
                    target,
                    port,
                    scheme,
                    method,
                    path,
                )
                probe["candidate_source"] = item.get("source", "bounded")
                if item.get("engine"):
                    probe["discovery_engine"] = item["engine"]
                probes.append(probe)

    session.close()

    # Persist raw evidence separately.
    evidence_path = evidence_dir / "backup-probes.json"
    save_json(
        evidence_path,
        {
            "schema_version": SCHEMA_VERSION,
            "checklist": CHECKLIST_ID,
            "generated_at": utc_now(),
            "target": target,
            "probes": probes,
        },
    )

    counts = summarize_probes(probes)

    artifact["candidates"] = candidate_items
    artifact["probes"] = probes
    artifact["discovery"] = discovery_info
    artifact["assessment"] = {
        "finding": False,
        "requires_review": (
            counts["backup_exposed"] > 0
            or counts["archive_exposed"] > 0
            or counts["config_exposed"] > 0
            or counts["database_exposed"] > 0
            or counts["candidate"] > 0
            or counts["probe_errors"] > 0
        ),
        "classification": (
            "backup-exposure-review"
            if (
                counts["backup_exposed"]
                or counts["archive_exposed"]
                or counts["config_exposed"]
                or counts["database_exposed"]
                or counts["candidate"]
                or counts["probe_errors"]
            )
            else "no-backup-exposure-observed"
        ),
    }

    update_cve_candidates(artifact, project_root)
    artifact["generated_at"] = utc_now()

    save_yaml(artifact_path, artifact)

    print("[PASS] Backup File Exposure berhasil dianalisis.")
    print(f"PROJECT          : {project_root.name}")
    print(f"TARGET           : {target}")
    print(f"CANDIDATES       : {len(candidate_items)}")
    print(f"METHODS          : {len(METHODS)}")
    print(f"PROBES           : {len(probes)}")
    print(f"BACKUP EXPOSED   : {counts['backup_exposed']}")
    print(f"ARCHIVE EXPOSED  : {counts['archive_exposed']}")
    print(f"CONFIG EXPOSED   : {counts['config_exposed']}")
    print(f"DATABASE EXPOSED : {counts['database_exposed']}")
    print(f"BACKUP CANDIDATE : {counts['candidate']}")
    print(f"ACCESS CONTROL   : {counts['access_control']}")
    print(f"REDIRECTED       : {counts['redirected']}")
    print(f"NOT FOUND        : {counts['not_found']}")
    print(f"APPLICATION      : {counts['application']}")
    print(f"SERVER ERRORS    : {counts['server_errors']}")
    print(f"PROBE ERRORS     : {counts['probe_errors']}")
    print(f"CVE CANDIDATES   : {artifact['cve']['candidate_count']}")
    print(f"REQUIRES REVIEW  : {artifact['assessment']['requires_review']}")
    print(f"STATUS           : {artifact['assessment']['classification']}")
    print(f"FILE             : {artifact_path}")
    print(f"EVIDENCE         : {evidence_path}")

    return 0


def is_observation(probe: Dict[str, Any]) -> bool:
    return probe.get("classification") in {
        "backup-file-exposed",
        "backup-archive-exposed",
        "backup-config-exposed",
        "backup-database-exposed",
        "backup-candidate",
        "access-controlled",
    }


def command_list(project_root: Path) -> int:
    artifact_path, _ = resolve_artifact_paths(project_root)

    if not artifact_path.exists():
        print("[ERROR] Artifact belum ada. Jalankan 'init' terlebih dahulu.")
        return 1

    artifact = load_yaml(artifact_path)
    probes = artifact.get("probes", [])

    observations = [
        probe for probe in probes if isinstance(probe, dict) and is_observation(probe)
    ]

    if not observations:
        print("[INFO] Tidak ada backup exposure observation yang perlu ditampilkan.")
        return 0

    print("[INFO] Backup exposure observations:")

    for probe in observations:
        print(
            f"- {probe.get('scheme', '').upper()} "
            f"{probe.get('port')} "
            f"{probe.get('method')} "
            f"{probe.get('path')} "
            f"-> {probe.get('status_code')} "
            f"[{probe.get('classification')}]"
        )

        indicators = probe.get("indicators") or []
        if indicators:
            print(f"  indicators: {', '.join(indicators)}")

        if probe.get("content_type"):
            print(f"  content-type: {probe['content_type']}")

        if probe.get("content_length"):
            print(f"  content-length: {probe['content_length']}")

        if probe.get("capture_truncated"):
            print("  capture: TRUNCATED")

    return 0


def command_verify(project_root: Path) -> int:
    artifact_path, evidence_dir = resolve_artifact_paths(project_root)

    if not artifact_path.exists():
        print("[FAIL] Artifact tidak ditemukan.")
        return 1

    artifact = load_yaml(artifact_path)
    probes = artifact.get("probes", [])
    candidates = artifact.get("candidates", [])

    errors: List[str] = []

    if artifact.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version tidak sesuai.")

    if artifact.get("checklist", {}).get("id") != CHECKLIST_ID:
        errors.append("checklist.id tidak sesuai.")

    if artifact.get("checklist", {}).get("automatic_finding") is not False:
        errors.append("automatic_finding harus false.")

    if artifact.get("checklist", {}).get("redirect_following") is not False:
        errors.append("redirect_following harus false.")

    if artifact.get("checklist", {}).get("mutation") is not False:
        errors.append("mutation harus false.")

    if artifact.get("checklist", {}).get("repository_clone") is not False:
        errors.append("repository_clone harus false.")

    if artifact.get("checklist", {}).get("archive_extraction") is not False:
        errors.append("archive_extraction harus false.")

    expected_probe_count = len(candidates) * len(METHODS) * 2
    # Only HTTP/HTTPS are in the active web-server scope.
    if len(probes) != expected_probe_count:
        errors.append(
            f"jumlah probes {len(probes)} tidak sesuai expected {expected_probe_count}."
        )

    candidate_paths = set()
    for item in candidates:
        path = item if isinstance(item, str) else item.get("path")
        if path:
            candidate_paths.add(norm_path(path))

    for probe in probes:
        path = norm_path(probe.get("path", ""))
        if path not in candidate_paths:
            errors.append(f"probe path di luar candidates: {path}")

        if probe.get("method") not in METHODS:
            errors.append(f"method tidak valid: {probe.get('method')}")

        if probe.get("classification") in {
            "backup-file-exposed",
            "backup-archive-exposed",
            "backup-config-exposed",
            "backup-database-exposed",
            "backup-candidate",
        } and not candidate_is_backup_path(path):
            errors.append(
                f"backup classification pada non-backup path: {path}"
            )

    evidence_file = evidence_dir / "backup-probes.json"
    if probes and not evidence_file.exists():
        errors.append("raw evidence backup-probes.json tidak ditemukan.")

    if errors:
        print("[FAIL] Backup File Exposure gagal validasi.")
        for error in errors:
            print(f"[FAIL] {error}")
        return 1

    counts = summarize_probes(probes)

    print("[PASS] Backup File Exposure memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print("[PASS] Status    : completed")
    print(f"[PASS] Target    : {artifact.get('target', {}).get('value')}")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(f"[PASS] Methods   : {len(METHODS)}")
    print(f"[PASS] Probes    : {len(probes)}")
    print(f"[PASS] Backup    : {counts['backup_exposed']}")
    print(f"[PASS] Archive   : {counts['archive_exposed']}")
    print(f"[PASS] Config    : {counts['config_exposed']}")
    print(f"[PASS] Database  : {counts['database_exposed']}")
    print(f"[PASS] Candidate : {counts['candidate']}")
    print(f"[PASS] CVE       : {artifact.get('cve', {}).get('candidate_count', 0)} candidate(s)")
    print(
        f"[PASS] Review    : "
        f"{1 if artifact.get('assessment', {}).get('requires_review') else 0}"
    )
    print(
        "[PASS] CVE Triage: backup exposure is not automatically mapped to a CVE; "
        "version evidence remains supporting evidence."
    )
    print(
        "[PASS] Assessment: backup indicators are review evidence; "
        "no automatic vulnerability finding."
    )

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools 4-004 Backup File Exposure"
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("version")
    subparsers.add_parser("init")
    subparsers.add_parser("list")
    subparsers.add_parser("verify")

    analyze = subparsers.add_parser("analyze")
    analyze.add_argument(
        "--discover",
        action="store_true",
        help="Run optional ffuf/gobuster discovery.",
    )
    analyze.add_argument(
        "--engine",
        choices=["ffuf", "gobuster"],
        help="Force discovery engine.",
    )
    analyze.add_argument(
        "--wordlist",
        help="Custom backup wordlist path.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "version":
        return command_version()

    project_root = find_project_root()

    try:
        if args.command == "init":
            return command_init(project_root)

        if args.command == "analyze":
            return command_analyze(
                project_root,
                discover=args.discover,
                engine_arg=args.engine,
                wordlist_arg=args.wordlist,
            )

        if args.command == "list":
            return command_list(project_root)

        if args.command == "verify":
            return command_verify(project_root)

    except (FileNotFoundError, ValueError, KeyError) as exc:
        print(f"[ERROR] {exc}")
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Dibatalkan oleh pengguna.")
        return 130

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
