#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Directory Discovery

Version: 1.1.1

Checklist mapping:
    02-006 - Directory discovery

Purpose:
    Discover common web paths on the authorized target using ffuf.
    A random non-existent URL baseline is collected before ffuf so that
    custom 404 / SPA fallback responses can be recognized as possible
    false positives.

Design:
    - "init" reads the completed target reconnaissance document once.
    - After "init", directory.yaml is the state file for this module.
    - "discover" collects a random baseline and then runs ffuf.
    - Results are retained as reconnaissance evidence.
    - Baseline matches are classified as possible false positives.
    - No credentials, cookies, or response bodies are stored.
    - Discovery does not authorize newly discovered paths.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

# IMPORTANT:
# This repository contains scripts/reconnaissance/http.py.
# When this file is executed directly, Python puts that directory at
# sys.path[0]. If urllib.request is imported before removing that path,
# stdlib "http.client" can be shadowed by the local http.py.
SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

for _entry in (str(SCRIPT_DIR), str(SCRIPTS_DIR)):
    while _entry in sys.path:
        sys.path.remove(_entry)

# Keep the repository scripts directory available for context/activity imports.
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

# Safe to import stdlib modules that depend on stdlib "http" now.
import urllib.error
import urllib.request

import yaml

try:
    from activity import ActivityError, record_activity
except ImportError:
    ActivityError = RuntimeError

    def record_activity(*args: Any, **kwargs: Any) -> None:
        return None


try:
    from context import ContextError, ProjectContext, require_active_project
except ImportError:
    ContextError = RuntimeError
    ProjectContext = Any  # type: ignore[misc,assignment]

    def require_active_project() -> Any:
        raise RuntimeError("context.py tidak dapat di-import.")


SCRIPT_VERSION = "1.1.1"
SCHEMA_VERSION = "1.1"
CHECKLIST_ID = "2-006"
CHECKLIST_NAME = "Directory discovery"

DEFAULT_WORDLIST = [
    "admin",
    "administrator",
    "api",
    "app",
    "assets",
    "backup",
    "backups",
    "config",
    "css",
    "dashboard",
    "docs",
    "download",
    "downloads",
    "files",
    "images",
    "img",
    "includes",
    "js",
    "login",
    "logs",
    "media",
    "public",
    "robots.txt",
    "sitemap.xml",
    "storage",
    "test",
    "tmp",
    "uploads",
    "user",
    "users",
    "vendor",
]

DEFAULT_EXTENSIONS = ["php", "html", "txt", "json", "xml"]
DEFAULT_RATE = 10
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 5
DEFAULT_MATCH_CODES = "200,204,301,302,307,308,401,403,405"

BASELINE_ATTEMPTS = 3
BASELINE_PREFIX = ".brebes-csirt-baseline"


class DirectoryError(RuntimeError):
    """Raised when directory reconnaissance cannot be completed."""


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def project_root() -> Path:
    context = require_active_project()
    return Path(context.project_path)


def directory_dir() -> Path:
    return project_root() / "02-reconnaissance" / "directory"


def directory_file() -> Path:
    return directory_dir() / "directory.yaml"


def evidence_dir() -> Path:
    return directory_dir() / "evidence"


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise DirectoryError(f"{label} tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise DirectoryError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise DirectoryError(f"Gagal membaca {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise DirectoryError(f"Format {path.name} harus berupa mapping/object.")

    return data


def _save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            yaml.safe_dump(
                data,
                handle,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
            )
    except OSError as exc:
        raise DirectoryError(f"Gagal menulis {path}\n{exc}") from exc


def _load_target() -> dict[str, Any]:
    path = project_root() / "02-reconnaissance" / "target" / "target.yaml"
    data = _load_yaml(path, "Target reconnaissance")

    target = data.get("target")
    if not isinstance(target, dict):
        raise DirectoryError(
            "Field 'target' pada target.yaml harus berupa mapping/object."
        )

    if str(target.get("status", "")).strip().lower() != "completed":
        raise DirectoryError(
            "Target reconnaissance belum completed.\n"
            "Jalankan terlebih dahulu:\n"
            "  python scripts/reconnaissance/target.py verify"
        )

    target_url = str(target.get("target_url", "")).strip()
    parsed = urlparse(target_url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DirectoryError(f"Target URL tidak valid: {target_url}")

    return {
        "application": str(target.get("application", "")).strip(),
        "target_url": target_url,
        "hostname": str(target.get("hostname") or parsed.hostname).strip(),
        "scheme": str(target.get("scheme") or parsed.scheme).strip().lower(),
        "port": str(
            target.get("port")
            or parsed.port
            or ("443" if parsed.scheme == "https" else "80")
        ),
        "environment": str(target.get("environment", "")).strip(),
        "assessment_type": str(target.get("assessment_type", "")).strip(),
        "scope_reference": str(target.get("scope_reference", "")).strip(),
    }


def _normalize_base_url(target_url: str) -> str:
    parsed = urlparse(target_url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DirectoryError(f"Target URL tidak valid: {target_url}")

    return f"{parsed.scheme}://{parsed.netloc}/"


def _resolve_ffuf() -> str | None:
    configured = os.environ.get("BREBES_FFUF")
    if configured:
        path = Path(configured)
        if path.is_file():
            return str(path)

    repository_root = SCRIPT_DIR.parent.parent

    candidates = [
        repository_root / "tools" / "ffuf" / "ffuf.exe",
        repository_root / "tools" / "ffuf" / "ffuf",
    ]

    system_ffuf = shutil.which("ffuf")
    if system_ffuf:
        candidates.append(Path(system_ffuf))

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return None


def _write_default_wordlist() -> Path:
    path = evidence_dir() / "directory-wordlist.txt"
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        "\n".join(DEFAULT_WORDLIST) + "\n",
        encoding="utf-8",
    )

    return path


def _load_directory() -> dict[str, Any]:
    data = _load_yaml(directory_file(), "Directory reconnaissance")

    if data.get("project_id") != project_root().name:
        raise DirectoryError(
            "Project ID pada directory.yaml tidak sesuai active project.\n"
            f"  Context : {project_root().name}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    if str(data.get("schema_version", "")).strip() != SCHEMA_VERSION:
        raise DirectoryError(
            f"Schema directory.yaml tidak didukung: "
            f"{data.get('schema_version')!r}"
        )

    directory = data.get("directory")

    if not isinstance(directory, dict):
        raise DirectoryError(
            "Field 'directory' pada directory.yaml harus berupa mapping/object."
        )

    return data


def _record_activity(item: str, action: str, status: str) -> None:
    try:
        record_activity(
            phase="02-reconnaissance",
            item=item,
            action=action,
            status=status,
            context=require_active_project(),
        )
    except TypeError:
        try:
            record_activity(
                phase="02-reconnaissance",
                item=item,
                action=action,
                status=status,
            )
        except Exception:
            pass
    except (ActivityError, Exception):
        pass


def _empty_document(target: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "directory": {
            "status": "not-started",
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": target["application"],
            "target_url": target["target_url"],
            "base_url": _normalize_base_url(target["target_url"]),
            "hostname": target["hostname"],
            "scheme": target["scheme"],
            "port": target["port"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_reference": target["scope_reference"],
            "method": "ffuf",
            "wordlist": "",
            "rate_limit": DEFAULT_RATE,
            "threads": DEFAULT_THREADS,
            "timeout": DEFAULT_TIMEOUT,
            "match_codes": DEFAULT_MATCH_CODES,
            "extensions": DEFAULT_EXTENSIONS,
            "follow_redirects": False,
            "baseline": {
                "status": "not-tested",
                "url": "",
                "path": "",
                "status_code": None,
                "content_length": None,
                "content_type": "",
                "words": None,
                "lines": None,
                "attempts": [],
                "classification": "",
                "notes": "",
            },
            "results": [],
            "summary": {
                "total": 0,
                "interesting": 0,
                "possible_false_positive": 0,
                "by_status": {},
            },
            "evidence": [],
            "notes": "",
            "discovered_at": "",
        },
    }


def init() -> int:
    target = _load_target()

    directory_dir().mkdir(parents=True, exist_ok=True)
    evidence_dir().mkdir(parents=True, exist_ok=True)

    wordlist = _write_default_wordlist()

    data = _empty_document(target)
    data["directory"]["wordlist"] = str(
        wordlist.relative_to(project_root())
    )

    _save_yaml(directory_file(), data)

    _record_activity(
        CHECKLIST_ID,
        "Directory discovery initialized",
        "in-progress",
    )

    print("[PASS] Directory Discovery berhasil diinisialisasi.")
    print(f"PROJECT: {project_root().name}")
    print(f"TARGET : {target['target_url']}")
    print(f"FILE   : {directory_file()}")

    return 0


def _random_baseline_path() -> str:
    return f"{BASELINE_PREFIX}-{secrets.token_hex(8)}"


def _response_signature(value: dict[str, Any]) -> tuple[Any, ...]:
    return (
        value.get("status_code"),
        value.get("content_length"),
        value.get("content_type"),
        value.get("words"),
        value.get("lines"),
    )


def _request_baseline(base_url: str, timeout: int) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []

    for _ in range(BASELINE_ATTEMPTS):
        path = "/" + _random_baseline_path()
        url = urljoin(base_url, path.lstrip("/"))

        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": (
                    f"BrebesKab-CSIRT-Tools/{SCRIPT_VERSION} "
                    "Directory-Recon"
                ),
                "Accept": "*/*",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()
                text = body.decode("utf-8", errors="replace")

                attempts.append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": int(response.status),
                        "content_length": len(body),
                        "content_type": str(
                            response.headers.get("Content-Type") or ""
                        ),
                        "words": len(text.split()),
                        "lines": len(text.splitlines()),
                        "error": "",
                    }
                )

        except urllib.error.HTTPError as exc:
            try:
                body = exc.read()
            except Exception:
                body = b""

            headers = exc.headers
            content_type = str(
                headers.get("Content-Type") if headers else ""
            )
            text = body.decode("utf-8", errors="replace")

            attempts.append(
                {
                    "path": path,
                    "url": url,
                    "status_code": int(exc.code),
                    "content_length": len(body),
                    "content_type": content_type,
                    "words": len(text.split()),
                    "lines": len(text.splitlines()),
                    "error": "",
                }
            )

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            attempts.append(
                {
                    "path": path,
                    "url": url,
                    "status_code": None,
                    "content_length": None,
                    "content_type": "",
                    "words": None,
                    "lines": None,
                    "error": str(exc),
                }
            )

    successful = [
        item for item in attempts
        if item.get("status_code") is not None
    ]

    if not successful:
        return {
            "status": "failed",
            "url": "",
            "path": "",
            "status_code": None,
            "content_length": None,
            "content_type": "",
            "words": None,
            "lines": None,
            "attempts": attempts,
            "classification": "baseline-unavailable",
            "notes": (
                "Tidak ada response baseline dari random non-existent "
                "path."
            ),
        }

    first = successful[0]
    signature = _response_signature(first)
    stable = all(
        _response_signature(item) == signature
        for item in successful[1:]
    )

    return {
        "status": "completed",
        "url": first["url"],
        "path": first["path"],
        "status_code": first["status_code"],
        "content_length": first["content_length"],
        "content_type": first["content_type"],
        "words": first["words"],
        "lines": first["lines"],
        "attempts": attempts,
        "classification": (
            "stable-baseline" if stable else "variable-baseline"
        ),
        "notes": (
            "Random non-existent paths menghasilkan response signature "
            "yang konsisten."
            if stable
            else
            "Response random non-existent paths tidak sepenuhnya "
            "konsisten; baseline pertama digunakan sebagai pembanding."
        ),
    }


def _parse_ffuf_results(
    ffuf_json: Path,
    baseline: dict[str, Any],
) -> list[dict[str, Any]]:
    try:
        with ffuf_json.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise DirectoryError(
            f"Gagal membaca output ffuf: {ffuf_json}\n{exc}"
        ) from exc

    raw_results = payload.get("results", [])

    if not isinstance(raw_results, list):
        raise DirectoryError("Field 'results' pada output ffuf bukan list.")

    results: list[dict[str, Any]] = []

    for raw in raw_results:
        if not isinstance(raw, dict):
            continue

        input_data = raw.get("input") or {}
        word = ""

        if isinstance(input_data, dict):
            word = str(
                input_data.get("FUZZ")
                or input_data.get("fuzz")
                or ""
            ).strip()

        url = str(raw.get("url") or "").strip()

        if not url and word:
            url = word

        if not url:
            continue

        item = {
            "path": urlparse(url).path or "/",
            "url": url,
            "method": "GET",
            "status_code": (
                int(raw["status"])
                if raw.get("status") is not None
                else None
            ),
            "content_length": (
                int(raw["length"])
                if raw.get("length") is not None
                else None
            ),
            "content_type": (
                raw.get("content-type")
                or raw.get("content_type")
                or ""
            ),
            "words": (
                int(raw["words"])
                if raw.get("words") is not None
                else None
            ),
            "lines": (
                int(raw["lines"])
                if raw.get("lines") is not None
                else None
            ),
            "redirect_location": (
                raw.get("redirectlocation")
                or raw.get("redirect_location")
                or ""
            ),
            "source": "ffuf",
        }

        if baseline.get("status") == "completed":
            item["baseline_match"] = (
                _response_signature(item)
                == _response_signature(baseline)
            )
        else:
            item["baseline_match"] = False

        item["classification"] = (
            "possible-false-positive"
            if item["baseline_match"]
            else "discovery-candidate"
        )

        item["notes"] = (
            "Response signature sama dengan random non-existent path "
            "baseline. Retained as evidence; perlu verifikasi manual."
            if item["baseline_match"]
            else
            "Response signature berbeda dari random non-existent "
            "path baseline."
        )

        results.append(item)

    return results


def discover(
    wordlist: str | None = None,
    rate: int = DEFAULT_RATE,
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
    extensions: list[str] | None = None,
    match_codes: str = DEFAULT_MATCH_CODES,
) -> int:
    data = _load_directory()
    directory = data["directory"]

    ffuf = _resolve_ffuf()

    if not ffuf:
        print("[FAIL] ffuf tidak ditemukan.")
        print(
            "       Install ffuf atau letakkan executable "
            "di tools/ffuf/ffuf.exe."
        )
        return 1

    if rate < 1 or threads < 1 or timeout < 1:
        print("[FAIL] Rate, threads, dan timeout harus >= 1.")
        return 1

    base_url = str(directory.get("base_url", "")).strip()

    if not base_url:
        raise DirectoryError("base_url belum tersedia pada directory.yaml.")

    if wordlist:
        wordlist_path = Path(wordlist).expanduser().resolve()
    else:
        configured = str(directory.get("wordlist") or "").strip()
        wordlist_path = (
            project_root() / configured
            if configured
            else _write_default_wordlist()
        )

    if not wordlist_path.is_file():
        print(f"[FAIL] Wordlist tidak ditemukan: {wordlist_path}")
        return 1

    extension_list = (
        list(extensions)
        if extensions is not None
        else list(directory.get("extensions") or DEFAULT_EXTENSIONS)
    )

    evidence_dir().mkdir(parents=True, exist_ok=True)

    baseline_file = evidence_dir() / "baseline.json"
    ffuf_file = evidence_dir() / "ffuf-directory.json"
    stderr_file = evidence_dir() / "ffuf-directory.stderr.log"

    print("[INFO] Menjalankan 2-006: Directory discovery")
    print(f"[INFO] Target   : {base_url}")
    print("[INFO] Baseline : random non-existent path")
    print(f"[INFO] Wordlist : {wordlist_path}")
    print(f"[INFO] Rate     : {rate} req/s")
    print(f"[INFO] Threads  : {threads}")
    print(f"[INFO] Timeout  : {timeout}s")
    print(f"[INFO] Matcher  : {match_codes}")

    _record_activity(
        CHECKLIST_ID,
        f"Directory discovery started: {base_url}",
        "in-progress",
    )

    print()
    print("[INFO] Mengambil baseline custom 404/error response...")

    baseline = _request_baseline(base_url, timeout)

    baseline_file.write_text(
        json.dumps(
            baseline,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    if baseline["status"] == "completed":
        print(
            "[PASS] Baseline berhasil: "
            f"HTTP {baseline.get('status_code')}, "
            f"Length {baseline.get('content_length')}, "
            f"Words {baseline.get('words')}, "
            f"Lines {baseline.get('lines')}"
        )
        print(
            "[INFO] Baseline classification: "
            f"{baseline.get('classification')}"
        )
    else:
        print("[WARN] Baseline gagal diperoleh.")
        print(
            "[WARN] Discovery tetap dilanjutkan, tetapi "
            "false-positive comparison tidak tersedia."
        )

    command = [
        ffuf,
        "-u",
        base_url.rstrip("/") + "/FUZZ",
        "-w",
        str(wordlist_path),
        "-of",
        "json",
        "-o",
        str(ffuf_file),
        "-t",
        str(threads),
        "-rate",
        str(rate),
        "-timeout",
        str(timeout),
        "-mc",
        match_codes,
        "-s",
    ]

    if extension_list:
        command.extend(
            [
                "-e",
                ",".join(
                    "." + value.lstrip(".")
                    for value in extension_list
                ),
            ]
        )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        print(f"[FAIL] Gagal menjalankan ffuf: {exc}")
        directory["status"] = "failed"
        directory["updated_at"] = now_iso()
        directory["baseline"] = baseline
        _save_yaml(directory_file(), data)

        _record_activity(
            CHECKLIST_ID,
            f"Directory discovery failed: {exc}",
            "failed",
        )

        return 1

    stderr_file.write_text(
        completed.stderr or "",
        encoding="utf-8",
    )

    if completed.returncode != 0:
        print(
            "[FAIL] ffuf gagal dengan exit code "
            f"{completed.returncode}."
        )

        if completed.stderr.strip():
            print(completed.stderr.strip())

        directory["status"] = "failed"
        directory["updated_at"] = now_iso()
        directory["baseline"] = baseline
        directory["evidence"] = [
            str(baseline_file.relative_to(project_root())),
            str(stderr_file.relative_to(project_root())),
        ]

        _save_yaml(directory_file(), data)

        _record_activity(
            CHECKLIST_ID,
            (
                "Directory discovery failed: "
                f"ffuf exit code {completed.returncode}"
            ),
            "failed",
        )

        return 1

    if not ffuf_file.is_file():
        print("[FAIL] ffuf selesai tetapi output JSON tidak ditemukan.")

        directory["status"] = "failed"
        directory["updated_at"] = now_iso()
        directory["baseline"] = baseline

        _save_yaml(directory_file(), data)

        _record_activity(
            CHECKLIST_ID,
            "Directory discovery failed: ffuf output missing",
            "failed",
        )

        return 1

    try:
        results = _parse_ffuf_results(
            ffuf_file,
            baseline,
        )
    except DirectoryError as exc:
        print(f"[FAIL] {exc}")

        directory["status"] = "failed"
        directory["updated_at"] = now_iso()
        directory["baseline"] = baseline

        _save_yaml(directory_file(), data)

        _record_activity(
            CHECKLIST_ID,
            f"Directory discovery failed: {exc}",
            "failed",
        )

        return 1

    by_status: dict[str, int] = {}
    interesting = 0
    possible_false_positive = 0

    for item in results:
        status_code = item.get("status_code")
        key = str(status_code) if status_code is not None else "unknown"

        by_status[key] = by_status.get(key, 0) + 1

        if status_code in {
            200,
            204,
            301,
            302,
            307,
            308,
            401,
            403,
            405,
        }:
            interesting += 1

        if item.get("baseline_match"):
            possible_false_positive += 1

    directory["status"] = "completed"
    directory["updated_at"] = now_iso()
    directory["baseline"] = baseline
    directory["results"] = results

    directory["summary"] = {
        "total": len(results),
        "interesting": interesting,
        "possible_false_positive": possible_false_positive,
        "by_status": by_status,
    }

    directory["evidence"] = [
        str(baseline_file.relative_to(project_root())),
        str(ffuf_file.relative_to(project_root())),
        str(stderr_file.relative_to(project_root())),
    ]

    directory["wordlist"] = str(
        wordlist_path.relative_to(project_root())
    )
    directory["rate_limit"] = rate
    directory["threads"] = threads
    directory["timeout"] = timeout
    directory["match_codes"] = match_codes
    directory["extensions"] = extension_list
    directory["discovered_at"] = now_iso()

    _save_yaml(directory_file(), data)

    print()
    print(f"TARGET          : {base_url}")
    print(f"FOUND           : {len(results)}")
    print(f"INTERESTING     : {interesting}")
    print(f"POSSIBLE FP     : {possible_false_positive}")
    print("STATUS          : completed")
    print(f"FILE            : {directory_file()}")

    if baseline.get("status") == "completed":
        print(
            "BASELINE        : "
            f"HTTP {baseline.get('status_code')} / "
            f"Length {baseline.get('content_length')}"
        )
    else:
        print("BASELINE        : unavailable")

    if results:
        print()
        print("DISCOVERED:")

        for item in results:
            status_code = item.get("status_code", "-")
            print(
                f"  [{status_code:>3}] "
                f"{item.get('path', '/')}"
            )

            if item.get("baseline_match"):
                print(
                    "       Classification: "
                    "possible-false-positive"
                )
                print(
                    "       WARNING       : "
                    "response signature matches baseline"
                )
            else:
                print(
                    "       Classification: "
                    "discovery-candidate"
                )
    else:
        print()
        print("[INFO] Tidak ada path yang match dengan filter.")
        print(
            "       Ini bukan bukti bahwa target tidak memiliki "
            "directory/path lain."
        )

    _record_activity(
        CHECKLIST_ID,
        (
            "Directory discovery completed: "
            f"{len(results)} result(s), "
            f"{possible_false_positive} possible false-positive(s)"
        ),
        "completed",
    )

    return 0


def list_results() -> int:
    data = _load_directory()
    directory = data["directory"]

    summary = directory.get("summary") or {}
    baseline = directory.get("baseline") or {}

    print(f"PROJECT: {data.get('project_id', project_root().name)}")
    print(f"TARGET  : {directory.get('base_url', '-')}")
    print(f"STATUS  : {directory.get('status', '-')}")
    print(f"TOTAL   : {summary.get('total', 0)}")
    print()

    print("BASELINE:")
    print(f"  Status        : {baseline.get('status', '-')}")
    print(f"  URL           : {baseline.get('url', '-')}")
    print(f"  Status Code   : {baseline.get('status_code', '-')}")
    print(
        f"  Content-Length: "
        f"{baseline.get('content_length', '-')}"
    )
    print(
        f"  Content-Type  : "
        f"{baseline.get('content_type', '-')}"
    )
    print(f"  Words         : {baseline.get('words', '-')}")
    print(f"  Lines         : {baseline.get('lines', '-')}")
    print(
        f"  Classification: "
        f"{baseline.get('classification', '-')}"
    )

    results = directory.get("results") or []

    if not results:
        print()
        print("Tidak ada hasil directory discovery.")
        return 0

    print()

    for item in results:
        print(
            f"[{item.get('status_code', '-'):>3}] "
            f"{item.get('path', '/')}"
        )
        print(f"  URL           : {item.get('url', '-')}")
        print(f"  Method        : {item.get('method', '-')}")
        print(
            f"  Content-Length: "
            f"{item.get('content_length', '-')}"
        )
        print(
            f"  Content-Type  : "
            f"{item.get('content_type', '-')}"
        )
        print(f"  Words         : {item.get('words', '-')}")
        print(f"  Lines         : {item.get('lines', '-')}")
        print(
            f"  Classification: "
            f"{item.get('classification', '-')}"
        )
        print(
            f"  Baseline Match: "
            f"{item.get('baseline_match', False)}"
        )

        if item.get("redirect_location"):
            print(
                f"  Redirect      : "
                f"{item.get('redirect_location')}"
            )

        print(f"  Source        : {item.get('source', '-')}")
        print(f"  Notes         : {item.get('notes', '-')}")
        print()

    return 0


def show() -> int:
    data = _load_directory()
    print(yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    ))
    return 0


def verify() -> int:
    data = _load_directory()
    directory = data["directory"]
    baseline = directory.get("baseline") or {}
    summary = directory.get("summary") or {}

    errors: list[str] = []

    if directory.get("checklist_id") != CHECKLIST_ID:
        errors.append("Checklist ID tidak sesuai.")

    if not str(directory.get("target_url", "")).strip():
        errors.append("Target URL kosong.")

    if not str(directory.get("base_url", "")).strip():
        errors.append("Base URL kosong.")

    if directory.get("method") != "ffuf":
        errors.append("Method discovery tidak sesuai.")

    if directory.get("status") != "completed":
        errors.append(
            "Directory discovery belum completed "
            f"(status={directory.get('status')})."
        )

    if baseline.get("status") != "completed":
        errors.append(
            "Baseline random non-existent path belum berhasil."
        )

    if not isinstance(directory.get("results"), list):
        errors.append("results harus berupa list.")

    if not isinstance(summary.get("total"), int):
        errors.append("summary.total tidak valid.")

    if not isinstance(
        summary.get("possible_false_positive"),
        int,
    ):
        errors.append(
            "summary.possible_false_positive tidak valid."
        )

    if errors:
        print("[FAIL] Directory Discovery verification gagal.")

        for error in errors:
            print(f"  - {error}")

        return 1

    print("[PASS] Directory Discovery memenuhi validasi.")
    print(
        f"[PASS] Checklist : "
        f"{CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(
        f"[PASS] Status    : "
        f"{directory.get('status')}"
    )
    print(
        f"[PASS] Baseline  : "
        f"{baseline.get('classification')}"
    )
    print(
        f"[PASS] Results   : "
        f"{summary.get('total', 0)}"
    )
    print(
        f"[PASS] Possible FP: "
        f"{summary.get('possible_false_positive', 0)}"
    )

    _record_activity(
        CHECKLIST_ID,
        "Directory discovery verified",
        "completed",
    )

    return 0


def status() -> int:
    data = _load_directory()
    directory = data["directory"]
    summary = directory.get("summary") or {}
    baseline = directory.get("baseline") or {}

    print(f"Project ID : {data.get('project_id', project_root().name)}")
    print(f"Status     : {directory.get('status', '-')}")
    print(f"Target     : {directory.get('target_url', '-')}")
    print(f"Method     : {directory.get('method', '-')}")
    print(f"Results    : {summary.get('total', 0)}")
    print(
        f"Possible FP: "
        f"{summary.get('possible_false_positive', 0)}"
    )
    print(f"Baseline   : {baseline.get('status', '-')}")
    print(f"Rate       : {directory.get('rate_limit', '-')}")
    print(f"Threads    : {directory.get('threads', '-')}")
    print(f"Timeout    : {directory.get('timeout', '-')}")
    print(f"Wordlist   : {directory.get('wordlist', '-')}")
    print(f"File       : {directory_file()}")

    by_status = summary.get("by_status") or {}

    if by_status:
        print()
        print("HTTP Status:")

        for code in sorted(
            by_status,
            key=lambda value: (value == "unknown", value),
        ):
            print(
                f"  {code}: "
                f"{by_status[code]}"
            )

    return 0


def remove() -> int:
    path = directory_file()

    if not path.exists():
        print("[INFO] Directory Discovery belum ada.")
        return 0

    confirm = input(
        "Hapus seluruh data Directory Discovery "
        "untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(directory_dir())

    _record_activity(
        CHECKLIST_ID,
        "Directory discovery data removed",
        "completed",
    )

    print("[PASS] Directory Discovery berhasil dihapus.")
    return 0


def version() -> int:
    print(
        f"BrebesKab-CSIRT-Tools "
        f"directory.py v{SCRIPT_VERSION}"
    )
    print(
        f"Checklist: "
        f"{CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : ffuf")
    print("Baseline : random non-existent path")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Directory Discovery\n"
        "\n"
        "Usage:\n"
        "  python scripts/reconnaissance/directory.py init\n"
        "  python scripts/reconnaissance/directory.py discover\n"
        "  python scripts/reconnaissance/directory.py list\n"
        "  python scripts/reconnaissance/directory.py show\n"
        "  python scripts/reconnaissance/directory.py verify\n"
        "  python scripts/reconnaissance/directory.py status\n"
        "  python scripts/reconnaissance/directory.py remove\n"
        "  python scripts/reconnaissance/directory.py version\n"
        "\n"
        "discover options:\n"
        "  --wordlist PATH\n"
        "  --rate N\n"
        "  --threads N\n"
        "  --timeout N\n"
        "  --extensions EXT [EXT ...]\n"
        "  --match-codes CODES\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "Directory discovery uses ffuf and a random non-existent URL\n"
        "baseline to identify possible false-positive responses.\n"
    )


def main(argv: list[str] | None = None) -> int:
    args = list(
        sys.argv[1:]
        if argv is None
        else argv
    )

    if not args or args[0] in {"-h", "--help", "help"}:
        print_help()
        return 0

    command = args[0].lower()

    if command == "version":
        return version()

    if command == "init":
        return init()

    if command == "list":
        return list_results()

    if command == "show":
        return show()

    if command == "verify":
        return verify()

    if command == "status":
        return status()

    if command == "remove":
        return remove()

    if command == "discover":
        options = args[1:]
        wordlist: str | None = None
        rate = DEFAULT_RATE
        threads = DEFAULT_THREADS
        timeout = DEFAULT_TIMEOUT
        extensions: list[str] | None = None
        match_codes = DEFAULT_MATCH_CODES

        index = 0

        while index < len(options):
            option = options[index]

            if option == "--wordlist":
                index += 1
                if index >= len(options):
                    print("[FAIL] --wordlist membutuhkan PATH.")
                    return 2
                wordlist = options[index]

            elif option == "--rate":
                index += 1
                if index >= len(options):
                    print("[FAIL] --rate membutuhkan nilai.")
                    return 2
                try:
                    rate = int(options[index])
                except ValueError:
                    print("[FAIL] --rate harus berupa angka.")
                    return 2

            elif option == "--threads":
                index += 1
                if index >= len(options):
                    print("[FAIL] --threads membutuhkan nilai.")
                    return 2
                try:
                    threads = int(options[index])
                except ValueError:
                    print("[FAIL] --threads harus berupa angka.")
                    return 2

            elif option == "--timeout":
                index += 1
                if index >= len(options):
                    print("[FAIL] --timeout membutuhkan nilai.")
                    return 2
                try:
                    timeout = int(options[index])
                except ValueError:
                    print("[FAIL] --timeout harus berupa angka.")
                    return 2

            elif option == "--match-codes":
                index += 1
                if index >= len(options):
                    print("[FAIL] --match-codes membutuhkan nilai.")
                    return 2
                match_codes = options[index]

            elif option == "--extensions":
                extensions = []
                index += 1

                while index < len(options):
                    value = options[index]
                    if value.startswith("--"):
                        index -= 1
                        break
                    extensions.append(value)
                    index += 1

            else:
                print(f"[FAIL] Option tidak dikenal: {option}")
                return 2

            index += 1

        try:
            return discover(
                wordlist=wordlist,
                rate=rate,
                threads=threads,
                timeout=timeout,
                extensions=extensions,
                match_codes=match_codes,
            )
        except (
            ContextError,
            DirectoryError,
            ActivityError,
        ) as exc:
            print(f"[FAIL] {exc}")
            return 1

    print(f"[ERROR] Command tidak dikenal: {args[0]}")
    print()
    print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
