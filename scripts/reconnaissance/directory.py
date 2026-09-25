#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance: Directory Discovery

Checklist:
    2-006 Directory discovery

Purpose:
    Discover web paths/directories on the authorized target using a controlled
    ffuf wordlist scan. The module records candidates as reconnaissance data;
    it does not treat a discovered path as a vulnerability.

Safety:
    - Uses the active project's target.yaml.
    - Does not automatically scan discovered subdomains.
    - Defaults to the primary in-scope target only.
    - Uses a conservative rate limit.
    - Does not perform destructive HTTP methods.
    - Does not upload files or modify application data.
    - Discovery results are evidence, not authorization.

Commands:
    init
    discover
    list
    show
    verify
    status
    remove
    version
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml


SCRIPT_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"

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

DEFAULT_EXTENSIONS = [
    "php",
    "html",
    "txt",
    "json",
    "xml",
]

DEFAULT_RATE = 10
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 5
DEFAULT_MATCH_CODES = "200,204,301,302,307,308,401,403,405"
DEFAULT_MAX_TIME = 0

DISCOVERY_DIR = "directory"
OUTPUT_FILE = "directory.yaml"


def _bootstrap_import_path() -> None:
    """
    The repository contains reconnaissance/http.py. If scripts/reconnaissance
    remains on sys.path while importing requests/yaml, Python may shadow the
    stdlib http package. Remove the current script directory before importing
    project-local modules.
    """
    script_dir = Path(__file__).resolve().parent
    scripts_dir = script_dir.parent

    for path in (str(script_dir), str(scripts_dir)):
        while path in sys.path:
            sys.path.remove(path)


_bootstrap_import_path()

try:
    from context import require_active_project
except ImportError:
    # Allows direct execution from the repository while keeping the same
    # behavior as the other reconnaissance modules.
    repo_root = Path(__file__).resolve().parents[2]
    scripts_root = repo_root / "scripts"
    for candidate in (repo_root, scripts_root):
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
    from context import require_active_project

try:
    from activity import record_activity
except ImportError:
    record_activity = None


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def project_context():
    return require_active_project()


def project_root() -> Path:
    context = project_context()
    return Path(context.project_path)


def output_dir() -> Path:
    return project_root() / "02-reconnaissance" / DISCOVERY_DIR


def output_file() -> Path:
    return output_dir() / OUTPUT_FILE


def evidence_dir() -> Path:
    return output_dir() / "evidence"


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {path}")

    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    if not isinstance(data, dict):
        raise ValueError(f"Format YAML tidak valid: {path}")

    return data


def save_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(
            data,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def load_target() -> dict[str, Any]:
    path = project_root() / "02-reconnaissance" / "target" / "target.yaml"
    data = load_yaml(path)

    target = data.get("target")
    if not isinstance(target, dict):
        raise ValueError("target.yaml tidak memiliki blok 'target'.")

    if target.get("status") != "completed":
        raise ValueError(
            "Target belum berstatus completed. Jalankan target.py terlebih dahulu."
        )

    target_url = str(target.get("target_url") or "").strip()
    if not target_url:
        raise ValueError("target.target_url tidak tersedia.")

    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"Target URL tidak valid: {target_url}")

    return {
        "application": target.get("application", ""),
        "target_url": target_url,
        "hostname": target.get("hostname", parsed.hostname),
        "scheme": parsed.scheme,
        "port": str(target.get("port") or parsed.port or ("443" if parsed.scheme == "https" else "80")),
        "environment": target.get("environment", ""),
        "assessment_type": target.get("assessment_type", ""),
        "scope_reference": target.get("scope_reference", ""),
    }


def normalize_base_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"URL target tidak valid: {url}")

    # Directory discovery should operate from the target origin. A path
    # supplied by target.yaml is retained only when it is not the root.
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"

    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"

    if path == "//":
        path = "/"

    return urljoin(base + "/", path.lstrip("/"))


def resolve_ffuf() -> str | None:
    candidates = []

    configured = os.environ.get("BREBES_FFUF")
    if configured:
        candidates.append(Path(configured))

    repo_root = Path(__file__).resolve().parents[2]
    candidates.extend(
        [
            repo_root / "tools" / "ffuf" / "ffuf.exe",
            repo_root / "tools" / "ffuf" / "ffuf",
        ]
    )

    which = shutil.which("ffuf")
    if which:
        candidates.append(Path(which))

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate)

    return None


def write_default_wordlist() -> Path:
    path = evidence_dir() / "directory-wordlist.txt"
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as handle:
        for item in DEFAULT_WORDLIST:
            handle.write(item + "\n")

    return path


def load_existing() -> dict[str, Any]:
    path = output_file()
    if not path.exists():
        raise FileNotFoundError(
            "directory.yaml belum ada. Jalankan 'init' terlebih dahulu."
        )

    data = load_yaml(path)

    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"Schema directory.yaml tidak didukung: {data.get('schema_version')}"
        )

    return data


def record(
    item: str,
    action: str,
    status: str,
) -> None:
    if record_activity is None:
        return

    try:
        record_activity(
            phase="02-reconnaissance",
            item=item,
            action=action,
            status=status,
        )
    except TypeError:
        # Compatibility with activity.py implementations that use positional
        # or slightly different optional arguments.
        try:
            record_activity(
                "02-reconnaissance",
                item,
                action,
                status,
            )
        except Exception:
            pass
    except Exception:
        pass


def init() -> int:
    target = load_target()

    out_dir = output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir().mkdir(parents=True, exist_ok=True)

    wordlist = write_default_wordlist()

    data = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_root().name,
        "updated_at": now_iso(),
        "directory": {
            "status": "not-started",
            "checklist_id": CHECKLIST_ID,
            "checklist_name": CHECKLIST_NAME,
            "application": target["application"],
            "target_url": target["target_url"],
            "base_url": normalize_base_url(target["target_url"]),
            "hostname": target["hostname"],
            "environment": target["environment"],
            "assessment_type": target["assessment_type"],
            "scope_reference": target["scope_reference"],
            "method": "ffuf",
            "wordlist": str(wordlist.relative_to(project_root())),
            "rate_limit": DEFAULT_RATE,
            "timeout": DEFAULT_TIMEOUT,
            "threads": DEFAULT_THREADS,
            "match_codes": DEFAULT_MATCH_CODES,
            "extensions": DEFAULT_EXTENSIONS,
            "follow_redirects": False,
            "results": [],
            "summary": {
                "total": 0,
                "interesting": 0,
                "by_status": {},
            },
            "evidence": [],
            "notes": "",
            "discovered_at": "",
        },
    }

    save_yaml(output_file(), data)

    record(
        CHECKLIST_ID,
        "Directory discovery initialized",
        "in-progress",
    )

    print("[PASS] Directory Discovery berhasil diinisialisasi.")
    print(f"PROJECT: {project_root().name}")
    print(f"TARGET : {target['target_url']}")
    print(f"FILE   : {output_file()}")

    return 0


def parse_ffuf_results(
    ffuf_json: Path,
    base_url: str,
) -> list[dict[str, Any]]:
    raw = load_yaml(ffuf_json) if ffuf_json.suffix in {".yaml", ".yml"} else None

    if raw is not None:
        payload = raw
    else:
        with ffuf_json.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

    results = payload.get("results", [])
    if not isinstance(results, list):
        return []

    parsed_results: list[dict[str, Any]] = []

    for result in results:
        if not isinstance(result, dict):
            continue

        url = str(result.get("url") or "").strip()
        input_data = result.get("input") or {}
        word = ""

        if isinstance(input_data, dict):
            word = str(
                input_data.get("FUZZ")
                or input_data.get("fuzz")
                or ""
            ).strip()

        status = result.get("status")
        length = result.get("length")
        words = result.get("words")
        lines = result.get("lines")
        content_type = result.get("content-type") or result.get("content_type")

        if not url and word:
            url = urljoin(base_url, word)

        if not url:
            continue

        parsed_results.append(
            {
                "path": urlparse(url).path or "/",
                "url": url,
                "status_code": int(status) if status is not None else None,
                "content_length": int(length) if length is not None else None,
                "words": int(words) if words is not None else None,
                "lines": int(lines) if lines is not None else None,
                "content_type": content_type,
                "redirect_location": result.get("redirectlocation")
                or result.get("redirect_location"),
                "method": "GET",
                "source": "ffuf",
            }
        )

    return parsed_results


def discover(
    wordlist: str | None = None,
    rate: int = DEFAULT_RATE,
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
    extensions: list[str] | None = None,
    match_codes: str = DEFAULT_MATCH_CODES,
) -> int:
    data = load_existing()
    directory = data["directory"]

    target_url = directory["target_url"]
    base_url = directory["base_url"]

    ffuf = resolve_ffuf()
    if not ffuf:
        print("[FAIL] ffuf tidak ditemukan.")
        print("       Install ffuf atau letakkan executable di tools/ffuf/ffuf.exe.")
        return 1

    if rate < 1:
        print("[FAIL] Rate harus >= 1 request/second.")
        return 1

    if threads < 1:
        print("[FAIL] Threads harus >= 1.")
        return 1

    if timeout < 1:
        print("[FAIL] Timeout harus >= 1 detik.")
        return 1

    if wordlist:
        wordlist_path = Path(wordlist).expanduser().resolve()
    else:
        configured = directory.get("wordlist")
        if configured:
            wordlist_path = project_root() / str(configured)
        else:
            wordlist_path = write_default_wordlist()

    if not wordlist_path.exists():
        print(f"[FAIL] Wordlist tidak ditemukan: {wordlist_path}")
        return 1

    ext_list = extensions if extensions is not None else list(
        directory.get("extensions") or DEFAULT_EXTENSIONS
    )

    output_json = evidence_dir() / "ffuf-directory.json"
    stderr_file = evidence_dir() / "ffuf-directory.stderr.log"

    evidence_dir().mkdir(parents=True, exist_ok=True)

    command = [
        ffuf,
        "-u",
        base_url.rstrip("/") + "/FUZZ",
        "-w",
        str(wordlist_path),
        "-of",
        "json",
        "-o",
        str(output_json),
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

    if ext_list:
        command.extend(["-e", ",".join("." + ext.lstrip(".") for ext in ext_list)])

    print("[INFO] Menjalankan 2-006: Directory discovery")
    print(f"[INFO] Target   : {base_url}")
    print(f"[INFO] Wordlist : {wordlist_path}")
    print(f"[INFO] Rate     : {rate} req/s")
    print(f"[INFO] Threads  : {threads}")
    print(f"[INFO] Timeout  : {timeout}s")
    print(f"[INFO] Matcher  : {match_codes}")

    record(
        CHECKLIST_ID,
        f"Directory discovery started: {base_url}",
        "in-progress",
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
        save_yaml(output_file(), data)
        record(
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
        # ffuf may return non-zero when the scan itself cannot be completed.
        print(f"[FAIL] ffuf gagal dengan exit code {completed.returncode}.")
        if completed.stderr:
            print(completed.stderr.strip())

        directory["status"] = "failed"
        directory["updated_at"] = now_iso()
        directory["evidence"] = [
            str(output_json.relative_to(project_root())),
            str(stderr_file.relative_to(project_root())),
        ]
        save_yaml(output_file(), data)

        record(
            CHECKLIST_ID,
            f"Directory discovery failed: ffuf exit code {completed.returncode}",
            "failed",
        )
        return 1

    if not output_json.exists():
        print("[FAIL] ffuf selesai tetapi output JSON tidak ditemukan.")
        directory["status"] = "failed"
        directory["updated_at"] = now_iso()
        save_yaml(output_file(), data)
        record(
            CHECKLIST_ID,
            "Directory discovery failed: ffuf output missing",
            "failed",
        )
        return 1

    try:
        results = parse_ffuf_results(output_json, base_url)
    except Exception as exc:
        print(f"[FAIL] Gagal membaca hasil ffuf: {exc}")
        directory["status"] = "failed"
        directory["updated_at"] = now_iso()
        save_yaml(output_file(), data)
        record(
            CHECKLIST_ID,
            f"Directory discovery failed: invalid ffuf result ({exc})",
            "failed",
        )
        return 1

    by_status: dict[str, int] = {}
    interesting = 0

    for item in results:
        code = item.get("status_code")
        key = str(code) if code is not None else "unknown"
        by_status[key] = by_status.get(key, 0) + 1

        if code in {200, 204, 301, 302, 307, 308, 401, 403, 405}:
            interesting += 1

    directory["status"] = "completed"
    directory["updated_at"] = now_iso()
    directory["results"] = results
    directory["summary"] = {
        "total": len(results),
        "interesting": interesting,
        "by_status": by_status,
    }
    directory["evidence"] = [
        str(output_json.relative_to(project_root())),
        str(stderr_file.relative_to(project_root())),
    ]
    directory["wordlist"] = str(wordlist_path.relative_to(project_root()))
    directory["rate_limit"] = rate
    directory["threads"] = threads
    directory["timeout"] = timeout
    directory["match_codes"] = match_codes
    directory["extensions"] = ext_list
    directory["discovered_at"] = now_iso()

    save_yaml(output_file(), data)

    print()
    print(f"TARGET       : {base_url}")
    print(f"FOUND        : {len(results)}")
    print(f"INTERESTING  : {interesting}")
    print(f"STATUS       : completed")
    print(f"FILE         : {output_file()}")

    if results:
        print()
        print("DISCOVERED:")
        for item in results:
            print(
                f"  [{item.get('status_code', '-'):>3}] "
                f"{item.get('path', '/')}"
            )
    else:
        print()
        print("[INFO] Tidak ada path yang match dengan filter.")
        print("       Ini bukan bukti bahwa target tidak memiliki directory/path lain.")

    record(
        CHECKLIST_ID,
        f"Directory discovery completed: {len(results)} result(s)",
        "completed",
    )

    return 0


def list_results() -> int:
    data = load_existing()
    directory = data["directory"]

    print(f"PROJECT: {data.get('project_id', project_root().name)}")
    print(f"TARGET  : {directory.get('base_url', '-')}")
    print(f"STATUS  : {directory.get('status', '-')}")
    print(f"TOTAL   : {directory.get('summary', {}).get('total', 0)}")

    results = directory.get("results", [])

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
        print(f"  Content-Length: {item.get('content_length', '-')}")
        print(f"  Content-Type  : {item.get('content_type', '-')}")
        if item.get("redirect_location"):
            print(f"  Redirect      : {item['redirect_location']}")
        print(f"  Source        : {item.get('source', '-')}")
        print()

    return 0


def show() -> int:
    data = load_existing()
    directory = data["directory"]

    print(yaml.safe_dump(data, allow_unicode=True, sort_keys=False))
    return 0


def verify() -> int:
    data = load_existing()
    directory = data["directory"]

    errors: list[str] = []

    if directory.get("checklist_id") != CHECKLIST_ID:
        errors.append("Checklist ID tidak sesuai.")

    if not directory.get("target_url"):
        errors.append("Target URL kosong.")

    if not directory.get("base_url"):
        errors.append("Base URL kosong.")

    if directory.get("method") != "ffuf":
        errors.append("Method discovery tidak sesuai.")

    status = directory.get("status")

    if status != "completed":
        errors.append(
            f"Directory discovery belum completed (status={status})."
        )

    summary = directory.get("summary") or {}
    if not isinstance(summary.get("total"), int):
        errors.append("Summary total tidak valid.")

    results = directory.get("results")
    if not isinstance(results, list):
        errors.append("Results bukan list.")

    if errors:
        print("[FAIL] Directory Discovery verification gagal.")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("[PASS] Directory Discovery memenuhi validasi.")
    print(f"[PASS] Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Status   : {status}")
    print(f"[PASS] Results  : {summary.get('total', 0)}")

    record(
        CHECKLIST_ID,
        "Directory discovery verified",
        "completed",
    )

    return 0


def status() -> int:
    data = load_existing()
    directory = data["directory"]
    summary = directory.get("summary") or {}

    print(f"PROJECT : {data.get('project_id', project_root().name)}")
    print(f"Target  : {directory.get('target_url', '-')}")
    print(f"Status  : {directory.get('status', '-')}")
    print(f"Method  : {directory.get('method', '-')}")
    print(f"Results : {summary.get('total', 0)}")
    print(f"Rate    : {directory.get('rate_limit', '-')}")
    print(f"Threads : {directory.get('threads', '-')}")
    print(f"Timeout : {directory.get('timeout', '-')}")
    print(f"Wordlist: {directory.get('wordlist', '-')}")
    print(f"File    : {output_file()}")

    by_status = summary.get("by_status") or {}
    if by_status:
        print()
        print("HTTP Status:")
        for code in sorted(by_status, key=lambda value: (value == "unknown", value)):
            print(f"  {code}: {by_status[code]}")

    return 0


def remove() -> int:
    path = output_file()

    if not path.exists():
        print("[INFO] directory.yaml tidak ditemukan.")
        return 0

    confirm = input(
        "Hapus seluruh data Directory Discovery untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0

    shutil.rmtree(output_dir())

    record(
        CHECKLIST_ID,
        "Directory discovery data removed",
        "completed",
    )

    print("[PASS] Directory Discovery berhasil dihapus.")
    return 0


def version() -> int:
    print(f"BrebesKab-CSIRT-Tools directory.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : ffuf")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BrebesKab-CSIRT-Tools - Directory Discovery"
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("init", help="Initialize Directory Discovery")
    sub.add_parser("list", help="List discovered paths")
    sub.add_parser("show", help="Show directory.yaml")
    sub.add_parser("verify", help="Validate Directory Discovery")
    sub.add_parser("status", help="Show Directory Discovery status")
    sub.add_parser("remove", help="Remove Directory Discovery data")
    sub.add_parser("version", help="Show version")

    discover_parser = sub.add_parser(
        "discover",
        help="Run controlled directory discovery with ffuf",
    )
    discover_parser.add_argument(
        "--wordlist",
        help="Path to a custom ffuf wordlist",
    )
    discover_parser.add_argument(
        "--rate",
        type=int,
        default=DEFAULT_RATE,
        help=f"Maximum requests/second (default: {DEFAULT_RATE})",
    )
    discover_parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Concurrent ffuf threads (default: {DEFAULT_THREADS})",
    )
    discover_parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    discover_parser.add_argument(
        "--extensions",
        nargs="*",
        default=None,
        help="Extensions without or with dot, e.g. php html json",
    )
    discover_parser.add_argument(
        "--match-codes",
        default=DEFAULT_MATCH_CODES,
        help=f"HTTP status matcher (default: {DEFAULT_MATCH_CODES})",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "init":
            return init()
        if args.command == "discover":
            return discover(
                wordlist=args.wordlist,
                rate=args.rate,
                threads=args.threads,
                timeout=args.timeout,
                extensions=args.extensions,
                match_codes=args.match_codes,
            )
        if args.command == "list":
            return list_results()
        if args.command == "show":
            return show()
        if args.command == "verify":
            return verify()
        if args.command == "status":
            return status()
        if args.command == "remove":
            return remove()
        if args.command == "version":
            return version()

    except KeyboardInterrupt:
        print()
        print("[WARN] Directory discovery dihentikan oleh operator.")
        record(
            CHECKLIST_ID,
            "Directory discovery interrupted by operator",
            "failed",
        )
        return 130
    except Exception as exc:
        print(f"[FAIL] {exc}")
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
