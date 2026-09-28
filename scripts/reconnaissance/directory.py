#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Reconnaissance - Directory Enumeration & Adaptive Scoring Engine

Version: 2.0.0

Checklist mapping:
    02-006 - Directory discovery

Purpose:
    Perform authorized directory/path enumeration with ffuf and Gobuster,
    using a global wordlist manifest, project selection metadata, baseline
    comparison, fuzzy response similarity, adaptive scoring, request budgets,
    feedback, confidence, evidence, and traceability.

Design:
    - The project owns references/metadata, not copies of global wordlists.
    - ffuf and Gobuster are normalized into one result schema.
    - Baseline responses are used as the primary noise/false-positive signal.
    - Wordlists have an initial score, runtime score, tier, and confidence.
    - Feedback is bounded and persisted per run; history is append-only.
    - Exploration candidates remain eligible even when their score is low.
    - Raw tool output is retained as evidence; no response bodies are stored.
    - This module does not authorize newly discovered paths.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# Import safety
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

for _entry in (str(SCRIPT_DIR), str(SCRIPTS_DIR)):
    while _entry in sys.path:
        sys.path.remove(_entry)

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.append(str(SCRIPTS_DIR))

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
    from context import ContextError, require_active_project
except ImportError:
    ContextError = RuntimeError

    def require_active_project() -> Any:
        raise RuntimeError("context.py tidak dapat di-import.")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_VERSION = "2.0.2"
SCHEMA_VERSION = "2.0"
CHECKLIST_ID = "2-006"
CHECKLIST_NAME = "Directory discovery"

DEFAULT_RATE = 10
DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 5
DEFAULT_MATCH_CODES = "200,204,301,302,307,308,401,403,405"
BASELINE_ATTEMPTS = 3
BASELINE_PREFIX = ".brebes-csirt-baseline"

DEFAULT_INITIAL_SCORE = 0.50
DEFAULT_PRIMARY_MIN = 0.80
DEFAULT_SECONDARY_MIN = 0.50
DEFAULT_EXPLORATION_MIN = 0.20

DEFAULT_EXTENSIONS = ["php", "html", "txt", "json", "xml"]

DEFAULT_MAX_EVIDENCE_GAIN = 0.15
DEFAULT_MAX_DISCOVERY_YIELD = 0.15
DEFAULT_MAX_NOISE_PENALTY = 0.20

DEFAULT_FUZZY_WEIGHTS = {
    "status_code": 0.35,
    "content_length": 0.25,
    "content_type": 0.10,
    "words": 0.15,
    "lines": 0.15,
}

INTERESTING_STATUS_CODES = {
    200, 204, 206, 301, 302, 307, 308, 401, 403, 405
}

HIGH_VALUE_STATUS_CODES = {200, 401, 403, 405}

SENSITIVE_PATH_TERMS = {
    "admin", "administrator", "backup", "backups", "config", "configuration",
    "debug", "internal", "private", "secret", "secrets", "upload", "uploads",
    "login", "signin", "dashboard", "api", "swagger", "openapi", "actuator",
    "server-status", "phpinfo", ".git", ".svn", ".env", "database", "db",
    "storage", "vendor", "test", "dev", "staging", "old", "tmp"
}


class DirectoryError(RuntimeError):
    """Raised when directory reconnaissance cannot be completed."""


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def run_id() -> str:
    return (
        "DIR-"
        + dt.datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
        + "-"
        + secrets.token_hex(3)
    )


def project_root() -> Path:
    context = require_active_project()
    return Path(context.project_path)


def directory_dir() -> Path:
    return project_root() / "02-reconnaissance" / "directory"


def directory_file() -> Path:
    return directory_dir() / "directory.yaml"


def evidence_dir() -> Path:
    return directory_dir() / "evidence"


def project_wordlists_dir() -> Path:
    return project_root() / "wordlists"


def selection_file() -> Path:
    return project_wordlists_dir() / "selected" / "selection.yaml"


def scoring_config_file() -> Path:
    return project_root() / "scoring" / "config" / "scoring.yaml"


def scoring_baseline_dir() -> Path:
    return project_root() / "scoring" / "baseline"


def scoring_results_dir() -> Path:
    return project_root() / "scoring" / "results"


def scoring_feedback_dir() -> Path:
    return project_root() / "scoring" / "feedback"


def scoring_history_dir() -> Path:
    return project_root() / "scoring" / "history"


def wordlist_runs_dir() -> Path:
    return project_wordlists_dir() / "runs"


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(project_root()))
    except ValueError:
        return str(path)


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


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        raise DirectoryError(f"Gagal menulis {path}\n{exc}") from exc


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        if math.isfinite(number):
            return number
    except (TypeError, ValueError):
        pass
    return default


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def _ratio_similarity(a: Any, b: Any) -> float:
    if a is None or b is None:
        return 0.0
    try:
        left = abs(float(a))
        right = abs(float(b))
    except (TypeError, ValueError):
        return 0.0
    if left == right:
        return 1.0
    denominator = max(left, right, 1.0)
    return _clamp(1.0 - abs(left - right) / denominator)


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


# ---------------------------------------------------------------------------
# Project / target state
# ---------------------------------------------------------------------------

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
            "enumeration": {
                "default_tool": "auto",
                "allowed_tools": ["ffuf", "gobuster"],
                "rate_limit": DEFAULT_RATE,
                "threads": DEFAULT_THREADS,
                "timeout": DEFAULT_TIMEOUT,
                "match_codes": DEFAULT_MATCH_CODES,
                "extensions": DEFAULT_EXTENSIONS,
                "follow_redirects": False,
            },
            "matching": {
                "fuzzy_enabled": True,
                "baseline_required": True,
            },
            "scoring": {
                "enabled": True,
                "adaptive": True,
            },
            "request_budget": {
                "enabled": True,
                "max_requests": None,
            },
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
                "confidence": 0.0,
            },
            "runs": [],
            "results": [],
            "summary": {
                "total": 0,
                "interesting": 0,
                "possible_false_positive": 0,
                "unique_paths": 0,
                "by_status": {},
            },
            "evidence": [],
            "notes": "",
            "discovered_at": "",
        },
    }


def _load_directory() -> dict[str, Any]:
    data = _load_yaml(directory_file(), "Directory reconnaissance")

    if data.get("project_id") != project_root().name:
        raise DirectoryError(
            "Project ID pada directory.yaml tidak sesuai active project.\n"
            f"  Context : {project_root().name}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    schema = str(data.get("schema_version", "")).strip()
    if schema not in {"1.1", SCHEMA_VERSION}:
        raise DirectoryError(
            f"Schema directory.yaml tidak didukung: {schema!r}"
        )

    directory = data.get("directory")
    if not isinstance(directory, dict):
        raise DirectoryError(
            "Field 'directory' pada directory.yaml harus berupa mapping/object."
        )

    return data


def _ensure_v2_state(data: dict[str, Any]) -> dict[str, Any]:
    """
    Migrate the previous 1.1 directory.yaml shape in memory without deleting
    historical evidence. The caller persists the upgraded state.
    """
    directory = data["directory"]

    enumeration = directory.get("enumeration")
    if not isinstance(enumeration, dict):
        enumeration = {
            "default_tool": str(directory.get("method") or "ffuf"),
            "allowed_tools": ["ffuf", "gobuster"],
            "rate_limit": int(directory.get("rate_limit") or DEFAULT_RATE),
            "threads": int(directory.get("threads") or DEFAULT_THREADS),
            "timeout": int(directory.get("timeout") or DEFAULT_TIMEOUT),
            "match_codes": str(
                directory.get("match_codes") or DEFAULT_MATCH_CODES
            ),
            "extensions": list(
                directory.get("extensions") or DEFAULT_EXTENSIONS
            ),
            "follow_redirects": bool(
                directory.get("follow_redirects", False)
            ),
        }
        directory["enumeration"] = enumeration
    else:
        enumeration.setdefault("default_tool", "auto")
        enumeration.setdefault("allowed_tools", ["ffuf", "gobuster"])
        enumeration.setdefault("rate_limit", DEFAULT_RATE)
        enumeration.setdefault("threads", DEFAULT_THREADS)
        enumeration.setdefault("timeout", DEFAULT_TIMEOUT)
        enumeration.setdefault("match_codes", DEFAULT_MATCH_CODES)
        enumeration.setdefault("extensions", DEFAULT_EXTENSIONS)
        enumeration.setdefault("follow_redirects", False)

    directory.setdefault(
        "matching",
        {"fuzzy_enabled": True, "baseline_required": True},
    )
    directory.setdefault(
        "scoring",
        {"enabled": True, "adaptive": True},
    )
    directory.setdefault(
        "request_budget",
        {"enabled": True, "max_requests": None},
    )
    directory.setdefault("runs", [])
    directory.setdefault("evidence", [])
    directory.setdefault("results", [])
    directory.setdefault(
        "summary",
        {
            "total": len(directory.get("results") or []),
            "interesting": 0,
            "possible_false_positive": 0,
            "unique_paths": 0,
            "by_status": {},
        },
    )

    if "method" not in directory:
        directory["method"] = enumeration.get("default_tool", "auto")
    if "wordlist" not in directory:
        directory["wordlist"] = ""

    data["schema_version"] = SCHEMA_VERSION
    data["updated_at"] = now_iso()
    return data


# ---------------------------------------------------------------------------
# Global wordlist manifest and selection
# ---------------------------------------------------------------------------

def _repository_root() -> Path:
    return SCRIPT_DIR.parent.parent


CANONICAL_WORDLIST_MANIFEST = (
    "config/dictionaries/directory/manifest.json"
)


def _manifest_candidates() -> list[Path]:
    """Return the single canonical global wordlist manifest.

    The project must never create or depend on a project-local manifest.
    Legacy paths are intentionally not returned here so a stale installation
    cannot silently become the source of truth.
    """
    repo = _repository_root()
    return [
        repo / "config" / "dictionaries" / "directory" / "manifest.json",
    ]


def _resolve_manifest_path(raw: str) -> Path:
    """Resolve a wordlist path without copying it into the project.

    Relative paths in the global manifest are resolved from the repository
    root first. Absolute paths are accepted as-is. Project-local resolution
    is deliberately not used as a fallback because the global manifest is
    the canonical source of wordlist locations.
    """
    value = str(raw).strip()
    if not value:
        return Path()

    path = Path(value).expanduser()
    if path.is_absolute():
        return path.resolve()

    return (_repository_root() / path).resolve()


def _load_manifest() -> tuple[Path, list[dict[str, Any]]]:
    candidates = [path for path in _manifest_candidates() if path.is_file()]
    if not candidates:
        raise DirectoryError(
            "Global wordlist manifest tidak ditemukan. Dicari di:\n"
            + "\n".join(f"  - {p}" for p in _manifest_candidates())
        )

    path = candidates[0]

    if path.resolve() != (
        _repository_root()
        / "config"
        / "dictionaries"
        / "directory"
        / "manifest.json"
    ).resolve():
        raise DirectoryError(
            "Manifest yang digunakan bukan canonical global manifest: "
            f"{path}"
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DirectoryError(
            f"Manifest wordlist tidak valid: {path}\n{exc}"
        ) from exc

    if isinstance(payload, list):
        raw_items: Any = payload
    elif isinstance(payload, dict):
        raw_items = (
            payload.get("wordlists")
            or payload.get("items")
            or payload.get("entries")
            or payload.get("data")
            or []
        )
    else:
        raw_items = []

    if not isinstance(raw_items, list):
        raise DirectoryError(
            f"Daftar wordlist pada manifest bukan list: {path}"
        )

    items: list[dict[str, Any]] = []

    for raw in raw_items:
        if not isinstance(raw, dict):
            continue

        wordlist_id = str(
            raw.get("wordlist_id")
            or raw.get("id")
            or raw.get("name")
            or ""
        ).strip()

        if not wordlist_id:
            continue

        item = dict(raw)
        item["wordlist_id"] = wordlist_id

        raw_path = (
            raw.get("path")
            or raw.get("file")
            or raw.get("wordlist_path")
            or raw.get("local_path")
            or raw.get("source_path")
            or raw.get("downloaded_path")
            or ""
        )

        item["path"] = str(raw_path).strip()

        if item["path"]:
            item["resolved_path"] = str(
                _resolve_manifest_path(item["path"])
            )

        items.append(item)

    return path, items


def _load_selection() -> dict[str, Any]:
    if not selection_file().is_file():
        return {
            "schema_version": "1.0",
            "project_id": project_root().name,
            "wordlists": [],
            "runs": [],
        }

    data = _load_yaml(selection_file(), "Wordlist selection")

    project_id = str(data.get("project_id", "")).strip()
    if project_id and project_id != project_root().name:
        raise DirectoryError(
            "Project ID pada selection.yaml tidak sesuai active project."
        )

    if not isinstance(data.get("wordlists", []), list):
        raise DirectoryError(
            "Field 'wordlists' pada selection.yaml harus berupa list."
        )

    data.setdefault("runs", [])
    return data


def _write_selection(data: dict[str, Any]) -> None:
    data["project_id"] = project_root().name
    data.setdefault("schema_version", "1.0")
    _save_yaml(selection_file(), data)


def _manifest_item_by_id(
    manifest_items: list[dict[str, Any]],
    wordlist_id: str,
) -> dict[str, Any] | None:
    wanted = wordlist_id.strip().lower()

    for item in manifest_items:
        if (
            str(item.get("wordlist_id", "")).strip().lower()
            == wanted
        ):
            return item

    return None


def _initial_score_for_item(item: dict[str, Any]) -> float:
    for key in (
        "initial_score",
        "score",
        "prior_score",
        "priority_score",
    ):
        if key in item:
            return _clamp(
                _safe_float(
                    item.get(key),
                    DEFAULT_INITIAL_SCORE,
                )
            )

    return DEFAULT_INITIAL_SCORE


def _tier_for_score(
    score: float,
    config: dict[str, Any],
) -> str:
    ranking = (
        config.get("ranking")
        if isinstance(config.get("ranking"), dict)
        else {}
    )

    tiers = (
        ranking.get("tiers")
        if isinstance(ranking, dict)
        else None
    )

    if isinstance(tiers, list):
        for tier in tiers:
            if not isinstance(tier, dict):
                continue

            minimum = _safe_float(
                tier.get("min_score"),
                -1,
            )
            maximum = _safe_float(
                tier.get("max_score"),
                -1,
            )

            if minimum <= score <= maximum:
                return str(
                    tier.get("name")
                    or "Exploration"
                )

    if score >= DEFAULT_PRIMARY_MIN:
        return "Primary"

    if score >= DEFAULT_SECONDARY_MIN:
        return "Secondary"

    return "Exploration"


def _selection_candidates(
    selection: dict[str, Any],
    manifest_items: list[dict[str, Any]],
    scoring_config: dict[str, Any],
) -> list[dict[str, Any]]:
    selected = selection.get("wordlists") or []

    if not isinstance(selected, list):
        selected = []

    result: list[dict[str, Any]] = []

    for raw in selected:
        if not isinstance(raw, dict):
            continue

        if raw.get("enabled", True) is False:
            continue

        wordlist_id = str(
            raw.get("wordlist_id")
            or raw.get("id")
            or ""
        ).strip()

        if not wordlist_id:
            continue

        manifest = (
            _manifest_item_by_id(
                manifest_items,
                wordlist_id,
            )
            or {}
        )

        merged = dict(manifest)
        merged.update(raw)
        merged["wordlist_id"] = wordlist_id
        # The manifest reference is metadata only and always canonical.
        merged["manifest_path"] = CANONICAL_WORDLIST_MANIFEST

        if not merged.get("path"):
            merged["path"] = manifest.get("path", "")

        if merged.get("path"):
            merged["resolved_path"] = str(
                _resolve_manifest_path(
                    str(merged["path"])
                )
            )

        initial = _clamp(
            _safe_float(
                merged.get("initial_score"),
                _initial_score_for_item(manifest),
            )
        )

        merged["initial_score"] = initial
        merged["score"] = _clamp(
            _safe_float(
                merged.get("final_score"),
                initial,
            )
        )
        merged["tier"] = _tier_for_score(
            merged["score"],
            scoring_config,
        )
        merged["confidence"] = _clamp(
            _safe_float(
                merged.get("confidence"),
                0.0,
            )
        )

        result.append(merged)

    return result


def _bootstrap_selection_from_manifest(
    scoring_config: dict[str, Any],
    limit: int | None = None,
) -> dict[str, Any]:
    manifest_path, manifest_items = _load_manifest()
    selection = _load_selection()

    existing = {
        str(item.get("wordlist_id", "")).strip().lower()
        for item in selection.get("wordlists", [])
        if isinstance(item, dict)
    }

    added = 0

    for item in manifest_items:
        wordlist_id = str(
            item.get("wordlist_id", "")
        ).strip()

        if (
            not wordlist_id
            or wordlist_id.lower() in existing
        ):
            continue

        path = str(item.get("path", "")).strip()

        if not path:
            continue

        score = _initial_score_for_item(item)

        selection.setdefault(
            "wordlists",
            [],
        ).append(
            {
                "wordlist_id": wordlist_id,
                "source": str(
                    item.get("source")
                    or item.get("provider")
                    or "unknown"
                ),
                "manifest_path": CANONICAL_WORDLIST_MANIFEST,
                "path": path,
                "enabled": True,
                "initial_score": score,
                "tier": _tier_for_score(
                    score,
                    scoring_config,
                ),
                "confidence": 0.0,
                "notes": (
                    "Auto-bootstrapped from global manifest."
                ),
            }
        )

        existing.add(wordlist_id.lower())
        added += 1

        if (
            limit is not None
            and added >= limit
        ):
            break

    _write_selection(selection)
    return selection


def list_wordlists() -> int:
    scoring_config = _load_scoring_config()

    try:
        manifest_path, manifest_items = _load_manifest()
    except DirectoryError as exc:
        print(f"[FAIL] {exc}")
        return 1

    selection = _load_selection()

    selected = _selection_candidates(
        selection,
        manifest_items,
        scoring_config,
    )

    selected_ids = {
        str(item.get("wordlist_id", "")).lower()
        for item in selected
    }

    print(
        "MANIFEST : "
        f"{CANONICAL_WORDLIST_MANIFEST}"
    )
    print(
        "PATH     : "
        f"{manifest_path}"
    )
    print(f"TOTAL    : {len(manifest_items)}")
    print(f"SELECTED : {len(selected)}")
    print()

    for item in sorted(
        manifest_items,
        key=lambda x: (
            str(
                x.get("wordlist_id", "")
            ).lower() not in selected_ids,
            -_initial_score_for_item(x),
            str(
                x.get("wordlist_id", "")
            ).lower(),
        ),
    ):
        wid = str(
            item.get("wordlist_id")
        )

        score = _initial_score_for_item(item)
        marker = (
            "*"
            if wid.lower() in selected_ids
            else " "
        )

        path = str(
            item.get("path")
            or "-"
        )

        print(
            f"{marker} {wid:<32} "
            f"score={score:.2f} "
            f"tier={_tier_for_score(score, scoring_config):<11} "
            f"path={path}"
        )

    return 0


# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

def _load_scoring_config() -> dict[str, Any]:
    if not scoring_config_file().is_file():
        raise DirectoryError(
            "Konfigurasi scoring tidak ditemukan: "
            f"{scoring_config_file()}"
        )

    data = _load_yaml(
        scoring_config_file(),
        "Scoring configuration",
    )

    data.setdefault("ranking", {})
    data.setdefault("exploration", {})
    data.setdefault("fuzzy", {})
    data.setdefault("request_budget", {})
    data.setdefault("feedback", {})
    data.setdefault("traceability", {})

    return data


def _fuzzy_weights(
    config: dict[str, Any],
) -> dict[str, float]:
    fuzzy = (
        config.get("fuzzy")
        if isinstance(
            config.get("fuzzy"),
            dict,
        )
        else {}
    )

    raw = (
        fuzzy.get("weights")
        if isinstance(fuzzy, dict)
        else None
    )

    weights = dict(DEFAULT_FUZZY_WEIGHTS)

    if isinstance(raw, dict):
        for key in weights:
            if key in raw:
                weights[key] = max(
                    0.0,
                    _safe_float(
                        raw.get(key),
                        weights[key],
                    ),
                )

    total = sum(weights.values())

    if total <= 0:
        return dict(DEFAULT_FUZZY_WEIGHTS)

    return {
        key: value / total
        for key, value in weights.items()
    }


def _feedback_limits(
    config: dict[str, Any],
) -> tuple[float, float, float]:
    feedback = (
        config.get("feedback")
        if isinstance(
            config.get("feedback"),
            dict,
        )
        else {}
    )

    limits = (
        feedback.get("limits")
        if isinstance(feedback, dict)
        else {}
    )

    if not isinstance(limits, dict):
        limits = {}

    return (
        max(
            0.0,
            _safe_float(
                limits.get("max_evidence_gain"),
                DEFAULT_MAX_EVIDENCE_GAIN,
            ),
        ),
        max(
            0.0,
            _safe_float(
                limits.get("max_discovery_yield"),
                DEFAULT_MAX_DISCOVERY_YIELD,
            ),
        ),
        max(
            0.0,
            _safe_float(
                limits.get("max_noise_penalty"),
                DEFAULT_MAX_NOISE_PENALTY,
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Tool resolution and adapters
# ---------------------------------------------------------------------------

def _resolve_executable(
    env_name: str,
    tool_name: str,
    repository_candidates: list[Path],
) -> str | None:
    configured = os.environ.get(env_name)

    if configured:
        path = Path(configured).expanduser()

        if path.is_file():
            return str(path.resolve())

    system_tool = shutil.which(tool_name)

    if system_tool:
        return system_tool

    for candidate in repository_candidates:
        if candidate.is_file():
            return str(candidate.resolve())

    return None


def _resolve_ffuf() -> str | None:
    repo = _repository_root()

    return _resolve_executable(
        "BREBES_FFUF",
        "ffuf",
        [
            repo / "tools" / "ffuf" / "ffuf.exe",
            repo / "tools" / "ffuf" / "ffuf",
        ],
    )


def _resolve_gobuster() -> str | None:
    repo = _repository_root()

    return _resolve_executable(
        "BREBES_GOBUSTER",
        "gobuster",
        [
            repo / "tools" / "gobuster" / "gobuster.exe",
            repo / "tools" / "gobuster" / "gobuster",
        ],
    )


def _available_tools() -> dict[str, str]:
    result: dict[str, str] = {}

    ffuf = _resolve_ffuf()
    gobuster = _resolve_gobuster()

    if ffuf:
        result["ffuf"] = ffuf

    if gobuster:
        result["gobuster"] = gobuster

    return result


def _select_tool(
    requested: str,
    allowed: list[str] | None = None,
) -> str:
    requested = requested.strip().lower()
    available = _available_tools()

    if allowed:
        allowed_set = {
            item.lower()
            for item in allowed
        }

        available = {
            key: value
            for key, value in available.items()
            if key in allowed_set
        }

    if requested in {
        "ffuf",
        "gobuster",
    }:
        if requested not in available:
            raise DirectoryError(
                f"Tool '{requested}' tidak tersedia. "
                f"Tool tersedia: "
                f"{', '.join(sorted(available)) or 'tidak ada'}"
            )

        return requested

    if requested != "auto":
        raise DirectoryError(
            f"Tool tidak dikenal: {requested}"
        )

    # Auto selection is deterministic and capability based.
    # It does not claim one tool is inherently better.
    for preferred in (
        "ffuf",
        "gobuster",
    ):
        if preferred in available:
            return preferred

    raise DirectoryError(
        "Tidak ada tool directory enumeration yang tersedia. "
        "Install ffuf atau Gobuster."
    )


def _parse_status_codes(
    value: str,
) -> set[int]:
    result: set[int] = set()

    for item in value.split(","):
        item = item.strip()

        if not item:
            continue

        try:
            result.add(int(item))
        except ValueError as exc:
            raise DirectoryError(
                f"HTTP status code tidak valid: {item}"
            ) from exc

    return result


def _build_ffuf_command(
    executable: str,
    base_url: str,
    wordlist_path: Path,
    output_path: Path,
    rate: int,
    threads: int,
    timeout: int,
    match_codes: str,
    extensions: list[str],
) -> list[str]:
    command = [
        executable,
        "-u",
        base_url.rstrip("/") + "/FUZZ",
        "-w",
        str(wordlist_path),
        "-of",
        "json",
        "-o",
        str(output_path),
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

    if extensions:
        command.extend(
            [
                "-e",
                ",".join(
                    "." + value.lstrip(".")
                    for value in extensions
                ),
            ]
        )

    return command


def _build_gobuster_command(
    executable: str,
    base_url: str,
    wordlist_path: Path,
    output_path: Path,
    threads: int,
    timeout: int,
    extensions: list[str],
) -> list[str]:
    command = [
        executable,
        "dir",
        "-u",
        base_url.rstrip("/") + "/",
        "-w",
        str(wordlist_path),
        "-o",
        str(output_path),
        "-t",
        str(threads),
        "--timeout",
        f"{timeout}s",
        "-q",
        "-n",
    ]

    if extensions:
        command.extend(
            [
                "-x",
                ",".join(
                    value.lstrip(".")
                    for value in extensions
                ),
            ]
        )

    return command


# ---------------------------------------------------------------------------
# Baseline and fuzzy analysis
# ---------------------------------------------------------------------------

def _random_baseline_path() -> str:
    return (
        f"{BASELINE_PREFIX}-"
        f"{secrets.token_hex(8)}"
    )


def _response_signature(
    value: dict[str, Any],
) -> tuple[Any, ...]:
    return (
        value.get("status_code"),
        value.get("content_length"),
        value.get("content_type"),
        value.get("words"),
        value.get("lines"),
    )


def _request_baseline(
    base_url: str,
    timeout: int,
) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []

    for _ in range(BASELINE_ATTEMPTS):
        path = "/" + _random_baseline_path()
        url = urljoin(
            base_url,
            path.lstrip("/"),
        )

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
            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:
                body = response.read()
                text = body.decode(
                    "utf-8",
                    errors="replace",
                )

                attempts.append(
                    {
                        "path": path,
                        "url": url,
                        "status_code": int(
                            response.status
                        ),
                        "content_length": len(body),
                        "content_type": str(
                            response.headers.get(
                                "Content-Type"
                            )
                            or ""
                        ),
                        "words": len(text.split()),
                        "lines": len(
                            text.splitlines()
                        ),
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
                headers.get("Content-Type")
                if headers
                else ""
            )

            text = body.decode(
                "utf-8",
                errors="replace",
            )

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

        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
        ) as exc:
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
        item
        for item in attempts
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
                "Tidak ada response baseline "
                "dari random non-existent path."
            ),
            "confidence": 0.0,
        }

    first = successful[0]
    signature = _response_signature(first)

    stable = all(
        _response_signature(item) == signature
        for item in successful[1:]
    )

    successful_ratio = (
        len(successful)
        / max(len(attempts), 1)
    )

    stability_ratio = (
        sum(
            1
            for item in successful
            if _response_signature(item) == signature
        )
        / max(len(successful), 1)
    )

    confidence = _clamp(
        0.5 * successful_ratio
        + 0.5 * stability_ratio
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
            "stable-baseline"
            if stable
            else "variable-baseline"
        ),
        "notes": (
            "Random non-existent paths menghasilkan "
            "response signature yang konsisten."
            if stable
            else
            "Response random non-existent paths "
            "tidak sepenuhnya konsisten; baseline "
            "pertama digunakan sebagai pembanding."
        ),
        "confidence": confidence,
    }


def _fuzzy_similarity(
    candidate: dict[str, Any],
    baseline: dict[str, Any],
    weights: dict[str, float],
) -> float:
    if (
        not baseline
        or baseline.get("status") != "completed"
    ):
        return 0.0

    status_similarity = (
        1.0
        if candidate.get("status_code")
        == baseline.get("status_code")
        else 0.0
    )

    length_similarity = _ratio_similarity(
        candidate.get("content_length"),
        baseline.get("content_length"),
    )

    candidate_type = str(
        candidate.get("content_type")
        or ""
    ).split(";")[0].strip().lower()

    baseline_type = str(
        baseline.get("content_type")
        or ""
    ).split(";")[0].strip().lower()

    type_similarity = (
        1.0
        if (
            candidate_type
            and candidate_type == baseline_type
        )
        else 0.0
    )

    words_similarity = _ratio_similarity(
        candidate.get("words"),
        baseline.get("words"),
    )

    lines_similarity = _ratio_similarity(
        candidate.get("lines"),
        baseline.get("lines"),
    )

    score = (
        weights["status_code"]
        * status_similarity
        + weights["content_length"]
        * length_similarity
        + weights["content_type"]
        * type_similarity
        + weights["words"]
        * words_similarity
        + weights["lines"]
        * lines_similarity
    )

    return _clamp(score)


def _path_is_interesting(
    path: str,
) -> bool:
    normalized = (
        path.strip()
        .lower()
        .strip("/")
    )

    if not normalized:
        return False

    segments = {
        segment
        for segment in normalized
        .replace("\\", "/")
        .split("/")
        if segment
    }

    if segments & SENSITIVE_PATH_TERMS:
        return True

    return any(
        term in normalized
        for term in (
            ".env",
            ".git",
            ".svn",
            "backup",
            "config",
            "admin",
            "swagger",
            "openapi",
            "phpinfo",
            "server-status",
        )
    )


def _classify_result(
    item: dict[str, Any],
    baseline: dict[str, Any],
    fuzzy_threshold: float,
    weights: dict[str, float] | None = None,
) -> dict[str, Any]:
    similarity = _fuzzy_similarity(
        item,
        baseline,
        weights or DEFAULT_FUZZY_WEIGHTS,
    )

    baseline_match = (
        similarity >= fuzzy_threshold
    )

    status_code = item.get(
        "status_code"
    )

    interesting_status = (
        status_code
        in INTERESTING_STATUS_CODES
    )

    high_value_status = (
        status_code
        in HIGH_VALUE_STATUS_CODES
    )

    path_interesting = _path_is_interesting(
        str(item.get("path") or "")
    )

    if baseline_match:
        classification = (
            "possible-false-positive"
        )
    elif (
        high_value_status
        or path_interesting
    ):
        classification = "interesting"
    elif interesting_status:
        classification = (
            "discovery-candidate"
        )
    else:
        classification = "low-signal"

    item["fuzzy_similarity"] = round(
        similarity,
        6,
    )
    item["baseline_match"] = (
        baseline_match
    )
    item["interesting_status"] = (
        interesting_status
    )
    item["high_value_status"] = (
        high_value_status
    )
    item["path_interesting"] = (
        path_interesting
    )
    item["classification"] = (
        classification
    )
    item["notes"] = (
        "Response sangat mirip baseline random path."
        if baseline_match
        else
        "Response berbeda dari baseline."
    )

    return item


# ---------------------------------------------------------------------------
# Output normalization
# ---------------------------------------------------------------------------

def _parse_ffuf_results(
    ffuf_json: Path,
    baseline: dict[str, Any],
    fuzzy_threshold: float,
    weights: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    try:
        payload = json.loads(
            ffuf_json.read_text(
                encoding="utf-8"
            )
        )
    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
        raise DirectoryError(
            f"Gagal membaca output ffuf: "
            f"{ffuf_json}\n{exc}"
        ) from exc

    raw_results = payload.get(
        "results",
        []
    )

    if not isinstance(
        raw_results,
        list,
    ):
        raise DirectoryError(
            "Field 'results' pada output ffuf bukan list."
        )

    results: list[dict[str, Any]] = []

    for raw in raw_results:
        if not isinstance(
            raw,
            dict,
        ):
            continue

        input_data = (
            raw.get("input")
            or {}
        )

        word = ""

        if isinstance(
            input_data,
            dict,
        ):
            word = str(
                input_data.get("FUZZ")
                or input_data.get("fuzz")
                or ""
            ).strip()

        url = str(
            raw.get("url")
            or ""
        ).strip()

        if not url and word:
            url = word

        if not url:
            continue

        item = {
            "path": (
                urlparse(url).path
                or "/"
            ),
            "url": url,
            "method": "GET",
            "status_code": (
                int(raw["status"])
                if raw.get("status")
                is not None
                else None
            ),
            "content_length": (
                int(raw["length"])
                if raw.get("length")
                is not None
                else None
            ),
            "content_type": (
                raw.get("content-type")
                or raw.get("content_type")
                or ""
            ),
            "words": (
                int(raw["words"])
                if raw.get("words")
                is not None
                else None
            ),
            "lines": (
                int(raw["lines"])
                if raw.get("lines")
                is not None
                else None
            ),
            "redirect_location": (
                raw.get("redirectlocation")
                or raw.get("redirect_location")
                or ""
            ),
            "source": "ffuf",
            "tool": "ffuf",
            "input_word": word,
        }

        results.append(
            _classify_result(
                item,
                baseline,
                fuzzy_threshold,
                weights,
            )
        )

    return results


def _parse_gobuster_results(
    gobuster_output: Path,
    base_url: str,
    baseline: dict[str, Any],
    fuzzy_threshold: float,
    weights: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    try:
        lines = gobuster_output.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
    except OSError as exc:
        raise DirectoryError(
            f"Gagal membaca output Gobuster: "
            f"{gobuster_output}\n{exc}"
        ) from exc

    results: list[dict[str, Any]] = []

    # Defensive parser for common Gobuster directory output:
    # /admin                (Status: 403) [Size: 1234]
    for line in lines:
        stripped = line.strip()

        if (
            not stripped
            or stripped.startswith("=")
        ):
            continue

        if "(Status:" not in stripped:
            continue

        try:
            before_status, after_status = (
                stripped.split(
                    "(Status:",
                    1,
                )
            )

            path = before_status.strip()

            status_text = (
                after_status
                .split(")", 1)[0]
                .strip()
            )

            status_code = int(
                status_text
            )

            content_length: int | None = None

            if "[Size:" in after_status:
                size_text = (
                    after_status
                    .split("[Size:", 1)[1]
                    .split("]", 1)[0]
                    .strip()
                )

                content_length = int(
                    size_text
                )

        except (
            ValueError,
            IndexError,
        ):
            continue

        if not path:
            continue

        url = urljoin(
            base_url,
            path.lstrip("/"),
        )

        item = {
            "path": (
                urlparse(url).path
                or "/"
            ),
            "url": url,
            "method": "GET",
            "status_code": status_code,
            "content_length": content_length,
            "content_type": "",
            "words": None,
            "lines": None,
            "redirect_location": "",
            "source": "gobuster",
            "tool": "gobuster",
            "input_word": path.strip("/"),
        }

        results.append(
            _classify_result(
                item,
                baseline,
                fuzzy_threshold,
                weights,
            )
        )

    return results


def _deduplicate_results(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    seen: set[
        tuple[str, int | None]
    ] = set()

    unique: list[dict[str, Any]] = []

    for item in results:
        key = (
            str(
                item.get("path")
                or ""
            ).rstrip("/")
            or "/",
            item.get("status_code"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    return unique


# ---------------------------------------------------------------------------
# Request budget
# ---------------------------------------------------------------------------

def _count_wordlist_entries(
    path: Path,
) -> int:
    try:
        count = 0

        with path.open(
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as handle:
            for line in handle:
                if line.strip():
                    count += 1

        return count

    except OSError as exc:
        raise DirectoryError(
            f"Gagal membaca wordlist {path}: {exc}"
        ) from exc


def _estimate_request_cost(
    entries: int,
    extensions: list[str],
) -> int:
    # Upper-bound estimate:
    # one base candidate plus one probe for each extension.
    multiplier = 1 + len(extensions)
    return entries * multiplier


def _budget_from_config(
    scoring_config: dict[str, Any],
    override: int | None,
) -> int | None:
    budget = scoring_config.get(
        "request_budget"
    )

    if not isinstance(
        budget,
        dict,
    ):
        budget = {}

    enabled = bool(
        budget.get(
            "enabled",
            True,
        )
    )

    if not enabled:
        return None

    if override is not None:
        return max(
            0,
            override,
        )

    raw = budget.get(
        "max_requests"
    )

    if raw in (
        None,
        "",
        0,
        "0",
    ):
        return None

    value = int(
        _safe_float(
            raw,
            0,
        )
    )

    return (
        value
        if value > 0
        else None
    )


# ---------------------------------------------------------------------------
# Feedback / adaptive scoring
# ---------------------------------------------------------------------------

def _calculate_feedback(
    initial_score: float,
    results: list[dict[str, Any]],
    request_count: int,
    scoring_config: dict[str, Any],
) -> dict[str, float]:
    if request_count <= 0:
        return {
            "evidence_gain": 0.0,
            "discovery_yield": 0.0,
            "noise_penalty": 0.0,
            "new_score": initial_score,
        }

    interesting = sum(
        1
        for item in results
        if (
            item.get("classification")
            == "interesting"
            or item.get("high_value_status")
        )
    )

    discoveries = sum(
        1
        for item in results
        if item.get("classification")
        in {
            "interesting",
            "discovery-candidate",
        }
    )

    noise = sum(
        1
        for item in results
        if item.get("classification")
        == "possible-false-positive"
    )

    (
        max_evidence,
        max_yield,
        max_noise,
    ) = _feedback_limits(
        scoring_config
    )

    evidence_gain = (
        _clamp(
            interesting
            / max(request_count, 1),
            0.0,
            1.0,
        )
        * max_evidence
    )

    discovery_yield = (
        _clamp(
            discoveries
            / max(request_count, 1),
            0.0,
            1.0,
        )
        * max_yield
    )

    noise_penalty = (
        _clamp(
            noise
            / max(request_count, 1),
            0.0,
            1.0,
        )
        * max_noise
    )

    new_score = _clamp(
        initial_score
        + evidence_gain
        + discovery_yield
        - noise_penalty
    )

    return {
        "evidence_gain": round(
            evidence_gain,
            6,
        ),
        "discovery_yield": round(
            discovery_yield,
            6,
        ),
        "noise_penalty": round(
            noise_penalty,
            6,
        ),
        "new_score": round(
            new_score,
            6,
        ),
    }


def _calculate_confidence(
    baseline: dict[str, Any],
    request_count: int,
    results: list[dict[str, Any]],
) -> float:
    baseline_confidence = _clamp(
        _safe_float(
            baseline.get(
                "confidence"
            ),
            0.0,
        )
    )

    volume_factor = (
        1.0
        - math.exp(
            -request_count
            / 1000.0
        )
    )

    result_factor = (
        1.0
        - math.exp(
            -len(results)
            / 50.0
        )
    )

    return round(
        _clamp(
            0.50
            * baseline_confidence
            + 0.30
            * volume_factor
            + 0.20
            * result_factor
        ),
        6,
    )


def _update_selection_score(
    selection: dict[str, Any],
    wordlist_id: str,
    final_score: float,
    confidence: float,
    tier: str,
) -> None:
    items = selection.get(
        "wordlists"
    )

    if not isinstance(
        items,
        list,
    ):
        return

    for item in items:
        if not isinstance(
            item,
            dict,
        ):
            continue

        if (
            str(
                item.get(
                    "wordlist_id",
                    "",
                )
            ).strip().lower()
            != wordlist_id.lower()
        ):
            continue

        item["final_score"] = round(
            final_score,
            6,
        )
        item["confidence"] = round(
            confidence,
            6,
        )
        item["tier"] = tier
        item["last_updated"] = now_iso()
        return


# ---------------------------------------------------------------------------
# Run metadata and evidence
# ---------------------------------------------------------------------------

def _run_directory(
    run: str,
) -> Path:
    return (
        evidence_dir()
        / "runs"
        / run
    )


def _write_run_metadata(
    run: str,
    payload: dict[str, Any],
) -> Path:
    path = (
        _run_directory(run)
        / "run.yaml"
    )

    _save_yaml(
        path,
        payload,
    )

    return path


def _save_scoring_artifacts(
    run: str,
    baseline: dict[str, Any],
    result_payload: dict[str, Any],
    feedback_payload: dict[str, Any],
) -> None:
    _save_yaml(
        scoring_baseline_dir()
        / f"{run}.yaml",
        {
            "run_id": run,
            "project_id": project_root().name,
            "created_at": now_iso(),
            "baseline": baseline,
        },
    )

    _save_yaml(
        scoring_results_dir()
        / f"{run}.yaml",
        result_payload,
    )

    _save_yaml(
        scoring_feedback_dir()
        / f"{run}.yaml",
        feedback_payload,
    )


def _append_history(
    run: str,
    history_item: dict[str, Any],
) -> None:
    path = (
        scoring_history_dir()
        / "scoring-history.yaml"
    )

    if path.is_file():
        data = _load_yaml(
            path,
            "Scoring history",
        )
    else:
        data = {
            "schema_version": "1.0",
            "project_id": project_root().name,
            "runs": [],
        }

    runs = data.get("runs")

    if not isinstance(
        runs,
        list,
    ):
        runs = []
        data["runs"] = runs

    runs.append(
        history_item
    )

    data["updated_at"] = now_iso()

    _save_yaml(
        path,
        data,
    )


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def _run_command(
    command: list[str],
    stderr_path: Path,
) -> subprocess.CompletedProcess[str]:
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
        raise DirectoryError(
            f"Gagal menjalankan tool: {exc}"
        ) from exc

    stderr_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    stderr_path.write_text(
        completed.stderr or "",
        encoding="utf-8",
    )

    return completed


def _execute_tool(
    tool: str,
    base_url: str,
    wordlist_path: Path,
    run: str,
    rate: int,
    threads: int,
    timeout: int,
    match_codes: str,
    extensions: list[str],
) -> tuple[
    int,
    Path,
    Path,
    list[str],
]:
    run_path = _run_directory(
        run
    )

    run_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix=f"{run}-"
    ) as temp_dir:
        temp = Path(temp_dir)

        if tool == "ffuf":
            executable = _resolve_ffuf()

            if not executable:
                raise DirectoryError(
                    "ffuf tidak ditemukan."
                )

            raw_output = (
                temp
                / "ffuf.json"
            )

            stderr_path = (
                temp
                / "stderr.log"
            )

            command = _build_ffuf_command(
                executable,
                base_url,
                wordlist_path,
                raw_output,
                rate,
                threads,
                timeout,
                match_codes,
                extensions,
            )

        else:
            executable = _resolve_gobuster()

            if not executable:
                raise DirectoryError(
                    "Gobuster tidak ditemukan."
                )

            raw_output = (
                temp
                / "gobuster.txt"
            )

            stderr_path = (
                temp
                / "stderr.log"
            )

            command = _build_gobuster_command(
                executable,
                base_url,
                wordlist_path,
                raw_output,
                threads,
                timeout,
                extensions,
            )

        completed = _run_command(
            command,
            stderr_path,
        )

        evidence_output = (
            _run_directory(run)
            / raw_output.name
        )

        evidence_stderr = (
            _run_directory(run)
            / "stderr.log"
        )

        if raw_output.is_file():
            shutil.copy2(
                raw_output,
                evidence_output,
            )
        else:
            evidence_output.write_text(
                "",
                encoding="utf-8",
            )

        shutil.copy2(
            stderr_path,
            evidence_stderr,
        )

    return (
        completed.returncode,
        evidence_output,
        evidence_stderr,
        command,
    )


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def init() -> int:
    target = _load_target()

    directory_dir().mkdir(
        parents=True,
        exist_ok=True,
    )

    evidence_dir().mkdir(
        parents=True,
        exist_ok=True,
    )

    (
        evidence_dir()
        / "runs"
    ).mkdir(
        parents=True,
        exist_ok=True,
    )

    for path in (
        project_wordlists_dir()
        / "selected",
        wordlist_runs_dir(),
        scoring_baseline_dir(),
        scoring_results_dir(),
        scoring_feedback_dir(),
        scoring_history_dir(),
    ):
        path.mkdir(
            parents=True,
            exist_ok=True,
        )

    if directory_file().is_file():
        data = _load_directory()
        data = _ensure_v2_state(data)

        _save_yaml(
            directory_file(),
            data,
        )

        print(
            "[INFO] directory.yaml sudah ada; "
            "state dimigrasikan ke schema 2.0."
        )
    else:
        data = _empty_document(
            target
        )

        _save_yaml(
            directory_file(),
            data,
        )

    if not selection_file().is_file():
        _write_selection(
            {
                "schema_version": "1.0",
                "project_id": project_root().name,
                "wordlists": [],
                "runs": [],
            }
        )

    print(
        "[PASS] Directory Enumeration Engine "
        "berhasil diinisialisasi."
    )
    print(
        f"PROJECT : {project_root().name}"
    )
    print(
        f"TARGET  : {target['target_url']}"
    )
    print(
        f"FILE    : {directory_file()}"
    )
    print()
    print("Workspace:")
    print(
        f"  Selection : {selection_file()}"
    )
    print(
        f"  Scoring   : {scoring_config_file()}"
    )
    print(
        f"  Evidence  : {evidence_dir()}"
    )

    _record_activity(
        CHECKLIST_ID,
        "Directory enumeration engine initialized",
        "in-progress",
    )

    return 0


# ---------------------------------------------------------------------------
# Main discovery / adaptive run
# ---------------------------------------------------------------------------

def discover(
    tool: str = "auto",
    wordlist_id: str | None = None,
    tier: str | None = None,
    adaptive: bool = False,
    wordlist: str | None = None,
    rate: int | None = None,
    threads: int | None = None,
    timeout: int | None = None,
    extensions: list[str] | None = None,
    match_codes: str | None = None,
    max_requests: int | None = None,
) -> int:
    data = _load_directory()
    data = _ensure_v2_state(data)
    directory = data["directory"]

    scoring_config = _load_scoring_config()

    if rate is None:
        rate = int(
            _safe_float(
                directory["enumeration"].get(
                    "rate_limit"
                ),
                DEFAULT_RATE,
            )
        )

    if threads is None:
        threads = int(
            _safe_float(
                directory["enumeration"].get(
                    "threads"
                ),
                DEFAULT_THREADS,
            )
        )

    if timeout is None:
        timeout = int(
            _safe_float(
                directory["enumeration"].get(
                    "timeout"
                ),
                DEFAULT_TIMEOUT,
            )
        )

    if match_codes is None:
        match_codes = str(
            directory["enumeration"].get(
                "match_codes"
            )
            or DEFAULT_MATCH_CODES
        )

    if extensions is None:
        extensions = list(
            directory["enumeration"].get(
                "extensions"
            )
            or DEFAULT_EXTENSIONS
        )

    if rate < 1 or threads < 1 or timeout < 1:
        print(
            "[FAIL] Rate, threads, dan timeout harus >= 1."
        )
        return 1

    _parse_status_codes(
        match_codes
    )

    base_url = str(
        directory.get(
            "base_url",
            "",
        )
    ).strip()

    if not base_url:
        raise DirectoryError(
            "base_url belum tersedia pada directory.yaml."
        )

    allowed_tools = (
        directory["enumeration"].get(
            "allowed_tools"
        )
    )

    if not isinstance(
        allowed_tools,
        list,
    ):
        allowed_tools = [
            "ffuf",
            "gobuster",
        ]

    selected_tool = _select_tool(
        tool,
        [
            str(x)
            for x in allowed_tools
        ],
    )

    manifest_path: Path | None = None
    manifest_items: list[
        dict[str, Any]
    ] = []

    selection = _load_selection()

    if wordlist:
        # Custom wordlists are allowed for compatibility/testing.
        # They are not copied into the project.
        candidate = {
            "wordlist_id": (
                wordlist_id
                or "custom"
            ),
            "source": "custom",
            "initial_score": (
                DEFAULT_INITIAL_SCORE
            ),
            "final_score": (
                DEFAULT_INITIAL_SCORE
            ),
            "confidence": 0.0,
            "tier": _tier_for_score(
                DEFAULT_INITIAL_SCORE,
                scoring_config,
            ),
        }
    else:
        (
            manifest_path,
            manifest_items,
        ) = _load_manifest()

        if not selection.get(
            "wordlists"
        ):
            print(
                "[INFO] selection.yaml masih kosong; "
                "bootstrap dari global manifest."
            )

            selection = (
                _bootstrap_selection_from_manifest(
                    scoring_config,
                    limit=None,
                )
            )

        candidates = _selection_candidates(
            selection,
            manifest_items,
            scoring_config,
        )

        if wordlist_id:
            candidates = [
                item
                for item in candidates
                if str(
                    item.get(
                        "wordlist_id",
                        "",
                    )
                ).lower()
                == wordlist_id.lower()
            ]

        if tier:
            candidates = [
                item
                for item in candidates
                if str(
                    item.get(
                        "tier",
                        "",
                    )
                ).lower()
                == tier.lower()
            ]

        if not candidates:
            raise DirectoryError(
                "Tidak ada wordlist candidate yang aktif "
                "dan memenuhi filter."
            )

        if adaptive:
            candidates.sort(
                key=lambda item: (
                    -_safe_float(
                        item.get(
                            "score"
                        ),
                        DEFAULT_INITIAL_SCORE,
                    ),
                    -_safe_float(
                        item.get(
                            "confidence"
                        ),
                        0.0,
                    ),
                    str(
                        item.get(
                            "wordlist_id",
                            "",
                        )
                    ).lower(),
                )
            )

        candidate = candidates[0]

    current_score = _clamp(
        _safe_float(
            candidate.get(
                "final_score"
            ),
            _safe_float(
                candidate.get(
                    "initial_score"
                ),
                DEFAULT_INITIAL_SCORE,
            ),
        )
    )

    initial_score = _clamp(
        _safe_float(
            candidate.get(
                "initial_score"
            ),
            DEFAULT_INITIAL_SCORE,
        )
    )

    candidate_path = str(
        candidate.get(
            "resolved_path"
        )
        or candidate.get(
            "path"
        )
        or ""
    ).strip()

    if wordlist:
        wordlist_path = (
            Path(wordlist)
            .expanduser()
            .resolve()
        )

        selected_wordlist_id = (
            wordlist_id
            or "custom"
        )
    else:
        if not candidate_path:
            raise DirectoryError(
                f"Wordlist '{candidate.get('wordlist_id')}' "
                "tidak memiliki path."
            )

        wordlist_path = (
            Path(candidate_path)
            .resolve()
        )

        selected_wordlist_id = str(
            candidate.get(
                "wordlist_id"
            )
        )

    if not wordlist_path.is_file():
        raise DirectoryError(
            f"Wordlist tidak ditemukan: "
            f"{wordlist_path}"
        )

    entries = _count_wordlist_entries(
        wordlist_path
    )

    estimated_requests = (
        _estimate_request_cost(
            entries,
            extensions,
        )
    )

    budget = _budget_from_config(
        scoring_config,
        max_requests,
    )

    if (
        budget is not None
        and estimated_requests > budget
    ):
        raise DirectoryError(
            "Estimated request cost melebihi request budget.\n"
            f"  Wordlist entries : {entries}\n"
            f"  Extensions       : {len(extensions)}\n"
            f"  Estimated cost   : {estimated_requests}\n"
            f"  Budget           : {budget}\n"
            "Gunakan wordlist yang lebih kecil, "
            "kurangi extensions, atau naikkan budget "
            "secara eksplisit."
        )

    run = run_id()
    started_at = now_iso()

    print("=" * 68)
    print(
        " BrebesKab-CSIRT-Tools - Directory Enumeration"
    )
    print("=" * 68)
    print(
        f"Version          : {SCRIPT_VERSION}"
    )
    print(
        f"Run ID           : {run}"
    )
    print(
        f"Project          : {project_root().name}"
    )
    print(
        f"Target           : {base_url}"
    )
    print(
        f"Tool             : {selected_tool}"
    )
    print(
        f"Wordlist         : {selected_wordlist_id}"
    )
    print(
        f"Initial score    : {initial_score:.4f}"
    )
    print(
        f"Current score    : {current_score:.4f}"
    )
    print(
        "Tier             : "
        f"{_tier_for_score(current_score, scoring_config)}"
    )
    print(
        "Confidence       : "
        f"{_safe_float(candidate.get('confidence'), 0.0):.4f}"
    )
    print(
        f"Entries          : {entries}"
    )
    print(
        f"Estimated req.   : {estimated_requests}"
    )
    print(
        "Budget           : "
        f"{budget if budget is not None else 'unlimited'}"
    )
    print(
        f"Adaptive         : {'yes' if adaptive else 'no'}"
    )
    print()

    _record_activity(
        CHECKLIST_ID,
        f"Directory enumeration started: {run}",
        "in-progress",
    )

    baseline = _request_baseline(
        base_url,
        timeout,
    )

    baseline_file = (
        _run_directory(run)
        / "baseline.json"
    )

    _save_json(
        baseline_file,
        baseline,
    )

    _save_json(
        evidence_dir()
        / "baseline.json",
        baseline,
    )

    if baseline["status"] == "completed":
        print(
            "[PASS] Baseline: "
            f"HTTP {baseline.get('status_code')} / "
            f"Length {baseline.get('content_length')} / "
            f"Confidence "
            f"{baseline.get('confidence', 0.0):.2f}"
        )
    else:
        print(
            "[WARN] Baseline tidak tersedia; "
            "fuzzy FP analysis terbatas."
        )

    fuzzy = (
        scoring_config.get(
            "fuzzy"
        )
        if isinstance(
            scoring_config.get("fuzzy"),
            dict,
        )
        else {}
    )

    fuzzy_threshold = _safe_float(
        fuzzy.get(
            "baseline_similarity_threshold"
        ),
        0.90,
    )

    fuzzy_weights = _fuzzy_weights(
        scoring_config
    )

    print(
        f"[INFO] Fuzzy threshold : "
        f"{fuzzy_threshold:.2f}"
    )
    print(
        f"[INFO] Rate            : "
        f"{rate} req/s"
    )
    print(
        f"[INFO] Threads         : "
        f"{threads}"
    )
    print(
        f"[INFO] Timeout         : "
        f"{timeout}s"
    )
    print(
        "[INFO] Extensions      : "
        f"{', '.join(extensions) if extensions else '-'}"
    )
    print()

    try:
        (
            returncode,
            raw_output,
            stderr_path,
            command,
        ) = _execute_tool(
            selected_tool,
            base_url,
            wordlist_path,
            run,
            rate,
            threads,
            timeout,
            match_codes,
            extensions,
        )

    except DirectoryError as exc:
        print(
            f"[FAIL] {exc}"
        )

        _record_activity(
            CHECKLIST_ID,
            (
                f"Directory enumeration failed: "
                f"{run}: {exc}"
            ),
            "failed",
        )

        return 1

    if returncode != 0:
        print(
            f"[FAIL] {selected_tool} gagal "
            f"dengan exit code {returncode}."
        )

        directory["status"] = "failed"
        directory["updated_at"] = now_iso()
        directory["baseline"] = baseline

        _save_yaml(
            directory_file(),
            data,
        )

        _record_activity(
            CHECKLIST_ID,
            (
                f"Directory enumeration failed: "
                f"{run}: exit {returncode}"
            ),
            "failed",
        )

        return 1

    if selected_tool == "ffuf":
        results = _parse_ffuf_results(
            raw_output,
            baseline,
            fuzzy_threshold,
            fuzzy_weights,
        )
    else:
        results = _parse_gobuster_results(
            raw_output,
            base_url,
            baseline,
            fuzzy_threshold,
            fuzzy_weights,
        )

    results = _deduplicate_results(
        results
    )

    request_count = estimated_requests

    feedback = _calculate_feedback(
        initial_score,
        results,
        request_count,
        scoring_config,
    )

    confidence = _calculate_confidence(
        baseline,
        request_count,
        results,
    )

    final_score = feedback[
        "new_score"
    ]

    final_tier = _tier_for_score(
        final_score,
        scoring_config,
    )

    interesting = sum(
        1
        for item in results
        if (
            item.get("classification")
            == "interesting"
            or item.get("high_value_status")
        )
    )

    possible_fp = sum(
        1
        for item in results
        if item.get(
            "baseline_match"
        )
    )

    unique_paths = len(
        {
            str(
                item.get(
                    "path"
                )
                or ""
            ).rstrip("/")
            or "/"
            for item in results
        }
    )

    by_status: dict[str, int] = {}

    for item in results:
        status_code = item.get(
            "status_code"
        )

        key = (
            str(status_code)
            if status_code is not None
            else "unknown"
        )

        by_status[key] = (
            by_status.get(
                key,
                0,
            )
            + 1
        )

    completed_at = now_iso()

    run_metadata = {
        "schema_version": "2.0",
        "run_id": run,
        "project_id": project_root().name,
        "target": base_url,
        "tool": selected_tool,
        "wordlist_id": selected_wordlist_id,
        "wordlist_path": (
            _relative(wordlist_path)
            if wordlist_path.is_relative_to(
                project_root()
            )
            else str(wordlist_path)
        ),
        "manifest": (
            str(manifest_path)
            if manifest_path
            else ""
        ),
        "adaptive": adaptive,
        "initial_score": round(
            initial_score,
            6,
        ),
        "previous_score": round(
            current_score,
            6,
        ),
        "final_score": round(
            final_score,
            6,
        ),
        "tier": final_tier,
        "confidence": confidence,
        "request_count": request_count,
        "estimated_request_cost": (
            estimated_requests
        ),
        "request_budget": budget,
        "evidence_gain": feedback[
            "evidence_gain"
        ],
        "discovery_yield": feedback[
            "discovery_yield"
        ],
        "noise_penalty": feedback[
            "noise_penalty"
        ],
        "baseline_confidence": baseline.get(
            "confidence",
            0.0,
        ),
        "started_at": started_at,
        "completed_at": completed_at,
    }

    run_metadata_file = (
        _write_run_metadata(
            run,
            run_metadata,
        )
    )

    result_payload = {
        "schema_version": "2.0",
        "run_id": run,
        "project_id": project_root().name,
        "tool": selected_tool,
        "wordlist_id": selected_wordlist_id,
        "request_count": request_count,
        "results": results,
        "summary": {
            "total": len(results),
            "interesting": interesting,
            "possible_false_positive": (
                possible_fp
            ),
            "unique_paths": unique_paths,
            "by_status": by_status,
        },
    }

    feedback_payload = {
        "schema_version": "2.0",
        "run_id": run,
        "project_id": project_root().name,
        "wordlist_id": selected_wordlist_id,
        "initial_score": initial_score,
        "previous_score": current_score,
        "evidence_gain": feedback[
            "evidence_gain"
        ],
        "discovery_yield": feedback[
            "discovery_yield"
        ],
        "noise_penalty": feedback[
            "noise_penalty"
        ],
        "new_score": final_score,
        "tier": final_tier,
        "confidence": confidence,
        "formula": (
            "new_score = initial_score + "
            "evidence_gain + discovery_yield "
            "- noise_penalty"
        ),
        "updated_at": completed_at,
    }

    _save_scoring_artifacts(
        run,
        baseline,
        result_payload,
        feedback_payload,
    )

    _append_history(
        run,
        {
            "run_id": run,
            "project_id": project_root().name,
            "tool": selected_tool,
            "wordlist_id": selected_wordlist_id,
            "initial_score": initial_score,
            "previous_score": current_score,
            "final_score": final_score,
            "tier": final_tier,
            "confidence": confidence,
            "request_count": request_count,
            "evidence_gain": feedback[
                "evidence_gain"
            ],
            "discovery_yield": feedback[
                "discovery_yield"
            ],
            "noise_penalty": feedback[
                "noise_penalty"
            ],
            "timestamp": completed_at,
        },
    )

    _update_selection_score(
        selection,
        selected_wordlist_id,
        final_score,
        confidence,
        final_tier,
    )

    selection.setdefault(
        "runs",
        [],
    )

    selection["runs"].append(
        {
            "run_id": run,
            "wordlist_id": selected_wordlist_id,
            "tool": selected_tool,
            "initial_score": initial_score,
            "final_score": final_score,
            "tier": final_tier,
            "confidence": confidence,
            "timestamp": completed_at,
        }
    )

    _write_selection(
        selection
    )

    directory["status"] = "completed"
    directory["updated_at"] = completed_at
    directory["method"] = selected_tool
    directory["wordlist"] = (
        _relative(wordlist_path)
        if wordlist_path.is_relative_to(
            project_root()
        )
        else str(wordlist_path)
    )
    directory["baseline"] = baseline

    directory.setdefault(
        "runs",
        [],
    )

    directory["runs"].append(
        {
            "run_id": run,
            "tool": selected_tool,
            "wordlist_id": selected_wordlist_id,
            "initial_score": initial_score,
            "final_score": final_score,
            "tier": final_tier,
            "confidence": confidence,
            "request_count": request_count,
            "timestamp": completed_at,
        }
    )

    directory["results"] = results

    directory["summary"] = {
        "total": len(results),
        "interesting": interesting,
        "possible_false_positive": (
            possible_fp
        ),
        "unique_paths": unique_paths,
        "by_status": by_status,
    }

    directory["evidence"] = [
        _relative(baseline_file),
        _relative(raw_output),
        _relative(stderr_path),
        _relative(run_metadata_file),
        _relative(
            scoring_results_dir()
            / f"{run}.yaml"
        ),
        _relative(
            scoring_feedback_dir()
            / f"{run}.yaml"
        ),
    ]

    directory["discovered_at"] = (
        completed_at
    )

    directory["scoring"] = {
        "enabled": True,
        "adaptive": adaptive,
        "wordlist_id": selected_wordlist_id,
        "initial_score": initial_score,
        "final_score": final_score,
        "tier": final_tier,
        "confidence": confidence,
        "evidence_gain": feedback[
            "evidence_gain"
        ],
        "discovery_yield": feedback[
            "discovery_yield"
        ],
        "noise_penalty": feedback[
            "noise_penalty"
        ],
    }

    directory["request_budget"] = {
        "enabled": budget is not None,
        "max_requests": budget,
        "estimated_requests": (
            estimated_requests
        ),
        "actual_request_count": (
            request_count
        ),
    }

    _save_yaml(
        directory_file(),
        data,
    )

    print()
    print("-" * 68)
    print(" ENUMERATION RESULT")
    print("-" * 68)
    print(
        f"FOUND            : {len(results)}"
    )
    print(
        f"INTERESTING      : {interesting}"
    )
    print(
        f"POSSIBLE FP      : {possible_fp}"
    )
    print(
        f"UNIQUE PATHS     : {unique_paths}"
    )
    print()
    print(" SCORING")
    print(
        f"Initial score    : {initial_score:.4f}"
    )
    print(
        f"Final score      : {final_score:.4f}"
    )
    print(
        f"Tier             : {final_tier}"
    )
    print(
        f"Confidence       : {confidence:.4f}"
    )
    print(
        "Evidence gain    : "
        f"+{feedback['evidence_gain']:.4f}"
    )
    print(
        "Discovery yield  : "
        f"+{feedback['discovery_yield']:.4f}"
    )
    print(
        "Noise penalty    : "
        f"-{feedback['noise_penalty']:.4f}"
    )
    print()
    print(" TRACEABILITY")
    print(
        f"Run ID           : {run}"
    )
    print(
        f"Raw output       : {raw_output}"
    )
    print(
        "Scoring result   : "
        f"{scoring_results_dir() / f'{run}.yaml'}"
    )
    print(
        "Feedback         : "
        f"{scoring_feedback_dir() / f'{run}.yaml'}"
    )
    print(
        "History          : "
        f"{scoring_history_dir() / 'scoring-history.yaml'}"
    )
    print(
        f"Directory state  : {directory_file()}"
    )

    if results:
        print()
        print("DISCOVERED:")

        for item in results:
            status_code = item.get(
                "status_code",
                "-",
            )

            print(
                f"  [{str(status_code):>3}] "
                f"{item.get('path', '/'): <40} "
                f"{item.get('classification', '-')}"
            )

    _record_activity(
        CHECKLIST_ID,
        (
            f"Directory enumeration completed: "
            f"{run}; {len(results)} result(s); "
            f"score {final_score:.4f}"
        ),
        "completed",
    )

    return 0


# ---------------------------------------------------------------------------
# Reporting / validation
# ---------------------------------------------------------------------------

def list_results() -> int:
    data = _load_directory()
    directory = data["directory"]

    summary = (
        directory.get(
            "summary"
        )
        or {}
    )

    baseline = (
        directory.get(
            "baseline"
        )
        or {}
    )

    scoring = (
        directory.get(
            "scoring"
        )
        or {}
    )

    print(
        "PROJECT      : "
        f"{data.get('project_id', project_root().name)}"
    )
    print(
        f"TARGET       : {directory.get('base_url', '-')}"
    )
    print(
        f"STATUS       : {directory.get('status', '-')}"
    )
    print(
        f"TOTAL        : {summary.get('total', 0)}"
    )
    print(
        f"INTERESTING  : {summary.get('interesting', 0)}"
    )
    print(
        "POSSIBLE FP  : "
        f"{summary.get('possible_false_positive', 0)}"
    )
    print(
        f"LAST SCORE   : {scoring.get('final_score', '-')}"
    )
    print(
        f"TIER         : {scoring.get('tier', '-')}"
    )
    print(
        f"CONFIDENCE   : {scoring.get('confidence', '-')}"
    )
    print()

    print("BASELINE:")
    print(
        f"  Status        : {baseline.get('status', '-')}"
    )
    print(
        "  Status Code   : "
        f"{baseline.get('status_code', '-')}"
    )
    print(
        "  Content-Length: "
        f"{baseline.get('content_length', '-')}"
    )
    print(
        "  Confidence    : "
        f"{baseline.get('confidence', '-')}"
    )
    print()

    results = (
        directory.get(
            "results"
        )
        or []
    )

    if not results:
        print(
            "Tidak ada hasil directory discovery."
        )
        return 0

    for item in results:
        print(
            f"[{str(item.get('status_code', '-')):>3}] "
            f"{item.get('path', '/')}"
        )
        print(
            f"  URL             : {item.get('url', '-')}"
        )
        print(
            f"  Tool            : {item.get('tool', '-')}"
        )
        print(
            "  Classification  : "
            f"{item.get('classification', '-')}"
        )
        print(
            "  Fuzzy similarity: "
            f"{item.get('fuzzy_similarity', '-')}"
        )
        print(
            "  Baseline match : "
            f"{item.get('baseline_match', False)}"
        )
        print(
            f"  Source          : {item.get('source', '-')}"
        )
        print()

    return 0


def show() -> int:
    data = _load_directory()

    print(
        yaml.safe_dump(
            data,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
    )

    return 0


def show_scoring() -> int:
    config = _load_scoring_config()

    print(
        yaml.safe_dump(
            config,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )
    )

    return 0


def status() -> int:
    data = _load_directory()
    directory = data["directory"]

    summary = (
        directory.get(
            "summary"
        )
        or {}
    )

    baseline = (
        directory.get(
            "baseline"
        )
        or {}
    )

    scoring = (
        directory.get(
            "scoring"
        )
        or {}
    )

    budget = (
        directory.get(
            "request_budget"
        )
        or {}
    )

    print(
        "Project ID     : "
        f"{data.get('project_id', project_root().name)}"
    )
    print(
        f"Status         : {directory.get('status', '-')}"
    )
    print(
        f"Target         : {directory.get('target_url', '-')}"
    )
    print(
        f"Method         : {directory.get('method', '-')}"
    )
    print(
        f"Results        : {summary.get('total', 0)}"
    )
    print(
        f"Interesting    : {summary.get('interesting', 0)}"
    )
    print(
        "Possible FP    : "
        f"{summary.get('possible_false_positive', 0)}"
    )
    print(
        f"Baseline       : {baseline.get('status', '-')}"
    )
    print(
        f"Wordlist       : {directory.get('wordlist', '-')}"
    )
    print(
        f"Score          : {scoring.get('final_score', '-')}"
    )
    print(
        f"Tier           : {scoring.get('tier', '-')}"
    )
    print(
        f"Confidence     : {scoring.get('confidence', '-')}"
    )
    print(
        "Rate           : "
        f"{directory.get('enumeration', {}).get('rate_limit', '-')}"
    )
    print(
        "Threads        : "
        f"{directory.get('enumeration', {}).get('threads', '-')}"
    )
    print(
        "Timeout        : "
        f"{directory.get('enumeration', {}).get('timeout', '-')}"
    )
    print(
        f"Budget         : {budget.get('max_requests', '-')}"
    )
    print(
        f"File           : {directory_file()}"
    )
    print(
        f"Manifest       : {CANONICAL_WORDLIST_MANIFEST}"
    )

    by_status = (
        summary.get(
            "by_status"
        )
        or {}
    )

    if by_status:
        print()
        print("HTTP Status:")

        for code in sorted(
            by_status,
            key=lambda value: (
                value == "unknown",
                value,
            ),
        ):
            print(
                f"  {code}: "
                f"{by_status[code]}"
            )

    return 0


def verify() -> int:
    data = _load_directory()
    directory = data["directory"]

    errors: list[str] = []

    if data.get(
        "project_id"
    ) != project_root().name:
        errors.append(
            "Project ID tidak sesuai active project."
        )

    if directory.get(
        "checklist_id"
    ) != CHECKLIST_ID:
        errors.append(
            "Checklist ID tidak sesuai."
        )

    if not str(
        directory.get(
            "target_url",
            "",
        )
    ).strip():
        errors.append(
            "Target URL kosong."
        )

    if not str(
        directory.get(
            "base_url",
            "",
        )
    ).strip():
        errors.append(
            "Base URL kosong."
        )

    enumeration = directory.get(
        "enumeration"
    )

    if not isinstance(
        enumeration,
        dict,
    ):
        errors.append(
            "enumeration harus berupa mapping."
        )

    allowed_tools = (
        enumeration.get(
            "allowed_tools",
            [],
        )
        if isinstance(
            enumeration,
            dict,
        )
        else []
    )

    if not isinstance(
        allowed_tools,
        list,
    ):
        errors.append(
            "enumeration.allowed_tools harus berupa list."
        )

    if not isinstance(
        directory.get(
            "results"
        ),
        list,
    ):
        errors.append(
            "results harus berupa list."
        )

    summary = (
        directory.get(
            "summary"
        )
        or {}
    )

    for field in (
        "total",
        "interesting",
        "possible_false_positive",
        "unique_paths",
    ):
        if not isinstance(
            summary.get(field),
            int,
        ):
            errors.append(
                f"summary.{field} tidak valid."
            )

    if not scoring_config_file().is_file():
        errors.append(
            "scoring/config/scoring.yaml "
            "tidak ditemukan."
        )

    if not selection_file().is_file():
        errors.append(
            "wordlists/selected/selection.yaml "
            "tidak ditemukan."
        )

    canonical_manifest = (
        _repository_root()
        / "config"
        / "dictionaries"
        / "directory"
        / "manifest.json"
    )

    if not canonical_manifest.is_file():
        errors.append(
            "Global wordlist manifest tidak ditemukan: "
            f"{canonical_manifest}"
        )
    else:
        try:
            _load_manifest()
        except DirectoryError as exc:
            errors.append(str(exc))

    if errors:
        print(
            "[FAIL] Directory Enumeration "
            "verification gagal."
        )

        for error in errors:
            print(
                f"  - {error}"
            )

        return 1

    print(
        "[PASS] Directory Enumeration Engine "
        "memenuhi structural validation."
    )
    print(
        f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(
        f"[PASS] Schema    : {data.get('schema_version')}"
    )
    print(
        "[PASS] Tools     : "
        + ", ".join(
            str(x)
            for x in allowed_tools
        )
    )
    print(
        f"[PASS] Results   : {summary.get('total', 0)}"
    )
    print(
        f"[PASS] Scoring   : {scoring_config_file()}"
    )
    print(
        f"[PASS] Selection : {selection_file()}"
    )

    _record_activity(
        CHECKLIST_ID,
        "Directory enumeration engine verified",
        "completed",
    )

    return 0


def remove() -> int:
    path = directory_file()

    if not path.exists():
        print(
            "[INFO] Directory Discovery belum ada."
        )
        return 0

    confirm = input(
        "Hapus seluruh data Directory Discovery "
        "untuk project aktif? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print(
            "[INFO] Dibatalkan."
        )
        return 0

    shutil.rmtree(
        directory_dir()
    )

    _record_activity(
        CHECKLIST_ID,
        "Directory discovery data removed",
        "completed",
    )

    print(
        "[PASS] Directory Discovery berhasil dihapus."
    )

    return 0


def version() -> int:
    print(
        "BrebesKab-CSIRT-Tools "
        f"directory.py v{SCRIPT_VERSION}"
    )
    print(
        f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}"
    )
    print(
        f"Schema   : {SCHEMA_VERSION}"
    )
    print(
        "Tools    : ffuf, gobuster"
    )
    print(
        "Features : baseline, fuzzy, scoring, "
        "budget, feedback, confidence, exploration"
    )
    print(
        f"Manifest : {CANONICAL_WORDLIST_MANIFEST}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="directory.py",
        description=(
            "BrebesKab-CSIRT-Tools - Directory Enumeration "
            "& Adaptive Scoring Engine"
        ),
    )

    sub = parser.add_subparsers(
        dest="command"
    )

    sub.add_parser(
        "init",
        help="Initialize directory engine state.",
    )

    sub.add_parser(
        "list",
        help="List latest normalized results.",
    )

    sub.add_parser(
        "show",
        help="Show directory.yaml.",
    )

    sub.add_parser(
        "show-scoring",
        help="Show scoring.yaml.",
    )

    sub.add_parser(
        "verify",
        help="Verify directory engine state.",
    )

    sub.add_parser(
        "status",
        help="Show current directory status.",
    )

    sub.add_parser(
        "remove",
        help="Remove directory discovery data.",
    )

    sub.add_parser(
        "version",
        help="Show version.",
    )

    sub.add_parser(
        "wordlists",
        help="List global wordlist manifest entries.",
    )

    discover_parser = sub.add_parser(
        "discover",
        help=(
            "Run directory enumeration "
            "with ffuf/Gobuster."
        ),
    )

    discover_parser.add_argument(
        "--tool",
        choices=(
            "auto",
            "ffuf",
            "gobuster",
        ),
        default="auto",
    )

    discover_parser.add_argument(
        "--wordlist",
        help="Custom wordlist path.",
    )

    discover_parser.add_argument(
        "--wordlist-id",
        help="Selected global wordlist ID.",
    )

    discover_parser.add_argument(
        "--tier",
        choices=(
            "Primary",
            "Secondary",
            "Exploration",
        ),
        help=(
            "Restrict candidate selection "
            "to a tier."
        ),
    )

    discover_parser.add_argument(
        "--adaptive",
        action="store_true",
        help=(
            "Rank candidates by current score "
            "before selecting the next run."
        ),
    )

    discover_parser.add_argument(
        "--rate",
        type=int,
    )

    discover_parser.add_argument(
        "--threads",
        type=int,
    )

    discover_parser.add_argument(
        "--timeout",
        type=int,
    )

    discover_parser.add_argument(
        "--max-requests",
        type=int,
    )

    discover_parser.add_argument(
        "--extensions",
        nargs="*",
        help=(
            "Extensions such as php html json. "
            "Empty means no extension."
        ),
    )

    discover_parser.add_argument(
        "--match-codes"
    )

    return parser


def main(
    argv: list[str] | None = None,
) -> int:
    parser = build_parser()

    args = parser.parse_args(
        sys.argv[1:]
        if argv is None
        else argv
    )

    if not args.command:
        parser.print_help()
        return 0

    try:
        if args.command == "init":
            return init()

        if args.command == "list":
            return list_results()

        if args.command == "show":
            return show()

        if args.command == "show-scoring":
            return show_scoring()

        if args.command == "verify":
            return verify()

        if args.command == "status":
            return status()

        if args.command == "remove":
            return remove()

        if args.command == "version":
            return version()

        if args.command == "wordlists":
            return list_wordlists()

        if args.command == "discover":
            return discover(
                tool=args.tool,
                wordlist_id=args.wordlist_id,
                tier=args.tier,
                adaptive=args.adaptive,
                wordlist=args.wordlist,
                rate=args.rate,
                threads=args.threads,
                timeout=args.timeout,
                extensions=args.extensions,
                match_codes=args.match_codes,
                max_requests=args.max_requests,
            )

    except (
        ContextError,
        DirectoryError,
        ActivityError,
        OSError,
        ValueError,
    ) as exc:
        print(
            f"[FAIL] {exc}"
        )
        return 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
