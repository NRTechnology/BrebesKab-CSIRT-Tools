#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Project Context Module

Version: 1.0.0

Centralized reader for the active pentest project context.

The active project is selected by:
    python scripts/project.py use PENTEST-YYYY-NNN

This module reads:
    .runtime/active-project.yaml

It does NOT:
- create or switch projects
- delete projects
- modify the active project
- create findings/evidence/activity records

It only resolves and validates the current project context so other
Python tools can consistently operate on the correct pentest project.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


SCRIPT_VERSION = "1.0.0"


class ContextError(RuntimeError):
    """Raised when the active project context is invalid or unavailable."""


@dataclass(frozen=True)
class ProjectContext:
    """Validated information about the currently active pentest project."""

    project_id: str
    project_path: Path
    application: str
    target: str
    environment: str
    assessment_type: str
    activated_at: str
    context_file: Path

    @property
    def timeline_path(self) -> Path:
        return self.project_path / "timeline"

    @property
    def activity_log_path(self) -> Path:
        return self.timeline_path / "activity.log"

    @property
    def evidence_path(self) -> Path:
        return self.project_path / "evidence"

    @property
    def findings_path(self) -> Path:
        return self.project_path / "findings"

    @property
    def retest_path(self) -> Path:
        return self.project_path / "retest"

    @property
    def scans_path(self) -> Path:
        return self.project_path / "scans"

    @property
    def report_path(self) -> Path:
        return self.project_path / "report"

    @property
    def assessment_file(self) -> Path:
        return self.project_path / "assessment.yaml"

    @property
    def checklist_file(self) -> Path:
        return self.project_path / "checklist.yaml"


def repository_root() -> Path:
    """
    Return the repository root.

    context.py is expected at:
        <repository>/scripts/context.py
    """
    return Path(__file__).resolve().parent.parent


def runtime_root() -> Path:
    """Return the repository .runtime directory."""
    return repository_root() / ".runtime"


def active_project_file() -> Path:
    """Return the active project context file."""
    return runtime_root() / "active-project.yaml"


def projects_root() -> Path:
    """Return the repository projects directory."""
    return repository_root() / "projects"


def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML mapping from a file."""
    if not path.is_file():
        raise ContextError(f"File tidak ditemukan: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ContextError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise ContextError(f"Gagal membaca file: {path}\n{exc}") from exc

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ContextError(f"Format YAML harus berupa mapping/object: {path}")

    return data


def _required_string(
    data: Dict[str, Any],
    key: str,
    source: Path,
) -> str:
    """Read a required non-empty string from YAML."""
    value = data.get(key)

    if not isinstance(value, str) or not value.strip():
        raise ContextError(
            f"Field '{key}' tidak valid atau kosong pada: {source}"
        )

    return value.strip()


def _resolve_project_path(raw_path: str) -> Path:
    """
    Resolve project_path from active-project.yaml.

    The project.py writer stores the path relative to the repository,
    for example:
        projects/PENTEST-2026-002

    Absolute paths are also accepted for robustness.
    """
    raw = Path(raw_path)

    if raw.is_absolute():
        return raw.resolve()

    return (repository_root() / raw).resolve()


def load_active_context() -> ProjectContext:
    """
    Load and validate the active project context.

    Raises:
        ContextError: when no active project exists or the context/project
                      is invalid.
    """
    context_file = active_project_file()

    if not context_file.is_file():
        raise ContextError(
            "Tidak ada active project.\n"
            "Gunakan:\n"
            "  python scripts/project.py use <PROJECT-ID>"
        )

    data = _load_yaml(context_file)

    schema_version = data.get("schema_version")
    if schema_version not in ("1.0", 1.0):
        raise ContextError(
            f"schema_version active project tidak didukung: "
            f"{schema_version!r}"
        )

    project_id = _required_string(data, "project_id", context_file)
    raw_project_path = _required_string(
        data, "project_path", context_file
    )

    project_path = _resolve_project_path(raw_project_path)

    if not project_path.is_dir():
        raise ContextError(
            f"Project aktif tidak ditemukan:\n"
            f"  {project_path}\n"
            f"Gunakan 'python scripts/project.py list' untuk melihat "
            f"project yang tersedia."
        )

    assessment_file = project_path / "assessment.yaml"

    if not assessment_file.is_file():
        raise ContextError(
            f"assessment.yaml tidak ditemukan pada project aktif:\n"
            f"  {assessment_file}"
        )

    assessment = _load_yaml(assessment_file)

    assessment_project_id = assessment.get("project_id")
    if assessment_project_id != project_id:
        raise ContextError(
            "Project ID tidak konsisten.\n"
            f"  Context : {project_id}\n"
            f"  Project : {assessment_project_id!r}\n"
            f"  File    : {assessment_file}"
        )

    application = _required_string(data, "application", context_file)
    target = _required_string(data, "target", context_file)
    environment = _required_string(data, "environment", context_file)
    assessment_type = _required_string(
        data, "assessment_type", context_file
    )
    activated_at = _required_string(data, "activated_at", context_file)

    return ProjectContext(
        project_id=project_id,
        project_path=project_path,
        application=application,
        target=target,
        environment=environment,
        assessment_type=assessment_type,
        activated_at=activated_at,
        context_file=context_file,
    )


def require_active_project() -> ProjectContext:
    """
    Return the active project or raise ContextError.

    This is the preferred function for tools that must never operate
    without an explicitly selected project.
    """
    return load_active_context()


def get_active_project_id() -> str:
    """Return the active project ID."""
    return require_active_project().project_id


def get_active_project_path() -> Path:
    """Return the absolute path of the active project."""
    return require_active_project().project_path


def get_active_project() -> ProjectContext:
    """Return the complete active ProjectContext."""
    return require_active_project()


def print_context(context: Optional[ProjectContext] = None) -> None:
    """Print the active project context in a human-readable format."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Project Context")
    print("=" * 72)
    print(f"Project ID  : {context.project_id}")
    print(f"Application : {context.application}")
    print(f"Target      : {context.target}")
    print(f"Environment : {context.environment}")
    print(f"Type        : {context.assessment_type}")
    print(f"Activated   : {context.activated_at}")
    print(f"Project     : {context.project_path}")
    print(f"Context     : {context.context_file}")


def print_help() -> None:
    """Print command-line help."""
    print(
        "Usage:\n"
        "  python scripts/context.py status\n"
        "  python scripts/context.py paths\n"
        "  python scripts/context.py version\n"
        "\n"
        "Commands:\n"
        "  status   Menampilkan active project context.\n"
        "  paths    Menampilkan lokasi penting pada active project.\n"
        "  version  Menampilkan versi context.py.\n"
    )


def print_paths(context: Optional[ProjectContext] = None) -> None:
    """Print important paths belonging to the active project."""
    if context is None:
        context = require_active_project()

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Project Paths")
    print("=" * 72)
    print(f"Project     : {context.project_path}")
    print(f"Assessment  : {context.assessment_file}")
    print(f"Checklist   : {context.checklist_file}")
    print(f"Timeline    : {context.timeline_path}")
    print(f"Activity    : {context.activity_log_path}")
    print(f"Evidence    : {context.evidence_path}")
    print(f"Findings    : {context.findings_path}")
    print(f"Retest      : {context.retest_path}")
    print(f"Scans       : {context.scans_path}")
    print(f"Report      : {context.report_path}")


def main(argv: Optional[list[str]] = None) -> int:
    """Command-line entry point."""
    import sys

    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = args[0].lower()

    try:
        if command == "status":
            print_context()
            return 0

        if command == "paths":
            print_paths()
            return 0

        if command == "version":
            print(f"BrebesKab-CSIRT-Tools context.py v{SCRIPT_VERSION}")
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except ContextError as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
