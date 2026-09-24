#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Project Manager

Usage:
    python scripts/project.py list
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[ERROR] PyYAML belum terinstall.")
    print("       Jalankan: python -m pip install PyYAML")
    sys.exit(1)


SCRIPT_VERSION = "1.0.0"


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def projects_root() -> Path:
    return repository_root() / "projects"


def active_project_file() -> Path:
    return repository_root() / ".runtime" / "active-project.yaml"


def load_yaml(path: Path) -> dict:
    if not path.is_file():
        return {}

    try:
        with path.open("r", encoding="utf-8-sig") as fh:
            data = yaml.safe_load(fh)
    except Exception:
        return {}

    return data if isinstance(data, dict) else {}


def get_active_project_id() -> str | None:
    data = load_yaml(active_project_file())
    project_id = data.get("project_id")

    if not isinstance(project_id, str):
        return None

    project_id = project_id.strip()
    return project_id or None


def list_projects() -> int:
    root = projects_root()

    if not root.is_dir():
        print("[INFO] Directory projects belum tersedia.")
        return 0

    project_dirs = sorted(
        [
            path
            for path in root.iterdir()
            if path.is_dir() and path.name.startswith("PENTEST-")
        ],
        key=lambda p: p.name.lower(),
    )

    active_id = get_active_project_id()

    print()
    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Pentest Projects")
    print("=" * 72)
    print(f"Version      : {SCRIPT_VERSION}")
    print(f"Repository   : {repository_root()}")
    print(f"Projects     : {root}")
    print()

    if not project_dirs:
        print("[INFO] Belum ada pentest project.")
        print()
        return 0

    print(f"{'':2}{'Project ID':<24} {'Application':<24} {'Status':<15}")
    print("-" * 72)

    for project_dir in project_dirs:
        project_id = project_dir.name
        assessment = load_yaml(project_dir / "assessment.yaml")

        application = assessment.get("application", "-")
        status = assessment.get("status", "unknown")

        if not isinstance(application, str):
            application = str(application)

        if not isinstance(status, str):
            status = str(status)

        marker = "*" if project_id == active_id else " "

        print(
            f"{marker} "
            f"{project_id:<24} "
            f"{application:<24} "
            f"{status:<15}"
        )

    print()
    if active_id:
        print(f"Active project: {active_id}")
    else:
        print("Active project: [none]")

    print()
    print("Keterangan:")
    print("  * = active project")
    print()
    return 0


def print_help() -> None:
    print(
        f"""BrebesKab-CSIRT-Tools Project Manager v{SCRIPT_VERSION}

Usage:
  python scripts/project.py list

Commands:
  list    Menampilkan seluruh pentest project dan active project.
"""
    )


def main() -> int:
    if len(sys.argv) != 2:
        print_help()
        return 1

    command = sys.argv[1].lower()

    if command == "list":
        return list_projects()

    print(f"[ERROR] Command tidak dikenal: {sys.argv[1]}")
    print()
    print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
