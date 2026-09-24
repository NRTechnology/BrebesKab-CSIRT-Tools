#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Activity Recorder

Version: 1.0.0

Centralized activity/audit-trail recorder for pentest projects.

This module is intended primarily for other Python scripts to import.
It uses context.py to determine the active project and therefore never
needs a --project argument.

Activity records answer:
    "What was actually done?"

They are different from:
- checklist items: what should be checked
- evidence: proof supporting an activity/finding
- findings: security issues identified during the assessment

Activity log:
    projects/<PROJECT-ID>/timeline/activity.log
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from .context import ProjectContext, require_active_project
except ImportError:
    from context import ProjectContext, require_active_project


SCRIPT_VERSION = "1.0.0"


class ActivityError(RuntimeError):
    """Raised when an activity cannot be recorded or read."""


@dataclass(frozen=True)
class ActivityRecord:
    """A single activity recorded in the project timeline."""

    activity_id: str
    timestamp: str
    phase: str
    item: str
    action: str
    status: str
    operator: str = ""

    def to_log_line(self) -> str:
        """Return the canonical pipe-delimited activity log line."""
        fields = [
            self.timestamp,
            self.activity_id,
            self.phase,
            self.item,
            self.action,
            self.status,
            self.operator,
        ]

        # Prevent the log format from being broken by embedded separators.
        sanitized = [
            str(value).replace("\r", " ").replace("\n", " ").replace("|", "/")
            for value in fields
        ]

        return " | ".join(sanitized)


LOG_HEADER = (
    "# BrebesKab-CSIRT-Tools Activity Log\n"
    "# timestamp | activity_id | phase | item | action | status | operator\n"
)


VALID_STATUSES = {
    "started",
    "in-progress",
    "completed",
    "skipped",
    "failed",
    "blocked",
}


def _now() -> str:
    """Return the current local timestamp with UTC offset."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _ensure_log_file(context: ProjectContext) -> Path:
    """Create the timeline directory and activity log if necessary."""
    timeline = context.timeline_path
    timeline.mkdir(parents=True, exist_ok=True)

    log_path = context.activity_log_path

    if not log_path.exists():
        log_path.write_text(LOG_HEADER, encoding="utf-8")

    return log_path


def _read_records(context: ProjectContext) -> list[ActivityRecord]:
    """Read valid activity records from the active project's log."""
    log_path = context.activity_log_path

    if not log_path.is_file():
        return []

    records: list[ActivityRecord] = []

    try:
        lines = log_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ActivityError(
            f"Gagal membaca activity log: {log_path}\n{exc}"
        ) from exc

    for line_number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        parts = [part.strip() for part in line.split("|")]

        if len(parts) != 7:
            # Do not make the entire activity system unusable because of
            # one malformed legacy/manual line. It can be investigated.
            continue

        timestamp, activity_id, phase, item, action, status, operator = parts

        records.append(
            ActivityRecord(
                activity_id=activity_id,
                timestamp=timestamp,
                phase=phase,
                item=item,
                action=action,
                status=status,
                operator=operator,
            )
        )

    return records


def _next_activity_id(context: ProjectContext) -> str:
    """Generate the next sequential ACT-xxxx ID."""
    records = _read_records(context)

    highest = 0

    for record in records:
        activity_id = record.activity_id.strip().upper()

        if not activity_id.startswith("ACT-"):
            continue

        number = activity_id[4:]

        if number.isdigit():
            highest = max(highest, int(number))

    return f"ACT-{highest + 1:04d}"


def record_activity(
    *,
    phase: str,
    item: str,
    action: str,
    status: str = "completed",
    operator: str = "",
    context: Optional[ProjectContext] = None,
) -> ActivityRecord:
    """
    Record one activity in the active project.

    This is the main API intended for other Python scripts.

    Example:
        activity = record_activity(
            phase="01-preparation",
            item="01-001",
            action="Authorization verified",
        )

    The project is resolved automatically from context.py unless an
    already-loaded ProjectContext is explicitly supplied.
    """
    if context is None:
        context = require_active_project()

    phase = phase.strip()
    item = item.strip()
    action = action.strip()
    status = status.strip().lower()
    operator = operator.strip()

    if not phase:
        raise ActivityError("Phase tidak boleh kosong.")

    if not item:
        raise ActivityError("Item tidak boleh kosong.")

    if not action:
        raise ActivityError("Action tidak boleh kosong.")

    if status not in VALID_STATUSES:
        allowed = ", ".join(sorted(VALID_STATUSES))
        raise ActivityError(
            f"Status tidak valid: {status!r}. "
            f"Gunakan salah satu: {allowed}"
        )

    log_path = _ensure_log_file(context)

    record = ActivityRecord(
        activity_id=_next_activity_id(context),
        timestamp=_now(),
        phase=phase,
        item=item,
        action=action,
        status=status,
        operator=operator,
    )

    try:
        with log_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(record.to_log_line() + "\n")
    except OSError as exc:
        raise ActivityError(
            f"Gagal menulis activity log: {log_path}\n{exc}"
        ) from exc

    return record


def list_activities(
    *,
    context: Optional[ProjectContext] = None,
) -> list[ActivityRecord]:
    """Return activity records for the active project."""
    if context is None:
        context = require_active_project()

    return _read_records(context)


def get_activity(
    activity_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> Optional[ActivityRecord]:
    """Find one activity by ACT-xxxx ID."""
    activity_id = activity_id.strip().upper()

    if not activity_id:
        raise ActivityError("Activity ID tidak boleh kosong.")

    for record in list_activities(context=context):
        if record.activity_id.upper() == activity_id:
            return record

    return None


def format_activity(record: ActivityRecord) -> str:
    """Return a human-readable activity record."""
    return (
        f"{record.activity_id} | "
        f"{record.timestamp} | "
        f"{record.phase} | "
        f"{record.item} | "
        f"{record.action} | "
        f"{record.status}"
        + (f" | {record.operator}" if record.operator else "")
    )


def print_activities(
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    """Print all activities for the active project."""
    if context is None:
        context = require_active_project()

    records = list_activities(context=context)

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Activity Timeline")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"Project    : {context.project_path}")
    print(f"Activity   : {context.activity_log_path}")
    print()

    if not records:
        print("[INFO] Belum ada activity.")
        return

    for record in records:
        print(format_activity(record))


def print_activity(
    activity_id: str,
    *,
    context: Optional[ProjectContext] = None,
) -> int:
    """Print one activity and return a process-style result code."""
    if context is None:
        context = require_active_project()

    record = get_activity(activity_id, context=context)

    if record is None:
        print(f"[INFO] Activity tidak ditemukan: {activity_id}")
        return 1

    print("=" * 72)
    print(" BrebesKab-CSIRT-Tools - Activity")
    print("=" * 72)
    print(f"Project ID : {context.project_id}")
    print(f"Activity ID: {record.activity_id}")
    print(f"Timestamp  : {record.timestamp}")
    print(f"Phase      : {record.phase}")
    print(f"Item       : {record.item}")
    print(f"Action     : {record.action}")
    print(f"Status     : {record.status}")
    print(f"Operator   : {record.operator or '[not-set]'}")
    return 0


def print_help() -> None:
    """Print optional diagnostic CLI help."""
    print(
        "Activity Recorder\n"
        "\n"
        "Primary use:\n"
        "  Import this module from other Python scripts.\n"
        "\n"
        "API:\n"
        "  record_activity(...)\n"
        "  list_activities(...)\n"
        "  get_activity(...)\n"
        "\n"
        "Diagnostic commands:\n"
        "  python scripts/activity.py list\n"
        "  python scripts/activity.py show ACT-0001\n"
        "  python scripts/activity.py version\n"
        "\n"
        "The active project is resolved automatically through context.py.\n"
        "No --project argument is required.\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    """Optional diagnostic command-line entry point."""
    import sys

    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help", "help"):
        print_help()
        return 0

    command = args[0].lower()

    try:
        if command == "list":
            print_activities()
            return 0

        if command == "show":
            if len(args) != 2:
                print("[ERROR] Gunakan: python scripts/activity.py show ACT-0001")
                return 2

            return print_activity(args[1])

        if command == "version":
            print(f"BrebesKab-CSIRT-Tools activity.py v{SCRIPT_VERSION}")
            return 0

        print(f"[ERROR] Command tidak dikenal: {args[0]}")
        print()
        print_help()
        return 2

    except ActivityError as exc:
        print(f"[ERROR] {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
