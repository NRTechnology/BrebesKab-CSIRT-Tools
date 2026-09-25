#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools
Preparation - Rules of Engagement (RoE)

Version: 1.0.0

Manage the Rules of Engagement for the active pentest project.

Storage:
    projects/<PROJECT-ID>/01-preparation/roe/roe.yaml

Design principles:
- The active project is resolved through context.py.
- No --project argument is required.
- RoE records how an authorized assessment may be performed.
- Credentials, passwords, tokens, API keys, and other secrets must NOT
  be stored in this file.
- Changes are recorded in timeline/activity.log through activity.py.

Checklist mapping:
    01-003 - Rules of Engagement
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

SCRIPT_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPT_DIR.parent

if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from activity import record_activity
from context import ContextError, ProjectContext, require_active_project


SCRIPT_VERSION = "1.0.0"
ROE_DIR_NAME = "roe"
ROE_FILE_NAME = "roe.yaml"

VALID_STATUSES = {
    "not-started",
    "draft",
    "pending-approval",
    "approved",
    "active",
    "suspended",
    "closed",
}

VALID_ENVIRONMENTS = {
    "production",
    "staging",
    "development",
    "test",
    "unknown",
}

VALID_ACTION_STATUSES = {
    "allowed",
    "prohibited",
    "conditional",
}


class RoEError(RuntimeError):
    """Raised when RoE data cannot be created or modified."""


def roe_dir(context: ProjectContext) -> Path:
    """Return the RoE directory."""
    return context.project_path / "01-preparation" / ROE_DIR_NAME


def roe_file(context: ProjectContext) -> Path:
    """Return the RoE YAML path."""
    return roe_dir(context) / ROE_FILE_NAME


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _empty_document(context: ProjectContext) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "project_id": context.project_id,
        "updated_at": _now(),
        "roe": {
            "status": "not-started",
            "title": "",
            "purpose": "",
            "assessment_type": context.assessment_type,
            "environment": context.environment,
            "authorization_reference": "",
            "scope_reference": "",
            "schedule": {
                "start": "",
                "end": "",
                "timezone": "Asia/Jakarta",
                "testing_windows": [],
                "blackout_windows": [],
            },
            "communication": {
                "primary_channel": "",
                "notification_before_testing": True,
                "incident_notification_required": True,
                "incident_notification_method": "",
                "escalation_notes": "",
            },
            "allowed_activities": [],
            "prohibited_activities": [],
            "conditional_activities": [],
            "safety_limits": {
                "rate_limit": "",
                "concurrency_limit": "",
                "request_limit": "",
                "resource_exhaustion_testing": False,
                "destructive_testing": False,
                "production_data_modification": False,
                "persistence_testing": False,
                "social_engineering": False,
                "physical_testing": False,
                "third_party_testing": False,
            },
            "data_handling": {
                "sensitive_data_allowed": False,
                "credential_storage": "prohibited",
                "token_storage": "prohibited",
                "pii_storage": "minimum-necessary",
                "sanitization_required": True,
                "retention_notes": "",
            },
            "evidence": {
                "request_response_capture": True,
                "screenshots_when_needed": True,
                "timestamp_required": True,
                "evidence_sanitization_required": True,
                "evidence_storage": "../evidence/",
            },
            "emergency_stop": {
                "enabled": True,
                "trigger_conditions": [],
                "stop_method": "",
                "emergency_contact_reference": "",
            },
            "change_control": {
                "scope_change_requires_reapproval": True,
                "schedule_change_requires_reapproval": True,
                "method_change_requires_reapproval": True,
                "deviation_notes": [],
            },
            "approval": {
                "approved_by": "",
                "approved_date": "",
                "approval_reference": "",
                "notes": "",
            },
            "notes": "",
        },
    }


def _load(context: ProjectContext) -> dict[str, Any]:
    """Load and validate roe.yaml."""
    path = roe_file(context)

    if not path.is_file():
        return _empty_document(context)

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise RoEError(f"YAML tidak valid: {path}\n{exc}") from exc
    except OSError as exc:
        raise RoEError(f"Gagal membaca: {path}\n{exc}") from exc

    if data is None:
        data = {}

    if not isinstance(data, dict):
        raise RoEError("Format roe.yaml harus berupa mapping/object.")

    if data.get("project_id") != context.project_id:
        raise RoEError(
            "Project ID pada roe.yaml tidak sesuai active project.\n"
            f"  Context : {context.project_id}\n"
            f"  File    : {data.get('project_id')!r}"
        )

    roe = data.get("roe")
    if not isinstance(roe, dict):
        raise RoEError("Field 'roe' harus berupa mapping/object.")

    defaults = _empty_document(context)["roe"]
    _merge_defaults(roe, defaults)

    status = str(roe.get("status", "")).strip().lower()
    if status not in VALID_STATUSES:
        raise RoEError(
            f"Status RoE tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data["roe"] = roe
    return data


def _merge_defaults(target: dict[str, Any], defaults: dict[str, Any]) -> None:
    """Recursively add missing default keys without overwriting user data."""
    for key, default in defaults.items():
        if key not in target:
            if isinstance(default, dict):
                target[key] = {}
                _merge_defaults(target[key], default)
            elif isinstance(default, list):
                target[key] = list(default)
            else:
                target[key] = default
        elif isinstance(default, dict) and isinstance(target[key], dict):
            _merge_defaults(target[key], default)


def _save(context: ProjectContext, data: dict[str, Any]) -> Path:
    directory = roe_dir(context)
    directory.mkdir(parents=True, exist_ok=True)

    data["schema_version"] = "1.0"
    data["project_id"] = context.project_id
    data["updated_at"] = _now()

    path = roe_file(context)

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
        raise RoEError(f"Gagal menulis: {path}\n{exc}") from exc

    return path


def initialize(*, context: Optional[ProjectContext] = None) -> Path:
    """Create roe.yaml if it does not exist."""
    if context is None:
        context = require_active_project()

    path = roe_file(context)

    if path.is_file():
        return path

    path = _save(context, _empty_document(context))

    record_activity(
        phase="01-preparation",
        item="01-003",
        action="Rules of Engagement initialized",
        status="in-progress",
        context=context,
    )

    return path


def _ensure_initialized(context: ProjectContext) -> dict[str, Any]:
    path = roe_file(context)
    if not path.is_file():
        initialize(context=context)
    return _load(context)


def _set_scalar(
    field: str,
    value: str,
    *,
    context: ProjectContext,
) -> None:
    data = _ensure_initialized(context)
    data["roe"][field] = value.strip()
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action=f"RoE field updated: {field}",
        status="in-progress",
        context=context,
    )


def set_status(status: str, *, context: Optional[ProjectContext] = None) -> None:
    if context is None:
        context = require_active_project()

    normalized = status.strip().lower()
    if normalized not in VALID_STATUSES:
        raise RoEError(
            f"Status tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_STATUSES))}"
        )

    data = _ensure_initialized(context)
    data["roe"]["status"] = normalized
    _save(context, data)

    activity_status = "completed" if normalized in {"approved", "active"} else "in-progress"

    record_activity(
        phase="01-preparation",
        item="01-003",
        action=f"RoE status changed to {normalized}",
        status=activity_status,
        context=context,
    )


def set_schedule(
    *,
    start: str = "",
    end: str = "",
    timezone: str = "Asia/Jakarta",
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    data = _ensure_initialized(context)
    schedule = data["roe"]["schedule"]
    schedule["start"] = start.strip()
    schedule["end"] = end.strip()
    schedule["timezone"] = timezone.strip() or "Asia/Jakarta"
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action="RoE assessment schedule updated",
        status="in-progress",
        context=context,
    )


def add_window(
    *,
    window_type: str,
    start: str,
    end: str,
    reason: str = "",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    if context is None:
        context = require_active_project()

    normalized = window_type.strip().lower()
    if normalized not in {"testing", "blackout"}:
        raise RoEError("window_type harus 'testing' atau 'blackout'.")

    if not start.strip() or not end.strip():
        raise RoEError("Start dan end window wajib diisi.")

    data = _ensure_initialized(context)
    key = "testing_windows" if normalized == "testing" else "blackout_windows"
    windows = data["roe"]["schedule"][key]

    item = {
        "window_id": f"{'TW' if normalized == 'testing' else 'BW'}-{len(windows) + 1:03d}",
        "start": start.strip(),
        "end": end.strip(),
        "reason": reason.strip(),
    }

    windows.append(item)
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action=f"RoE {normalized} window added: {item['window_id']}",
        status="in-progress",
        context=context,
    )

    return item


def _next_rule_id(items: list[dict[str, Any]], prefix: str) -> str:
    highest = 0
    for item in items:
        value = str(item.get("rule_id", "")).upper()
        if value.startswith(prefix) and value[len(prefix):].isdigit():
            highest = max(highest, int(value[len(prefix):]))
    return f"{prefix}{highest + 1:03d}"


def add_rule(
    *,
    action: str,
    description: str,
    condition: str = "",
    status: str = "allowed",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    if context is None:
        context = require_active_project()

    description = description.strip()
    if not description:
        raise RoEError("Deskripsi aktivitas wajib diisi.")

    normalized_status = status.strip().lower()
    if normalized_status not in VALID_ACTION_STATUSES:
        raise RoEError(
            f"Rule status tidak valid: {status!r}. "
            f"Gunakan: {', '.join(sorted(VALID_ACTION_STATUSES))}"
        )

    data = _ensure_initialized(context)
    roe = data["roe"]

    if normalized_status == "allowed":
        prefix = "ALLOW-"
        key = "allowed_activities"
    elif normalized_status == "prohibited":
        prefix = "DENY-"
        key = "prohibited_activities"
    else:
        prefix = "COND-"
        key = "conditional_activities"

    item = {
        "rule_id": _next_rule_id(roe[key], prefix),
        "action": action.strip(),
        "description": description,
    }

    if condition.strip():
        item["condition"] = condition.strip()

    roe[key].append(item)
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action=f"RoE rule added: {item['rule_id']} ({normalized_status})",
        status="in-progress",
        context=context,
    )

    return item


def set_safety(
    *,
    rate_limit: Optional[str] = None,
    concurrency_limit: Optional[str] = None,
    request_limit: Optional[str] = None,
    resource_exhaustion: Optional[bool] = None,
    destructive_testing: Optional[bool] = None,
    production_data_modification: Optional[bool] = None,
    persistence_testing: Optional[bool] = None,
    social_engineering: Optional[bool] = None,
    physical_testing: Optional[bool] = None,
    third_party_testing: Optional[bool] = None,
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    data = _ensure_initialized(context)
    safety = data["roe"]["safety_limits"]

    if rate_limit is not None:
        safety["rate_limit"] = rate_limit.strip()
    if concurrency_limit is not None:
        safety["concurrency_limit"] = concurrency_limit.strip()
    if request_limit is not None:
        safety["request_limit"] = request_limit.strip()

    flags = {
        "resource_exhaustion_testing": resource_exhaustion,
        "destructive_testing": destructive_testing,
        "production_data_modification": production_data_modification,
        "persistence_testing": persistence_testing,
        "social_engineering": social_engineering,
        "physical_testing": physical_testing,
        "third_party_testing": third_party_testing,
    }

    for key, value in flags.items():
        if value is not None:
            safety[key] = value

    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action="RoE safety limits updated",
        status="in-progress",
        context=context,
    )


def set_communication(
    *,
    channel: Optional[str] = None,
    notify_before: Optional[bool] = None,
    incident_required: Optional[bool] = None,
    incident_method: Optional[str] = None,
    escalation_notes: Optional[str] = None,
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    data = _ensure_initialized(context)
    communication = data["roe"]["communication"]

    if channel is not None:
        communication["primary_channel"] = channel.strip()
    if notify_before is not None:
        communication["notification_before_testing"] = notify_before
    if incident_required is not None:
        communication["incident_notification_required"] = incident_required
    if incident_method is not None:
        communication["incident_notification_method"] = incident_method.strip()
    if escalation_notes is not None:
        communication["escalation_notes"] = escalation_notes.strip()

    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action="RoE communication rules updated",
        status="in-progress",
        context=context,
    )


def add_stop_trigger(
    trigger: str,
    *,
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    trigger = trigger.strip()
    if not trigger:
        raise RoEError("Emergency stop trigger wajib diisi.")

    data = _ensure_initialized(context)
    triggers = data["roe"]["emergency_stop"]["trigger_conditions"]

    if trigger not in triggers:
        triggers.append(trigger)

    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action="RoE emergency stop trigger added",
        status="in-progress",
        context=context,
    )


def set_emergency_stop(
    *,
    method: Optional[str] = None,
    contact_reference: Optional[str] = None,
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    data = _ensure_initialized(context)
    emergency = data["roe"]["emergency_stop"]

    if method is not None:
        emergency["stop_method"] = method.strip()
    if contact_reference is not None:
        emergency["emergency_contact_reference"] = contact_reference.strip()

    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action="RoE emergency stop procedure updated",
        status="in-progress",
        context=context,
    )


def add_deviation(
    description: str,
    *,
    approved_by: str = "",
    approved_date: str = "",
    context: Optional[ProjectContext] = None,
) -> dict[str, Any]:
    if context is None:
        context = require_active_project()

    description = description.strip()
    if not description:
        raise RoEError("Deviation description wajib diisi.")

    data = _ensure_initialized(context)
    deviations = data["roe"]["change_control"]["deviation_notes"]

    item = {
        "deviation_id": f"DEV-{len(deviations) + 1:03d}",
        "description": description,
        "approved_by": approved_by.strip(),
        "approved_date": approved_date.strip(),
        "recorded_at": _now(),
    }

    deviations.append(item)
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action=f"RoE deviation recorded: {item['deviation_id']}",
        status="in-progress",
        context=context,
    )

    return item


def set_approval(
    *,
    approved_by: str,
    approved_date: str,
    approval_reference: str = "",
    notes: str = "",
    context: Optional[ProjectContext] = None,
) -> None:
    if context is None:
        context = require_active_project()

    if not approved_by.strip():
        raise RoEError("Approved by wajib diisi.")
    if not approved_date.strip():
        raise RoEError("Approval date wajib diisi.")

    data = _ensure_initialized(context)
    approval = data["roe"]["approval"]

    approval["approved_by"] = approved_by.strip()
    approval["approved_date"] = approved_date.strip()
    approval["approval_reference"] = approval_reference.strip()
    approval["notes"] = notes.strip()

    data["roe"]["status"] = "approved"
    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action="RoE approved",
        status="completed",
        context=context,
    )


def show(*, context: Optional[ProjectContext] = None) -> dict[str, Any]:
    if context is None:
        context = require_active_project()
    return _load(context)


def validate(*, context: Optional[ProjectContext] = None) -> list[str]:
    """
    Validate the minimum information needed before RoE approval.

    This is deliberately stricter than YAML syntax validation.
    """
    if context is None:
        context = require_active_project()

    data = _load(context)
    roe = data["roe"]
    errors: list[str] = []

    if not str(roe.get("title", "")).strip():
        errors.append("Title belum diisi.")

    if not str(roe.get("purpose", "")).strip():
        errors.append("Purpose belum diisi.")

    if not str(roe.get("authorization_reference", "")).strip():
        errors.append("Authorization reference belum diisi.")

    if not str(roe.get("scope_reference", "")).strip():
        errors.append("Scope reference belum diisi.")

    schedule = roe.get("schedule", {})
    if not str(schedule.get("start", "")).strip():
        errors.append("Schedule start belum diisi.")
    if not str(schedule.get("end", "")).strip():
        errors.append("Schedule end belum diisi.")

    emergency = roe.get("emergency_stop", {})
    if not str(emergency.get("stop_method", "")).strip():
        errors.append("Emergency stop method belum diisi.")
    if not emergency.get("trigger_conditions"):
        errors.append("Minimal satu emergency stop trigger harus ditentukan.")

    safety = roe.get("safety_limits", {})
    if not str(safety.get("rate_limit", "")).strip():
        errors.append("Rate limit belum ditentukan.")

    communication = roe.get("communication", {})
    if not str(communication.get("primary_channel", "")).strip():
        errors.append("Primary communication channel belum diisi.")

    return errors


def _print_value(value: Any, indent: int = 0) -> None:
    prefix = " " * indent

    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print(f"{prefix}{key}:")
                _print_value(item, indent + 2)
            else:
                print(f"{prefix}{key}: {item}")
    elif isinstance(value, list):
        if not value:
            print(f"{prefix}[none]")
        else:
            for item in value:
                if isinstance(item, dict):
                    print(f"{prefix}-")
                    _print_value(item, indent + 2)
                else:
                    print(f"{prefix}- {item}")
    else:
        print(f"{prefix}{value}")


def _prompt(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    return value if value else default


def interactive_add_rule(context: ProjectContext) -> None:
    print("\n=== Add RoE Rule ===")
    status = _prompt("Status", "allowed").lower()
    action = _prompt("Action")
    description = _prompt("Description")
    condition = _prompt("Condition (optional)")

    item = add_rule(
        action=action,
        description=description,
        condition=condition,
        status=status,
        context=context,
    )

    print(f"[PASS] Rule berhasil disimpan: {item['rule_id']}")


def interactive_init(context: ProjectContext) -> None:
    print("\n=== Initialize Rules of Engagement ===")
    path = initialize(context=context)
    data = _load(context)
    roe = data["roe"]

    print(f"RoE file: {path}")

    roe["title"] = _prompt("Title", roe["title"])
    roe["purpose"] = _prompt("Purpose", roe["purpose"])
    roe["authorization_reference"] = _prompt(
        "Authorization Reference",
        roe["authorization_reference"],
    )
    roe["scope_reference"] = _prompt(
        "Scope Reference",
        roe["scope_reference"],
    )
    roe["communication"]["primary_channel"] = _prompt(
        "Primary Communication Channel",
        roe["communication"]["primary_channel"],
    )
    roe["schedule"]["start"] = _prompt(
        "Assessment Start",
        roe["schedule"]["start"],
    )
    roe["schedule"]["end"] = _prompt(
        "Assessment End",
        roe["schedule"]["end"],
    )
    roe["schedule"]["timezone"] = _prompt(
        "Timezone",
        roe["schedule"]["timezone"],
    )
    roe["safety_limits"]["rate_limit"] = _prompt(
        "Rate Limit",
        roe["safety_limits"]["rate_limit"] or "To be determined",
    )
    roe["emergency_stop"]["stop_method"] = _prompt(
        "Emergency Stop Method",
        roe["emergency_stop"]["stop_method"],
    )

    if not roe["emergency_stop"]["trigger_conditions"]:
        print("\nTambahkan emergency stop trigger. Kosongkan jika selesai.")
        while True:
            trigger = input("Trigger: ").strip()
            if not trigger:
                break
            roe["emergency_stop"]["trigger_conditions"].append(trigger)

    _save(context, data)

    record_activity(
        phase="01-preparation",
        item="01-003",
        action="Rules of Engagement draft configured",
        status="in-progress",
        context=context,
    )

    print("[PASS] Draft RoE berhasil disimpan.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage Rules of Engagement for the active pentest project."
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create/configure the RoE draft.")
    p_init.add_argument(
        "--non-interactive",
        action="store_true",
        help="Only create the file without prompts.",
    )

    sub.add_parser("show", help="Show the current RoE.")
    sub.add_parser("validate", help="Validate RoE readiness.")

    p_status = sub.add_parser("status", help="Set RoE status.")
    p_status.add_argument("status", choices=sorted(VALID_STATUSES))

    p_set = sub.add_parser("set", help="Set a scalar RoE field.")
    p_set.add_argument(
        "field",
        choices=[
            "title",
            "purpose",
            "authorization_reference",
            "scope_reference",
            "notes",
        ],
    )
    p_set.add_argument("value")

    p_schedule = sub.add_parser("schedule", help="Set the assessment schedule.")
    p_schedule.add_argument("--start", required=True)
    p_schedule.add_argument("--end", required=True)
    p_schedule.add_argument("--timezone", default="Asia/Jakarta")

    p_window = sub.add_parser("window", help="Add a testing or blackout window.")
    p_window.add_argument("type", choices=["testing", "blackout"])
    p_window.add_argument("--start", required=True)
    p_window.add_argument("--end", required=True)
    p_window.add_argument("--reason", default="")

    p_rule = sub.add_parser("rule", help="Add an allowed/prohibited/conditional rule.")
    p_rule.add_argument(
        "status",
        choices=sorted(VALID_ACTION_STATUSES),
    )
    p_rule.add_argument("--action", required=True)
    p_rule.add_argument("--description", required=True)
    p_rule.add_argument("--condition", default="")

    p_safety = sub.add_parser("safety", help="Set safety limits.")
    p_safety.add_argument("--rate-limit")
    p_safety.add_argument("--concurrency-limit")
    p_safety.add_argument("--request-limit")
    p_safety.add_argument(
        "--resource-exhaustion",
        choices=["true", "false"],
    )
    p_safety.add_argument(
        "--destructive-testing",
        choices=["true", "false"],
    )
    p_safety.add_argument(
        "--production-data-modification",
        choices=["true", "false"],
    )
    p_safety.add_argument(
        "--persistence-testing",
        choices=["true", "false"],
    )
    p_safety.add_argument(
        "--social-engineering",
        choices=["true", "false"],
    )
    p_safety.add_argument(
        "--physical-testing",
        choices=["true", "false"],
    )
    p_safety.add_argument(
        "--third-party-testing",
        choices=["true", "false"],
    )

    p_comm = sub.add_parser("communication", help="Set communication rules.")
    p_comm.add_argument("--channel")
    p_comm.add_argument(
        "--notify-before",
        choices=["true", "false"],
    )
    p_comm.add_argument(
        "--incident-required",
        choices=["true", "false"],
    )
    p_comm.add_argument("--incident-method")
    p_comm.add_argument("--escalation-notes")

    p_stop = sub.add_parser("stop-trigger", help="Add an emergency stop trigger.")
    p_stop.add_argument("trigger")

    p_stop_cfg = sub.add_parser("stop", help="Configure emergency stop procedure.")
    p_stop_cfg.add_argument("--method")
    p_stop_cfg.add_argument("--contact-reference")

    p_dev = sub.add_parser("deviation", help="Record a RoE deviation/change.")
    p_dev.add_argument("description")
    p_dev.add_argument("--approved-by", default="")
    p_dev.add_argument("--approved-date", default="")

    p_approve = sub.add_parser("approve", help="Approve the RoE.")
    p_approve.add_argument("--approved-by", required=True)
    p_approve.add_argument("--approved-date", required=True)
    p_approve.add_argument("--reference", default="")
    p_approve.add_argument("--notes", default="")

    sub.add_parser("add-rule", help="Interactively add a RoE rule.")
    sub.add_parser("version", help="Show script version.")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        context = require_active_project()

        if args.command == "init":
            if args.non_interactive:
                path = initialize(context=context)
                print(f"[PASS] RoE berhasil diinisialisasi: {path}")
            else:
                interactive_init(context)
            return 0

        if args.command == "show":
            data = show(context=context)
            print(f"PROJECT: {context.project_id}")
            print(f"FILE   : {roe_file(context)}")
            print()
            _print_value(data["roe"])
            return 0

        if args.command == "validate":
            errors = validate(context=context)
            if errors:
                print("[FAIL] RoE belum siap:")
                for error in errors:
                    print(f"  - {error}")
                return 1
            print("[PASS] RoE memenuhi validasi minimum.")
            return 0

        if args.command == "status":
            set_status(args.status, context=context)
            print(f"[PASS] Status RoE: {args.status}")
            return 0

        if args.command == "set":
            _set_scalar(args.field, args.value, context=context)
            print(f"[PASS] Field '{args.field}' berhasil diperbarui.")
            return 0

        if args.command == "schedule":
            set_schedule(
                start=args.start,
                end=args.end,
                timezone=args.timezone,
                context=context,
            )
            print("[PASS] Schedule RoE berhasil diperbarui.")
            return 0

        if args.command == "window":
            item = add_window(
                window_type=args.type,
                start=args.start,
                end=args.end,
                reason=args.reason,
                context=context,
            )
            print(f"[PASS] Window berhasil disimpan: {item['window_id']}")
            return 0

        if args.command == "rule":
            item = add_rule(
                action=args.action,
                description=args.description,
                condition=args.condition,
                status=args.status,
                context=context,
            )
            print(f"[PASS] Rule berhasil disimpan: {item['rule_id']}")
            return 0

        if args.command == "add-rule":
            interactive_add_rule(context)
            return 0

        if args.command == "safety":
            bool_map = {
                "resource_exhaustion": args.resource_exhaustion,
                "destructive_testing": args.destructive_testing,
                "production_data_modification": args.production_data_modification,
                "persistence_testing": args.persistence_testing,
                "social_engineering": args.social_engineering,
                "physical_testing": args.physical_testing,
                "third_party_testing": args.third_party_testing,
            }

            kwargs: dict[str, Any] = {
                "rate_limit": args.rate_limit,
                "concurrency_limit": args.concurrency_limit,
                "request_limit": args.request_limit,
            }

            for key, value in bool_map.items():
                kwargs[key] = (
                    None
                    if value is None
                    else value.lower() == "true"
                )

            set_safety(context=context, **kwargs)
            print("[PASS] Safety limits berhasil diperbarui.")
            return 0

        if args.command == "communication":
            set_communication(
                channel=args.channel,
                notify_before=(
                    None
                    if args.notify_before is None
                    else args.notify_before.lower() == "true"
                ),
                incident_required=(
                    None
                    if args.incident_required is None
                    else args.incident_required.lower() == "true"
                ),
                incident_method=args.incident_method,
                escalation_notes=args.escalation_notes,
                context=context,
            )
            print("[PASS] Communication rules berhasil diperbarui.")
            return 0

        if args.command == "stop-trigger":
            add_stop_trigger(args.trigger, context=context)
            print("[PASS] Emergency stop trigger berhasil ditambahkan.")
            return 0

        if args.command == "stop":
            set_emergency_stop(
                method=args.method,
                contact_reference=args.contact_reference,
                context=context,
            )
            print("[PASS] Emergency stop procedure berhasil diperbarui.")
            return 0

        if args.command == "deviation":
            item = add_deviation(
                args.description,
                approved_by=args.approved_by,
                approved_date=args.approved_date,
                context=context,
            )
            print(f"[PASS] Deviation berhasil dicatat: {item['deviation_id']}")
            return 0

        if args.command == "approve":
            set_approval(
                approved_by=args.approved_by,
                approved_date=args.approved_date,
                approval_reference=args.reference,
                notes=args.notes,
                context=context,
            )
            print("[PASS] RoE disetujui dan status menjadi approved.")
            return 0

        if args.command == "version":
            print(f"roe.py {SCRIPT_VERSION}")
            return 0

        parser.error("Perintah tidak dikenal.")
        return 2

    except (ContextError, RoEError, OSError, ValueError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[INFO] Dibatalkan oleh user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
