#!/usr/bin/env python3
"""
BrebesKab-CSIRT-Tools - Authentication Brute-Force Protection

Checklist: 5-006 Brute-Force / Rate-Limit Protection

Purpose
-------
Controlled assessment of repeated authentication-failure protection using one
explicitly authorized test account. This script is intentionally NOT an
unrestricted password-cracking or credential-stuffing tool.

The assessment is bounded to a maximum of five failed login attempts. It uses
one generated invalid password value and never uses a password wordlist,
credential spray, arbitrary usernames, or distributed attempts.

Human-interaction policy
------------------------
If the login flow presents a human-interaction control such as Cloudflare
Turnstile or CAPTCHA, automated authentication testing stops immediately.
No challenge bypass is attempted. Under the agreed assessment rule, a
human-interaction requirement is classified as PASS for anti-automation
protection because the automated brute-force path cannot continue.

Security model
--------------
* Active authorized test account only.
* Username is decrypted only in memory.
* The real password is never needed for this checklist.
* The generated invalid password is never persisted in evidence.
* CSRF values, cookies, authorization headers, and password fields are not
  persisted in plaintext.
* Redirects are disabled for assessment requests.
* Strict stop conditions prevent lockout escalation and uncontrolled testing.
* HTTP status alone is not treated as a vulnerability.
* Findings are not automatic; policy failure requires sufficient evidence.
* CVE correlation is secondary metadata only; version match != vulnerability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests
    import yaml
    from bs4 import BeautifulSoup
except ImportError as exc:  # pragma: no cover
    print(f"[FAIL] Dependency tidak tersedia: {exc}")
    raise SystemExit(1)


SCRIPT_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "5-006"
CHECKLIST_NAME = "Brute-Force / Rate-Limit Protection"
PHASE = "05 Authentication"
DEFAULT_LOGIN_PATH = "/login"
DEFAULT_TIMEOUT = 15
DEFAULT_FAILED_ATTEMPTS = 5
MAX_FAILED_ATTEMPTS = 5
DEFAULT_DELAY_SECONDS = 1.0
MAX_DELAY_SECONDS = 10.0
MAX_BODY_BYTES = 262144
BODY_SAMPLE_CHARS = 4000
USER_AGENT = "BrebesKab-CSIRT-Tools/5-006"

HUMAN_INTERACTION_PATTERNS = [
    r"cloudflare turnstile",
    r"cf-turnstile",
    r"turnstile",
    r"captcha",
    r"g-recaptcha",
    r"hcaptcha",
    r"human verification",
    r"verify you are human",
    r"prove you are human",
    r"challenge-platform",
]

RATE_LIMIT_PATTERNS = [
    r"too many requests",
    r"rate limit",
    r"rate-limit",
    r"temporarily blocked",
    r"try again later",
    r"too many login",
    r"too many attempts",
    r"request limit",
]
LOCKOUT_PATTERNS = [
    r"account locked",
    r"account lock",
    r"temporarily locked",
    r"login locked",
    r"user locked",
    r"blocked account",
]
LOGIN_FAILURE_PATTERNS = [
    r"invalid credentials",
    r"invalid username",
    r"invalid password",
    r"incorrect password",
    r"wrong password",
    r"login failed",
    r"authentication failed",
    r"username.*password",
]


class BruteForceError(RuntimeError):
    """Controlled brute-force/rate-limit assessment error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_yaml(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(str(path))
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def dump_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(
            data,
            handle,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
        )


def dump_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def runtime_context() -> dict[str, Any]:
    root = repo_root()
    active = root / ".runtime" / "active-project.yaml"
    data = load_yaml(active)
    if not isinstance(data, dict):
        raise BruteForceError("Active project context bukan object YAML.")

    project_id = str(data.get("project_id") or data.get("id") or "").strip()
    raw_path = str(data.get("project_path") or "").strip()
    if not project_id or not raw_path:
        raise BruteForceError("project_id/project_path tidak lengkap pada active-project.yaml.")

    project_path = Path(raw_path)
    if not project_path.is_absolute():
        project_path = root / project_path
    project_path = project_path.resolve()
    if not project_path.exists():
        raise BruteForceError(f"Project aktif tidak ditemukan: {project_path}")

    assessment = project_path / "assessment.yaml"
    if not assessment.exists():
        raise BruteForceError(f"assessment.yaml tidak ditemukan: {assessment}")

    assessment_data = load_yaml(assessment)
    if isinstance(assessment_data, dict):
        assessment_project_id = str(
            assessment_data.get("project_id") or assessment_data.get("id") or ""
        ).strip()
        if assessment_project_id and assessment_project_id != project_id:
            raise BruteForceError(
                "project_id active context tidak sama dengan assessment.yaml: "
                f"{project_id} != {assessment_project_id}"
            )

    return {
        "project_id": project_id,
        "project_path": project_path,
        "active_context": active,
        "assessment": assessment,
        "assessment_data": assessment_data,
    }


def locate_scope(project_path: Path) -> Path:
    for path in (
        project_path / "01-preparation" / "scope" / "scope.yaml",
        project_path / "01-preparation" / "scope" / "scope.yml",
    ):
        if path.exists():
            return path
    raise BruteForceError("scope.yaml tidak ditemukan pada project aktif.")


def extract_scope(scope: dict[str, Any]) -> list[dict[str, Any]]:
    section = scope.get("scope", {})
    items = section.get("in_scope", []) if isinstance(section, dict) else scope.get("in_scope", [])
    return items if isinstance(items, list) else []


def target_from_scope(scope: dict[str, Any]) -> dict[str, Any]:
    for item in extract_scope(scope):
        if not isinstance(item, dict):
            continue
        value = str(item.get("value") or item.get("hostname") or "").strip()
        scope_type = str(item.get("type") or "").lower()
        if not value or scope_type not in {"domain", "hostname", "url"}:
            continue

        ports = item.get("ports") or item.get("authorized_ports") or [80, 443]
        authorized_ports = []
        for port in ports:
            try:
                authorized_ports.append(int(port))
            except (TypeError, ValueError):
                continue
        if not authorized_ports:
            authorized_ports = [80, 443]

        if value.startswith(("http://", "https://")):
            base_url = value.rstrip("/")
            hostname = urlparse(base_url).hostname or value
        else:
            hostname = value
            base_url = f"https://{value}"

        return {
            "scope_id": str(item.get("scope_id") or "IN-001"),
            "type": scope_type,
            "value": value,
            "hostname": hostname,
            "url": base_url,
            "authorized_ports": authorized_ports,
        }
    raise BruteForceError("Tidak ada domain/hostname in-scope yang dapat digunakan.")


def artifact_dir(project_path: Path) -> Path:
    return project_path / "05-authentication" / "bruteforce"


def artifact_file(project_path: Path) -> Path:
    return artifact_dir(project_path) / "bruteforce.yaml"


def evidence_file(project_path: Path) -> Path:
    return artifact_dir(project_path) / "evidence" / "bruteforce-probes.json"


def account_file(project_path: Path) -> Path:
    return project_path / "01-preparation" / "account" / "accounts.yaml"


def load_account(account_id: str, context: dict[str, Any]) -> dict[str, Any]:
    """Load one authorized account metadata record without exposing credentials."""
    data = load_yaml(account_file(context["project_path"]))
    accounts = data.get("accounts", []) if isinstance(data, dict) else []
    wanted = account_id.strip().upper()
    for account in accounts:
        if not isinstance(account, dict):
            continue
        if str(account.get("account_id") or "").strip().upper() != wanted:
            continue
        status = str(account.get("status") or "").strip().lower()
        if status != "active":
            raise BruteForceError(f"Test account {wanted} tidak active.")
        credentials = account.get("credentials")
        if not isinstance(credentials, dict):
            raise BruteForceError(f"Credential metadata {wanted} tidak valid.")
        encrypted_username = str(credentials.get("username") or "").strip()
        if not encrypted_username:
            raise BruteForceError(f"Encrypted username {wanted} tidak tersedia.")
        return {
            "account_id": wanted,
            "status": status,
            "username_encrypted": encrypted_username,
        }
    raise BruteForceError(f"Test account tidak ditemukan: {wanted}")


def decrypt_username(encrypted_username: str, project_id: str) -> str:
    scripts_dir = Path(__file__).resolve().parents[1]
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    try:
        from secrets import SecretsError, decrypt
    except ImportError as exc:
        raise BruteForceError(f"Modul scripts.secrets tidak tersedia: {exc}") from exc

    try:
        username = decrypt(encrypted_username, project_id=project_id)
    except SecretsError as exc:
        raise BruteForceError("Username test account tidak dapat didecrypt dengan project key.") from exc
    if not username:
        raise BruteForceError("Username test account hasil decrypt kosong.")
    return username


def detect_patterns(text: str, patterns: list[str]) -> list[str]:
    found = []
    for pattern in patterns:
        if re.search(pattern, text, re.I):
            found.append(pattern)
    return found


def safe_sample(text: str) -> str:
    value = re.sub(r"(?i)(password\s*[=:]\s*)[^&\s<]+", r"\1[REDACTED]", text)
    value = re.sub(r"(?i)(csrf[^=\s]*\s*[=:]\s*)[^&\s<]+", r"\1[REDACTED]", value)
    return value[:BODY_SAMPLE_CHARS]


def response_snapshot(response: requests.Response) -> dict[str, Any]:
    try:
        body = response.text[:MAX_BODY_BYTES]
    except Exception:
        body = ""
    text = body[:BODY_SAMPLE_CHARS]
    location = response.headers.get("Location")
    return {
        "status_code": response.status_code,
        "reason": response.reason,
        "location": location,
        "content_type": response.headers.get("Content-Type"),
        "server": response.headers.get("Server"),
        "retry_after_present": bool(response.headers.get("Retry-After")),
        "set_cookie_present": bool(response.headers.get("Set-Cookie")),
        "body_sample": safe_sample(text),
        "body_sha256": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
    }


def human_interaction_state(response: requests.Response) -> dict[str, Any]:
    try:
        body = response.text[:MAX_BODY_BYTES]
    except Exception:
        body = ""
    header_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    combined = f"{header_text}\n{body}"
    matches = detect_patterns(combined, HUMAN_INTERACTION_PATTERNS)
    return {
        "detected": bool(matches),
        "indicators": matches,
        "policy": "PASS_AND_STOP_AUTOMATION",
    }


def classify_rate_limit(response: requests.Response, body: str) -> dict[str, Any]:
    combined = body[:MAX_BODY_BYTES]
    rate_matches = detect_patterns(combined, RATE_LIMIT_PATTERNS)
    lock_matches = detect_patterns(combined, LOCKOUT_PATTERNS)
    human_matches = detect_patterns(combined, HUMAN_INTERACTION_PATTERNS)

    return {
        "rate_limit_detected": bool(response.status_code == 429 or rate_matches),
        "rate_limit_indicators": rate_matches,
        "lockout_detected": bool(lock_matches),
        "lockout_indicators": lock_matches,
        "human_interaction_detected": bool(human_matches),
        "human_interaction_indicators": human_matches,
        "retry_after_present": bool(response.headers.get("Retry-After")),
    }


def discover_login_form(
    session: requests.Session,
    login_url: str,
    timeout: int,
) -> dict[str, Any]:
    started = time.monotonic()
    response = session.get(login_url, timeout=timeout, allow_redirects=False)
    elapsed = round((time.monotonic() - started) * 1000, 2)

    human = human_interaction_state(response)
    soup = BeautifulSoup(response.text[:MAX_BODY_BYTES], "html.parser")
    forms = []
    selected = None

    for form in soup.find_all("form"):
        action = urljoin(login_url, str(form.get("action") or login_url))
        method = str(form.get("method") or "GET").upper()
        fields = []
        for element in form.find_all(["input", "button", "textarea", "select"]):
            name = str(element.get("name") or "").strip()
            field_type = str(element.get("type") or element.name or "").lower()
            if name:
                fields.append({"name": name, "type": field_type})
        username_fields = [
            f["name"] for f in fields if re.search(r"user|email|login|identifier", f["name"], re.I)
        ]
        password_fields = [
            f["name"] for f in fields if f["type"] == "password" or re.search(r"pass", f["name"], re.I)
        ]
        csrf_fields = [
            f["name"] for f in fields if re.search(r"csrf|token", f["name"], re.I)
        ]
        record = {
            "action": action,
            "method": method,
            "field_count": len(fields),
            "username_fields": username_fields,
            "password_fields": password_fields,
            "csrf_fields": csrf_fields,
        }
        forms.append(record)
        if selected is None and username_fields and password_fields:
            selected = record

    return {
        "request": {
            "method": "GET",
            "url": login_url,
            "status_code": response.status_code,
            "elapsed_ms": elapsed,
        },
        "response": response_snapshot(response),
        "human_interaction": human,
        "forms": forms,
        "selected_form": selected,
        "cookies_observed": len(session.cookies),
    }


def csrf_value(form: BeautifulSoup, csrf_name: str) -> str | None:
    if not csrf_name:
        return None
    element = form.find("input", attrs={"name": csrf_name})
    if element is None:
        return None
    value = element.get("value")
    return str(value) if value is not None else ""


def discover_form_for_attempt(
    session: requests.Session,
    login_url: str,
    timeout: int,
) -> tuple[str, str, str, dict[str, Any], str | None]:
    response = session.get(login_url, timeout=timeout, allow_redirects=False)
    human = human_interaction_state(response)
    if human["detected"]:
        return login_url, "POST", "", human, None

    soup = BeautifulSoup(response.text[:MAX_BODY_BYTES], "html.parser")
    selected = None
    for form in soup.find_all("form"):
        password = form.find("input", attrs={"type": "password"})
        if password is None:
            continue
        action = urljoin(login_url, str(form.get("action") or login_url))
        method = str(form.get("method") or "POST").upper()
        username = form.find(
            "input",
            attrs={"name": re.compile(r"user|email|login|identifier", re.I)},
        )
        if username is None:
            username = form.find("input", attrs={"type": "text"})
        if username is None:
            continue
        csrf = form.find(
            "input",
            attrs={"name": re.compile(r"csrf|token", re.I)},
        )
        csrf_name = str(csrf.get("name") or "") if csrf else ""
        csrf_token = csrf_value(form, csrf_name) if csrf_name else None
        selected = (action, method, str(username.get("name") or "username"), human, csrf_token)
        break

    if selected is None:
        raise BruteForceError("Login form dengan username/password tidak ditemukan.")
    return selected


def generated_invalid_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "BF-TEST-" + "".join(secrets.choice(alphabet) for _ in range(24))


def sanitize_location(location: str | None, login_url: str) -> str | None:
    if not location:
        return None
    try:
        parsed = urlparse(urljoin(login_url, location))
        return parsed.path or "/"
    except Exception:
        return None


def auth_failure_indicator(response: requests.Response, body: str) -> bool:
    if response.status_code in {401, 403, 429}:
        return True
    if response.status_code in {301, 302, 303, 307, 308}:
        location = str(response.headers.get("Location") or "")
        if "/login" in location.lower():
            return True
    return bool(detect_patterns(body, LOGIN_FAILURE_PATTERNS))


def perform_failed_attempts(
    *,
    target: dict[str, Any],
    username: str,
    login_url: str,
    max_attempts: int,
    timeout: int,
    delay: float,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    attempts: list[dict[str, Any]] = []
    stop_reason = None
    result = "REVIEW"
    rate_limit_observed = False
    lockout_observed = False
    human_interaction_observed = False

    invalid_password = generated_invalid_password()
    try:
        for number in range(1, max_attempts + 1):
            if number > 1:
                time.sleep(delay)

            action, method, username_field, human, csrf_token = discover_form_for_attempt(
                session, login_url, timeout
            )
            if human["detected"]:
                human_interaction_observed = True
                stop_reason = "Human interaction detected; automated testing stopped."
                result = "PASS"
                break

            if method != "POST":
                stop_reason = f"Login form method {method} tidak didukung untuk controlled test."
                result = "REVIEW"
                break

            password_field = "password"
            # Re-read the form to preserve actual field names without logging values.
            page = session.get(login_url, timeout=timeout, allow_redirects=False)
            if human_interaction_state(page)["detected"]:
                human_interaction_observed = True
                stop_reason = "Human interaction detected before authentication attempt."
                result = "PASS"
                break
            soup = BeautifulSoup(page.text[:MAX_BODY_BYTES], "html.parser")
            form = None
            for candidate in soup.find_all("form"):
                if candidate.find("input", attrs={"type": "password"}):
                    form = candidate
                    break
            if form is None:
                stop_reason = "Login form menghilang sebelum attempt."
                result = "REVIEW"
                break
            password_element = form.find("input", attrs={"type": "password"})
            password_field = str(password_element.get("name") or "password")
            csrf_element = form.find("input", attrs={"name": re.compile(r"csrf|token", re.I)})
            csrf_name = str(csrf_element.get("name") or "") if csrf_element else ""
            csrf_token = str(csrf_element.get("value") or "") if csrf_element else None

            payload = {
                username_field: username,
                password_field: invalid_password,
            }
            if csrf_name:
                payload[csrf_name] = csrf_token or ""

            started = time.monotonic()
            response = session.post(
                action,
                data=payload,
                timeout=timeout,
                allow_redirects=False,
            )
            elapsed = round((time.monotonic() - started) * 1000, 2)
            try:
                body = response.text[:MAX_BODY_BYTES]
            except Exception:
                body = ""

            classification = classify_rate_limit(response, body)
            auth_failed = auth_failure_indicator(response, body)
            snapshot = response_snapshot(response)
            snapshot["location"] = sanitize_location(response.headers.get("Location"), login_url)
            snapshot["elapsed_ms"] = elapsed

            attempt = {
                "attempt": number,
                "request": {
                    "method": "POST",
                    "url": action,
                    "username_field": username_field,
                    "password_field": password_field,
                    "csrf_present": bool(csrf_name),
                    "password_logged": False,
                    "csrf_logged": False,
                },
                "response": snapshot,
                "classification": classification,
                "authentication_failure_indicator": auth_failed,
                "plaintext_password_persisted": False,
            }
            attempts.append(attempt)

            if classification["human_interaction_detected"]:
                human_interaction_observed = True
                stop_reason = "Human interaction detected after failed authentication attempt."
                result = "PASS"
                break

            if classification["rate_limit_detected"]:
                rate_limit_observed = True
                stop_reason = "Rate-limit protection observed; testing stopped."
                result = "PASS"
                break

            if classification["lockout_detected"]:
                lockout_observed = True
                stop_reason = "Account-lockout protection observed; testing stopped."
                result = "PASS"
                break

            if response.status_code in {401, 403}:
                # Authentication rejection alone does not prove rate limiting;
                # continue only within the strict maximum bound.
                continue

        else:
            if len(attempts) >= max_attempts:
                stop_reason = "Maximum bounded failed-login attempts reached without observed protection."
                result = "REVIEW"
    finally:
        # Do not keep session cookies beyond the bounded test.
        session.close()

    summary = {
        "result": result,
        "attempts_sent": len(attempts),
        "maximum_attempts": max_attempts,
        "rate_limit_observed": rate_limit_observed,
        "lockout_observed": lockout_observed,
        "human_interaction_observed": human_interaction_observed,
        "stop_reason": stop_reason,
        "automatic_finding": False,
        "finding": False,
        "requires_review": result == "REVIEW",
    }
    return summary, attempts


def cve_correlation(context: dict[str, Any]) -> dict[str, Any]:
    version_path = context["project_path"] / "04-web-server-configuration" / "version" / "version.yaml"
    result: dict[str, Any] = {
        "source": str(version_path),
        "source_checklist": "4-001",
        "candidate_count": 0,
        "candidates": [],
        "assessment_note": "CVE correlation is secondary metadata only; version match is not a vulnerability.",
    }
    if not version_path.exists():
        result["assessment_note"] = "4-001 version.yaml tidak ditemukan; CVE correlation tidak dilakukan."
        return result
    try:
        data = load_yaml(version_path)
    except Exception as exc:
        result["assessment_note"] = f"Gagal membaca 4-001 version.yaml: {exc}"
        return result

    products = data.get("cve_correlation", {}).get("products", []) if isinstance(data, dict) else []
    if not isinstance(products, list):
        products = []
    keywords = re.compile(
        r"authentication|brute.?force|rate.?limit|throttl|lockout|login|credential|password",
        re.I,
    )
    candidates = []
    for product in products:
        if not isinstance(product, dict):
            continue
        for cve in product.get("cves", []) or []:
            if not isinstance(cve, dict):
                continue
            description = str(cve.get("description") or "")
            if not keywords.search(description):
                continue
            candidates.append(
                {
                    "cve_id": str(cve.get("cve") or cve.get("cve_id") or ""),
                    "product": str(product.get("product") or cve.get("product") or ""),
                    "version": str(product.get("version") or cve.get("version") or ""),
                    "severity": cve.get("severity"),
                    "cvss": cve.get("cvss"),
                    "description": description[:2000],
                    "classification": "authentication-relevant-candidate",
                    "requires_validation": True,
                    "finding": False,
                }
            )
    result["candidate_count"] = len(candidates)
    result["candidates"] = candidates
    return result


def initial_artifact(context: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": context["project_id"],
        "tool": {
            "name": "BrebesKab-CSIRT-Tools",
            "script": "bruteforce.py",
            "version": SCRIPT_VERSION,
        },
        "checklist": {
            "id": CHECKLIST_ID,
            "name": CHECKLIST_NAME,
            "phase": PHASE,
            "focus": "Controlled repeated authentication-failure protection assessment.",
            "status": "initialized",
        },
        "target": {
            "application": context["assessment_data"].get("application") or context["project_id"],
            "hostname": target["hostname"],
            "url": target["url"],
            "environment": context["assessment_data"].get("environment") or "Production",
            "assessment_type": context["assessment_data"].get("assessment_type") or "Grey Box",
            "scope_id": target["scope_id"],
            "scope_reference": "01-preparation/scope/scope.yaml",
            "authorized_ports": target["authorized_ports"],
            "login_path": DEFAULT_LOGIN_PATH,
        },
        "methodology": {
            "description": "Bounded repeated failed-login assessment using one authorized account and one generated invalid password.",
            "account_scope": "one active authorized test account",
            "maximum_failed_attempts": MAX_FAILED_ATTEMPTS,
            "default_failed_attempts": DEFAULT_FAILED_ATTEMPTS,
            "invalid_password_strategy": "one generated invalid value; never persisted",
            "wordlist": False,
            "password_cracking": False,
            "credential_spraying": False,
            "username_enumeration": False,
            "distributed_attempts": False,
            "redirect_following": False,
            "human_interaction_policy": "PASS_AND_STOP_AUTOMATION",
            "captcha_bypass": False,
            "automatic_finding": False,
        },
        "baseline": {
            "scope_source": "01-preparation/scope/scope.yaml",
            "account_source": "01-preparation/account/accounts.yaml",
            "version_source": "04-web-server-configuration/version/version.yaml",
            "candidate_policy": "Authentication endpoint discovered from login form; no generic endpoint fuzzing.",
        },
        "toolchain": {
            "mandatory": [
                "Python",
                "requests",
                "PyYAML",
                "BeautifulSoup",
                "scripts.context",
                "scripts.secrets",
                "accounts.yaml",
            ],
            "optional": ["curl"],
        },
        "probe": {
            "method": "GET discovery + bounded POST failed-login attempts",
            "timeout_seconds": DEFAULT_TIMEOUT,
            "allow_redirects": False,
            "max_body_bytes": MAX_BODY_BYTES,
            "body_sample_chars": BODY_SAMPLE_CHARS,
            "maximum_failed_attempts": MAX_FAILED_ATTEMPTS,
            "delay_seconds": DEFAULT_DELAY_SECONDS,
            "human_interaction_stop": True,
        },
        "source_status": {
            "scope": "completed",
            "account": "completed",
            "version": "pending",
        },
        "results": {
            "account_id": None,
            "login_discovery": {},
            "attempts": [],
            "summary": {},
        },
        "summary": {
            "result": "not_tested",
            "attempts_sent": 0,
            "rate_limit_observed": False,
            "lockout_observed": False,
            "human_interaction_observed": False,
            "finding": False,
            "requires_review": False,
        },
        "cve_correlation": {
            "source": "04-web-server-configuration/version/version.yaml",
            "source_checklist": "4-001",
            "candidate_count": 0,
            "candidates": [],
            "assessment_note": "Not tested until analyze; version match != vulnerability.",
        },
        "assessment": {
            "result": "not_tested",
            "finding": False,
            "requires_review": False,
            "automatic_finding": False,
            "reason": "Belum dilakukan testing.",
        },
        "evidence": {
            "path": "05-authentication/bruteforce/evidence/bruteforce-probes.json",
            "password_logged": False,
            "plaintext_password_persisted": False,
            "csrf_logged": False,
            "session_cookie_logged": False,
        },
        "errors": [],
        "notes": [
            "Human interaction requirement is PASS for anti-automation under the agreed assessment rule.",
            "Human interaction is never bypassed.",
            "HTTP status alone is not a vulnerability finding.",
            "CVE/version correlation is secondary and requires target validation.",
        ],
        "generated_at": utc_now(),
        "updated_at": utc_now(),
    }


def cmd_version() -> int:
    print(f"BrebesKab-CSIRT-Tools bruteforce.py v{SCRIPT_VERSION}")
    print(f"Checklist: {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema   : {SCHEMA_VERSION}")
    print("Method   : bounded failed-login assessment + human-interaction stop policy")
    print("Storage  : bruteforce.yaml + bruteforce-probes.json; password/CSRF/session values never persisted")
    print("Limit    : maximum 5 failed attempts using one authorized account and one generated invalid password")
    print("Client   : requests.Session; redirects disabled; strict stop conditions")
    print("Human   : Turnstile/CAPTCHA/human interaction = PASS and stop; no bypass")
    print("CVE      : secondary correlation only; version match != vulnerability")
    return 0


def cmd_init() -> int:
    context = runtime_context()
    scope = load_yaml(locate_scope(context["project_path"]))
    target = target_from_scope(scope)
    path = artifact_file(context["project_path"])
    if path.exists():
        print(f"[INFO] Artifact sudah ada: {path}")
        return 0
    data = initial_artifact(context, target)
    dump_yaml(path, data)
    print(f"[PASS] Brute-Force / Rate-Limit Protection diinisialisasi: {path}")
    return 0


def cmd_analyze(account_id: str | None, attempts: int, timeout: int, delay: float) -> int:
    if attempts < 1 or attempts > MAX_FAILED_ATTEMPTS:
        raise BruteForceError(f"failed-attempts harus 1..{MAX_FAILED_ATTEMPTS}.")
    if timeout < 1:
        raise BruteForceError("timeout harus >= 1 detik.")
    if delay < 0 or delay > MAX_DELAY_SECONDS:
        raise BruteForceError(f"delay harus 0..{MAX_DELAY_SECONDS} detik.")

    context = runtime_context()
    scope = load_yaml(locate_scope(context["project_path"]))
    target = target_from_scope(scope)
    if 443 not in target["authorized_ports"] and 80 not in target["authorized_ports"]:
        raise BruteForceError("Target tidak memiliki port HTTP/HTTPS authorized.")

    if not account_id:
        raise BruteForceError("--account-id wajib diisi untuk controlled failed-login testing.")

    account = load_account(account_id, context)
    username = decrypt_username(account["username_encrypted"], context["project_id"])

    login_url = target["url"] + DEFAULT_LOGIN_PATH
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    discovery = discover_login_form(session, login_url, timeout)
    session.close()

    path = artifact_file(context["project_path"])
    evidence_path = evidence_file(context["project_path"])
    data = load_yaml(path) if path.exists() else initial_artifact(context, target)

    data["tool"]["version"] = SCRIPT_VERSION
    data["checklist"]["status"] = "completed"
    data["target"]["hostname"] = target["hostname"]
    data["target"]["url"] = target["url"]
    data["target"]["scope_id"] = target["scope_id"]
    data["target"]["authorized_ports"] = target["authorized_ports"]
    data["results"]["account_id"] = account["account_id"]
    data["results"]["login_discovery"] = discovery
    data["source_status"]["version"] = "completed"
    data["updated_at"] = utc_now()

    print(f"[INFO] Account       : {account['account_id']}")
    print(f"[INFO] Target        : {target['hostname']}")
    print(f"[INFO] Login URL     : {login_url}")
    print(f"[INFO] Max attempts  : {attempts}")

    if discovery["human_interaction"]["detected"]:
        summary = {
            "result": "PASS",
            "attempts_sent": 0,
            "maximum_attempts": attempts,
            "rate_limit_observed": False,
            "lockout_observed": False,
            "human_interaction_observed": True,
            "stop_reason": "Human interaction detected on login page; automated brute-force testing stopped.",
            "automatic_finding": False,
            "finding": False,
            "requires_review": False,
        }
        attempts_data: list[dict[str, Any]] = []
        print("[PASS] Human interaction protection terdeteksi.")
        print("[PASS] Automated brute-force testing dihentikan; challenge tidak dibypass.")
    else:
        selected = discovery.get("selected_form")
        if not selected:
            raise BruteForceError("Login form tidak menyediakan kandidat username/password.")
        summary, attempts_data = perform_failed_attempts(
            target=target,
            username=username,
            login_url=login_url,
            max_attempts=attempts,
            timeout=timeout,
            delay=delay,
        )
        print(f"[INFO] Attempts sent : {summary['attempts_sent']}")
        print(f"[INFO] Rate limit    : {'YES' if summary['rate_limit_observed'] else 'NO'}")
        print(f"[INFO] Lockout       : {'YES' if summary['lockout_observed'] else 'NO'}")
        print(f"[INFO] Human         : {'YES' if summary['human_interaction_observed'] else 'NO'}")

    cves = cve_correlation(context)
    data["results"]["attempts"] = attempts_data
    data["results"]["summary"] = summary
    data["summary"] = {
        "result": summary["result"].lower(),
        "attempts_sent": summary["attempts_sent"],
        "rate_limit_observed": summary["rate_limit_observed"],
        "lockout_observed": summary["lockout_observed"],
        "human_interaction_observed": summary["human_interaction_observed"],
        "finding": False,
        "requires_review": summary["requires_review"],
    }
    data["cve_correlation"] = cves
    data["assessment"] = {
        "result": summary["result"].lower(),
        "finding": False,
        "requires_review": summary["requires_review"],
        "automatic_finding": False,
        "reason": summary["stop_reason"],
    }
    data["evidence"] = {
        "path": "05-authentication/bruteforce/evidence/bruteforce-probes.json",
        "password_logged": False,
        "plaintext_password_persisted": False,
        "csrf_logged": False,
        "session_cookie_logged": False,
    }
    data["generated_at"] = data.get("generated_at") or utc_now()
    data["updated_at"] = utc_now()
    dump_yaml(path, data)

    evidence = {
        "schema_version": SCHEMA_VERSION,
        "project_id": context["project_id"],
        "checklist_id": CHECKLIST_ID,
        "account_id": account["account_id"],
        "target": {
            "hostname": target["hostname"],
            "url": target["url"],
            "scope_id": target["scope_id"],
        },
        "login_discovery": discovery,
        "attempts": attempts_data,
        "summary": summary,
        "security": {
            "password_logged": False,
            "plaintext_password_persisted": False,
            "csrf_logged": False,
            "session_cookie_logged": False,
        },
        "generated_at": utc_now(),
    }
    dump_json(evidence_path, evidence)

    print(f"Assessment result : {summary['result']}")
    print(f"Finding           : FALSE")
    print(f"Requires review   : {'YES' if summary['requires_review'] else 'NO'}")
    print(f"[PASS] Evidence   : {evidence_path}")
    return 0


def cmd_show() -> int:
    context = runtime_context()
    path = artifact_file(context["project_path"])
    if not path.exists():
        print("[INFO] Brute-Force / Rate-Limit Protection belum ada.")
        return 0
    data = load_yaml(path)
    print(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False))
    return 0


def cmd_status() -> int:
    context = runtime_context()
    path = artifact_file(context["project_path"])
    if not path.exists():
        print("[INFO] Status: not initialized")
        return 0
    data = load_yaml(path)
    summary = data.get("summary", {})
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Status    : {data.get('checklist', {}).get('status', 'unknown')}")
    print(f"Result    : {summary.get('result', 'not_tested')}")
    print(f"Attempts  : {summary.get('attempts_sent', 0)}")
    print(f"Human     : {summary.get('human_interaction_observed', False)}")
    print(f"Finding   : {summary.get('finding', False)}")
    return 0


def cmd_list() -> int:
    context = runtime_context()
    path = artifact_file(context["project_path"])
    if not path.exists():
        print("[INFO] Brute-Force / Rate-Limit Protection belum ada.")
        return 0
    data = load_yaml(path)
    summary = data.get("summary", {})
    print(f"{CHECKLIST_ID} | {CHECKLIST_NAME} | {summary.get('result', 'not_tested')}")
    print(f"Account: {data.get('results', {}).get('account_id') or '-'}")
    print(f"Attempts: {summary.get('attempts_sent', 0)}")
    return 0


def cmd_verify() -> int:
    context = runtime_context()
    path = artifact_file(context["project_path"])
    evidence_path = evidence_file(context["project_path"])
    errors: list[str] = []

    if not path.exists():
        errors.append(f"Artifact tidak ditemukan: {path}")
        if errors:
            print("[FAIL] Brute-Force / Rate-Limit Protection belum memenuhi validasi.")
            for error in errors:
                print(f"  - {error}")
            return 1

    try:
        data = load_yaml(path)
    except Exception as exc:
        errors.append(f"Artifact YAML tidak dapat dibaca: {exc}")
        data = {}

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version harus {SCHEMA_VERSION}.")
    if data.get("project_id") != context["project_id"]:
        errors.append("project_id artifact tidak sesuai active project.")
    if data.get("tool", {}).get("version") != SCRIPT_VERSION:
        errors.append(f"tool.version tidak sesuai script. Expected {SCRIPT_VERSION}; Found {data.get('tool', {}).get('version')}")
    if data.get("checklist", {}).get("id") != CHECKLIST_ID:
        errors.append("checklist.id tidak sesuai.")
    if data.get("checklist", {}).get("name") != CHECKLIST_NAME:
        errors.append("checklist.name tidak sesuai.")

    summary = data.get("summary", {})
    assessment = data.get("assessment", {})
    evidence = data.get("evidence", {})
    methodology = data.get("methodology", {})
    probe = data.get("probe", {})
    toolchain = data.get("toolchain", {})

    if methodology.get("human_interaction_policy") != "PASS_AND_STOP_AUTOMATION":
        errors.append("methodology.human_interaction_policy tidak sesuai.")
    if methodology.get("maximum_failed_attempts") != MAX_FAILED_ATTEMPTS:
        errors.append("methodology.maximum_failed_attempts tidak sesuai.")
    if methodology.get("wordlist") is not False:
        errors.append("methodology.wordlist harus false.")
    if methodology.get("password_cracking") is not False:
        errors.append("methodology.password_cracking harus false.")
    if methodology.get("credential_spraying") is not False:
        errors.append("methodology.credential_spraying harus false.")
    if methodology.get("captcha_bypass") is not False:
        errors.append("methodology.captcha_bypass harus false.")
    if probe.get("allow_redirects") is not False:
        errors.append("probe.allow_redirects harus false.")
    if probe.get("human_interaction_stop") is not True:
        errors.append("probe.human_interaction_stop harus true.")
    if assessment.get("automatic_finding") is not False:
        errors.append("assessment.automatic_finding harus false.")
    if assessment.get("finding") is not False:
        errors.append("assessment.finding harus false.")
    if evidence.get("password_logged") is not False:
        errors.append("evidence.password_logged harus false.")
    if evidence.get("plaintext_password_persisted") is not False:
        errors.append("evidence.plaintext_password_persisted harus false.")
    if evidence.get("csrf_logged") is not False:
        errors.append("evidence.csrf_logged harus false.")
    if evidence.get("session_cookie_logged") is not False:
        errors.append("evidence.session_cookie_logged harus false.")

    mandatory = set(toolchain.get("mandatory", [])) if isinstance(toolchain.get("mandatory"), list) else set()
    for item in {"Python", "requests", "PyYAML", "BeautifulSoup", "scripts.context", "scripts.secrets", "accounts.yaml"}:
        if item not in mandatory:
            errors.append(f"toolchain.mandatory missing: {item}")

    attempts = data.get("results", {}).get("attempts", [])
    if not isinstance(attempts, list):
        errors.append("results.attempts harus list.")
    elif len(attempts) > MAX_FAILED_ATTEMPTS:
        errors.append(f"results.attempts melebihi maksimum {MAX_FAILED_ATTEMPTS}.")
    else:
        for item in attempts:
            if item.get("request", {}).get("password_logged") is not False:
                errors.append("Attempt password_logged harus false.")
            if item.get("request", {}).get("csrf_logged") is not False:
                errors.append("Attempt csrf_logged harus false.")
            if item.get("plaintext_password_persisted") is not False:
                errors.append("Attempt plaintext_password_persisted harus false.")

    if not evidence_path.exists():
        errors.append(f"Evidence tidak ditemukan: {evidence_path}")
    else:
        try:
            evidence_data = load_yaml(evidence_path) if evidence_path.suffix in {".yaml", ".yml"} else json.loads(evidence_path.read_text(encoding="utf-8"))
            if evidence_data.get("project_id") != context["project_id"]:
                errors.append("Evidence project_id tidak sesuai.")
            security = evidence_data.get("security", {})
            for key in ("password_logged", "plaintext_password_persisted", "csrf_logged", "session_cookie_logged"):
                if security.get(key) is not False:
                    errors.append(f"Evidence security.{key} harus false.")
        except Exception as exc:
            errors.append(f"Evidence tidak dapat divalidasi: {exc}")

    if errors:
        print("[FAIL] Brute-Force / Rate-Limit Protection belum memenuhi validasi.")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("[PASS] Brute-Force / Rate-Limit Protection memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {context['project_id']}")
    print(f"[PASS] File      : {path}")
    print(f"[PASS] Probes    : {len(attempts)}")
    print("[PASS] Encoding  : UTF-8 tanpa BOM")
    return 0


def cmd_remove() -> int:
    import shutil

    context = runtime_context()
    path = artifact_dir(context["project_path"])
    if not path.exists():
        print("[INFO] Brute-Force / Rate-Limit Protection belum ada.")
        return 0
    confirm = input("Hapus seluruh data Brute-Force / Rate-Limit Protection untuk project aktif? [y/N]: ").strip().lower()
    if confirm != "y":
        print("[INFO] Dibatalkan.")
        return 0
    shutil.rmtree(path)
    print("[PASS] Brute-Force / Rate-Limit Protection berhasil dihapus.")
    return 0


def print_help() -> None:
    print(
        "BrebesKab-CSIRT-Tools - Brute-Force / Rate-Limit Protection\n\n"
        "Checklist:\n"
        "  5-006 Brute-Force / Rate-Limit Protection\n\n"
        "Usage:\n"
        "  python scripts/authentication/bruteforce.py version\n"
        "  python scripts/authentication/bruteforce.py init\n"
        "  python scripts/authentication/bruteforce.py analyze --account-id TA-002\n"
        "  python scripts/authentication/bruteforce.py analyze --account-id TA-002 --failed-attempts 5 --delay 1\n"
        "  python scripts/authentication/bruteforce.py list\n"
        "  python scripts/authentication/bruteforce.py show\n"
        "  python scripts/authentication/bruteforce.py status\n"
        "  python scripts/authentication/bruteforce.py verify\n"
        "  python scripts/authentication/bruteforce.py remove\n\n"
        "Safety:\n"
        "  - Maximum 5 failed attempts.\n"
        "  - One active authorized account only.\n"
        "  - One generated invalid password; no wordlist/cracking/spraying.\n"
        "  - Redirects disabled.\n"
        "  - Turnstile/CAPTCHA/human interaction => PASS and stop.\n"
        "  - No CAPTCHA bypass or lockout escalation.\n"
        "  - Password, CSRF, and session values are never persisted.\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "command",
        nargs="?",
        default="help",
        choices=("version", "init", "analyze", "list", "show", "status", "verify", "remove", "help"),
    )
    parser.add_argument("--account-id", dest="account_id", default=None)
    parser.add_argument("--failed-attempts", dest="failed_attempts", type=int, default=DEFAULT_FAILED_ATTEMPTS)
    parser.add_argument("--timeout", dest="timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--delay", dest="delay", type=float, default=DEFAULT_DELAY_SECONDS)
    args = parser.parse_args(argv)

    try:
        if args.command == "help":
            print_help()
            return 0
        if args.command == "version":
            return cmd_version()
        if args.command == "init":
            return cmd_init()
        if args.command == "analyze":
            return cmd_analyze(args.account_id, args.failed_attempts, args.timeout, args.delay)
        if args.command == "list":
            return cmd_list()
        if args.command == "show":
            return cmd_show()
        if args.command == "status":
            return cmd_status()
        if args.command == "verify":
            return cmd_verify()
        if args.command == "remove":
            return cmd_remove()
        raise BruteForceError(f"Command tidak dikenal: {args.command}")
    except (BruteForceError, FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}")
        return 1
    except requests.RequestException as exc:
        print(f"[ERROR] HTTP request gagal: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
