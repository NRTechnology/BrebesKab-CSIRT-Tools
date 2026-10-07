#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BrebesKab-CSIRT-Tools
Checklist 7-005 - Expression / Template / Parser Injection
Version 1.0.7

GET-only, same-origin, authenticated, non-destructive.
Does NOT test SQLi, XSS, command injection, or path traversal.
Reflection/HTTP 500/parser errors are forensic signals, not automatic findings.
Automatic finding requires strong evidence of server-side expression evaluation.
Newly observed arithmetic signals that are not strong enough remain manual-review notes.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
import yaml

SCRIPT_VERSION = "1.0.7"
SCHEMA_VERSION = "1.0"
CHECKLIST_ID = "7-005"
CHECKLIST_NAME = "Expression / Template / Parser Injection"
SCRIPT_NAME = "BrebesKab-CSIRT-Tools Expression/Template/Parser Injection"

ROOT = Path(__file__).resolve().parents[2]
PROJECTS = ROOT / "projects"

REQUEST_TIMEOUT = 20
REQUEST_DELAY_MS = 150
MAX_DEPTH = 5
MAX_CANDIDATES = 200
MAX_PARAMS_PER_URL = 5
MAX_BODY_SAMPLE = 12000
MAX_CONTEXTS = 10
USER_AGENT = f"BrebesKab-CSIRT-Tools/{SCRIPT_VERSION}"

# Safe probes only. No shell, file, network, SQL, XSS, or destructive payloads.
PAYLOADS = [
    {
        "id": "expr-curly-49",
        "category": "expression",
        "payload": "{{7*7}}",
        "purpose": "Detect simple server-side template/expression evaluation.",
        "expected": "49",
    },
    {
        "id": "expr-dollar-49",
        "category": "expression",
        "payload": "${7*7}",
        "purpose": "Detect common expression-language interpolation.",
        "expected": "49",
    },
    {
        "id": "template-curly-token",
        "category": "template",
        "payload": "{{BREBESINJ_TOKEN}}",
        "purpose": "Detect template parsing/evaluation context.",
        "expected": None,
    },
    {
        "id": "template-dollar-token",
        "category": "template",
        "payload": "${BREBESINJ_TOKEN}",
        "purpose": "Detect expression/template interpolation context.",
        "expected": None,
    },
    {
        "id": "template-percent-token",
        "category": "template",
        "payload": "<%=BREBESINJ_TOKEN%>",
        "purpose": "Detect legacy/template interpolation context.",
        "expected": None,
    },
    {
        "id": "parser-curly-malformed",
        "category": "parser",
        "payload": "{{19*}}",
        "purpose": "Trigger controlled parser/template syntax handling.",
        "expected": None,
    },
]

PARSER_PATTERNS = [
    r"\bsyntax\s+error\b",
    r"\bparse\s+error\b",
    r"\bparser\s+error\b",
    r"\bunexpected\s+(?:token|character|end|identifier|symbol)\b",
    r"\binvalid\s+(?:expression|template|syntax|filter)\b",
    r"\btemplate\s+(?:error|exception)\b",
    r"\bexpression\s+(?:error|exception)\b",
    r"\btemplateexception\b",
    r"\bexpressionlanguage\b",
    r"\bjinja2?\b",
    r"\btwig\b",
    r"\bfreemarker\b",
    r"\bthymeleaf\b",
    r"\bvelocity\b",
    r"\bhandlebars\b",
]
CHALLENGE_MARKERS = ("captcha", "recaptcha", "turnstile", "cf-chl", "challenge-platform")
STRONG_CHALLENGE_HEADERS = ("cf-mitigated", "x-captcha", "x-challenge")


def now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def sample(value: Any, limit: int = MAX_BODY_SAMPLE) -> str:
    s = str(value or "")
    return s if len(s) <= limit else s[:limit] + "\n...[truncated]..."


def yaml_load(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML tidak valid: {path}")
    return data


def save_yaml(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def artifact_path(project: str) -> Path:
    return PROJECTS / project / "07-input-validation" / "injection" / "injection.yaml"


def evidence_path(project: str) -> Path:
    return PROJECTS / project / "07-input-validation" / "injection" / "evidence" / "injection-probes.json"


def find_project() -> str:
    for p in PROJECTS.glob("*/01-preparation/scope/scope.yaml"):
        try:
            d = yaml_load(p)
            section = d.get("scope", d)
            for item in section.get("in_scope", []):
                if isinstance(item, dict) and item.get("scope_id") == "IN-001":
                    return p.parts[-4]
        except Exception:
            pass
    for p in PROJECTS.glob("*/05-authentication/session/session.yaml"):
        return p.parts[-4]
    raise RuntimeError("Project ID tidak ditemukan.")


def scope(project: str) -> Dict[str, Any]:
    path = PROJECTS / project / "01-preparation" / "scope" / "scope.yaml"
    if not path.exists():
        raise FileNotFoundError(f"scope.yaml tidak ditemukan: {path}")
    d = yaml_load(path)
    section = d.get("scope", d)
    entries = section.get("in_scope", [])
    item = next((x for x in entries if isinstance(x, dict) and x.get("scope_id") == "IN-001"), None)
    if item is None:
        raise ValueError("Scope IN-001 tidak ditemukan.")
    value = item.get("value") or item.get("hostname") or item.get("url")
    typ = str(item.get("type", "")).lower()
    ports = item.get("ports") or [80, 443]
    if typ not in ("domain", "hostname", "url") or not value:
        raise ValueError("Scope IN-001 harus berupa domain/hostname/url.")
    base = str(value).rstrip("/") if typ == "url" else f"https://{str(value).strip('/')}"
    u = urlparse(base)
    if u.scheme not in ("http", "https") or not u.netloc:
        raise ValueError(f"URL scope tidak valid: {base}")
    return {
        "scope_id": "IN-001",
        "type": typ,
        "value": str(value),
        "hostname": u.hostname,
        "url": base,
        "ports": ports,
        "source": str(path),
    }


def session(project: str) -> requests.Session:
    path = PROJECTS / project / "05-authentication" / "session" / "session.yaml"
    if not path.exists():
        raise FileNotFoundError(f"session.yaml tidak ditemukan: {path}")
    d = yaml_load(path)
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    headers = d.get("headers")
    if isinstance(headers, dict):
        for k, v in headers.items():
            if v is not None:
                s.headers[str(k)] = str(v)

    cookies = d.get("cookies")
    if isinstance(cookies, dict):
        for k, v in cookies.items():
            s.cookies.set(str(k), str(v))
    elif isinstance(cookies, list):
        for c in cookies:
            if isinstance(c, dict) and c.get("name") is not None:
                s.cookies.set(str(c["name"]), str(c.get("value", "")))

    cookie_header = d.get("cookie_header") or d.get("cookie")
    if isinstance(cookie_header, str) and cookie_header.strip():
        s.headers["Cookie"] = cookie_header.strip()
    return s


def same_origin(a: str, b: str) -> bool:
    x, y = urlparse(a), urlparse(b)
    return x.scheme.lower() == y.scheme.lower() and x.netloc.lower() == y.netloc.lower()


def normalize(url: str) -> str:
    u = urlparse(url)
    return urlunparse((u.scheme.lower(), u.netloc.lower(), u.path or "/", "", u.query, ""))


def replace_param(url: str, name: str, value: str) -> str:
    u = urlparse(url)
    pairs = parse_qsl(u.query, keep_blank_values=True)
    out, found = [], False
    for k, v in pairs:
        if k == name and not found:
            out.append((k, value))
            found = True
        else:
            out.append((k, v))
    if not found:
        out.append((name, value))
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(out, doseq=True), ""))


def hrefs(body: str, base: str) -> List[str]:
    result = []
    for m in re.finditer(r"""(?is)<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["']""", body):
        h = m.group(1).strip()
        if h and not h.startswith(("#", "javascript:", "mailto:", "tel:")):
            result.append(urljoin(base, h))
    return result


def get_forms(body: str, base: str) -> List[Dict[str, Any]]:
    result = []
    for fm in re.finditer(r"(?is)<form\b([^>]*)>(.*?)</form>", body):
        attrs, content = fm.group(1), fm.group(2)
        mm = re.search(r"""(?i)\bmethod\s*=\s*["']([^"']+)["']""", attrs)
        am = re.search(r"""(?i)\baction\s*=\s*["']([^"']*)["']""", attrs)
        if (mm.group(1).upper() if mm else "GET") != "GET":
            continue
        action = urljoin(base, am.group(1).strip() if am else base)
        params = []
        for im in re.finditer(r"(?is)<input\b([^>]*)>", content):
            ia = im.group(1)
            nm = re.search(r"""(?i)\bname\s*=\s*["']([^"']+)["']""", ia)
            if not nm:
                continue
            vm = re.search(r"""(?i)\bvalue\s*=\s*["']([^"']*)["']""", ia)
            params.append({"name": nm.group(1), "value": vm.group(1) if vm else ""})
        if params:
            result.append({"url": normalize(action), "method": "GET", "params": params[:MAX_PARAMS_PER_URL]})
    return result


def score(name: str, value: str) -> int:
    n = name.lower()
    high = {"query", "q", "search", "keyword", "filter", "where", "expression",
            "template", "view", "format", "type", "name", "id", "value",
            "input", "condition", "resource", "theme", "option", "mode"}
    medium = {"page", "sort", "order", "category", "slug", "title", "code", "key", "data", "content"}
    return (30 if n in high else 15 if n in medium else 0) + min(len(value), 20) + (
        15 if any(x in n for x in ("search", "query", "filter", "template", "expr")) else 0
    )


def crawl(s: requests.Session, base: str) -> Tuple[List[str], List[Dict[str, Any]], List[Dict[str, Any]]]:
    queue = [(base, 0)]
    visited = set()
    links = []
    forms = []
    candidates = {}

    while queue:
        url, depth = queue.pop(0)
        url = normalize(url)
        if url in visited or depth > MAX_DEPTH or not same_origin(base, url):
            continue
        visited.add(url)
        try:
            r = s.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        links.append(url)

        for link in hrefs(r.text, url):
            link = normalize(link)

            # External links may be recorded as discovered links, but they
            # must never become probe candidates. The checklist is strictly
            # same-origin and must not send authenticated probes to external
            # destinations.
            if not same_origin(base, link):
                continue

            if link not in visited:
                queue.append((link, depth + 1))

            q = parse_qsl(urlparse(link).query, keep_blank_values=True)
            for name, value in q[:MAX_PARAMS_PER_URL]:
                endpoint = urlunparse((urlparse(link).scheme, urlparse(link).netloc,
                                       urlparse(link).path or "/", "", "", ""))
                key = (endpoint, name)
                candidates[key] = {
                    "url": link, "method": "GET", "parameter": name,
                    "original_value": value, "source": "query",
                    "score": score(name, value), "depth": depth,
                }

        fs = get_forms(r.text, url)
        forms.extend(fs)
        for form in fs:
            for p in form["params"]:
                key = (form["url"], p["name"])
                candidates[key] = {
                    "url": form["url"], "method": "GET", "parameter": p["name"],
                    "original_value": p["value"], "source": "get_form",
                    "score": score(p["name"], p["value"]), "depth": depth,
                }

    ordered = sorted(candidates.values(), key=lambda x: (-x["score"], x["url"], x["parameter"]))
    return links, ordered[:MAX_CANDIDATES], forms


def snapshot(r: requests.Response) -> Dict[str, Any]:
    body = r.text or ""
    headers = {str(k).lower(): str(v) for k, v in list(r.headers.items())[:80]}
    return {
        "status": r.status_code,
        "reason": r.reason,
        "url": r.url,
        "content_type": r.headers.get("Content-Type", ""),
        "body_length": len(body),
        "body_hash": sha(body),
        "body_sample": sample(body),
        "headers": headers,
    }


def challenge(r: requests.Response, baseline_markers: List[str] | None = None) -> Dict[str, Any]:
    text = (r.text or "").lower()
    markers = sorted({m for m in CHALLENGE_MARKERS if m in text})
    base = set(baseline_markers or [])
    new = sorted(set(markers) - base)
    strong_headers = [h for h in STRONG_CHALLENGE_HEADERS if r.headers.get(h)]
    status_signal = r.status_code in (403, 429)
    detected = bool(strong_headers or (status_signal and new))
    return {
        "challenge_detected": detected,
        "challenge_markers": markers,
        "baseline_challenge_markers": sorted(base),
        "new_challenge_markers": new,
        "challenge_header_signal": bool(strong_headers),
        "challenge_header_names": strong_headers,
        "challenge_status_signal": status_signal,
    }


def parser_errors(body: str) -> List[str]:
    return sorted({p for p in PARSER_PATTERNS if re.search(p, body or "", re.I)})


def contexts(body: str, token: str) -> List[str]:
    result, start = [], 0
    while len(result) < MAX_CONTEXTS:
        i = body.find(token, start)
        if i < 0:
            break
        result.append(body[max(0, i - 180):min(len(body), i + len(token) + 180)])
        start = i + max(len(token), 1)
    return result


def evaluation_contexts(body: str, expected: str | None) -> List[str]:
    """Return bounded contexts around the expected evaluation marker."""
    if not expected:
        return []
    return contexts(body, expected)


def parameter_contexts(
    contexts_found: List[str],
    parameter: str,
) -> List[str]:
    """
    Keep only response contexts that are structurally tied to the parameter
    currently being tested.

    A numeric result found elsewhere in the response is intentionally not
    allowed to become automatic expression-evaluation evidence. This removes
    the previous out-of-context detector behavior while preserving the raw
    arithmetic signal for manual review.

    The context must contain a direct HTML/DOM-style reference to the tested
    parameter, such as:
      name="keyword"
      id="keyword"
      data-keyword="..."
      name='keyword'
    """
    if not parameter:
        return []

    p = re.escape(str(parameter))
    patterns = (
        rf'\bname\s*=\s*["\']{p}["\']',
        rf'\bid\s*=\s*["\'][^"\']*\b{p}\b[^"\']*["\']',
        rf'\bdata-{p}\b',
        rf'\bdata-[a-z0-9_-]+\s*=\s*["\'][^"\']*\b{p}\b[^"\']*["\']',
    )

    result = []
    for context in contexts_found:
        c = context or ""
        if any(re.search(pattern, c, re.I) for pattern in patterns):
            result.append(c)

    return result


def protected_parameter(parameter: str) -> bool:
    """
    Parameters that are normally security/session/instrumentation values are
    never treated as automatic expression-evaluation context.

    Their arithmetic signals are still preserved as forensic/manual-review
    notes.
    """
    n = (parameter or "").lower()
    protected_tokens = (
        "csrf",
        "token",
        "nonce",
        "session",
        "cookie",
        "signature",
        "sig",
        "hash",
        "auth",
    )
    return any(token in n for token in protected_tokens)


def strong_expression_evidence(
    body: str,
    baseline_body: str,
    payload: str,
    expected: str | None,
    status: int,
    parameter: str = "",
) -> Dict[str, Any]:
    """
    Conservative automatic-evaluation detector.

    IMPORTANT:
    A newly introduced arithmetic result such as "49" is preserved as a
    forensic signal, but a result found elsewhere in the response is NOT
    allowed to become a finding.

    Automatic expression-evaluation evidence requires the expected result to
    appear inside a response context structurally tied to the parameter being
    tested. Generic page-wide occurrences, CSRF/session/token values,
    Debugbar/Kint output, timestamps, counters, and unrelated response
    content remain manual-review signals only.

    Existing payloads, crawl behavior, request behavior, and evidence are
    intentionally preserved. This function only narrows the assessment of
    arithmetic evaluation signals.
    """
    expected_present = bool(expected and expected in body)
    baseline_has_expected = bool(expected and expected in (baseline_body or ""))
    payload_present = bool(payload and payload in body)
    non_error_status = status < 400

    contexts_found = evaluation_contexts(body, expected)
    contextual_contexts = parameter_contexts(contexts_found, parameter)
    out_of_context_contexts = [
        ctx for ctx in contexts_found if ctx not in contextual_contexts
    ]

    protected = protected_parameter(parameter)

    # Preserve the arithmetic signal for forensic/manual review, but do not
    # promote it to a finding merely because the expected number appeared
    # somewhere in a successful response.
    evaluation_signal = bool(
        expected_present
        and not baseline_has_expected
        and not payload_present
        and non_error_status
    )

    # Automatic finding is now strictly context-bound.
    # Security/session/token parameters are explicitly excluded from automatic
    # evaluation even if their name happens to occur near the expected value.
    contextual_evidence = bool(
        evaluation_signal
        and contextual_contexts
        and not protected
    )

    manual_review = bool(evaluation_signal and not contextual_evidence)

    if manual_review:
        if protected:
            manual_reason = (
                "Expected arithmetic result was newly introduced, but the "
                "tested parameter is a security/session/token-style parameter; "
                "automatic evaluation is disabled and manual verification is required."
            )
        elif not contextual_contexts:
            manual_reason = (
                "Expected arithmetic result was newly introduced, but no response "
                "context structurally tied to the tested parameter was found; "
                "the arithmetic signal is preserved for manual verification."
            )
        else:
            manual_reason = (
                "Expected arithmetic result was newly introduced, but the "
                "context does not satisfy automatic evaluation requirements; "
                "inspect the exact response location manually."
            )
    else:
        manual_reason = None

    return {
        "strong_evaluation_evidence": contextual_evidence,
        "evaluation_signal": evaluation_signal,
        "expected_result_present": expected_present,
        "expected_result_in_baseline": baseline_has_expected,
        "payload_absent_in_response": not payload_present,
        "non_error_status": non_error_status,
        "evaluation_contexts": contexts_found,
        "contextual_evaluation_contexts": contextual_contexts,
        "out_of_context_evaluation_contexts": out_of_context_contexts,
        "protected_parameter_context": protected,
        "evaluation_requires_manual_review": manual_review,
        "manual_review_reason": manual_reason,
    }


def baseline(s: requests.Session, c: Dict[str, Any]) -> Dict[str, Any]:
    url = replace_param(c["url"], c["parameter"], c["original_value"])
    t = time.perf_counter()
    try:
        r = s.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        elapsed = round((time.perf_counter() - t) * 1000, 2)
        snap = snapshot(r)
        ch = challenge(r)
        return {
            "request": {"method": "GET", "url": url, "parameter": c["parameter"], "value": c["original_value"]},
            "response": snap, "elapsed_ms": elapsed,
            "challenge_markers": ch["challenge_markers"], "request_error": None,
        }
    except requests.RequestException as e:
        return {
            "request": {"method": "GET", "url": url, "parameter": c["parameter"], "value": c["original_value"]},
            "response": None, "elapsed_ms": round((time.perf_counter() - t) * 1000, 2),
            "challenge_markers": [], "request_error": str(e),
        }


def assess(r: requests.Response, elapsed: float, p: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    body = r.text or ""
    snap = snapshot(r)
    br = b.get("response") or {}
    errors = parser_errors(body)
    ch = challenge(r, b.get("challenge_markers", []))
    reflected = p["payload"] in body
    expected = p.get("expected")
    baseline_body = br.get("body_sample", "") or ""

    # Only the two known arithmetic probes can produce an automatic finding.
    # A bare "49" anywhere in the response is NOT sufficient: debug/error
    # pages can contain unrelated occurrences of the same value.
    evaluation = strong_expression_evidence(
        body=body,
        baseline_body=baseline_body,
        payload=p["payload"],
        expected=expected if p["id"] in {"expr-curly-49", "expr-dollar-49"} else None,
        status=r.status_code,
        parameter=p.get("_parameter", ""),
    )
    evaluated = evaluation["strong_evaluation_evidence"]

    status_changed = br.get("status") is not None and r.status_code != br["status"]
    body_changed = br.get("body_hash") is not None and snap["body_hash"] != br["body_hash"]
    finding = evaluated
    review = bool(
        reflected
        or errors
        or status_changed
        or body_changed
        or ch["challenge_detected"]
        or r.status_code >= 500
        or evaluation["evaluation_requires_manual_review"]
    )

    return {
        "payload_id": p["id"], "category": p["category"], "payload": p["payload"],
        "purpose": p["purpose"], "request": {"method": "GET"},
        "response": snap, "elapsed_ms": elapsed,
        "signals": {
            "payload_reflected": reflected,
            "expression_evaluated": evaluated,
            "evaluation_marker": expected if evaluation["evaluation_signal"] else None,
            **evaluation,
            "parser_error": bool(errors),
            "parser_error_signatures": errors,
            **ch,
            "status_changed": status_changed,
            "body_changed": body_changed,
            "http_error": r.status_code >= 400,
        },
        "evidence": {
            "reflection_contexts": contexts(body, p["payload"]),
            "evaluation_contexts": evaluation["evaluation_contexts"],
            "out_of_context_evaluation_contexts": evaluation["out_of_context_evaluation_contexts"],
            "contextual_evaluation_contexts": evaluation["contextual_evaluation_contexts"],
            "baseline_status": br.get("status"),
            "baseline_body_hash": br.get("body_hash"),
            "baseline_body_sample": sample(br.get("body_sample", "")),
            "response_body_hash": snap["body_hash"],
            "response_body_sample": snap["body_sample"],
        },
        "assessment": {
            "finding": finding,
            "requires_review": review,
            "confidence": "high" if finding else "review" if review else "none",
            "reason": (
                "Strong evidence of server-side expression evaluation."
                if finding else
                evaluation["manual_review_reason"]
                if evaluation["evaluation_requires_manual_review"] else
                "Forensic signal preserved for manual review."
                if review else
                "No relevant injection signal."
            ),
            "manual_review": {
                "required": bool(evaluation["evaluation_requires_manual_review"]),
                "reason": evaluation["manual_review_reason"],
            },
        },
    }


def analyze_candidate(s: requests.Session, c: Dict[str, Any]) -> Dict[str, Any]:
    b = baseline(s, c)
    record = {"candidate": c, "baseline": b, "probes": []}
    if b["request_error"]:
        record["candidate_assessment"] = {
            "finding": False, "requires_review": True,
            "reason": "Baseline request failed."
        }
        return record

    for i, p in enumerate(PAYLOADS):
        if i:
            time.sleep(REQUEST_DELAY_MS / 1000)
        url = replace_param(c["url"], c["parameter"], p["payload"])
        t = time.perf_counter()
        try:
            r = s.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            elapsed = round((time.perf_counter() - t) * 1000, 2)
            p_probe = dict(p)
            p_probe["_parameter"] = c["parameter"]
            item = assess(r, elapsed, p_probe, b)
            item["request"].update({
                "url": url,
                "parameter": c["parameter"],
                "original_value": c["original_value"],
            })
        except requests.RequestException as e:
            item = {
                "payload_id": p["id"], "category": p["category"], "payload": p["payload"],
                "purpose": p["purpose"],
                "request": {"method": "GET", "url": url, "parameter": c["parameter"],
                            "original_value": c["original_value"]},
                "response": None, "elapsed_ms": round((time.perf_counter() - t) * 1000, 2),
                "signals": {
                    "payload_reflected": False, "expression_evaluated": False,
                    "evaluation_marker": None, "parser_error": False,
                    "parser_error_signatures": [], "challenge_detected": False,
                    "challenge_markers": [], "baseline_challenge_markers": b.get("challenge_markers", []),
                    "new_challenge_markers": [], "challenge_header_signal": False,
                    "challenge_header_names": [], "challenge_status_signal": False,
                    "status_changed": False, "body_changed": False, "http_error": False,
                },
                "evidence": {"reflection_contexts": [], "error": str(e)},
                "assessment": {
                    "finding": False, "requires_review": True,
                    "confidence": "review", "reason": "Request error preserved for review."
                },
            }
        record["probes"].append(item)

    record["candidate_assessment"] = {
        "finding": any(x["assessment"]["finding"] for x in record["probes"]),
        "requires_review": any(x["assessment"]["requires_review"] for x in record["probes"]),
    }
    return record


def artifact(project: str, sc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "script": {
            "name": SCRIPT_NAME, "version": SCRIPT_VERSION,
            "checklist_id": CHECKLIST_ID, "checklist": CHECKLIST_NAME,
        },
        "project": {"project_id": project},
        "target": {
            "scope_id": sc["scope_id"], "hostname": sc["hostname"],
            "url": sc["url"], "environment": "Production",
            "mode": "Black Box", "ports": sc["ports"],
        },
        "methodology": {
            "description": "Same-origin crawl and bounded non-destructive GET probes for expression/template/parser injection using the existing authenticated session.",
            "authentication": "Authenticated session from session.yaml",
            "same_origin_only": True, "redirect_following": False,
            "http_methods": ["GET"], "automatic_finding": True,
            "reflection_is_finding": False, "http_500_is_finding": False,
            "parser_error_is_finding": False,
            "challenge_requires_strong_signal": True,
            "challenge_marker_alone_is_not_stop": True,
            "strong_evaluation_required": True,
            "arithmetic_result_alone_is_not_evidence": True,
            "reflected_arithmetic_payload_is_not_evidence": True,
            "http_error_cannot_confirm_evaluation": True,
            "arithmetic_result_context_required": True,
            "arithmetic_signal_preserved_for_manual_review": True,
            "evaluation_requires_parameter_context": True,
            "security_token_context_is_not_automatic_evidence": True,
            "no_command_execution": True, "no_sql_injection": True,
            "no_xss": True, "no_path_traversal": True,
            "no_file_read_write_delete": True, "no_upload": True,
            "no_reverse_shell": True, "no_external_callbacks": True,
            "no_credential_harvesting": True, "forensic_evidence_preserved": True,
        },
        "toolchain": {
            "language": "Python",
            "libraries": ["requests", "PyYAML", "urllib.parse", "hashlib", "re", "argparse"],
            "external_scanners": [], "nmap": False, "ffuf": False,
            "sqlmap": False, "commix": False,
        },
        "payload_policy": {
            "categories": ["expression", "template", "parser"],
            "payloads": [{k: v for k, v in p.items() if k != "expected"} for p in PAYLOADS],
            "delay_ms": REQUEST_DELAY_MS,
        },
        "crawler": {
            "max_depth": MAX_DEPTH, "max_candidates": MAX_CANDIDATES,
            "max_params_per_url": MAX_PARAMS_PER_URL,
        },
        "results": {
            "status": "initialized", "started_at": None, "completed_at": None,
            "links": 0, "query_candidates": 0, "get_forms": 0,
            "candidates": 0, "tested": 0, "probes": 0, "reflected": 0,
            "evaluation_signals": 0, "evaluation_manual_review": 0, "parser_errors": 0, "challenge": 0,
            "http_errors": 0, "request_errors": 0, "findings": 0,
            "requires_review": 0,
        },
        "candidates": [],
        "notes": [
            "Reflection is forensic evidence, not a finding.",
            "HTTP 500 is forensic evidence, not a finding.",
            "Generic parser/template errors require manual verification.",
            "Automatic finding requires strong evidence of server-side expression evaluation.",
            "A bare arithmetic result such as 49 is not evidence of evaluation.",
            "A reflected arithmetic payload is not evidence of evaluation.",
            "HTTP 4xx/5xx responses cannot confirm automatic expression evaluation.",
            "Evaluation requires the expected result to be newly introduced, the payload to be absent, and a non-error response.",
            "A newly introduced arithmetic result is preserved as an evaluation signal even when it is downgraded from finding to manual review.",
            "Arithmetic results found outside the tested parameter context are not automatic findings.",
            "Security/session/token-style parameters are not automatic expression-evaluation contexts.",
            "When an arithmetic evaluation signal is downgraded, its response contexts and manual-review reason remain in evidence.",
            "The detector intentionally favors false negatives over false positives.",
            "Generic CAPTCHA/reCAPTCHA/Turnstile markers alone do not stop probing.",
            "Only non-destructive expression/template/parser probes are used.",
            "SQLi, XSS, Command Injection, and Path Traversal are covered by separate checklists.",
            "External links are not probe candidates and are never tested.",
        ],
        "created_at": now(), "updated_at": now(),
    }


def cmd_version(_):
    print(SCRIPT_NAME)
    print(f"Version   : {SCRIPT_VERSION}")
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Schema    : {SCHEMA_VERSION}")
    return 0


def cmd_init(a):
    project = a.project or find_project()
    sc = scope(project)
    path = artifact_path(project)
    save_yaml(path, artifact(project, sc))
    print("[PASS] Injection artifact siap.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {project}")
    print(f"[PASS] File      : {path}")
    return 0


def cmd_crawl(a):
    project = a.project or find_project()
    path = artifact_path(project)
    art = yaml_load(path)
    s = session(project)
    links, candidates, forms = crawl(s, art["target"]["url"])
    art["candidates"] = candidates
    art["crawl"] = {"links": links, "get_forms": forms}
    art["results"].update({
        "status": "crawled", "links": len(links),
        "query_candidates": sum(c["source"] == "query" for c in candidates),
        "get_forms": len(forms), "candidates": len(candidates),
    })
    art["updated_at"] = now()
    save_yaml(path, art)
    print("[PASS] Injection crawl selesai.")
    print(f"[PASS] Links     : {len(links)}")
    print(f"[PASS] Query candidates: {art['results']['query_candidates']}")
    print(f"[PASS] GET forms : {len(forms)}")
    print(f"[PASS] Candidates: {len(candidates)}")
    print(f"[PASS] File      : {path}")
    return 0


def cmd_analyze(a):
    project = a.project or find_project()
    path = artifact_path(project)
    art = yaml_load(path)
    candidates = art.get("candidates", [])
    if not candidates:
        print("[FAIL] Candidates kosong. Jalankan crawl terlebih dahulu.")
        return 1

    s = session(project)
    started = now()
    records = [analyze_candidate(s, c) for c in candidates]
    probes = [p for r in records for p in r["probes"]]

    ev = {
        "schema_version": SCHEMA_VERSION,
        "script": {"name": SCRIPT_NAME, "version": SCRIPT_VERSION, "checklist_id": CHECKLIST_ID},
        "project_id": project,
        "target": {k: art["target"][k] for k in ("scope_id", "hostname", "url")},
        "methodology": {
            "http_methods": ["GET"], "same_origin_only": True,
            "redirect_following": False, "authenticated_session": True,
            "non_destructive": True, "reflection_is_finding": False,
            "http_500_is_finding": False, "parser_error_is_finding": False,
            "challenge_marker_alone_is_stop": False, "strong_evaluation_required": True,
            "arithmetic_result_alone_is_not_evidence": True,
            "reflected_arithmetic_payload_is_not_evidence": True,
            "http_error_cannot_confirm_evaluation": True,
            "arithmetic_result_context_required": True,
            "arithmetic_signal_preserved_for_manual_review": True,
            "evaluation_requires_parameter_context": True,
            "security_token_context_is_not_automatic_evidence": True,
        },
        "payloads": [{k: v for k, v in p.items() if k != "expected"} for p in PAYLOADS],
        "probe_records": records, "generated_at": now(),
    }
    ep = evidence_path(project)
    save_json(ep, ev)

    art["results"].update({
        "status": "completed", "started_at": started, "completed_at": now(),
        "tested": len(records), "probes": len(probes),
        "reflected": sum(p["signals"].get("payload_reflected", False) for p in probes),
        "evaluation_signals": sum(p["signals"].get("expression_evaluated", False) for p in probes),
        "evaluation_manual_review": sum(p["signals"].get("evaluation_requires_manual_review", False) for p in probes),
        "parser_errors": sum(p["signals"].get("parser_error", False) for p in probes),
        "challenge": sum(p["signals"].get("challenge_detected", False) for p in probes),
        "http_errors": sum(p["signals"].get("http_error", False) for p in probes),
        "request_errors": sum(not bool(p.get("response")) for p in probes),
        "findings": sum(p["assessment"].get("finding", False) for p in probes),
        "requires_review": sum(p["assessment"].get("requires_review", False) for p in probes),
    })
    art["evidence"] = {"file": str(ep), "records": len(records)}
    art["updated_at"] = now()
    save_yaml(path, art)

    print("[PASS] Injection analyze selesai.")
    print(f"[PASS] Candidates: {art['results']['candidates']}")
    print(f"[PASS] Tested    : {art['results']['tested']}")
    print(f"[PASS] Probes    : {art['results']['probes']}")
    print(f"[PASS] Reflected : {art['results']['reflected']}")
    print(f"[PASS] Evaluated : {art['results']['evaluation_signals']}")
    print(f"[PASS] Eval review: {art['results']['evaluation_manual_review']}")
    print(f"[PASS] Parser err: {art['results']['parser_errors']}")
    print(f"[PASS] Challenge : {art['results']['challenge']}")
    print(f"[PASS] HTTP error: {art['results']['http_errors']}")
    print(f"[PASS] Findings  : {art['results']['findings']}")
    print(f"[PASS] Review    : {art['results']['requires_review']}")
    print(f"[PASS] Evidence  : {ep}")
    return 0


def cmd_show(a):
    project = a.project or find_project()
    print(yaml.safe_dump(yaml_load(artifact_path(project)), allow_unicode=True, sort_keys=False))
    return 0


def cmd_status(a):
    project = a.project or find_project()
    r = yaml_load(artifact_path(project)).get("results", {})
    print(f"Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"Version   : {SCRIPT_VERSION}")
    print(f"Project   : {project}")
    print(f"Status    : {r.get('status')}")
    print(f"Candidates: {r.get('candidates', 0)}")
    print(f"Probes    : {r.get('probes', 0)}")
    print(f"Findings  : {r.get('findings', 0)}")
    print(f"Review    : {r.get('requires_review', 0)}")
    return 0


def utf8_no_bom(path: Path) -> bool:
    raw = path.read_bytes()
    return not raw.startswith(b"\xef\xbb\xbf") and bool(raw.decode("utf-8"))


def cmd_verify(a):
    project = a.project or find_project()
    path = artifact_path(project)
    errors = []
    if not path.exists():
        errors.append(f"Artifact tidak ditemukan: {path}")
    else:
        try:
            if not utf8_no_bom(path):
                errors.append("Artifact bukan UTF-8 tanpa BOM.")
            art = yaml_load(path)
            if art.get("schema_version") != SCHEMA_VERSION:
                errors.append("Schema version tidak sesuai.")
            sc = art.get("script", {})
            if sc.get("version") != SCRIPT_VERSION:
                errors.append("Version artifact tidak sesuai.")
            if sc.get("checklist_id") != CHECKLIST_ID:
                errors.append("Checklist ID tidak sesuai.")
            if art.get("project", {}).get("project_id") != project:
                errors.append("Project ID tidak sesuai.")
            if art.get("target", {}).get("scope_id") != "IN-001":
                errors.append("Scope bukan IN-001.")
            m = art.get("methodology", {})
            for key in (
                "same_origin_only", "no_command_execution", "no_sql_injection",
                "no_xss", "no_path_traversal", "no_file_read_write_delete",
                "no_upload", "no_reverse_shell", "no_external_callbacks",
                "no_credential_harvesting", "forensic_evidence_preserved",
            ):
                if m.get(key) is not True:
                    errors.append(f"Safety rule tidak aktif: {key}")
            if m.get("http_methods") != ["GET"]:
                errors.append("Method harus GET-only.")
            if m.get("reflection_is_finding") is not False:
                errors.append("Reflection tidak boleh menjadi finding.")
            if m.get("http_500_is_finding") is not False:
                errors.append("HTTP 500 tidak boleh menjadi finding.")
            if m.get("parser_error_is_finding") is not False:
                errors.append("Parser error tidak boleh menjadi finding.")
            if m.get("strong_evaluation_required") is not True:
                errors.append("Strong evaluation evidence harus diwajibkan.")
            if m.get("arithmetic_result_alone_is_not_evidence") is not True:
                errors.append("Hasil aritmetika saja tidak boleh menjadi evidence.")
            if m.get("reflected_arithmetic_payload_is_not_evidence") is not True:
                errors.append("Payload arithmetic yang ter-reflect tidak boleh menjadi evidence.")
            if m.get("http_error_cannot_confirm_evaluation") is not True:
                errors.append("HTTP error tidak boleh mengonfirmasi evaluasi.")
            if m.get("arithmetic_result_context_required") is not True:
                errors.append("Konteks hasil aritmetika harus diwajibkan.")
            if m.get("arithmetic_signal_preserved_for_manual_review") is not True:
                errors.append("Signal aritmetika harus tetap dipertahankan untuk review manual.")
            if m.get("evaluation_requires_parameter_context") is not True:
                errors.append("Evaluation harus membutuhkan parameter context.")
            if m.get("security_token_context_is_not_automatic_evidence") is not True:
                errors.append("Security/session/token context tidak boleh menjadi automatic evidence.")

            candidates = art.get("candidates", [])
            if art.get("results", {}).get("candidates") != len(candidates):
                errors.append("Jumlah candidates tidak konsisten.")

            target_url = art.get("target", {}).get("url", "")
            for c in candidates:
                cu = c.get("url", "")
                if not target_url or not same_origin(target_url, cu):
                    errors.append(f"External/non-same-origin candidate terdeteksi: {cu}")
                    break

            ep = evidence_path(project)
            if art.get("results", {}).get("status") == "completed":
                if not ep.exists():
                    errors.append("Evidence tidak ditemukan.")
                else:
                    if not utf8_no_bom(ep):
                        errors.append("Evidence bukan UTF-8 tanpa BOM.")
                    ev = json.loads(ep.read_text(encoding="utf-8"))
                    records = ev.get("probe_records", [])
                    probes = sum(len(r.get("probes", [])) for r in records)
                    if len(records) != art["results"].get("tested"):
                        errors.append("tested tidak sama dengan evidence.")
                    if probes != art["results"].get("probes"):
                        errors.append("probes tidak sama dengan evidence.")
                    if ev.get("script", {}).get("version") != SCRIPT_VERSION:
                        errors.append("Version evidence tidak sesuai.")
                    if ev.get("script", {}).get("checklist_id") != CHECKLIST_ID:
                        errors.append("Checklist evidence tidak sesuai.")
        except Exception as e:
            errors.append(str(e))

    if errors:
        for e in errors:
            print(f"[FAIL] {e}")
        return 1

    r = yaml_load(path).get("results", {})
    print("[PASS] Injection memenuhi validasi.")
    print(f"[PASS] Checklist : {CHECKLIST_ID} {CHECKLIST_NAME}")
    print(f"[PASS] Project   : {project}")
    print(f"[PASS] File      : {path}")
    print(f"[PASS] Candidates: {r.get('candidates', 0)}")
    print(f"[PASS] Probes    : {r.get('probes', 0)}")
    print("[PASS] Encoding  : UTF-8 tanpa BOM")
    return 0


def main():
    p = argparse.ArgumentParser(description=SCRIPT_NAME)
    p.add_argument("--project", help="Project ID; default auto-detect.")
    sub = p.add_subparsers(dest="command", required=True)
    for name, fn in (
        ("version", cmd_version), ("init", cmd_init), ("crawl", cmd_crawl),
        ("analyze", cmd_analyze), ("show", cmd_show), ("status", cmd_status),
        ("verify", cmd_verify),
    ):
        sub.add_parser(name).set_defaults(fn=fn)
    a = p.parse_args()
    try:
        return int(a.fn(a))
    except KeyboardInterrupt:
        print("[FAIL] Dibatalkan oleh pengguna.")
        return 130
    except Exception as e:
        print(f"[FAIL] {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
