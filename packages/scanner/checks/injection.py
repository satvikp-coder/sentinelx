"""sql_injection and reflected_xss: compare an ordinary value against one harmless probe value
per reachable parameter (GET query parameters, and POST form fields the crawler found - never the
login form, and never a file-upload form). Every probe value is inert: a single quote character,
or plain text carrying HTML-special characters. Neither check ever sends a working script or a
real SQL statement; `verify.py` independently reproduces a candidate before it can be confirmed."""

from __future__ import annotations

import re
from urllib.parse import urlencode

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..http import Outcome
from ..models import Candidate, Endpoint
from .base import CheckSpec, candidate_id, excerpt, pick_sample, set_query_param, severity_for

SQL_SPEC = CheckSpec(
    id="sql_injection", vuln_class=VulnClass.SQL_INJECTION,
    owasp_category="A03:2021 Injection",
    preconditions="a GET parameter or a non-login POST form field is reachable",
    safe_strategy="compare the response to an ordinary value against the response to the same "
                  "value with one trailing single quote; flag only a database-error signature")
XSS_SPEC = CheckSpec(
    id="reflected_xss", vuln_class=VulnClass.REFLECTED_XSS,
    owasp_category="A03:2021 Injection",
    preconditions="a GET parameter or a non-login POST form field is reachable",
    safe_strategy="send a unique inert marker with HTML-special characters and check whether it "
                  "comes back unencoded; the marker contains no script and runs nothing")
BASELINE_VALUE = "widgetA1"
PROBE_SUFFIX = "'"
XSS_MARKER_PREFIX = "sx_mark_"
DB_ERROR_RE = re.compile(
    r"SQLSTATE|SQLite3?::|SQLITE_ERROR|no such column|no such table|unrecognized token|"
    r"syntax error(?: near| in)|PDOException|OperationalError|mysql_fetch|ORA-\d{5}|"
    r"org\.postgresql|You have an error in your SQL syntax", re.IGNORECASE)
LOGIN_FIELD_HINTS = ("password",)


def _marker() -> str:
    return XSS_MARKER_PREFIX + "<\"'>&" + "z"


def _get_targets(ctx: ScanContext) -> list[tuple[str, str, Endpoint]]:
    """(persona, sample_path, endpoint) for every GET endpoint with at least one parameter."""
    out = []
    for (method, _template), ep in ctx.inventory.items():
        if method != "GET" or not ep.params:
            continue
        persona, sample = pick_sample(ctx, ep)
        out.append((persona, sample, ep))
    return out


def _post_form_targets(ctx: ScanContext) -> list[tuple[str, Endpoint]]:
    """Non-login, non-upload POST forms the crawler found (HTML forms only)."""
    out = []
    for (method, template), ep in ctx.inventory.items():
        if method != "POST" or not ep.params or template == ctx.personas_file.login.path:
            continue
        if any(f.has_file for f in ep.forms):
            continue
        out.append((template, ep))
    return out


def _probe_post(ctx: ScanContext, template: str, field: str, value: str) -> Outcome:
    # the request runs as the "anonymous" persona, so the declared account is the scanner's own
    # synthetic placeholder - not a persona whose cookies this request does not carry
    account = ctx.personas_file.failed_login_username
    body = urlencode({field: value})
    return ctx.call("anonymous", "POST", template, body=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    reason="harmless probe value in a form field (sql_injection / reflected_xss "
                          "checks)", account=account)


def run_sql_injection(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []
    for persona, sample, ep in _get_targets(ctx):
        for param in ep.params:
            baseline = ctx.get(persona, set_query_param(sample, param, BASELINE_VALUE))
            probe = ctx.get(persona, set_query_param(sample, param, BASELINE_VALUE + PROBE_SUFFIX))
            if not (baseline.allowed and probe.allowed):
                continue
            if DB_ERROR_RE.search(probe.text) and not DB_ERROR_RE.search(baseline.text):
                out.append(Candidate(
                    id=candidate_id(SQL_SPEC.id), check_id=SQL_SPEC.id,
                    vuln_class=SQL_SPEC.vuln_class, severity=severity_for(SQL_SPEC.vuln_class),
                    confidence="medium", method="GET", endpoint=ep.template,
                    endpoints=[ep.template], param=param, persona=persona,
                    summary=f"Parameter {param!r} of {ep.template} produced a database-error "
                            "signature when given a value ending in a single quote.",
                    evidence_event_ids=[e for e in [baseline.event_id, probe.event_id] if e],
                    excerpt=excerpt(probe.text),
                    proof={"sample": sample, "param": param, "baseline": BASELINE_VALUE,
                          "probe_suffix": PROBE_SUFFIX, "persona": persona}))
    for template, ep in _post_form_targets(ctx):
        for field in ep.params:
            if any(hint in field.lower() for hint in LOGIN_FIELD_HINTS):
                continue
            baseline = _probe_post(ctx, template, field, BASELINE_VALUE)
            probe = _probe_post(ctx, template, field, BASELINE_VALUE + PROBE_SUFFIX)
            if not (baseline.allowed and probe.allowed):
                continue
            if DB_ERROR_RE.search(probe.text) and not DB_ERROR_RE.search(baseline.text):
                out.append(Candidate(
                    id=candidate_id(SQL_SPEC.id), check_id=SQL_SPEC.id,
                    vuln_class=SQL_SPEC.vuln_class, severity=severity_for(SQL_SPEC.vuln_class),
                    confidence="medium", method="POST", endpoint=template, endpoints=[template],
                    param=field, persona="anonymous",
                    summary=f"Form field {field!r} of {template} produced a database-error "
                            "signature when given a value ending in a single quote.",
                    evidence_event_ids=[e for e in [baseline.event_id, probe.event_id] if e],
                    excerpt=excerpt(probe.text),
                    proof={"template": template, "field": field, "baseline": BASELINE_VALUE,
                          "probe_suffix": PROBE_SUFFIX}))
    return out


def run_reflected_xss(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []
    marker = _marker()
    for persona, sample, ep in _get_targets(ctx):
        for param in ep.params:
            probe = ctx.get(persona, set_query_param(sample, param, marker))
            if probe.allowed and marker in probe.text:
                out.append(Candidate(
                    id=candidate_id(XSS_SPEC.id), check_id=XSS_SPEC.id,
                    vuln_class=XSS_SPEC.vuln_class, severity=severity_for(XSS_SPEC.vuln_class),
                    confidence="high", method="GET", endpoint=ep.template,
                    endpoints=[ep.template], param=param, persona=persona,
                    summary=f"Parameter {param!r} of {ep.template} reflected an inert marker "
                            "containing HTML-special characters without encoding.",
                    evidence_event_ids=[e for e in [probe.event_id] if e],
                    excerpt=excerpt(probe.text), proof={"sample": sample, "param": param,
                                                        "marker": marker, "persona": persona}))
    for template, ep in _post_form_targets(ctx):
        for field in ep.params:
            if any(hint in field.lower() for hint in LOGIN_FIELD_HINTS):
                continue
            probe = _probe_post(ctx, template, field, marker)
            if probe.allowed and marker in probe.text:
                out.append(Candidate(
                    id=candidate_id(XSS_SPEC.id), check_id=XSS_SPEC.id,
                    vuln_class=XSS_SPEC.vuln_class, severity=severity_for(XSS_SPEC.vuln_class),
                    confidence="high", method="POST", endpoint=template, endpoints=[template],
                    param=field, persona="anonymous",
                    summary=f"Form field {field!r} of {template} reflected an inert marker "
                            "containing HTML-special characters without encoding.",
                    evidence_event_ids=[e for e in [probe.event_id] if e],
                    excerpt=excerpt(probe.text),
                    proof={"template": template, "field": field, "marker": marker}))
    return out
