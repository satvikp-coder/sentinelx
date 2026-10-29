"""verbose_errors: trigger a harmless malformed request (a non-numeric id, or syntactically
invalid JSON to the login endpoint) and look for a stack trace or an internal file path."""

from __future__ import annotations

import re

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate
from .base import CheckSpec, candidate_id, excerpt, pick_sample, set_query_param, severity_for

SPEC = CheckSpec(
    id="verbose_errors", vuln_class=VulnClass.VERBOSE_ERRORS,
    owasp_category="A05:2021 Security Misconfiguration",
    preconditions="an id-shaped GET parameter exists, or the login endpoint accepts JSON",
    safe_strategy="send a non-numeric id, or syntactically invalid JSON to the login endpoint, "
                  "and look for a stack trace or an internal path in the response")
TRACE_RE = re.compile(
    r"Traceback \(most recent|Stack trace:|\bat\s+\S+\s+\([^)]*:\d+:\d+\)|\.js:\d+:\d+|"
    r"Fatal error:|Warning:.*on line \d+|node_modules[/\\]|/var/www/|/app/server\.js|"
    r'"stack"\s*:', re.IGNORECASE)
ID_PARAMS = {"id", "order_id", "product_id", "note_id"}
MALFORMED_ID = "][()"


def run(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []
    for (method, _template), ep in ctx.inventory.items():
        if method != "GET":
            continue
        for param in ep.params:
            if param not in ID_PARAMS:
                continue
            persona, sample = pick_sample(ctx, ep)
            probe = ctx.get(persona, set_query_param(sample, param, MALFORMED_ID))
            if probe.allowed and TRACE_RE.search(probe.text):
                out.append(Candidate(
                    id=candidate_id(SPEC.id), check_id=SPEC.id, vuln_class=SPEC.vuln_class,
                    severity=severity_for(SPEC.vuln_class), confidence="high", method="GET",
                    endpoint=ep.template, endpoints=[ep.template], param=param, persona=persona,
                    summary=f"A malformed value for {param!r} on {ep.template} produced an "
                            "internal stack trace or file path.",
                    evidence_event_ids=[e for e in [probe.event_id] if e],
                    excerpt=excerpt(probe.text),
                    proof={"sample": sample, "param": param, "malformed_value": MALFORMED_ID,
                          "persona": persona}))
    spec = ctx.personas_file.login
    if spec.encoding == "json":
        probe = ctx.call(
            "anonymous", "POST", spec.path, body="{not valid json",
            headers={"Content-Type": "application/json"},
            reason="malformed request to check for verbose error output",
            account=ctx.personas_file.failed_login_username)
        if probe.allowed and TRACE_RE.search(probe.text):
            out.append(Candidate(
                id=candidate_id(SPEC.id), check_id=SPEC.id, vuln_class=SPEC.vuln_class,
                severity=severity_for(SPEC.vuln_class), confidence="high", method="POST",
                endpoint=spec.path, endpoints=[spec.path], persona="anonymous",
                summary=f"A syntactically invalid JSON body to {spec.path} produced an internal "
                        "stack trace or file path.",
                evidence_event_ids=[e for e in [probe.event_id] if e], excerpt=excerpt(probe.text),
                proof={"path": spec.path, "malformed_body": "{not valid json"}))
    return out
