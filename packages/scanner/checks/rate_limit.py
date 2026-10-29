"""missing_rate_limit: a CAPPED burst (never more than 15, and never more than the profile's
own `login_burst`, which is itself bounded to <= 15 by `SiteScanProfile`) of failed logins for a
NONEXISTENT synthetic username. This is behavioural evidence (timing/status pattern), not a
structural proof, and the finding says so."""

from __future__ import annotations

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate
from .base import CheckSpec, candidate_id, excerpt, severity_for

HARD_CAP = 15  # never exceeded, regardless of what a profile or anything else says
SPEC = CheckSpec(
    id="missing_rate_limit", vuln_class=VulnClass.MISSING_RATE_LIMIT,
    owasp_category="A07:2021 Identification and Authentication Failures",
    preconditions="the login endpoint is reachable",
    safe_strategy=f"send at most {HARD_CAP} failed logins for a NONEXISTENT synthetic username "
                  "and look for any throttling, lockout, delay or challenge")


def _attempt(ctx: ScanContext, username: str, n: int) -> dict[str, object] | None:
    spec = ctx.personas_file.login
    if spec.encoding == "json":
        import json

        body, headers = json.dumps({spec.username_field: username,
                                    spec.password_field: f"wrong-{n}"}), {
            "Content-Type": "application/json"}
    else:
        from urllib.parse import urlencode

        body, headers = urlencode({spec.username_field: username,
                                   spec.password_field: f"wrong-{n}"}), {
            "Content-Type": "application/x-www-form-urlencoded"}
    out = ctx.call("anonymous", "POST", spec.path, body=body, headers=headers,
                   reason="failed-login burst for a nonexistent synthetic username (capped)",
                   account=username)
    if not out.allowed:
        return None
    return {"status": out.status, "elapsed_ms": out.elapsed_ms, "event_id": out.event_id}


def applicable(ctx: ScanContext) -> list[str]:
    return [ctx.personas_file.login.path]


def run(ctx: ScanContext) -> list[Candidate]:
    username = ctx.personas_file.failed_login_username
    cap = min(HARD_CAP, ctx.profile.login_burst)
    attempts: list[dict[str, object]] = []
    for n in range(1, cap + 1):
        result = _attempt(ctx, username, n)
        if result is None:  # budget/rate/kill-switch stopped it: report what we saw, honestly
            break
        attempts.append(result)
    assert len(attempts) <= HARD_CAP
    if len(attempts) < 2:
        return []
    statuses = {int(a["status"]) for a in attempts}  # type: ignore[arg-type]
    throttled = any(s in {429, 423} for s in statuses) or len(statuses) > 1
    if throttled:
        return []
    out = Candidate(
        id=candidate_id(SPEC.id), check_id=SPEC.id, vuln_class=SPEC.vuln_class,
        severity=severity_for(SPEC.vuln_class), confidence="medium", method="POST",
        endpoint=ctx.personas_file.login.path, endpoints=[ctx.personas_file.login.path],
        persona="anonymous", behavioral=True,
        summary=f"{len(attempts)} failed logins for a nonexistent username all behaved "
                f"identically ({sorted(statuses)}): no throttling, lockout or delay observed. "
                "This is behavioural evidence, not a structural proof.",
        evidence_event_ids=[e for a in attempts if (e := a.get("event_id"))],
        excerpt=excerpt(str([{"status": a["status"]} for a in attempts])),
        proof={"attempts": len(attempts), "statuses": sorted(statuses), "username": username})
    return [out]
