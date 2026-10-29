"""security_headers_and_cookies: passive inspection of response headers and Set-Cookie flags on
the pages a persona already visits. No new kind of request; GET only."""

from __future__ import annotations

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate
from .base import CheckSpec, candidate_id, excerpt, severity_for

SPEC = CheckSpec(
    id="security_headers_and_cookies",
    vuln_class=VulnClass.SECURITY_HEADERS_AND_COOKIES,
    owasp_category="A05:2021 Security Misconfiguration",
    preconditions="the start page and (if credentials exist) a login response are reachable",
    safe_strategy="read the headers and Set-Cookie flags of pages already requested; no probing",
)
EXPECTED_HEADERS = ("content-security-policy", "x-content-type-options", "x-frame-options")
SESSION_COOKIE_HINTS = ("session", "sid", "phpsessid", "token", "auth")


def _missing_headers(headers: dict[str, str]) -> list[str]:
    return [h for h in EXPECTED_HEADERS if h not in headers]


def _cookie_problems(set_cookies: list[str]) -> dict[str, list[str]]:
    problems: dict[str, list[str]] = {}
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        if not any(hint in name.lower() for hint in SESSION_COOKIE_HINTS):
            continue
        low = raw.lower()
        missing = [flag for flag in ("httponly", "samesite") if flag not in low]
        if missing:
            problems[name] = missing
    return problems


def applicable(ctx: ScanContext) -> list[str]:
    out = [ctx.personas_file.start_path]
    if any(p.credentials for p in ctx.personas_file.personas):
        out.append(ctx.personas_file.login.path)
    return out


def run(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []
    home = ctx.get("anonymous", ctx.personas_file.start_path)
    if not home.allowed:
        return out
    missing = _missing_headers(home.headers)
    if missing:
        out.append(Candidate(
            id=candidate_id(SPEC.id), check_id=SPEC.id, vuln_class=SPEC.vuln_class,
            severity=severity_for(SPEC.vuln_class), confidence="high", method="GET",
            endpoint=ctx.personas_file.start_path, endpoints=[ctx.personas_file.start_path],
            persona="anonymous", summary=f"Missing security headers: {', '.join(missing)}.",
            evidence_event_ids=[e for e in [home.event_id] if e],
            excerpt=excerpt(", ".join(f"{k}={v}" for k, v in home.headers.items())),
            proof={"path": ctx.personas_file.start_path, "missing_headers": missing}))
    creds_persona = next((p.name for p in ctx.personas_file.personas if p.credentials), None)
    if creds_persona:
        session = ctx.ensure_persona(creds_persona, fresh=True)  # logging in makes a fresh session
        problems = _cookie_problems(list(session.raw_set_cookies.values()))
        if problems:
            out.append(Candidate(
                id=candidate_id(SPEC.id), check_id=SPEC.id, vuln_class=SPEC.vuln_class,
                severity=severity_for(SPEC.vuln_class), confidence="high", method="POST",
                endpoint=ctx.personas_file.login.path, endpoints=[ctx.personas_file.login.path],
                persona=creds_persona,
                summary=f"Session cookie(s) missing flags: {problems}.",
                evidence_event_ids=[], excerpt=excerpt(str(problems)),
                proof={"cookie_problems": problems, "persona": creds_persona}))
    return out
