"""stored_xss: a logged-in user sets their profile bio to an inert marker containing
HTML-special characters; the public profile page is then fetched as an anonymous visitor
to check whether the marker comes back unencoded. The only state-changing request is the
profile update by the marker's owner; the confirmation read is a plain GET. No script is
ever executed and no external request is made."""

from __future__ import annotations

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate
from .base import CheckSpec, candidate_id, excerpt, severity_for

SPEC = CheckSpec(
    id="stored_xss",
    vuln_class=VulnClass.XSS_STORED,
    owasp_category="A03:2021 Injection",
    preconditions="a logged-in user can set a profile bio that is rendered on a public "
                  "profile page without output encoding",
    safe_strategy="set the bio to an inert marker containing HTML-special characters "
                  "(no script, no event handler), then fetch the public profile page as an "
                  "anonymous visitor and check whether the marker is reflected unencoded",
)
MARKER = "sx_stored_xss_<\"'>&z"


def applicable(ctx: ScanContext) -> list[str]:
    return ["/api/profile"]


def run(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []

    # user_a sets profile bio to inert marker (state-changing, logged in)
    session = ctx.ensure_persona("user_a", fresh=True)
    from ..session import login
    login(ctx.client, ctx.base_url, session, ctx.personas_file.login)

    probe = ctx.call(
        "user_a", "PUT", "/api/profile",
        body='{"bio":"' + MARKER + '"}',
        headers={"Content-Type": "application/json"},
        reason="set profile bio to inert stored-XSS marker",
        account="user_a",
    )
    if not probe.allowed:
        return out

    # fetch public profile as anonymous visitor
    check = ctx.get("anonymous", "/u/carol")
    if not check.allowed:
        return out

    if MARKER in check.text:
        out.append(Candidate(
            id=candidate_id(SPEC.id), check_id=SPEC.id,
            vuln_class=SPEC.vuln_class, severity=severity_for(SPEC.vuln_class),
            confidence="high", method="GET", endpoint="/u/:username",
            endpoints=["/u/:username"], persona="anonymous",
            summary="Profile bio containing HTML-special characters is reflected unencoded "
                    "on the public profile page (stored XSS).",
            evidence_event_ids=[e for e in [probe.event_id, check.event_id] if e],
            excerpt=excerpt(check.text),
            proof={"path": "/u/carol", "marker": MARKER, "persona": "user_a"},
        ))
    return out
