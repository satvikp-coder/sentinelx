"""authz_post: broken object authorization for state-changing operations (POST/PUT/PATCH/DELETE).
A logged-in user (user_a) creates a resource via POST /api/notes; another logged-in user
(user_b) attempts to modify or delete that same resource via PUT/DELETE /api/notes/:id.
Ownership must be enforced on state-changing requests, not just reads."""

from __future__ import annotations

import json

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate
from .base import CheckSpec, candidate_id, excerpt, severity_for

SPEC = CheckSpec(
    id="authz_post",
    vuln_class=VulnClass.BROKEN_OBJECT_AUTHORIZATION,
    owasp_category="A01:2021 Broken Access Control",
    preconditions="a logged-in user can create a state-changing resource and another logged-in "
                  "user can attempt to modify or delete that resource by id",
    safe_strategy="user_a creates a note via POST /api/notes; user_b attempts to update or "
                  "delete the same note via PUT/DELETE /api/notes/:id; ownership must block user_b",
)

NOTE_TITLE = "sx_authz_post_" + __import__("uuid").uuid4().hex[:8]


def applicable(ctx: ScanContext) -> list[str]:
    return ["/api/notes"]


def run(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []

    # user_a creates a note via POST /api/notes (state-changing)
    session = ctx.ensure_persona("user_a", fresh=True)
    from ..session import login
    login(ctx.client, ctx.base_url, session, ctx.personas_file.login)

    create = ctx.call(
        "user_a", "POST", "/api/notes",
        body='{"title":"' + NOTE_TITLE + '","body":"user_a private note"}',
        headers={"Content-Type": "application/json"},
        reason="user_a creates a note (state-changing)",
        account="user_a",
    )
    if not create.allowed or create.status not in (200, 201):
        return out

    try:
        note_id = str(json.loads(create.text)["id"])
    except (ValueError, KeyError, TypeError):
        return out

    # user_b attempts to modify user_a's note via PUT /api/notes/:id
    session_b = ctx.ensure_persona("user_b", fresh=True)
    login(ctx.client, ctx.base_url, session_b, ctx.personas_file.login)

    probe = ctx.call(
        "user_b", "PUT", f"/api/notes/{note_id}",
        body='{"title":"user_b modified","body":"user_b modified this note"}',
        headers={"Content-Type": "application/json"},
        reason="user_b attempts to modify user_a's note (state-changing BOLA)",
        account="user_b",
    )

    if probe.allowed and probe.status in (200, 201):
        out.append(Candidate(
            id=candidate_id(SPEC.id), check_id=SPEC.id,
            vuln_class=SPEC.vuln_class, severity=severity_for(SPEC.vuln_class),
            confidence="high", method="PUT", endpoint="/api/notes/:id",
            endpoints=["/api/notes/:id"], persona="user_b",
            summary="user_b (another logged-in user) can modify user_a's note via PUT "
                    "/api/notes/:id (no ownership check on state-changing requests).",
            evidence_event_ids=[e for e in [create.event_id, probe.event_id] if e],
            excerpt=excerpt(probe.text),
            proof={"note_id": note_id, "victim_persona": "user_a",
                   "attacker_persona": "user_b"},
        ))

    return out
