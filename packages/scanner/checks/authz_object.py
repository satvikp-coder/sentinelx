"""broken_object_authorization: with persona A, request an object using an id persona B's OWN
session visited (B's exact sample path+query, path- or query-parameter id alike), and compare the
returned content against what B saw at that same URL. Read-only GETs only."""

from __future__ import annotations

import re

from sentinelx.common_schemas import VulnClass

from ..context import ScanContext
from ..models import Candidate, Endpoint
from .base import CheckSpec, candidate_id, excerpt, severity_for

SPEC = CheckSpec(
    id="broken_object_authorization", vuln_class=VulnClass.BROKEN_OBJECT_AUTHORIZATION,
    owasp_category="A01:2021 Broken Access Control",
    preconditions="persona B visited an id-shaped, authenticated-looking endpoint persona A can "
                  "also reach",
    safe_strategy="persona A requests the exact URL persona B's own session visited (read-only "
                  "GET) and the response is compared against what B saw at that same URL")
ID_PARAMS = {"id", "order_id", "note_id", "product_id"}
MIN_CONTENT_LEN = 10


def _applies(ep: Endpoint) -> bool:
    if ep.statuses.get("anonymous") == 200:
        return False  # publicly readable data (e.g. a product page): not a privacy question
    return "{id}" in ep.template or bool(ID_PARAMS & set(ep.params))


def _content_slice(text: str) -> str:
    idx = text.lower().find("<h1>")
    body = text[idx:idx + 250] if idx != -1 else text
    return re.sub(r"\s+", " ", body).strip()


def applicable(ctx: ScanContext) -> list[str]:
    return [ep.template for (method, _t), ep in ctx.inventory.items()
           if method == "GET" and _applies(ep) and ep.samples.get("user_b")]


def run(ctx: ScanContext) -> list[Candidate]:
    out: list[Candidate] = []
    for (method, _template), ep in ctx.inventory.items():
        if method != "GET" or not _applies(ep):
            continue
        for url in ep.samples.get("user_b", []):
            b_out = ctx.get("user_b", url)
            if not b_out.allowed or b_out.status != 200:
                continue
            b_slice = _content_slice(b_out.text)
            if len(b_slice) < MIN_CONTENT_LEN:
                continue
            a_out = ctx.get("user_a", url)
            if a_out.allowed and a_out.status == 200 and _content_slice(a_out.text) == b_slice:
                out.append(Candidate(
                    id=candidate_id(SPEC.id), check_id=SPEC.id, vuln_class=SPEC.vuln_class,
                    severity=severity_for(SPEC.vuln_class), confidence="high", method="GET",
                    endpoint=ep.template, endpoints=[ep.template], persona="user_a",
                    summary=f"Persona A received persona B's own content at {url!r} "
                            "(no ownership check on the object id).",
                    evidence_event_ids=[e for e in [b_out.event_id, a_out.event_id] if e],
                    excerpt=excerpt(a_out.text),
                    proof={"url": url, "victim_persona": "user_b", "attacker_persona": "user_a"}))
    return out
