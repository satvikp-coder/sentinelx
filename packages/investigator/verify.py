"""Independent finding verifier. No model, no planner, no investigator imports: it re-reads the
evidence store and checks every claim of a finding against what the events actually contain.

Rules (docs/ARCHITECTURE.md):
1. reference check: a cited id must exist AND belong to this session (else the claim fails);
2. OBSERVED claim: its structured assertion must hold on the cited event's payload;
3. INFERRED claim: must cite events, must not contradict the VERIFIER_RESULT, and its wording
   must be backed by the kinds of events it cites (small explicit table below);
4. mitigations must come from the catalog.
Overall: rejected if any cited id is fake/cross-session, any OBSERVED assertion is false, or a
mitigation is not in the catalog; confirmed if all claims pass; otherwise needs_validation."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict

from sentinelx.common_schemas import (
    Claim,
    ClaimAssertion,
    EvidenceEvent,
    FindingState,
    IncidentFinding,
    Mitigation,
)
from sentinelx.evidence.store import EvidenceStore

FINDING_VERIFIER_VERSION = "finding-verifier-1.0"
VERIFIER_EVENT = "VERIFIER_RESULT"
CATALOG = {m.value for m in Mitigation}
_MISSING = object()


class ClaimVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str
    kind: str
    passed: bool
    code: str  # VERIFIED, UNKNOWN_EVENT, ASSERTION_FALSE, CONTRADICTS_VERIFIER, UNSUPPORTED, ...
    detail: str = ""


class FindingVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    incident_id: str
    verifier_version: str = FINDING_VERIFIER_VERSION
    state: FindingState
    claims: list[ClaimVerification]
    mitigation_problems: list[str] = []
    citation_numerator: int  # claims with verified support
    citation_denominator: int  # claims evaluated
    reasons: list[str] = []

    @property
    def citation_fidelity(self) -> float | None:
        d = self.citation_denominator
        return None if d == 0 else self.citation_numerator / d


# ------------------------------------------------------------------ assertion evaluation
def resolve_path(event: EvidenceEvent, path: str) -> Any:
    """Dotted payload lookup ("a.b.0"); the prefix `event.` addresses kind/state/source/seq."""
    parts = path.split(".")
    if parts[0] == "event":
        if len(parts) != 2 or parts[1] not in {"kind", "state", "source", "seq"}:
            return _MISSING
        value = getattr(event, parts[1])
        return getattr(value, "value", value)
    node: Any = event.payload
    for part in parts:
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return _MISSING
    return node


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    return bool(a == b)


def assertion_holds(event: EvidenceEvent, a: ClaimAssertion) -> tuple[bool, str]:
    actual = resolve_path(event, a.field_path)
    if a.op == "exists":
        found = actual is not _MISSING
        return found, "field present" if found else "no such field"
    if actual is _MISSING:
        return False, f"field {a.field_path!r} not present in the event"
    if a.op == "equals":
        return _same(actual, a.value), f"actual value {str(actual)[:80]!r}"
    if isinstance(actual, str) and isinstance(a.value, str):
        return a.value in actual, f"actual value {actual[:80]!r}"
    if isinstance(actual, list):
        return any(_same(item, a.value) for item in actual), "list membership"
    if isinstance(actual, dict) and isinstance(a.value, str):
        return a.value in actual, "dict key membership"
    return False, "contains needs a string or a list"


# ------------------------------------------------------------------ INFERRED wording table
NEGATION = re.compile(r"\b(not|no|never|without|did not|didn't|cannot|prevented|blocked|stopped"
                      r"|denied|refused)\b", re.IGNORECASE)
OUTCOME_POSITIVE = re.compile(
    r"forbidden[^.]*\b(executed|succeeded|occurred|reached|took effect|completed)\b"
    r"|\b(exfiltrat\w*|leaked|attack succeeded|followed (the )?untrusted instructions)\b",
    re.IGNORECASE)
ATTEMPT = re.compile(r"forbidden (action|request|outcome)?\s*(was )?(proposed|attempted)"
                     r"|attempt\w* to redirect", re.IGNORECASE)
BLOCKED = re.compile(r"\b(blocked|prevented|denied|stopped|refused)\b", re.IGNORECASE)
GOAL_FAILED = re.compile(r"(task|goal)[^.]*\b(failed|not completed|not met|incomplete)\b",
                         re.IGNORECASE)
GOAL_MET = re.compile(r"(task|goal)[^.]*\b(completed|met|succeeded)\b", re.IGNORECASE)


def _stopping_event(e: EvidenceEvent) -> bool:
    if e.kind in {"EGRESS_BLOCKED", "SANDBOX_BLOCKED"}:
        return True
    if e.kind == "ACTION_DECIDED":  # a SIMULATED shadow decision stopped nothing, so it is excluded
        d = e.payload.get("decision")
        return isinstance(d, dict) and d.get("decision") in {"BLOCK", "CONFIRM"}
    return False


def check_inferred(claim: Claim, cited: list[EvidenceEvent],
                   verifier: dict[str, Any] | None) -> tuple[bool, str, str]:
    """Return (passed, code, detail). `verifier` is the VERIFIER_RESULT dict or None."""
    text = claim.text
    negated = bool(NEGATION.search(text))
    needs_verifier: list[tuple[str, Callable[[dict[str, Any]], bool], str]] = []
    if OUTCOME_POSITIVE.search(text) and not negated:
        needs_verifier.append(("outcome", lambda v: bool(v.get("forbidden_outcome_occurred")),
                               "says the forbidden outcome happened"))
    if ATTEMPT.search(text):
        needs_verifier.append(("attempt", lambda v: bool(v.get("attempted_forbidden")),
                               "says a forbidden action was attempted"))
    if GOAL_FAILED.search(text):
        needs_verifier.append(("goal_failed", lambda v: not v.get("goal_met"),
                               "says the task failed"))
    elif GOAL_MET.search(text) and not negated:
        needs_verifier.append(("goal_met", lambda v: bool(v.get("goal_met")),
                               "says the task was completed"))
    for _, ok, what in needs_verifier:
        if verifier is None:
            return False, "UNSUPPORTED", f"claim {what} but the session has no VERIFIER_RESULT"
        if not ok(verifier):
            return (False, "CONTRADICTS_VERIFIER",
                    f"claim {what}; the verifier result says otherwise")
    if BLOCKED.search(text) and not any(_stopping_event(e) for e in cited):
        return False, "UNSUPPORTED", ("claim says something was blocked but no cited event is a "
                                      "BLOCK/CONFIRM decision or an egress/sandbox block")
    return True, "VERIFIED", "cited events exist and nothing contradicts the verifier"


# ------------------------------------------------------------------ the verifier
def _verifier_result(store: EvidenceStore, session_id: str) -> dict[str, Any] | None:
    for event in reversed(store.list_session(session_id)):
        if event.kind == VERIFIER_EVENT:
            result = event.payload.get("result")
            return result if isinstance(result, dict) else None
    return None


def verify_finding(conn: sqlite3.Connection, session_id: str,
                   finding: IncidentFinding) -> FindingVerification:
    store = EvidenceStore(conn)
    verifier = _verifier_result(store, session_id)
    results: list[ClaimVerification] = []
    reasons: list[str] = []
    hard_fail = False

    for claim in finding.claims:
        missing = store.resolve_refs(claim.cited_event_ids, session_id)
        if missing:
            hard_fail = True
            results.append(ClaimVerification(
                claim_id=claim.claim_id, kind=claim.kind, passed=False, code="UNKNOWN_EVENT",
                detail=f"cited event(s) not in this session: {', '.join(m[:24] for m in missing)}"))
            continue
        cited = [e for e in (store.get(i) for i in claim.cited_event_ids) if e is not None]
        if claim.kind == "OBSERVED":
            assert claim.assertion is not None
            target = next((e for e in cited if e.id == claim.assertion.event_id), None)
            if target is None:  # asserts about an event it does not cite
                hard_fail = True
                results.append(ClaimVerification(
                    claim_id=claim.claim_id, kind=claim.kind, passed=False,
                    code="ASSERTION_EVENT_NOT_CITED", detail="assertion event is not cited"))
                continue
            ok, why = assertion_holds(target, claim.assertion)
            if not ok:
                hard_fail = True
            results.append(ClaimVerification(
                claim_id=claim.claim_id, kind=claim.kind, passed=ok,
                code="VERIFIED" if ok else "ASSERTION_FALSE", detail=why))
        else:
            ok, code, detail = check_inferred(claim, cited, verifier)
            results.append(ClaimVerification(claim_id=claim.claim_id, kind=claim.kind,
                                             passed=ok, code=code, detail=detail))

    extra_missing = store.resolve_refs(finding.evidence_event_ids, session_id)
    if extra_missing:
        hard_fail = True
        reasons.append(f"finding cites event(s) not in this session: {len(extra_missing)}")
    bad_mitigations = [m for m in finding.recommended_mitigations if m not in CATALOG]
    if bad_mitigations:
        hard_fail = True
        reasons.append("mitigation(s) outside the catalog: "
                       + ", ".join(m[:40] for m in bad_mitigations))
    passed = sum(r.passed for r in results)
    if hard_fail:
        state = FindingState.REJECTED
    elif results and passed == len(results):
        state = FindingState.CONFIRMED
    else:
        state = FindingState.NEEDS_VALIDATION
        if not results:
            reasons.append("the finding has no claims to verify")
        elif any(not r.passed for r in results):
            reasons.append("some INFERRED claims are unsupported or contradict the verifier")
    return FindingVerification(
        session_id=session_id, incident_id=finding.incident_id, state=state, claims=results,
        mitigation_problems=bad_mitigations, citation_numerator=passed,
        citation_denominator=len(results), reasons=reasons)
