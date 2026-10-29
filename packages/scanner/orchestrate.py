"""Scan orchestration: register -> verify the target -> recon -> hunt -> verify candidates ->
report. Uses the session state machine (kind SCAN) and the evidence store; honours the budget,
the rate limit and the kill switch (all enforced inside `GuardedClient`, not here); always ends
with an explicit stop reason."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.common_schemas import EvidenceState, TargetAuthorization
from sentinelx.evidence.store import EvidenceStore
from sentinelx.model_clients import ModelClient

from .checks import CATALOG
from .context import ScanContext, authz_profile_for
from .coverage import CoverageLedger, build_ledger
from .http import GuardedClient, start_scan_session
from .model_assist import ExplainOutcome, PlanOutcome, explain_confirmed, suggest_plan
from .models import Candidate, Finding, SiteScanProfile, Verification, load_paths, load_personas
from .recon import crawl, discover
from .verify import verify_candidate

FINDING_CANDIDATE_EVENT = "SCAN_FINDING_CANDIDATE"
FINDING_VERIFIED_EVENT = "SCAN_FINDING_VERIFIED"


@dataclass
class ScanResult:
    session_id: str
    target_id: str
    stop_reason: str
    findings: list[Finding]
    coverage: CoverageLedger
    plan: PlanOutcome
    explain: ExplainOutcome
    requests_used: int
    duration_ms: float
    skipped_checks: dict[str, str] = field(default_factory=dict)


def _check_order(profile: SiteScanProfile, plan: list[str]) -> list[str]:
    """The declared order from the plan, but never a check the profile itself excludes."""
    return [c for c in plan if c in profile.checks]


def run_scan(target: TargetAuthorization, profile: SiteScanProfile, labs_root: Path,
            lab_name: str, conn: Any, *, client: ModelClient | None = None,
            use_model_for_plan: bool = False, use_model_for_explanations: bool = False,
            kill: Any = None, cancel_event: threading.Event | None = None,
            transport: Any = None, resolver: Any = None) -> ScanResult:
    started = time.perf_counter()
    authz_config = profile_to_authz_config(profile)
    authz_profile = authz_profile_for(profile, load_personas(labs_root / lab_name /
                                                              "personas.json"))
    session_id = start_scan_session(conn, target, authz_config, authz_profile)
    gc_kwargs: dict[str, Any] = {"config": authz_config, "profile": authz_profile}
    if kill is not None:
        gc_kwargs["kill"] = kill
    if transport is not None:
        gc_kwargs["transport"] = transport
    if resolver is not None:
        gc_kwargs["resolver"] = resolver
    guarded = GuardedClient(target, conn=conn, session_id=session_id, **gc_kwargs)
    ctx = ScanContext(target=target, client=guarded, profile=profile, paths=load_paths(),
                      personas_file=load_personas(labs_root / lab_name / "personas.json"))
    store = EvidenceStore(conn)

    def stopped_reason() -> str | None:
        if cancel_event is not None and cancel_event.is_set():
            return "CANCELLED"
        s = guarded.counters.stopped
        return s.reason if s is not None else None

    for persona in ctx.personas_file.personas:
        if stopped_reason():
            break
        crawl(ctx, persona.name)
        if persona.name == "anonymous":
            discover(ctx, persona.name)

    plan = (suggest_plan(ctx, profile.checks, client, session_id) if use_model_for_plan
            else PlanOutcome(list(profile.checks), False, "no model requested for the plan"))
    order = _check_order(profile, plan.checks)
    candidates: list[Candidate] = []
    skipped: dict[str, str] = {}
    for check_id in order:
        reason = stopped_reason()
        if reason:
            skipped[check_id] = reason
            continue
        check = CATALOG[check_id]
        try:
            candidates.extend(check.run(ctx))
        except Exception as exc:  # noqa: BLE001 - one bad check must not crash the scan
            store.append(session_id, "SCAN_CHECK_ERROR", EvidenceState.OBSERVED, "scanner",
                        {"check_id": check_id, "error": f"{type(exc).__name__}: {exc}"[:300]})

    findings: list[Finding] = []
    for candidate in candidates:
        if stopped_reason():
            verification = Verification("needs_validation", "scan stopped before verification",
                                        False)
        else:
            verification = verify_candidate(ctx, candidate)
        found = store.append(session_id, FINDING_CANDIDATE_EVENT, EvidenceState.INFERRED,
                             "scanner", {"candidate": candidate.model_dump(mode="json")})
        confirmed = verification.state == "confirmed"
        store.append(
            session_id, FINDING_VERIFIED_EVENT,
            EvidenceState.VERIFIED if confirmed else EvidenceState.OBSERVED, "scanner.verify",
            {"candidate_id": candidate.id, "state": verification.state,
             "flagged": not confirmed, "verification": verification.model_dump(mode="json")},
            parent_event_id=found.id)
        findings.append(Finding(candidate=candidate, verification=verification))

    explain = (explain_confirmed(findings, client) if use_model_for_explanations
              else ExplainOutcome({}, False, "model not requested for explanations"))
    for f in findings:
        if f.candidate.id in explain.explanations:
            f.explanation = explain.explanations[f.candidate.id]
            f.explanation_label = "MODEL-GENERATED"

    reason = stopped_reason() or "completed"
    store.append(session_id, "SCAN_FINISHED", EvidenceState.OBSERVED, "scanner", {
        "stop_reason": reason, "requests_used": guarded.counters.requests,
        "candidates": len(candidates), "confirmed": sum(f.verification.state == "confirmed"
                                                         for f in findings)})
    ledger = build_ledger(ctx, order, candidates, skipped)
    return ScanResult(session_id, target.target_id, reason, findings, ledger, plan, explain,
                      guarded.counters.requests, (time.perf_counter() - started) * 1000, skipped)


def profile_to_authz_config(profile: SiteScanProfile) -> Any:
    from .authz import AuthzConfig

    return AuthzConfig(allow_state_changing_in_labs=profile.state_changing,
                      requests_per_second=profile.requests_per_second, burst=profile.burst,
                      request_budget=profile.request_budget)
