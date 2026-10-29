"""Part E: the decision ladder, approval, and escalation. Nothing here ever writes to the
original labs/<lab>/ directory. A VERIFIED AUTO patch is PROPOSED and waits for a human
ApprovalRecord; only then does it reach labs_applied/<lab>/ (never the original lab)."""

from __future__ import annotations

import shutil
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.common_schemas import (
    ApprovalDecision,
    ApprovalRecord,
    EscalationStatus,
    EscalationTicket,
    PatchProposal,
    RepairVerification,
    SessionKind,
    VerificationStatus,
)
from sentinelx.evidence.records import RecordStore
from sentinelx.evidence.sessions import SessionService

from .models import FixPolicyEntry, RepoScope
from .patch_gen import PatchGenResult
from .verify import VerificationReport

REPO_ROOT = Path(__file__).resolve().parents[2]
APPLIED_ROOT = REPO_ROOT / "labs_applied"
FIXER_ACTOR = "fixer-1"


def start_fix_session(conn, finding_id: str) -> str:
    session, _ = SessionService(conn).create(SessionKind.FIX, "fixer-1", FIXER_ACTOR,
                                              target_id=finding_id)
    return session.id


@dataclass(frozen=True)
class LadderOutcome:
    status: str  # "AWAITING_APPROVAL" | "ESCALATED" | "REJECTED_RETRY"
    patch_id: str | None = None
    ticket_id: str | None = None


def record_patch_proposal(conn, finding_id: str, patch: PatchGenResult,
                          files_touched: list[str]) -> str:
    patch_id = f"patch_{uuid.uuid4().hex[:12]}"
    proposal = PatchProposal(
        id=patch_id, finding_id=finding_id, diff=patch.diff, explanation=patch.explanation,
        files_touched=files_touched or ["unknown"],
        fix_category=patch.fix_category.value if patch.fix_category else "unknown")
    RecordStore(conn).insert(proposal)
    return patch_id


def record_verification(conn, patch_id: str, report: VerificationReport) -> None:
    RecordStore(conn).insert(RepairVerification(
        patch_id=patch_id, checks=report.check_results, status=report.status,
        verifier_version="fixer-verify-1", duration_ms=report.total_duration_ms))


def escalate(conn, *, finding_id: str, evidence_event_ids: list[str], explanation: str,
            options: list[str], suggested_interim_shield: str | None = None) -> str:
    ticket_id = f"esc_{uuid.uuid4().hex[:12]}"
    RecordStore(conn).insert(EscalationTicket(
        id=ticket_id, finding_id=finding_id, evidence_event_ids=evidence_event_ids or ["n/a"],
        explanation=explanation, options=options[:3],
        suggested_interim_shield_id=suggested_interim_shield, status=EscalationStatus.OPEN,
        created_at=datetime.now(UTC)))
    return ticket_id


def decide(conn, *, finding_id: str, vuln_class: str, policy_entry: FixPolicyEntry | None,
          patch: PatchGenResult, verification: VerificationReport | None,
          rejected_count: int, evidence_event_ids: list[str],
          files_touched: list[str]) -> LadderOutcome:
    """The ladder itself: it records state, it never applies anything."""
    if patch.status != "VALIDATED":
        ticket_id = escalate(
            conn, finding_id=finding_id, evidence_event_ids=evidence_event_ids,
            explanation=f"The model could not produce a patch that passed validation for this "
                       f"{vuln_class} finding ({patch.status}): {'; '.join(patch.reasons)}",
            options=["Have a human write the fix directly.",
                    "Retry patch generation with a different model profile.",
                    "Leave unfixed; the scanner will catch it again next scan."])
        return LadderOutcome("ESCALATED", ticket_id=ticket_id)

    patch_id = record_patch_proposal(conn, finding_id, patch, files_touched)
    if verification is not None:
        record_verification(conn, patch_id, verification)

    if policy_entry is not None and policy_entry.decision == "NEEDS_HUMAN":
        verified = bool(verification and verification.status == VerificationStatus.VERIFIED)
        state_word = "VERIFIED" if verified else "proposed"
        ticket_id = escalate(
            conn, finding_id=finding_id, evidence_event_ids=evidence_event_ids,
            explanation=(f"{vuln_class} fixes depend on a business decision this patch cannot "
                        f"make on its own; a {state_word} patch ({patch_id}) exists for a "
                        "human to review, but this class is never auto-applied."),
            options=[f"Review and approve patch {patch_id} as written.",
                    "Ask for a different fix approach (e.g. a stricter policy).",
                    "Reject and have a human implement the business rule directly."])
        return LadderOutcome("ESCALATED", patch_id=patch_id, ticket_id=ticket_id)

    if verification is None or verification.status != VerificationStatus.VERIFIED:
        if rejected_count + 1 >= 2:
            failed = [c.result.name for c in (verification.checks if verification else [])
                     if not c.result.passed]
            ticket_id = escalate(
                conn, finding_id=finding_id, evidence_event_ids=evidence_event_ids,
                explanation=f"Verification was rejected twice for this {vuln_class} finding "
                           f"(failed checks: {failed}); patch {patch_id} was never confirmed "
                           "safe to apply.",
                options=["Have a human review and fix the patch by hand.",
                        "Retry diagnosis - the located file/lines may be wrong.",
                        "Leave unfixed; the scanner will catch it again next scan."])
            return LadderOutcome("ESCALATED", patch_id=patch_id, ticket_id=ticket_id)
        return LadderOutcome("REJECTED_RETRY", patch_id=patch_id)

    return LadderOutcome("AWAITING_APPROVAL", patch_id=patch_id)


def apply_approved(conn, *, patch_id: str, lab: str, scope: RepoScope, reviewer: str,
                   rationale: str = "approved") -> str:
    """Record the ApprovalRecord, then copy the scope's CURRENT (patched) state into
    labs_applied/<lab>/current/. Whatever was already in current/ is kept as a timestamped
    rollback copy first - the ORIGINAL labs/<lab>/ is never touched by this."""
    approval = ApprovalRecord(id=f"appr_{uuid.uuid4().hex[:12]}", subject_type="patch",
                              subject_id=patch_id, reviewer=reviewer,
                              decision=ApprovalDecision.APPROVE, rationale=rationale,
                              timestamp=datetime.now(UTC))
    RecordStore(conn).insert(approval)

    dest = APPLIED_ROOT / lab
    current = dest / "current"
    if current.exists():
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        shutil.copytree(current, dest / f"rollback_{stamp}")
        shutil.rmtree(current)
    current.mkdir(parents=True, exist_ok=True)
    for item in scope.work_dir.iterdir():
        if item.name == ".git":
            continue
        target = current / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)
    return approval.id


def reject_approval(conn, *, patch_id: str, reviewer: str, rationale: str) -> str:
    approval = ApprovalRecord(id=f"appr_{uuid.uuid4().hex[:12]}", subject_type="patch",
                              subject_id=patch_id, reviewer=reviewer,
                              decision=ApprovalDecision.REJECT, rationale=rationale,
                              timestamp=datetime.now(UTC))
    RecordStore(conn).insert(approval)
    return approval.id


def rollback(lab: str, rollback_dir_name: str) -> None:
    """Restore labs_applied/<lab>/current/ from a named rollback_<stamp> snapshot."""
    dest = APPLIED_ROOT / lab
    source = dest / rollback_dir_name
    if not source.is_dir():
        raise ValueError(f"no such rollback copy: {rollback_dir_name!r}")
    current = dest / "current"
    shutil.rmtree(current, ignore_errors=True)
    shutil.copytree(source, current)
