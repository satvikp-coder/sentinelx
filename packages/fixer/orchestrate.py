"""Ties Parts A-E together: one finding -> diagnosis -> patch generation -> independent
verification -> the decision ladder. Never applies anything by itself - AWAITING_APPROVAL
means a verified patch PROPOSAL exists and a human must call ladder.apply_approved()."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sentinelx.common_schemas import CheckResult, VerificationStatus, VulnClass
from sentinelx.model_clients import ModelClient

from .apply import ApplyError, apply_diff
from .diagnose import DiagnosedLocation, DiagnosisFailure, diagnose
from .ladder import LadderOutcome, decide, escalate
from .models import FixPolicy, RepoScope
from .patch_gen import PatchGenResult, generate_patch
from .scope import create_scope, destroy_scope
from .verify import TimedCheck, VerificationReport, verify_patch

REPO_ROOT = Path(__file__).resolve().parents[2]
FIX_RUNS_DIR = REPO_ROOT / "evaluations" / "fix_runs"
MAX_LADDER_RETRIES = 2


@dataclass
class FixOutcome:
    finding_id: str
    vuln_class: str
    status: str  # "AWAITING_APPROVAL" | "ESCALATED"
    patch_id: str | None = None
    ticket_id: str | None = None
    diagnosis: DiagnosedLocation | None = None
    patch: PatchGenResult | None = None
    verification: VerificationReport | None = None
    retries_used: int = 0


def _save_scope_record(patch_id: str, lab: str, scope: RepoScope, diff: str) -> None:
    FIX_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    (FIX_RUNS_DIR / f"{patch_id}.json").write_text(json.dumps(
        {"lab": lab, "work_dir": str(scope.work_dir), "diff": diff}, indent=2), encoding="utf-8")


def load_scope_record(patch_id: str) -> tuple[str, RepoScope]:
    data = json.loads((FIX_RUNS_DIR / f"{patch_id}.json").read_text(encoding="utf-8"))
    from .scope import source_dir_for

    scope = RepoScope(lab=data["lab"], source_dir=source_dir_for(data["lab"]),
                      work_dir=Path(data["work_dir"]))
    return data["lab"], scope


def run_fix(finding: dict, *, lab: str, conn, client: ModelClient, policy: FixPolicy,
           original_findings: list[dict]) -> FixOutcome:
    candidate = finding["candidate"]
    finding_id, vuln_class = candidate["id"], candidate["vuln_class"]
    policy_entry = policy.for_class(VulnClass(vuln_class))
    scope = create_scope(lab)
    outcome: LadderOutcome | None = None
    diag: DiagnosedLocation | None = None
    patch: PatchGenResult | None = None
    verification: VerificationReport | None = None
    retries = 0
    try:
        loc_or_fail = diagnose(scope, method=candidate["method"], endpoint=candidate["endpoint"],
                               param=candidate.get("param"), summary=candidate["summary"],
                               vuln_class=vuln_class, client=client)
        if isinstance(loc_or_fail, DiagnosisFailure):
            ticket_id = escalate(
                conn, finding_id=finding_id, evidence_event_ids=[],
                explanation=f"Could not locate code for this {vuln_class} finding: "
                           f"{loc_or_fail.reason}",
                options=["Have a human point the fixer at the right file directly.",
                        "Extend route_to_file() for this endpoint shape.",
                        "Leave unfixed; the scanner will catch it again next scan."])
            return FixOutcome(finding_id, vuln_class, "ESCALATED", ticket_id=ticket_id)
        diag = loc_or_fail
        baseline_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=scope.work_dir, check=True, capture_output=True,
            text=True).stdout.strip()

        while True:
            patch = generate_patch(scope, diag, vuln_class=vuln_class, method=candidate["method"],
                                   endpoint=candidate["endpoint"], summary=candidate["summary"],
                                   client=client, allowed_files={diag.file})
            verification = None
            if patch.status == "VALIDATED":
                # each attempt starts from the unpatched baseline, never stacked on a
                # previous (rejected) attempt's changes
                subprocess.run(["git", "reset", "-q", "--hard", baseline_commit],
                               cwd=scope.work_dir, check=True, capture_output=True)
                try:
                    apply_diff(scope, patch.diff, commit_message=f"fix: {vuln_class} "
                              f"({diag.file}:{diag.line_start}-{diag.line_end})")
                    verification = verify_patch(
                        scope, patch_id=f"tmp-{finding_id}", diff_text=patch.diff,
                        allowed_files={diag.file}, diagnosed_file=diag.file,
                        vuln_class=vuln_class, endpoint=candidate["endpoint"],
                        method=candidate["method"], original_findings=original_findings)
                except ApplyError as exc:
                    verification = VerificationReport(patch_id=f"tmp-{finding_id}")
                    verification.checks = [TimedCheck(
                        CheckResult(name="apply_diff", passed=False,
                                   output_excerpt=str(exc)[:500]), 0)]
                    verification.status = VerificationStatus.REJECTED
            outcome = decide(conn, finding_id=finding_id, vuln_class=vuln_class,
                             policy_entry=policy_entry, patch=patch, verification=verification,
                             rejected_count=retries, evidence_event_ids=[],
                             files_touched=[diag.file])
            if outcome.status != "REJECTED_RETRY" or retries >= MAX_LADDER_RETRIES:
                break
            retries += 1
    finally:
        if outcome is None or outcome.status != "AWAITING_APPROVAL":
            destroy_scope(scope)

    if outcome.status == "AWAITING_APPROVAL" and outcome.patch_id and patch:
        _save_scope_record(outcome.patch_id, lab, scope, patch.diff)
    return FixOutcome(finding_id, vuln_class, outcome.status, patch_id=outcome.patch_id,
                      ticket_id=outcome.ticket_id, diagnosis=diag, patch=patch,
                      verification=verification, retries_used=retries)
