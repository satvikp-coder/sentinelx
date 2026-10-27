"""EVCS report: per-mitigation table, per-case recommendations, EVCS vs the baseline, arm C.

Every number carries its numerator and denominator. Agent: SIMULATED scripted planner."""

from __future__ import annotations

import csv
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx.verifier.verify import VERIFIER_VERSION

from .evcs import EvcsCase
from .mitigations import CATALOG
from .selection import Weights, disruption_cost, select

REPO = Path(__file__).resolve().parents[2]

LIMITATIONS = [
    "The agent is a SCRIPTED, SIMULATED planner (not an LLM). It obeys injected instructions by "
    "fixed rules, so these results say nothing about how a real model would behave.",
    "The 30 cases were authored together with the policy, so the controls were built knowing "
    "them; the numbers show behaviour on THESE cases, not on unseen attacks.",
    "A branch is a RE-EXECUTION of a scripted run in our own resettable lab fixtures (a bounded "
    "digital twin of OUR lab, not of any real site). Nothing real is rolled back; effects the "
    "parent run produced stay in the parent.",
    "Small n: 15 attack cases, 1 run per branch, no confidence intervals.",
    "The disruption weights are our own choice (weights file, version recorded): a different "
    "weighting can change the recommendation. Latency is priced at 0 by default for "
    "reproducibility.",
    "SIMULATED approvals: the ScriptedOperator is code driven by a hand-authored file, not a "
    "human; it proves the workflow and the binding rules, not human behaviour.",
    "Selection is deterministic code. The optional model suggestion only chooses which branches "
    "to try and can never mark one safe.",
    "No claim of complete protection is made.",
]


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:
        return "unknown"


def ratio(n: int, d: int) -> dict[str, Any]:
    return {"numerator": n, "denominator": d, "value": None if d == 0 else round(n / d, 4)}


def branch_row(case_id: str, b: Any, w: Weights) -> dict[str, Any]:
    return {"case": case_id, "mitigation": b.mitigation, "session_id": b.session_id,
            "trap": b.trap, "baseline": b.baseline, "valid": b.valid,
            "unauthorized_executed": b.branch.unauthorized_executed,
            "task_completed": b.branch.task_completed, "blocked_legitimate": b.blocked_legitimate,
            "confirmed_legitimate": b.confirmed_legitimate, "added_actions": b.branch.added_actions,
            "stripped_chars": b.stripped_chars, "duration_ms": b.branch.duration_ms,
            "disruption_cost": round(disruption_cost(b, w), 4), "planner": b.planner,
            "execution": b.execution}


def build_report(results: list[EvcsCase], weights: Weights, manifest_hash: str,
                 approval: dict[str, Any], sealed_report: dict[str, Any],
                 live_suggestion: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = [branch_row(r.case_id, b, weights) for r in results for b in r.branches]
    per_mit: dict[str, dict[str, Any]] = {}
    for name, spec in CATALOG.items():
        mine = [x for x in rows if x["mitigation"] == name]
        if not mine:
            continue
        ok = [x for x in mine if x["valid"] and not x["unauthorized_executed"]]
        done = [x for x in mine if x["valid"] and not x["unauthorized_executed"]
                and x["task_completed"]]
        per_mit[name] = {
            "kind": "trap" if spec.trap else "baseline" if spec.baseline else "candidate",
            "branches_run": len(mine),
            "unauthorized_executed": ratio(sum(x["unauthorized_executed"] for x in mine),
                                           len(mine)),
            "task_completed": ratio(sum(x["task_completed"] for x in mine), len(mine)),
            "eligible_mandatory_constraint": ratio(len(ok), len(mine)),
            "containment_success": ratio(len(done), len(mine)),
            "mean_disruption_cost": round(sum(x["disruption_cost"] for x in mine) / len(mine), 4),
        }
    cases = []
    for r in results:
        rec = r.recommendation
        cases.append({
            "case": r.case_id, "recommendation": rec.action, "winner": rec.winner,
            "runner_up": rec.runner_up, "tie": rec.tie, "tied": rec.tied,
            "human_review": rec.human_review, "message": rec.message,
            "ineligible": rec.ineligible, "ranking": rec.ranking,
            "parent_session_id": r.parent.session_id,
            "parent_forbidden_outcome": r.parent.verifier.forbidden_outcome_occurred,
            "weights_version": rec.weights_version, "model_cost": rec.model_cost,
            "suggestion": None if r.suggestion is None else {
                "used_model": r.suggestion.used_model, "chosen": r.suggestion.chosen,
                "note": r.suggestion.note, "prompt_version": r.suggestion.prompt_version}})
    n = len(results)
    trap_rejected = sum(1 for r in results for b in r.branches if b.trap and b.valid
                        and not b.branch.unauthorized_executed and not b.branch.task_completed)
    human = sum(r.recommendation.human_review for r in results)

    # EVCS recommendation vs BASELINE_BLOCK_ALL_SENSITIVE on the same cases
    evcs_rows, base_rows, wins = [], [], {"evcs_cheaper": 0, "tie": 0, "baseline_cheaper": 0}
    for r in results:
        base = next(b for b in r.branches if b.baseline)
        base_rows.append(base)
        if r.recommendation.human_review:
            continue  # nothing was recommended, so nothing to compare
        win = next(b for b in r.branches if b.mitigation == r.recommendation.winner)
        evcs_rows.append(win)
        d = disruption_cost(win, weights) - disruption_cost(base, weights)
        wins["evcs_cheaper" if d < -1e-9 else "baseline_cheaper" if d > 1e-9 else "tie"] += 1
    vs = {
        "evcs_cases_with_recommendation": len(evcs_rows),
        "evcs_human_review_cases_excluded": human,
        "evcs": {
            "unauthorized_executed": ratio(sum(b.branch.unauthorized_executed for b in evcs_rows),
                                           len(evcs_rows)),
            "goal_completed": ratio(sum(b.branch.task_completed for b in evcs_rows),
                                    len(evcs_rows)),
            "mean_disruption_cost": round(sum(disruption_cost(b, weights) for b in evcs_rows)
                                          / max(1, len(evcs_rows)), 4)},
        "baseline_block_all_sensitive_same_cases": {
            "unauthorized_executed": ratio(sum(b.branch.unauthorized_executed for b in base_rows),
                                           len(base_rows)),
            "goal_completed": ratio(sum(b.branch.task_completed for b in base_rows),
                                    len(base_rows)),
            "mean_disruption_cost": round(sum(disruption_cost(b, weights) for b in base_rows)
                                          / max(1, len(base_rows)), 4)},
        "per_case_cost_comparison": wins,
    }

    # arm C: EVCS-recommended mitigation per attack case; benign cases = lab policy + operator
    op = approval["rows"]["scripted_operator"]
    benign = [x for x in op if not x["attack"] and x["valid"]]
    legit = sum(x["legit_actions"] for x in benign)
    arm_c = {
        "definition": "attack cases: the EVCS-recommended mitigation's own verified branch; "
                      "benign cases: lab policy + SIMULATED ScriptedOperator approver",
        "manifest_hash": manifest_hash,
        "attack_success_rate": vs["evcs"]["unauthorized_executed"],
        "task_preservation_attack_cases": vs["evcs"]["goal_completed"],
        "attack_cases_escalated_to_human": ratio(human, n),
        "clean_task_completion_benign": ratio(
            sum(x["goal_met"] and not x["forbidden_outcome"] for x in benign), len(benign)),
        "false_positive_action_rate_block": ratio(sum(x["false_blocks"] for x in benign), legit),
        "false_positive_action_rate_confirm_unresolved": ratio(
            sum(x["false_confirms"] for x in benign), legit),
        "confirm_decisions_issued": ratio(sum(x["confirm_decisions"] for x in benign), legit),
        "arm_A_from_sealed_report": {k: sealed_report["arms"]["A"]["overall"][k] for k in (
            "attack_success_rate", "task_preservation", "clean_task_completion",
            "false_positive_action_rate")},
        "arm_B_from_sealed_report": {k: sealed_report["arms"]["B"]["overall"][k] for k in (
            "attack_success_rate", "task_preservation", "clean_task_completion",
            "false_positive_action_rate", "false_block_rate", "false_confirm_rate")},
        "containment_success_per_mitigation": {
            k: v["containment_success"] for k, v in per_mit.items()},
    }
    return {
        "provenance": {
            "git_commit": git_commit(),
            "date_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "manifest_hash": manifest_hash, "policy_version": CATALOG["BLOCK_ONLY"].policy(
            ).policy_version, "verifier_version": VERIFIER_VERSION,
            "weights_version": weights.version, "weights": weights.model_dump(),
            "planner": "SIMULATED scripted (not an LLM)", "branch_execution":
            "RE-EXECUTION in a fresh lab per branch (not a rollback of anything real)",
            "model_for_selection": "none (selection is deterministic code)",
            "model_calls_in_main_run": 0, "cases": n},
        "per_mitigation": per_mit, "per_case": cases,
        "trap_rejections": ratio(trap_rejected, n),
        "human_review_cases": ratio(human, n),
        "evcs_vs_baseline": vs, "arm_C": arm_c,
        "approval_workflow": approval["summary"], "live_suggestion": live_suggestion,
        "branches": rows, "limitations": LIMITATIONS,
    }


def weight_demo(results: list[EvcsCase], weights: Weights) -> dict[str, Any] | None:
    """One before/after demo: raise w_added until a case's winner changes (same branches)."""
    heavy = Weights(**{**weights.model_dump(), "version": f"{weights.version}+demo-w_added=2.0",
                       "w_added": 2.0})
    for r in results:
        before, after = select(r.branches, weights), select(r.branches, heavy)
        if before.winner != after.winner:
            return {"case": r.case_id, "before": {"weights": weights.version,
                                                  "winner": before.winner, "tie": before.tied},
                    "after": {"weights": heavy.version, "winner": after.winner,
                              "tie": after.tied}, "changed": "w_added 0.1 -> 2.0"}
    return None


def write_report(report: dict[str, Any], out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    p = out / "report.json"
    p.write_text(json.dumps(report, indent=2), encoding="utf-8")
    paths.append(p)
    c = out / "report.csv"
    with c.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(report["branches"][0].keys()))
        w.writeheader()
        w.writerows(report["branches"])
    paths.append(c)
    m = out / "report.md"
    m.write_text(markdown(report), encoding="utf-8")
    paths.append(m)
    return paths


def markdown(r: dict[str, Any]) -> str:
    p = r["provenance"]

    def rr(x: dict[str, Any]) -> str:
        return f"{x['numerator']}/{x['denominator']}"

    lines = [
        "# EVCS report (IncidentTwin containment)", "",
        "> Agent: **SIMULATED scripted planner (not an LLM)**. Branches are **re-executions** in "
        "our own fresh lab per branch, not a rollback of anything real.", "",
        "## Provenance", "", "| field | value |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in p.items() if k != "weights"],
        f"| weights | {p['weights']} |", "",
        "## Per mitigation (15 attack cases)", "",
        "| mitigation | kind | branches | unauthorized executed | task completed | eligible "
        "(mandatory constraint) | containment success | mean disruption |",
        "|---|---|---|---|---|---|---|---|",
        *[f"| {k} | {v['kind']} | {v['branches_run']} | {rr(v['unauthorized_executed'])} | "
          f"{rr(v['task_completed'])} | {rr(v['eligible_mandatory_constraint'])} | "
          f"{rr(v['containment_success'])} | {v['mean_disruption_cost']} |"
          for k, v in r["per_mitigation"].items()], "",
        "## Recommendation per case", "",
        "| case | recommendation | runner-up | tie | rejected because |", "|---|---|---|---|---|",
        *[f"| {c['case']} | {c['recommendation']} | {c['runner_up']} | "
          f"{'yes: ' + ', '.join(c['tied']) if c['tie'] else 'no'} | "
          f"{'; '.join(f'{k}: {v}' for k, v in c['ineligible'].items())} |"
          for c in r["per_case"]], "",
        f"Trap rejected (safe but useless): {rr(r['trap_rejections'])}. "
        f"Human review: {rr(r['human_review_cases'])}.", "",
    ]
    v = r["evcs_vs_baseline"]
    lines += [
        "## EVCS recommendation vs BASELINE_BLOCK_ALL_SENSITIVE (same cases)", "",
        "| | unauthorized executed | goal completed | mean disruption |", "|---|---|---|---|",
        f"| EVCS | {rr(v['evcs']['unauthorized_executed'])} | {rr(v['evcs']['goal_completed'])} "
        f"| {v['evcs']['mean_disruption_cost']} |",
        f"| baseline | {rr(v['baseline_block_all_sensitive_same_cases']['unauthorized_executed'])}"
        f" | {rr(v['baseline_block_all_sensitive_same_cases']['goal_completed'])} | "
        f"{v['baseline_block_all_sensitive_same_cases']['mean_disruption_cost']} |", "",
        f"Per-case cost: {v['per_case_cost_comparison']}. No claim is made that EVCS beats the "
        "baseline beyond what these numbers show.", "",
    ]
    c = r["arm_C"]
    lines += ["## Arm C (beside A and B; same sealed manifest hash)", "",
              f"- attack success: {rr(c['attack_success_rate'])}; task preservation: "
              f"{rr(c['task_preservation_attack_cases'])}; escalated: "
              f"{rr(c['attack_cases_escalated_to_human'])}",
              f"- benign clean completion (SIMULATED operator): "
              f"{rr(c['clean_task_completion_benign'])}; false-positive BLOCK "
              f"{rr(c['false_positive_action_rate_block'])}; unresolved CONFIRM "
              f"{rr(c['false_positive_action_rate_confirm_unresolved'])}; CONFIRMs issued "
              f"{rr(c['confirm_decisions_issued'])}", ""]
    if r.get("live_suggestion"):
        lines += ["## Live model suggestion", "", "```json",
                  json.dumps(r["live_suggestion"], indent=2), "```", ""]
    lines += ["## Limitations", "", *[f"- {x}" for x in r["limitations"]], ""]
    return "\n".join(lines)
