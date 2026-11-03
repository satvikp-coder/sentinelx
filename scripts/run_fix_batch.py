"""Part G: select findings BY RULE (never cherry-picked after the fact) and run the fix engine
against them for real, with the Baseten Spark Open profile (NVIDIA Glimmer fallback, labelled).

Selection rule, per lab: the first confirmed AUTO-class finding of each of 3 different
vuln_classes (sorted lexicographically by class, then by finding id), plus 1 confirmed
NEEDS_HUMAN-class finding (lexicographically first class, lowest id) to show the escalation
path. At most 6 AUTO findings total across both labs (3 per lab) + up to 1 NEEDS_HUMAN per lab.

Usage: python scripts/run_fix_batch.py --php-scan <report.json> --node-scan <report.json>
           [--out evaluations/example_fix_report] [--db evaluations/fix_runs/fix.sqlite]
"""

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.fixer.orchestrate import run_fix  # noqa: E402
from sentinelx.fixer.policy import load_fix_policy  # noqa: E402
from sentinelx.model_clients import ModelClient, load_models_config, resolve_task  # noqa: E402


def select_findings(report: dict, policy, *, max_auto: int = 3) -> tuple[list[dict], dict | None]:
    confirmed = [f for f in report["findings"] if f["verification"]["state"] == "confirmed"]
    by_class: dict[str, list[dict]] = {}
    for f in confirmed:
        by_class.setdefault(f["candidate"]["vuln_class"], []).append(f)
    for cls in by_class:
        by_class[cls].sort(key=lambda f: f["candidate"]["id"])

    auto_classes = sorted(c for c in by_class
                          if (e := policy.entries.get(c)) and e.decision == "AUTO")
    human_classes = sorted(c for c in by_class
                           if (e := policy.entries.get(c)) and e.decision == "NEEDS_HUMAN")
    selected = [by_class[c][0] for c in auto_classes[:max_auto]]
    needs_human = by_class[human_classes[0]][0] if human_classes else None
    return selected, needs_human


def run_one(finding: dict, lab: str, conn, client, policy, original_findings, models_config,
            profile_name: str, patch_format: str | None = None) -> dict:
    start = time.monotonic()
    outcome = run_fix(finding, lab=lab, conn=conn, client=client, policy=policy,
                      original_findings=original_findings, models_config=models_config,
                      profile_name=profile_name, patch_format=patch_format)
    elapsed_s = time.monotonic() - start
    return {
        "lab": lab, "finding_id": outcome.finding_id, "vuln_class": outcome.vuln_class,
        "status": outcome.status, "patch_id": outcome.patch_id, "ticket_id": outcome.ticket_id,
        "retries_used": outcome.retries_used, "elapsed_s": round(elapsed_s, 1),
        "patch_format": patch_format or getattr(policy, "patch_format", "diff"),
        "diagnosis": outcome.diagnosis.model_dump(mode="json") if outcome.diagnosis else None,
        "diff": outcome.patch.diff if outcome.patch else None,
        "explanation": outcome.patch.explanation if outcome.patch else None,
        "patch_status": outcome.patch.status if outcome.patch else None,
        "patch_reasons": outcome.patch.reasons if outcome.patch else [],
        "verification": [
            {"name": c.result.name, "passed": c.result.passed, "duration_ms": c.duration_ms,
             "excerpt": c.result.output_excerpt}
            for c in outcome.verification.checks] if outcome.verification else [],
        "verification_status": (outcome.verification.status.value
                                if outcome.verification else None),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--php-scan", required=True)
    ap.add_argument("--node-scan", required=True)
    ap.add_argument("--out", default=str(ROOT / "evaluations" / "example_fix_report"))
    ap.add_argument("--db", default=str(ROOT / "evaluations" / "fix_runs" / "fix.sqlite"))
    ap.add_argument("--patch-format", choices=["edits", "diff"], default=None,
                    help="Patch format for this batch (default: the configured patch_format)")
    args = ap.parse_args()

    policy = load_fix_policy()
    php_report = json.loads(Path(args.php_scan).read_text(encoding="utf-8"))
    node_report = json.loads(Path(args.node_scan).read_text(encoding="utf-8"))

    php_selected, php_human = select_findings(php_report, policy)
    node_selected, node_human = select_findings(node_report, policy)
    batch: list[tuple[str, dict, list]] = (
        [("vibe_shop_php", f, php_report["findings"]) for f in php_selected]
        + ([("vibe_shop_php", php_human, php_report["findings"])] if php_human else [])
        + [("vibe_notes_node", f, node_report["findings"]) for f in node_selected]
        + ([("vibe_notes_node", node_human, node_report["findings"])] if node_human else []))

    print("selected findings (by rule, not cherry-picked):")
    for lab, f, _ in batch:
        print(f"  {lab}: {f['candidate']['id']} ({f['candidate']['vuln_class']})")

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(Path(args.db))
    migrate(conn)
    models_config = load_models_config()
    routed = resolve_task(conn, models_config, "patch_generation")
    if routed.status != "OK":
        print(f"MODEL_UNAVAILABLE for patch_generation: {routed.detail}")
        return 2
    print(f"\nmodel profile: {routed.profile_name}"
         f"{' (FALLBACK - primary unavailable)' if routed.fallback_used else ''}\n")
    client = ModelClient(routed.config)

    results = []
    try:
        for lab, finding, original_findings in batch:
            print(f"running {lab} / {finding['candidate']['id']} ...")
            result = run_one(finding, lab, conn, client, policy, original_findings,
                             models_config, routed.profile_name, patch_format=args.patch_format)
            results.append(result)
            print(f"  -> {result['status']} ({result['elapsed_s']}s, "
                 f"{result['retries_used']} retries)")
    finally:
        client.close()

    from sentinelx.model_clients import check_budget

    budget = check_budget(conn, models_config, routed.profile_name)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "provenance": {
            "model_profile": routed.profile_name, "fallback_used": routed.fallback_used,
            "fix_policy_version": policy.policy_version, "generated_at_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "spend": {"spent_usd": budget.spent_usd, "hard_cap_usd": budget.hard_cap_usd,
                  "remaining_usd": budget.remaining_usd},
        "results": results,
        "limitations": [
            "This batch was selected BY RULE (first 3 AUTO classes + 1 NEEDS_HUMAN per lab, "
            "lexicographic) before any run - no cherry-picking of good results afterwards.",
            "Verification measures the scanner's own check plus the lab's benign traffic, not "
            "completeness of security - a VERIFIED patch is not a guarantee of no other bugs.",
            "NEEDS_HUMAN findings are never auto-fixed, regardless of verification outcome.",
            "Estimated spend is computed from Baseten's published per-token prices, not a real "
            "invoice - check the Baseten dashboard for the actual bill.",
            "The sample is small (2 labs, up to 8 findings); it demonstrates the mechanism, not "
            "statistical confidence in the fixer's overall success rate.",
        ],
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {out_dir / 'report.json'}")
    print(f"spend: ${budget.spent_usd:.5f} / ${budget.hard_cap_usd:.2f} "
         f"(${budget.remaining_usd:.5f} remaining)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
