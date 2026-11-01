"""Run the Site Guard fix engine against a lab's own, already-scanned, confirmed findings.

Usage:
  python scripts/run_fix.py --target vibe_shop_php --scan-report <report.json>
      [--findings cand_sql_injection_0001 ...] [--max 6]
  python scripts/run_fix.py --approve patch_abc123 --reviewer "satvik"
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.fixer.ladder import apply_approved  # noqa: E402
from sentinelx.fixer.orchestrate import load_scope_record, run_fix  # noqa: E402
from sentinelx.fixer.policy import load_fix_policy  # noqa: E402
from sentinelx.model_clients import ModelClient, load_models_config, resolve_task  # noqa: E402

DEFAULT_DB = ROOT / "evaluations" / "fix_runs" / "fix.sqlite"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target")
    ap.add_argument("--scan-report")
    ap.add_argument("--findings", nargs="*", default=None)
    ap.add_argument("--max", type=int, default=6)
    ap.add_argument("--approve")
    ap.add_argument("--reviewer", default="developer")
    ap.add_argument("--patch-format", choices=["edits", "diff"], default=None,
                    help="Patch format for this run (default: the configured "
                         "patch_format in configs/fix/policy.yaml, currently 'diff')")
    ap.add_argument("--db", default=str(DEFAULT_DB))
    args = ap.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    conn = connect(Path(args.db))
    migrate(conn)

    if args.approve:
        lab, scope = load_scope_record(args.approve)
        approval_id = apply_approved(conn, patch_id=args.approve, lab=lab, scope=scope,
                                     reviewer=args.reviewer)
        print(f"approved {args.approve} -> {approval_id}; applied to "
             f"labs_applied/{lab}/current/")
        return 0

    if not args.target or not args.scan_report:
        ap.error("--target and --scan-report are required unless --approve is given")

    findings = json.loads(Path(args.scan_report).read_text(encoding="utf-8"))["findings"]
    confirmed = [f for f in findings if f["verification"]["state"] == "confirmed"]
    if args.findings:
        confirmed = [f for f in confirmed if f["candidate"]["id"] in set(args.findings)]
    confirmed = confirmed[: args.max]

    models_config = load_models_config()
    routed = resolve_task(conn, models_config, "patch_generation")
    if routed.status != "OK":
        print(f"MODEL_UNAVAILABLE for patch_generation: {routed.detail}")
        return 2
    print(f"model profile: {routed.profile_name}"
         f"{' (fallback)' if routed.fallback_used else ''}")
    client = ModelClient(routed.config)
    policy = load_fix_policy()

    try:
        for f in confirmed:
            cand = f["candidate"]
            outcome = run_fix(f, lab=args.target, conn=conn, client=client, policy=policy,
                             original_findings=findings, models_config=models_config,
                             profile_name=routed.profile_name,
                             patch_format=args.patch_format)
            print(f"{cand['id']} ({cand['vuln_class']}): {outcome.status} "
                 f"patch={outcome.patch_id} ticket={outcome.ticket_id} "
                 f"retries={outcome.retries_used}")
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
