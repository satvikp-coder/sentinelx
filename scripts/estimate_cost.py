"""Dry-run cost estimator for a budgeted model profile (Prompt 9 Part 0.6.b). Prints
calls x worst-case tokens -> worst-case dollars, and REFUSES (nonzero exit) a batch whose
worst case would push spend past (hard_cap - already_spent - reserved). This is an ESTIMATE
from the profile's published prices, not a bill - check the Baseten dashboard for the real one.

Usage: python scripts/estimate_cost.py --profile baseten_spark_open --calls 6
           --tokens-in 2000 --tokens-out 1500 [--db evaluations/model_usage.sqlite]
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.model_clients import check_budget, estimate_cost, load_models_config  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--calls", type=int, required=True)
    ap.add_argument("--tokens-in", type=int, required=True, help="worst-case input tokens/call")
    ap.add_argument("--tokens-out", type=int, required=True, help="worst-case output tokens/call")
    ap.add_argument("--cached-tokens", type=int, default=0, help="worst-case cached input/call")
    ap.add_argument("--db", default=str(ROOT / "evaluations" / "model_usage.sqlite"))
    args = ap.parse_args()

    config = load_models_config()
    profile = config.profiles.get(args.profile)
    if profile is None:
        print(f"ERROR: no profile {args.profile!r} in configs/models.yaml")
        return 2

    per_call = estimate_cost(profile, args.tokens_in, args.tokens_out, args.cached_tokens)
    worst_case_total = per_call * args.calls
    print(f"{args.calls} calls x worst-case ({args.tokens_in} in / {args.tokens_out} out"
         f"{f' / {args.cached_tokens} cached' if args.cached_tokens else ''} tokens) "
         f"@ {profile.name} -> ${worst_case_total:.4f} worst case (${per_call:.4f}/call)")
    if not profile.price_per_1m.verified:
        print(f"NOTE: {profile.name}'s prices are UNVERIFIED (placeholder) - "
             f"{profile.price_per_1m.note or 'no published rate found'}")

    conn = connect(Path(args.db))
    migrate(conn)
    bc = check_budget(conn, config, args.profile)
    if bc.status == "UNBUDGETED":
        print(f"{profile.name} has no configured budget - nothing to check against.")
        return 0
    budget = config.budget[args.profile]
    usable_remaining = bc.remaining_usd - budget.reserved_usd if bc.remaining_usd else 0.0
    print(f"spend so far: ${bc.spent_usd:.4f} / ${bc.hard_cap_usd:.2f} hard cap "
         f"(${budget.reserved_usd:.2f} reserved, never spent by experiments) "
         f"-> ${usable_remaining:.4f} usable before this batch")

    if bc.status == "BUDGET_EXHAUSTED":
        print("REFUSED: the hard cap is already reached.")
        return 1
    if worst_case_total > usable_remaining:
        print(f"REFUSED: worst case (${worst_case_total:.4f}) exceeds the usable remaining "
             f"budget (${usable_remaining:.4f}).")
        return 1
    print("OK: worst case fits within the usable remaining budget.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
