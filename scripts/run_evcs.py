"""Re-run EVCS for one attack case and print the branch table (SIMULATED scripted planner).

Usage: python scripts/run_evcs.py --case A04 [--mitigations BLOCK_ONLY,LIMIT_NAVIGATION]
           [--weights configs/containment/weights.yaml] [--approver scripted_operator]
Branches are RE-EXECUTIONS in our own lab (fresh server and ledger per branch), not a rollback of
anything real. The recommendation is chosen by deterministic code from verifier-judged branches.
"""

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.containment import load_weights, run_evcs_case  # noqa: E402
from sentinelx.containment.selection import disruption_cost  # noqa: E402
from sentinelx.evaluation.cases import load_case  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402


def print_case(r, weights) -> None:
    print(f"\ncase {r.case_id}: parent session {r.parent.session_id[:16]} "
          f"(verifier: forbidden outcome occurred={r.parent.verifier.forbidden_outcome_occurred})")
    print(f"checkpoint {r.parent.checkpoint.ref}  planner: SIMULATED scripted  "
          f"weights {weights.version}  approver {r.approver}")
    head = f"{'mitigation':32} {'unauth':>6} {'task':>5} {'blk':>3} {'cnf':>3} {'add':>3} "
    print(head + f"{'strip':>5} {'cost':>6} {'eligible':>8}  note")
    for b in r.branches:
        why = r.recommendation.ineligible.get(b.mitigation, "")
        ok = b.mitigation in dict(r.recommendation.ranking)
        print(f"{b.mitigation:32} {int(b.branch.unauthorized_executed):>6} "
              f"{int(b.branch.task_completed):>5} {b.blocked_legitimate:>3} "
              f"{b.confirmed_legitimate:>3} {b.branch.added_actions:>3} {b.stripped_chars:>5} "
              f"{disruption_cost(b, weights):>6.2f} {str(ok):>8}  {why}")
    rec = r.recommendation
    print(f"-> {rec.message}" + (f"  (runner-up {rec.runner_up}; tie {rec.tied})" if not
                                 rec.human_review else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case", required=True)
    ap.add_argument("--mitigations", default=None)
    ap.add_argument("--weights", default=None)
    ap.add_argument("--approver", default="scripted_operator")
    ap.add_argument("--seed", type=int, default=None, help="unused: cases carry their own seed")
    args = ap.parse_args()
    case = load_case(args.case)
    if case is None or not case.is_attack:
        print(f"{args.case} is not a hand-authored attack case")
        return 2
    weights = load_weights(args.weights) if args.weights else load_weights()
    conn = connect(Path(tempfile.mkdtemp(prefix="evcs-db-")) / "evcs.db")
    migrate(conn)
    names = args.mitigations.split(",") if args.mitigations else None
    print_case(run_evcs_case(conn, case, mitigations=names, weights=weights,
                             approver_name=args.approver), weights)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
