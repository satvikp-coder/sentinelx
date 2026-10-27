"""Run a sealed manifest: every case x arm x repetition, paired and order-randomised.

Usage: python scripts/run_experiment.py --manifest evaluations/manifest.json
           [--repetitions N] [--out-root evaluations/runs] [--run-id ID]
           [--expect-hash SHA256] [--example-dir DIR]
The agent is a SCRIPTED, SIMULATED planner (no model). Reports are written to
<out-root>/<run_id>/report.{json,csv,md}; raw run folders are gitignored.
"""

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # `apps` (the lab) is imported from the repo root

from sentinelx.evaluation.runner import run_experiment  # noqa: E402

SUMMARY = (
    ("attack_success_rate", "ASR (forbidden outcome in ledger)"),
    ("attempt_rate", "attempt rate"),
    ("attack_block_rate", "attack block rate"),
    ("task_preservation", "task preservation"),
    ("clean_task_completion", "clean task completion (benign)"),
    ("false_positive_action_rate", "false-positive action rate"),
    ("false_block_rate", "  of which BLOCK"),
    ("false_confirm_rate", "  of which CONFIRM"),
)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--repetitions", type=int, default=None)
    ap.add_argument("--out-root", default=str(ROOT / "evaluations" / "runs"))
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--expect-hash", default=None)
    ap.add_argument("--example-dir", default=None, help="copy the report files here")
    args = ap.parse_args()
    result = run_experiment(args.manifest, args.out_root, repetitions=args.repetitions,
                            run_id=args.run_id, expected_hash=args.expect_hash,
                            progress=lambda line: print(line, flush=True))
    report = result.report
    prov = report["provenance"]
    print()
    print(f"run {prov['run_id']} | manifest {prov['manifest_hash']}")
    print(f"policy {prov['policy_version']} | verifier {prov['verifier_version']} | "
          f"planner: {prov['planner']} | model: {prov['model']}")
    for arm, a in report["arms"].items():
        print()
        print(f"=== arm {arm}: {report['manifest']['arms'][arm]}")
        print(f"valid runs {a['runs_valid']}/{a['runs_total']} "
              f"({a['attack_valid']} attack, {a['benign_valid']} benign), "
              f"invalid {len(a['invalid'])}")
        for key, label in SUMMARY:
            m = a["overall"][key]
            print(f"  {label:38} {m['numerator']:>3}/{m['denominator']:<3} = {m['value']:.3f}")
    print()
    print(f"invalid runs: {report['invalid_runs']['total']}")
    print("report files: " + ", ".join(str(p) for p in result.report_paths))
    if args.example_dir:
        dest = Path(args.example_dir)
        dest.mkdir(parents=True, exist_ok=True)
        for p in result.report_paths:
            shutil.copy2(p, dest / p.name)
        print(f"example report copied to {dest}")


if __name__ == "__main__":
    main()
