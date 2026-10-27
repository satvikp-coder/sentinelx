"""Run a manifest with the MODEL-DRIVEN planner (REAL LLM, arms A and B), never the scripted one.

Usage: python scripts/run_model_experiment.py --manifest evaluations/manifest.json
           [--repetitions 1] [--out-root evaluations/runs] [--run-id ID] [--example-dir DIR]
           [--wall-clock 300] [--run-call-cap 10] [--expected-calls-per-run 6]
           [--record] [--estimate-only] [--force-all]

Prints a CALL-BUDGET ESTIMATE before any model call. If the expected calls exceed the experiment
ceiling (MODEL_EXPERIMENT_CALL_CEILING, default 400) a stratified subset (attack + its benign
neighbour pairs, spread over families) is run instead and the report says so. The synthetic lab
token is deliberately allowed into prompts (lab-only; every other secret is still redacted).
Provider, model and key come from .env (the key is never printed).
"""

import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.evaluation.manifest import load_manifest  # noqa: E402
from sentinelx.evaluation.planners import ModelPlannerFactory  # noqa: E402
from sentinelx.evaluation.runner import run_experiment  # noqa: E402
from sentinelx.model_clients import ModelClient, load_config  # noqa: E402

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


def stratified_pairs(cases, max_runs: int, arms: int, reps: int) -> list[str]:
    """Attack + benign-neighbour pairs, round-robin over families, until the run budget is hit."""
    by_family: dict[str, list] = {}
    for c in cases:
        if c.label == "attack":
            by_family.setdefault(str(c.family), []).append(c)
    chosen: list[str] = []
    queues = [list(v) for _, v in sorted(by_family.items())]
    per_pair = 2 * arms * reps
    while queues and (len(chosen) + 2) * arms * reps <= max_runs:
        for q in list(queues):
            if (len(chosen) + 2) * arms * reps > max_runs:
                break
            a = q.pop(0)
            chosen += [a.case_id, a.neighbor_id]
            if not q:
                queues.remove(q)
    del per_pair
    return list(dict.fromkeys(chosen))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--repetitions", type=int, default=1)
    ap.add_argument("--out-root", default=str(ROOT / "evaluations" / "runs"))
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--example-dir", default=None)
    ap.add_argument("--wall-clock", type=float, default=300.0)
    ap.add_argument("--run-call-cap", type=int, default=10)
    ap.add_argument("--expected-calls-per-run", type=float, default=6.0)
    ap.add_argument("--record", action="store_true", help="save cassettes of model replies")
    ap.add_argument("--estimate-only", action="store_true")
    ap.add_argument("--force-all", action="store_true", help="ignore the ceiling (still enforced)")
    args = ap.parse_args()

    cfg = load_config()
    cfg = cfg.model_copy(update={"allow_synthetic_token_in_prompts": True,
                                 "run_call_cap": args.run_call_cap,
                                 "record_cassettes": args.record})
    print("model config:", cfg.describe())
    if cfg.requires_key and not cfg.api_key.get_secret_value():
        print("MODEL_API_KEY is not set in .env: no run (MODEL_UNAVAILABLE).")
        return 2
    manifest = load_manifest(args.manifest)
    arms = len(manifest.arms)
    reps = args.repetitions
    total_runs = len(manifest.cases) * arms * reps
    expected = total_runs * args.expected_calls_per_run
    worst = total_runs * cfg.run_call_cap
    ceiling = cfg.experiment_call_ceiling
    print("\n=== CALL-BUDGET ESTIMATE (before any model call) ===")
    print(f"cases {len(manifest.cases)} x arms {arms} x repetitions {reps} = {total_runs} runs")
    print(f"expected model calls ~ {expected:.0f} ({args.expected_calls_per_run:g}/run); "
          f"worst case {worst} ({cfg.run_call_cap}/run cap); ceiling {ceiling}; "
          f"latency ~3-12 s/call at {cfg.max_rpm} req/min max")
    only = None
    if expected > ceiling and not args.force_all:
        max_runs = int(ceiling // args.expected_calls_per_run)
        from sentinelx.evaluation.cases import load_all_cases
        cases = [c for c in load_all_cases(include_generated=manifest.source == "generated")
                 if c.id in {m.case_id for m in manifest.cases}]
        wrapped = [type("C", (), {"label": c.label, "family": getattr(c.template, "family", ""),
                                  "case_id": c.id, "neighbor_id": c.neighbor_id})()
                   for c in cases]
        only = stratified_pairs(wrapped, max_runs, arms, reps)
        print(f"OVER CEILING -> STRATIFIED SUBSET of {len(only)} cases: {only}")
    else:
        print("within ceiling -> running the FULL manifest")
    if args.estimate_only:
        return 0
    # the hard stop is the printed worst case for what will actually run, so a slow run cannot
    # silently turn later runs into MODEL_UNAVAILABLE; the SELECTION above used the ceiling
    n_runs = (len(only) * arms * reps) if only else total_runs
    cfg = cfg.model_copy(update={"experiment_call_ceiling": max(1, n_runs * cfg.run_call_cap)})

    client = ModelClient(cfg)
    try:
        result = run_experiment(
            args.manifest, args.out_root, repetitions=reps, run_id=args.run_id,
            planner_factory=ModelPlannerFactory(client),
            budget_overrides={"wall_clock_seconds": args.wall_clock}, only_cases=only,
            progress=lambda line: print(line, flush=True))
    finally:
        client.close()
    report = result.report
    prov = report["provenance"]
    print(f"\nrun {prov['run_id']} | manifest {prov['manifest_hash']}")
    print(f"policy {prov['policy_version']} | verifier {prov['verifier_version']}")
    print(f"planner: {prov['planner']} | provider {prov.get('provider')} | model {prov['model']} "
          f"| mode {prov.get('mode')} | prompt {prov.get('prompt_version')}")
    for arm, a in report["arms"].items():
        print(f"\n=== arm {arm}: {report['manifest']['arms'][arm]}")
        print(f"valid runs {a['runs_valid']}/{a['runs_total']} "
              f"({a['attack_valid']} attack, {a['benign_valid']} benign), "
              f"invalid {len(a['invalid'])}")
        for key, label in SUMMARY:
            m = a["overall"][key]
            shown = "n/a (" + m["note"] + ")" if m["value"] is None else f"{m['value']:.3f}"
            print(f"  {label:38} {m['numerator']:>3}/{m['denominator']:<3} = {shown}")
        print("  model usage:", report["model_usage"].get(arm))
    print(f"\ninvalid runs: {report['invalid_runs']['total']}")
    print("report files: " + ", ".join(str(p) for p in result.report_paths))
    if args.example_dir:
        dest = Path(args.example_dir)
        dest.mkdir(parents=True, exist_ok=True)
        for p in result.report_paths:
            shutil.copy2(p, dest / p.name)
        print(f"report copied to {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
