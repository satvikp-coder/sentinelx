"""Run a Site Guard scan against ONE lab target: register -> verify -> recon -> hunt -> verify
candidates -> report. Resets the lab first (fresh, reproducible seeded state) and stops it when
done. Never scans anything but a lab target; the authorization gate enforces this on every
request regardless of what this script does.

Usage: python scripts/run_scan.py --target vibe_shop_php [--profile configs/scan/lab_default.yaml]
           [--model] [--out evaluations/scan_runs/<run>]
"""

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apps import labctl  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.model_clients import ModelClient, load_config  # noqa: E402
from sentinelx.scanner.authz import register_lab_target  # noqa: E402
from sentinelx.scanner.models import load_profile  # noqa: E402
from sentinelx.scanner.orchestrate import run_scan  # noqa: E402
from sentinelx.scanner.report import build_report, write_report  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, choices=sorted(labctl.LABS))
    ap.add_argument("--profile", default=str(ROOT / "configs" / "scan" / "lab_default.yaml"))
    ap.add_argument("--model", action="store_true", help="use the model for plan + explanations")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    print(f"resetting {args.target} to its seeded state ...")
    state_hash = labctl.reset(args.target)
    assert len(state_hash) == 64, f"unexpected state hash {state_hash!r}"
    lab = labctl.get(args.target)
    print(f"{args.target}: reset, state hash {state_hash[:16]}..., healthy at {lab.base_url}")

    profile = load_profile(args.profile)
    target = register_lab_target(args.target, ["127.0.0.1"], [lab.port])
    conn = connect(Path(tempfile.mkdtemp(prefix="scan-db-")) / "scan.db")
    migrate(conn)

    client = None
    model_info = {"provider": "none", "model": "none", "mode": "none"}
    if args.model:
        cfg = load_config()
        print("model config:", cfg.describe())
        if cfg.requires_key and not cfg.api_key.get_secret_value():
            print("MODEL_API_KEY is not set in .env: running without the model.")
        else:
            client = ModelClient(cfg)
            model_info = {"provider": cfg.provider, "model": cfg.model, "mode": "LIVE"}

    try:
        result = run_scan(target, profile, ROOT / "labs", args.target, conn, client=client,
                          use_model_for_plan=args.model, use_model_for_explanations=args.model)
    finally:
        if client is not None:
            client.close()
        labctl.down(args.target)

    report = build_report(result, target, profile, model_info if args.model else None)
    out_dir = Path(args.out) if args.out else ROOT / "evaluations" / "scan_runs" / (
        f"{args.target}-{result.session_id[:12]}")
    paths = write_report(report, out_dir)

    p = report["provenance"]
    print(f"\nsession {p['session_id']} | profile {p['profile_version']} "
          f"({p['profile_sha256'][:12]}) | stop reason: {p['stop_reason']}")
    print(f"requests {p['requests_used']}/{p['request_budget']} | coverage "
          f"{p['coverage_percent']}% | duration {p['duration_ms']} ms")
    print(f"plan: {result.plan.note}")
    if report["skipped_checks"]:
        print(f"skipped checks: {report['skipped_checks']}")
    print(f"\n{'vuln_class':32} {'confirmed':>9} {'needs_val':>9} {'rejected':>8}")
    for cls, counts in sorted(report["by_vuln_class"].items()):
        print(f"{cls:32} {counts.get('confirmed', 0):>9} {counts.get('needs_validation', 0):>9} "
              f"{counts.get('rejected', 0):>8}")
    print("\nreport files: " + ", ".join(str(x) for x in paths))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
