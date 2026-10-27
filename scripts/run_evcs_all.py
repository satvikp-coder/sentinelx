"""Part H: EVCS on ALL 15 hand-authored attack cases of the sealed manifest (SIMULATED scripted
planner, no model), plus the approval check, and the report in evaluations/example_report_evcs/.

Usage: python scripts/run_evcs_all.py [--out evaluations/example_report_evcs]
The optional live model suggestion is a separate script (scripts/run_evcs_suggest.py)."""

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.containment import load_weights, run_evcs_case  # noqa: E402
from sentinelx.containment.approval_eval import approval_check, summarize  # noqa: E402
from sentinelx.containment.report import (  # noqa: E402
    build_report,
    weight_demo,
    write_report,
)
from sentinelx.evaluation.cases import load_all_cases  # noqa: E402
from sentinelx.evaluation.manifest import load_manifest  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "evaluations" / "example_report_evcs"))
    args = ap.parse_args()
    manifest = load_manifest(ROOT / "evaluations" / "manifest.json")
    weights = load_weights()
    db = Path(tempfile.mkdtemp(prefix="evcs-all-")) / "evcs.db"
    conn = connect(db)
    migrate(conn)
    results = []
    for case in [c for c in load_all_cases() if c.is_attack]:
        r = run_evcs_case(conn, case)
        results.append(r)
        print(f"{case.id}: {r.recommendation.message}"
              + (f"  tie={r.recommendation.tied}" if r.recommendation.tie else ""), flush=True)
    rows = approval_check(conn, progress=None)
    approval = {"rows": rows, "summary": {k: summarize(v) for k, v in rows.items()}}
    sealed_path = ROOT / "evaluations" / "example_report" / "report.json"
    sealed = json.loads(sealed_path.read_text("utf-8"))
    report = build_report(results, weights, manifest.manifest_hash, approval, sealed)
    report["weight_demo"] = weight_demo(results, weights)
    paths = write_report(report, Path(args.out))
    print("\nreport files:", ", ".join(str(p) for p in paths))
    print("evidence db:", db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
