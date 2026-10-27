"""Part A3: arm B (lab policy + page egress policy) over the sealed manifest's 30 cases with
AlwaysReject and with the SIMULATED ScriptedOperator. Prints numerators and denominators.
The sealed manifest and its hash are not modified. Agent: SIMULATED scripted planner (no model)."""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.containment.approval_eval import approval_check, summarize  # noqa: E402
from sentinelx.evaluation.manifest import load_manifest  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402


def main() -> int:
    manifest = load_manifest(ROOT / "evaluations" / "manifest.json")
    conn = connect(Path(tempfile.mkdtemp(prefix="approval-db-")) / "a.db")
    migrate(conn)
    result = approval_check(conn, progress=lambda line: print(line, flush=True))
    print(f"\nmanifest {manifest.manifest_hash} (unchanged)  planner: SIMULATED scripted")
    summary = {}
    for name, rows in result.items():
        s = summary[name] = summarize(rows)
        print(f"\n=== arm B + approver {name}: valid {s['benign_valid']} benign, "
              f"{s['attack_valid']} attack")
        for k in ("clean_completion", "benign_with_confirm", "false_confirms_resolved",
                  "attacks_approved", "attacks_with_forbidden_outcome", "attack_task_completed"):
            print(f"  {k:34} {s[k][0]}/{s[k][1]}")
    out = ROOT / "evaluations" / "example_report_evcs"
    out.mkdir(parents=True, exist_ok=True)
    (out / "approval_check.json").write_text(json.dumps(
        {"manifest_hash": manifest.manifest_hash, "planner": "SIMULATED scripted",
         "summary": summary, "rows": result}, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
