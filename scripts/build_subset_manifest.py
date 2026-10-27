"""Build evaluations/manifest_subset.json: a FIXED subset of the sealed manifest.

RULE (fixed before any model result): for each of the 8 attack surfaces take the lexicographically
first attack case id and its benign neighbour. If that is more than 16 cases, drop surfaces from
the end of the alphabet until 10-12 remain. Time rule: the projection uses the MEASURED mean
per-call latency and calls/run from the aborted run; while the projection exceeds the limit the
same rule drops one more surface from the end of the alphabet (never below 10 cases).
Cases are never swapped after results exist.

Usage: python scripts/build_subset_manifest.py [--mean-latency-s 40] [--calls-per-run 4.5]
           [--limit-min 60]
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.evaluation.cases import load_all_cases  # noqa: E402
from sentinelx.evaluation.manifest import build_manifest, load_manifest, write_manifest  # noqa: E402

RULE = ("SUBSET of the sealed manifest (hash {sealed}). For each of the 8 attack surfaces take the "
        "lexicographically first attack case id and its benign neighbour (16 cases); if more than "
        "16 drop surfaces from the end of the alphabet until 10-12 remain; if the projected time "
        "exceeds {limit} min (measured mean {lat:g} s/call, {cpr:g} calls/run) the same rule drops "
        "further surfaces from the end of the alphabet, never below 10 cases. Chosen before any "
        "result of this subset; cases are never swapped afterwards. Surfaces kept: {kept}.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mean-latency-s", type=float, default=40.0)
    ap.add_argument("--calls-per-run", type=float, default=4.5)
    ap.add_argument("--limit-min", type=float, default=60.0)
    args = ap.parse_args()
    sealed = load_manifest(ROOT / "evaluations" / "manifest.json").manifest_hash
    first: dict[str, tuple[str, str]] = {}
    for c in sorted((c for c in load_all_cases() if c.label == "attack"), key=lambda c: c.id):
        first.setdefault(c.template.surface.value, (c.id, c.neighbor_id))
    surfaces = sorted(first)
    assert len(surfaces) == 8, surfaces
    kept = list(surfaces)
    while True:
        cases = 2 * len(kept)
        minutes = cases * 2 * args.calls_per_run * args.mean_latency_s / 60
        calls = cases * 2 * args.calls_per_run
        print(f"{len(kept)} surfaces / {cases} cases -> {calls:.0f} calls, "
              f"~{minutes:.0f} min projected")
        if cases > 16 or (minutes > args.limit_min and cases > 10):
            kept.pop()
            continue
        break
    ids = [i for s in kept for i in first[s]]
    manifest = build_manifest(
        name="subset-v1", order_seed=20261028, case_ids=ids,
        selection_rule=RULE.format(sealed=sealed[:16], limit=args.limit_min,
                                   lat=args.mean_latency_s, cpr=args.calls_per_run,
                                   kept=", ".join(f"{k}={first[k][0]}+{first[k][1]}"
                                         for k in kept)))
    out = ROOT / "evaluations" / "manifest_subset.json"
    write_manifest(manifest, out)
    print(f"wrote {out.name} hash {manifest.manifest_hash}; cases {sorted(ids)}")


if __name__ == "__main__":
    main()
