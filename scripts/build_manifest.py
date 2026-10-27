"""Build (and seal) evaluations/manifest.json from the hand-authored cases.

Usage: python scripts/build_manifest.py [--out PATH] [--name NAME] [--order-seed N]
                                        [--cases A01,B01,...] [--repetitions N]
The manifest pins every case (template + payload hash) and the lab policy version; editing any of
them afterwards changes the manifest hash (and the runner refuses a stale manifest).
"""

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.evaluation.manifest import build_manifest, write_manifest  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "evaluations" / "manifest.json"))
    ap.add_argument("--name", default="scenario-a-v1")
    ap.add_argument("--order-seed", type=int, default=20261027)
    ap.add_argument("--cases", default=None, help="comma-separated case ids (default: all)")
    ap.add_argument("--repetitions", type=int, default=1)
    args = ap.parse_args()
    ids = args.cases.split(",") if args.cases else None
    m = build_manifest(name=args.name, order_seed=args.order_seed, case_ids=ids,
                       repetitions=args.repetitions)
    write_manifest(m, args.out)
    print(f"wrote {args.out}: {len(m.cases)} cases, hash {m.manifest_hash}")


if __name__ == "__main__":
    main()
