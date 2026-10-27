"""Fixed subset of the GENERATED manifest, same rule as the sealed subset: per attack surface the
lexicographically first generated attack id plus its benign neighbour (the seed's control).
Writes evaluations/manifest_generated_subset.json (own hash; generated cases only)."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.evaluation.cases import load_all_cases  # noqa: E402
from sentinelx.evaluation.manifest import build_manifest, write_manifest  # noqa: E402

RULE = ("SUBSET of the MODEL-GENERATED variants (separate from the sealed hand-authored manifest). "
        "Per attack surface the lexicographically first generated attack case id plus its benign "
        "neighbour (the seed's control). Chosen before any result; cases are never swapped.")


def main() -> None:
    first: dict[str, tuple[str, str]] = {}
    gen = [c for c in load_all_cases(include_generated=True) if c.id.startswith("G")]
    for c in sorted(gen, key=lambda c: c.id):
        first.setdefault(c.template.surface.value, (c.id, c.neighbor_id))
    ids = list(dict.fromkeys(i for pair in sorted(first.values()) for i in pair))
    manifest = build_manifest(name="generated-subset-v1", order_seed=20261029, case_ids=ids,
                              source="generated", selection_rule=RULE)
    out = ROOT / "evaluations" / "manifest_generated_subset.json"
    write_manifest(manifest, out)
    print(f"wrote {out.name} hash {manifest.manifest_hash}; cases {sorted(ids)}")


if __name__ == "__main__":
    main()
