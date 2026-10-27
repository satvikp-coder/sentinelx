"""Generate bounded red-team variants with the real model (gen_prompt_v1) and seal a SEPARATE
manifest (evaluations/manifest_generated.json). The model only writes plain text for an approved
slot; every candidate passes the static safety checker; labels come from the hand-authored seed.

Usage: python scripts/generate_variants.py [--seeds A01,A15]
           [--surfaces visible_text,role_spoofing,misleading_workflow_notice]
           [--length 220] [--candidates 3] [--attempts 3] [--record]
Reads provider / model / key from .env (never printed).
"""

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.adversarial import (  # noqa: E402
    build_generated_case,
    generate_variants,
    load_seed_spec,
    write_generated_case,
)
from sentinelx.common_schemas import Surface  # noqa: E402
from sentinelx.evaluation.cases import load_all_cases  # noqa: E402
from sentinelx.evaluation.manifest import build_manifest, write_manifest  # noqa: E402
from sentinelx.model_clients import ModelClient, load_config  # noqa: E402

TONES = ["formal", "urgent", "friendly", "technical"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="A01,A15")
    ap.add_argument("--surfaces", default="visible_text,role_spoofing,misleading_workflow_notice")
    ap.add_argument("--length", type=int, default=220)
    ap.add_argument("--candidates", type=int, default=3)
    ap.add_argument("--attempts", type=int, default=3)
    ap.add_argument("--start-index", type=int, default=1,
                    help="first G-number to use (never overwrites unless the number repeats)")
    ap.add_argument("--skip-indices", default="", help="comma list of G-numbers to leave untouched")
    ap.add_argument("--record", action="store_true", help="save cassettes of the model replies")
    args = ap.parse_args()

    cfg = load_config()
    cfg = cfg.model_copy(update={"record_cassettes": args.record})
    print("model config:", cfg.describe())
    if cfg.requires_key and not cfg.api_key.get_secret_value():
        print("MODEL_API_KEY is not set in .env: nothing generated.")
        return 2
    client = ModelClient(cfg)
    seeds = {c.id: c.template for c in load_all_cases()}
    rejected: Counter[str] = Counter()
    candidates_total = accepted_total = calls = 0
    made: list[str] = []
    index = args.start_index - 1
    skip = {int(x) for x in args.skip_indices.split(",") if x}
    try:
        for seed_id in args.seeds.split(","):
            spec = load_seed_spec(seed_id)
            for surface_name in args.surfaces.split(","):
                surface = Surface(surface_name)
                index += 1
                while index in skip:
                    index += 1
                tone = TONES[(index - 1) % len(TONES)]
                chosen = None
                for attempt in range(1, args.attempts + 1):
                    out = generate_variants(client, seeds[seed_id], spec, surface, tone,  # type: ignore[arg-type]
                                            args.length, args.candidates)
                    calls += 1
                    print(f"\n[{seed_id} x {surface_name} x {tone}] attempt {attempt}: "
                          f"model {out.model_result.status.value} "
                          f"({out.model_result.latency_ms:.0f} ms, "
                          f"{out.model_result.tokens_in}+{out.model_result.tokens_out} tokens)")
                    if out.model_result.error:
                        print("   model error:", out.model_result.error)
                    for c in out.candidates:
                        candidates_total += 1
                        accepted_total += c.accepted
                        mark = "ACCEPT" if c.accepted else "REJECT"
                        print(f"   {mark}: {c.text[:110]!r}")
                        for r in c.reasons:
                            rejected[r.split(":")[0].split("(")[0].strip()] += 1
                            print(f"           - {r}")
                    if out.accepted:
                        chosen = (out, out.accepted[0].text)
                        break
                if chosen is None:
                    print(f"   -> no safe variant for {seed_id} x {surface_name}; skipped")
                    index -= 0
                    continue
                case = build_generated_case(seeds[seed_id], chosen[0], chosen[1], index)
                paths = write_generated_case(case)
                made.append(case.template.id)
                print(f"   -> wrote {case.template.id} ({paths[0].name}, {paths[1].name})")
    finally:
        client.close()
    print("\n=== generation summary ===")
    print(f"model calls: {calls}; candidates: {candidates_total}; "
          f"passed the safety checker: {accepted_total}; rejected: "
          f"{candidates_total - accepted_total}")
    for reason, n in rejected.most_common():
        print(f"   rejected for '{reason}': {n}")
    print(f"generated cases kept: {len(made)} -> {made}")
    if made:
        neighbors = sorted({seeds[s].benign_neighbor_id for s in args.seeds.split(",")})
        manifest = build_manifest(name="generated-v1", order_seed=20261028,
                                  case_ids=[*made, *neighbors], source="generated")
        out_path = ROOT / "evaluations" / "manifest_generated.json"
        write_manifest(manifest, out_path)
        print(f"separate manifest: {out_path.name}  hash {manifest.manifest_hash}  "
              f"({len(manifest.cases)} cases: {len(made)} generated + controls {neighbors})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
