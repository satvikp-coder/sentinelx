"""Optional live model role (containment_prompt_v1): ONE suggestion call per case for the first 3
attack case ids (lexicographic). The model only chooses which candidate mitigations to TRY; the
selection stays deterministic code. Unavailable/invalid model -> the full catalog, said so.

Usage: python scripts/run_evcs_suggest.py [--cases 3] [--report-dir evaluations/example_report_evcs]
Reads provider / model / key from .env (the key is never printed). Does not run the investigator
or the planner with the model."""

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.containment import load_weights, run_evcs_case  # noqa: E402
from sentinelx.containment.report import markdown  # noqa: E402
from sentinelx.evaluation.cases import load_all_cases  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.model_clients import ModelClient, load_config  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=3)
    ap.add_argument("--report-dir", default=str(ROOT / "evaluations" / "example_report_evcs"))
    args = ap.parse_args()
    report_dir = Path(args.report_dir)
    report_path = report_dir / "report.json"
    full = {c["case"]: c for c in json.loads(report_path.read_text("utf-8"))["per_case"]}
    cfg = load_config()
    print("model config:", cfg.describe())
    if cfg.requires_key and not cfg.api_key.get_secret_value():
        print("MODEL_API_KEY is not set in .env: the full catalog would be used (no live run).")
        return 2
    client = ModelClient(cfg)
    conn = connect(Path(tempfile.mkdtemp(prefix="evcs-suggest-")) / "s.db")
    migrate(conn)
    ids = sorted(c.id for c in load_all_cases() if c.is_attack)[:args.cases]
    out = []
    try:
        for cid in ids:
            case = next(c for c in load_all_cases() if c.id == cid)
            r = run_evcs_case(conn, case, client=client, weights=load_weights())
            s = r.suggestion
            full_winner = full[cid]["winner"]
            item = {
                "case": cid, "mode": "LIVE" if s and s.used_model else "FALLBACK (full catalog)",
                "provider": s.result.provider if s and s.result else None,
                "model": s.result.model if s and s.result else None,
                "prompt_version": s.prompt_version if s else None,
                "status": s.result.status.value if s and s.result else None,
                "latency_ms": round(s.result.latency_ms) if s and s.result else None,
                "tokens_in": s.result.tokens_in if s and s.result else None,
                "tokens_out": s.result.tokens_out if s and s.result else None,
                "model_subset": s.chosen if s else None, "note": s.note if s else None,
                "full_catalog_winner": full_winner,
                "subset_included_full_catalog_winner": (full_winner in s.chosen) if s else None,
                "winner_with_subset": r.recommendation.winner,
                "human_review": r.recommendation.human_review,
                "branches_run": [b.mitigation for b in r.branches]}
            out.append(item)
            print(json.dumps(item, indent=2), flush=True)
    finally:
        client.close()
    report = json.loads(report_path.read_text("utf-8"))
    report["live_suggestion"] = {
        "label": "LIVE model suggestion, one call per case; selection remains deterministic code",
        "cases": out}
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    (report_dir / "report.md").write_text(markdown(report), encoding="utf-8")
    inc = sum(bool(i["subset_included_full_catalog_winner"]) for i in out)
    print(f"\nmodel subset included the full-catalog winner in {inc}/{len(out)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
