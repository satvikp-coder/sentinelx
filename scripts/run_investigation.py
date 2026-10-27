"""Investigate a FIXED set of stored sessions with the live model (one call each) AND with the
deterministic baseline, verify both independently and print the numbers.

Fixed set (rule chosen before running): the unprotected (A) and protected (B) sessions of the first
3 attack cases (lexicographic by case id) of the given model run. Failed runs are included and
reported as they are. The run's evidence database is COPIED first; the original is not touched.

Usage: python scripts/run_investigation.py --run-dir evaluations/runs/model-subset-1
           [--cases 3] [--out-dir evaluations/example_investigation] [--no-model]
Provider, model and key come from .env (the key is never printed).
"""

import argparse
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinelx.evidence.db import connect  # noqa: E402
from sentinelx.investigator import citation_fidelity, investigate  # noqa: E402
from sentinelx.model_clients import ModelClient, load_config  # noqa: E402


def copy_db(src: Path, dst: Path) -> sqlite3.Connection:
    if dst.exists():
        dst.unlink()
    dst.parent.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(f"file:{src.as_posix()}?mode=ro", uri=True)
    target = sqlite3.connect(dst)
    source.backup(target)
    source.close()
    target.close()
    return connect(dst)


def show(label: str, inv) -> dict:
    v = inv.verification
    f = inv.finding
    print(f"\n--- {label}: mode={inv.mode} state={v.state.value} severity={f.severity.value} "
          f"citation {v.citation_numerator}/{v.citation_denominator}")
    if inv.note:
        print("    NOTE:", inv.note)
    for claim, res in zip(f.claims, v.claims, strict=True):
        print(f"    [{res.claim_id}] {claim.kind:8} {'PASS' if res.passed else 'FAIL'} "
              f"{res.code:20} {claim.text[:100]}")
        if not res.passed:
            print(f"          -> {res.detail}")
    for reason in v.reasons:
        print("    reason:", reason)
    return {"mode": inv.mode, "state": v.state.value, "severity": f.severity.value,
            "numerator": v.citation_numerator, "denominator": v.citation_denominator,
            "note": inv.note, "summary": f.finding,
            "claims": [{"id": r.claim_id, "kind": c.kind, "passed": r.passed, "code": r.code,
                        "detail": r.detail, "text": c.text, "cited": c.cited_event_ids,
                        "assertion": c.assertion.model_dump() if c.assertion else None,
                        "confidence": c.confidence}
                       for c, r in zip(f.claims, v.claims, strict=True)],
            "mitigations": f.recommended_mitigations}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--cases", type=int, default=3)
    ap.add_argument("--out-dir", default=str(ROOT / "evaluations" / "example_investigation"))
    ap.add_argument("--no-model", action="store_true")
    args = ap.parse_args()
    run_dir = Path(args.run_dir)
    records = [json.loads(line) for line in (run_dir / "runs.jsonl").read_text("utf-8").splitlines()
               if line.strip()]
    attack_ids = sorted({r["case_id"] for r in records if r["case_id"].startswith(("A", "G"))})
    chosen = attack_ids[:args.cases]
    work = Path(args.out_dir)
    conn = copy_db(run_dir / "evidence.db", work / "evidence_copy.db")

    client = None
    if not args.no_model:
        cfg = load_config()
        print("model config:", cfg.describe())
        if cfg.requires_key and not cfg.api_key.get_secret_value():
            print("MODEL_API_KEY is not set in .env: baseline only.")
        else:
            client = ModelClient(cfg)
    print(f"fixed set: attack cases {chosen} x arms A,B from {run_dir.name}")
    out: list[dict] = []
    model_v, base_v = [], []
    fallbacks: list[str] = []
    try:
        for case_id in chosen:
            for arm in ("A", "B"):
                rec = next((r for r in records if r["case_id"] == case_id and r["arm"] == arm),
                           None)
                if rec is None or not rec.get("session_id"):
                    print(f"\n--- {case_id} arm {arm}: no session recorded; skipped")
                    continue
                sid = rec["session_id"]
                base = investigate(conn, sid, None, store_result=False)
                t0 = time.perf_counter()
                inv = investigate(conn, sid, client) if client else base
                wall = (time.perf_counter() - t0) * 1000
                mr = inv.model_result
                print(f"\n=== {case_id} arm {arm} session {sid[:16]} run-valid={rec['valid']} "
                      f"state={rec.get('invalid_reason') or 'ok'}")
                shown = show("INVESTIGATION", inv)
                shown_base = show("BASELINE (same session)", base)
                if inv.mode == "MODEL":
                    model_v.append(inv.verification)
                    base_v.append(base.verification)
                elif client:
                    fallbacks.append(f"{case_id}/{arm}: {inv.note}")
                if mr is not None:
                    print(f"    model: status={mr.status.value} provider={mr.provider} "
                          f"model={mr.model} mode={mr.mode.value} latency={mr.latency_ms:.0f} ms "
                          f"tokens {mr.tokens_in}+{mr.tokens_out} http_calls={mr.http_calls} "
                          f"retries={mr.retries} repair={mr.repair_attempts} wall={wall:.0f} ms")
                out.append({"case": case_id, "arm": arm, "session_id": sid,
                            "run_valid": rec["valid"], "investigation": shown,
                            "baseline": shown_base,
                            "model_call": None if mr is None else {
                                "status": mr.status.value, "provider": mr.provider,
                                "model": mr.model, "mode": mr.mode.value,
                                "latency_ms": round(mr.latency_ms), "tokens_in": mr.tokens_in,
                                "tokens_out": mr.tokens_out, "http_calls": mr.http_calls,
                                "error": mr.error}})
    finally:
        if client:
            client.close()
        conn.close()
    n_model = len(model_v)
    print("\n=== citation fidelity ===")
    num, den = citation_fidelity(model_v)
    print(f"MODEL-mode findings   : {num}/{den} claims verified  ({n_model} findings)")
    num_b, den_b = citation_fidelity(base_v)
    print(f"BASELINE (same sessions as the model-mode ones): {num_b}/{den_b}")
    all_base = [o["baseline"] for o in out]
    nb = sum(o["numerator"] for o in all_base)
    db = sum(o["denominator"] for o in all_base)
    print(f"BASELINE (all {len(all_base)} sessions): {nb}/{db}")
    print(f"fell back to baseline: {len(fallbacks)} of {len(out)}")
    for line in fallbacks:
        print("   ", line)
    work.mkdir(parents=True, exist_ok=True)
    (work / "investigations.json").write_text(json.dumps({
        "run_dir": run_dir.name, "cases": chosen, "findings": out,
        "model_fidelity": [num, den], "baseline_fidelity_same_sessions": [num_b, den_b],
        "baseline_fidelity_all": [nb, db], "fallbacks": fallbacks}, indent=2), encoding="utf-8")
    shutil.copy2(work / "investigations.json", work / "investigations.copy.json")
    (work / "investigations.copy.json").unlink()
    print("written:", work / "investigations.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
