"""Report generation: report.json, report.csv, report.md (with provenance and limitations).

``assert_complete`` makes report generation FAIL if any rate lacks its numerator and
denominator (or claims a value over a zero denominator)."""

from __future__ import annotations

import csv
import io
import json
import subprocess
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx.verifier import VERIFIER_VERSION

from .manifest import ARM_DESCRIPTIONS, REPO_ROOT, Manifest
from .metrics import MetricError, compute_arm_metrics, latency_summary
from .records import PlannerInfo, RunRecord

LIMITATIONS = [
    "The agent is a SCRIPTED, deliberately gullible simulation. It is not an LLM and says "
    "nothing about how any real model behaves.",
    "Results show how the implemented controls behave against THESE specific hand-authored "
    "cases. They say nothing about unseen attacks, other fixtures, or real models.",
    "Counts are small (tens of cases, one repetition by default); rates carry large uncertainty "
    "and no confidence intervals are claimed.",
    "No claim of complete protection is made. A 0% attack success rate here means these cases "
    "were stopped, not that other attacks would be.",
    "Arm B's static policy was written knowing the lab; the false-positive and false-confirm "
    "numbers show its cost on these benign cases only.",
    "Latency figures measure a local sqlite/Playwright prototype on one machine; they are not "
    "production performance claims.",
]


MODEL_LIMITATIONS = [
    "The agent is a REAL language model (see provenance for provider, model and mode), driven "
    "by one fixed prompt (prompt_v1). Results describe THIS model, THIS prompt and THIS date; "
    "another model, prompt or sampling seed can behave differently.",
    "Model output is nondeterministic (temperature 1.0): with one repetition per case each "
    "number is a single sample, so small differences between arms are not evidence. Counts are "
    "small (tens of cases) and no confidence intervals are claimed.",
    "Results show how the controls behave against THESE hand-authored cases. They say nothing "
    "about unseen attacks, adaptive attackers, other tasks or other models. No claim of complete "
    "protection is made.",
    "The attack text was NOT tuned to the model: a low unprotected attack success rate means "
    "this model resisted these particular texts, not that the attacks are harmless.",
    "The system prompt contains a generic notice that page content is untrusted data, and the "
    "user notes name the pages/endpoints to use; both make the model more resistant than a bare "
    "agent would be. The user-requested answer format is part of the goal assertion.",
    "Arm B's static policy was written knowing the lab; the false-positive and false-confirm "
    "numbers show its cost on these benign cases only.",
    "The hosted trial endpoint has undocumented rate limits and variable latency; runs that hit "
    "MODEL_UNAVAILABLE are invalid, excluded from rates and counted. Latency figures are for "
    "this endpoint on this day and are not production claims.",
]


def limitations_for(planner: PlannerInfo) -> list[str]:
    return MODEL_LIMITATIONS if planner.is_llm else LIMITATIONS


class ReportIncomplete(MetricError):
    """A rate lacks its numerator/denominator (or contradicts itself)."""


def git_info() -> dict[str, Any]:
    def run(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, text=True,
                              check=True, timeout=10).stdout.strip()

    try:
        return {"commit": run("rev-parse", "HEAD"), "dirty": bool(run("status", "--porcelain"))}
    except Exception:
        return {"commit": "unknown", "dirty": None}


def build_report(records: list[RunRecord], manifest: Manifest, run_id: str,
                 *, git: dict[str, Any] | None = None) -> dict[str, Any]:
    planners = {r.planner.model_dump_json() for r in records}
    if len(planners) != 1:
        raise ReportIncomplete(
            "a report covers exactly ONE planner; SIMULATED and model-driven runs (or different "
            f"models/prompts) must be reported separately, found {len(planners)}")
    planner = records[0].planner
    arms = {arm: compute_arm_metrics(records, arm) for arm in manifest.arms}
    policy_versions = sorted(
        {r.policy_version for r in records if r.policy_version and r.arm == "B"})
    verifier_versions = sorted({r.verifier_version for r in records if r.verifier_version})
    report: dict[str, Any] = {
        "provenance": {
            "run_id": run_id,
            "git": git or git_info(),
            "date_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "manifest_hash": manifest.manifest_hash,
            "manifest_name": manifest.name,
            "policy_version": policy_versions[0] if len(policy_versions) == 1 else policy_versions,
            "verifier_version": (verifier_versions[0] if len(verifier_versions) == 1
                                 else verifier_versions or VERIFIER_VERSION),
            "planner": planner.label,
            "model": planner.model,
            "provider": planner.provider,
            "mode": ("SIMULATED (no model, no LLM)" if not planner.is_llm
                     else f"{planner.mode} (real LLM)"),
            "prompt_version": planner.prompt_version,
            "reasoning_effort": planner.reasoning_effort,
            "order_seed": manifest.order_seed,
            "repetitions": manifest.repetitions,
        },
        "manifest": {
            "cases": len(manifest.cases),
            "attacks": sum(c.label == "attack" for c in manifest.cases),
            "benign": sum(c.label == "benign" for c in manifest.cases),
            "arms": {a: ARM_DESCRIPTIONS[a] for a in manifest.arms},
            "selection_rule": manifest.selection_rule or None,
        },
        "arms": {arm: m.as_dict() for arm, m in arms.items()},
        "model_usage": ({arm: model_usage(records, arm) for arm in manifest.arms}
                        if planner.is_llm else None),
        "pairing": pairing_check(records),
        "invalid_runs": {
            "total": sum(len(m.invalid) for m in arms.values()),
            "runs": [dict(arm=arm, **inv) for arm, m in arms.items() for inv in m.invalid],
        },
        "limitations": limitations_for(planner),
    }
    assert_complete(report)
    return report


def model_usage(records: Iterable[RunRecord], arm: str) -> dict[str, Any]:
    """Calls, tokens and model latency for one arm (counts ALL runs, valid or not)."""
    runs = [r for r in records if r.arm == arm]
    latencies = [x for r in runs for x in r.model_latency_ms]
    return {
        "runs": len(runs),
        "model_http_calls": sum(r.model_calls for r in runs),
        "tokens_in": sum(r.model_tokens_in for r in runs),
        "tokens_out": sum(r.model_tokens_out for r in runs),
        "rate_limit_hits": sum(r.model_rate_limit_hits for r in runs),
        "retries": sum(r.model_retries for r in runs),
        "invalid_outputs": sum(r.model_invalid_outputs for r in runs),
        "latency": latency_summary(latencies),
    }


def pairing_check(records: Iterable[RunRecord]) -> dict[str, Any]:
    by_pair: dict[tuple[str, int], dict[str, RunRecord]] = {}
    for r in records:
        by_pair.setdefault((r.case_id, r.rep), {})[r.arm] = r
    both = {k: v for k, v in by_pair.items() if {"A", "B"} <= set(v)}
    valid_both = {k: v for k, v in both.items() if v["A"].valid and v["B"].valid}
    mismatches = sorted(f"{k[0]}#{k[1]}" for k, v in valid_both.items()
                        if v["A"].fixture_hash != v["B"].fixture_hash
                        or v["A"].seed != v["B"].seed)
    return {"pairs": len(by_pair), "pairs_with_both_arms": len(both),
            "pairs_both_valid": len(valid_both), "fixture_or_seed_mismatches": mismatches}


def assert_complete(node: Any, path: str = "report") -> None:
    """Raise ReportIncomplete if any rate dict lacks numerator/denominator or lies."""
    if isinstance(node, dict):
        rate_keys = {"numerator", "denominator", "value"} & set(node)
        if rate_keys:
            missing = {"numerator", "denominator", "value"} - set(node)
            if missing:
                raise ReportIncomplete(f"{path}: rate is missing {sorted(missing)}")
            num, den, val = node["numerator"], node["denominator"], node["value"]
            if not isinstance(num, int) or not isinstance(den, int):
                raise ReportIncomplete(f"{path}: numerator/denominator must be integers")
            if den == 0:
                if val is not None or not node.get("note"):
                    raise ReportIncomplete(f"{path}: zero denominator needs value=None and a note")
            elif val is None or abs(val - num / den) > 1e-5:
                raise ReportIncomplete(f"{path}: value does not equal numerator/denominator")
        for key, child in node.items():
            assert_complete(child, f"{path}.{key}")
    elif isinstance(node, list):
        for i, child in enumerate(node):
            assert_complete(child, f"{path}[{i}]")


# ------------------------------------------------------------------ renderers
def _is_rate(d: Any) -> bool:
    return isinstance(d, dict) and {"numerator", "denominator", "value"} <= set(d)


def csv_rows(report: dict[str, Any]) -> list[list[Any]]:
    rows: list[list[Any]] = []

    def emit(arm: str, scope: str, key: str, metrics: dict[str, Any]) -> None:
        for name, m in metrics.items():
            if _is_rate(m):
                rows.append([arm, scope, key, name, m["numerator"], m["denominator"], m["value"],
                             m.get("note", "")])

    for arm, a in report["arms"].items():
        emit(arm, "overall", "-", a["overall"])
        emit(arm, "benign_page_requests", "-", {"benign_runs_with_blocked_page_requests":
                                                a["benign_page_request_blocks"]})
        for scope in ("by_surface", "by_scenario"):
            for key, metrics in a[scope].items():
                emit(arm, scope, key, metrics)
        emit(arm, "stopped_by_rule", "-", a["stopped_by_rule"])
    return rows


def render_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["arm", "scope", "key", "metric", "numerator", "denominator", "value", "note"])
    w.writerows(csv_rows(report))
    return buf.getvalue()


def _fmt(m: dict[str, Any]) -> str:
    if m["denominator"] == 0:
        return f"n/a ({m['note']})"
    return f"{m['numerator']}/{m['denominator']} = {m['value']:.3f}"


def render_markdown(report: dict[str, Any]) -> str:
    p = report["provenance"]
    lines = [
        f"# Experiment report: {p['manifest_name']}", "",
        ("**The agent is a SCRIPTED, SIMULATED, deliberately gullible planner (not an LLM). "
         "Model: none.**") if p["model"] == "none" else
        (f"**The agent is a REAL language model: {p['planner']}. Provider: {p['provider']}. "
         f"Model: {p['model']}. Mode: {p['mode']}.**"),
        "", "## Provenance", "",
        "| field | value |", "|---|---|",
        f"| run id | `{p['run_id']}` |",
        f"| git commit | `{p['git']['commit']}` (dirty: {p['git']['dirty']}) |",
        f"| date (UTC) | {p['date_utc']} |",
        f"| manifest hash | `{p['manifest_hash']}` |",
        *([f"| SUBSET | {report['manifest']['cases']} cases. "
           f"{report['manifest']['selection_rule']} |"]
          if report["manifest"].get("selection_rule") else []),
        f"| policy version | `{p['policy_version']}` |",
        f"| verifier version | `{p['verifier_version']}` |",
        f"| planner | {p['planner']} |",
        f"| model / provider | {p['model']} / {p['provider']} |",
        f"| prompt version | {p.get('prompt_version')} |",
        f"| reasoning setting | {p.get('reasoning_effort')} |",
        f"| mode | {p['mode']} |",
        f"| order seed / repetitions | {p['order_seed']} / {p['repetitions']} |", "",
        f"Cases: {report['manifest']['attacks']} attack + {report['manifest']['benign']} benign. "
        + "; ".join(f"arm {a} = {d}" for a, d in report["manifest"]["arms"].items()), "",
    ]
    for arm, a in report["arms"].items():
        lines += [f"## Arm {arm}: {report['manifest']['arms'][arm]}", "",
                  f"Runs: {a['runs_valid']} valid of {a['runs_total']} "
                  f"({a['attack_valid']} attack, {a['benign_valid']} benign); "
                  f"invalid: {len(a['invalid'])}", "", "| metric | numerator / denominator |",
                  "|---|---|"]
        lines += [f"| {k} | {_fmt(v)} |" for k, v in a["overall"].items()]
        lines += [f"| {k} | {_fmt(a['benign_page_request_blocks'])} |"
                  for k in ("benign runs with a blocked page request",)]
        usage = (report.get("model_usage") or {}).get(arm)
        if usage:
            lat = usage["latency"]
            lines += ["", "**Model usage**", "",
                      f"- HTTP calls: {usage['model_http_calls']} (retries {usage['retries']}, "
                      f"rate-limit hits {usage['rate_limit_hits']}, invalid outputs "
                      f"{usage['invalid_outputs']})",
                      f"- tokens: {usage['tokens_in']} in / {usage['tokens_out']} out",
                      "- model latency: " + (f"n={lat['n']}, insufficient sample" if "note" in lat
                                            else f"n={lat['n']}, p50 {lat['p50_ms']} ms, "
                                                 f"p95 {lat['p95_ms']} ms")]
        lines += ["", "**Latency**", ""]
        for name, s in a["latency"].items():
            lines.append(f"- {name}: n={s['n']}, " + ("insufficient sample" if "note" in s else
                         f"p50 {s['p50_ms']} ms, p95 {s['p95_ms']} ms"))
        for title, scope in (("By surface", "by_surface"), ("By scenario", "by_scenario")):
            lines += ["", f"**{title}**", "",
                      "| group | runs | ASR | attempt | block | preservation | clean completion |",
                      "|---|---|---|---|---|---|---|"]
            for key, g in a[scope].items():
                cells = [_fmt(g[m]) if m in g else "-" for m in (
                    "attack_success_rate", "attempt_rate", "attack_block_rate", "task_preservation",
                    "clean_task_completion")]
                lines.append(f"| {key} | {g['runs']} | " + " | ".join(cells) + " |")
        lines += ["", "**Which control stopped forbidden attempts (attack runs)**", "",
                  "| control | runs |", "|---|---|"]
        lines += [f"| {k} | {_fmt(v)} |" for k, v in a["stopped_by_rule"].items()]
        lines += ["", "**All real non-ALLOW decisions by rule (attack + benign)**", "",
                  "| rule | count |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in a["decisions_by_rule"].items()] or ["| - | 0 |"]
        lines += [""]
    pr = report["pairing"]
    lines += ["## Pairing and invalid runs", "",
              f"- pairs: {pr['pairs']}, with both arms: {pr['pairs_with_both_arms']}, "
              f"both valid: {pr['pairs_both_valid']}",
              f"- fixture/seed mismatches between paired arms: {pr['fixture_or_seed_mismatches']}",
              f"- invalid runs (excluded from rates, counted): {report['invalid_runs']['total']}"]
    lines += [f"  - {r['arm']} {r['case_id']}#{r['rep']}: {r['reason']}"
              for r in report["invalid_runs"]["runs"]]
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in report["limitations"]] + [""]
    return "\n".join(lines)


def write_report(report: dict[str, Any], run_dir: str | Path) -> list[Path]:
    assert_complete(report)  # refuse to write anything for an incomplete report
    d = Path(run_dir)
    d.mkdir(parents=True, exist_ok=True)
    paths = [d / "report.json", d / "report.csv", d / "report.md"]
    paths[0].write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8",
                        newline="\n")
    paths[1].write_text(render_csv(report), encoding="utf-8", newline="\n")
    paths[2].write_text(render_markdown(report), encoding="utf-8", newline="\n")
    return paths


def numbers_signature(report: dict[str, Any]) -> str:
    """Everything except latency, run ids, dates and git info: equal for reproducible runs."""
    arms = json.loads(json.dumps(report["arms"], sort_keys=True))
    for a in arms.values():
        a.pop("latency", None)
        for inv in a.get("invalid", []):
            inv.pop("run_id", None)
    stable = {"arms": arms, "pairing": report["pairing"],
              "manifest_hash": report["provenance"]["manifest_hash"]}
    return json.dumps(stable, sort_keys=True)
