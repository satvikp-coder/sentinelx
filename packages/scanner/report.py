"""Scan report: report.json, report.md, coverage-ledger.json. No PLANTED.json / ground truth
here - scoring against it happens afterwards, in `sentinelx.evaluation.scan_scoring`."""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx.common_schemas import TargetAuthorization

from .model_assist import EXPLAIN_PROMPT_VERSION, PLAN_PROMPT_VERSION
from .models import SiteScanProfile
from .orchestrate import ScanResult

REPO = Path(__file__).resolve().parents[2]
SCANNER_VERSION = "scanner-1.0"
LIMITATIONS = [
    "Lab-only synthetic targets: non-lab scanning is disabled by the authorization gate.",
    "The scanner and the labs were authored in the same project: recall measures how well this "
    "scanner finds weaknesses planted in OUR OWN labs, not its performance against real sites.",
    "Behavioural findings (missing_rate_limit) are weaker evidence than a structural "
    "reproduction and never reach the 'confirmed' state; they stay 'needs_validation'.",
    "A confirmed finding that matches no planted class/endpoint is reported separately for "
    "manual review; it may be a real, unplanted weakness and is never counted as a false "
    "positive automatically.",
    "No claim of complete coverage is made; the coverage ledger lists every unexercised cell "
    "and why.",
    "The model, when used, only orders/selects checks from the fixed catalog and writes "
    "explanations of already-confirmed findings; it never decides what is vulnerable.",
]


def git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
                              text=True, check=True).stdout.strip()
    except Exception:
        return "unknown"


def build_report(result: ScanResult, target: TargetAuthorization, profile: SiteScanProfile,
                 model_info: dict[str, Any] | None) -> dict[str, Any]:
    by_class: dict[str, Counter[str]] = {}
    for f in result.findings:
        by_class.setdefault(f.candidate.vuln_class.value, Counter())[f.verification.state] += 1
    provenance = {
        "git_commit": git_commit(), "date_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scanner_version": SCANNER_VERSION, "profile_name": profile.name,
        "profile_version": profile.profile_version, "profile_sha256": profile.sha256,
        "target_id": target.target_id, "target_lab": target.lab,
        "authz_status": target.status.value, "session_id": result.session_id,
        "coverage_percent": result.coverage.coverage_percent,
        "requests_used": result.requests_used, "request_budget": profile.request_budget,
        "duration_ms": round(result.duration_ms, 1), "stop_reason": result.stop_reason,
        "plan_prompt_version": PLAN_PROMPT_VERSION if result.plan.used_model else None,
        "explain_prompt_version": EXPLAIN_PROMPT_VERSION if result.explain.used_model else None,
        "model": model_info or {"provider": "none", "model": "none", "mode": "none"},
    }
    return {
        "provenance": provenance,
        "plan": {"checks": result.plan.checks, "used_model": result.plan.used_model,
                 "note": result.plan.note},
        "explain": {"used_model": result.explain.used_model, "note": result.explain.note,
                    "count": len(result.explain.explanations)},
        "skipped_checks": result.skipped_checks,
        "by_vuln_class": {k: dict(v) for k, v in by_class.items()},
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "coverage_ledger": result.coverage.model_dump(mode="json"),
        "limitations": LIMITATIONS,
    }


def markdown(report: dict[str, Any]) -> str:
    p = report["provenance"]
    lines = [
        f"# Scan report - {p['target_id']}", "",
        "## Provenance", "", "| field | value |", "|---|---|",
        *[f"| {k} | {v} |" for k, v in p.items()], "",
        "## Findings by class", "", "| vuln_class | confirmed | needs_validation | rejected |",
        "|---|---|---|---|",
        *[f"| {k} | {v.get('confirmed', 0)} | {v.get('needs_validation', 0)} | "
          f"{v.get('rejected', 0)} |" for k, v in report["by_vuln_class"].items()], "",
        f"## Coverage: {p['coverage_percent']}%", "",
        f"Skipped checks: {report['skipped_checks'] or 'none'}", "",
        "## Limitations", "", *[f"- {x}" for x in report["limitations"]], "",
    ]
    return "\n".join(lines)


def write_report(report: dict[str, Any], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    j = out_dir / "report.json"
    j.write_text(json.dumps(report, indent=2), encoding="utf-8")
    paths.append(j)
    m = out_dir / "report.md"
    m.write_text(markdown(report), encoding="utf-8")
    paths.append(m)
    c = out_dir / "coverage-ledger.json"
    c.write_text(json.dumps(report["coverage_ledger"], indent=2), encoding="utf-8")
    paths.append(c)
    return paths
