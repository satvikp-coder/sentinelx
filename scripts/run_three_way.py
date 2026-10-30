#!/usr/bin/env python3
"""Run three-way shield evaluation against vibe_notes_node.

Three arms:
  A: Direct to lab (no shield) - raw httpx to lab
  B: Shield in monitor mode - through shield proxy (if running)
  C: Shield in enforce mode with auto_shield - through shield proxy (if running)

Note: Shield proxy integration is not complete. Arms B and C currently
run without a running shield proxy, so they behave like Arm A.
Results are reported honestly with this limitation noted.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx


def run_hacker_simulator(base_url: str, target_id: str) -> dict:
    """Run hacker simulator directly against lab (no shield proxy)."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts.hacker_sim import run_simulation

    result = run_simulation(
        base_url=base_url,
        target_id=target_id,
        shield_proxy=None,
        shield_mode="monitor",
        auto_shield=False,
    )

    attack_results = []
    for r in result.attack_results:
        attack_results.append({
            "stage": r.stage,
            "sent": r.requests_sent,
            "blocked_by_marker": 0,  # No shield proxy running
            "blocked_by_lab": r.requests_blocked,
            "reached_upstream": r.requests_reached_upstream,
            "latency_p50": r.latency_p50,
            "latency_p95": r.latency_p95,
        })

    return {
        "attack_results": attack_results,
        "benign_sent": result.benign_sent,
        "benign_blocked_by_marker": 0,
        "benign_blocked_by_lab": result.benign_blocked,
        "benign_altered": result.benign_altered,
        "intent_accuracy": result.intent_accuracy,
        "rules_proposed": result.rules_proposed,
        "rules_activated": result.rules_activated,
        "rules_rejected": result.rules_rejected,
        "rules_expired": result.rules_expired,
        "escalations_created": result.escalations_created,
        "shield_latency_p50": None,
        "shield_latency_p95": None,
    }


def save_report(results: dict, output_dir: Path):
    """Save report to evaluations/example_shield_report/."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save report.json
    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "note": "Shield proxy not running; Arms B and C same as Arm A. Shield proxy integration incomplete.",
        "scenarios": results,
    }
    with open(output_dir / "report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)

    # Save report.md
    md = generate_markdown_report(results)
    with open(output_dir / "report.md", "w") as f:
        f.write(md)


def generate_markdown_report(results: dict) -> str:
    md = ["# Shield Evaluation Report\n"]
    md.append(f"Generated: {datetime.now(UTC).isoformat()}\n")
    md.append("**Note**: Shield proxy not running; Arms B and C same as Arm A (direct to lab).\n")
    md.append("Shield proxy integration incomplete; honest metrics reported.\n\n")

    md.append("## Three-Way Comparison\n\n")
    md.append("| Metric | A: No Shield | B: Monitor | C: Enforce+Auto |\n")
    md.append("|--------|-------------|------------|-----------------|\n")

    for scenario_key, label in [("A", "A: No Shield"), ("B", "B: Monitor"), ("C", "C: Enforce+Auto")]:
        if scenario_key in results:
            r = results[scenario_key]
            total_sent = sum(s["sent"] for s in r["attack_results"])
            total_blocked_by_marker = sum(s["blocked_by_marker"] for s in r["attack_results"])
            total_blocked_by_lab = sum(s["blocked_by_lab"] for s in r["attack_results"])
            total_reached = sum(s["reached_upstream"] for s in r["attack_results"])
            benign_sent = r["benign_sent"]
            benign_blocked_by_marker = r["benign_blocked_by_marker"]
            benign_altered = r["benign_altered"]

            md.append(f"| {label} | sent={total_sent} blocked_by_shield={total_blocked_by_marker} blocked_by_lab={total_blocked_by_lab} reached={total_reached} | benign sent={benign_sent} blocked_by_shield={benign_blocked_by_marker} altered={r['benign_altered']} |\n")

    md.append("\n## Per-Stage Breakdown\n\n")
    md.append("| Stage | A: sent/blocked_by_shield/blocked_by_lab/reached | B: sent/blocked_by_shield/blocked_by_lab/reached | C: sent/blocked_by_shield/blocked_by_lab/reached |\n")
    md.append("|-------|-----------------------------------------------|-----------------------------------------------|-----------------------------------------------|\n")

    stages = ["recon", "failed_logins", "object_enum", "injection", "admin_probe"]
    for stage in stages:
        row = f"| {stage} |"
        for scenario_key in ["A", "B", "C"]:
            if scenario_key in results:
                for s in results[scenario_key]["attack_results"]:
                    if s["stage"] == stage:
                        row += f" {s['sent']}/{s['blocked_by_marker']}/{s['blocked_by_lab']}/{s['reached_upstream']} |"
                        break
        md.append(row + "\n")

    md.append("\n## Intent Accuracy\n\n")
    for scenario_key in ["A", "B", "C"]:
        if scenario_key in results:
            md.append(f"- {scenario_key}: {results[scenario_key]['intent_accuracy']:.2f}\n")

    md.append("\n## Time to Protect (seconds from first malicious request to first ACTIVE rule)\n\n")
    md.append("| Stage | A | B | C |\n")
    md.append("|-------|---|---|---|\n")
    for stage in ["recon", "failed_logins", "object_enum", "injection", "admin_probe"]:
        md.append(f"| {stage} | n/a | n/a | not protected |\n")

    md.append("\n## Benign Traffic Impact\n\n")
    for scenario_key in ["A", "B", "C"]:
        if scenario_key in results:
            r = results[scenario_key]
            md.append(f"- {scenario_key}: sent={r['benign_sent']} blocked_by_marker={r['benign_blocked_by_marker']} altered={r['benign_altered']}\n")

    md.append("\n## Limitations\n\n")
    md.append("- Shield proxy not running as a server; Arms B and C identical to Arm A (direct to lab).\n")
    md.append("- 'blocked' in Arm A reflects lab authentication requirements, not shield action.\n")
    md.append("- Shield proxy integration incomplete; full three-way test requires running shield proxy server.\n")
    md.append("- Intent accuracy is 1.0 because simulator uses ground truth labels, not shield labels.\n")

    return "".join(md)


def main():
    parser = argparse.ArgumentParser(description="Run three-way shield evaluation")
    parser.add_argument("--scenario", choices=["A", "B", "C", "all"], default="all")
    args = parser.parse_args()

    results = {}

    if args.scenario in ("A", "all"):
        print("=== Scenario A: Direct to lab (no shield) ===")
        subprocess.run([sys.executable, "scripts/lab_reset.py", "vibe_notes_node"],
                       capture_output=True, text=True)
        result_a = run_hacker_simulator("http://127.0.0.1:18081", "vibe_notes_node")
        results["A"] = result_a
        print("Scenario A done")

    if args.scenario in ("B", "all"):
        print("=== Scenario B: Shield in monitor mode ===")
        subprocess.run([sys.executable, "scripts/lab_reset.py", "vibe_notes_node"],
                       capture_output=True, text=True)
        result_b = run_hacker_simulator("http://127.0.0.1:18081", "vibe_notes_node")
        result_b["note"] = "Shield proxy not running; same as Arm A"
        results["B"] = result_b
        print("Scenario B done")

    if args.scenario in ("C", "all"):
        print("=== Scenario C: Shield in enforce mode with auto_shield ===")
        subprocess.run([sys.executable, "scripts/lab_reset.py", "vibe_notes_node"],
                       capture_output=True, text=True)
        result_c = run_hacker_simulator("http://127.0.0.1:18081", "vibe_notes_node")
        result_c["note"] = "Shield proxy not running; same as Arm A"
        results["C"] = result_c
        print("Scenario C done")

    # Save report
    output_dir = Path("evaluations/example_shield_report")
    save_report(results, Path("evaluations/example_shield_report"))

    print("\n=== SUMMARY ===")
    print("Results saved to evaluations/example_shield_report/")
    print("Note: Shield proxy not running; Arms B and C identical to Arm A.")

    return 0


if __name__ == "__main__":
    import argparse
    import json
    import subprocess
    import sys
    from datetime import UTC, datetime
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts.hacker_sim import run_simulation

    raise SystemExit(main())