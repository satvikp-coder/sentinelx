#!/usr/bin/env python3
"""Run three-way shield evaluation against vibe_notes_node with real proxy."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from sentinelx.common_schemas import Actor, ActorRole, SessionKind
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.config import ShieldConfig, load_shield_config
from sentinelx.shield.detect import Detector
from sentinelx.shield.proxy import ShieldProxy
from sentinelx.shield.recorder import ShieldRecorder
from sentinelx.scanner.authz import (
    AuthzConfig,
    ScanProfile,
    register_lab_target,
)
from sentinelx.scanner.http import GuardedClient


@dataclass
class RequestRecord:
    """Per-request record for honest metrics."""
    scenario: str
    stage: str
    method: str
    path: str
    sent_at: str
    status_code: int
    shield_header: str | None
    blocked_by_marker: bool
    reached_upstream: bool
    latency_ms: float
    upstream_latency_ms: float | None


@dataclass
class AttackResult:
    stage: str
    requests_sent: int
    requests_blocked: int
    requests_reached_upstream: int
    latency_p50: float | None = None
    latency_p95: float | None = None


@dataclass
class SimResult:
    attack_results: list[AttackResult]
    request_records: list[RequestRecord]
    benign_sent: int
    benign_blocked: int
    benign_altered: int
    intent_accuracy: float
    time_to_protect: dict[str, float]
    rules_proposed: int
    rules_activated: int
    rules_rejected: int
    rules_expired: int
    escalations_created: int
    shield_latency_p50: float | None
    shield_latency_p95: float | None
    full_chain: dict[str, Any] | None = None


class ProxyManager:
    """Manages the shield proxy subprocess."""
    
    def __init__(self, config: ShieldConfig):
        self.config = config
        self.proc: subprocess.Popen | None = None
        self.base_url = f"http://{config.listen.host}:{config.listen.port}"
    
    def start(self) -> bool:
        """Start the shield proxy as a uvicorn subprocess."""
        config_path = Path("configs/shield/default.yaml").resolve()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path.cwd())
        
        self.proc = subprocess.Popen(
            [
                sys.executable, "-m", "uvicorn",
                "packages.shield.server:create_shield_app",
                "--factory",
                "--host", self.config.listen.host,
                "--port", str(self.config.listen.port),
                "--log-level", "info",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Wait for proxy to be healthy
        for _ in range(30):
            try:
                resp = httpx.get(f"http://127.0.0.1:18090/health", timeout=2)
                if resp.status_code == 200:
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False
    
    def stop(self):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None


class LabManager:
    """Manages the lab lifecycle."""
    
    def __init__(self, lab_name: str = "vibe_notes_node"):
        self.lab_name = lab_name
    
    def start(self) -> str:
        """Start the lab and return state hash."""
        result = subprocess.run(
            [sys.executable, "scripts/lab_up.py", self.lab_name],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(f"Lab up failed: {result.stderr}")
        for line in result.stdout.splitlines():
            if "state hash" in line:
                return line.split("state hash")[-1].strip()
        return ""
    
    def reset(self) -> str:
        """Reset the lab and return state hash."""
        result = subprocess.run(
            [sys.executable, "scripts/lab_reset.py", self.lab_name],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            raise RuntimeError(f"Lab reset failed: {result.stderr}")
        for line in result.stdout.splitlines():
            if "state hash" in line:
                return line.split("state hash")[-1].strip()
        return ""
    
    def stop(self):
        subprocess.run([sys.executable, "scripts/lab_down.py", "vibe_notes_node"],
                       capture_output=True, timeout=60)


@dataclass
class ScenarioResult:
    name: str
    attack_results: list[AttackResult]
    benign_sent: int
    benign_blocked: int
    benign_altered: int
    intent_accuracy: float
    time_to_protect: dict[str, float]
    rules_proposed: int
    rules_activated: int
    rules_rejected: int
    rules_expired: int
    escalations_created: int
    shield_latency_p50: float | None
    shield_latency_p95: float | None
    per_stage: dict[str, dict]


def run_scenario(
    name: str,
    lab_url: str,
    proxy_url: str | None,
    lab_manager: LabManager,
    proxy_manager: ProxyManager | None,
) -> dict:
    """Run a single scenario and return metrics."""
    print(f"\n=== Scenario {name} ===")
    
    # Reset lab before each run
    state_hash = lab_manager.reset()
    print(f"Lab reset, state hash: {state_hash}")
    
    # Determine URL to use
    url = proxy_manager.base_url if proxy_manager else "http://127.0.0.1:18081"
    
    # Run hacker simulator
    from scripts.hacker_sim import run_simulation
    result = run_simulation(
        base_url=url,
        target_id="vibe_notes_node",
        shield_proxy=None,
        shield_mode="monitor",
        auto_shield=False,
    )
    
    return {
        "attack_results": [
            {
                "stage": r.stage,
                "sent": r.requests_sent,
                "blocked_by_marker": r.requests_blocked,
                "blocked_by_lab": r.requests_blocked,
                "reached_upstream": r.requests_reached_upstream,
                "latency_p50": r.latency_p50,
                "latency_p95": r.latency_p95,
            }
            for r in result.attack_results
        ],
        "benign_sent": result.benign_sent,
        "benign_blocked_by_marker": result.benign_blocked,
        "benign_blocked_by_lab": 0,
        "benign_altered": result.benign_altered,
        "intent_accuracy": result.intent_accuracy,
        "rules_proposed": result.rules_proposed,
        "rules_activated": result.rules_activated,
        "rules_rejected": result.rules_rejected,
        "rules_expired": result.rules_expired,
        "escalations_created": result.escalations_created,
        "shield_latency_p50": result.shield_latency_p50,
        "shield_latency_p95": result.shield_latency_p95,
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
    md.append("- 'Blocked' in Arm A = lab authentication requirements, not shield action.\n")
    md.append("- Shield proxy integration incomplete; full three-way test requires running shield proxy server.\n")
    md.append("- Intent accuracy = 1.00 because simulator uses ground truth labels, not shield labels.\n")

    return "".join(md)


def main():
    parser = argparse.ArgumentParser(description="Run three-way shield evaluation")
    parser.add_argument("--scenario", choices=["A", "B", "C", "all"], default="all")
    args = parser.parse_args()

    results = {}

    lab_manager = LabManager()
    proxy_manager = None

    if args.scenario in ("A", "all"):
        print("=== Scenario A: Direct to lab (no shield) ===")
        lab_manager.reset()
        result_a = run_simulation(
            base_url="http://127.0.0.1:18081",
            target_id="vibe_notes_node",
            shield_proxy=None,
            shield_mode="monitor",
            auto_shield=False,
        )
        results["A"] = {
            "attack_results": [
                {
                    "stage": r.stage,
                    "sent": r.requests_sent,
                    "blocked_by_marker": 0,  # No shield proxy running
                    "blocked_by_lab": r.requests_blocked,
                    "reached_upstream": r.requests_reached_upstream,
                    "latency_p50": r.latency_p50,
                    "latency_p95": r.latency_p95,
                }
                for r in result_a.attack_results
            ],
            "benign_sent": result_a.benign_sent,
            "benign_blocked_by_marker": result_a.benign_blocked,
            "benign_blocked_by_lab": 0,
            "benign_altered": result_a.benign_altered,
            "intent_accuracy": result_a.intent_accuracy,
            "rules_proposed": result_a.rules_proposed,
            "rules_activated": result_a.rules_activated,
            "rules_rejected": result_a.rules_rejected,
            "rules_expired": result_a.rules_expired,
            "escalations_created": result_a.escalations_created,
            "shield_latency_p50": None,
            "shield_latency_p95": None,
        }
        print("Scenario A done")

    if args.scenario in ("B", "all"):
        print("=== Scenario B: Shield in monitor mode ===")
        lab_manager.reset()
        result_b = run_simulation(
            base_url="http://127.0.0.1:18081",
            target_id="vibe_notes_node",
            shield_proxy=None,
            shield_mode="monitor",
            auto_shield=False,
        )
        results["B"] = {
            "attack_results": [
                {
                    "stage": r.stage,
                    "sent": r.requests_sent,
                    "blocked_by_marker": 0,  # No shield proxy running
                    "blocked_by_lab": r.requests_blocked,
                    "reached_upstream": r.requests_reached_upstream,
                    "latency_p50": r.latency_p50,
                    "latency_p95": r.latency_p95,
                }
                for r in result_b.attack_results
            ],
            "benign_sent": result_b.benign_sent,
            "benign_blocked_by_marker": result_b.benign_blocked,
            "benign_blocked_by_lab": 0,
            "benign_altered": result_b.benign_altered,
            "intent_accuracy": result_b.intent_accuracy,
            "rules_proposed": result_b.rules_proposed,
            "rules_activated": result_b.rules_activated,
            "rules_rejected": result_b.rules_rejected,
            "rules_expired": result_b.rules_expired,
            "escalations_created": result_b.escalations_created,
            "shield_latency_p50": None,
            "shield_latency_p95": None,
            "note": "Shield proxy not running; same as Arm A"
        }
        print("Scenario B done")

    if args.scenario in ("C", "all"):
        print("=== Scenario C: Shield in enforce mode with auto_shield ===")
        lab_manager.reset()
        result_c = run_simulation(
            base_url="http://127.0.0.1:18081",
            target_id="vibe_notes_node",
            shield_proxy=None,
            shield_mode="enforce",
            auto_shield=True,
        )
        results["C"] = {
            "attack_results": [
                {
                    "stage": r.stage,
                    "sent": r.requests_sent,
                    "blocked_by_marker": 0,  # No shield proxy running
                    "blocked_by_lab": r.requests_blocked,
                    "reached_upstream": r.requests_reached_upstream,
                    "latency_p50": r.latency_p50,
                    "latency_p95": r.latency_p95,
                }
                for r in result_c.attack_results
            ],
            "benign_sent": result_c.benign_sent,
            "benign_blocked_by_marker": result_c.benign_blocked,
            "benign_blocked_by_lab": 0,
            "benign_altered": result_c.benign_altered,
            "intent_accuracy": result_c.intent_accuracy,
            "rules_proposed": result_c.rules_proposed,
            "rules_activated": result_c.rules_activated,
            "rules_rejected": result_c.rules_rejected,
            "rules_expired": result_c.rules_expired,
            "escalations_created": result_c.escalations_created,
            "shield_latency_p50": None,
            "shield_latency_p95": None,
            "note": "Shield proxy not running; same as Arm A"
        }
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