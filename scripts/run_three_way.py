#!/usr/bin/env python3
"""Run three-way shield evaluation against vibe_notes_node."""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.config import ShieldConfig
from sentinelx.shield.detect import Detector
from sentinelx.shield.proxy import ShieldProxy
from sentinelx.shield.recorder import ShieldRecorder


@dataclass
class ScenarioResult:
    name: str
    attack_results: list[dict]
    benign_sent: int
    benign_blocked: int
    intent_accuracy: float
    rules_proposed: int
    rules_activated: int
    rules_rejected: int
    rules_expired: int
    escalations_created: int
    shield_latency_p50: float | None
    shield_latency_p95: float | None


async def run_shield_proxy(config: ShieldConfig, store: EvidenceStore, session_id: str,
                          detector: Detector, recorder: ShieldRecorder) -> ShieldProxy:
    """Start shield proxy and return it."""
    proxy = ShieldProxy(config, store, session_id, detector, None, None, time.monotonic)
    return proxy


def run_hacker_simulator(base_url: str, target_id: str) -> dict:
    """Run hacker simulator and return metrics."""
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
            "blocked": r.requests_blocked,
            "latency_p50": r.latency_p50,
            "latency_p95": r.latency_p95,
        })

    return {
        "attack_results": attack_results,
        "benign_sent": result.benign_sent,
        "benign_blocked": result.benign_blocked,
        "intent_accuracy": result.intent_accuracy,
        "rules_proposed": result.rules_proposed,
        "rules_activated": result.rules_activated,
        "rules_rejected": result.rules_rejected,
        "rules_expired": result.rules_expired,
        "escalations_created": result.escalations_created,
        "shield_latency_p50": result.shield_latency_p50,
        "shield_latency_p95": result.shield_latency_p95,
    }


async def run_scenario_a() -> dict:
    """Scenario A: Direct to lab (no shield)."""
    print("=== Scenario A: Direct to lab (no shield) ===")
    result = run_hacker_simulator("http://127.0.0.1:18081", "vibe_notes_node")
    return result


async def run_scenario_b() -> dict:
    """Scenario B: Shield in monitor mode."""
    print("=== Scenario B: Shield in monitor mode ===")
    # For now, run without shield proxy (would need full proxy integration)
    # This is a placeholder - full integration would need proxy running
    result = run_hacker_simulator("http://127.0.0.1:18081", "vibe_notes_node")
    return result


async def run_scenario_c() -> dict:
    """Scenario C: Shield in enforce mode with auto_shield."""
    print("=== Scenario C: Shield in enforce mode with auto_shield ===")
    # Placeholder - full integration would need proxy running
    result = run_hacker_simulator("http://127.0.0.1:18081", "vibe_notes_node")
    return result


def main():
    parser = argparse.ArgumentParser(description="Run three-way shield evaluation")
    parser.add_argument("--scenario", choices=["A", "B", "C", "all"], default="all")
    args = parser.parse_args()

    # Reset lab before each run
    subprocess.run([sys.executable, "scripts/lab_reset.py", "vibe_notes_node"],
                   capture_output=True, text=True)

    if args.scenario in ("A", "all"):
        result_a = asyncio.run(run_scenario_a())
        print("Scenario A done")
        print(json.dumps(result_a, indent=2, default=str))

    if args.scenario in ("B", "all"):
        result_b = asyncio.run(run_scenario_b())
        print("Scenario B done")
        print(json.dumps(result_b, indent=2, default=str))

    if args.scenario in ("C", "all"):
        result_c = asyncio.run(run_scenario_c())
        print("Scenario C done")
        print(json.dumps(result_c, indent=2, default=str))

    print("\n=== SUMMARY ===")
    print("Note: Full shield proxy integration needed for B and C scenarios")
    print("Current results are from direct lab access (simulator only)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
