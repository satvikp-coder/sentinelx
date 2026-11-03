"""Tests for TASK 25: evaluation harness (tests/unit/test_evaluation_harness.py).

All tests are offline/mocked - no live model calls are made.
The harness is verified against the existing sentinelx.evaluation infrastructure.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelx.evaluation.harness import HarnessConfig, HarnessError, run_harness
from sentinelx.evaluation.manifest import (
    compute_manifest_hash,
    load_manifest,
)
from sentinelx.evaluation.metrics import MetricError, rate
from sentinelx.evaluation.records import RunRecord, VerifierResult

# ---------------------------------------------------------------------------
# Manifest tests
# ---------------------------------------------------------------------------

def test_manifest_has_30_cases() -> None:
    """The sealed manifest contains exactly 30 cases."""
    manifest_path = Path("evaluations/manifest.json")
    manifest = load_manifest(manifest_path)
    assert len(manifest.cases) == 30

    # Verify all cases have required fields
    for case in manifest.cases:
        assert case.case_id is not None
        assert case.scenario in ("S1", "S2", "S3")
        assert case.label in ("attack", "benign")
        assert case.case_hash is not None


def test_manifest_hash_matches() -> None:
    """The manifest's recorded hash matches the recomputed hash."""
    manifest_path = Path("evaluations/manifest.json")
    manifest = load_manifest(manifest_path)
    computed_hash = compute_manifest_hash(manifest)
    assert manifest.manifest_hash == computed_hash


# ---------------------------------------------------------------------------
# Rate validation tests
# ---------------------------------------------------------------------------

def test_rate_validates_denominator() -> None:
    """rate() raises MetricError on zero or negative denominator."""
    with pytest.raises(MetricError, match="denominator"):
        rate("test", numerator=5, denominator=0)

    with pytest.raises(MetricError, match="denominator"):
        rate("test", numerator=5, denominator=-1)


def test_rate_validates_numerator_range() -> None:
    """rate() raises MetricError when numerator exceeds denominator."""
    from sentinelx.evaluation.metrics import rate

    with pytest.raises(MetricError, match="numerator"):
        rate("test", numerator=5, denominator=3)


def test_rate_value() -> None:
    """rate() returns correct numerator/denominator/value."""
    from sentinelx.evaluation.metrics import rate

    r = rate("test_rate", numerator=3, denominator=10)
    assert r.numerator == 3
    assert r.denominator == 10
    assert r.value == 0.3


# ---------------------------------------------------------------------------
# RunRecord tests
# ---------------------------------------------------------------------------

def test_run_record_creation() -> None:
    """RunRecord can be created with all required fields."""
    v = VerifierResult(
        session_id="s1",
        scenario_id="A01",
        verifier_version="1.1.0",
        forbidden_outcome_occurred=True,
        goal_met=False,
        attempted_forbidden=True,
        executed_forbidden=True,
        blocked_forbidden=False,
        false_blocks=0,
        false_confirms=0,
        legit_actions_attempted=5,
        egress_blocked=0,
        stopped_by=[],
    )

    record = RunRecord(
        run_id="r1",
        case_id="A01",
        arm="A",
        rep=0,
        label="attack",
        scenario="S2",
        surface="visible_text",
        order_index=0,
        seed=3001,
        session_id="s1",
        valid=True,
        invalid_reason=None,
        fixture_hash="a3cb19da6b202b9caf4173b78c440e1ea6ed299c6e06a7693d8dc61337bb7cc9",
        policy_version="lab@ca58ac2c47ae",
        verifier_version="1.1.0",
        planner={"name": "scripted-naive", "kind": "SIMULATED_SCRIPTED_NAIVE"},
        provider="none",
        model="none",
        mode="SIMULATED",
        model_calls=0,
        model_tokens_in=0,
        model_tokens_out=0,
        model_latency_ms=[],
        model_rate_limit_hits=0,
        model_retries=0,
        model_invalid_outputs=0,
        total_ms=100.0,
        gateway_decision_ms=[],
        page_policy_ms=[],
        end_state="COMPLETED",
        abort_reason=None,
        chain_ok=True,
        leaked_processes=0,
        started_at="2026-01-01T00:00:00Z",
        ended_at="2026-01-01T00:00:00Z",
        verifier=v,
        block_rules={},
    )

    assert record.run_id == "r1"
    assert record.case_id == "A01"
    assert record.arm == "A"
    assert record.valid is True


# ---------------------------------------------------------------------------
# Harness tests
# ---------------------------------------------------------------------------

def test_harness_loads_manifest(tmp_path: Path) -> None:
    """The harness loads and verifies the sealed manifest."""
    manifest_path = Path("evaluations/manifest.json")
    assert manifest_path.is_file()

    config = HarnessConfig(manifest_path=manifest_path, out_dir=tmp_path / "out")
    result = run_harness(config)
    assert result.manifest is not None
    assert result.manifest.manifest_hash is not None
    assert len(result.manifest.cases) == 30


def test_harness_rejects_bad_manifest(tmp_path: Path) -> None:
    """A tampered manifest raises HarnessError."""
    manifest_path = Path("evaluations/manifest.json")
    tampered = tmp_path / "tampered.json"
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["name"] = "tampered"
    tampered.write_text(json.dumps(data, indent=2), encoding="utf-8")

    config = HarnessConfig(manifest_path=tampered, out_dir=tmp_path / "out2")
    with pytest.raises(HarnessError, match="recorded hash"):
        run_harness(config)
