"""Production cost paths preserve uncertainty; no provider or credential-file access."""

import json
import sys

import pytest

from scripts import estimate_cost as estimate_cli
from scripts import final_run
from sentinelx.evidence.db import connect, migrate
from sentinelx.model_clients.profiles import (
    UNKNOWN_FREE_TIER_COST,
    check_budget,
    cumulative_spend,
    estimate_cost,
    load_models_config,
    record_usage,
    resolve_task,
)
from sentinelx.report.loader import load_fix, load_provenance
from sentinelx.report.render import render_fix


def test_unverified_nvidia_price_is_not_a_numeric_zero():
    profiles = load_models_config().profiles
    assert estimate_cost(profiles["nvidia_glimmer"], 2000, 1500) is None
    assert estimate_cost(profiles["baseten_spark_open"], 2000, 1500) == pytest.approx(0.008875)


def test_estimate_cli_labels_unknown_nvidia_without_fake_dollars(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "estimate_cost.py", "--profile", "nvidia_glimmer", "--calls", "6",
        "--tokens-in", "2000", "--tokens-out", "1500", "--db", str(tmp_path / "usage.db"),
    ])
    assert estimate_cli.main() == 0  # explicitly UNBUDGETED, not verified as free
    output = capsys.readouterr().out
    assert UNKNOWN_FREE_TIER_COST in output
    assert "$0.0000" not in output
    assert "no configured budget" in output


def test_dry_run_preserves_unknown_total_and_known_subtotal(tmp_path, monkeypatch, capsys):
    def no_process(*args, **kwargs):
        pytest.fail("Dry-run launched a subprocess")

    monkeypatch.setattr(final_run, "run_cmd", no_process)
    out = tmp_path / "plan.json"
    assert final_run.main([
        "--dry-run", "--evaluations", str(tmp_path / "empty"), "--manifest-out", str(out),
    ]) == 0
    plan = json.loads(out.read_text())
    assert plan["estimated_spend_usd_total"] is None
    assert set(plan["unknown_cost_steps"]) == {"agent_model", "scan"}
    estimates = {s["name"]: s["estimated"] for s in plan["steps"] if s["estimated"]}
    assert estimates["agent_model"]["worst_case_usd"] is None
    assert estimates["agent_model"]["cost_display"] == UNKNOWN_FREE_TIER_COST
    assert plan["known_estimated_spend_usd_subtotal"] == float(
        estimates["fix"]["worst_case_usd"])
    output = capsys.readouterr().out
    assert UNKNOWN_FREE_TIER_COST in output
    assert "worst-case estimate: $0.0000" not in output


def test_executed_manifest_does_not_sum_unknown_as_zero(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    monkeypatch.setattr(final_run, "git_commit", lambda: "test-revision")
    records = [
        final_run.StepRecord("priced", [], estimated={"worst_case_usd": "1.25"}),
        final_run.StepRecord("unpriced", [], estimated={"worst_case_usd": None}),
    ]
    path = tmp_path / "executed.json"
    final_run._write_manifest(path, datetime.now(UTC), records, dry_run=False)
    data = json.loads(path.read_text())
    assert data["estimated_spend_usd_total"] is None
    assert data["known_estimated_spend_usd_subtotal"] == 1.25
    assert data["unknown_cost_steps"] == ["unpriced"]


@pytest.mark.parametrize("profile", ["nvidia_glimmer", "baseten_spark_open"])
def test_unknown_usage_is_not_hidden_by_sql_sum(tmp_path, profile):
    conn = connect(tmp_path / "usage.db")
    try:
        migrate(conn)
        assert cumulative_spend(conn, profile) == 0  # genuinely no calls
        for cost in [1.0, None]:
            record_usage(conn, session_id=None, profile_name=profile, provider="synthetic",
                         model="synthetic", tokens_in=1, tokens_out=1, latency_ms=1,
                         estimated_cost=cost)
        assert cumulative_spend(conn, profile) is None
        cfg = load_models_config()
        budget = check_budget(conn, cfg, profile)
        assert budget.spent_usd is None and budget.remaining_usd is None
        if profile == "baseten_spark_open":
            assert budget.status == "COST_UNKNOWN"
            routed = resolve_task(conn, cfg, "patch_generation", env_file=None,
                                  environ={"BASETEN_API_KEY": "synthetic-budget-test"})
            assert routed.status == "MODEL_UNAVAILABLE"
            assert "COST_UNKNOWN" in routed.detail
        else:
            assert budget.status == "UNBUDGETED"
    finally:
        conn.close()


def test_budgeted_cli_refuses_unknown_recorded_spend(tmp_path, monkeypatch, capsys):
    path = tmp_path / "usage.db"
    conn = connect(path)
    migrate(conn)
    record_usage(conn, session_id=None, profile_name="baseten_spark_open", provider="baseten",
                 model="synthetic", tokens_in=1, tokens_out=1, latency_ms=1, estimated_cost=None)
    conn.close()
    monkeypatch.setattr(sys, "argv", [
        "estimate_cost.py", "--profile", "baseten_spark_open", "--calls", "1",
        "--tokens-in", "100", "--tokens-out", "100", "--db", str(path),
    ])
    assert estimate_cli.main() == 1
    assert "REFUSED" in capsys.readouterr().out


def test_old_nvidia_report_zero_is_unknown_without_rewriting_file(tmp_path):
    folder = tmp_path / "example_fix_report"
    folder.mkdir()
    path = folder / "report.json"
    source = json.dumps({
        "provenance": {"model_profile": "nvidia_glimmer"},
        "spend": {"spent_usd": 0.0, "hard_cap_usd": None, "remaining_usd": None},
        "results": [{"finding_id": "synthetic", "lab": "synthetic", "status": "ESCALATED"}],
    })
    path.write_text(source)
    section = load_fix(tmp_path)
    assert section.ok
    assert section.data.spend["spent_usd"] is None
    assert UNKNOWN_FREE_TIER_COST in render_fix(section)
    assert "$0.0000" not in render_fix(section)
    provenance = next(s for s in load_provenance(tmp_path) if s.ok)
    assert UNKNOWN_FREE_TIER_COST in provenance.data.spend
    assert path.read_text() == source
