"""Tests for Task 30: External Scanner QA Harness (Strix/PentAGI).

Tests: disabled-by-default config, authorization checks, kill switch,
dry-run planning, budget tracking, evidence storage, import results,
independent verification, attribution inventory.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sentinelx.external_scanner import (
    AuthorizationError,
    BudgetTracker,
    ExternalEvidenceStore,
    ExternalFinding,
    ExternalScannerConfig,
    KillSwitch,
    ScannerConfig,
    build_dry_run_plan,
    check_authorization,
    import_external_results,
    is_authorized,
    is_local_lab_url,
    verify_external_finding,
)

# ------------------------------------------------------------------ config

def test_disabled_by_default():
    """External scanner harness is disabled by default."""
    config = ExternalScannerConfig.disabled_defaults()
    assert config.enabled is False
    assert config.scanners["strix"].enabled is False
    assert config.scanners["pentagi"].enabled is False
    assert config.require_human_approval is True
    assert config.local_lab_only is True


def test_is_local_lab_url():
    """Only localhost / 127.0.0.1 / *.lab.test URLs are considered local."""
    assert is_local_lab_url("http://127.0.0.1:8080/") is True
    assert is_local_lab_url("http://localhost:8080/") is True
    assert is_local_lab_url("http://app.lab.test/") is True
    assert is_local_lab_url("http://evil.com/") is False
    assert is_local_lab_url("https://example.com/") is False
    assert is_local_lab_url(None) is False


# ------------------------------------------------------------------ authorization

def test_authorization_disabled():
    """Disabled config rejects all operations."""
    config = ExternalScannerConfig.disabled_defaults()
    assert is_authorized(config, "strix") is False
    with pytest.raises(AuthorizationError):
        check_authorization(config, "strix")


def test_authorization_enabled_but_human_approval_required():
    """Enabled config still requires human approval by default."""
    config = ExternalScannerConfig(
        enabled=True,
        scanners={
            "strix": ScannerConfig(name="strix", enabled=True, target_url="http://127.0.0.1:8080/"),
        },
        require_human_approval=True,
    )
    assert is_authorized(config, "strix") is False
    with pytest.raises(AuthorizationError):
        check_authorization(config, "strix")


def test_authorization_non_local_url_rejected():
    """Non-local target URLs are rejected."""
    config = ExternalScannerConfig(
        enabled=True,
        require_human_approval=False,
        scanners={
            "strix": ScannerConfig(
                name="strix", enabled=True, target_url="http://evil.com/",
                dry_run=True,
            ),
        },
    )
    assert is_authorized(config, "strix") is False
    with pytest.raises(AuthorizationError):
        check_authorization(config, "strix")


def test_authorization_local_url_ok():
    """Local lab URL with human approval disabled passes authorization."""
    config = ExternalScannerConfig(
        enabled=True,
        require_human_approval=False,
        scanners={
            "strix": ScannerConfig(
                name="strix", enabled=True, target_url="http://127.0.0.1:8080/",
                dry_run=True,
            ),
        },
    )
    assert is_authorized(config, "strix") is True


# ------------------------------------------------------------------ kill switch

def test_kill_switch():
    """Kill switch halts operations when triggered."""
    ks = KillSwitch()
    assert ks.active is False
    ks.check()  # should not raise

    ks.trigger()
    assert ks.active is True
    with pytest.raises(RuntimeError):
        ks.check()

    ks.reset()
    assert ks.active is False
    ks.check()  # should not raise


# ------------------------------------------------------------------ dry run

def test_dry_run_plan_not_authorized():
    """Dry-run plan for unauthorized scanner shows would_execute=False."""
    plan = build_dry_run_plan(
        scanner_name="strix",
        operation="scan",
        target_url="http://127.0.0.1:8080/",
        request_budget=100,
        time_budget_seconds=300,
        authorized=False,
    )
    assert plan.would_execute is False
    assert plan.reason == "not authorized"


def test_dry_run_plan_no_target():
    """Dry-run plan with no target URL shows would_execute=False."""
    plan = build_dry_run_plan(
        scanner_name="strix",
        operation="scan",
        target_url=None,
        request_budget=100,
        time_budget_seconds=300,
        authorized=True,
    )
    assert plan.would_execute is False
    assert plan.reason == "no target URL configured"


def test_dry_run_plan_would_execute():
    """Dry-run plan for authorized scanner with target shows would_execute=True."""
    plan = build_dry_run_plan(
        scanner_name="strix",
        operation="scan",
        target_url="http://127.0.0.1:8080/",
        request_budget=100,
        time_budget_seconds=300,
        authorized=True,
    )
    assert plan.would_execute is True
    assert plan.reason == "dry-run: would execute against lab target"


# ------------------------------------------------------------------ budget tracker

def test_budget_tracker():
    """Budget tracker enforces request and time limits."""
    bt = BudgetTracker(request_budget=3, time_budget_seconds=1)
    assert bt.can_make_request() is True
    assert bt.remaining_requests() == 3

    bt.record_request()
    assert bt.requests_used == 1
    assert bt.remaining_requests() == 2

    bt.record_request()
    bt.record_request()
    assert bt.can_make_request() is False
    with pytest.raises(RuntimeError):
        bt.check()


# ------------------------------------------------------------------ evidence store

def test_evidence_store_add_and_list():
    """External evidence store adds and lists findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "evidence.db"
        store = ExternalEvidenceStore(str(db_path))

        finding = ExternalFinding(
            scanner_name="strix",
            scanner_version="1.0",
            finding_id="ext-001",
            title="Test Finding",
            description="A test finding",
            severity="medium",
            target="http://127.0.0.1:8080/",
            evidence={"key": "value"},
            imported_at="2026-01-01T00:00:00Z",
        )
        store.add_finding(finding)

        findings = store.list_findings()
        assert len(findings) == 1
        assert findings[0].finding_id == "ext-001"
        assert findings[0].confirmed is False

        # Confirm the finding
        store.confirm_finding("ext-001", "independent verification passed")
        findings = store.list_findings(confirmed_only=True)
        assert len(findings) == 1
        assert findings[0].confirmed is True
        assert findings[0].confirmation_reason == "independent verification passed"

        store.close()


# ------------------------------------------------------------------ import results

def test_import_external_results():
    """Import external results marks all findings as unconfirmed."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "evidence.db"
        store = ExternalEvidenceStore(str(db_path))

        results = [
            {
                "finding_id": "ext-001",
                "title": "Finding 1",
                "description": "First finding",
                "severity": "high",
                "target": "http://127.0.0.1:8080/",
                "evidence": {"key": "value"},
            },
            {
                "finding_id": "ext-002",
                "title": "Finding 2",
                "description": "Second finding",
                "severity": "low",
                "target": "http://127.0.0.1:8080/",
                "evidence": {},
            },
        ]
        ids = import_external_results(store, "strix", "1.0", results)
        assert len(ids) == 2
        assert "ext-001" in ids
        assert "ext-002" in ids

        findings = store.list_findings()
        assert len(findings) == 2
        for f in findings:
            assert f.confirmed is False
            assert f.scanner_name == "strix"

        store.close()


# ------------------------------------------------------------------ independent verification

def test_verify_external_finding_no_match():
    """External finding with no matching Sentinel target is not confirmed."""
    class FakeFinding:
        finding_id = "ext-001"
        scanner_name = "strix"
        target = "http://evil.com/"

    result = verify_external_finding(
        FakeFinding(),
        {"targets": ["http://127.0.0.1:8080/"]},
    )
    assert result.confirmed is False
    assert result.evidence_match is False


def test_verify_external_finding_match():
    """External finding with matching Sentinel target still requires confirmation."""
    class FakeFinding:
        finding_id = "ext-001"
        scanner_name = "strix"
        target = "http://127.0.0.1:8080/"

    result = verify_external_finding(
        FakeFinding(),
        {"targets": ["http://127.0.0.1:8080/"]},
    )
    assert result.confirmed is False  # still requires human confirmation
    assert result.evidence_match is True


# ------------------------------------------------------------------ attribution

def test_attribution_inventory():
    """Third-party inventory includes Strix and PentAGI."""
    from sentinelx.external_scanner.attribution import THIRD_PARTY_INVENTORY, get_inventory
    inventory = get_inventory()
    names = {c.name for c in inventory}
    assert "Strix" in names
    assert "PentAGI" in names
    assert len(THIRD_PARTY_INVENTORY) == 2
