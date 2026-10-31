"""Tests for the static report: loader, escaping, integrity (all offline)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelx.common_schemas import Actor, ActorRole, EvidenceState, SessionKind
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.report.integrity import check_integrity
from sentinelx.report.loader import MetricError, load_all
from sentinelx.report.render import render_index

HOSTILE = "<script>alert(1)</script>"
HOSTILE_IMG = '<img src=x onerror=alert(2)>'


def _metric(name: str, num: int, den: int) -> dict:
    return {"name": name, "numerator": num, "denominator": den, "value": num / den}


def _make_fixture(root: Path, *, session_id: str = "ses_test0000000000000000000000",
                  bad_denominator: bool = False, hostile: bool = False) -> Path:
    """Minimal fake evaluations folder shaped exactly like the real report schemas."""
    den = None if bad_denominator else 5
    block = {"name": "attack_block_rate", "numerator": 3,
             **({"denominator": den} if den is not None else {}), "value": 0.6}
    paired = {
        "provenance": {"planner": "SIMULATED scripted", "provider": "none", "model": "none",
                       "mode": "SIMULATED (no model, no LLM)", "run_id": "r1",
                       "git": {"commit": "abc123"}, "manifest_hash": "h1",
                       "date_utc": "2026-10-31T00:00:00Z", "policy_version": "p@1"},
        "arms": {"A": {"overall": {"attack_block_rate": block},
                       "benign_page_request_blocks": _metric("benign_page_request_blocks",
                                                             0, 5)},
                 "B": {"overall": {"attack_block_rate": _metric("attack_block_rate", 5, 5)},
                       "benign_page_request_blocks": _metric("benign_page_request_blocks",
                                                             0, 5)}},
        "pairing": {"pairs": 2},
        "limitations": [HOSTILE] if hostile else ["small n"],
    }
    (root / "example_report").mkdir(parents=True)
    (root / "example_report" / "report.json").write_text(json.dumps(paired), encoding="utf-8")

    scan = {
        "provenance": {"target_id": "vibe_notes_node", "session_id": session_id,
                       "coverage_percent": 90.0, "requests_used": 10, "request_budget": 100,
                       "model": {"provider": "none", "model": "none", "mode": "none"}},
        "findings": [], "limitations": ["lab-only"],
    }
    lab = root / "example_scan_report" / "vibe_notes_node"
    lab.mkdir(parents=True)
    (lab / "report.json").write_text(json.dumps(scan), encoding="utf-8")
    scoring = {
        "lab": "vibe_notes_node", "planted_found": ["N-01"], "planted_missed": ["N-02"],
        "overall_recall": _metric("recall_overall", 1, 2),
        "unmatched_confirmed_for_manual_review": [
            {"finding_id": "f1", "vuln_class": "xss", "method": "GET", "endpoint": "/",
             "summary": HOSTILE_IMG if hostile else "suspicious"}],
        "clean_copy_false_findings_count": 0,
    }
    (lab / "scoring.json").write_text(json.dumps(scoring), encoding="utf-8")

    shield = {"generated": "2026-10-31T00:00:00Z", "lab": "vibe_notes_node",
              "lab_state_hash": "0" * 64, "caveats": [],
              "arms": {"A": {"records": 1, "refused_by_guarded_client": 0,
                             "attack": {"total": {"sent": 5, "reached_upstream": 5,
                                                  "blocked_by_shield": 0, "lab_4xx_5xx": 1},
                                        "per_stage": {"recon": {"sent": 5, "reached_upstream": 5,
                                                                "blocked_by_shield": 0,
                                                                "lab_4xx_5xx": 1}}},
                             "benign": {"sent": 2, "blocked_or_altered_by_shield": 0,
                                        "lab_4xx_5xx": 0, "blocked_by_rule": []},
                             "rules": "n/a", "time_to_protect": "n/a",
                             "intent_accuracy": "n/a"}}}
    (root / "example_shield_report").mkdir()
    (root / "example_shield_report" / "report.json").write_text(json.dumps(shield),
                                                               encoding="utf-8")
    return root


def test_loader_reads_exact_numerators_and_denominators(tmp_path):
    root = _make_fixture(tmp_path)
    sections = load_all(root)
    assert sections["agent_guard_scripted"].ok
    run = sections["agent_guard_scripted"].data
    m = run.arms["A"].metrics["attack_block_rate"]
    assert (m.numerator, m.denominator) == (3, 5)
    scan = sections["scan"].data[0]
    assert scan.planted_total == 2 and scan.recall.rate == "1/2"
    shield = sections["shield"].data[0]
    assert shield.attack_total == {"sent": 5, "reached_upstream": 5,
                                   "blocked_by_shield": 0, "lab_4xx_5xx": 1}
    inv = sections["investigator"]
    assert not inv.ok  # fixture has no investigations.json -> NOT AVAILABLE


def test_missing_file_gives_not_available(tmp_path):
    sections = load_all(tmp_path)  # empty dir: every source missing
    for name in ("agent_guard_scripted", "investigator", "evcs", "fix", "shield"):
        assert sections[name].status == "NOT AVAILABLE"
        assert sections[name].error is not None


def test_missing_denominator_raises_naming_metric(tmp_path):
    root = _make_fixture(tmp_path, bad_denominator=True)
    with pytest.raises(MetricError) as exc:
        load_all(root)
    assert "attack_block_rate" in str(exc.value)


def test_hostile_payload_is_escaped_never_live(tmp_path):
    root = _make_fixture(tmp_path, hostile=True)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text
    assert "<script>alert(1)" not in html_text
    assert "&lt;img src=x onerror=alert(2)&gt;" in html_text
    assert "<img src=x onerror" not in html_text


def test_output_has_no_external_resources(tmp_path):
    root = _make_fixture(tmp_path)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8").lower()
    for needle in ("<script", "<iframe", "<link", "http://", "https://", "url(", "@import",
                   "onclick=", "onerror=", "innerHTML"):
        assert needle not in html_text, needle


def test_integrity_detects_tampered_event(tmp_path):
    db_path = tmp_path / "evidence.db"
    conn = connect(db_path)
    migrate(conn)
    session_svc = SessionService(conn)
    session, _ = session_svc.create(kind=SessionKind.GUARD, policy_version="1.0",
                                    actor=Actor(id="t", role=ActorRole.SYSTEM))
    store = EvidenceStore(conn)
    store.append(session.id, "k", EvidenceState.OBSERVED, "t", {"a": 1})
    second = store.append(session.id, "k", EvidenceState.OBSERVED, "t", {"b": 2})

    root = _make_fixture(tmp_path / "evals", session_id=session.id)
    clean = check_integrity(root, db_path)
    ok_row = next(r for r in clean.rows if r.session_id == session.id)
    assert ok_row.status == "OK"

    conn.execute("UPDATE events SET payload = ? WHERE id = ?",
                 (json.dumps({"i": 999}), second.id))
    conn.commit()
    tampered = check_integrity(root, db_path)
    row = next(r for r in tampered.rows if r.session_id == session.id)
    assert row.status == "BROKEN"
    assert second.id in row.detail
