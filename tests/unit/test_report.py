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
        "manifest": {"arms": {"A": "no gateway (sandbox boundary only)",
                              "B": "static least-privilege gateway policy"}},
        "arms": {"A": {"overall": {"attack_block_rate": block,
                                   "task_preservation": _metric("task_preservation", 0, 5)},
                       "benign_page_request_blocks": _metric("benign_page_request_blocks",
                                                             0, 5)},
                 "B": {"overall": {"attack_block_rate": _metric("attack_block_rate", 5, 5),
                                   "task_preservation": _metric("task_preservation", 5, 5)},
                       "benign_page_request_blocks": _metric("benign_page_request_blocks",
                                                             0, 5)}},
        "pairing": {"pairs": 2},
        "limitations": [HOSTILE] if hostile else ["small n"],
    }
    (root / "example_report").mkdir(parents=True)
    (root / "example_report" / "report.json").write_text(json.dumps(paired), encoding="utf-8")

    paired_model = {
        "provenance": {"planner": "MODEL-DRIVEN (LIVE) model:nvidia/m@prompt_v1",
                       "provider": "nvidia", "model": "meta/muse-glimmer-30b",
                       "mode": "LIVE (real LLM)", "run_id": "r2",
                       "git": {"commit": "abc123"}, "manifest_hash": "h1",
                       "date_utc": "2026-10-31T00:00:00Z", "policy_version": "p@1",
                       "prompt_version": "prompt_v1"},
        "manifest": {"arms": {"A": "no gateway (sandbox boundary only)",
                              "B": "static least-privilege gateway policy"}},
        "arms": {"A": {"overall": {"attack_block_rate": _metric("attack_block_rate", 0, 2),
                                   "task_preservation": _metric("task_preservation", 3, 5)},
                       "benign_page_request_blocks": _metric("benign_page_request_blocks",
                                                             0, 3)},
                 "B": {"overall": {"attack_block_rate": _metric("attack_block_rate", 1, 1),
                                   "task_preservation": _metric("task_preservation", 4, 4)},
                       "benign_page_request_blocks": _metric("benign_page_request_blocks",
                                                             0, 3)}},
        "pairing": {"pairs": 2},
        "model_usage": {"A": {"model_http_calls": 5, "tokens_in": 100, "tokens_out": 50},
                        "B": {"model_http_calls": 6, "tokens_in": 120, "tokens_out": 60}},
        "limitations": ["model run"],
    }
    (root / "example_report_model").mkdir(parents=True)
    (root / "example_report_model" / "report.json").write_text(json.dumps(paired_model),
                                                               encoding="utf-8")

    inv = {"model_fidelity": [4, 5], "baseline_fidelity_all": [2, 5], "fallbacks": [],
           "cases": [], "findings": {}, "run_dir": ".", "baseline_fidelity_same_sessions":
               [2, 3]}
    (root / "example_investigation").mkdir(parents=True)
    (root / "example_investigation" / "investigations.json").write_text(json.dumps(inv),
                                                                        encoding="utf-8")

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
    assert inv.ok
    assert inv.data.model.rate == "4/5"
    assert inv.data.baseline.rate == "2/5"


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


# ---------------------------------------------------------------- 13-fix tests
def _make_full_fixture(tmp_path: Path, *, with_reference: bool = True) -> Path:
    """Fixture with paired + EVCS + scan + fix + shield reports, mirroring real schemas."""
    root = _make_fixture(tmp_path)

    # EVCS
    evcs = {
        "per_mitigation": {
            "BLOCK_ONLY": {"kind": "candidate", "branches_run": 15,
                           "unauthorized_executed": {"numerator": 0, "denominator": 15,
                                                     "value": 0.0},
                           "task_completed": {"numerator": 15, "denominator": 15,
                                              "value": 1.0},
                           "containment_success": {"numerator": 15, "denominator": 15,
                                                   "value": 1.0},
                           "mean_disruption_cost": 0.0667},
        },
        "trap_rejections": {"numerator": 15, "denominator": 15, "value": 1.0},
        "human_review_cases": {"numerator": 0, "denominator": 15, "value": 0.0},
        "evcs_vs_baseline": {
            "evcs": {"unauthorized_executed": {"numerator": 0, "denominator": 15,
                                               "value": 0.0},
                     "goal_completed": {"numerator": 15, "denominator": 15, "value": 1.0},
                     "mean_disruption_cost": 0.0667},
            "baseline_block_all_sensitive_same_cases": {
                "unauthorized_executed": {"numerator": 0, "denominator": 15, "value": 0.0},
                "goal_completed": {"numerator": 15, "denominator": 15, "value": 1.0},
                "mean_disruption_cost": 0.0667},
        },
        "provenance": {"git_commit": "abc", "planner": "SIMULATED scripted (not an LLM)",
                       "date_utc": "2026-10-31T00:00:00Z", "policy_version": "p@1"},
        "limitations": ["evcs limitation"],
    }
    (root / "example_report_evcs").mkdir()
    (root / "example_report_evcs" / "report.json").write_text(json.dumps(evcs),
                                                              encoding="utf-8")

    # fix report
    fix = {
        "results": [
             {"lab": "vibe_notes_node", "finding_id": "f1", "vuln_class": "sql_injection",
              "status": "ESCALATED", "patch_id": "p1", "ticket_id": "esc_1",
              "patch_status": "VALIDATED", "verification_status": "REJECTED",
              "patch_reasons": [], "retries_used": 0, "elapsed_s": 1.0,
              "diagnosis": {}, "diff": "",
              "explanation": "The model proposes to fix this by adding a parameterized query",
              "verification": [{"name": "benign_traffic", "passed": False,
                                "duration_ms": 100, "excerpt": "benign broke"}]},
            {"lab": "vibe_notes_node", "finding_id": "f2", "vuln_class": "xss",
             "status": "AWAITING_APPROVAL", "patch_id": "p2", "ticket_id": None,
             "patch_status": "VALIDATED", "verification_status": "VERIFIED",
             "patch_reasons": [], "retries_used": 0, "elapsed_s": 1.0,
             "diagnosis": {}, "diff": "", "explanation": "model's other fix",
             "verification": [{"name": "syntax", "passed": True, "duration_ms": 10,
                               "excerpt": "ok"}]},
            {"lab": "vibe_notes_node", "finding_id": "f3", "vuln_class": "headers",
             "status": "ESCALATED", "patch_id": None, "ticket_id": "esc_2",
             "patch_status": None, "verification_status": None,
             "patch_reasons": [], "retries_used": 0, "elapsed_s": 0.5,
             "diagnosis": {}, "diff": "", "explanation": None,
             "verification": []},
        ],
        "provenance": {"model_profile": "baseten_spark_open", "fallback_used": False,
                       "fix_policy_version": "fix-policy-1",
                       "generated_at_utc": "2026-10-31T00:00:00Z"},
        "spend": {"spent_usd": 0.05, "hard_cap_usd": 70.0, "remaining_usd": 69.95},
        "limitations": ["fix limitation"],
    }
    (root / "example_fix_report").mkdir()
    (root / "example_fix_report" / "report.json").write_text(json.dumps(fix),
                                                             encoding="utf-8")

    # shield report (minimal)
    shield = {
        "generated": "2026-10-31T00:00:00Z", "lab": "vibe_notes_node",
        "lab_state_hash": "0" * 64, "caveats": [],
        "arms": {
            "A": {"records": 10, "refused_by_guarded_client": 0,
                  "attack": {"total": {"sent": 5, "reached_upstream": 5,
                                       "blocked_by_shield": 0, "lab_4xx_5xx": 1},
                             "per_stage": {"recon": {"sent": 5, "reached_upstream": 5,
                                                     "blocked_by_shield": 0,
                                                     "lab_4xx_5xx": 1}}},
                  "benign": {"sent": 2, "blocked_or_altered_by_shield": 0,
                             "lab_4xx_5xx": 0, "blocked_by_rule": []},
                  "rules": "n/a", "time_to_protect": "n/a", "intent_accuracy": "n/a"},
            "C": {"records": 10, "refused_by_guarded_client": 0,
                  "attack": {"total": {"sent": 5, "reached_upstream": 3,
                                       "blocked_by_shield": 2, "lab_4xx_5xx": 1},
                             "per_stage": {"recon": {"sent": 5, "reached_upstream": 3,
                                                     "blocked_by_shield": 2,
                                                     "lab_4xx_5xx": 1}}},
                  "benign": {"sent": 2, "blocked_or_altered_by_shield": 0,
                             "lab_4xx_5xx": 0, "blocked_by_rule": []},
                  "rules": {"proposed": 3, "activated": 2, "rejected_by_gate": 1,
                            "escalations": 1},
                  "time_to_protect": {"recon": {"seconds": 0.05, "rule": "r1",
                                                "pre_activated": False},
                                      "injection": "not protected"},
                  "intent_accuracy": {"recon": {"correct": 2, "labelled": 5, "sent": 5,
                                                "accuracy": 0.4}}},
        },
    }
    (root / "example_shield_report").mkdir(exist_ok=True)
    (root / "example_shield_report" / "report.json").write_text(json.dumps(shield),
                                                                encoding="utf-8")
    if with_reference:
        ref_dir = root / "example_scan_report" / "vibe_notes_node_reference"
        ref_dir.mkdir(exist_ok=True)
        ref = {"provenance": {"target_id": "vibe_notes_node_reference",
                              "coverage_percent": 95.0, "requests_used": 100,
                              "request_budget": 500,
                              "model": {"provider": "none", "model": "none",
                                        "mode": "none"}},
               "findings": [{"verification": {"state": "confirmed"},
                             "candidate": {"id": "cf1"}}],
               "limitations": ["clean copy"]}
        (ref_dir / "report.json").write_text(json.dumps(ref), encoding="utf-8")
    # example_model_assisted_scan is needed for provenance to be fully OK
    mas_dir = root / "example_model_assisted_scan"
    mas_dir.mkdir(exist_ok=True)
    mas = {"provenance": {"target_id": "vibe_notes_node", "coverage_percent": 90.0,
                          "requests_used": 50, "request_budget": 500,
                          "session_id": "ses_mas", "date_utc": "2026-10-31T00:00:00Z",
                          "git_commit": "abc", "profile_name": "lab_default",
                          "profile_version": "1", "profile_sha256": "abc",
                          "scanner_version": "1", "authz_status": "VERIFIED",
                          "duration_ms": 1000, "stop_reason": "budget",
                          "model": {"provider": "nvidia",
                                    "model": "meta/muse-glimmer-30b", "mode": "LIVE"},
                          "plan_prompt_version": None, "explain_prompt_version": None},
           "findings": [], "by_vuln_class": {}, "coverage_ledger": {"rows": []},
           "plan": {"checks": [], "used_model": False, "note": "scripted"},
           "explain": {"used_model": False, "note": "", "count": 0},
           "skipped_checks": [], "limitations": ["model-assisted scan"]}
    (mas_dir / "report.json").write_text(json.dumps(mas), encoding="utf-8")
    return root


def test_scan_not_labeled_simulated(tmp_path):
    root = _make_full_fixture(tmp_path)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8")
    scan_start = html_text.index("Site Guard scan")
    fix_start = html_text.index("Fix engine")
    scan_html = html_text[scan_start:fix_start]
    assert "SIMULATED" not in scan_html
    assert "OBSERVED" in scan_html
    assert "SCORED against planted ground truth" in scan_html


def test_no_question_mark_none_or_protecteds(tmp_path):
    root = _make_full_fixture(tmp_path)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8")
    for banned in ("?/", ">None<", "None<", "protecteds", ">?<"):
        assert banned not in html_text, banned


def test_arm_a_defended_only_metric_shows_na(tmp_path):
    root = _make_full_fixture(tmp_path)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8")
    assert "n/a (defended runs only)" in html_text
    # arm A card must not show task_preservation as a bare rate
    agent_start = html_text.index("Agent Guard results")
    evcs_start = html_text.index("Containment")
    agent_html = html_text[agent_start:evcs_start]
    assert agent_html.count("task_preservation") == 6  # 2 tables x 2 arms + 2 cards (arm B only)


def test_rejected_fix_never_shows_explanation_as_result(tmp_path):
    root = _make_full_fixture(tmp_path)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8")
    assert "model's description of its proposed patch (not verified)" in html_text
    assert "no patch produced" in html_text
    assert "benign broke" in html_text  # failing check reason shown for REJECTED
    assert "The model proposes to fix this" in html_text
    fix_start = html_text.index("Fix engine")
    integrity_start = html_text.index("Evidence integrity")
    fix_html = html_text[fix_start:integrity_start]
    assert fix_html.index("model's description") < fix_html.index("The model proposes")


def test_benign_caveat_present_with_gate_rejected_count(tmp_path):
    root = _make_full_fixture(tmp_path)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8")
    assert "benign-replay gate" in html_text
    assert "which rejected 1 rules" in html_text


def test_footer_consistent_with_not_available(tmp_path):
    root = _make_full_fixture(tmp_path, with_reference=True)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8")
    assert "some sections not available" in html_text
    assert "all sections available" not in html_text
    # without the reference lab the footer flips to "all sections available"
    root2 = _make_full_fixture(tmp_path / "full", with_reference=False)
    sections2 = load_all(root2)
    result2 = render_index(sections2, check_integrity(root2, None),
                           tmp_path / "full_index.html")
    html2 = result2.out_path.read_text(encoding="utf-8")
    assert "all sections available" in html2


def test_accuracy_equals_correct_over_sent(tmp_path):
    root = _make_full_fixture(tmp_path)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    html_text = result.out_path.read_text(encoding="utf-8")
    # recon: correct=2, sent=5 -> accuracy 0.400
    assert "<td>2</td><td>5</td><td>0.400</td>" in html_text


def test_model_dict_provenance_renders_provider_model_mode(tmp_path):
    root = _make_full_fixture(tmp_path)
    sections = load_all(root)
    prov = sections["provenance:example_report_model"]
    assert prov.ok
    assert "/" in prov.data.model_label
    assert "(" in prov.data.model_label


# ---------------------------------------------------------------- 13 html-fix tests
def _build_html(tmp_path: Path) -> str:
    root = _make_full_fixture(tmp_path)
    sections = load_all(root)
    result = render_index(sections, check_integrity(root, None), tmp_path / "index.html")
    return result.out_path.read_text(encoding="utf-8")


def test_balanced_tags(tmp_path):
    from html.parser import HTMLParser

    class TagBalance(HTMLParser):
        VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
                "link", "meta", "param", "source", "track", "wbr"}

        def __init__(self):
            super().__init__()
            self.stack: list[str] = []
            self.errors: list[str] = []

        def handle_starttag(self, tag: str, attrs) -> None:
            if tag not in self.VOID:
                self.stack.append(tag)

        def handle_endtag(self, tag: str) -> None:
            if tag in self.VOID:
                return
            if self.stack and self.stack[-1] == tag:
                self.stack.pop()
            else:
                self.errors.append(f"unexpected </{tag}>, stack top: "
                                   f"{self.stack[-1] if self.stack else 'empty'}")

    html_text = _build_html(tmp_path)
    parser = TagBalance()
    parser.feed(html_text)
    assert not parser.errors, parser.errors[:5]
    assert not parser.stack, f"unclosed tags: {parser.stack}"


def test_no_double_escaped_entities(tmp_path):
    html_text = _build_html(tmp_path)
    assert "&middot;" not in html_text
    assert "&amp;" not in html_text
    assert "\u00b7" in html_text
