"""sentinelx.evaluation.scan_scoring against a synthetic finding set (no network, no labs)."""

from __future__ import annotations

from sentinelx.evaluation.scan_scoring import (
    CLASS_MAP,
    budget_usage,
    clean_copy_check,
    load_planted,
    normalize_endpoint,
    score,
)


def finding(vuln_class: str, method: str, endpoint: str, state: str,
           finding_id: str = "f1") -> dict:
    return {"candidate": {"id": finding_id, "vuln_class": vuln_class, "method": method,
                          "endpoint": endpoint, "endpoints": [endpoint], "summary": "s"},
            "verification": {"state": state}}


def test_normalize_endpoint_folds_id_shapes() -> None:
    assert normalize_endpoint("/api/notes/42") == "/api/notes/{id}"
    assert normalize_endpoint("/api/notes/:id") == "/api/notes/{id}"
    assert normalize_endpoint("/api/notes/{id}") == "/api/notes/{id}"
    assert normalize_endpoint("/order_view.php?id=1") == "/order_view.php"
    assert normalize_endpoint("/Index.PHP/") == "/index.php"
    assert normalize_endpoint("/") == "/"


def test_class_map_covers_every_planted_class_in_both_real_labs() -> None:
    for lab in ("vibe_shop_php", "vibe_notes_node"):
        manifest = load_planted(lab)
        for w in manifest.weaknesses:
            assert w.vuln_class in CLASS_MAP, (lab, w.id, w.vuln_class)


def test_exact_recall_and_unmatched_on_a_synthetic_result_set() -> None:
    manifest = load_planted("vibe_shop_php")
    sql = next(w for w in manifest.weaknesses if w.vuln_class == "SQL_INJECTION")
    bola = next(w for w in manifest.weaknesses if w.vuln_class == "BROKEN_OBJECT_AUTHORIZATION")
    findings = [
        finding("sql_injection", sql.method, sql.endpoint, "confirmed", "f_sql"),
        finding("broken_object_authorization", bola.method, bola.endpoint, "confirmed", "f_bola"),
        finding("reflected_xss", "GET", "/totally/unrelated/path", "confirmed", "f_extra"),
        finding("debug_exposure", "GET", "/info.php", "needs_validation", "f_nv"),
        finding("verbose_errors", "GET", "/x", "rejected", "f_rej"),
    ]
    result = score("vibe_shop_php", findings)
    assert result.planted_found == sorted([sql.id, bola.id])
    assert sql.id not in result.planted_missed and bola.id not in result.planted_missed
    assert len(result.planted_missed) == len(manifest.weaknesses) - 2
    assert result.overall == {"name": "recall_overall", "numerator": 2,
                              "denominator": len(manifest.weaknesses), "value": round(
                                  2 / len(manifest.weaknesses), 6)}
    assert result.per_class["SQL_INJECTION"]["value"] == 1.0
    assert [u["finding_id"] for u in result.unmatched_confirmed] == ["f_extra"]
    assert result.needs_validation == 1 and result.rejected == 1


def test_a_finding_on_the_wrong_method_or_endpoint_does_not_match() -> None:
    manifest = load_planted("vibe_notes_node")
    rate = next(w for w in manifest.weaknesses if w.vuln_class == "NO_RATE_LIMITING")
    wrong_method = finding("missing_rate_limit", "GET", rate.endpoint, "confirmed")
    wrong_endpoint = finding("missing_rate_limit", rate.method, "/nowhere", "confirmed")
    assert score("vibe_notes_node", [wrong_method]).planted_found == []
    assert score("vibe_notes_node", [wrong_endpoint]).planted_found == []
    right = finding("missing_rate_limit", rate.method, rate.endpoint, "confirmed")
    assert score("vibe_notes_node", [right]).planted_found == [rate.id]


def test_an_any_method_planted_item_matches_either_method(tmp_path) -> None:
    import json

    lab_dir = tmp_path / "fake_lab"
    lab_dir.mkdir()
    (lab_dir / "PLANTED.json").write_text(json.dumps({
        "lab": "fake_lab", "language": "php", "base_port": 1, "note": "n", "weaknesses": [{
            "id": "F-01", "vuln_class": "SQL_INJECTION", "severity": "high", "file": "a.php",
            "line_start": 1, "line_end": 1, "endpoint": "/any.php", "method": "ANY",
            "description": "d", "safe_confirmation_strategy": "observe",
            "expected_fix_category": "PARAMETERIZE_QUERY", "requires_human_decision": False}]}),
        encoding="utf-8")
    get_hit = score("fake_lab", [finding("sql_injection", "GET", "/any.php", "confirmed")],
                    labs_root=tmp_path)
    post_hit = score("fake_lab", [finding("sql_injection", "POST", "/any.php", "confirmed")],
                     labs_root=tmp_path)
    assert get_hit.planted_found == ["F-01"] and post_hit.planted_found == ["F-01"]


def test_clean_copy_check_counts_only_the_labs_own_planted_classes() -> None:
    findings_on_reference = [
        finding("sql_injection", "GET", "/product.php", "confirmed", "leaked"),
        finding("reflected_xss", "GET", "/contact.php", "needs_validation", "nv"),
        finding("permissive_cors", "GET", "/somewhere-not-in-planted", "confirmed", "other"),
    ]
    result = clean_copy_check("vibe_shop_php", findings_on_reference)
    assert result.false_findings_count == 2
    assert {f["finding_id"] for f in result.false_findings} == {"leaked", "other"}


def test_clean_copy_check_is_zero_on_an_empty_result_set() -> None:
    assert clean_copy_check("vibe_notes_node", []).false_findings_count == 0


def test_budget_usage_has_a_numerator_and_denominator() -> None:
    d = budget_usage(37, 500)
    assert d["numerator"] == 37 and d["denominator"] == 500 and 0 < d["value"] < 1


def test_missing_denominator_raises() -> None:
    import pytest

    from sentinelx.evaluation.metrics import MetricError, rate

    with pytest.raises(MetricError):
        rate("x", 1, 0)
    with pytest.raises(MetricError):
        rate("x", None, 10)
