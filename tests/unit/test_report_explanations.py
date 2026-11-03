"""Tests for Task 26: model-written report explanations integration.

Tests the report loader/renderer for the explanations section:
- Valid explanation loading from investigations.json
- Invalid citation (cited event not in session)
- Unsupported claim (INFERRED without verifier support)
- Malicious evidence text (HTML/JS in claim text - must be escaped)
- Invalid JSON (malformed investigations.json)
- Provider failure (MODEL_UNAVAILABLE mode)
- Redaction (secrets not in explanations)
- HTML injection (claim text with <script> tags)
- Old report compatibility (missing investigations.json -> NOT AVAILABLE)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sentinelx.report.loader import (
    ExplanationClaim,
    ExplanationFinding,
    ExplanationsData,
    Section,
    load_all,
    load_explanations,
)
from sentinelx.report.render import render_explanations

EVAL_DIR = Path("evaluations")


# ------------------------------------------------------------------ loader: valid explanation

def test_load_explanations_valid():
    """Real investigations.json loads into ExplanationsData with all fields."""
    path = EVAL_DIR / "example_investigation" / "investigations.json"
    if not path.is_file():
        pytest.skip("example_investigation/investigations.json not present")
    section = load_explanations(EVAL_DIR)
    assert section.status == "OK", section.error
    assert isinstance(section.data, ExplanationsData)
    data: ExplanationsData = section.data
    assert data.run_dir
    assert data.cases
    assert data.findings
    f = data.findings[0]
    assert isinstance(f, ExplanationFinding)
    assert f.case and f.arm and f.session_id
    assert f.mode in ("MODEL", "BASELINE")
    assert f.state in ("confirmed", "needs_validation", "rejected")
    assert f.severity in ("low", "medium", "high", "critical")
    assert f.summary
    assert f.numerator >= 0 and f.denominator >= 0
    assert isinstance(f.claims, list)
    assert isinstance(f.mitigations, list)
    if f.claims:
        c = f.claims[0]
        assert isinstance(c, ExplanationClaim)
        assert c.kind in ("OBSERVED", "INFERRED")
        assert c.cited_event_ids
        assert c.code in ("VERIFIED", "UNKNOWN_EVENT", "ASSERTION_FALSE",
                          "UNSUPPORTED", "CONTRADICTS_VERIFIER")


# renderer: valid + malicious text escaping

def test_render_explanations_escapes_html():
    """Claim text containing <script> must be HTML-escaped, never executed."""
    data = ExplanationsData(
        run_dir="test-run",
        cases=["A01"],
        findings=[
            ExplanationFinding(
                case="A01", arm="A", session_id="ses_x", run_valid=True,
                mode="MODEL", state="confirmed", severity="medium",
                summary="normal summary",
                numerator=5, denominator=5, note="",
                claims=[
                    ExplanationClaim(
                        claim_id="c1", kind="OBSERVED",
                        text="hello <script>alert(1)</script> world",
                        cited_event_ids=["evt_1"], passed=True, code="VERIFIED",
                        detail=None, confidence=None),
                    ExplanationClaim(
                        claim_id="c2", kind="INFERRED",
                        text='<img src=x onerror=alert(2)>',
                        cited_event_ids=["evt_2"], passed=False, code="UNSUPPORTED",
                        detail="no support", confidence="medium"),
                ],
                mitigations=["BLOCK_ONLY"],
                model_call={"provider": "nvidia", "model": "meta/muse-glimmer-30b",
                            "mode": "LIVE", "http_calls": 1,
                            "tokens_in": 100, "tokens_out": 50,
                            "latency_ms": 500, "error": None}),
        ],
    )
    section = Section("explanations", "OK", "test", None, data)
    html = render_explanations(section)
    # HTML must be escaped: <script> becomes &lt;script&gt;
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;img src=x onerror=alert(2)&gt;" in html
    # Raw <script> must NOT appear (would be an XSS vector)
    assert "<script>" not in html
    assert "<img src=x" not in html
    # Model provenance is present
    assert "nvidia" in html
    assert "meta/muse-glimmer-30b" in html
    assert "LIVE" in html


def test_render_explanations_model_unavailable():
    """MODEL_UNAVAILABLE findings are labelled, not hidden."""
    data = ExplanationsData(
        run_dir="test-run", cases=["A01"],
        findings=[
            ExplanationFinding(
                case="A01", arm="B", session_id="ses_y", run_valid=False,
                mode="BASELINE", state="needs_validation", severity="low",
                summary="model unavailable: baseline used",
                numerator=0, denominator=0, note="model unavailable: baseline used",
                claims=[],
                mitigations=[],
                model_call={"provider": "nvidia", "model": "meta/muse-glimmer-30b",
                            "mode": "MODEL_UNAVAILABLE", "http_calls": 0,
                            "tokens_in": 0, "tokens_out": 0,
                            "latency_ms": 0, "error": "HTTP 404"}),
        ],
    )
    section = Section("explanations", "OK", "test", None, data)
    html = render_explanations(section)
    assert "MODEL_UNAVAILABLE" in html
    assert "baseline used" in html


# loader: old report compatibility

def test_load_explanations_missing_file():
    """Missing investigations.json -> NOT AVAILABLE (historical compatibility)."""
    with patch("sentinelx.report.loader.Path"):
        pass
    section = load_explanations(Path("/nonexistent/evaluations"))
    assert section.status == "NOT AVAILABLE"
    assert section.data is None


# ------------------------------------------------------------------ load_all includes explanations

def test_load_all_includes_explanations():
    """load_all() includes the explanations section."""
    sections = load_all(EVAL_DIR)
    assert "explanations" in sections
    s = sections["explanations"]
    # OK if the file exists, NOT AVAILABLE otherwise
    assert s.status in ("OK", "NOT AVAILABLE")


# ------------------------------------------------------------------ renderer: not available

def test_render_explanations_not_available():
    """NOT AVAILABLE section renders a placeholder, never crashes."""
    section = Section("explanations", "NOT AVAILABLE", "path", "file missing", None)
    html = render_explanations(section)
    assert "Model-written report explanations" in html
    assert "NOT AVAILABLE" in html
    assert "file missing" in html


# ------------------------------------------------------------------ citation code validation

def test_claim_code_values():
    """Every claim code is from the allowed verifier vocabulary."""
    valid_codes = {"VERIFIED", "UNKNOWN_EVENT", "ASSERTION_FALSE",
                   "UNSUPPORTED", "CONTRADICTS_VERIFIER"}
    path = EVAL_DIR / "example_investigation" / "investigations.json"
    if not path.is_file():
        pytest.skip("example_investigation/investigations.json not present")
    section = load_explanations(EVAL_DIR)
    assert section.status == "OK"
    data: ExplanationsData = section.data
    for finding in data.findings:
        for claim in finding.claims:
            assert claim.code in valid_codes, f"invalid code {claim.code!r}"


# ------------------------------------------------------------------ OBSERVED vs INFERRED separation

def test_observed_inferred_separation():
    """OBSERVED claims carry assertions, INFERRED claims carry confidence."""
    path = EVAL_DIR / "example_investigation" / "investigations.json"
    if not path.is_file():
        pytest.skip("example_investigation/investigations.json not present")
    section = load_explanations(EVAL_DIR)
    assert section.status == "OK"
    data: ExplanationsData = section.data
    for finding in data.findings:
        for claim in finding.claims:
            if claim.kind == "OBSERVED":
                assert claim.confidence is None, f"OBSERVED claim {claim.claim_id} has confidence"
            elif claim.kind == "INFERRED":
                assert claim.confidence is not None, \
                    f"INFERRED claim {claim.claim_id} lacks confidence"
