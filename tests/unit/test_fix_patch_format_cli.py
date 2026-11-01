"""Tests that --patch-format is parsed by scripts/run_fix.py and reaches the generator
selection (orchestrate.run_fix's patch_format argument). Mocked routing + recorder for
run_fix; no live model calls, no Docker."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

ROOT = Path(__file__).resolve().parents[2]


def _load_script():
    spec = importlib.util.spec_from_file_location("run_fix_script",
                                                  ROOT / "scripts" / "run_fix.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_scan_report(tmp_path: Path) -> Path:
    report = {"findings": [{"candidate": {"id": "cand_1", "vuln_class": "sql_injection",
                                          "method": "GET", "endpoint": "/user",
                                          "summary": "s", "param": None},
                            "verification": {"state": "confirmed"}}]}
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


@pytest.fixture
def script(monkeypatch):
    mod = _load_script()
    captured: list[dict] = []

    def fake_run_fix(finding, **kwargs):
        captured.append(kwargs)
        return SimpleNamespace(status="AWAITING_APPROVAL", patch_id="p1", ticket_id=None,
                               retries_used=0)

    def fake_resolve_task(conn, models_config, task):
        from sentinelx.model_clients import ModelConfig

        return SimpleNamespace(status="OK", profile_name="test_profile",
                               fallback_used=False,
                               config=ModelConfig(provider="nvidia",
                                                  base_url="https://api.example.test/v1",
                                                  model="meta/mock",
                                                  api_key=SecretStr("sk-fake-test-key-000"),
                                                  max_rpm=6000, max_retries=0))

    monkeypatch.setattr(mod, "run_fix", fake_run_fix)
    monkeypatch.setattr(mod, "resolve_task", fake_resolve_task)
    return mod, captured


def _run(script_mod, tmp_path, *extra):
    mod, captured = script_mod
    argv = ["run_fix.py", "--target", "vibe_notes_node",
            "--scan-report", str(_write_scan_report(tmp_path)),
            "--db", str(tmp_path / "fix.sqlite"), *extra]
    monkeypatch_argv = argv
    old = sys.argv
    sys.argv = monkeypatch_argv
    try:
        rc = mod.main()
    finally:
        sys.argv = old
    return rc, captured


def test_patch_format_edits_reaches_generator_selection(script, tmp_path, monkeypatch):
    rc, captured = _run(script, tmp_path, "--patch-format", "edits")
    assert rc == 0
    assert len(captured) == 1
    assert captured[0]["patch_format"] == "edits"


def test_patch_format_diff_reaches_generator_selection(script, tmp_path, monkeypatch):
    rc, captured = _run(script, tmp_path, "--patch-format", "diff")
    assert rc == 0
    assert captured[0]["patch_format"] == "diff"


def test_patch_format_default_is_none_config_applies(script, tmp_path, monkeypatch):
    rc, captured = _run(script, tmp_path)
    assert rc == 0
    assert captured[0]["patch_format"] is None


def test_patch_format_unknown_value_fails_clearly(script, tmp_path, monkeypatch, capsys):
    mod, _ = script
    argv = ["run_fix.py", "--target", "x",
            "--scan-report", str(_write_scan_report(tmp_path)),
            "--db", str(tmp_path / "fix.sqlite"), "--patch-format", "bogus"]
    old = sys.argv
    sys.argv = argv
    try:
        with pytest.raises(SystemExit) as exc:
            mod.main()
    finally:
        sys.argv = old
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice" in err
