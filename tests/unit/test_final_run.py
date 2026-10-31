"""Tests for scripts/final_run.py (all subprocess calls mocked; nothing runs)."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("final_run", REPO / "scripts" / "final_run.py")
fr = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault("final_run", fr)
SPEC.loader.exec_module(fr)

FAKE_KEY = "fake-secret-key-abc123"


def ok_proc(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=cmd, returncode=0,
                                       stdout="$0.0607 worst case\nOK", stderr="")


def proc(cmd: list[str], code: int, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=cmd, returncode=code, stdout=out, stderr=err)


@pytest.fixture()
def recorder(monkeypatch):
    calls: list[list[str]] = []

    def _run(cmd, timeout=3600):
        calls.append(list(cmd))
        return ok_proc(cmd)

    monkeypatch.setattr(fr, "run_cmd", _run)
    monkeypatch.setattr(fr, "git_commit", lambda: "testcommit")
    return calls


def test_dry_run_runs_nothing(recorder, tmp_path):
    manifest = tmp_path / "run_manifest.json"
    code = fr.main(["--dry-run", "--manifest-out", str(manifest)])
    assert code == 0
    step_cmds = [c for c in recorder
                 if not any(part.endswith("estimate_cost.py") for part in c)]
    assert step_cmds == [], "dry-run must not execute any evaluation step"
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    assert doc["dry_run"] is True
    assert all(s["exit_code"] is None for s in doc["steps"])
    assert all(str(s["skipped_reason"]).startswith("dry-run") for s in doc["steps"])


def test_failing_step_stops_and_manifest_records(recorder, tmp_path, monkeypatch):
    def _run(cmd, timeout=3600):
        recorder.append(list(cmd))
        if any(part.endswith("run_experiment.py") for part in cmd):
            return proc(cmd, 1, err="boom")
        return ok_proc(cmd)

    monkeypatch.setattr(fr, "run_cmd", _run)
    manifest = tmp_path / "run_manifest.json"
    code = fr.main(["--only", "agent_scripted", "--manifest-out", str(manifest)])
    assert code == 1
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    assert doc["steps"][0]["exit_code"] == 1
    assert "boom" in doc["steps"][0]["output_tail"]
    assert any("lab_down.py" in " ".join(c) for c in recorder), "labs must be shut down"
    ran_after = [c for c in recorder if any(p.endswith("run_model_experiment.py") for p in c)]
    assert ran_after == [], "run must stop at the first failing step"


def test_over_budget_step_is_refused(recorder, tmp_path, monkeypatch):
    def _run(cmd, timeout=3600):
        recorder.append(list(cmd))
        if any(part.endswith("estimate_cost.py") for part in cmd):
            return proc(cmd, 3, out="refused: over budget")
        return ok_proc(cmd)

    monkeypatch.setattr(fr, "run_cmd", _run)
    manifest = tmp_path / "run_manifest.json"
    code = fr.main(["--only", "agent_model", "--manifest-out", str(manifest)])
    assert code == 3
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    step = doc["steps"][0]
    assert step["estimated"]["guard_exit_code"] == 3
    assert step["exit_code"] is None
    ran = [c for c in recorder if any("run_model_experiment" in p for p in c)]
    assert ran == [], "the refused step must not run"


def test_only_runs_a_single_step(recorder, tmp_path):
    manifest = tmp_path / "run_manifest.json"
    code = fr.main(["--only", "report", "--manifest-out", str(manifest)])
    assert code == 0
    step_cmds = [c for c in recorder
                 if not any(part.endswith("estimate_cost.py") for part in c)
                 and not any(part.endswith("lab_down.py") for part in c)]
    assert len(step_cmds) == 1
    assert any(part == "report" for part in step_cmds[0])
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    assert [s["name"] for s in doc["steps"]] == ["report"]


def test_no_key_like_string_in_any_output(recorder, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MODEL_API_KEY", FAKE_KEY)
    manifest = tmp_path / "run_manifest.json"
    code = fr.main(["--dry-run", "--manifest-out", str(manifest)])
    assert code == 0
    captured = capsys.readouterr()
    assert FAKE_KEY not in captured.out
    assert FAKE_KEY not in captured.err
    assert FAKE_KEY not in manifest.read_text(encoding="utf-8")
