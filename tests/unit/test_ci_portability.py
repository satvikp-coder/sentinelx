"""Regression contracts for failures exposed by the Python 3.11/Linux CI run."""
from __future__ import annotations

import copy
import json
import os
import stat

import pytest

from sentinelx.evaluation.report import numbers_signature
from sentinelx.fixer.models import RepoScope


@pytest.mark.parametrize("path", [r"..\..\windows\system32", r"C:\outside", r"C:outside",
                                  r"\\server\share\file", "/outside", "sub/../file"])
def test_portable_scope_rejects_foreign_path_syntax(tmp_path, path):
    scope = RepoScope(lab="synthetic", source_dir=tmp_path, work_dir=tmp_path / "work")
    scope.work_dir.mkdir()
    with pytest.raises(ValueError, match="escapes"):
        scope.resolve_in_scope(path)


def test_dry_run_is_complete_without_historical_scan_reports(tmp_path, monkeypatch):
    from scripts import final_run

    def unexpected(*args, **kwargs):
        raise AssertionError("dry-run launched a subprocess")

    monkeypatch.setattr(final_run.subprocess, "run", unexpected)
    manifest = tmp_path / "manifest.json"
    assert final_run.main(["--dry-run", "--evaluations", str(tmp_path / "empty"),
                           "--manifest-out", str(manifest)]) == 0
    result = json.loads(manifest.read_text())
    assert set(result["model_providers"]) == {"nvidia_glimmer", "baseten_spark_open"}
    assert all(s["skipped_reason"] == "dry-run: not executed" for s in result["steps"])
    fix = next(s for s in result["steps"] if s["name"] == "fix")
    assert fix["estimated"]["prerequisite_note"]
    assert fix["exit_code"] is None


def test_reproducibility_preserves_raw_browser_counts_and_exact_tool_counts():
    report = {"arms": {"B": {"decisions_by_rule": {"EGRESS_BLOCKED": 1, "TOOL_BLOCK": 1},
                            "overall": {"executed": 0}}},
              "pairing": {"pairs": 1}, "provenance": {"manifest_hash": "synthetic"}}
    retried = copy.deepcopy(report)
    retried["arms"]["B"]["decisions_by_rule"]["EGRESS_BLOCKED"] = 2
    assert numbers_signature(report) == numbers_signature(retried)
    assert retried["arms"]["B"]["decisions_by_rule"]["EGRESS_BLOCKED"] == 2
    changed = copy.deepcopy(retried)
    changed["arms"]["B"]["decisions_by_rule"]["TOOL_BLOCK"] = 2
    assert numbers_signature(changed) != numbers_signature(retried)
    changed = copy.deepcopy(retried)
    changed["arms"]["B"]["overall"]["executed"] = 1
    assert numbers_signature(changed) != numbers_signature(retried)
    changed = copy.deepcopy(retried)
    changed["arms"]["B"]["decisions_by_rule"]["EGRESS_BLOCKED"] = 0
    assert numbers_signature(changed) != numbers_signature(retried)


@pytest.mark.skipif(os.name != "posix", reason="POSIX bind-mount permissions require Linux")
def test_docker_scratch_is_writable_by_container_uid(tmp_path, monkeypatch):
    from apps import labctl

    monkeypatch.setattr(labctl, "LABS_DIR", tmp_path)
    lab = labctl.Lab("synthetic", "docker", 18080, "synthetic", "test.db")
    lab.dir.mkdir()
    labctl._prepare_docker_data(lab)
    assert stat.S_IMODE(lab.data_dir.stat().st_mode) == 0o777
    assert stat.S_IMODE((lab.data_dir / "uploads").stat().st_mode) == 0o777


def test_docker_scratch_rejects_redirected_data_before_mkdir(tmp_path, monkeypatch):
    from apps import labctl

    monkeypatch.setattr(labctl, "LABS_DIR", tmp_path)
    lab = labctl.Lab("synthetic", "docker", 18080, "synthetic", "test.db")
    lab.dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (lab.dir / "data").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink permission unavailable")
    with pytest.raises(labctl.LabError, match="redirect"):
        labctl._prepare_docker_data(lab)
    assert not (outside / "uploads").exists()


def test_lab_shutdown_refuses_reused_foreign_node_pid(tmp_path, monkeypatch):
    from apps import labctl

    monkeypatch.setattr(labctl, "LABS_DIR", tmp_path)
    lab = labctl.Lab("synthetic", "node", 18081, "", "test.db")
    lab.dir.mkdir()
    monkeypatch.setattr(labctl, "LABS", {"synthetic": lab})
    pf = labctl._pid_file(lab)
    pf.write_text("12345")
    terminated = []

    class ForeignNode:
        def name(self):
            return "node.exe"

        def cwd(self):
            return str(tmp_path / "another-app")

        def cmdline(self):
            return ["node", "server.js"]

        def terminate(self):
            terminated.append(True)

    monkeypatch.setattr(labctl.psutil, "Process", lambda pid: ForeignNode())
    with pytest.raises(labctl.LabError, match="refusing termination"):
        labctl.down("synthetic")
    assert not terminated
    assert pf.read_text() == "12345"


def test_fix_dispatch_uses_report_created_by_preceding_scan(tmp_path, monkeypatch):
    import subprocess

    from scripts import final_run

    evaluations = tmp_path / "evaluations"
    fix = next(s for s in final_run.build_steps(evaluations) if s.name == "fix")
    assert fix.commands == []
    report = evaluations / "scan_runs" / "new-run" / "report.json"
    observed = []

    def run(command, **kwargs):
        if command == ["synthetic-scan"]:
            report.parent.mkdir(parents=True)
            report.write_text(json.dumps({"provenance": {"target_id": "vibe_notes_node"}}))
        elif "scripts/run_fix.py" in command:
            observed.append(command[command.index("--scan-report") + 1])
        return subprocess.CompletedProcess(command, 0, "synthetic leaf", "")

    monkeypatch.setattr(final_run, "run_cmd", run)
    monkeypatch.setattr(final_run, "estimate_spend", lambda step: (0, "0.0607"))
    monkeypatch.setattr(final_run, "_build_child_env", lambda live: {})
    monkeypatch.setattr(final_run, "git_commit", lambda: "synthetic")
    monkeypatch.setattr(final_run, "shutdown_labs", lambda: None)
    result = final_run.execute([final_run.PlannedStep("scan", [["synthetic-scan"]]), fix],
        dry_run=False, only=None, continue_on_error=False, manifest_path=tmp_path / "manifest.json")
    assert result == 0
    assert observed == [str(report)]
