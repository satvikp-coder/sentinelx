"""Tests for sentinelx CLI: site, shield, escalations, agent check (Phase B). No network."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from sentinelx_cli import escalations as esc_mod
from sentinelx_cli import shield_cmd as shield_mod
from sentinelx_cli import site as site_mod

CLI = "from sentinelx_cli.main import main; sys.exit(main())"
REPO = Path(__file__).resolve().parents[2]
FAKE = "fake_secret_value_do_not_print_456"


def run_cli(*argv: str, cwd: Path, env: dict | None = None):
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    cmd = [sys.executable, "-c", f"import sys; sys.argv={list(argv)!r}; {CLI}"]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(cwd), env=full_env)


def test_site_add_lab_registers(tmp_path):
    result = run_cli("sentinelx", "site", "add", "http://127.0.0.1:18081", "--lab", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "registered lab target" in result.stdout


def test_site_add_lab_rejects_non_loopback(tmp_path):
    result = run_cli("sentinelx", "site", "add", "http://example.com", "--lab", cwd=tmp_path)
    assert result.returncode == 2
    assert "--lab only allowed" in result.stderr


def test_site_add_non_lab_prints_token_and_does_not_scan(tmp_path):
    result = run_cli("sentinelx", "site", "add", "https://example.com", cwd=tmp_path)
    assert result.returncode == 0
    assert "ownership token:" in result.stdout
    assert ".well-known/sentinelx-verify.txt" in result.stdout
    assert "DISABLED unless ALLOW_NON_LAB_TARGETS=true" in result.stdout
    assert "nothing was scanned" in result.stdout
    assert "run_scan" not in result.stdout


def test_site_guard_refuses_non_lab_upstream(tmp_path):
    result = run_cli("sentinelx", "site", "guard", "--upstream", "http://example.com",
                     "--listen", "127.0.0.1:18090", cwd=tmp_path)
    assert result.returncode == 2
    assert "must be a lab target" in result.stderr


def test_agent_check_allow_and_block(tmp_path):
    shutil.copy(REPO / "configs/policy/default.yaml", tmp_path / "policy.yaml")
    shutil.copy(REPO / "configs/policy/signals.yaml", tmp_path / "signals.yaml")
    (tmp_path / "ok.json").write_text(json.dumps({
        "tool": "navigate", "arguments": {"url": "http://orders.lab.test/cart"},
        "allowed_hosts": ["orders.lab.test"]}), encoding="utf-8")
    (tmp_path / "bad.json").write_text(json.dumps({
        "tool": "navigate", "arguments": {"url": "http://evil.example/collect"},
        "allowed_hosts": ["orders.lab.test"]}), encoding="utf-8")

    ok = run_cli("sentinelx", "agent", "check", "--policy", "policy.yaml",
                 "--action", "ok.json", cwd=tmp_path)
    assert ok.returncode == 0, ok.stderr
    assert "decision: ALLOW" in ok.stdout
    assert "reason_code: SAFE_ALLOWLIST" in ok.stdout

    bad = run_cli("sentinelx", "agent", "check", "--policy", "policy.yaml",
                  "--action", "bad.json", cwd=tmp_path)
    assert bad.returncode == 0, bad.stderr
    assert "decision: BLOCK" in bad.stdout
    assert "reason_code: HOST_NOT_ALLOWED" in bad.stdout


def test_agent_check_invalid_policy_exits_2(tmp_path):
    (tmp_path / "policy.yaml").write_text("not: [valid]: yaml\n", encoding="utf-8")
    (tmp_path / "a.json").write_text('{"tool": "navigate"}', encoding="utf-8")
    result = run_cli("sentinelx", "agent", "check", "--policy", "policy.yaml",
                     "--action", "a.json", cwd=tmp_path)
    assert result.returncode == 2
    assert "invalid policy" in result.stderr


def test_shield_and_escalations_list_on_fresh_db(tmp_path):
    shield = run_cli("sentinelx", "shield", "list", cwd=tmp_path)
    assert shield.returncode == 0
    assert "No rules" in shield.stdout

    db = tmp_path / "fresh.sqlite"
    esc = run_cli("sentinelx", "escalations", "list", "--db", str(db), cwd=tmp_path)
    assert esc.returncode == 0
    assert "no escalation tickets" in esc.stdout


def test_site_scan_mocked_backend(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(site_mod, "run_script", lambda s, a: calls.append((s, a)) or 0)
    rc = site_mod._scan(argparse.Namespace(target_id="vibe_notes_node"))
    assert rc == 0
    assert calls == [("run_scan.py", ["--target", "vibe_notes_node"])]


def test_site_fix_mocked_backend(tmp_path, monkeypatch):
    monkeypatch.setattr(site_mod, "repo_root", lambda: tmp_path)
    run_dir = tmp_path / "evaluations" / "scan_runs" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(json.dumps({
        "provenance": {"target_id": "vibe_notes_node"}, "findings": []}), encoding="utf-8")
    repo_dir = tmp_path / "repo_dir"
    repo_dir.mkdir()
    calls = []
    monkeypatch.setattr(site_mod, "run_script", lambda s, a: calls.append((s, a)) or 0)

    rc = site_mod._fix(argparse.Namespace(target_id="vibe_notes_node", repo=str(repo_dir)))
    assert rc == 0
    assert calls == [("run_fix.py", ["--target", "vibe_notes_node",
                                     "--scan-report", str(run_dir / "report.json")])]
    # legacy call shape (no --patch-format given): the flag must NOT be added

    bad = site_mod._fix(argparse.Namespace(target_id="vibe_notes_node",
                                           repo=str(tmp_path / "missing")))
    assert bad == 1


def test_site_fix_patch_format_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr(site_mod, "repo_root", lambda: tmp_path)
    run_dir = tmp_path / "evaluations" / "scan_runs" / "run1"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(json.dumps({
        "provenance": {"target_id": "vibe_notes_node"}, "findings": []}), encoding="utf-8")
    repo_dir = tmp_path / "repo_dir"
    repo_dir.mkdir()
    calls = []
    monkeypatch.setattr(site_mod, "run_script", lambda s, a: calls.append((s, a)) or 0)

    base = {"target_id": "vibe_notes_node", "repo": str(repo_dir)}
    rc = site_mod._fix(argparse.Namespace(**base, patch_format="edits"))
    assert rc == 0
    assert calls[-1][1][-2:] == ["--patch-format", "edits"]

    rc = site_mod._fix(argparse.Namespace(**base, patch_format="diff"))
    assert rc == 0
    assert calls[-1][1][-2:] == ["--patch-format", "diff"]

    # omitted -> omitted: the configured default applies inside run_fix.py
    rc = site_mod._fix(argparse.Namespace(**base, patch_format=None))
    assert rc == 0
    assert "--patch-format" not in calls[-1][1]


def test_shield_wrapper_builds_real_arguments(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(shield_mod, "run_script", lambda s, a: calls.append((s, a)) or 0)
    ns = argparse.Namespace(db=str(tmp_path / "rules.sqlite"), rule_id="rule_1",
                            reason="cleanup", minutes=30, reviewer="satvik",
                            benign_file=None)
    assert shield_mod.shield_cmd(ns, "remove") == 0
    assert calls[-1] == ("shield_rules.py",
                         ["--db", str(tmp_path / "rules.sqlite"), "remove", "rule_1",
                          "--reason", "cleanup"])
    assert shield_mod.shield_cmd(ns, "extend") == 0
    assert calls[-1] == ("shield_rules.py",
                         ["--db", str(tmp_path / "rules.sqlite"), "extend", "rule_1",
                          "--minutes", "30"])
    assert shield_mod.shield_cmd(ns, "approve") == 0
    assert calls[-1] == ("shield_rules.py",
                         ["--db", str(tmp_path / "rules.sqlite"), "approve", "rule_1",
                          "--reviewer", "satvik", "--reason", "cleanup"])


def test_escalations_wrapper_builds_real_arguments(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(esc_mod, "run_script", lambda s, a: calls.append((s, a)) or 0)
    ns = argparse.Namespace(db=str(tmp_path / "e.sqlite"), ticket_id="esc_1",
                            reviewer="satvik", decision="approve", rationale="fixed")
    assert esc_mod.escalations_cmd(ns, "resolve") == 0
    assert calls[-1] == ("escalations.py",
                         ["resolve", "esc_1", "--reviewer", "satvik",
                          "--decision", "approve", "--rationale", "fixed",
                          "--db", str(tmp_path / "e.sqlite")])
    empty = argparse.Namespace(db=None)
    assert esc_mod.escalations_cmd(empty, "list") == 0
    assert calls[-1] == ("escalations.py", ["list"])


def test_doctor_and_site_never_print_secret_values(tmp_path):
    doctor = run_cli("sentinelx", "doctor", cwd=tmp_path, env={"MODEL_API_KEY": FAKE})
    assert doctor.returncode == 0
    assert FAKE not in doctor.stdout and FAKE not in doctor.stderr
    assert "MODEL_API_KEY: set" in doctor.stdout

    add = run_cli("sentinelx", "site", "add", "https://example.com", cwd=tmp_path,
                  env={"MODEL_API_KEY": FAKE, "ALLOW_NON_LAB_TARGETS": "1"})
    assert FAKE not in add.stdout and FAKE not in add.stderr
