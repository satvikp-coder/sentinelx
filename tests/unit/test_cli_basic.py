"""Tests for sentinelx CLI: doctor, init (Phase A)."""

from __future__ import annotations

import os
import subprocess
import sys

CLI = "from sentinelx_cli.main import main; sys.exit(main())"


def run_cli(*argv: str, cwd: str | None = None, env: dict | None = None):
    """Run the CLI in-process via `python -c` and return the CompletedProcess."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    cmd = [sys.executable, "-c", f"import sys; sys.argv={list(argv)!r}; {CLI}"]
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env=full_env)


def test_help_lists_all_commands():
    result = run_cli("sentinelx", "--help")
    assert result.returncode == 0
    for name in ("doctor", "init", "site", "shield", "escalations", "agent"):
        assert name in result.stdout


def test_doctor_exits_zero_and_reports_checks():
    result = run_cli("sentinelx", "doctor")
    assert result.returncode == 0
    assert "Python:" in result.stdout
    assert "All checks PASSED" in result.stdout
    assert "Lab ports:" in result.stdout


def test_init_creates_both_files(tmp_path):
    result = run_cli("sentinelx", "init", cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "sentinelx.site.yaml").is_file()
    assert (tmp_path / "sentinelx.agent.yaml").is_file()
    assert "Created: sentinelx.site.yaml" in result.stdout


def test_init_refuses_overwrite_without_force(tmp_path):
    run_cli("sentinelx", "init", cwd=str(tmp_path))
    result = run_cli("sentinelx", "init", cwd=str(tmp_path))
    assert result.returncode == 1
    assert "already exist" in result.stderr
    assert "--force" in result.stderr


def test_init_force_overwrites(tmp_path):
    (tmp_path / "sentinelx.site.yaml").write_text("# old\n", encoding="utf-8")
    result = run_cli("sentinelx", "init", "--force", cwd=str(tmp_path))
    assert result.returncode == 0
    text = (tmp_path / "sentinelx.site.yaml").read_text(encoding="utf-8")
    assert "SentinelX Site Guard configuration" in text


def test_doctor_never_prints_secret_values():
    fake = "fake_secret_value_do_not_print_123"
    result = run_cli("sentinelx", "doctor", env={"MODEL_API_KEY": fake})
    assert result.returncode == 0
    assert fake not in result.stdout
    assert fake not in result.stderr
    assert "MODEL_API_KEY: set" in result.stdout
