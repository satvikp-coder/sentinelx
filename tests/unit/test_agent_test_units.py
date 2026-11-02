"""Unit tests for the sentinelx agent test CLI (Task 24).

Tests the adapter protocol, adapter implementations, and runner logic
without requiring a live lab server or model calls.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from packages.agent_runtime.types import HistoryEntry, Observation
from packages.agent_test.adapter import (
    Adapter,
    AdapterResult,
    ExecutableAdapter,
    HttpAdapter,
    ScriptedAdapter,
    load_adapter,
)

# ---------------------------------------------------------------------------
# AdapterResult
# ---------------------------------------------------------------------------

def test_adapter_result_action():
    r = AdapterResult.action_result("navigate", {"url": "http://x/"}, "test")
    assert r.action == "navigate"
    assert r.arguments == {"url": "http://x/"}
    assert r.finish is False
    assert r.error is None


def test_adapter_result_finish():
    r = AdapterResult.finish_result("done", "test")
    assert r.finish is True
    assert r.answer == "done"


def test_adapter_result_error():
    r = AdapterResult.error_result("boom", "test")
    assert r.error == "boom"
    assert r.finish is False


# ---------------------------------------------------------------------------
# ScriptedAdapter (deterministic, no network)
# ---------------------------------------------------------------------------

def test_scripted_adapter_follows_script():
    a = ScriptedAdapter("s1", 8080)
    assert a.name == "scripted_naive"
    assert a.kind == "SIMULATED_ADAPTER:scripted_naive"

    obs = Observation(session_id="s1", step=1, now=datetime.now(UTC))
    hist: list[HistoryEntry] = []

    r1 = a.next_action(obs, hist)
    assert r1.action == "navigate"
    assert r1.arguments == {"url": "http://127.0.0.1:8080/"}
    assert r1.finish is False

    r2 = a.next_action(obs, hist)
    assert r2.action == "read_page"
    assert r2.finish is False

    r3 = a.next_action(obs, hist)
    assert r3.finish is True
    assert r3.answer == "task completed"

    # Script exhausted: still finish
    r4 = a.next_action(obs, hist)
    assert r4.finish is True


def test_scripted_adapter_reset():
    a = ScriptedAdapter("s1", 8080)
    obs = Observation(session_id="s1", step=1, now=datetime.now(UTC))
    a.next_action(obs, [])
    assert a._step == 1
    a.reset()
    assert a._step == 0
    r = a.next_action(obs, [])
    assert r.action == "navigate"


# ---------------------------------------------------------------------------
# ExecutableAdapter (no shell=True)
# ---------------------------------------------------------------------------

def test_executable_adapter_no_shell_true():
    # ExecutableAdapter passes argv directly to Popen; no shell parameter.
    a = ExecutableAdapter(["python", "-c", "pass"])
    assert a._proc is None
    # argv is a list, not a shell string
    assert isinstance(a.argv, list)
    assert a.argv == ["python", "-c", "pass"]


# ---------------------------------------------------------------------------
# HttpAdapter (127.0.0.1 only)
# ---------------------------------------------------------------------------

def test_http_adapter_rejects_public_url():
    with pytest.raises(ValueError, match="must be http://127.0.0.1"):
        HttpAdapter("http://example.com/")
    with pytest.raises(ValueError, match="must be http://127.0.0.1"):
        HttpAdapter("https://127.0.0.1:8080/")


def test_http_adapter_accepts_localhost():
    a = HttpAdapter("http://127.0.0.1:8080/adapter")
    assert a.url == "http://127.0.0.1:8080/adapter"
    a = HttpAdapter("http://localhost:8080/adapter")
    assert a.url == "http://localhost:8080/adapter"


# ---------------------------------------------------------------------------
# load_adapter
# ---------------------------------------------------------------------------

def test_load_adapter_scripted():
    a = load_adapter("scripted:s1:8080")
    assert isinstance(a, ScriptedAdapter)
    assert a.scenario_id == "s1"
    assert a.lab_port == 8080


def test_load_adapter_exec():
    a = load_adapter("exec:python myserver.py")
    assert isinstance(a, ExecutableAdapter)
    assert a.argv == ["python", "myserver.py"]


def test_load_adapter_http():
    a = load_adapter("http://127.0.0.1:8080/adapter")
    assert isinstance(a, HttpAdapter)


def test_load_adapter_unknown():
    with pytest.raises(ValueError, match="unknown adapter spec"):
        load_adapter("ftp://example.com/")


def test_load_adapter_bad_scripted():
    with pytest.raises(ValueError, match="invalid scripted adapter spec"):
        load_adapter("scripted:s1")


# ---------------------------------------------------------------------------
# Adapter base class contract
# ---------------------------------------------------------------------------

def test_adapter_is_abstract():
    with pytest.raises(TypeError):
        Adapter()  # type: ignore[abstract]


def test_adapter_has_required_attributes():
    class Concrete(Adapter):
        def next_action(self, observation, history):
            return AdapterResult.finish_result("x")

    c = Concrete()
    c.name = "test"
    assert hasattr(c, "next_action")
    assert hasattr(c, "reset")
    assert hasattr(c, "name")
    assert hasattr(c, "kind")


# ---------------------------------------------------------------------------
# Runner uses the adapter via the Planner seam
# ---------------------------------------------------------------------------

def test_adapter_to_planner_next_action_signature():
    """The adapter's next_action matches the Planner protocol signature."""
    import inspect

    from packages.agent_runtime.types import Planner

    assert hasattr(Planner, "next_action")
    # ScriptedAdapter must be callable with (observation, history)
    sig = inspect.signature(ScriptedAdapter.next_action)
    params = list(sig.parameters.keys())
    assert "self" in params
    assert "observation" in params
    assert "history" in params


# ---------------------------------------------------------------------------
# CLI errors
# ---------------------------------------------------------------------------

def test_cli_agent_test_invalid_adapter_spec():
    from cli.sentinelx_cli.agent_cmd import agent_test
    # Invalid spec -> load_adapter raises -> exit code 2
    code = agent_test("ftp://bad/", "vibe_notes_node", "s1")
    assert code == 2
