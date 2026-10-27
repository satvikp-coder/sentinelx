"""Sandbox boundary (both arms), redirects, protected-arm execution guard, clean shutdown."""

from __future__ import annotations

import socket
import tempfile
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil
import pytest

from apps.fixture_lab.server import LabServer
from sentinelx.agent_runtime import (
    ActionOutcome,
    Finish,
    HistoryEntry,
    KillSwitch,
    Observation,
    RunConfig,
    run_session_sync,
)
from sentinelx.agent_runtime.adapter import BrowserAdapter
from sentinelx.common_schemas import ActionRequest, Arm, Decision, SessionState
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.store import EvidenceStore
from sentinelx.policy import PolicyConfig
from tests.e2e.conftest import load_spec

pytestmark = pytest.mark.browser


class ListPlanner:
    """Test stub: replays a fixed list of (tool, args), then finishes. Not an agent."""

    name = "list-planner-test-stub"
    kind = "TEST_STUB"

    def __init__(self, actions: list[tuple[str, dict[str, Any]]],
                 hook: Callable[[int], None] | None = None, boom_at: int | None = None) -> None:
        self.actions, self.hook, self.boom_at, self.calls = actions, hook, boom_at, 0

    def next_action(self, obs: Observation, history: Sequence[HistoryEntry]
                    ) -> ActionRequest | Finish:
        self.calls += 1
        if self.hook:
            self.hook(self.calls)
        if self.boom_at == self.calls:
            raise RuntimeError("planner exploded")
        if obs.step - 1 >= len(self.actions):
            return Finish("done")
        tool, args = self.actions[obs.step - 1]
        return ActionRequest(session_id=obs.session_id, step=obs.step,
                             action_id=f"{obs.session_id}:{obs.step}", timestamp=datetime.now(UTC),
                             actor=self.name, tool=tool, arguments=args)


def run(db, lab, policy, sid, planner, arm, spec=None, **cfg):
    spec = spec or load_spec(sid)
    result = run_session_sync(db, lab, spec, planner, RunConfig(arm=arm, **cfg), policy)
    return result, EvidenceStore(db).list_session(result.session_id), lab.read_ledger()


def of_kind(events, kind):
    return [e for e in events if e.kind == kind]


# ------------------------------------------------------------------ sandbox: BOTH arms
def off_lab_urls(port: int) -> list[str]:
    return [
        "http://example.com/", "https://example.com/", "http://93.184.216.34/",
        f"http://127.0.0.1:{port}/collect", f"http://[::1]:{port}/", "http://orders.lab.test:1/",
        f"http://localhost:{port}/", "ftp://example.com/x", "file:///C:/Windows/win.ini",
        "data:text/html,<h1>x</h1>", "javascript:alert(1)",
    ]


def test_unprotected_arm_still_cannot_leave_the_lab(lab, db, lab_policy) -> None:
    urls = off_lab_urls(lab.port)
    actions: list[tuple[str, dict[str, Any]]] = [("navigate", {"url": u}) for u in urls]
    actions += [("http_request", {"method": "GET", "url": "http://example.com/"}),
                ("http_request", {"method": "POST", "url": f"http://127.0.0.1:{lab.port}/collect",
                                  "body": "x"}),
                ("http_request", {"method": "POST", "url": "http://collector.lab.test:1/collect",
                                  "body": "x"})]
    res, events, ledger = run(db, lab, lab_policy, "S1", ListPlanner(actions), Arm.UNPROTECTED)
    assert res.state is SessionState.COMPLETED
    executed = of_kind(events, "ACTION_EXECUTED")
    assert len(executed) == len(actions)
    assert all(e.payload["ok"] is False and e.payload["sandbox_blocked"] for e in executed)
    blocked = of_kind(events, "SANDBOX_BLOCKED")
    assert len(blocked) >= len(actions)
    assert ledger == [], "nothing may reach a lab endpoint through an off-lab or IP-literal URL"
    assert not of_kind(events, "ACTION_DECIDED")  # unprotected: the sandbox alone did this


def test_protected_arm_sandbox_is_independent_of_the_gateway(lab, db, lab_policy) -> None:
    # A scenario that (wrongly) lists example.com and a loopback IP as allowed: the GATEWAY
    # allows these navigations, and the SANDBOX still aborts them.
    spec = load_spec("S1").model_copy(update={"allowed_hosts": ["example.com", "127.0.0.1"]})
    actions = [("navigate", {"url": f"http://example.com:{lab.port}/"}),
               ("navigate", {"url": f"http://127.0.0.1:{lab.port}/orders/1042"}),
               ("navigate", {"url": "http://example.com/"})]
    res, events, ledger = run(db, lab, lab_policy, "S1", ListPlanner(actions), Arm.PROTECTED, spec)
    decisions = [e.payload["decision"] for e in of_kind(events, "ACTION_DECIDED")]
    assert [d["decision"] for d in decisions] == ["ALLOW", "ALLOW", "BLOCK"]
    assert decisions[2]["reason_code"] == "PORT_NOT_ALLOWED"
    executed = of_kind(events, "ACTION_EXECUTED")
    assert len(executed) == 2 and all(e.payload["sandbox_blocked"] for e in executed)
    assert len(of_kind(events, "SANDBOX_BLOCKED")) >= 2 and ledger == []
    assert res.state is SessionState.COMPLETED


def test_direct_adapter_blocks_off_lab_requests_and_reports_events() -> None:
    import asyncio

    async def go() -> list[tuple[str, dict[str, Any]]]:
        seen: list[tuple[str, dict[str, Any]]] = []
        async with BrowserAdapter(5999, lambda k, p: seen.append((k, p))) as adapter:
            req = lambda tool, **a: ActionRequest(  # noqa: E731
                session_id="s", step=1, action_id="a", timestamp=datetime.now(UTC), actor="t",
                tool=tool, arguments=a)
            out = await adapter.execute(req("navigate", url="http://example.com/"))
            assert out.ok is False and out.sandbox_blocked
            out = await adapter.execute(req("http_request", method="GET", url="http://1.1.1.1/"))
            assert out.ok is False and out.sandbox_blocked
            out = await adapter.execute(req("exec_shell", cmd="whoami"))
            assert out.ok is False and out.error.startswith("UNKNOWN_TOOL")
        return seen

    kinds = [k for k, _ in asyncio.run(go())]
    assert kinds.count("SANDBOX_BLOCKED") >= 2


# ------------------------------------------------------------------ redirects
def test_redirect_to_an_off_lab_host_is_aborted_in_both_arms(lab, db, lab_policy) -> None:
    url = f"http://orders.lab.test:{lab.port}/redirect?to=http://example.com/landing"
    for arm in (Arm.UNPROTECTED, Arm.PROTECTED):
        _, events, ledger = run(db, lab, lab_policy, "S1",
                                ListPlanner([("navigate", {"url": url})]), arm)
        assert any("example.com" in e.payload["url"] for e in of_kind(events, "SANDBOX_BLOCKED"))
        assert ledger == []


def test_redirect_hop_is_checked_with_the_policy_only_in_the_protected_arm(
        lab, db, lab_policy) -> None:
    url = (f"http://orders.lab.test:{lab.port}/redirect"
           f"?to=http://collector.lab.test:{lab.port}/collect")
    _, events_u, ledger_u = run(db, lab, lab_policy, "S1",
                                ListPlanner([("navigate", {"url": url})]), Arm.UNPROTECTED)
    assert len(ledger_u) == 1 and ledger_u[0]["path"] == "/collect"  # hop followed: side effect!
    assert not of_kind(events_u, "EGRESS_BLOCKED")
    _, events_p, ledger_p = run(db, lab, lab_policy, "S1",
                                ListPlanner([("navigate", {"url": url})]), Arm.PROTECTED)
    hops = of_kind(events_p, "EGRESS_BLOCKED")
    assert len(hops) == 1 and hops[0].payload["reason"] == "HOST_NOT_ALLOWED"
    assert hops[0].payload["channel"] == "redirect_hop"
    assert hops[0].payload["boundary"] == "page_egress_policy"
    assert ledger_p == [] and not of_kind(events_p, "SANDBOX_BLOCKED")


# ------------------------------------------------------------------ no execution without ALLOW
def test_adapter_is_never_called_in_the_protected_arm_without_a_prior_allow(
        lab, db, lab_policy, monkeypatch) -> None:
    calls: list[str] = []
    violations: list[str] = []
    original = BrowserAdapter.execute
    store = EvidenceStore(db)

    async def guarded(self: BrowserAdapter, request: ActionRequest) -> ActionOutcome:
        calls.append(request.tool)
        allowed = any(
            e.kind == "ACTION_DECIDED" and e.payload["decision"]["action_id"] == request.action_id
            and e.payload["decision"]["effective_action"] == "ALLOW"
            for e in store.list_session(request.session_id)
        )
        if not allowed:
            violations.append(request.action_id)
        return await original(self, request)

    monkeypatch.setattr(BrowserAdapter, "execute", guarded)
    from sentinelx.agent_runtime import ScriptedNaivePlanner

    for sid in ("S1", "S2", "S3", "B2"):
        run_session_sync(db, lab, load_spec(sid), ScriptedNaivePlanner(sid, lab.port),
                         RunConfig(arm=Arm.PROTECTED), lab_policy)
    assert calls and violations == []
    assert "http_request" not in calls, "every attack-driven http_request was blocked first"


def test_block_and_confirm_are_never_executed(lab, db, lab_policy) -> None:
    actions = [("http_request", {"method": "POST", "url": f"http://collector.lab.test:{lab.port}/"
                                                          "collect", "body": "x"}),
               ("exec_shell", {"cmd": "whoami"}), ("click", {"selector": "#nope", "x": "1"}),
               ("navigate", {"url": f"http://orders.lab.test:{lab.port}/orders/1042"})]
    res, events, ledger = run(db, lab, lab_policy, "S1", ListPlanner(actions), Arm.PROTECTED)
    decided = [e.payload["decision"] for e in of_kind(events, "ACTION_DECIDED")]
    assert [d["decision"] for d in decided] == ["BLOCK", "BLOCK", "BLOCK", "ALLOW"]
    assert len(of_kind(events, "ACTION_EXECUTED")) == 1 and ledger == []
    assert res.state is SessionState.COMPLETED  # blocked actions are events, not failures


def test_shorter_policy_step_cap_is_enforced_by_the_gateway(lab, db, lab_policy) -> None:
    from sentinelx.policy import LoadedPolicy

    tight = LoadedPolicy.from_config(
        PolicyConfig.model_validate({**lab_policy.config.model_dump(), "max_steps": 2}),
        lab_policy.signal_phrases)
    acts = [("navigate", {"url": f"http://orders.lab.test:{lab.port}/orders/1042"})] * 4
    res, events, _ = run(db, lab, tight, "S1", ListPlanner(acts), Arm.PROTECTED, max_steps=10)
    reasons = [e.payload["decision"]["reason_code"] for e in of_kind(events, "ACTION_DECIDED")]
    assert reasons[:2] == ["SAFE_ALLOWLIST"] * 2 and set(reasons[2:]) == {"MAX_STEPS_EXCEEDED"}
    assert res.state is SessionState.COMPLETED


# ------------------------------------------------------------------ lifecycle and cleanup
def leftovers(before: set[int]) -> list[psutil.Process]:
    """Child processes not present before the run (waits briefly for slow exits)."""
    extra = [p for p in psutil.Process().children(recursive=True) if p.pid not in before]
    _, alive = psutil.wait_procs(extra, timeout=5)
    return alive


def port_closed(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) != 0


def test_no_browser_process_or_port_is_left_after_a_run_a_cancel_and_a_crash() -> None:
    before = {p.pid for p in psutil.Process().children(recursive=True)}
    with tempfile.TemporaryDirectory() as tmp:
        server = LabServer(Path(tmp) / "led").start()
        port = server.port
        conn = connect(Path(tmp) / "d.db")
        migrate(conn)
        from sentinelx.policy import load_policy

        policy = load_policy(Path(__file__).resolve().parents[2] / "configs/policy/lab.yaml")
        url = ("navigate", {"url": f"http://orders.lab.test:{port}/orders/1042"})
        # normal run
        res, *_ = run(conn, server, policy, "S1", ListPlanner([url, ("read_page", {})]),
                      Arm.PROTECTED)
        assert res.state is SessionState.COMPLETED and leftovers(before) == []
        # cancel mid-run
        stop = threading.Event()
        res, events, _ = (lambda r: (r[0], r[1], r[2]))(run_with_cancel(conn, server, policy, stop,
                                                                          url))
        assert res.state is SessionState.CANCELLED and res.abort_reason == "CANCELLED"
        assert leftovers(before) == []
        # planner crash
        res, events, _ = run(conn, server, policy, "S1",
                             ListPlanner([url, url], boom_at=2), Arm.UNPROTECTED)
        assert res.state is SessionState.FAILED and res.abort_reason == "RUNTIME_ERROR"
        assert of_kind(events, "RUN_ERROR")[0].payload["error_class"] == "RuntimeError"
        assert leftovers(before) == []
        conn.close()
        server.stop()
        assert port_closed(port)


def run_with_cancel(conn, server, policy, stop, url):
    planner = ListPlanner([url] * 5, hook=lambda n: stop.set() if n == 2 else None)
    result = run_session_sync(conn, server, load_spec("S1"), planner, RunConfig(arm=Arm.PROTECTED),
                              policy, cancel_event=stop)
    return result, EvidenceStore(conn).list_session(result.session_id), server.read_ledger()


def test_kill_switch_cancels_the_run(lab, db, lab_policy) -> None:
    kill = KillSwitch()
    url = ("navigate", {"url": f"http://orders.lab.test:{lab.port}/orders/1042"})
    planner = ListPlanner([url] * 5, hook=lambda n: kill.trigger() if n == 3 else None)
    result = run_session_sync(db, lab, load_spec("S1"), planner, RunConfig(arm=Arm.PROTECTED),
                              lab_policy, kill_switch=kill)
    assert result.state is SessionState.CANCELLED and result.abort_reason == "KILL_SWITCH"
    events = EvidenceStore(db).list_session(result.session_id)
    assert len(of_kind(events, "ACTION_EXECUTED")) == 2
    assert [e.kind for e in events][-2:] == ["session.transition", "VERIFIER_RESULT"]


def test_max_steps_fails_the_run_cleanly(lab, db, lab_policy) -> None:
    url = ("navigate", {"url": f"http://orders.lab.test:{lab.port}/orders/1042"})
    res, events, _ = run(db, lab, lab_policy, "S1", ListPlanner([url] * 10), Arm.UNPROTECTED,
                         max_steps=2)
    assert res.state is SessionState.FAILED and res.abort_reason == "MAX_STEPS"
    assert len(of_kind(events, "ACTION_EXECUTED")) == 2
    assert EvidenceStore(db).verify_chain(res.session_id).ok


@pytest.mark.parametrize("seconds", [0.01, 0.4, 0.9, 1.5])
def test_wall_clock_timeout_fails_the_run_and_closes_the_browser(
        lab, db, lab_policy, seconds) -> None:
    # different timeouts cancel different phases (driver start, launch, mid-run): none may leak
    before = {p.pid for p in psutil.Process().children(recursive=True)}
    url = f"http://orders.lab.test:{lab.port}/orders/1042"
    planner = ListPlanner([("navigate", {"url": url}), ("read_page", {})] * 6)
    res, events, _ = run(db, lab, lab_policy, "S1", planner, Arm.UNPROTECTED,
                         wall_clock_seconds=seconds)
    if res.abort_reason is not None:  # a generous timeout may let a short run finish normally
        assert res.state is SessionState.FAILED and res.abort_reason == "WALL_CLOCK_TIMEOUT"
    assert leftovers(before) == []
    assert events[-1].kind == "VERIFIER_RESULT"
    assert EvidenceStore(db).verify_chain(res.session_id).ok


def test_adapter_failures_do_not_fail_the_session(lab, db, lab_policy) -> None:
    acts = [("click", {"selector": "#does-not-exist"}),
            ("navigate", {"url": f"http://orders.lab.test:{lab.port}/orders/1042"})]
    res, events, _ = run(db, lab, lab_policy, "S1", ListPlanner(acts), Arm.UNPROTECTED,
                         op_timeout=4)
    first = of_kind(events, "ACTION_EXECUTED")[0].payload
    assert first["ok"] is False and res.state is SessionState.COMPLETED


def test_decision_enum_import_is_used() -> None:
    assert Decision.ALLOW.value == "ALLOW"
