"""Run one agent task in the lab, UNPROTECTED (arm A) or PROTECTED (arm B), with full evidence.

Event order for every action (the invariant the tests pin down):

    ACTION_PROPOSED  ->  [PROTECTED: ACTION_DECIDED | UNPROTECTED: SHADOW_DECISION (SIMULATED)]
                     ->  ACTION_EXECUTED   (only if the arm's rule allows it)

Protected arm: ``_execute_allowed`` is the ONLY place the adapter is called, and it requires a
gateway decision whose effective action is ALLOW. A BLOCK / CONFIRM is an evidence event, not a
session failure; the planner is told "blocked by policy: <reason>" and carries on.
Unprotected arm: no gateway; execution is still behind the sandbox boundary. The shadow
decision is analysis only (state SIMULATED) and never affects execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelx.common_schemas import (
    ActionRequest,
    Actor,
    ActorRole,
    Arm,
    Decision,
    EvidenceState,
    PolicyDecision,
    ScenarioSpec,
    SessionKind,
    SessionState,
    VerifierResult,
)
from sentinelx.evidence.records import RecordStore
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.policy import (
    LoadedPolicy,
    SessionContext,
    UntrustedText,
    evaluate,
    evaluate_page_request,
)
from sentinelx.policy.gateway import PROPOSED_KIND, decide_and_record
from sentinelx.verifier.record import verify_and_record

from .adapter import BrowserAdapter
from .types import (
    ActionOutcome,
    Finish,
    HistoryEntry,
    KillSwitch,
    LabHandle,
    Observation,
    Planner,
)

SYSTEM = Actor(id="agent_runtime", role=ActorRole.SYSTEM)
PROVIDER_LABEL = "local-scripted (SIMULATED, not an LLM)"
SHADOW_KIND = "SHADOW_DECISION"
EXECUTED_KIND = "ACTION_EXECUTED"
OBSERVATION_KIND = "OBSERVATION_RECORDED"


@dataclass(frozen=True)
class RunConfig:
    arm: Arm
    seed: int | None = None
    max_steps: int = 20
    wall_clock_seconds: float = 90.0
    op_timeout: float = 8.0
    headless: bool = True


@dataclass
class RunResult:
    session_id: str
    scenario_id: str
    arm: Arm
    state: SessionState
    abort_reason: str | None
    final_answer: str | None
    fixture_hash: str
    policy_version: str
    verifier: VerifierResult | None
    steps: int
    gateway_decision_ms: list[float] = field(default_factory=list)  # protected arm only
    page_policy_ms: list[float] = field(default_factory=list)  # protected arm only
    total_ms: float = 0.0
    boundaries: tuple[str, ...] = ()


def materialize_scenario(spec: ScenarioSpec, port: int) -> ScenarioSpec:
    """The lab picks its port at runtime, so allowed hosts become exact ``host:port`` entries."""
    return spec.model_copy(update={"allowed_hosts": [f"{h}:{port}" for h in spec.allowed_hosts]})


class _Runner:
    def __init__(self, conn: sqlite3.Connection, lab: LabHandle, spec: ScenarioSpec,
                 planner: Planner, config: RunConfig, policy: LoadedPolicy,
                 kill_switch: KillSwitch | None, cancel_event: threading.Event | None) -> None:
        self.conn, self.lab, self.spec, self.planner = conn, lab, spec, planner
        self.config, self.policy = config, policy
        self.kill = kill_switch or KillSwitch()
        self.cancel = cancel_event or threading.Event()
        self.svc = SessionService(conn)
        self.store: EvidenceStore = self.svc.evidence
        self.protected = config.arm is Arm.PROTECTED
        self.session_id = ""
        self.scenario = materialize_scenario(spec, lab.port)
        self.history: list[HistoryEntry] = []
        self.request_times: deque[float] = deque()
        self.page_texts: dict[str, str] = {}
        self.last_step: int | None = None
        self.final_answer: str | None = None
        self.abort_reason: str | None = None
        self.adapter: BrowserAdapter | None = None
        self.gateway_ms: list[float] = []
        self.page_policy_ms: list[float] = []
        self.boundaries = (("sandbox", "policy_gateway", "page_egress_policy") if self.protected
                           else ("sandbox",))

    # ------------------------------------------------------------------ evidence helpers
    def _event(self, kind: str, payload: dict[str, Any],
               state: EvidenceState = EvidenceState.OBSERVED, parent: str | None = None) -> str:
        return self.store.append(self.session_id, kind, state, "agent_runtime", payload,
                                 parent_event_id=parent).id

    def _on_adapter_event(self, kind: str, payload: dict[str, Any]) -> None:
        self._event(kind, payload)

    def _transition(self, to: SessionState) -> None:
        self.svc.transition(self.session_id, to, SYSTEM)

    # ------------------------------------------------------------------ main flow
    async def run(self) -> RunResult:
        started = time.perf_counter()
        spec, cfg = self.spec, self.config
        records = RecordStore(self.conn)
        if records.get(ScenarioSpec, spec.id) is None:
            records.insert(spec)
        session, _ = self.svc.create(
            SessionKind.AGENT_RUN, self.policy.policy_version, SYSTEM, scenario_id=spec.id,
            arm=cfg.arm, model=self.planner.name, provider=PROVIDER_LABEL,
            fixture_version=spec.fixture_version,
        )
        self.session_id = session.id
        seed = spec.seed if cfg.seed is None else cfg.seed
        fixture_hash = self.lab.reset(spec.id, seed)
        self._event("RUN_STARTED", {
            "arm": cfg.arm.value, "scenario_id": spec.id, "seed": seed,
            "attack_surface": spec.attack_surface, "fixture_hash": fixture_hash,
            "policy_version": self.policy.policy_version,
            "policy_mode": self.policy.config.mode.value,
            "planner": {"name": self.planner.name, "kind": self.planner.kind,
                        "is_llm": False, "label": "SIMULATED scripted agent, not an LLM"},
            "protected": self.protected, "lab_port": self.lab.port, "max_steps": cfg.max_steps,
            "boundaries": list(self.boundaries),
        })
        self._transition(SessionState.READY)
        self._transition(SessionState.RUNNING)
        final_state = SessionState.COMPLETED
        try:
            await self._session()
        except asyncio.CancelledError:
            self.abort_reason = "TASK_CANCELLED"
            self._finalize(SessionState.CANCELLED)
            raise
        except Exception as exc:
            self.abort_reason = "RUNTIME_ERROR"
            self._event("RUN_ERROR", {"error_class": type(exc).__name__,
                                      "message": str(exc)[:300]})
        if self.abort_reason in {"KILL_SWITCH", "CANCELLED", "TASK_CANCELLED"}:
            final_state = SessionState.CANCELLED
        elif self.abort_reason is not None:
            final_state = SessionState.FAILED
        verifier = self._finalize(final_state)
        return RunResult(self.session_id, spec.id, cfg.arm, final_state, self.abort_reason,
                         self.final_answer, fixture_hash, self.policy.policy_version, verifier,
                         len(self.history), list(self.gateway_ms), list(self.page_policy_ms),
                         (time.perf_counter() - started) * 1000.0, self.boundaries)

    def _finalize(self, state: SessionState) -> VerifierResult | None:
        if self.abort_reason:
            self._event("RUN_ABORTED", {"reason": self.abort_reason})
        self._event("RUN_FINISHED", {"final_answer": self.final_answer,
                                     "steps": len(self.history), "arm": self.config.arm.value,
                                     "end_state": state.value, "abort_reason": self.abort_reason})
        self._transition(state)
        try:  # ground truth is read only here, after the agent has stopped
            return verify_and_record(self.conn, self.spec, self.session_id, self.lab.read_ledger())
        except Exception as exc:
            self._event("VERIFIER_ERROR", {"error_class": type(exc).__name__,
                                           "message": str(exc)[:300]})
            return None

    async def _session(self) -> None:
        """Start the browser, then run the steps under the wall-clock budget.

        The budget starts once the browser is up: cancelling Playwright in the middle of its own
        start-up leaves its connection tasks pending and can hang interpreter shutdown, so
        start-up is bounded only by Playwright's launch timeouts.
        """
        page_policy = self._page_policy if self.protected else None
        async with BrowserAdapter(self.lab.port, self._on_adapter_event, page_policy,
                                  self.config.op_timeout, self.config.headless) as adapter:
            self.adapter = adapter
            try:
                async with asyncio.timeout(self.config.wall_clock_seconds):
                    await self._steps()
            except TimeoutError:
                self.abort_reason = "WALL_CLOCK_TIMEOUT"
            finally:
                self._event("EGRESS_SUMMARY", {"boundaries": list(self.boundaries),
                                               **adapter.egress_summary()})

    def _page_policy(self, url: str, resource_type: str, method: str, source: str | None,
                     body: str | None = None) -> Any:
        """Page-initiated requests go through the SAME deterministic policy code path."""
        t0 = time.perf_counter()
        decision = evaluate_page_request(
            {"url": url, "resource_type": resource_type, "method": method, "source_url": source,
             "body": body},
            self.scenario, self.policy)
        self.page_policy_ms.append((time.perf_counter() - t0) * 1000.0)
        return decision

    async def _steps(self) -> None:
        obs = Observation(self.session_id, 1, datetime.now(UTC))
        while True:
            if self.kill.active:
                self.abort_reason = "KILL_SWITCH"
                return
            if self.cancel.is_set():
                self.abort_reason = "CANCELLED"
                return
            if len(self.history) >= self.config.max_steps:
                self.abort_reason = "MAX_STEPS"
                return
            planned = self.planner.next_action(obs, self.history)
            if isinstance(planned, Finish):
                self.final_answer = planned.answer
                return
            obs = await self._step(planned, obs.step)

    # ------------------------------------------------------------------ one action
    def _context(self) -> SessionContext:
        now = time.monotonic()
        while self.request_times and now - self.request_times[0] > 60:
            self.request_times.popleft()
        texts = tuple(UntrustedText(source=k, text=v) for k, v in self.page_texts.items() if v)
        return SessionContext(
            session_id=self.session_id, state=self.svc.get(self.session_id).state,
            last_step=self.last_step, steps_taken=len(self.history),
            requests_last_minute=len(self.request_times), kill_switch=self.kill.active,
            page_origin=self.adapter.current_url if self.adapter else None,
            untrusted_texts=texts,
        )

    async def _step(self, req: ActionRequest, step: int) -> Observation:
        ctx = self._context()
        self.request_times.append(time.monotonic())
        if self.protected:
            result = decide_and_record(self.conn, self.session_id, req, self.scenario,
                                       self.policy, ctx)
            proposal_id, decision = result.proposed_event_id, result.decision
            self.gateway_ms.append(result.decision_ms)
            outcome = await self._execute_allowed(req, decision, proposal_id)
        else:
            proposal_id = self._event(PROPOSED_KIND, req.model_dump(mode="json"),
                                      EvidenceState.PROPOSED)
            shadow = evaluate(req, self.scenario, self.policy, ctx)
            self._event(SHADOW_KIND, {
                "label": "SIMULATED shadow decision: analysis only, did not affect execution",
                "decision": shadow.model_dump(mode="json")}, EvidenceState.SIMULATED, proposal_id)
            outcome = await self._execute(req, proposal_id)
            decision = None
        self.last_step = req.step
        return self._observe(req, step, outcome, decision)

    async def _execute_allowed(self, req: ActionRequest, decision: PolicyDecision,
                               proposal_id: str) -> ActionOutcome | None:
        """The ONLY path to the adapter in the protected arm: requires an effective ALLOW."""
        if decision.effective_action is not Decision.ALLOW:
            return None
        return await self._execute(req, proposal_id)

    async def _execute(self, req: ActionRequest, proposal_id: str) -> ActionOutcome:
        assert self.adapter is not None
        outcome = await self.adapter.execute(req)
        self._event(EXECUTED_KIND, {"tool": req.tool, "action_id": req.action_id,
                                    "arm": self.config.arm.value, **outcome.summary()},
                    parent=proposal_id)
        return outcome

    def _observe(self, req: ActionRequest, step: int, outcome: ActionOutcome | None,
                 decision: PolicyDecision | None) -> Observation:
        now = datetime.now(UTC)
        if outcome is None:  # blocked / needs confirmation: NOT executed, the run continues
            assert decision is not None
            reason = decision.reason_code
            self.history.append(HistoryEntry(step, req, "blocked", reason))
            return Observation(self.session_id, step + 1, now, self._url(),
                               text=f"blocked by policy: {reason}", outcome="blocked",
                               blocked_reason=f"blocked by policy: {reason}")
        status = "ok" if outcome.ok else "error"
        self.history.append(HistoryEntry(step, req, status, outcome.error))
        event_id = None
        if outcome.text:
            source = "tool_result" if req.tool in {"tool_call", "http_request"} else "page_text"
            self.page_texts[source] = outcome.text
            event_id = self._event(OBSERVATION_KIND, {
                "source": source, "url": outcome.final_url, "action_id": req.action_id,
                "text_length": len(outcome.text),
                "text_sha256": hashlib.sha256(outcome.text.encode()).hexdigest(),
                "excerpt": outcome.text[:1500], "untrusted": True,
            }, parent=None)
        return Observation(self.session_id, step + 1, now, outcome.final_url or self._url(),
                           text=outcome.text if outcome.ok else "", outcome=status,
                           blocked_reason=outcome.error, tool_result=outcome.tool_result,
                           event_id=event_id)

    def _url(self) -> str | None:
        return self.adapter.current_url if self.adapter else None


async def run_session(
    conn: sqlite3.Connection,
    lab: LabHandle,
    scenario: ScenarioSpec,
    planner: Planner,
    config: RunConfig,
    policy: LoadedPolicy,
    *,
    kill_switch: KillSwitch | None = None,
    cancel_event: threading.Event | None = None,
) -> RunResult:
    """Execute one task. Always ends the session cleanly and closes the browser."""
    return await _Runner(conn, lab, scenario, planner, config, policy, kill_switch,
                         cancel_event).run()


def run_session_sync(*args: Any, **kwargs: Any) -> RunResult:
    return asyncio.run(run_session(*args, **kwargs))
