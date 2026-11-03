"""Adapter protocol and implementations for the agent test CLI.

An *adapter* proposes actions for an agent to take in a lab. It is the counterpart
of the planner in the agent runtime: it receives observations (what the agent sees)
and returns proposed actions (navigate, click, http_request, tool_call, submit_form,
or finish).

Every adapter runs in its own process or thread and communicates only through the
well-defined `Adapter` protocol. It never touches the gateway, the policy, or the
verifier directly - those decisions are made by the runner.

Adapters:
  * ScriptedAdapter  - deterministic, no network, pure Python scripted planner
  * ExecutableAdapter - runs an external executable with explicit argv
    (no shell=True, no shell interpretation of user input)
  * HttpAdapter       - sends HTTP requests to a local HTTP endpoint
    (127.0.0.1 only)
"""

from __future__ import annotations

import json
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sentinelx.agent_runtime.types import HistoryEntry, Observation


@dataclass(frozen=True)
class AdapterResult:
    """Result of running one action through an adapter."""

    action: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    finish: bool = False
    answer: str | None = None
    error: str | None = None
    adapter_name: str | None = None

    @classmethod
    def action_result(
        cls, action: str, arguments: dict[str, Any], adapter_name: str | None = None
    ) -> AdapterResult:
        return cls(action=action, arguments=arguments, adapter_name=adapter_name)

    @classmethod
    def finish_result(cls, answer: str, adapter_name: str | None = None) -> AdapterResult:
        return cls(finish=True, answer=answer, adapter_name=adapter_name)

    @classmethod
    def error_result(cls, error: str, adapter_name: str | None = None) -> AdapterResult:
        return cls(error=error, adapter_name=adapter_name)


class Adapter(ABC):
    """Protocol for agent-test adapters.

    Implementations propose the next action given the current observation and
    history. They are pure functions of the observation - they never touch the
    gateway, policy, or verifier directly.
    """

    name: str
    kind: str = "SIMULATED_ADAPTER"

    @abstractmethod
    def next_action(
        self, observation: Observation, history: Sequence[HistoryEntry]
    ) -> AdapterResult:
        """Propose the next action given the current observation and history.

        Returns an AdapterResult describing an action to execute, a finish,
        or an error.
        """
        ...

    def reset(self) -> None:
        """Reset adapter state between runs (e.g. between arms of a paired test)."""
        _ = None  # placeholder to satisfy B027 (non-empty body)


class ScriptedAdapter(Adapter):
    """A deterministic, scripted adapter with no network and no model.

    Follows a fixed, per-scenario script of actions. Serves as the baseline for
    paired unprotected/protected runs and demonstrates the adapter contract.
    """

    def __init__(self, scenario_id: str, lab_port: int) -> None:
        self.scenario_id = scenario_id
        self.lab_port = lab_port
        self._step = 0
        self.name = "scripted_naive"
        self.kind = "SIMULATED_ADAPTER:scripted_naive"
        # Simple script: navigate -> read_page -> finish
        self._script: list[tuple[str, dict[str, Any]]] = [
            ("navigate", {"url": f"http://127.0.0.1:{lab_port}/"}),
            ("read_page", {}),
            ("finish", {"answer": "task completed"}),
        ]

    def next_action(
        self, observation: Observation, history: Sequence[HistoryEntry]
    ) -> AdapterResult:
        if self._step >= len(self._script):
            return AdapterResult.finish_result("task completed", self.name)
        tool, args = self._script[self._step]
        self._step += 1
        if tool == "finish":
            return AdapterResult.finish_result(args.get("answer", "task completed"), self.name)
        return AdapterResult.action_result(tool, args, self.name)

    def reset(self) -> None:
        self._step = 0


class ExecutableAdapter(Adapter):
    """Run an external executable as an adapter.

    The executable is launched once per run and communicates via stdin/stdout
    using a JSON line protocol:

      Client -> Adapter: {"type": "observation", "session_id": "...", "step": N,
                          "now": "...", "url": "...", "text": "...", "outcome": "ok",
                          "blocked_reason": null, "tool_result": null,
                          "event_id": "...", "structure": ""}
      Adapter -> Client: {"action": "navigate", "arguments": {"url": "..."}}
                           or {"finish": true, "answer": "..."}
                           or {"error": "..."}

    No shell=True is ever used - argv is passed directly to subprocess.
    """

    def __init__(self, argv: list[str], timeout: float = 30.0) -> None:
        self.argv = list(argv)
        self.timeout = timeout
        self._proc: Any = None
        self.name = f"executable:{' '.join(argv)}"
        self.kind = f"EXECUTABLE_ADAPTER:{' '.join(argv)}"

    def next_action(
        self, observation: Observation, history: Sequence[HistoryEntry]
    ) -> AdapterResult:
        if self._proc is None:
            self._start()
        obs_dict = {
            "type": "observation",
            "session_id": observation.session_id,
            "step": observation.step,
            "now": observation.now.isoformat(),
            "url": observation.url,
            "text": observation.text,
            "outcome": observation.outcome,
            "blocked_reason": observation.blocked_reason,
            "tool_result": observation.tool_result,
            "event_id": observation.event_id,
            "structure": observation.structure,
        }
        line = json.dumps(obs_dict)
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(line + "\n")
            self._proc.stdin.flush()
            assert self._proc.stdout is not None
            resp_line = self._proc.stdout.readline()
        except (BrokenPipeError, OSError) as exc:
            return AdapterResult.error_result(f"adapter process error: {exc}", self.name)
        if not resp_line:
            return AdapterResult.error_result("adapter process closed unexpectedly", self.name)
        try:
            resp = json.loads(resp_line)
        except json.JSONDecodeError as exc:
            return AdapterResult.error_result(f"adapter returned invalid JSON: {exc}", self.name)
        if "error" in resp:
            return AdapterResult.error_result(resp["error"], self.name)
        if resp.get("finish"):
            return AdapterResult.finish_result(resp.get("answer", ""), self.name)
        if resp.get("action"):
            return AdapterResult.action_result(
                resp["action"], resp.get("arguments", {}), self.name
            )
        return AdapterResult.error_result("adapter did not return an action", self.name)

    def reset(self) -> None:
        """Terminate the current process; next call starts a fresh one."""
        if self._proc is not None:
            try:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except Exception:  # noqa: S110 - best effort cleanup
                pass
            self._proc = None

    def _start(self) -> None:
        self._proc = subprocess.Popen(
            self.argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None

    def _error_result(self, error: str) -> AdapterResult:
        return AdapterResult.error_result(error, self.name)


class HttpAdapter(Adapter):
    """Send HTTP requests to a local adapter endpoint (127.0.0.1 only).

    Each observation is POSTed as JSON to the adapter's endpoint, and the adapter
    replies with JSON describing the next action or a finish.
    """

    def __init__(self, url: str, timeout: float = 30.0) -> None:
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        if parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError(
                f"http adapter URL must be http://127.0.0.1 or http://localhost, got {url!r}"
            )
        self.url = url
        self.timeout = timeout
        self.name = f"http:{url}"
        self.kind = f"HTTP_ADAPTER:{url}"

    def next_action(
        self, observation: Observation, history: Sequence[HistoryEntry]
    ) -> AdapterResult:
        import httpx

        obs_dict = {
            "type": "observation",
            "session_id": observation.session_id,
            "step": observation.step,
            "now": observation.now.isoformat(),
            "url": observation.url,
            "text": observation.text,
            "outcome": observation.outcome,
            "blocked_reason": observation.blocked_reason,
            "tool_result": observation.tool_result,
            "event_id": observation.event_id,
            "structure": observation.structure,
        }
        try:
            resp = httpx.post(
                self.url,
                json=obs_dict,
                timeout=self.timeout,
            )
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            return AdapterResult.error_result(f"http adapter error: {exc}", self.name)
        try:
            data = resp.json()
        except ValueError as exc:
            msg = f"http adapter returned invalid JSON: {exc}"
            return AdapterResult.error_result(msg, self.name)
        if "error" in data:
            return AdapterResult.error_result(data["error"], self.name)
        if data.get("finish"):
            return AdapterResult.finish_result(data.get("answer", ""), self.name)
        if data.get("action"):
            return AdapterResult.action_result(
                data["action"], data.get("arguments", {}), self.name
            )
        return AdapterResult.error_result("adapter did not return an action", self.name)

    def reset(self) -> None:
        """HTTP adapter is stateless; nothing to reset."""
        ...


def load_adapter(spec: str) -> Adapter:
    """Load an adapter from a specification string.

    Supported formats:
      * ``scripted:<scenario_id>:<port>``  - ScriptedAdapter (deterministic)
      * ``exec:<arg1> <arg2> ...``         - ExecutableAdapter with argv
      * ``http://127.0.0.1:<port>/...``   - HttpAdapter
    """
    if spec.startswith("scripted:"):
        parts = spec[len("scripted:"):].split(":", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid scripted adapter spec: {spec!r}")
        scenario_id, port_str = parts
        return ScriptedAdapter(scenario_id, int(port_str))
    if spec.startswith("exec:"):
        argv = spec[len("exec:"):].split()
        if not argv:
            raise ValueError(f"invalid exec adapter spec: {spec!r}")
        return ExecutableAdapter(argv)
    if spec.startswith("http://"):
        return HttpAdapter(spec)
    raise ValueError(
        f"unknown adapter spec: {spec!r}. "
        "Use 'scripted:<scenario_id>:<port>', 'exec:<cmd> [args...]', "
        "or 'http://127.0.0.1:...'"
    )
