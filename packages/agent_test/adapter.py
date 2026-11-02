"""Adapter protocol and implementations for the agent test CLI.

An *adapter* proposes actions for an agent to take in a lab. It is the counterpart
of the planner in the agent runtime: it receives observations (what the agent sees)
and returns proposed actions (navigate, click, http_request, tool_call, submit_form,
or finish).

Every adapter runs in its own process or thread and communicates only through the
well-defined `Adapter` protocol. It never touches the gateway, the policy, or the
verifier directly - those decisions are made by the runner.

Adapters:
  * ScriptedAdapter  - wraps the existing ScriptedNaivePlanner (deterministic,
    no network, pure Python)
  * ExecutableAdapter - runs an external executable with explicit argv
    (no shell=True, no shell interpretation of user input)
  * HttpAdapter       - sends HTTP requests to a local HTTP endpoint
    (127.0.0.1 only)
"""

from __future__ import annotations

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


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
    """Protocol for edit-based patch generation.

    Implementations propose the next patch given the current excerpt and history.
    They are pure functions of the excerpt - they never touch the gateway,
    policy, or verifier directly.
    """

    name: str

    @abstractmethod
    def generate_patch(
        self, scope: Any, loc: Any, *, vuln_class: str, method: str,
        endpoint: str, summary: str, client: Any,
        allowed_files: set[str] | None = None,
        usage_sink: list | None = None,
    ) -> Any:
        """Propose an edit-based patch given the diagnosed location and context.

        Returns a PatchGenResult with either a validated patch or a rejection.
        """
        ...

    def reset(self) -> None:
        """Reset adapter state between runs (e.g. between arms of a paired test)."""
        # Default no-op reset; subclasses may override.
        _ = None  # placeholder to satisfy B027 (non-empty body)


class ScriptedAdapter(Adapter):
    """Wrap the existing PatchGenOutput as an adapter.

    This is the reference implementation: deterministic, no network, pure Python.
    It demonstrates the adapter contract and serves as the baseline for paired
    unprotected/protected runs.
    """

    def __init__(self, scenario_id: str, lab_port: int) -> None:
        self._patch_gen = None
        self.name = "scripted_naive"

    def generate_patch(
        self, scope: Any, loc: Any, *, vuln_class: str, method: str,
        endpoint: str, summary: str, client: Any,
        allowed_files: set[str] | None = None,
        usage_sink: list | None = None,
    ) -> Any:
        return self._patch_gen

    def reset(self) -> None:
        """No state to reset - PatchGenOutput is recreated per run."""
        ...


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
        self._stdin: Any = None
        self._stdout: Any = None
        self.name = f"executable:{' '.join(argv)}"

    def generate_patch(
        self, scope: Any, loc: Any, *, vuln_class: str, method: str,
        endpoint: str, summary: str, client: Any,
        allowed_files: set[str] | None = None,
        usage_sink: list | None = None,
    ) -> Any:
        if self._proc is None:
            self._start()
        obs_dict = {
            "scope": str(scope.work_dir),
            "loc": {
                "file": loc.file,
                "line_start": loc.line_start,
                "line_end": loc.line_end,
                "reasoning": loc.reasoning,
            },
            "vuln_class": vuln_class,
            "method": method,
            "endpoint": endpoint,
            "summary": summary,
        }
        line = json.dumps({"type": "observation", **obs_dict})
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(line + "\n")
            self._proc.stdin.flush()
            assert self._proc.stdout is not None
            resp_line = self._proc.stdout.readline()
        except (BrokenPipeError, OSError) as exc:
            return self._error_result(f"adapter process error: {exc}")
        if not resp_line:
            return self._error_result("adapter process closed unexpectedly")
        try:
            resp = json.loads(resp_line)
        except json.JSONDecodeError as exc:
            return self._error_result(f"adapter returned invalid JSON: {exc}")
        if "error" in resp:
            return self._error_result(resp["error"])
        if resp.get("diff"):
            return self._patch_result(resp["diff"], resp.get("explanation", ""))
        return self._error_result("adapter did not return a diff")

    def reset(self) -> None:
        """Terminate the current process; next call starts a fresh one."""
        if self._proc is not None:
            try:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except Exception:  # noqa: S110 - best effort cleanup
                pass
            self._proc = None
            self._stdin = None
            self._stdout = None

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
        self._stdin = self._proc.stdin
        self._stdout = self._proc.stdout

    def _error_result(self, error: str) -> Any:
        from sentinelx.fixer.patch_gen import PatchGenResult
        return PatchGenResult("MODEL_UNAVAILABLE", reasons=[error])

    def _patch_result(self, diff: str, explanation: str) -> Any:
        from sentinelx.fixer.models import FixCategory
        from sentinelx.fixer.patch_gen import PatchGenResult
        return PatchGenResult(
            "VALIDATED",
            diff=diff,
            explanation=explanation,
            fix_category=FixCategory.PARAMETERIZED_QUERY,
            retries_used=0,
        )


class HttpAdapter(Adapter):
    """Send HTTP requests to a local adapter endpoint (127.0.0.1 only).

    Each observation is POSTed as JSON to the adapter's endpoint, and the adapter
    replies with JSON describing the next patch or a finish.
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

    def generate_patch(
        self, scope: Any, loc: Any, *, vuln_class: str, method: str,
        endpoint: str, summary: str, client: Any,
        allowed_files: set[str] | None = None,
        usage_sink: list | None = None,
    ) -> Any:
        import httpx

        obs_dict = {
            "scope": str(scope.work_dir),
            "loc": {
                "file": loc.file,
                "line_start": loc.line_start,
                "line_end": loc.line_end,
                "reasoning": loc.reasoning,
            },
            "vuln_class": vuln_class,
            "method": method,
            "endpoint": endpoint,
            "summary": summary,
        }
        try:
            resp = httpx.post(
                self.url,
                json={"type": "observation", **obs_dict},
                timeout=self.timeout,
            )
        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            return self._error_result(f"http adapter error: {exc}")
        try:
            data = resp.json()
        except ValueError as exc:
            return self._error_result(f"http adapter returned invalid JSON: {exc}")
        if "error" in data:
            return self._error_result(data["error"])
        if resp.get("diff"):
            return self._patch_result(resp["diff"], resp.get("explanation", ""))
        return self._error_result("adapter did not return a diff")

    def reset(self) -> None:
        """HTTP adapter is stateless; nothing to reset."""
        ...

    def _error_result(self, error: str) -> Any:
        from sentinelx.fixer.patch_gen import PatchGenResult
        return PatchGenResult("MODEL_UNAVAILABLE", reasons=[error])

    def _patch_result(self, diff: str, explanation: str) -> Any:
        from sentinelx.fixer.models import FixCategory
        from sentinelx.fixer.patch_gen import PatchGenResult
        return PatchGenResult(
            "VALIDATED",
            diff=diff,
            explanation=explanation,
            fix_category=FixCategory.PARAMETERIZED_QUERY,
            retries_used=0,
        )


def load_adapter(spec: str) -> Adapter:
    """Load an adapter from a specification string.

    Supported formats:
      * ``scripted:<scenario_id>:<port>``  - ScriptedNaivePlanner wrapper
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
