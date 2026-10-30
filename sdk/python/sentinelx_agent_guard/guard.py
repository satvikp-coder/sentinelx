"""sentinelx-agent-guard: a tiny policy-enforced wrapper for agent tools.

Every tool call is checked by the REAL deterministic policy gateway
(``sentinelx.policy.evaluate``) BEFORE the tool runs. The guard policy file is strict
(unknown keys are rejected) with exactly these keys:

    allowed_hosts: ["orders.lab.test"]     # exact hosts; no wildcards
    allowed_tools: ["fetch_page"]          # pre-allowed (safe allowlist) tools
    high_impact_actions: ["send_data"]     # need human approval (CONFIRM) in enforce mode
    secret_patterns: ["CANARY-[A-Z0-9]{8,}"]  # extra regexes on top of built-in detectors

Tool arguments are checked as the caller passes them: argument names are accepted as
observed for the called tool (the 4-key policy carries no tool schema), scalar types and
length are still enforced, a ``url`` argument is scope-checked against ``allowed_hosts``,
and secrets anywhere in the arguments are refused.
"""

from __future__ import annotations

import functools
import inspect
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from sentinelx.common_schemas import (
    ApprovalDecision,
    ApprovalRecord,
    Decision,
    PolicyMode,
    ScenarioSpec,
    SessionState,
)
from sentinelx.policy import LoadedPolicy, SessionContext, approval_subject_id, evaluate
from sentinelx.policy.config import HighImpact, PolicyConfig, ToolArgRule

from .errors import GuardBlocked

_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MODES = ("monitor", "enforce")


class GuardPolicy(BaseModel):
    """Strict schema for the guard policy file (extra keys are rejected)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_hosts: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    high_impact_actions: tuple[str, ...] = ()
    secret_patterns: tuple[str, ...] = ()

    @field_validator("allowed_tools", "high_impact_actions")
    @classmethod
    def _valid_tool_names(cls, names: tuple[str, ...]) -> tuple[str, ...]:
        for n in names:
            if not _NAME.match(n):
                raise ValueError(f"invalid tool name: {n!r}")
        return names


def load_guard_policy(path: str | Path) -> GuardPolicy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: policy file must be a mapping")
    return GuardPolicy.model_validate(data)


class Guard:
    """Check every tool call with the policy gateway; enforce or monitor."""

    def __init__(self, policy_file: str | Path, mode: str = "monitor",
                 approver: Callable[[dict[str, Any]], bool] | None = None) -> None:
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self.approver = approver
        self.policy = load_guard_policy(policy_file)
        self.history: list[Any] = []  # PolicyDecision objects, in call order
        self._calls = 0
        high = set(self.policy.high_impact_actions)
        self._allowed_tools = tuple(t for t in self.policy.allowed_tools if t not in high)
        self._high = tuple(self.policy.high_impact_actions)
        self._known = tuple(dict.fromkeys([*self.policy.allowed_tools, *self._high]))

    # ------------------------------------------------------------------ gateway plumbing
    def _effective_policy(self, tool: str, arguments: dict[str, Any]) -> LoadedPolicy:
        rules = []
        for name in self._known:
            if name == tool:
                keys = tuple(sorted(str(k) for k in arguments))
                rules.append(ToolArgRule(tool=name, required=(), allowed=keys,
                                         url_args=("url",) if "url" in arguments else (),
                                         max_length=65_536))
            else:
                rules.append(ToolArgRule(tool=name))
        config = PolicyConfig(
            policy_name="agent_guard",
            mode=PolicyMode.ENFORCE if self.mode == "enforce" else PolicyMode.MONITOR,
            allowed_tools=self._allowed_tools,
            high_impact_actions=tuple(
                HighImpact(action=t, decision=Decision.CONFIRM) for t in self._high),
            tool_argument_rules=tuple(rules),
            secret_patterns=tuple(self.policy.secret_patterns),
        )
        return LoadedPolicy.from_config(config, ())

    @staticmethod
    def _scenario(tool: str, known: tuple[str, ...], hosts: tuple[str, ...]) -> ScenarioSpec:
        return ScenarioSpec(
            id="agent-guard", seed=0, fixture_id="sdk", fixture_version="1",
            goal="agent tool call", allowed_hosts=list(hosts), allowed_actions=list(known),
            attack_surface="sdk", attack_payload_id="sdk",
            forbidden_outcome={"type": "none", "endpoint": "none"},
            goal_assertion={"type": "none", "expected": None},
        )

    def _evaluate(self, tool: str, arguments: dict[str, Any], *, approved: bool = False):
        self._calls += 1
        action_id = f"guard-{self._calls}"
        approvals: tuple[ApprovalRecord, ...] = ()
        if approved:
            approvals = (ApprovalRecord(
                id=f"approval-{self._calls}", subject_type="action",
                subject_id=approval_subject_id(action_id, tool, arguments),
                reviewer="guard-approver", decision=ApprovalDecision.APPROVE,
                rationale="approved by the SDK approver", timestamp=datetime.now(UTC)),)
        context = SessionContext(session_id="agent-guard", state=SessionState.RUNNING,
                                 approvals=approvals)
        request = dict(session_id="agent-guard", step=self._calls, action_id=action_id,
                       timestamp=datetime.now(UTC), actor="agent", tool=tool,
                       arguments=arguments)
        policy = self._effective_policy(tool, arguments)
        scenario = self._scenario(tool, self._known, self.policy.allowed_hosts)
        decision = evaluate(request, scenario, policy, context)
        self.history.append(decision)
        return decision

    # ------------------------------------------------------------------ public API
    def check(self, action: dict[str, Any]):
        """Evaluate one {"tool": ..., "arguments": {...}} dict; return the PolicyDecision."""
        if not isinstance(action, dict) or set(action) - {"tool", "arguments"}:
            raise ValueError('action must be a dict with keys "tool" and "arguments"')
        tool = action.get("tool")
        arguments = action.get("arguments") or {}
        if not isinstance(tool, str) or not _NAME.match(tool):
            raise ValueError(f"invalid tool name: {tool!r}")
        if not isinstance(arguments, dict):
            raise ValueError('"arguments" must be an object')
        return self._evaluate(tool, arguments)

    def tool(self, name: str) -> Callable:
        """Decorator: check the call with the gateway BEFORE the tool runs."""
        def decorate(fn: Callable) -> Callable:
            signature = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                arguments = {k: v for k, v in bound.arguments.items()}
                decision = self._evaluate(name, arguments)
                if self.mode == "monitor":
                    return fn(*args, **kwargs)
                if decision.decision is Decision.BLOCK:
                    raise GuardBlocked(name, decision)
                if decision.decision is Decision.CONFIRM:
                    approved = bool(self.approver and self.approver(
                        {"tool": name, "arguments": arguments}))
                    if not approved:
                        raise GuardBlocked(name, decision)
                    recheck = self._evaluate(name, arguments, approved=True)
                    if recheck.decision is not Decision.ALLOW:
                        raise GuardBlocked(name, recheck)
                return fn(*args, **kwargs)
            return wrapper
        return decorate


__all__ = ["Guard", "GuardPolicy", "GuardBlocked", "load_guard_policy",
           "ValidationError"]
