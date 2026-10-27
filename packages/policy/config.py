"""Policy configuration: strict, frozen, content-addressed.

The loaded policy is immutable: every model is frozen and every collection is a tuple, so
nothing in a request, a page or model output can change it during a session.
policy_version = "<policy_name>@<first 12 hex of SHA-256 over the canonical policy content>".
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import ConfigDict, Field, field_validator, model_validator

from sentinelx.common_schemas import Decision, PolicyMode, SXModel

Name = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")]


class _Frozen(SXModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ToolArgRule(_Frozen):
    tool: Name
    required: tuple[Name, ...] = ()
    allowed: tuple[Name, ...] = ()
    url_args: tuple[Name, ...] = ()
    max_length: Annotated[int, Field(ge=0, le=100_000)] = 2000

    @model_validator(mode="after")
    def _consistent(self) -> ToolArgRule:
        allowed = set(self.allowed)
        if not set(self.required) <= allowed:
            raise ValueError(f"{self.tool}: required args must be in allowed args")
        if not set(self.url_args) <= allowed:
            raise ValueError(f"{self.tool}: url_args must be in allowed args")
        return self


class ArgCondition(_Frozen):
    """True when the named argument equals (case-insensitively) one of ``values``."""

    arg: Name
    values: Annotated[tuple[Annotated[str, Field(min_length=1, max_length=64)], ...],
                      Field(min_length=1)]


class HighImpact(_Frozen):
    """A tool (optionally only for certain argument values) that needs a human or is blocked."""

    action: Name
    decision: Literal[Decision.CONFIRM, Decision.BLOCK]
    when: tuple[ArgCondition, ...] = ()  # empty = every call to the tool

    def matches(self, arguments: dict[str, object]) -> bool:
        for cond in self.when:
            value = arguments.get(cond.arg)
            if not isinstance(value, str) or value.upper() not in {v.upper() for v in cond.values}:
                return False
        return True


class PageSubresourceRules(_Frozen):
    """Rules for requests a PAGE initiates itself (img, script, fetch, XHR, form posts,
    redirects, WebSocket, ...). They run in the same deterministic policy code path as
    actions (``sentinelx.policy.evaluate_page_request``) and are versioned with the policy."""

    enabled: bool = True
    blocked_resource_types: tuple[Name, ...] = ("websocket", "eventsource", "ping")
    allowed_methods: tuple[Name, ...] = ("GET", "HEAD", "POST")


class PolicyConfig(_Frozen):
    policy_name: Name
    mode: PolicyMode = PolicyMode.ENFORCE
    allowed_tools: tuple[Name, ...]
    tool_argument_rules: tuple[ToolArgRule, ...]
    high_impact_actions: tuple[HighImpact, ...] = ()
    page_subresource: PageSubresourceRules = PageSubresourceRules()
    blocked_destinations: tuple[str, ...] = ()
    secret_patterns: tuple[str, ...] = ()
    max_steps: Annotated[int, Field(ge=1, le=10_000)] = 20
    max_requests_per_minute: Annotated[int, Field(ge=1, le=100_000)] = 60
    default_decision: Literal[Decision.BLOCK] = Decision.BLOCK
    trailing_dot: Literal["reject", "normalize"] = "reject"
    allow_about_blank: bool = False

    @field_validator("secret_patterns")
    @classmethod
    def _compile(cls, patterns: tuple[str, ...]) -> tuple[str, ...]:
        for p in patterns:
            if len(p) > 500:
                raise ValueError("secret pattern too long")
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"invalid secret pattern: {exc}") from exc
        return patterns

    @model_validator(mode="after")
    def _consistent(self) -> PolicyConfig:
        tools = [r.tool for r in self.tool_argument_rules]
        if len(set(tools)) != len(tools):
            raise ValueError("duplicate tool_argument_rules")
        keys = [(h.action, h.model_dump_json(include={"when"})) for h in self.high_impact_actions]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate high_impact_actions")
        high = {h.action for h in self.high_impact_actions}
        known = set(tools)
        if not set(self.allowed_tools) <= known or not high <= known:
            raise ValueError("every allowed tool and high-impact action needs argument rules")
        for tool in set(self.allowed_tools) & high:  # allowed AND high-impact: only conditionally
            if any(not h.when for h in self.high_impact_actions if h.action == tool):
                raise ValueError(f"{tool}: allowed and unconditionally high-impact")
        return self

    def rule_for(self, tool: str) -> ToolArgRule | None:
        return next((r for r in self.tool_argument_rules if r.tool == tool), None)

    def high_impact_decision(
        self, tool: str, arguments: dict[str, object] | None = None
    ) -> Decision | None:
        """BLOCK beats CONFIRM when several entries match; None = not high-impact."""
        hits = [h.decision for h in self.high_impact_actions
                if h.action == tool and h.matches(arguments or {})]
        if not hits:
            return None
        return Decision.BLOCK if Decision.BLOCK in hits else Decision.CONFIRM


def compute_policy_version(config: PolicyConfig) -> str:
    """Content hash of the canonical policy (any semantic edit changes it)."""
    canonical = json.dumps(
        config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    return f"{config.policy_name}@{digest}"


@dataclass(frozen=True)
class LoadedPolicy:
    """Immutable policy handed to evaluate(): config + its version + the signal phrase list."""

    config: PolicyConfig
    policy_version: str
    signal_phrases: tuple[str, ...] = ()

    @classmethod
    def from_config(
        cls, config: PolicyConfig, signal_phrases: tuple[str, ...] = ()
    ) -> LoadedPolicy:
        return cls(config, compute_policy_version(config), tuple(signal_phrases))


def load_signal_phrases(path: str | Path) -> tuple[str, ...]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    phrases = data.get("instruction_override_phrases", [])
    if not isinstance(phrases, list) or not all(isinstance(p, str) and p for p in phrases):
        raise ValueError("instruction_override_phrases must be a list of non-empty strings")
    return tuple(phrases)


def load_policy(path: str | Path, signals_path: str | Path | None = None) -> LoadedPolicy:
    """Load a policy YAML (strict). Signal phrases come from signals.yaml beside it by default."""
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{p.name}: policy file must be a mapping")
    config = PolicyConfig.model_validate(raw)
    sig = Path(signals_path) if signals_path else p.with_name("signals.yaml")
    phrases = load_signal_phrases(sig) if sig.exists() else ()
    return LoadedPolicy.from_config(config, phrases)
