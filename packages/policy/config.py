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


class HighImpact(_Frozen):
    action: Name
    decision: Literal[Decision.CONFIRM, Decision.BLOCK]


class PolicyConfig(_Frozen):
    policy_name: Name
    mode: PolicyMode = PolicyMode.ENFORCE
    allowed_tools: tuple[Name, ...]
    tool_argument_rules: tuple[ToolArgRule, ...]
    high_impact_actions: tuple[HighImpact, ...] = ()
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
        high = [h.action for h in self.high_impact_actions]
        if len(set(high)) != len(high):
            raise ValueError("duplicate high_impact_actions")
        known = set(tools)
        if not set(self.allowed_tools) <= known or not set(high) <= known:
            raise ValueError("every allowed tool and high-impact action needs argument rules")
        if set(self.allowed_tools) & set(high):
            raise ValueError("a tool cannot be both allowed and high-impact")
        return self

    def rule_for(self, tool: str) -> ToolArgRule | None:
        return next((r for r in self.tool_argument_rules if r.tool == tool), None)

    def high_impact_decision(self, tool: str) -> Decision | None:
        return next((h.decision for h in self.high_impact_actions if h.action == tool), None)


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
