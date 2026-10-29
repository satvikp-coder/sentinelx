"""Task-routed model profiles (configs/models.yaml) and the hard spend guard for Baseten.

Independent of the single-profile `sentinelx.model_clients.config.load_config()` path, which
every existing caller (model_assist.py, the EVCS/agent-runtime model calls) keeps using
unchanged - this module is opt-in, for callers that want task-based routing with a budget
(the fixer, Part A-G of Prompt 9). Verified prices and sources are recorded in
docs/DECISIONS.md; this file must not drift from that record without updating it there too.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, SecretStr

from .config import REPO_ROOT, ModelConfig, parse_env_file

CONFIG_PATH = REPO_ROOT / "configs" / "models.yaml"
KEY_REQUIRED_PROVIDERS = {"nvidia", "baseten", "together", "fireworks", "meta_api"}


class PriceInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    input_usd: float
    cached_input_usd: float
    output_usd: float
    verified: bool
    note: str | None = None
    source: str | None = None


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    provider: str
    base_url: str
    model: str
    api_key_env: str
    reasoning_effort: str | None = None
    max_tokens: int
    price_per_1m: PriceInfo


class RoutingEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    primary: str
    fallback: str


class Budget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hard_cap_usd: float
    warning_usd: float
    reserved_usd: float = 0.0


class ModelsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config_version: str
    profiles: dict[str, Profile]
    routing: dict[str, RoutingEntry]
    budget: dict[str, Budget] = {}


def load_models_config(path: Path = CONFIG_PATH) -> ModelsConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    profiles = {name: Profile(name=name, **spec) for name, spec in raw["profiles"].items()}
    routing = {task: RoutingEntry(**spec) for task, spec in raw["routing"].items()}
    budget = {name: Budget(**spec) for name, spec in raw.get("budget", {}).items()}
    return ModelsConfig(config_version=raw["config_version"], profiles=profiles,
                        routing=routing, budget=budget)


def estimate_cost(profile: Profile, tokens_in: int, tokens_out: int,
                  cached_tokens: int = 0) -> float:
    """USD, from the profile's published per-1M-token prices. Reasoning tokens are already
    inside `tokens_out` (the provider bills them as completion/output tokens)."""
    p = profile.price_per_1m
    billed_in = max(tokens_in - cached_tokens, 0)
    return (billed_in * p.input_usd + cached_tokens * p.cached_input_usd
            + tokens_out * p.output_usd) / 1_000_000


def cumulative_spend(conn: sqlite3.Connection, profile_name: str) -> float:
    """Sum of `usage.estimated_cost` already recorded for this profile. This is the running
    total of ACTUAL estimated spend from completed calls, not a projection."""
    row = conn.execute(
        "SELECT COALESCE(SUM(estimated_cost), 0) FROM usage WHERE profile = ?",
        (profile_name,)).fetchone()
    return float(row[0])


@dataclass(frozen=True)
class BudgetCheck:
    status: str  # "UNBUDGETED" | "OK" | "WARNING" | "BUDGET_EXHAUSTED"
    spent_usd: float
    hard_cap_usd: float | None
    remaining_usd: float | None


def check_budget(conn: sqlite3.Connection, config: ModelsConfig, profile_name: str) -> BudgetCheck:
    """Call before EVERY call on a budgeted profile. BUDGET_EXHAUSTED is a hard stop - the
    caller must not make the request, retry, or fall through to it silently."""
    budget = config.budget.get(profile_name)
    if budget is None:
        return BudgetCheck("UNBUDGETED", 0.0, None, None)
    spent = cumulative_spend(conn, profile_name)
    remaining = budget.hard_cap_usd - spent
    if spent >= budget.hard_cap_usd:
        return BudgetCheck("BUDGET_EXHAUSTED", spent, budget.hard_cap_usd, max(remaining, 0.0))
    if spent >= budget.warning_usd:
        return BudgetCheck("WARNING", spent, budget.hard_cap_usd, remaining)
    return BudgetCheck("OK", spent, budget.hard_cap_usd, remaining)


def record_usage(conn: sqlite3.Connection, *, session_id: str | None, profile_name: str,
                 provider: str, model: str, tokens_in: int, tokens_out: int, latency_ms: float,
                 estimated_cost: float | None, error: str | None = None) -> None:
    import datetime as _dt

    conn.execute(
        "INSERT INTO usage (session_id, provider, model, profile, tokens_in, tokens_out, "
        "latency_ms, estimated_cost, error, timestamp) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (session_id, provider, model, profile_name, tokens_in, tokens_out, latency_ms,
         estimated_cost, error, _dt.datetime.now(_dt.UTC).isoformat()))
    conn.commit()


@dataclass(frozen=True)
class RoutedProfile:
    status: str  # "OK" | "BUDGET_EXHAUSTED" | "MODEL_UNAVAILABLE"
    profile_name: str = ""
    config: ModelConfig | None = None
    budget: BudgetCheck | None = None
    fallback_used: bool = False
    detail: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


def _api_key(profile: Profile, environ: Mapping[str, str], env_file: Path | None) -> SecretStr:
    merged = parse_env_file(env_file) if env_file is not None else {}
    merged.update(environ)
    return SecretStr(merged.get(profile.api_key_env, ""))


def resolve_task(conn: sqlite3.Connection, config: ModelsConfig, task: str, *,
                 environ: Mapping[str, str] | None = None,
                 env_file: Path | None = REPO_ROOT / ".env") -> RoutedProfile:
    """Resolve a task category (e.g. "patch_generation") to a usable profile: try the primary,
    fall back to the ONE configured fallback if the primary's key is not set or its budget is
    exhausted, and label the fallback in the result (never silent). Neither available ->
    MODEL_UNAVAILABLE, never a retry loop.

    `environ` defaults to the real process environment and `env_file` to the repo's real
    `.env`, overlaid by `environ` - same precedence as `load_config()`. Tests that want to
    simulate a missing key should pass `env_file=None` so they are not affected by whatever is
    actually configured on the machine running them."""
    route = config.routing.get(task)
    if route is None:
        return RoutedProfile("MODEL_UNAVAILABLE", detail=f"no routing entry for task {task!r}")
    env = os.environ if environ is None else environ
    attempts: list[tuple[str, bool]] = [(route.primary, False), (route.fallback, True)]
    reasons: list[str] = []
    for name, is_fallback in attempts:
        profile = config.profiles.get(name)
        if profile is None:
            reasons.append(f"{name}: no such profile")
            continue
        key = _api_key(profile, env, env_file)
        if profile.provider in KEY_REQUIRED_PROVIDERS and not key.get_secret_value():
            reasons.append(f"{name}: {profile.api_key_env} is not set")
            continue
        bc = check_budget(conn, config, name)
        if bc.status == "BUDGET_EXHAUSTED":
            reasons.append(f"{name}: BUDGET_EXHAUSTED (${bc.spent_usd:.2f} >= "
                           f"${bc.hard_cap_usd:.2f})")
            continue
        cfg = ModelConfig(provider=profile.provider, base_url=profile.base_url,
                          model=profile.model, api_key=key,
                          reasoning_effort=profile.reasoning_effort,
                          max_tokens=profile.max_tokens)
        return RoutedProfile("OK", profile_name=name, config=cfg, budget=bc,
                             fallback_used=is_fallback,
                             detail="" if not is_fallback else
                             f"fallback used - {'; '.join(reasons)}")
    return RoutedProfile("BUDGET_EXHAUSTED"
                         if any("BUDGET_EXHAUSTED" in r for r in reasons) else "MODEL_UNAVAILABLE",
                         detail="; ".join(reasons))
