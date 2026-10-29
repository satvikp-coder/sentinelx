"""Sentinel X model adapter: provider-agnostic OpenAI-compatible client with explicit failure
states, rate limiting, a circuit breaker, call budgets, strict output parsing and cassettes."""

from .cassette import CassetteMiss, CassetteStore
from .client import CallRecorder, ModelClient
from .config import PROVIDERS, ModelConfig, load_config
from .limits import CircuitBreaker, TokenBucket
from .parsing import OutputError, parse_strict
from .profiles import (
    BudgetCheck,
    ModelsConfig,
    Profile,
    RoutedProfile,
    check_budget,
    cumulative_spend,
    estimate_cost,
    load_models_config,
    record_usage,
    resolve_task,
)
from .recording import EvidenceRecorder
from .types import ModelCallStatus, ModelOptions, ModelResult

__all__ = [
    "PROVIDERS", "BudgetCheck", "CallRecorder", "CassetteMiss", "CassetteStore",
    "CircuitBreaker", "EvidenceRecorder", "ModelCallStatus", "ModelClient", "ModelConfig",
    "ModelOptions", "ModelResult", "ModelsConfig", "OutputError", "Profile", "RoutedProfile",
    "TokenBucket", "check_budget", "cumulative_spend", "estimate_cost", "load_config",
    "load_models_config", "parse_strict", "record_usage", "resolve_task",
]
