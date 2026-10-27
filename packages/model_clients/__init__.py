"""Sentinel X model adapter: provider-agnostic OpenAI-compatible client with explicit failure
states, rate limiting, a circuit breaker, call budgets, strict output parsing and cassettes."""

from .cassette import CassetteMiss, CassetteStore
from .client import CallRecorder, ModelClient
from .config import PROVIDERS, ModelConfig, load_config
from .limits import CircuitBreaker, TokenBucket
from .parsing import OutputError, parse_strict
from .recording import EvidenceRecorder
from .types import ModelCallStatus, ModelOptions, ModelResult

__all__ = [
    "PROVIDERS", "CallRecorder", "CassetteMiss", "CassetteStore", "CircuitBreaker",
    "EvidenceRecorder", "ModelCallStatus", "ModelClient", "ModelConfig", "ModelOptions",
    "ModelResult", "OutputError", "TokenBucket", "load_config", "parse_strict",
]
