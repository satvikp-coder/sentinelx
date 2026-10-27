"""Result types for model calls. A failed call is an explicit status, never a silent fallback."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sentinelx.common_schemas import ModelMode


class ModelCallStatus(StrEnum):
    OK = "OK"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_OUTPUT = "INVALID_OUTPUT"


@dataclass(frozen=True)
class ModelOptions:
    """Per-call overrides; None means "use the configured default"."""

    temperature: float | None = None
    top_p: float | None = None
    max_tokens: int | None = None
    reasoning_effort: str | None = None


@dataclass
class ModelResult:
    status: ModelCallStatus
    provider: str
    model: str
    mode: ModelMode
    parsed: Any = None  # validated Pydantic object, or None
    raw_content_hash: str | None = None
    latency_ms: float = 0.0  # time spent in HTTP requests (not limiter waits or backoff)
    tokens_in: int = 0
    tokens_out: int = 0
    retries: int = 0  # transport-level retries (timeouts, 429, 5xx)
    repair_attempts: int = 0  # validation-error feedback re-asks (0 or 1)
    http_calls: int = 0
    rate_limit_hits: int = 0
    request_id: str | None = None
    error: str | None = None  # redacted; never contains the key
    estimated_cost: float | None = None  # None: the provider publishes no price
    reasoning_chars: int = 0  # reasoning text is NOT kept; only its length and hash
    reasoning_hash: str | None = None
    finish_reason: str | None = None
    task: str = ""
    request_hash: str = ""
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is ModelCallStatus.OK
