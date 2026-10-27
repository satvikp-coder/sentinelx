"""Write every model call to the usage table and as a MODEL_CALL evidence event.

The event holds hashes and counts, NOT prompts or replies (unless the DEBUG flag is on)."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from sentinelx.common_schemas import EvidenceState, UsageRecord
from sentinelx.evidence.records import RecordStore
from sentinelx.evidence.store import EvidenceStore

from .types import ModelResult


class EvidenceRecorder:
    def __init__(self, conn: sqlite3.Connection, session_id: str, prompt_version: str = "") -> None:
        self.conn, self.session_id, self.prompt_version = conn, session_id, prompt_version

    def record(self, result: ModelResult, debug_messages: list[dict[str, str]] | None) -> None:
        RecordStore(self.conn).insert(UsageRecord(
            session_id=self.session_id, provider=result.provider, model=result.model,
            tokens_in=result.tokens_in, tokens_out=result.tokens_out,
            latency_ms=int(result.latency_ms), estimated_cost=result.estimated_cost,
            error=result.error, timestamp=datetime.now(UTC)))
        payload: dict[str, object] = {
            "task": result.task, "status": result.status.value, "provider": result.provider,
            "model": result.model, "mode": result.mode.value,
            "latency_ms": round(result.latency_ms, 1), "tokens_in": result.tokens_in,
            "tokens_out": result.tokens_out, "retries": result.retries,
            "repair_attempts": result.repair_attempts, "http_calls": result.http_calls,
            "rate_limit_hits": result.rate_limit_hits, "request_id": result.request_id,
            "request_hash": result.request_hash, "raw_content_hash": result.raw_content_hash,
            "reasoning_chars": result.reasoning_chars, "reasoning_hash": result.reasoning_hash,
            "finish_reason": result.finish_reason, "error": result.error,
            "prompt_version": self.prompt_version,
            "reasoning_effort": result.reasoning_effort,
        }
        if debug_messages is not None:
            payload["debug_messages"] = debug_messages
        EvidenceStore(self.conn).append(self.session_id, "MODEL_CALL", EvidenceState.OBSERVED,
                                        "model_client", payload)
