"""The ONE live test: a single tiny real call to the configured model.

Skipped only when no usable key is configured, and then loudly (see tests/conftest.py). It prints
provider, model, mode, tokens and latency into the pytest summary; it never prints the key."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ConfigDict

from sentinelx.model_clients import ModelCallStatus, ModelClient, load_config


class Pong(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str


@pytest.mark.live
def test_live_smoke_one_tiny_real_call(request: pytest.FixtureRequest) -> None:
    cfg = load_config()
    client = ModelClient(cfg)
    try:
        result = client.complete(
            "live_smoke",
            [{"role": "system", "content": 'Reply with one JSON object only: {"answer": "<text>"}'},
             {"role": "user", "content": 'Set "answer" to the single word pong.'}],
            Pong)
    finally:
        client.close()
    request.config.live_notes.append(  # type: ignore[attr-defined]
        f"status={result.status.value} provider={result.provider} model={result.model} "
        f"mode={result.mode.value} latency_ms={result.latency_ms:.0f} tokens_in={result.tokens_in} "
        f"tokens_out={result.tokens_out} retries={result.retries} "
        f"rate_limit_hits={result.rate_limit_hits} request_id={result.request_id}")
    assert result.status is ModelCallStatus.OK, result.error
    assert result.parsed is not None and result.tokens_in > 0 and result.tokens_out > 0
    assert result.latency_ms > 0 and result.provider == cfg.provider
    assert cfg.api_key.get_secret_value() not in repr(result)
