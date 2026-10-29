"""Mocked tests for the Baseten task-routing profiles and hard spend guard
(sentinelx.model_clients.profiles). No network; FAKE_KEY is a synthetic placeholder."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel, ConfigDict, SecretStr

from sentinelx.evidence.db import connect, migrate
from sentinelx.model_clients import ModelClient, ModelConfig, ModelOptions
from sentinelx.model_clients.profiles import (
    Budget,
    ModelsConfig,
    Profile,
    RoutingEntry,
    check_budget,
    cumulative_spend,
    estimate_cost,
    record_usage,
    resolve_task,
)

FAKE_BASETEN_KEY = "bt_" + "Zz9Yy8Xx" * 4  # synthetic, not a credential


class Reply(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "db.sqlite")
    migrate(c)
    return c


def config(*, hard_cap: float = 70.0, warning: float = 50.0, reserved: float = 30.0
          ) -> ModelsConfig:
    primary = Profile(name="baseten_spark_open", provider="baseten",
                      base_url="https://inference.baseten.co/v1",
                      model="meta-models/muse-spark-open-1026", api_key_env="BASETEN_API_KEY",
                      reasoning_effort="low", max_tokens=4096,
                      price_per_1m={"input_usd": 1.25, "cached_input_usd": 0.15,
                                    "output_usd": 4.25, "verified": True})
    fallback = Profile(name="nvidia_glimmer", provider="nvidia",
                       base_url="https://integrate.api.nvidia.com/v1",
                       model="meta/muse-glimmer-30b", api_key_env="MODEL_API_KEY",
                       reasoning_effort="low", max_tokens=2048,
                       price_per_1m={"input_usd": 0.0, "cached_input_usd": 0.0,
                                    "output_usd": 0.0, "verified": False})
    return ModelsConfig(
        config_version="test-1", profiles={primary.name: primary, fallback.name: fallback},
        routing={"patch_generation": RoutingEntry(primary=primary.name, fallback=fallback.name)},
        budget={primary.name: Budget(hard_cap_usd=hard_cap, warning_usd=warning,
                                     reserved_usd=reserved)})


def test_budget_cap_blocks_the_call(conn) -> None:
    cfg = config(hard_cap=10.0)
    record_usage(conn, session_id=None, profile_name="baseten_spark_open", provider="baseten",
                 model="x", tokens_in=1, tokens_out=1, latency_ms=1.0, estimated_cost=10.0)
    bc = check_budget(conn, cfg, "baseten_spark_open")
    assert bc.status == "BUDGET_EXHAUSTED"
    routed = resolve_task(conn, cfg, "patch_generation", env_file=None,
                          environ={"BASETEN_API_KEY": FAKE_BASETEN_KEY,
                                   "MODEL_API_KEY": "fake-nvidia-key"})
    # exhausted primary -> falls through to the fallback, which is NOT budgeted/exhausted
    assert routed.status == "OK" and routed.profile_name == "nvidia_glimmer"
    assert routed.fallback_used is True and "BUDGET_EXHAUSTED" in routed.detail


def test_warning_threshold_short_of_the_hard_cap(conn) -> None:
    cfg = config(hard_cap=70.0, warning=50.0)
    record_usage(conn, session_id=None, profile_name="baseten_spark_open", provider="baseten",
                 model="x", tokens_in=1, tokens_out=1, latency_ms=1.0, estimated_cost=55.0)
    bc = check_budget(conn, cfg, "baseten_spark_open")
    assert bc.status == "WARNING" and bc.spent_usd == 55.0
    # still callable - WARNING is not a hard stop
    routed = resolve_task(conn, cfg, "patch_generation", env_file=None,
                          environ={"BASETEN_API_KEY": FAKE_BASETEN_KEY})
    assert routed.status == "OK" and routed.profile_name == "baseten_spark_open"
    assert routed.fallback_used is False


def test_routing_falls_back_and_is_labeled_when_the_primary_key_is_missing(conn) -> None:
    cfg = config()
    routed = resolve_task(conn, cfg, "patch_generation", env_file=None,
                          environ={"MODEL_API_KEY": "fake-nvidia-key"})  # no BASETEN_API_KEY
    assert routed.status == "OK" and routed.profile_name == "nvidia_glimmer"
    assert routed.fallback_used is True
    assert "BASETEN_API_KEY is not set" in routed.detail


def test_neither_profile_available_is_model_unavailable_not_a_retry(conn) -> None:
    cfg = config()
    routed = resolve_task(conn, cfg, "patch_generation", env_file=None, environ={})
    assert routed.status == "MODEL_UNAVAILABLE"
    assert routed.config is None


def test_estimator_refuses_an_oversized_batch(conn) -> None:
    cfg = config(hard_cap=70.0, reserved=30.0)
    profile = cfg.profiles["baseten_spark_open"]
    per_call = estimate_cost(profile, tokens_in=2000, tokens_out=1500)
    usable = cfg.budget["baseten_spark_open"].hard_cap_usd - cumulative_spend(
        conn, "baseten_spark_open") - cfg.budget["baseten_spark_open"].reserved_usd
    small_batch_total = per_call * 6
    huge_batch_total = per_call * 10_000_000
    assert small_batch_total <= usable
    assert huge_batch_total > usable


def test_api_key_never_appears_in_routed_profile_repr_or_detail(conn) -> None:
    cfg = config()
    routed = resolve_task(conn, cfg, "patch_generation", env_file=None,
                          environ={"BASETEN_API_KEY": FAKE_BASETEN_KEY})
    assert FAKE_BASETEN_KEY not in repr(routed)
    assert FAKE_BASETEN_KEY not in routed.detail
    assert routed.config is not None
    assert FAKE_BASETEN_KEY not in repr(routed.config)
    assert FAKE_BASETEN_KEY not in str(routed.config)


def test_reasoning_tokens_count_as_output_for_billing(conn) -> None:
    """Baseten's own docs: usage.completion_tokens already includes reasoning tokens. The
    client must bill on that whole figure, not strip reasoning out of it."""
    cfg = config()
    profile = cfg.profiles["baseten_spark_open"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "id": "chatcmpl-1",
            "choices": [{"message": {"role": "assistant",
                                     "content": json.dumps({"answer": "hi"}),
                                     "reasoning_content": "thinking " * 50},
                        "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 300}})

    client = ModelClient(
        ModelConfig(provider="baseten", base_url="https://api.example.test/v1",
                   model=profile.model, api_key=SecretStr(FAKE_BASETEN_KEY),
                   reasoning_effort="low", max_retries=0),
        transport=httpx.MockTransport(handler))
    result = client.complete("patch_generation",
                             [{"role": "user", "content": "go"}], Reply,
                             options=ModelOptions(max_tokens=512))
    assert result.ok and result.tokens_out == 300  # the whole completion_tokens, reasoning in it
    cost = estimate_cost(profile, result.tokens_in, result.tokens_out)
    assert cost == pytest.approx((20 * 1.25 + 300 * 4.25) / 1_000_000)
