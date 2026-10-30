"""Model path tests (mocked client only). No live model calls."""

import asyncio

import httpx

from sentinelx.common_schemas import IntentLabel
from sentinelx.model_clients import ModelClient, ModelConfig
from sentinelx.shield.proxy import ShieldProxy

FAKE_KEY = "nvapi-" + "k1m2n3o4" * 5


def _model_config():
    return ModelConfig(provider="local", base_url="http://127.0.0.1:1", model="test",
                       api_key=FAKE_KEY, run_call_cap=8)


def _client_with_handler(handler):
    transport = httpx.MockTransport(handler)
    return ModelClient(_model_config(), transport=transport, sleep=lambda s: None)


def _valid_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "id": "chatcmpl-1",
            "choices": [{"message": {"role": "assistant",
                                     "content": '{"intent": "INJECTION_PROBE", '
                                                  '"summary": "model says sqli", '
                                                  '"cited_event_ids": ["evt_1"], '
                                                  '"confidence": 0.9}'},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 5},
        })
    return handler


def _run_model_assess(proxy, client, client_key, signals, event_ids, now):
    return asyncio.new_event_loop().run_until_complete(
        proxy.model_assess(client_key, signals, event_ids, client, now))


def _fresh_proxy():
    p = ShieldProxy.__new__(ShieldProxy)
    p._model_calls = {}
    return p


def test_model_valid_assessment_is_used():
    client = _client_with_handler(_valid_response())
    p = _fresh_proxy()
    result = _run_model_assess(p, client, "c1", ["sql_break_char"], ["evt_1"], 1000.0)
    assert result.model_used is True
    assert result.note is None
    assert result.intent == IntentLabel.INJECTION_PROBE
    assert result.confidence == 0.9
    assert result.cited_event_ids == ["evt_1"]


def test_model_invalid_output_falls_back_to_rules_only():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"not": "an assessment"})
    client = _client_with_handler(handler)
    p = _fresh_proxy()
    result = _run_model_assess(p, client, "c1", ["scanner_ua"], ["evt_1"], 1000.0)
    assert result.model_used is False
    assert result.note == "model unavailable: rules-only"
    assert result.intent == IntentLabel.RECON


def test_model_unavailable_falls_back_to_rules_only():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="error")
    client = _client_with_handler(handler)
    p = _fresh_proxy()
    result = _run_model_assess(p, client, "c1", ["scanner_ua"], ["evt_1"], 1000.0)
    assert result.model_used is False
    assert result.note == "model unavailable: rules-only"


def test_model_per_window_cap_enforced():
    client = _client_with_handler(_valid_response())
    p = _fresh_proxy()
    r1 = _run_model_assess(p, client, "c1", ["scanner_ua"], ["evt_1"], 1000.0)
    assert r1.model_used is True
    r2 = _run_model_assess(p, client, "c1", ["scanner_ua"], ["evt_1"], 1000.0)
    assert r2.model_used is False
    assert r2.note == "model unavailable: rules-only"
