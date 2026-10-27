"""Provider-agnostic, OpenAI-compatible Chat Completions client (httpx; no vendor SDK).

Rules this module enforces (CLAUDE.md rules 1, 2, 5, 6):
* Every model reply is UNTRUSTED data: only the final `content` is parsed, strictly, and
  validated against the task's Pydantic schema (extra=forbid). Nothing is silently repaired.
* A failed call is an explicit status (MODEL_UNAVAILABLE / TIMEOUT / RATE_LIMITED /
  INVALID_OUTPUT). A failed LIVE call never falls back to a recording.
* Prompts are redacted before they leave the process. The API key exists only in the
  Authorization header: it is never logged, stored, put in an event or in an exception.
* Reasoning text is ignored; only its length and SHA-256 are kept.
"""

from __future__ import annotations

import email.utils
import hashlib
import logging
import random
import time
from collections.abc import Callable
from typing import Any, Protocol

import httpx
from pydantic import BaseModel

from sentinelx.common_schemas import ModelMode, ModelStatus
from sentinelx.policy.redaction import redact

from .cassette import CassetteMiss, CassetteStore, Recorded, request_key
from .config import ModelConfig
from .limits import CircuitBreaker, TokenBucket
from .parsing import OutputError, parse_strict
from .types import ModelCallStatus, ModelOptions, ModelResult

log = logging.getLogger("sentinelx.model")
S = ModelCallStatus


class CallRecorder(Protocol):
    def record(self, result: ModelResult, debug_messages: list[dict[str, str]] | None) -> None: ...


class ModelClient:
    def __init__(
        self, config: ModelConfig, *, transport: httpx.BaseTransport | None = None,
        cassettes: CassetteStore | None = None, recorder: CallRecorder | None = None,
        clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self.config = config
        self.recorder = recorder
        # what to name (and key cassettes by): in RECORDED mode, the provider that was recorded
        self.provider_label = (config.recorded_provider if config.provider == "recorded"
                               else config.provider)
        self.cassettes = cassettes or CassetteStore()
        self._sleep, self._rng, self._clock = sleep, rng, clock
        self.http = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(config.read_timeout_s, connect=config.connect_timeout_s))
        self.limiter = TokenBucket(config.max_rpm, clock=clock, sleep=sleep)
        self.breaker = CircuitBreaker(config.breaker_threshold, config.breaker_cooldown_s, clock)
        self.logical_calls = 0
        self.http_calls = 0
        self.tokens_in = 0
        self.tokens_out = 0
        self.rate_limit_hits = 0
        self.last_error: str | None = None
        self._run_calls = 0
        self._run_cap: int | None = None

    # ------------------------------------------------------------------ lifecycle / status
    @property
    def mode(self) -> ModelMode:
        return ModelMode.RECORDED if self.config.provider == "recorded" else ModelMode.LIVE

    def begin_run(self, cap: int | None = None) -> None:
        self._run_calls, self._run_cap = 0, cap if cap is not None else self.config.run_call_cap

    def end_run(self) -> int:
        calls, self._run_calls, self._run_cap = self._run_calls, 0, None
        return calls

    def close(self) -> None:
        self.http.close()

    def model_status(self) -> ModelStatus:
        """What the API/dashboard will show: which provider/model, mode, usage, last error."""
        return ModelStatus(
            provider=self.provider_label, model=self.config.model or "(unset)",
            mode=ModelMode.UNAVAILABLE if self.breaker.state == "open" else self.mode,
            calls=self.logical_calls, tokens=self.tokens_in + self.tokens_out,
            error=self.last_error)

    # ------------------------------------------------------------------ public API
    def complete(self, task: str, messages: list[dict[str, str]], schema: type[BaseModel],
                 options: ModelOptions | None = None) -> ModelResult:
        cfg = self.config
        opts = options or ModelOptions()
        eff = {
            "temperature": opts.temperature if opts.temperature is not None else cfg.temperature,
            "top_p": opts.top_p if opts.top_p is not None else cfg.top_p,
            "max_tokens": opts.max_tokens if opts.max_tokens is not None else cfg.max_tokens,
            "reasoning_effort": (opts.reasoning_effort if opts.reasoning_effort is not None
                                 else cfg.reasoning_effort),
        }
        sent = redact(messages, skip=cfg.redaction_skip).value  # secrets never leave the process
        result = ModelResult(
            status=S.MODEL_UNAVAILABLE, provider=self.provider_label,
            model=cfg.model or "(unset)", mode=self.mode, task=task,
            reasoning_effort=eff["reasoning_effort"] or "default",
            request_hash=request_key(self.provider_label, cfg.model, task, sent, eff))
        reason = self._precheck()
        if reason:
            return self._finish(result, S.MODEL_UNAVAILABLE, reason, sent)
        content = self._exchange(result, sent, eff)
        if content is None:
            return self._finish(result, result.status, result.error, sent)
        try:
            parsed = parse_strict(content, schema)
        except OutputError as first:
            if result.finish_reason == "length":
                reason = f"finish_reason=length: {first}"
                return self._finish(result, S.INVALID_OUTPUT, reason, sent)
            # ONE retry that feeds the validation error back; never silently repaired
            result.repair_attempts = 1
            retry_msgs = [*sent,
                          {"role": "assistant", "content": content[:2000]},
                          {"role": "user", "content": (
                              f"That reply was rejected: {first}. Reply again with exactly ONE "
                              "JSON object in the required format and nothing else.")}]
            content2 = self._exchange(result, redact(retry_msgs, skip=cfg.redaction_skip).value,
                                      eff)
            if content2 is None:
                return self._finish(result, result.status, result.error, sent)
            try:
                parsed = parse_strict(content2, schema)
            except OutputError as second:
                reason = f"{second}"
                if result.finish_reason == "length":
                    reason = f"finish_reason=length: {second}"
                return self._finish(result, S.INVALID_OUTPUT, reason, sent)
        result.parsed = parsed
        return self._finish(result, S.OK, None, sent)

    # ------------------------------------------------------------------ guards
    def _precheck(self) -> str | None:
        cfg = self.config
        if cfg.provider == "meta_api" and not cfg.enable_meta_api:
            return "meta_api is disabled (no paid Meta API access is configured)"
        if cfg.provider != "recorded":
            if cfg.requires_key and not cfg.api_key.get_secret_value():
                return "MODEL_API_KEY is not set"
            missing = [n for n, v in (("MODEL_BASE_URL", cfg.base_url), ("MODEL_NAME", cfg.model))
                       if not v]
            if missing:
                return f"model config incomplete: {', '.join(missing)} not set"
            if not self.breaker.allow():
                return "circuit breaker is open after repeated failures"
        if self.http_calls >= cfg.experiment_call_ceiling and cfg.provider != "recorded":
            return "experiment call ceiling reached"
        if self.tokens_in + self.tokens_out >= cfg.experiment_token_ceiling:
            return "experiment token ceiling reached"
        return None

    def _run_cap_hit(self) -> bool:
        return self._run_cap is not None and self._run_calls >= self._run_cap

    # ------------------------------------------------------------------ one logical exchange
    def _exchange(self, result: ModelResult, messages: list[dict[str, str]],
                  eff: dict[str, Any]) -> str | None:
        """Send `messages`, fill `result`, and return the final content (or None on failure)."""
        if self._run_cap_hit():
            result.status, result.error = S.MODEL_UNAVAILABLE, "per-run model call cap reached"
            return None
        self._run_calls += 1
        self.logical_calls += 1
        key = request_key(self.provider_label, self.config.model, result.task, messages, eff)
        if self.config.provider == "recorded":
            return self._replay(result, key)
        return self._live(result, messages, eff, key)

    def _replay(self, result: ModelResult, key: str) -> str | None:
        try:
            rec = self.cassettes.load(key)
        except CassetteMiss as exc:  # RECORDED mode never reaches the network
            result.status, result.error = S.MODEL_UNAVAILABLE, str(exc)
            return None
        result.tokens_in += rec.tokens_in
        result.tokens_out += rec.tokens_out
        result.request_id = rec.request_id
        result.finish_reason = rec.finish_reason
        return self._accept(result, rec.content, rec.finish_reason)

    def _live(self, result: ModelResult, messages: list[dict[str, str]], eff: dict[str, Any],
              key: str) -> str | None:
        cfg = self.config
        body: dict[str, Any] = {"model": cfg.model, "messages": messages,
                                "temperature": eff["temperature"], "top_p": eff["top_p"],
                                "max_tokens": eff["max_tokens"], "stream": False}
        if eff["reasoning_effort"]:
            body["reasoning_effort"] = eff["reasoning_effort"]
        headers = {"Authorization": f"Bearer {cfg.api_key.get_secret_value()}",
                   "Content-Type": "application/json", "Accept": "application/json"}
        url = f"{cfg.base_url}/chat/completions"
        last_status, last_error, response = S.MODEL_UNAVAILABLE, "no attempt made", None
        attempt = not_found = 0
        while True:
            self.limiter.acquire()
            self.http_calls += 1
            result.http_calls += 1
            wait = 0.0
            started = self._clock()
            try:
                response = self.http.post(url, headers=headers, json=body)
            except httpx.TimeoutException:
                result.latency_ms += (self._clock() - started) * 1000
                last_status, last_error = S.TIMEOUT, "request timed out"
            except httpx.TransportError as exc:
                result.latency_ms += (self._clock() - started) * 1000
                last_status = S.MODEL_UNAVAILABLE
                last_error = f"transport error: {type(exc).__name__}"
            else:
                result.latency_ms += (self._clock() - started) * 1000
                code = response.status_code
                if code == 200:
                    break
                snippet = self._scrub(response.text)
                result.retry_status_codes.append(code)  # every non-200, kept for the usage row
                if code == 404 and not_found < cfg.not_found_retries:
                    # the hosted endpoint returned transient empty-body 404s (docs/AUDIT): retry
                    # at most `not_found_retries` times; a persistent 404 stays MODEL_UNAVAILABLE
                    not_found += 1
                    last_status, last_error = S.MODEL_UNAVAILABLE, f"HTTP 404: {snippet}"
                    result.retries += 1
                    self._sleep(min(cfg.backoff_cap_s, cfg.backoff_base_s * (2 ** (not_found - 1)))
                                * (0.5 + self._rng() * 0.5))
                    response = None
                    continue
                if code == 429:
                    result.rate_limit_hits += 1
                    self.rate_limit_hits += 1
                    last_status, last_error = S.RATE_LIMITED, "HTTP 429 (rate limited)"
                    wait = min(_retry_after(response), cfg.retry_after_cap_s)
                elif code >= 500:
                    last_status, last_error = S.MODEL_UNAVAILABLE, f"HTTP {code}: {snippet}"
                else:  # 4xx: our request or our key is wrong; retrying cannot help
                    self.breaker.record_failure()
                    result.status = S.MODEL_UNAVAILABLE
                    result.error = f"HTTP {code}: {snippet}"
                    self.last_error = result.error
                    return None
            response = None
            if attempt >= cfg.max_retries:
                break
            result.retries += 1
            backoff = min(cfg.backoff_cap_s, cfg.backoff_base_s * (2 ** attempt))
            self._sleep(max(wait, backoff * (0.5 + self._rng() * 0.5)))
            attempt += 1
        if response is None:
            self.breaker.record_failure()
            result.status, result.error = last_status, last_error
            self.last_error = last_error
            return None
        self.breaker.record_success()
        return self._read_response(result, response, messages, eff, key)

    def _read_response(self, result: ModelResult, response: httpx.Response,
                       messages: list[dict[str, str]], eff: dict[str, Any], key: str) -> str | None:
        try:
            doc = response.json()
            choice = doc["choices"][0]
            message = choice["message"]
        except (ValueError, KeyError, IndexError, TypeError):
            result.status, result.error = S.INVALID_OUTPUT, "malformed response envelope"
            return None
        usage = doc.get("usage") or {}
        t_in, t_out = int(usage.get("prompt_tokens") or 0), int(usage.get("completion_tokens") or 0)
        result.tokens_in += t_in
        result.tokens_out += t_out
        self.tokens_in += t_in
        self.tokens_out += t_out
        result.request_id = (response.headers.get("nvcf-reqid")
                             or response.headers.get("x-request-id") or doc.get("id"))
        reasoning = message.get("reasoning_content") or message.get("reasoning") or ""
        if isinstance(reasoning, str) and reasoning:
            result.reasoning_chars += len(reasoning)  # length + hash only; the text is dropped
            result.reasoning_hash = hashlib.sha256(reasoning.encode("utf-8")).hexdigest()
        content = message.get("content")
        content = content if isinstance(content, str) else ""
        result.finish_reason = choice.get("finish_reason")
        text = self._accept(result, content, result.finish_reason)
        if text is not None and self.config.record_cassettes:
            self.cassettes.save(key, provider=self.provider_label, model=self.config.model,
                                task=result.task,
                                rec=Recorded(text, result.finish_reason, t_in, t_out,
                                             result.request_id))
        return text

    def _accept(self, result: ModelResult, content: str, finish_reason: str | None) -> str | None:
        """Common tail for live and replayed replies."""
        result.raw_content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if finish_reason == "length" and not content.strip():
            result.status = S.INVALID_OUTPUT
            result.error = ("finish_reason=length with empty content: the reasoning used the whole "
                            "max_tokens budget")
            return None
        return content

    # ------------------------------------------------------------------ bookkeeping
    def _scrub(self, text: str) -> str:
        key = self.config.api_key.get_secret_value()
        if key:
            text = text.replace(key, "[REDACTED:api_key]")
        return str(redact(text).value)[:300]

    def _finish(self, result: ModelResult, status: ModelCallStatus, error: str | None,
                sent: list[dict[str, str]]) -> ModelResult:
        result.status = status
        result.error = self._scrub(error) if error else None
        if status is not S.OK:
            self.last_error = result.error
        elif status is S.OK:
            self.last_error = None
        log.info("model call task=%s status=%s provider=%s model=%s mode=%s latency_ms=%.0f "
                 "tokens_in=%d tokens_out=%d retries=%d", result.task, status.value,
                 result.provider, result.model, result.mode.value, result.latency_ms,
                 result.tokens_in, result.tokens_out, result.retries)
        if self.recorder is not None:
            try:
                self.recorder.record(result, sent if self.config.debug_log_prompts else None)
            except Exception:  # noqa: BLE001 - bookkeeping must never mask the model result
                log.exception("model call recorder failed")
        return result


def _retry_after(response: httpx.Response) -> float:
    raw = response.headers.get("retry-after", "").strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(raw)
        return max(0.0, when.timestamp() - time.time())
    except (TypeError, ValueError):
        return 0.0
