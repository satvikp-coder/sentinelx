"""Model client configuration. Everything comes from `.env` / the environment; the API key lives
in a SecretStr and is only ever placed in the Authorization header."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

REPO_ROOT = Path(__file__).resolve().parents[2]
PROVIDERS = ("nvidia", "baseten", "together", "fireworks", "local", "recorded", "meta_api")
# Providers known to need a key. `local` (any OpenAI-compatible URL) may legitimately have none.
KEY_REQUIRED = {"nvidia", "baseten", "together", "fireworks", "meta_api"}
# `reasoning_effort` is only sent where it was verified to be accepted (see docs/DECISIONS.md).
DEFAULT_REASONING_EFFORT = {"nvidia": "low"}
Provider = Literal["nvidia", "baseten", "together", "fireworks", "local", "recorded", "meta_api"]


class ModelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: Provider = "nvidia"
    base_url: str = ""
    model: str = ""
    api_key: SecretStr = SecretStr("")
    # reliability
    max_rpm: Annotated[int, Field(ge=1, le=10_000)] = 20  # conservative: the limit is undocumented
    connect_timeout_s: Annotated[float, Field(gt=0)] = 10.0
    read_timeout_s: Annotated[float, Field(gt=0)] = 120.0
    max_retries: Annotated[int, Field(ge=0, le=10)] = 3
    backoff_base_s: Annotated[float, Field(ge=0)] = 1.0
    backoff_cap_s: Annotated[float, Field(ge=0)] = 20.0
    retry_after_cap_s: Annotated[float, Field(ge=0)] = 60.0
    # budgets
    run_call_cap: Annotated[int, Field(ge=1)] = 8
    experiment_call_ceiling: Annotated[int, Field(ge=1)] = 400
    experiment_token_ceiling: Annotated[int, Field(ge=1)] = 1_000_000
    breaker_threshold: Annotated[int, Field(ge=1)] = 5
    breaker_cooldown_s: Annotated[float, Field(ge=0)] = 30.0
    # request defaults (docs: temperature 1.0, top_p 0.95; reasoning + answer share max_tokens)
    max_tokens: Annotated[int, Field(ge=16, le=131_072)] = 2048
    temperature: Annotated[float, Field(ge=0, le=2)] = 1.0
    top_p: Annotated[float, Field(gt=0, le=1)] = 0.95
    reasoning_effort: str | None = None
    # RECORDED mode replays recordings made with this provider (cassette keys include it)
    recorded_provider: Provider = "nvidia"
    # switches
    debug_log_prompts: bool = False  # default OFF: events carry hashes, not prompts
    enable_meta_api: bool = False  # no card: meta_api stays disabled unless explicitly enabled
    record_cassettes: bool = False  # only via --record
    # Lab runs only: leave the SYNTHETIC lab token unredacted in prompts (it is fake by design).
    allow_synthetic_token_in_prompts: bool = False

    @property
    def requires_key(self) -> bool:
        return self.provider in KEY_REQUIRED

    @property
    def redaction_skip(self) -> frozenset[str]:
        if self.allow_synthetic_token_in_prompts:
            return frozenset({"synthetic_token"})
        return frozenset()

    def describe(self) -> dict[str, object]:
        """Safe-to-log summary (never the key)."""
        return {"provider": self.provider, "model": self.model, "base_url": self.base_url,
                "key": "set" if self.api_key.get_secret_value() else "NOT set",
                "max_rpm": self.max_rpm, "run_call_cap": self.run_call_cap,
                "reasoning_effort": self.reasoning_effort}


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _num(raw: str | None, cast: type, default: object) -> object:
    try:
        return cast(raw) if raw not in (None, "") else default
    except ValueError:
        return default


def load_config(env_file: Path | None = None, environ: Mapping[str, str] | None = None
                ) -> ModelConfig:
    """Read `.env` (default: repo root) then let real environment variables override it."""
    merged = parse_env_file(env_file if env_file is not None else REPO_ROOT / ".env")
    merged.update({k: v for k, v in (os.environ if environ is None else environ).items()
                   if k.startswith("MODEL_")})
    provider = (merged.get("MODEL_PROVIDER") or "nvidia").strip().lower()
    if provider not in PROVIDERS:
        raise ValueError(f"MODEL_PROVIDER must be one of {PROVIDERS}, got {provider!r}")
    effort = merged.get("MODEL_REASONING_EFFORT")
    if effort is None:
        effort = DEFAULT_REASONING_EFFORT.get(provider)
    flags = lambda k: merged.get(k, "").strip().lower() in {"1", "true", "yes"}  # noqa: E731
    fields: dict[str, object] = {
        "provider": provider,
        "base_url": merged.get("MODEL_BASE_URL", "").rstrip("/"),
        "model": merged.get("MODEL_NAME", ""),
        "api_key": SecretStr(merged.get("MODEL_API_KEY", "")),
        "reasoning_effort": effort or None,
        "debug_log_prompts": flags("MODEL_DEBUG_LOG_PROMPTS"),
        "enable_meta_api": flags("MODEL_ENABLE_META_API"),
    }
    if merged.get("MODEL_RECORDED_PROVIDER"):
        fields["recorded_provider"] = merged["MODEL_RECORDED_PROVIDER"].strip().lower()
    for env, name, cast in (
        ("MODEL_MAX_RPM", "max_rpm", int), ("MODEL_RUN_CALL_CAP", "run_call_cap", int),
        ("MODEL_EXPERIMENT_CALL_CEILING", "experiment_call_ceiling", int),
        ("MODEL_EXPERIMENT_TOKEN_CEILING", "experiment_token_ceiling", int),
        ("MODEL_BREAKER_THRESHOLD", "breaker_threshold", int),
        ("MODEL_BREAKER_COOLDOWN_S", "breaker_cooldown_s", float),
        ("MODEL_MAX_TOKENS", "max_tokens", int), ("MODEL_TEMPERATURE", "temperature", float),
        ("MODEL_TOP_P", "top_p", float), ("MODEL_MAX_RETRIES", "max_retries", int),
        ("MODEL_CONNECT_TIMEOUT_S", "connect_timeout_s", float),
        ("MODEL_READ_TIMEOUT_S", "read_timeout_s", float),
    ):
        if merged.get(env):
            fields[name] = _num(merged.get(env), cast, None)
    return ModelConfig.model_validate({k: v for k, v in fields.items() if v is not None})
