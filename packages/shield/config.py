"""Shield configuration: strict Pydantic model loaded from ``configs/shield/default.yaml``."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinelx.scanner.authz import is_lab_host


class SizeCaps(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_request_bytes: Annotated[int, Field(ge=0)] = 1_048_576
    max_response_bytes: Annotated[int, Field(ge=0)] = 1_048_576


class Timeouts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    connect_timeout_s: Annotated[float, Field(gt=0)] = 5.0
    read_timeout_s: Annotated[float, Field(gt=0)] = 15.0


class Listen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str = "127.0.0.1"
    port: Annotated[int, Field(ge=1, le=65535)] = 18090


class ShieldConfig(BaseModel):
    """Operator configuration for the live shield. Frozen and strict (extra=forbid)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Annotated[str, Field(pattern="^(monitor|recommend|enforce)$")] = "monitor"
    auto_shield: bool = False
    fail_open: bool = True
    upstream: str
    listen: Listen = Listen()
    size_caps: SizeCaps = SizeCaps()
    timeouts: Timeouts = Timeouts()
    lab_mode: bool = False
    kill_switch_file: str | None = None
    evidence_batch_interval_s: Annotated[float, Field(gt=0)] = 5.0
    suspicious_rate_cap_per_min: Annotated[int, Field(ge=0)] = 20

    @model_validator(mode="after")
    def _upstream_must_be_lab_target(self) -> ShieldConfig:
        from urllib.parse import urlsplit

        host = urlsplit(self.upstream).hostname or ""
        if not is_lab_host(host):
            raise ValueError(
                "shield upstream must be an authorized LAB target "
                f"(loopback or *.lab.test), got {self.upstream!r}"
            )
        return self


def load_shield_config(path: str | Path) -> ShieldConfig:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return ShieldConfig.model_validate(data)
