"""Base model and shared types. Everything is strict, versioned and UTC-only."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, PlainSerializer

SCHEMA_VERSION = "1.0"


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


def format_utc(value: datetime) -> str:
    """Fixed ISO-8601 UTC format (microseconds always present, 'Z' suffix)."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


UTCDatetime = Annotated[
    datetime,
    AfterValidator(_require_utc),
    PlainSerializer(format_utc, return_type=str, when_used="json"),
]


class SXModel(BaseModel):
    """Base for all contracts: unknown fields are rejected, schema_version is carried."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
