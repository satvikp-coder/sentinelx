"""Strict parsing of model output. All model output is untrusted data.

Allowed leniency: stripping ONE surrounding Markdown code fence. Nothing else is repaired:
no trailing-comma fixes, no quote fixes, no "find the JSON in the prose"."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ValidationError

_FENCE = re.compile(r"\A```(?:json)?[ \t]*\n(.*)\n```\Z", re.DOTALL)


class OutputError(ValueError):
    """The model's content is not exactly one valid JSON object for the schema."""


def _no_constants(name: str) -> Any:
    raise OutputError(f"non-standard JSON constant {name!r}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise OutputError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def strip_one_fence(text: str) -> str:
    text = text.strip()
    m = _FENCE.match(text)
    return m.group(1).strip() if m else text


def parse_strict(content: str, schema: type[BaseModel]) -> BaseModel:
    """Content -> validated schema instance, or OutputError with a short reason."""
    text = strip_one_fence(content)
    if not text:
        raise OutputError("empty content")
    try:
        data = json.loads(text, parse_constant=_no_constants,
                          object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError as exc:
        where = f"line {exc.lineno}, col {exc.colno}"
        raise OutputError(f"not valid JSON: {exc.msg} ({where})") from exc
    if not isinstance(data, dict):
        raise OutputError("the reply must be one JSON object")
    try:
        return schema.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(f"{'.'.join(map(str, e['loc'])) or '(root)'}: {e['msg']}"
                             for e in exc.errors()[:5])
        raise OutputError(f"schema violation: {problems}") from exc
