"""Secret redaction, applied before storage and before any model call (CLAUDE.md rule 6).

Best-effort pattern matching: it reduces leakage, it does not guarantee that no secret
survives. Callers still must not put real credentials into labs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_NOT_YET = r"(?!\[REDACTED)"

# (kind, compiled pattern, replacement). Order matters: specific shapes before generic ones.
_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED:private_key]",
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}"),
        "[REDACTED:jwt]",
    ),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED:aws_key]"),
    (
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        "[REDACTED:github_token]",
    ),
    ("nvidia_key", re.compile(r"\bnvapi-[A-Za-z0-9_-]{16,}"), "[REDACTED:nvidia_key]"),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "[REDACTED:api_key]"),
    (
        "synthetic_token",
        re.compile(r"\bsynth_tok_[0-9a-f]{8,}\b"),
        "[REDACTED:synthetic_token]",
    ),
    (
        "bearer",
        re.compile(r"(?i)\b(bearer)\s+" + _NOT_YET + r"[A-Za-z0-9._~+/=-]{8,}"),
        r"\1 [REDACTED:bearer]",
    ),
    (
        "cookie",
        re.compile(r"(?im)\b((?:set-)?cookie)\s*:[ \t]*" + _NOT_YET + r"[^\r\n]+"),
        r"\1: [REDACTED:cookie]",
    ),
    (
        "kv_secret",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|token)"
            r"(\s*[=:]\s*)" + _NOT_YET + r"(?!\s)[^\s&;,\"']+"
        ),
        r"\1\2[REDACTED:secret]",
    ),
]

_SYNTHETIC_TOKEN = re.compile(r"synth_tok_[0-9a-f]{8,}")

_SENSITIVE_KEYS = re.compile(
    r"(?i)^(password|passwd|pwd|secret|client_secret|api[_-]?key|apikey|token|access_token|"
    r"refresh_token|auth_token|authorization|proxy-authorization|cookie|set-cookie|"
    r"private_key|x-api-key)$"
)


@dataclass(frozen=True)
class RedactionResult:
    value: Any
    count: int


def _redact_str(text: str, skip: frozenset[str] = frozenset()) -> tuple[str, int]:
    total = 0
    for kind, pattern, repl in _PATTERNS:
        if kind in skip:
            continue
        if kind == "kv_secret" and "synthetic_token" in skip:
            # "Session token: synth_tok_..." must stay readable when the synthetic token is
            # deliberately let through; every other key=value secret is still redacted.
            changed = 0

            def keep_synthetic(m: re.Match[str]) -> str:
                nonlocal changed
                value = m.group(0)[m.end(2) - m.start(0):]
                if _SYNTHETIC_TOKEN.fullmatch(value):
                    return m.group(0)
                changed += 1
                return f"{m.group(1)}{m.group(2)}[REDACTED:secret]"

            text = pattern.sub(keep_synthetic, text)
            total += changed
            continue
        text, n = pattern.subn(repl, text)
        total += n
    return text, total


def _walk(value: Any, skip: frozenset[str] = frozenset()) -> tuple[Any, int]:
    if isinstance(value, str):
        return _redact_str(value, skip)
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        total = 0
        for k, v in value.items():
            if isinstance(k, str) and _SENSITIVE_KEYS.match(k) and v not in (None, ""):
                if isinstance(v, str) and v.startswith("[REDACTED"):
                    out[k] = v
                else:
                    out[k] = "[REDACTED:field]"
                    total += 1
            else:
                out[k], n = _walk(v, skip)
                total += n
        return out, total
    if isinstance(value, list | tuple):
        items, total = [], 0
        for v in value:
            nv, n = _walk(v, skip)
            items.append(nv)
            total += n
        return (items if isinstance(value, list) else tuple(items)), total
    return value, 0


def redact(value: Any, skip: frozenset[str] = frozenset()) -> RedactionResult:
    """Return a redacted deep copy of ``value`` (str / dict / list) and the number of redactions.

    ``skip`` names pattern kinds to leave alone. The only intended use is the lab's SYNTHETIC
    token ({"synthetic_token"}) in model prompts, so a model can actually see (and be tempted
    to leak) the fake secret. Nothing else should ever be skipped."""
    new, count = _walk(value, skip)
    return RedactionResult(value=new, count=count)
