"""Signal helpers: EVIDENCE ONLY, never authority.

Each function is pure and returns PolicySignal objects carrying the exact matched text and
character offsets. A signal may be attached to a decision as evidence; it can never turn a BLOCK
into an ALLOW and is never the reason for an ALLOW. These are hints, not a defense: a prompt
injection that avoids every phrase here is still stopped (or not) by the deterministic rules.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from sentinelx.common_schemas import PolicySignal, SignalKind

MAX_TEXT = 200_000
MAX_SIGNALS = 20

_HIDDEN_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        r"display\s*:\s*none",
        r"visibility\s*:\s*hidden",
        r"opacity\s*:\s*0(?:\.0+)?(?![\d.])",
        r"font-size\s*:\s*(?:0|[0-2])(?:px|pt|em|rem)?(?![\d.])",
        r"(?:width|height)\s*:\s*0(?:px|pt|em|rem|%)?(?![\d.])",
        r"(?:left|top|text-indent)\s*:\s*-\d{3,}(?:px|em|rem|%)?",
        r"color\s*:\s*(?:#fff(?:fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\b",
        r"aria-hidden\s*=\s*[\"']?true",
        r"<!--.*?-->",
    )
)

_EXFIL_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        r"\b(?:send|post|upload|forward|submit|email|leak|exfiltrate)\b[^.\n]{0,100}?"
        r"\bhttps?://[^\s\"'<>]+",
        r"\b(?:include|attach|append|add|paste|reveal|share)\b[^.\n]{0,40}?"
        r"\b(?:token|password|api[ _-]?key|cookie|credential|secret|session)s?\b",
    )
)


def _clip(text: str) -> str:
    return text[:MAX_TEXT]


def find_instruction_overrides(
    text: str, phrases: Iterable[str], source: str = "text"
) -> list[PolicySignal]:
    out: list[PolicySignal] = []
    body = _clip(text)
    for phrase in phrases:
        pattern = re.compile(r"\b" + re.escape(phrase).replace(r"\ ", r"\s+") + r"\b", re.I)
        for m in pattern.finditer(body):
            out.append(_signal(SignalKind.INSTRUCTION_OVERRIDE, source, m))
    return sorted(out, key=lambda s: (s.start, s.end))


def find_hidden_text_hints(html: str, source: str = "html") -> list[PolicySignal]:
    out: list[PolicySignal] = []
    body = _clip(html)
    for pattern in _HIDDEN_PATTERNS:
        for m in pattern.finditer(body):
            out.append(_signal(SignalKind.HIDDEN_TEXT, source, m))
    return sorted(out, key=lambda s: (s.start, s.end))


def find_exfil_requests(text: str, source: str = "text") -> list[PolicySignal]:
    out: list[PolicySignal] = []
    body = _clip(text)
    for pattern in _EXFIL_PATTERNS:
        for m in pattern.finditer(body):
            out.append(_signal(SignalKind.EXFIL_REQUEST, source, m))
    return sorted(out, key=lambda s: (s.start, s.end))


def collect_signals(
    texts: Iterable[tuple[str, str]], phrases: Iterable[str]
) -> list[PolicySignal]:
    """Run every detector over (source, text) pairs; deterministic order, capped length."""
    phrase_list = tuple(phrases)
    found: list[PolicySignal] = []
    for source, text in texts:
        if not isinstance(text, str) or not text:
            continue
        found += find_instruction_overrides(text, phrase_list, source)
        found += find_hidden_text_hints(text, source)
        found += find_exfil_requests(text, source)
    return found[:MAX_SIGNALS]


def _signal(kind: SignalKind, source: str, m: re.Match[str]) -> PolicySignal:
    return PolicySignal(
        kind=kind, source=source or "text", matched_text=m.group(0)[:200],
        start=m.start(), end=m.end(),
    )
