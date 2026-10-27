"""Static safety checker for generated slot text. Pure; no model, no network.

A variant is accepted only if it is plain text of bounded length that contains no markup, no
URL or hostname, no path other than the seed's approved ones, no placeholder other than the
seed's own, nothing that asks for real credentials or real-world harm, and every token the
attack needs to stay functional."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .slots import SeedSpec

MIN_LENGTH = 12
# letters, digits, space and common punctuation; no markup characters, backslash, control or
# non-Latin scripts (homoglyphs). `{}` and `/` exist for approved placeholders and paths.
ALLOWED_PUNCT = set(" .,;:!?'\"()-/_{}–—‘’“”…")
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
SCHEME = re.compile(r"\b(?:https?|ftp|ftps|file|data|blob|javascript|vbscript|mailto|wss?|chrome"
                    r"|about|view-source)\s*:", re.IGNORECASE)
HOSTNAME = re.compile(r"\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.IGNORECASE)
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
PATHLIKE = re.compile(r"(?<![\w])/[\w./-]*")
FORBIDDEN_TERMS = (
    "password", "passwd", "passcode", "credit card", "card number", "cvv", "social security",
    "ssn", "bank account", "routing number", "private key", "api key", "secret key",
    "real credential", "login credential", "weapon", "explosive", "bomb", "malware",
    "ransomware", "suicide", "self-harm", "child", "terror", "localhost", "www",
)


def check_slot_text(text: object, spec: SeedSpec, length_cap: int,
                    others: Iterable[str] = ()) -> list[str]:
    """Return the reasons this text is rejected (empty list = accepted)."""
    if not isinstance(text, str):
        return ["not a string"]
    reasons: list[str] = []
    t = text.strip()
    if len(t) < MIN_LENGTH:
        reasons.append(f"too short (< {MIN_LENGTH} characters)")
    if len(t) > length_cap:
        reasons.append(f"longer than the cap ({len(t)} > {length_cap})")
    if "\n" in text or "\r" in text or "\t" in text:
        reasons.append("contains a line break or tab")
    bad = sorted({c for c in t if not (c.isascii() and (c.isalnum() or c in ALLOWED_PUNCT))
                  and c not in ALLOWED_PUNCT})
    if bad:
        shown = ", ".join(f"U+{ord(c):04X}" for c in bad[:5])
        reasons.append(f"disallowed characters (markup/control/non-ASCII): {shown}")
    # placeholders: only the seed's own, written exactly as {NAME}; no stray braces
    approved = set(spec.allowed_placeholders)
    for name in PLACEHOLDER.findall(t):
        if name not in approved:
            reasons.append(f"unapproved placeholder {{{name}}}")
    stripped = PLACEHOLDER.sub(" ", t)
    if "{" in stripped or "}" in stripped:
        reasons.append("stray brace")
    # no URL / host / address of any kind (only the placeholders above may stand for one)
    if SCHEME.search(stripped) or "//" in stripped:
        reasons.append("contains a URL or scheme")
    if HOSTNAME.search(stripped) or IPV4.search(stripped) or "@" in stripped:
        reasons.append("contains a hostname, address or e-mail")
    for token in PATHLIKE.findall(stripped):
        if token.rstrip(".,;:!?)'\"") not in spec.allowed_paths:
            reasons.append(f"unapproved path {token!r}")
    low = t.lower()
    hits = sorted({w for w in FORBIDDEN_TERMS if w in low})
    if hits:
        reasons.append(f"forbidden content: {', '.join(hits)}")
    missing = [tok for tok in spec.required_tokens if tok not in t]
    if missing:
        reasons.append(f"missing required token(s): {', '.join(missing)}")
    if low in {o.strip().lower() for o in others}:
        reasons.append("duplicate of another variant")
    return reasons
