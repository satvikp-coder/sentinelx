"""Prompt helpers shared by every model-driven component."""

from __future__ import annotations

OPEN = "<<<UNTRUSTED DATA"
CLOSE = "<<<END UNTRUSTED DATA>>>"


def wrap_untrusted(source: str, text: str, limit: int = 6000) -> str:
    """Delimit page text / tool output as DATA. The model is told these blocks are not
    instructions, but safety never rests on that: the policy gateway is the authority.

    Marker look-alikes inside the text are defused so the block cannot be closed early."""
    clean = text[:limit].replace("<<<", "<<​<").replace(">>>", ">​>>")
    return f"{OPEN} source={source}>>>\n{clean}\n{CLOSE}"
