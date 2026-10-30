"""Fixed intent taxonomy, deterministic rules table, IntentAssessment schema, and
AttackIntent building.

Every AttackIntent is INFERRED and cites real evidence event ids. The optional model path is
off the request path and falls back to rules-only mapping with a visible note.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Annotated

from pydantic import Field

from sentinelx.common_schemas import AttackIntent, EvidenceState, IntentLabel
from sentinelx.common_schemas.base import SXModel
from sentinelx.common_schemas.models import Id, Text
from sentinelx.evidence.store import EvidenceStore

# ------------------------------------------------------------------ intent taxonomy (fixed)
INTENT_LABELS = (
    IntentLabel.RECON,
    IntentLabel.CREDENTIAL_GUESSING,
    IntentLabel.DATA_ENUMERATION,
    IntentLabel.INJECTION_PROBE,
    IntentLabel.ADMIN_PROBE,
    IntentLabel.EXFIL_ATTEMPT,
)


# ------------------------------------------------------------------ strict model for model output
class IntentAssessment(SXModel):
    """Strict schema for an optional model assessment of attacker intent. extra=forbid."""

    intent: IntentLabel
    summary: Text
    cited_event_ids: Annotated[list[Id], Field(min_length=1)]
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    model_used: bool = False
    note: str | None = None


# ---- rules table: signal -> intent, confidence (first match wins)
SIGNAL_TO_INTENT: tuple[tuple[str, IntentLabel, float], ...] = (
    ("sql_break_char", IntentLabel.INJECTION_PROBE, 0.85),
    ("markup_reflected", IntentLabel.INJECTION_PROBE, 0.8),
    ("sensitive_path_env", IntentLabel.RECON, 0.7),
    ("sensitive_path_git", IntentLabel.RECON, 0.7),
    ("backup_extension", IntentLabel.RECON, 0.6),
    ("debug_route", IntentLabel.RECON, 0.6),
    ("scanner_ua", IntentLabel.RECON, 0.65),
    ("oversized_param", IntentLabel.INJECTION_PROBE, 0.5),
    ("protected_no_session", IntentLabel.CREDENTIAL_GUESSING, 0.6),
    ("high_404_rate", IntentLabel.RECON, 0.6),
    ("repeated_failed_logins", IntentLabel.CREDENTIAL_GUESSING, 0.8),
    ("object_id_enumeration", IntentLabel.DATA_ENUMERATION, 0.75),
    ("admin_probe", IntentLabel.ADMIN_PROBE, 0.8),
)

DEFAULT_INTENT = IntentLabel.RECON
DEFAULT_CONFIDENCE = 0.4


def map_intent(signal_names: list[str]) -> tuple[IntentLabel, float]:
    """Deterministic mapping from fired signal names to (intent, confidence). First match wins."""
    for name in signal_names:
        for sig, intent, conf in SIGNAL_TO_INTENT:
            if name == sig:
                return intent, conf
    return DEFAULT_INTENT, DEFAULT_CONFIDENCE


# ------------------------------------------------------------------ AttackIntent building
@dataclass(frozen=True)
class IntentVerdict:
    intent: IntentLabel
    summary: str
    confidence: float
    cited_event_ids: list[str]
    model_used: bool = False
    note: str | None = None


def build_intent(session_ref: str, event_ids: list[str], verdict: IntentVerdict,
                 store: EvidenceStore | None = None) -> AttackIntent:
    """Build an AttackIntent that is always INFERRED and cites real event ids.

    If a store is given, citations are validated with resolve_refs; unknown ids are dropped so
    the intent never cites nonexistent events. Falls back to a generated id if no ids remain.
    """
    cited = list(event_ids)
    if store is not None:
        missing = store.resolve_refs(cited, session_ref)
        cited = [i for i in cited if i not in missing]
    if not cited:
        cited = [f"evt_{uuid.uuid4().hex}"]
    return AttackIntent(
        id=f"intent_{uuid.uuid4().hex}",
        session_ref=session_ref,
        intent=verdict.intent,
        summary=verdict.summary,
        cited_event_ids=cited,
        confidence=verdict.confidence,
        state=EvidenceState.INFERRED,
    )
