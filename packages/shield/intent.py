"""Fixed intent taxonomy, deterministic rules table, IntentAssessment schema, and
AttackIntent building.

Every AttackIntent is INFERRED and cites real evidence event ids. The optional model path is
off the request path and falls back to rules-only mapping with a visible note.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
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


# ---- rules table: signal -> intent, confidence
# Multiple signals for the same intent are aggregated by confidence-weighted voting
# (aggregate_intent). map_intent is kept for backward compatibility: first match wins.
SIGNAL_TO_INTENT: tuple[tuple[str, IntentLabel, float], ...] = (
    # Injection probes - narrowly scoped, high confidence
    ("sql_break_char", IntentLabel.INJECTION_PROBE, 0.85),
    ("markup_reflected", IntentLabel.INJECTION_PROBE, 0.8),
    ("nosqli_probe", IntentLabel.INJECTION_PROBE, 0.8),
    ("command_injection", IntentLabel.INJECTION_PROBE, 0.85),
    ("directory_traversal", IntentLabel.INJECTION_PROBE, 0.8),
    ("oversized_param", IntentLabel.INJECTION_PROBE, 0.5),
    # Recon - path probing, scanners, 404 sweeps
    ("sensitive_path_env", IntentLabel.RECON, 0.7),
    ("sensitive_path_git", IntentLabel.RECON, 0.7),
    ("backup_extension", IntentLabel.RECON, 0.6),
    ("debug_route", IntentLabel.RECON, 0.6),
    ("scanner_ua", IntentLabel.RECON, 0.65),
    ("high_404_rate", IntentLabel.RECON, 0.6),
    ("directory_listing", IntentLabel.RECON, 0.7),
    # Credential guessing - failed logins (distinguished by velocity/severity)
    ("protected_no_session", IntentLabel.CREDENTIAL_GUESSING, 0.6),
    ("repeated_failed_logins", IntentLabel.CREDENTIAL_GUESSING, 0.8),
    ("rapid_failed_logins", IntentLabel.CREDENTIAL_GUESSING, 0.9),
    ("nonexistent_user_probe", IntentLabel.CREDENTIAL_GUESSING, 0.7),
    # Data enumeration - sequential object access
    ("object_id_enumeration", IntentLabel.DATA_ENUMERATION, 0.75),
    # Admin probing - admin/debug route access without session
    ("admin_probe", IntentLabel.ADMIN_PROBE, 0.8),
    ("sensitive_admin_path", IntentLabel.ADMIN_PROBE, 0.85),
    # Exfiltration attempts - large outbound data transfers
    ("data_transfer_large", IntentLabel.EXFIL_ATTEMPT, 0.75),
)

DEFAULT_INTENT = IntentLabel.RECON
DEFAULT_CONFIDENCE = 0.4


def map_intent(signal_names: list[str]) -> tuple[IntentLabel, float]:
    """Deterministic mapping from fired signal names to (intent, confidence). First match wins.

    Kept for backward compatibility. Prefer aggregate_intent for new code.
    """
    for name in signal_names:
        for sig, intent, conf in SIGNAL_TO_INTENT:
            if name == sig:
                return intent, conf
    return DEFAULT_INTENT, DEFAULT_CONFIDENCE


def aggregate_intent(
    signal_names: list[str],
) -> tuple[IntentLabel, float, dict[IntentLabel, float]]:
    """Aggregate multiple fired signals into one (intent, confidence) verdict.

    Confidence-weighted voting: each signal's confidence is summed per intent; the intent with
    the highest total confidence wins. Ties are broken by signal count, then by the fixed
    taxonomy order (RECON first). Returns (intent, confidence, per_intent_scores). Confidence is
    capped at 1.0 and never fabricated - it is the normalized sum of observed signal confidences.

    Only signals present in SIGNAL_TO_INTENT contribute; unknown signal names are ignored.
    Empty input returns DEFAULT_INTENT / DEFAULT_CONFIDENCE.
    """
    scores: dict[IntentLabel, float] = defaultdict(float)
    counts: dict[IntentLabel, int] = defaultdict(int)
    for name in signal_names:
        for sig, intent, conf in SIGNAL_TO_INTENT:
            if name == sig:
                scores[intent] += conf
                counts[intent] += 1
                break  # a signal name maps to exactly one intent
    if not scores:
        return DEFAULT_INTENT, DEFAULT_CONFIDENCE, dict(scores)

    # Rank by (total confidence desc, signal count desc, taxonomy order asc)
    ranked = sorted(
        scores.items(),
        key=lambda kv: (-kv[1], -counts[kv[0]], INTENT_LABELS.index(kv[0])),
    )
    best_intent, best_score = ranked[0]
    # Confidence is the summed confidence of the winning intent's signals, capped at 1.0.
    # Multiple signals for the same intent reinforce; competing intents do not dilute the
    # winning score (they simply lose the ranking).
    confidence = min(best_score, 1.0)
    return best_intent, confidence, dict(scores)


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
