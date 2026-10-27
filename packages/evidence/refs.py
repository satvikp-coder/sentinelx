"""Citation checking: findings and intents may only cite events that exist in their session."""

from __future__ import annotations

from sentinelx.common_schemas import SXModel

from .store import EvidenceStore

_CITATION_FIELDS = ("evidence_event_ids", "cited_event_ids", "intent_event_ids")


class UnknownEventReference(ValueError):
    def __init__(self, missing: list[str], session_id: str) -> None:
        self.missing = missing
        self.session_id = session_id
        super().__init__(f"cites nonexistent events in session {session_id}: {missing}")


def cited_ids(model: SXModel) -> list[str]:
    ids: list[str] = []
    for name in _CITATION_FIELDS:
        ids.extend(getattr(model, name, None) or [])
    return ids


def assert_citations_exist(store: EvidenceStore, session_id: str, model: SXModel) -> None:
    """Raise UnknownEventReference if any cited event id does not exist in ``session_id``."""
    missing = store.resolve_refs(cited_ids(model), session_id)
    if missing:
        raise UnknownEventReference(missing, session_id)
