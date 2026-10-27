"""Shared runtime types: observations, outcomes, the Planner seam, the LabHandle seam.

Everything in an Observation that came from a page or a tool is UNTRUSTED data.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from sentinelx.common_schemas import ActionRequest

# Tools a planner may propose. Anything else is an unknown tool (the gateway blocks it).
KNOWN_TOOLS = ("navigate", "read_page", "click", "http_request", "tool_call", "submit_form")


@dataclass(frozen=True)
class Observation:
    """What the planner sees before choosing its next action."""

    session_id: str
    step: int  # step number the next ActionRequest must carry (1-based, strictly increasing)
    now: datetime
    url: str | None = None  # current page URL (untrusted)
    text: str = ""  # untrusted page / tool text produced by the last action
    outcome: str = "start"  # start | ok | blocked | error
    blocked_reason: str | None = None  # e.g. "blocked by policy: SECRET_EGRESS"
    tool_result: dict[str, Any] | None = None  # untrusted JSON from a mock tool
    event_id: str | None = None  # evidence event that recorded this observation
    structure: str = ""  # untrusted summary of forms / links / buttons on the page


@dataclass(frozen=True)
class Finish:
    answer: str


@dataclass(frozen=True)
class HistoryEntry:
    step: int
    request: ActionRequest
    outcome: str  # ok | blocked | error
    blocked_reason: str | None = None


@dataclass
class ActionOutcome:
    """Result of executing one action in the adapter (text is UNTRUSTED)."""

    ok: bool
    status: int | None = None
    final_url: str | None = None
    text: str = ""
    error: str | None = None
    tool_result: dict[str, Any] | None = None
    sandbox_blocked: bool = False
    structure: str = ""  # forms / links / buttons (UNTRUSTED), returned by read_page

    def summary(self) -> dict[str, Any]:
        """Redaction-friendly summary stored in ACTION_EXECUTED (no page text)."""
        return {"ok": self.ok, "status": self.status, "final_url": self.final_url,
                "text_length": len(self.text), "error": self.error,
                "sandbox_blocked": self.sandbox_blocked}


class PlannerError(Exception):
    """A planner could not produce an action (e.g. the model is unavailable). The run ends
    FAILED with ``abort_reason`` and is excluded from rates (but counted)."""

    def __init__(self, abort_reason: str, detail: str = "") -> None:
        self.abort_reason, self.detail = abort_reason, detail
        super().__init__(f"{abort_reason}: {detail}" if detail else abort_reason)


@runtime_checkable
class Planner(Protocol):
    """Seam for planners. Prompt 5 adds a model-driven planner behind this same interface."""

    name: str
    kind: str  # e.g. "SIMULATED_SCRIPTED_NAIVE" (never claims to be an LLM)

    def next_action(
        self, observation: Observation, history: Sequence[HistoryEntry]
    ) -> ActionRequest | Finish: ...


@runtime_checkable
class LabHandle(Protocol):
    """What the runtime needs from a lab. The runtime never gets the ledger path or token."""

    @property
    def port(self) -> int: ...

    def reset(self, scenario_id: str, seed: int | None = None) -> str: ...

    def read_ledger(self) -> list[dict[str, Any]]: ...


@dataclass
class KillSwitch:
    """A process-wide stop. Once triggered the run is cancelled and the gateway also blocks."""

    _event: threading.Event = field(default_factory=threading.Event)

    def trigger(self) -> None:
        self._event.set()

    @property
    def active(self) -> bool:
        return self._event.is_set()
