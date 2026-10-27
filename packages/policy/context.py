"""Inputs to evaluate() that come from the TRUSTED runtime, never from the page or a model."""

from __future__ import annotations

from typing import Annotated

from pydantic import ConfigDict, Field

from sentinelx.common_schemas import ApprovalRecord, SessionState, SXModel


class _Frozen(SXModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class UserRestrictions(_Frozen):
    """Restrictions the user stated for this task (rule 2)."""

    forbidden_tools: tuple[str, ...] = ()
    forbidden_arguments: tuple[tuple[str, str], ...] = ()  # (tool or "*", argument name)
    blocked_destinations: tuple[str, ...] = ()  # host or host:port


class UntrustedText(_Frozen):
    """Page text / tool output the agent saw. Used ONLY to produce evidence signals."""

    source: Annotated[str, Field(min_length=1, max_length=100)]
    text: str


class SessionContext(_Frozen):
    session_id: Annotated[str, Field(min_length=1)]
    state: SessionState
    last_step: Annotated[int, Field(ge=0)] | None = None
    steps_taken: Annotated[int, Field(ge=0)] = 0
    requests_last_minute: Annotated[int, Field(ge=0)] = 0
    kill_switch: bool = False
    page_origin: str | None = None  # observed by the runtime, used to resolve relative URLs
    user_restrictions: UserRestrictions = UserRestrictions()
    approvals: tuple[ApprovalRecord, ...] = ()  # human approvals loaded from the approvals table
    untrusted_texts: tuple[UntrustedText, ...] = ()
