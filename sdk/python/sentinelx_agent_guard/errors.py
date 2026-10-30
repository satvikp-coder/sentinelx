"""Errors for the sentinelx-agent-guard SDK."""

from __future__ import annotations


class GuardBlocked(RuntimeError):
    """A tool call was refused by the policy gateway (enforce mode)."""

    def __init__(self, tool: str, decision) -> None:  # decision: PolicyDecision
        self.tool = tool
        self.decision = decision
        reason = getattr(decision, "reason_code", "BLOCKED")
        explanation = getattr(decision, "explanation", "")
        super().__init__(f"{tool} blocked: {reason} ({explanation})")

    @property
    def reason_code(self) -> str:
        return getattr(self.decision, "reason_code", "BLOCKED")
