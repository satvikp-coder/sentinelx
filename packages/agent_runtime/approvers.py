"""Human-approval workflow for CONFIRM decisions: who answers, and how.

An approver sees ONE ApprovalRequest (bound to an exact tool + arguments digest + session +
policy version) and the proposed action, and answers approve / reject / timeout. It never decides
alone: the runtime records the answer and the gateway RE-EVALUATES the action, so an approval can
never override infrastructure deny, user restrictions or scenario permissions (rules 1-3).

``ScriptedOperator`` is a SIMULATED human. It reads an independent per-scenario file
(fixtures/operator_policy/<scenario id>.json, hand-authored from the user's goal) that the
planner, the gateway and the mitigations never see: this module is imported only by the runtime
wiring and the experiment code, and a test pins that down.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from sentinelx.common_schemas import ActionRequest, ApprovalRequest

OPERATOR_DIR = Path(__file__).resolve().parents[2] / "fixtures" / "operator_policy"
Outcome = Literal["approve", "reject", "timeout"]


@dataclass(frozen=True)
class Verdict:
    outcome: Outcome
    reviewer: str
    rationale: str


class Approver(Protocol):
    name: str
    simulated: bool  # True: the answer is produced by code, not by a person

    def decide(self, request: ApprovalRequest, action: ActionRequest) -> Verdict: ...


class AlwaysReject:
    """Safe default: nothing that needs a human is ever executed."""

    name, simulated = "always_reject", False

    def decide(self, request: ApprovalRequest, action: ActionRequest) -> Verdict:
        return Verdict("reject", "policy:always_reject", "default: no approver configured")


class TimeoutApprover:
    """An unattended session: nobody answers within `after_steps` steps, so it never executes."""

    simulated = False

    def __init__(self, after_steps: int = 3) -> None:
        self.after_steps = after_steps
        self.name = f"timeout_after_{after_steps}_steps"

    def decide(self, request: ApprovalRequest, action: ActionRequest) -> Verdict:
        return Verdict("timeout", "policy:timeout",
                       f"no answer within {self.after_steps} steps; treated as not approved")


class IntendedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    method: str | None = None
    host: str | None = None  # lab host label, e.g. "calendar" for calendar.lab.test
    path: str | None = None  # exact URL path (query ignored)
    field_name: str | None = None


class OperatorPolicy(BaseModel):
    """What the REAL user intends for this scenario, authored from the goal text alone."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    user_goal: str
    intended_actions: list[IntendedAction]


def load_operator_policy(scenario_id: str, directory: Path = OPERATOR_DIR) -> OperatorPolicy | None:
    path = directory / f"{scenario_id}.json"
    if not path.is_file():
        return None
    return OperatorPolicy.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _matches(intended: IntendedAction, action: ActionRequest) -> bool:
    args = action.arguments
    if intended.tool != action.tool:
        return False
    if intended.method and str(args.get("method", "")).upper() != intended.method.upper():
        return False
    if intended.field_name and args.get("field_name") != intended.field_name:
        return False
    if intended.host or intended.path:
        url = args.get("url")
        if not isinstance(url, str):
            return False
        parts = urlsplit(url)
        if intended.host and (parts.hostname or "").split(".")[0] != intended.host:
            return False
        if intended.path and parts.path != intended.path:
            return False
    return True


class ScriptedOperator:
    """SIMULATED human. Approves exactly the actions listed in the independent operator file."""

    simulated = True

    def __init__(self, scenario_id: str, directory: Path = OPERATOR_DIR) -> None:
        self.scenario_id = scenario_id
        self.name = "scripted_operator (SIMULATED)"
        self.policy = load_operator_policy(scenario_id, directory)

    def decide(self, request: ApprovalRequest, action: ActionRequest) -> Verdict:
        who = f"SIMULATED operator ({self.scenario_id})"
        if self.policy is None:
            return Verdict("reject", who, "SIMULATED: no operator policy file for this scenario")
        if any(_matches(i, action) for i in self.policy.intended_actions):
            return Verdict("approve", who, "SIMULATED: the action is listed in the operator policy")
        return Verdict("reject", who, "SIMULATED: the user did not intend this action")


def make_approver(name: str, scenario_id: str, directory: Path = OPERATOR_DIR) -> Approver:
    if name == "always_reject":
        return AlwaysReject()
    if name.startswith("timeout"):
        return TimeoutApprover()
    if name in {"scripted_operator", "operator"}:
        return ScriptedOperator(scenario_id, directory)
    raise ValueError(f"unknown approver {name!r}")
