"""Deterministic selection. Code only: a model (or a branch's own description) can never mark a
branch safe. A mitigation is recommended only if the independent verifier says no unauthorized
outcome happened AND the task was completed; among those, the least disruptive wins."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .branch import BranchResult

WEIGHTS_FILE = Path(__file__).resolve().parents[2] / "configs" / "containment" / "weights.yaml"
# fixed tie-break: the least invasive mitigation first
TIE_ORDER = ("BLOCK_ONLY", "PAUSE_AND_CONFIRM", "STRIP_UNTRUSTED_INSTRUCTION",
             "LIMIT_NAVIGATION", "ROLLBACK_AND_RETRY")
NO_SAFE = "no safe mitigation preserves the task: human review required"
EPS = 1e-9
NonNeg = Annotated[float, Field(ge=0.0)]


class Weights(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    w_blocked: NonNeg
    w_confirm: NonNeg
    w_added: NonNeg
    w_strip: NonNeg
    w_latency: NonNeg


def load_weights(path: str | Path = WEIGHTS_FILE) -> Weights:
    return Weights.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))


def disruption_cost(b: BranchResult, w: Weights) -> float:
    return (w.w_blocked * b.blocked_legitimate + w.w_confirm * b.confirmed_legitimate
            + w.w_added * b.branch.added_actions + w.w_strip * (b.stripped_chars / 100.0)
            + w.w_latency * (b.branch.duration_ms / 1000.0))


def utility(b: BranchResult, w: Weights) -> float:
    return 1.0 - disruption_cost(b, w)


@dataclass
class Recommendation:
    winner: str | None
    runner_up: str | None
    human_review: bool
    message: str
    tie: bool = False
    tied: list[str] = field(default_factory=list)
    ranking: list[tuple[str, float]] = field(default_factory=list)  # eligible, completing
    ineligible: dict[str, str] = field(default_factory=dict)  # mitigation -> why
    weights_version: str = ""
    model_cost: float = 0.0

    @property
    def action(self) -> str:
        return "ESCALATE_TO_HUMAN" if self.human_review else str(self.winner)


def select(branches: list[BranchResult], weights: Weights) -> Recommendation:
    ineligible: dict[str, str] = {}
    pool: list[tuple[str, float]] = []
    for b in branches:
        name = b.mitigation
        if b.trap or b.baseline:  # controls: reported, never recommendable
            ineligible[name] = "trap control" if b.trap else "baseline comparison"
        elif not b.valid:
            ineligible[name] = f"invalid run ({b.invalid_reason})"
        elif b.branch.unauthorized_executed:
            ineligible[name] = "unauthorized outcome executed (mandatory constraint failed)"
        elif not b.branch.task_completed:
            ineligible[name] = "task not completed"
        else:
            pool.append((name, round(utility(b, weights), 9)))
    rec = Recommendation(None, None, True, NO_SAFE, ineligible=ineligible,
                         weights_version=weights.version)
    if not pool:
        return rec
    order = {n: i for i, n in enumerate(TIE_ORDER)}
    pool.sort(key=lambda t: (-t[1], order.get(t[0], len(order)), t[0]))
    top = [n for n, u in pool if abs(u - pool[0][1]) <= EPS]
    rec.ranking = pool
    rec.winner = pool[0][0]
    rec.runner_up = pool[1][0] if len(pool) > 1 else None
    rec.human_review, rec.message = False, f"recommend {rec.winner}"
    rec.tie, rec.tied = len(top) > 1, top if len(top) > 1 else []
    return rec
