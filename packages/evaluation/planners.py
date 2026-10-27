"""Planner factories for the experiment runner. Each factory also DESCRIBES its planner, so the
run header, every record and the report name the planner, provider, model and mode."""

from __future__ import annotations

from typing import Any, Protocol

from sentinelx.agent_runtime import ModelPlanner, ScriptedNaivePlanner, brief_from_task
from sentinelx.model_clients import ModelClient

from .cases import Case
from .records import PLANNER_LABEL, PlannerInfo


class PlannerFactory(Protocol):
    def __call__(self, case: Case, lab: Any) -> Any: ...

    def describe(self) -> PlannerInfo: ...


class ScriptedPlannerFactory:
    """The SIMULATED scripted planner (not an LLM)."""

    def __call__(self, case: Case, lab: Any) -> ScriptedNaivePlanner:
        return ScriptedNaivePlanner(case.id, lab.port, task=case.template.task)

    def describe(self) -> PlannerInfo:
        return PlannerInfo(name=ScriptedNaivePlanner.name, kind=ScriptedNaivePlanner.kind,
                           label=PLANNER_LABEL)


class ModelPlannerFactory:
    """A real model behind the same interface. One shared ModelClient across the experiment, so
    the rate limiter, circuit breaker and call/token ceilings apply to the whole experiment."""

    def __init__(self, client: ModelClient) -> None:
        self.client = client

    def __call__(self, case: Case, lab: Any) -> ModelPlanner:
        brief = brief_from_task(case.template.authorized_goal, case.template.task, lab.port)
        return ModelPlanner(self.client, brief)

    def describe(self) -> PlannerInfo:
        probe = ModelPlanner(self.client, brief_from_task("probe", _PROBE_TASK, 0))
        return planner_info(probe)


def planner_info(planner: Any) -> PlannerInfo:
    """PlannerInfo for any planner object (falls back to 'SIMULATED scripted' attributes)."""
    return PlannerInfo(
        name=planner.name, kind=planner.kind, label=getattr(planner, "label", PLANNER_LABEL),
        is_llm=bool(getattr(planner, "is_llm", False)),
        provider=getattr(planner, "provider_label", "none"),
        model=getattr(planner, "model_label", "none"),
        mode=getattr(planner, "mode_label", "SIMULATED"),
        prompt_version=getattr(planner, "prompt_version", None))


def _probe_task():  # a minimal valid TaskScript, used only to describe the planner
    from sentinelx.common_schemas import TaskScript

    return TaskScript.model_validate({"steps": [{"tool": "read_page"}],
                                      "answer": [{"kind": "agenda"}]})


_PROBE_TASK = _probe_task()
