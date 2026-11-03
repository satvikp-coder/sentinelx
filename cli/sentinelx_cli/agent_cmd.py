#!/usr/bin/env python3
"""sentinelx agent - evaluate actions against a policy gateway or test an adapter."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.common_schemas import ScenarioSpec, SessionState
from sentinelx.policy import SessionContext, evaluate, load_policy

ACTION_KEYS = {"tool", "arguments", "allowed_hosts", "goal"}


def agent_cmd(args) -> int:
    if args.agent_cmd == "check":
        return agent_check(Path(args.policy), Path(args.action))
    elif args.agent_cmd == "test":
        return agent_test(args.adapter, args.lab, args.scenario)
    print(f"Unknown agent command: {args.agent_cmd}", file=sys.stderr)
    return 1


def agent_check(policy_path: Path, action_path: Path) -> int:
    """Load policy + action, run one evaluation, print decision. Exit 2 on validation errors."""
    if not policy_path.is_file():
        print(f"ERROR: policy file not found: {policy_path}", file=sys.stderr)
        return 2
    if not action_path.is_file():
        print(f"ERROR: action file not found: {action_path}", file=sys.stderr)
        return 2

    try:
        policy = load_policy(policy_path)
    except Exception as exc:  # strict loader: surface the validation message
        print(f"ERROR: invalid policy: {exc}", file=sys.stderr)
        return 2

    try:
        spec = json.loads(action_path.read_text(encoding="utf-8"))
        if not isinstance(spec, dict) or set(spec) - ACTION_KEYS:
            raise ValueError(f"action JSON keys must be a subset of {sorted(ACTION_KEYS)}")
        tool = spec["tool"]
        arguments = spec.get("arguments") or {}
        allowed_hosts = spec.get("allowed_hosts") or []
        goal = spec.get("goal") or "sentinelx agent check"
        if not isinstance(tool, str) or not tool:
            raise ValueError("'tool' must be a non-empty string")
        if not isinstance(arguments, dict):
            raise ValueError("'arguments' must be an object")
        if not isinstance(allowed_hosts, list):
            raise ValueError("'allowed_hosts' must be a list")
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: invalid action: {exc}", file=sys.stderr)
        return 2

    scenario = ScenarioSpec(
        id="cli-check", seed=0, fixture_id="cli", fixture_version="1",
        goal=goal, allowed_hosts=allowed_hosts, allowed_actions=[tool],
        attack_surface="cli", attack_payload_id="cli",
        forbidden_outcome={"type": "none", "endpoint": "none"},
        goal_assertion={"type": "none", "expected": None},
    )
    context = SessionContext(session_id="cli-check", state=SessionState.RUNNING)
    request = dict(
        session_id="cli-check", step=1, action_id="cli-check-1",
        timestamp=datetime.now(UTC), actor="cli", tool=tool, arguments=arguments,
    )
    decision = evaluate(request, scenario, policy, context)

    print(f"decision: {decision.decision.value}")
    print(f"reason_code: {decision.reason_code}")
    print(f"rule_ids: {decision.rule_ids}")
    print(f"requires_human: {decision.requires_human}")
    print(f"explanation: {decision.explanation}")
    return 0


def agent_test(adapter_spec: str, lab: str, scenario_id: str) -> int:
    """Run an adapter against a lab in both unprotected and protected arms."""
    from sentinelx.agent_test.adapter import load_adapter
    from sentinelx.agent_test.runner import AgentTestConfig, run_agent_test

    try:
        adapter = load_adapter(adapter_spec)
    except Exception as exc:
        print(f"ERROR: invalid adapter spec: {exc}", file=sys.stderr)
        return 2

    config = AgentTestConfig(
        adapter=adapter,
        lab=lab,
        scenario_id=scenario_id,
    )

    try:
        result = run_agent_test(config)
    except Exception as exc:
        print(f"ERROR: agent test failed: {exc}", file=sys.stderr)
        return 1

    print(f"Adapter: {result.adapter_name}")
    print(f"Lab: {result.lab}")
    print(f"Scenario: {result.scenario_id}")
    print(f"Fixture hash: {result.fixture_hash}")
    print()
    print(f"  Arm A (unprotected): {result.arm_a.outcome}")
    print(f"    retries: {result.arm_a.retries_used}, duration: {result.arm_a.duration_ms:.1f}ms")
    print(f"  Arm B (protected):  {result.arm_b.outcome}")
    print(f"    retries: {result.arm_b.retries_used}, duration: {result.arm_b.duration_ms:.1f}ms")
    print()
    print(f"  Attack success: {result.attack_success_numerator}/"
          f"{result.attack_success_denominator}")
    print(f"  Task completion: {result.task_completion_numerator}/"
          f"{result.task_completion_denominator}")
    print(f"  False positive blocks: {result.false_positive_blocks}")
    print(f"  Task preservation: {result.task_preservation}")
    return 0
