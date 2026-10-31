#!/usr/bin/env python3
"""sentinelx agent - evaluate ONE action with the real policy gateway."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.common_schemas import ScenarioSpec, SessionState
from sentinelx.policy import SessionContext, evaluate, load_policy

ACTION_KEYS = {"tool", "arguments", "allowed_hosts", "goal"}


def agent_cmd(args) -> int:
    if args.agent_cmd != "check":
        print(f"Unknown agent command: {args.agent_cmd}", file=sys.stderr)
        return 1
    return agent_check(Path(args.policy), Path(args.action))


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
