#!/usr/bin/env python3
"""sentinelx agent - Agent Guard SDK commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sentinelx.common_schemas import ScenarioSpec
from sentinelx.policy.config import LoadedPolicy
from sentinelx.policy.engine import evaluate


def agent_cmd(args) -> int:
    if args.agent_cmd == "check":
        return _agent_check(args)
    else:
        print(f"Unknown agent command: {args.agent_cmd}", file=sys.stderr)
        return 1


def _agent_check(args) -> int:
    policy_path = Path(args.policy)
    action_path = Path(args.action)

    if not policy_path.exists():
        print(f"ERROR: Policy file not found: {policy_path}", file=sys.stderr)
        return 2
    if not action_path.exists():
        print(f"ERROR: Action file not found: {action_path}", file=sys.stderr)
        return 2

    # Load policy
    with open(policy_path) as f:
        import yaml
        policy_data = yaml.safe_load(f)

    # Load action
    with open(action_path) as f:
        action_data = json.load(f)

    # Create policy object
    try:
        policy = LoadedPolicy.from_yaml(policy_path)
    except Exception as e:
        print(f"ERROR: Invalid policy: {e}", file=sys.stderr)
        return 2

    # Build action request
    try:
        action_request = {
            "action_id": "cli_check",
            "step": 0,
            "actor": "agent",
            "tool": action_data.get("tool"),
            "arguments": action_data.get("arguments", {}),
            "origin_observation_ids": [],
        }
    except Exception as e:
        print(f"ERROR: Invalid action format: {e}", file=sys.stderr)
        return 2

    # Create minimal scenario and session context
    scenario = {
        "id": "cli_check",
        "seed": 0,
        "fixture_id": "cli",
        "fixture_version": "1",
        "goal": "CLI check",
        "allowed_hosts": [],
        "allowed_actions": [],
        "attack_surface": "cli",
        "attack_payload_id": "cli",
        "forbidden_outcome": {"type": "none", "endpoint": "none"},
        "goal_assertion": {"type": "none", "expected": None},
    }

    session_context = {
        "session_id": "cli_check",
        "step": 0,
        "actor": "cli",
    }

    # Evaluate
    from sentinelx.common_schemas import ActionRequest as AR
    from sentinelx.common_schemas import SessionContext

    action_req = AR(**action_request)
    scenario_spec = ScenarioSpec(**scenario)
    session_ctx = SessionContext(**session_context)

    decision = evaluate(
        action_request=action_request,
        scenario=scenario_spec,
        policy_config=policy,
        session_context=session_ctx,
    )

    # Print decision
    print(f"Decision: {decision.decision.value}")
    print(f"Reason: {decision.reason_code}")
    print(f"Explanation: {decision.explanation}")
    print(f"Requires human: {decision.requires_human}")
    if decision.signals:
        print(f"Signals: {[s.kind.value for s in decision.signals]}")

    return 0 if decision.decision.value != "BLOCK" else 1
