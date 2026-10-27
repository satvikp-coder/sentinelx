"""Page-initiated request rules + conditional high-impact rules (pure, no browser)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from sentinelx.common_schemas import Decision, PolicyMode, ScenarioSpec, SessionState
from sentinelx.policy import (
    LoadedPolicy,
    PolicyConfig,
    SessionContext,
    evaluate,
    evaluate_page_request,
    load_policy,
)

ROOT = Path(__file__).resolve().parents[2]
LAB = load_policy(ROOT / "configs" / "policy" / "lab.yaml")
PORT = 4321
ORDERS = f"http://orders.lab.test:{PORT}"
COLLECTOR = f"http://collector.lab.test:{PORT}"
NOW = "2026-10-27T12:00:00Z"


def scenario(actions=("navigate", "read_page", "http_request")) -> ScenarioSpec:
    return ScenarioSpec.model_validate(dict(
        id="x", seed=1, fixture_id="f", fixture_version="1", goal="g",
        allowed_hosts=[f"orders.lab.test:{PORT}"], allowed_actions=list(actions),
        attack_surface="s", attack_payload_id="p",
        forbidden_outcome={"type": "endpoint_called", "endpoint": "collector.lab.test/collect"},
        goal_assertion={"type": "answer_contains", "expected": ["x"]}))


def page(url: str, rtype: str = "image", method: str = "GET", source: str | None = None, **kw):
    return evaluate_page_request(
        dict(url=url, resource_type=rtype, method=method, source_url=source), scenario(),
        kw.get("policy", LAB))


# (id, request kwargs, expected decision, expected rule (rule_ids[-1]), expected reason)
CASES = [
    ("same-host-image", dict(url=f"{ORDERS}/static/logo.svg"), "ALLOW", "IN_SCOPE",
     "PAGE_REQUEST_IN_SCOPE"),
    ("same-host-document", dict(url=f"{ORDERS}/orders/1042", rtype="document"), "ALLOW",
     "IN_SCOPE", "PAGE_REQUEST_IN_SCOPE"),
    ("same-host-fetch-post", dict(url=f"{ORDERS}/api/x", rtype="fetch", method="POST"), "ALLOW",
     "IN_SCOPE", "PAGE_REQUEST_IN_SCOPE"),
    ("collector-image", dict(url=f"{COLLECTOR}/collect?x=1"), "BLOCK", "DESTINATION_NOT_ALLOWED",
     "HOST_NOT_ALLOWED"),
    ("collector-fetch", dict(url=f"{COLLECTOR}/collect", rtype="fetch"), "BLOCK",
     "DESTINATION_NOT_ALLOWED", "HOST_NOT_ALLOWED"),
    ("collector-form-post", dict(url=f"{COLLECTOR}/collect", rtype="document", method="POST"),
     "BLOCK", "DESTINATION_NOT_ALLOWED", "HOST_NOT_ALLOWED"),
    ("port-mismatch", dict(url="http://orders.lab.test:9/x"), "BLOCK",
     "DESTINATION_NOT_ALLOWED", "PORT_NOT_ALLOWED"),
    ("userinfo-trick", dict(url=f"http://orders.lab.test@collector.lab.test:{PORT}/"), "BLOCK",
     "DESTINATION_NOT_ALLOWED", "USERINFO_IN_URL"),
    ("ip-literal", dict(url=f"http://127.0.0.1:{PORT}/"), "BLOCK", "DESTINATION_NOT_ALLOWED",
     "IP_LITERAL_NOT_ALLOWED"),
    ("websocket-even-same-host", dict(url=f"ws://orders.lab.test:{PORT}/s", rtype="websocket"),
     "BLOCK", "RESOURCE_TYPE_BLOCKED", "RESOURCE_TYPE_BLOCKED"),
    ("beacon-ping", dict(url=f"{ORDERS}/p", rtype="ping", method="POST"), "BLOCK",
     "RESOURCE_TYPE_BLOCKED", "RESOURCE_TYPE_BLOCKED"),
    ("put-method", dict(url=f"{ORDERS}/x", rtype="fetch", method="PUT"), "BLOCK",
     "METHOD_NOT_ALLOWED", "METHOD_NOT_ALLOWED"),
    ("secret-to-allowed-host", dict(url=f"{ORDERS}/p?t=synth_tok_0123456789abcdef"), "BLOCK",
     "SECRET_EGRESS", "SECRET_EGRESS"),
    ("redirect-hop-in-scope", dict(url=f"{ORDERS}/b", rtype="document", source=f"{ORDERS}/a"),
     "ALLOW", "IN_SCOPE", "PAGE_REQUEST_IN_SCOPE"),
    ("redirect-hop-to-collector",
     dict(url=f"{COLLECTOR}/collect", rtype="document", source=f"{ORDERS}/redirect"), "BLOCK",
     "DESTINATION_NOT_ALLOWED", "HOST_NOT_ALLOWED"),
]


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_page_request_table(case) -> None:
    _, kw, decision, rule, reason = case
    d = page(kw["url"], kw.get("rtype", "image"), kw.get("method", "GET"), kw.get("source"))
    assert (d.decision.value, d.rule_ids[-1], d.reason_code) == (decision, rule, reason), d
    assert d.rule_ids[0] == "PAGE_SUBRESOURCE" and d.policy_version == LAB.policy_version
    assert d.effective_action == d.decision


def test_decision_is_deterministic_and_has_a_stable_id() -> None:
    a = page(f"{COLLECTOR}/collect")
    assert a == page(f"{COLLECTOR}/collect")
    assert a.action_id.startswith("page:") and a.action_id != page(f"{ORDERS}/x").action_id


@pytest.mark.parametrize("junk", [None, 5, "str", [], {}, {"url": ""}, {"url": "x", "extra": 1},
                                  {"url": "http://a/", "resource_type": ""}])
def test_junk_never_raises_and_blocks(junk: Any) -> None:
    d = evaluate_page_request(junk, scenario(), LAB)
    assert d.decision is Decision.BLOCK
    assert evaluate_page_request({"url": ORDERS, "resource_type": "image"}, "junk", LAB
                                 ).decision is Decision.BLOCK
    assert evaluate_page_request({"url": ORDERS, "resource_type": "image"}, scenario(), "junk"
                                 ).decision is Decision.BLOCK


def test_rules_are_versioned_with_the_policy() -> None:
    off = LoadedPolicy.from_config(PolicyConfig.model_validate(
        {**LAB.config.model_dump(), "page_subresource": {"enabled": False}}))
    assert off.policy_version != LAB.policy_version
    d = page(f"{COLLECTOR}/collect", policy=off)
    assert d.decision is Decision.ALLOW and d.reason_code == "PAGE_RULES_DISABLED"
    looser = LoadedPolicy.from_config(PolicyConfig.model_validate(
        {**LAB.config.model_dump(),
         "page_subresource": {"blocked_resource_types": [], "allowed_methods": ["GET"]}}))
    assert looser.policy_version not in {off.policy_version, LAB.policy_version}


def test_monitor_mode_records_would_have_blocked() -> None:
    mon = LoadedPolicy.from_config(PolicyConfig.model_validate(
        {**LAB.config.model_dump(), "mode": "monitor"}))
    d = page(f"{COLLECTOR}/collect", policy=mon)
    assert d.decision is Decision.BLOCK and d.effective_action is Decision.ALLOW
    assert d.would_have_decided is Decision.BLOCK and d.policy_mode is PolicyMode.MONITOR


# ----------------------------------------------------------- conditional high-impact rules
def act(tool: str, step: int = 1, **args: Any) -> dict[str, Any]:
    return dict(session_id="s1", step=step, action_id=f"a{step}", timestamp=NOW, actor="agent",
                tool=tool, arguments=args)


def ctx() -> SessionContext:
    return SessionContext(session_id="s1", state=SessionState.RUNNING, page_origin=f"{ORDERS}/")


@pytest.mark.parametrize(
    ("args", "decision", "reason"),
    [
        (dict(method="GET", url=f"{ORDERS}/api/orders/1042"), "ALLOW", "SAFE_ALLOWLIST"),
        (dict(method="get", url=f"{ORDERS}/api/orders/1042"), "ALLOW", "SAFE_ALLOWLIST"),
        (dict(method="POST", url=f"{ORDERS}/api/feedback", body="hi"), "CONFIRM",
         "CONFIRMATION_REQUIRED"),
        (dict(method="post", url=f"{ORDERS}/api/feedback", body="hi"), "CONFIRM",
         "CONFIRMATION_REQUIRED"),
        (dict(method="DELETE", url=f"{ORDERS}/api/x"), "CONFIRM", "CONFIRMATION_REQUIRED"),
        (dict(method="POST", url=f"{COLLECTOR}/collect", body="x"), "BLOCK", "HOST_NOT_ALLOWED"),
        (dict(method="GET", url=f"{COLLECTOR}/collect"), "BLOCK", "HOST_NOT_ALLOWED"),
        (dict(method="POST", url=f"{ORDERS}/api/feedback",
              body="t=synth_tok_0123456789abcdef"), "BLOCK", "SECRET_EGRESS"),
    ],
)
def test_http_request_is_allowed_for_reads_and_confirmed_for_state_changes(args, decision,
                                                                           reason) -> None:
    d = evaluate(act("http_request", **args), scenario(), LAB, ctx())
    assert (d.decision.value, d.reason_code) == (decision, reason), d
    assert d.requires_human is (decision == "CONFIRM")


def test_http_request_still_needs_scenario_permission() -> None:
    d = evaluate(act("http_request", method="GET", url=f"{ORDERS}/x"),
                 scenario(("navigate", "read_page")), LAB, ctx())
    assert d.decision is Decision.BLOCK and d.reason_code == "TOOL_NOT_IN_SCENARIO"


def test_conditional_high_impact_config_is_validated() -> None:
    base = LAB.config.model_dump()
    bad_unconditional = {**base, "high_impact_actions": [
        {"action": "http_request", "decision": "CONFIRM"}]}
    with pytest.raises(ValidationError):  # allowed AND unconditionally high-impact
        PolicyConfig.model_validate(bad_unconditional)
    dup = {**base, "high_impact_actions": base["high_impact_actions"] * 2}
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate(dup)
    empty_values = {**base, "high_impact_actions": [
        {"action": "http_request", "decision": "CONFIRM",
         "when": [{"arg": "method", "values": []}]}]}
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate(empty_values)


def test_block_beats_confirm_when_both_match() -> None:
    base = LAB.config.model_dump()
    both = {**base, "high_impact_actions": [
        {"action": "http_request", "decision": "CONFIRM",
         "when": [{"arg": "method", "values": ["POST"]}]},
        {"action": "http_request", "decision": "BLOCK",
         "when": [{"arg": "method", "values": ["POST", "PUT"]}]}]}
    cfg = PolicyConfig.model_validate(both)
    assert cfg.high_impact_decision("http_request", {"method": "POST"}) is Decision.BLOCK
    assert cfg.high_impact_decision("http_request", {"method": "GET"}) is None
    assert cfg.high_impact_decision("http_request", {}) is None
