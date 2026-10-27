"""Policy for requests a PAGE initiates (img, script, iframe, link, fetch/XHR, form posts,
redirect hops, WebSocket, beacons, CSS url()). Pure and deterministic like ``evaluate``:
no I/O, no clock, no network, no model.

A page-initiated request is treated as a PROPOSED side effect of whatever the agent loaded.
In the PROTECTED arm the browser adapter asks this function about EVERY request before it is
served; the rule set lives in the policy file (``page_subresource``), so it is versioned with
``policy_version`` and cannot be changed from a page or a model.

Order: PAGE rules disabled -> malformed -> blocked resource type -> blocked method ->
secret in URL -> destination (exact allowed host; redirect hops via ``check_redirect``) -> ALLOW.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Any

from pydantic import ConfigDict, Field

from sentinelx.common_schemas import Decision, PolicyDecision, PolicyMode, ScenarioSpec, SXModel

from .config import LoadedPolicy
from .engine import contains_secret
from .urls import check_redirect, check_url

PAGE_SUBRESOURCE = "PAGE_SUBRESOURCE"


class PageRequest(SXModel):
    """A request the page itself caused (never a model-proposed action)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: Annotated[str, Field(min_length=1, max_length=4096)]
    resource_type: Annotated[str, Field(min_length=1, max_length=40)]
    method: Annotated[str, Field(min_length=1, max_length=16)] = "GET"
    source_url: Annotated[str, Field(max_length=4096)] | None = None  # set for redirect hops


def _decision(req_id: str, policy: LoadedPolicy, decision: Decision, rule: str, reason: str,
              explanation: str) -> PolicyDecision:
    mode = policy.config.mode
    softened = mode is PolicyMode.MONITOR and decision is not Decision.ALLOW
    return PolicyDecision(
        action_id=req_id, decision=decision, policy_version=policy.policy_version,
        rule_ids=[PAGE_SUBRESOURCE, rule], reason_code=reason, explanation=explanation,
        requires_human=False, policy_mode=mode,
        effective_action=Decision.ALLOW if softened else decision,
        would_have_decided=decision if mode is PolicyMode.MONITOR else None,
    )


def evaluate_page_request(
    page_request: Any, scenario: Any, policy: Any
) -> PolicyDecision:
    """Decide one page-initiated request. Never raises; anything unexpected is a BLOCK."""
    req_id = "page:unknown"
    try:
        if not isinstance(policy, LoadedPolicy):
            return PolicyDecision(
                action_id=req_id, decision=Decision.BLOCK, policy_version="unknown",
                rule_ids=[PAGE_SUBRESOURCE, "POLICY_INVALID"], reason_code="POLICY_INVALID",
                explanation="No valid loaded policy was supplied.", requires_human=False)
        req = (page_request if isinstance(page_request, PageRequest)
               else PageRequest.model_validate(page_request))
        scn = (scenario if isinstance(scenario, ScenarioSpec)
               else ScenarioSpec.model_validate(scenario))
        req_id = "page:" + hashlib.sha256(
            f"{req.method} {req.resource_type} {req.url}".encode()).hexdigest()[:12]
        rules = policy.config.page_subresource
        if not rules.enabled:
            return _decision(req_id, policy, Decision.ALLOW, "PAGE_RULES_DISABLED",
                             "PAGE_RULES_DISABLED",
                             "Page-request rules are disabled in this policy.")
        if req.resource_type.lower() in {t.lower() for t in rules.blocked_resource_types}:
            return _decision(req_id, policy, Decision.BLOCK, "RESOURCE_TYPE_BLOCKED",
                             "RESOURCE_TYPE_BLOCKED",
                             f"Page requests of type {req.resource_type!r} are not allowed.")
        if req.method.upper() not in {m.upper() for m in rules.allowed_methods}:
            return _decision(req_id, policy, Decision.BLOCK, "METHOD_NOT_ALLOWED",
                             "METHOD_NOT_ALLOWED",
                             f"Page requests using {req.method.upper()} are not allowed.")
        if contains_secret({"url": req.url}, policy.config):
            return _decision(req_id, policy, Decision.BLOCK, "SECRET_EGRESS", "SECRET_EGRESS",
                             "The request URL contains a secret-like value.")
        cfg = policy.config
        if req.source_url:
            res = check_redirect(req.source_url, req.url, scn.allowed_hosts,
                                 allow_about_blank=cfg.allow_about_blank,
                                 trailing_dot=cfg.trailing_dot)
        else:
            res = check_url(req.url, scn.allowed_hosts, None,
                            allow_about_blank=cfg.allow_about_blank,
                            trailing_dot=cfg.trailing_dot)
        if not res.ok:
            return _decision(req_id, policy, Decision.BLOCK, "DESTINATION_NOT_ALLOWED",
                             res.reason_code, "The destination is not an allowed host.")
        return _decision(req_id, policy, Decision.ALLOW, "IN_SCOPE", "PAGE_REQUEST_IN_SCOPE",
                         "In-scope page request.")
    except Exception:
        return PolicyDecision(
            action_id=req_id, decision=Decision.BLOCK,
            policy_version=getattr(policy, "policy_version", "unknown"),
            rule_ids=[PAGE_SUBRESOURCE, "INTERNAL_ERROR"], reason_code="INTERNAL_ERROR",
            explanation="The page-request check failed internally; failing closed.",
            requires_human=False)
