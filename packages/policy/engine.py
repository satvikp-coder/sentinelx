"""The deterministic policy gateway: evaluate() is the ONLY authority for allow / block / confirm.

Pure function: no I/O, no clock, no randomness, no network, no model calls. Unknown anything
fails closed. Page text, tool output and model output reach this module only as data to be
validated; nothing in them can alter the policy or the decision. Signals (evidence hints) are
computed AFTER the verdict and are attached to it; they cannot change it.

Pipeline (first matching rule decides; documented in docs/ARCHITECTURE.md):
  1 INFRASTRUCTURE_DENY   2 USER_RESTRICTIONS   3 SCENARIO_PERMISSIONS
  4 HUMAN_CONFIRMATION    5 SAFE_ALLOWLIST      6 DEFAULT_DENY
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from sentinelx.common_schemas import (
    ActionRequest,
    Decision,
    PolicyDecision,
    PolicyMode,
    PolicySignal,
    ScenarioSpec,
    SessionState,
)

from .config import LoadedPolicy, PolicyConfig, ToolArgRule
from .context import SessionContext
from .redaction import redact
from .signals import collect_signals
from .urls import check_url, host_matches, normalize_url

INFRASTRUCTURE_DENY = "INFRASTRUCTURE_DENY"
USER_RESTRICTIONS = "USER_RESTRICTIONS"
SCENARIO_PERMISSIONS = "SCENARIO_PERMISSIONS"
HUMAN_CONFIRMATION = "HUMAN_CONFIRMATION"
SAFE_ALLOWLIST = "SAFE_ALLOWLIST"
DEFAULT_DENY = "DEFAULT_DENY"

# Reason codes that stay enforced even in monitor mode: the request cannot be interpreted
# at all, or a human pulled the kill switch / the session is not running.
HARD_STOPS = frozenset(
    {
        "MALFORMED_REQUEST", "CONTEXT_INVALID", "SCENARIO_INVALID", "POLICY_INVALID",
        "INTERNAL_ERROR", "KILL_SWITCH", "SESSION_NOT_RUNNING", "SESSION_MISMATCH",
    }
)

_EXPLANATIONS = {
    "MALFORMED_REQUEST": "The action request failed strict validation.",
    "CONTEXT_INVALID": "The session context failed strict validation.",
    "SCENARIO_INVALID": "The scenario failed strict validation.",
    "POLICY_INVALID": "No valid loaded policy was supplied.",
    "INTERNAL_ERROR": "The gateway failed internally; failing closed.",
    "KILL_SWITCH": "The kill switch is active.",
    "SESSION_NOT_RUNNING": "The session is not in the RUNNING state.",
    "SESSION_MISMATCH": "The request belongs to a different session.",
    "STEP_NOT_INCREASING": "The step number did not strictly increase.",
    "MAX_STEPS_EXCEEDED": "The session exceeded the policy's max_steps.",
    "RATE_LIMIT_EXCEEDED": "The session exceeded the policy's request rate limit.",
    "UNKNOWN_TOOL": "The tool/action type is not known to the policy.",
    "USER_FORBIDDEN_TOOL": "The user forbade this tool for the task.",
    "USER_FORBIDDEN_ARGUMENT": "The user forbade this argument for the task.",
    "BLOCKED_DESTINATION": "The destination is on the blocked list.",
    "SECRET_EGRESS": "An argument contains a secret-like value; it must not leave the sandbox.",
    "TOOL_NOT_IN_SCENARIO": "The scenario does not permit this tool.",
    "ARG_NOT_ALLOWED": "An argument is not permitted for this tool.",
    "ARG_MISSING": "A required argument is missing.",
    "ARG_TYPE_INVALID": "An argument has a disallowed type (scalars only).",
    "ARG_TOO_LONG": "An argument exceeds the tool's maximum length.",
    "DESTINATION_NOT_ALLOWED": "The destination is not an allowed host.",
    "HIGH_IMPACT_BLOCKED": "High-impact action is configured to be blocked.",
    "CONFIRMATION_REQUIRED": "High-impact action needs a recorded human approval.",
    "APPROVAL_REJECTED": "A human rejected this exact action.",
    "HUMAN_APPROVED": "A human approved this exact action; all other rules passed.",
    "SAFE_ALLOWLIST": "Allowed read/navigation/interaction on an in-scope destination.",
    "DEFAULT_DENY": "Nothing explicitly allows this action.",
}


@dataclass(frozen=True)
class _Verdict:
    decision: Decision
    stage: str
    rule: str
    reason: str
    detail: str = ""
    requires_human: bool = False


def args_digest(tool: str, arguments: dict[str, Any]) -> str:
    """16-hex digest binding an approval to one exact tool + arguments."""
    doc = json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(doc.encode("utf-8")).hexdigest()[:16]


def approval_subject_id(action_id: str, tool: str, arguments: dict[str, Any]) -> str:
    return f"{action_id}:{args_digest(tool, arguments)}"


def _block(stage: str, rule: str, reason: str | None = None, detail: str = "") -> _Verdict:
    return _Verdict(Decision.BLOCK, stage, rule, reason or rule, detail)


# ------------------------------------------------------------------ rule 1
def _rule_infrastructure(req: ActionRequest, ctx: SessionContext, scn: ScenarioSpec,
                         pol: LoadedPolicy) -> _Verdict | None:
    cfg, s = pol.config, INFRASTRUCTURE_DENY
    if ctx.kill_switch:
        return _block(s, "KILL_SWITCH")
    if ctx.state is not SessionState.RUNNING:
        return _block(s, "SESSION_NOT_RUNNING", detail=f"state={ctx.state.value}")
    if req.session_id != ctx.session_id:
        return _block(s, "SESSION_MISMATCH")
    if ctx.last_step is not None and req.step <= ctx.last_step:
        return _block(s, "STEP_NOT_INCREASING", detail=f"step={req.step} last={ctx.last_step}")
    if ctx.steps_taken >= cfg.max_steps:
        return _block(s, "MAX_STEPS_EXCEEDED", detail=f"max_steps={cfg.max_steps}")
    if ctx.requests_last_minute >= cfg.max_requests_per_minute:
        return _block(s, "RATE_LIMIT_EXCEEDED", detail=f"limit={cfg.max_requests_per_minute}/min")
    if cfg.rule_for(req.tool) is None:
        return _block(s, "UNKNOWN_TOOL")
    return None


# ------------------------------------------------------------------ rule 2
def _url_args(rule: ToolArgRule, req: ActionRequest) -> list[tuple[str, Any]]:
    return [(n, req.arguments[n]) for n in rule.url_args if n in req.arguments]


def _contains_secret(arguments: dict[str, Any], cfg: PolicyConfig) -> bool:
    strings: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            strings.append(v)
            strings.append(unquote(v))
        elif isinstance(v, dict):
            for k, x in v.items():
                walk(str(k))
                walk(x)
        elif isinstance(v, list | tuple):
            for x in v:
                walk(x)

    walk(arguments)
    if redact(arguments).count > 0 or any(redact(s).count > 0 for s in strings):
        return True
    patterns = [re.compile(p) for p in cfg.secret_patterns]
    return any(p.search(s) for p in patterns for s in strings)


def _rule_user_restrictions(req: ActionRequest, ctx: SessionContext, scn: ScenarioSpec,
                            pol: LoadedPolicy) -> _Verdict | None:
    cfg, s, ur = pol.config, USER_RESTRICTIONS, ctx.user_restrictions
    if req.tool in ur.forbidden_tools:
        return _block(s, "USER_FORBIDDEN_TOOL")
    for tool, arg in ur.forbidden_arguments:
        if tool in ("*", req.tool) and arg in req.arguments:
            return _block(s, "USER_FORBIDDEN_ARGUMENT", detail=f"arg={arg[:50]!r}")
    rule = cfg.rule_for(req.tool)
    blocked = (*cfg.blocked_destinations, *ur.blocked_destinations)
    if rule is not None:
        for name, value in _url_args(rule, req):
            res = normalize_url(value, ctx.page_origin, allow_about_blank=cfg.allow_about_blank,
                                trailing_dot=cfg.trailing_dot)
            if res.ok and host_matches(blocked, res.host, res.port, res.scheme, any_port=True):
                return _block(s, "BLOCKED_DESTINATION", detail=f"arg={name}")
    if _contains_secret(req.arguments, cfg):
        return _block(s, "SECRET_EGRESS")
    return None


# ------------------------------------------------------------------ rule 3
def _rule_scenario(req: ActionRequest, ctx: SessionContext, scn: ScenarioSpec,
                   pol: LoadedPolicy) -> _Verdict | None:
    cfg, s = pol.config, SCENARIO_PERMISSIONS
    rule = cfg.rule_for(req.tool)
    if rule is None:  # unreachable after rule 1, kept so this rule is safe on its own
        return _block(s, "UNKNOWN_TOOL")
    if req.tool not in scn.allowed_actions:
        return _block(s, "TOOL_NOT_IN_SCENARIO")
    for name, value in req.arguments.items():
        if name not in rule.allowed:
            return _block(s, "ARG_NOT_ALLOWED", detail=f"arg={name[:50]!r}")
        if not isinstance(value, str | int | float | bool):  # scalars only
            return _block(s, "ARG_TYPE_INVALID", detail=f"arg={name[:50]!r}")
        if isinstance(value, str) and len(value) > rule.max_length:
            return _block(s, "ARG_TOO_LONG", detail=f"arg={name[:50]!r}")
    for name in rule.required:
        if name not in req.arguments:
            return _block(s, "ARG_MISSING", detail=f"arg={name}")
    for name, value in _url_args(rule, req):
        res = check_url(value, scn.allowed_hosts, ctx.page_origin,
                        allow_about_blank=cfg.allow_about_blank, trailing_dot=cfg.trailing_dot)
        if not res.ok:
            return _block(s, "DESTINATION_NOT_ALLOWED", res.reason_code, f"arg={name}")
    return None


# ------------------------------------------------------------------ rule 4
def _rule_human_confirmation(req: ActionRequest, ctx: SessionContext, scn: ScenarioSpec,
                             pol: LoadedPolicy) -> _Verdict | None:
    s = HUMAN_CONFIRMATION
    configured = pol.config.high_impact_decision(req.tool)
    if configured is None:
        return None
    if configured is Decision.BLOCK:
        return _block(s, "HIGH_IMPACT_BLOCKED")
    subject = approval_subject_id(req.action_id, req.tool, req.arguments)
    matching = [a for a in ctx.approvals if a.subject_type == "action" and a.subject_id == subject]
    if any(a.decision.value == "reject" for a in matching):
        return _block(s, "APPROVAL_REJECTED")
    if any(a.decision.value == "approve" for a in matching):
        return _Verdict(Decision.ALLOW, s, "HUMAN_APPROVED", "HUMAN_APPROVED")
    return _Verdict(Decision.CONFIRM, s, "CONFIRMATION_REQUIRED", "CONFIRMATION_REQUIRED",
                    requires_human=True)


# ------------------------------------------------------------------ rule 5
def _rule_safe_allowlist(req: ActionRequest, ctx: SessionContext, scn: ScenarioSpec,
                         pol: LoadedPolicy) -> _Verdict | None:
    if req.tool in pol.config.allowed_tools:
        return _Verdict(Decision.ALLOW, SAFE_ALLOWLIST, "SAFE_ALLOWLIST", "SAFE_ALLOWLIST")
    return None


_RULES: tuple[Callable[..., _Verdict | None], ...] = (
    _rule_infrastructure,
    _rule_user_restrictions,
    _rule_scenario,
    _rule_human_confirmation,
    _rule_safe_allowlist,
)


# ------------------------------------------------------------------ plumbing
def _coerce(model_cls: type, obj: Any) -> Any:
    """Strictly validate ``obj`` into ``model_cls`` (re-validating existing instances)."""
    try:
        if isinstance(obj, model_cls):
            return model_cls.model_validate(obj.model_dump(mode="python"))
        if isinstance(obj, dict):
            return model_cls.model_validate(obj)
    except Exception:
        return None
    return None


def _salvage_id(raw: Any) -> str:
    if isinstance(raw, dict):
        v = raw.get("action_id")
        if isinstance(v, str) and 0 < len(v) <= 200:
            return v
    return "unknown"


def _signals(req: ActionRequest, ctx: SessionContext, pol: LoadedPolicy) -> list[PolicySignal]:
    try:
        texts = [(f"arguments.{k}", v) for k, v in req.arguments.items() if isinstance(v, str)]
        texts += [(t.source, t.text) for t in ctx.untrusted_texts]
        return collect_signals(texts, pol.signal_phrases)
    except Exception:
        return []


def _finalize(v: _Verdict, action_id: str, version: str, mode: PolicyMode,
              signals: list[PolicySignal]) -> PolicyDecision:
    explanation = _EXPLANATIONS.get(v.reason, _EXPLANATIONS["DEFAULT_DENY"])
    if v.detail:
        explanation = f"{explanation} ({v.detail})"
    monitor = mode is PolicyMode.MONITOR
    softened = monitor and v.reason not in HARD_STOPS
    return PolicyDecision(
        action_id=action_id,
        decision=v.decision,
        policy_version=version,
        rule_ids=[v.stage, v.rule],
        reason_code=v.reason,
        explanation=explanation,
        requires_human=v.requires_human,
        policy_mode=mode,
        effective_action=Decision.ALLOW if softened else v.decision,
        would_have_decided=v.decision if monitor else None,
        signals=signals,
    )


def evaluate(
    action_request: Any, scenario: Any, policy_config: Any, session_context: Any
) -> PolicyDecision:
    """Decide one proposed action. Never raises; anything unexpected is a BLOCK."""
    action_id = _salvage_id(action_request)
    try:
        return _evaluate(action_request, scenario, policy_config, session_context)
    except Exception:
        return _finalize(
            _block(INFRASTRUCTURE_DENY, "INTERNAL_ERROR"), action_id,
            getattr(policy_config, "policy_version", "unknown"), PolicyMode.ENFORCE, [],
        )


def _evaluate(action_request: Any, scenario: Any, policy: Any, session_context: Any
              ) -> PolicyDecision:
    if not isinstance(policy, LoadedPolicy):
        return _finalize(_block(INFRASTRUCTURE_DENY, "POLICY_INVALID"),
                         _salvage_id(action_request), "unknown", PolicyMode.ENFORCE, [])
    req = _coerce(ActionRequest, action_request)
    ctx = _coerce(SessionContext, session_context)
    scn = _coerce(ScenarioSpec, scenario)
    mode, version = policy.config.mode, policy.policy_version
    if req is None:
        return _finalize(_block(INFRASTRUCTURE_DENY, "MALFORMED_REQUEST"),
                         _salvage_id(action_request), version, mode, [])
    if ctx is None:
        return _finalize(_block(INFRASTRUCTURE_DENY, "CONTEXT_INVALID"), req.action_id,
                         version, mode, [])
    if scn is None:
        return _finalize(_block(INFRASTRUCTURE_DENY, "SCENARIO_INVALID"), req.action_id,
                         version, mode, _signals(req, ctx, policy))
    verdict = None
    for rule in _RULES:
        verdict = rule(req, ctx, scn, policy)
        if verdict is not None:
            break
    if verdict is None:
        verdict = _block(DEFAULT_DENY, "DEFAULT_DENY")
    return _finalize(verdict, req.action_id, version, mode, _signals(req, ctx, policy))
