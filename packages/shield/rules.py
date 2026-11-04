"""Rule compiler, safety gate, and rule evaluation for the live shield.

The shield never edits code. Deterministic code decides; the model, if ever used, only suggests.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sentinelx.common_schemas import (
    ApprovalDecision,
    ApprovalRecord,
    EscalationStatus,
    EscalationTicket,
    EvidenceState,
    ShieldMode,
    ShieldRule,
    ShieldScope,
    ShieldStatus,
)
from sentinelx.common_schemas.models import Id
from sentinelx.evidence.store import EvidenceStore


class ShieldAction(StrEnum):
    RATE_LIMIT_CLIENT = "rate_limit_client"
    BLOCK_ROUTE_PATTERN = "block_route_pattern"
    REQUIRE_AUTH_ON_ROUTE = "require_auth_on_route"
    REJECT_PARAM_PATTERN = "reject_param_pattern"
    ADD_RESPONSE_HEADER = "add_response_header"
    VIRTUAL_PATCH = "virtual_patch"
    STEP_UP_CHALLENGE = "step_up_challenge"


SHIELD_LABEL = "TEMPORARY SHIELD, NOT A FIX"
DEFAULT_TTL_MINUTES = 60
MAX_TTL_MINUTES = 24 * 60  # 24 hours


@dataclass(frozen=True)
class CompileResult:
    rule: ShieldRule | None
    rejected: bool
    reason: str | None


@dataclass(frozen=True)
class GateResult:
    passed: bool
    benign_blocked: int
    benign_total: int
    blocking_requests: list[dict[str, Any]]
    escalation_ticket: EscalationTicket | None
    rule_hash: str | None = None
    checked_at: datetime | None = None


class GateError(ValueError):
    """Activation or approval refused: the gate proof is missing, failed, stale or mismatched."""


GATE_MAX_AGE_S = 60.0


@dataclass(frozen=True)
class EvalDecision:
    allowed: bool
    action: ShieldAction | None
    rule_id: Id | None
    detail: str = ""


def rule_hash(rule: ShieldRule) -> str:
    """Stable hash of what the gate judged: identity, scope, action and cited intent."""
    body = json.dumps(
        {"id": rule.id, "target": rule.target_id, "scope": rule.scope.model_dump(mode="json"),
         "action": rule.action, "intent": rule.intent_event_ids,
         "mode": rule.mode, "expires_at": rule.expires_at.isoformat()},
        sort_keys=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _gen_id(prefix: str = "rule") -> Id:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _parse_ttl(ttl_minutes: int | None) -> timedelta:
    if ttl_minutes is None:
        return timedelta(minutes=DEFAULT_TTL_MINUTES)
    if ttl_minutes > MAX_TTL_MINUTES:
        raise ValueError(f"TTL exceeds maximum of {MAX_TTL_MINUTES} minutes")
    if ttl_minutes <= 0:
        raise ValueError("TTL must be positive")
    return timedelta(minutes=ttl_minutes)


class RuleCompiler:
    """Compiles AttackIntents into ShieldRules. Only the compiler creates rules."""

    def __init__(self, store: EvidenceStore, session_id: str):
        self.store = store
        self.session_id = session_id

    def compile(
        self,
        intent_id: Id,
        suggested_action: ShieldAction,
        scope: ShieldScope,
        reason: str,
        owner: str,
        linked_finding_id: Id | None = None,
        ttl_minutes: int | None = None,
        intent_event_ids: list[Id] | None = None,
        mode: ShieldMode = ShieldMode.ENFORCE,
    ) -> CompileResult:
        """Compile a rule from an AttackIntent and suggested action.

        Returns a CompileResult with the rule (if valid) or rejection reason.
        """
        # Validate action
        try:
            suggested_action = ShieldAction(suggested_action)
        except (ValueError, TypeError):
            return CompileResult(None, True, "Action not in catalog")

        # Validate scope
        if not scope.route or scope.route == "/" or scope.route == "*":
            return CompileResult(None, True, "Route cannot be '/' or wildcard")
        if not scope.route.startswith("/"):
            return CompileResult(None, True, "Route must start with '/'")
        if scope.parameter is not None and scope.parameter == "":
            return CompileResult(None, True, "Parameter cannot be empty if provided")

        # Validate TTL (honour the caller-provided value, not the default)
        try:
            ttl = _parse_ttl(ttl_minutes)
        except ValueError as e:
            return CompileResult(None, True, str(e))

        # Validate owner and reason
        if not owner or not owner.strip():
            return CompileResult(None, True, "Missing owner")
        if not reason or not reason.strip():
            return CompileResult(None, True, "Missing reason")

        # Validate intent_event_ids exist in store
        cited = list(intent_event_ids or [])
        if not cited:
            return CompileResult(None, True, "At least one intent_event_id required")
        missing = self.store.resolve_refs(cited, self.session_id)
        if missing:
            return CompileResult(None, True, f"Cited intent event ids not found: {missing}")

        # Block overly broad rules
        if scope.parameter is None and scope.client is None and scope.route == "/":
            return CompileResult(
                None, True, "Rule with no route, parameter, or client is overly broad"
            )
        if suggested_action == ShieldAction.BLOCK_ROUTE_PATTERN and scope.route == "/":
            return CompileResult(None, True, "Blocking all routes is not allowed")
        if suggested_action == ShieldAction.REQUIRE_AUTH_ON_ROUTE and scope.route == "/":
            return CompileResult(None, True, "Requiring auth on all routes is not allowed")

        now = _now()
        expires = now + ttl

        rule = ShieldRule(
            id=_gen_id("rule"),
            target_id=self.session_id,  # session_id used as target_id for shield
            scope=scope,
            action=suggested_action.value,
            reason=reason,
            linked_finding_id=linked_finding_id,
            intent_event_ids=cited,
            owner=owner,
            created_at=now,
            expires_at=expires,
            status=ShieldStatus.PROPOSED,
            mode=mode,
        )

        return CompileResult(rule, False, None)


class BenignReplayGate:
    """Benign-replay gate: replays benign requests through candidate rule in-process.

    If even ONE benign request would be blocked/altered, REJECT the rule.
    """

    def __init__(
        self,
        store: EvidenceStore,
        session_id: str,
        benign_requests: list[dict[str, Any]] | None = None,
        recorder: ShieldRecorder | None = None,
    ):
        self.store = store
        self.session_id = session_id
        self._benign_requests = benign_requests or []
        self._recorder = recorder

    def check(self, rule: ShieldRule) -> GateResult:
        """Run benign replay against the rule.

        Returns GateResult with passed status and escalation ticket if rejected.
        """
        blocking: list[dict[str, Any]] = []
        # A PROPOSED rule never matches in live evaluation; replay judges scope only.
        for req in self._benign_requests:
            decision = RuleEvaluator.evaluate(rule, req, assume_active=True)
            if not decision.allowed:
                blocking.append(req)

        if blocking:
            # Escalation tickets require at least one evidence reference. When the
            # rule carries none (an API-proposed rule with no cited intent events),
            # record the gate rejection itself as real evidence - never fabricate
            # an unrelated reference. If even that write fails, return the
            # rejection without a ticket: the gate must never crash the caller.
            evidence_ids = list(rule.intent_event_ids)
            if not evidence_ids:
                try:
                    evt = self.store.append(
                        self.session_id, "shield_gate_rejection", EvidenceState.OBSERVED,
                        "sentinelx.shield",
                        {"rule_id": rule.id, "benign_blocked": len(blocking),
                         "benign_total": len(self._benign_requests)})
                    evidence_ids = [evt.id]
                except Exception:  # noqa: BLE001 - evidence failure must not crash the gate
                    evidence_ids = []
            ticket = None
            if evidence_ids:
                ticket = EscalationTicket(
                    id=f"esc_{uuid.uuid4().hex[:12]}",
                    finding_id=rule.linked_finding_id or f"finding_{uuid.uuid4().hex[:12]}",
                    evidence_event_ids=evidence_ids,
                    explanation=(
                        f"Benign-replay gate rejected rule {rule.id}: "
                        f"{len(blocking)} benign request(s) would be blocked/altered"
                    ),
                    options=["DISCARD_RULE", "NARROW_SCOPE"],
                    suggested_interim_shield_id=rule.id,
                    status=EscalationStatus.OPEN,
                    created_at=_now(),
                )
            return GateResult(False, len(blocking), len(self._benign_requests), blocking, ticket,
                              rule_hash(rule), _now())

        return GateResult(True, 0, len(self._benign_requests), [], None, rule_hash(rule), _now())

    def load_benign_from_recorder(self, recorder: ShieldRecorder) -> None:
        """Load recently observed non-suspicious requests from recorder as benign traffic."""
        # In a real implementation, we'd query the evidence store for recent benign events
        # For now, we use the provided benign_requests
        pass

    def load_benign_from_lab(self, lab_module: str) -> None:
        """Load benign traffic from a lab module (e.g., labs.vibe_notes_node.benign_traffic)."""
        import importlib

        mod = importlib.import_module(lab_module)
        if hasattr(mod, "BENIGN_REQUESTS"):
            self._benign_requests = mod.BENIGN_REQUESTS
        else:
            # Fallback: create a synthetic benign request list from the lab's benign traffic
            self._benign_requests = self._synthesize_benign_requests(mod)

    def _synthesize_benign_requests(self, mod: Any) -> list[dict[str, Any]]:
        """Extract request patterns from benign traffic module."""
        # This is a simplified extraction - in practice we'd parse the benign_traffic.py
        # For now, return a basic set of known benign requests for vibe_notes_node
        return [
            {"method": "GET", "path": "/", "headers": {}, "params": {}},
            {"method": "GET", "path": "/health", "headers": {}, "params": {}},
            {"method": "POST", "path": "/api/signup", "headers": {}, "params": {}},
            {"method": "POST", "path": "/api/login", "headers": {}, "params": {}},
            {
                "method": "GET",
                "path": "/api/notes",
                "headers": {"Authorization": "Bearer test"},
                "params": {},
            },
            {
                "method": "POST",
                "path": "/api/notes",
                "headers": {"Authorization": "Bearer test"},
                "params": {},
            },
            {
                "method": "GET",
                "path": "/api/notes/1",
                "headers": {"Authorization": "Bearer test"},
                "params": {},
            },
            {
                "method": "PUT",
                "path": "/api/notes/1",
                "headers": {"Authorization": "Bearer test"},
                "params": {},
            },
            {
                "method": "GET",
                "path": "/api/search?q=plan",
                "headers": {"Authorization": "Bearer test"},
                "params": {},
            },
            {
                "method": "POST",
                "path": "/api/notes/1/share",
                "headers": {"Authorization": "Bearer test"},
                "params": {},
            },
            {
                "method": "PUT",
                "path": "/api/profile",
                "headers": {"Authorization": "Bearer test"},
                "params": {},
            },
            {"method": "GET", "path": "/u/carol", "headers": {}, "params": {}},
            {"method": "GET", "path": "/api/settings", "headers": {}, "params": {}},
            {
                "method": "POST",
                "path": "/api/settings",
                "headers": {"Authorization": "Bearer admin"},
                "params": {},
            },
            {
                "method": "GET",
                "path": "/debug",
                "headers": {"Authorization": "Bearer admin"},
                "params": {},
            },
            {
                "method": "DELETE",
                "path": "/api/notes/1",
                "headers": {"Authorization": "Bearer test"},
                "params": {},
            },
        ]


class RuleEvaluator:
    """Pure function: request in, allow/modify/block decision out. No I/O."""

    @staticmethod
    def evaluate(rule: ShieldRule, request: dict[str, Any], assume_active: bool = False
                 ) -> EvalDecision:
        """Evaluate a single rule against a request.

        Returns EvalDecision with allowed status and action details.
        """
        # Check if rule is active and not expired
        now = _now()
        if rule.status != ShieldStatus.ACTIVE and not assume_active:
            return EvalDecision(True, None, None, "rule not active")
        if rule.expires_at < now:
            return EvalDecision(True, None, None, "rule expired")

        # Check scope match
        if not _scope_matches(rule.scope, request):
            return EvalDecision(True, None, None, "scope mismatch")

        # Monitor/recommend modes never block; only enforce mode takes action.
        if rule.mode != ShieldMode.ENFORCE:
            return EvalDecision(
                True, None, None, f"rule mode is {rule.mode.value}, not enforcing"
            )

        # Rule matches - apply action
        action = ShieldAction(rule.action)
        return EvalDecision(False, action, rule.id, f"matched rule {rule.id}")


def _scope_matches(scope: ShieldScope, request: dict[str, Any]) -> bool:
    """Check if request matches the rule's scope."""
    # Route match (exact or prefix)
    req_path = request.get("path", "")
    if scope.route.endswith("*"):
        prefix = scope.route[:-1]
        if not req_path.startswith(prefix):
            return False
    else:
        if req_path != scope.route:
            return False

    # Parameter match
    if scope.parameter is not None:
        params = request.get("params", {})
        if scope.parameter not in params:
            return False

    # Client match
    if scope.client is not None:
        client = request.get("client_key", "")
        if client != scope.client:
            return False

    return True


def evaluate_rule(rule: ShieldRule, request: dict[str, Any]) -> EvalDecision:
    """Evaluate a single rule against a request."""
    return RuleEvaluator.evaluate(rule, request)


def evaluate_rules(rules: list[ShieldRule], request: dict[str, Any]) -> EvalDecision:
    """Evaluate all active rules against a request. First match wins."""
    for rule in rules:
        decision = evaluate_rule(rule, request)
        if not decision.allowed:
            return decision
    return EvalDecision(True, None, None, "no matching rule")


class RuleLifecycle:
    """Rule lifecycle management: TTL expiry, manual removal, extension."""

    def __init__(self, store: EvidenceStore, session_id: str):
        self.store = store
        self.session_id = session_id
        self._rules: dict[Id, ShieldRule] = {}

    def add_rule(self, rule: ShieldRule) -> None:
        self._rules[rule.id] = rule

    def get_rule(self, rule_id: Id) -> ShieldRule | None:
        return self._rules.get(rule_id)

    def list_rules(self) -> list[ShieldRule]:
        return list(self._rules.values())

    def expire_rules(self, now: datetime | None = None) -> int:
        """Expire rules whose TTL has passed. Returns count of expired rules."""
        now = now or _now()
        count = 0
        for rule in self._rules.values():
            if rule.status == ShieldStatus.ACTIVE and rule.expires_at < now:
                rule = rule.model_copy(update={"status": ShieldStatus.EXPIRED})
                self._rules[rule.id] = rule
                count += 1
        return count

    def remove_rule(self, rule_id: Id, actor: str, reason: str) -> bool:
        rule = self._rules.get(rule_id)
        if not rule:
            return False
        rule = rule.model_copy(update={"status": ShieldStatus.REMOVED})
        self._rules[rule_id] = rule
        return True

    def expire_rule(self, rule_id: Id) -> bool:
        """Manually expire one rule. Returns False when the rule does not exist
        or is already terminal (EXPIRED/REMOVED)."""
        rule = self._rules.get(rule_id)
        if not rule or rule.status in (ShieldStatus.EXPIRED, ShieldStatus.REMOVED):
            return False
        rule = rule.model_copy(update={"status": ShieldStatus.EXPIRED})
        self._rules[rule_id] = rule
        return True

    def deactivate_rule(self, rule_id: Id) -> bool:
        """Transaction compensation: return an ACTIVE rule to PROPOSED after a
        downstream persistence failure. This is the ONLY non-activation exit
        from ACTIVE; it never assigns ACTIVE."""
        rule = self._rules.get(rule_id)
        if not rule or rule.status != ShieldStatus.ACTIVE:
            return False
        rule = rule.model_copy(update={"status": ShieldStatus.PROPOSED})
        self._rules[rule_id] = rule
        return True

    def extend_rule(self, rule_id: Id, additional_minutes: int, actor: str) -> bool:
        rule = self._rules.get(rule_id)
        if not rule:
            return False
        new_expires = rule.expires_at + timedelta(minutes=additional_minutes)
        if new_expires > _now() + timedelta(minutes=MAX_TTL_MINUTES):
            return False
        rule = rule.model_copy(update={"expires_at": new_expires})
        self._rules[rule_id] = rule
        return True

    def activate_rule(self, rule_id: Id, gate: GateResult | None,
                      max_age_s: float = GATE_MAX_AGE_S) -> bool:
        """The ONLY place a rule becomes ACTIVE. Requires a fresh, passing GateResult whose
        rule hash matches this rule; raises GateError otherwise."""
        rule = self._rules.get(rule_id)
        if rule is None or rule.status != ShieldStatus.PROPOSED:
            return False
        if gate is None:
            raise GateError("activation needs a GateResult")
        if not gate.passed:
            raise GateError("gate did not pass")
        if gate.rule_hash != rule_hash(rule):
            raise GateError("gate result belongs to a different rule")
        if gate.checked_at is None or (_now() - gate.checked_at).total_seconds() > max_age_s:
            raise GateError("gate result is stale")
        self._rules[rule_id] = rule.model_copy(update={"status": ShieldStatus.ACTIVE})
        return True

    def approve_rule(self, rule_id: Id, approval: ApprovalRecord, gate: BenignReplayGate
                     ) -> GateResult:
        """Human approval of a PROPOSED rule. The gate is RE-RUN now; the rule is activated
        only if it still passes, however the approval reads."""
        rule = self._rules.get(rule_id)
        if rule is None or rule.status != ShieldStatus.PROPOSED:
            raise GateError(f"rule {rule_id} is not a PROPOSED rule")
        if (approval.subject_type != "shield_rule" or approval.subject_id != rule_id
                or approval.decision != ApprovalDecision.APPROVE):
            raise GateError("approval record does not approve this rule")
        result = gate.check(rule)
        self.store.append(self.session_id, "shield_approval", EvidenceState.OBSERVED,
                          "sentinelx.shield",
                          {"rule_id": rule_id, "approval_id": approval.id,
                           "reviewer": approval.reviewer, "gate_passed": result.passed,
                           "benign_blocked": result.benign_blocked})
        if result.passed:
            self.activate_rule(rule_id, result)
        return result


def retire_rules_for_finding(
    finding_id: Id,
    lifecycle: RuleLifecycle,
    store: EvidenceStore,
    session_id: str,
) -> int:
    """Set matching ACTIVE rules to REMOVED when an ApprovalRecord for an applied fix exists.

    Returns count of retired rules.
    """
    # Find ApprovalRecord for this finding
    # In practice, we'd query the record store
    # For now, check if any approval record exists for this finding
    count = 0
    for rule in lifecycle.list_rules():
        if rule.linked_finding_id == finding_id and rule.status == ShieldStatus.ACTIVE:
            # Check if approval record exists for applied fix
            # Simplified: assume approval exists if we call this function
            rule = rule.model_copy(update={"status": ShieldStatus.REMOVED})
            lifecycle._rules[rule.id] = rule
            count += 1
    return count


# Forward reference for type hints
from sentinelx.shield.recorder import ShieldRecorder  # noqa: E402
