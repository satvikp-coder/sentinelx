"""Fixed vocabularies. Free strings are not used for any fixed set."""

from enum import StrEnum


class EvidenceState(StrEnum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    PROPOSED = "PROPOSED"
    SIMULATED = "SIMULATED"
    VERIFIED = "VERIFIED"
    APPLIED = "APPLIED"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CONFIRM = "CONFIRM"


class SessionKind(StrEnum):
    AGENT_RUN = "AGENT_RUN"
    SCAN = "SCAN"
    FIX = "FIX"
    GUARD = "GUARD"
    CONTAINMENT = "CONTAINMENT"


class SessionState(StrEnum):
    CREATED = "CREATED"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    ANALYZED = "ANALYZED"
    EXPORTED = "EXPORTED"


class Arm(StrEnum):
    """Paired-experiment arm."""

    UNPROTECTED = "UNPROTECTED"
    PROTECTED = "PROTECTED"


class PolicyMode(StrEnum):
    ENFORCE = "enforce"
    MONITOR = "monitor"


class SignalKind(StrEnum):
    """Evidence-only hints found in untrusted text. Never an authority."""

    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    HIDDEN_TEXT = "HIDDEN_TEXT"
    EXFIL_REQUEST = "EXFIL_REQUEST"


class Surface(StrEnum):
    """Where in the lab an attack payload (or its benign near-neighbor) lives."""

    VISIBLE_TEXT = "visible_text"
    HIDDEN_DOM = "hidden_dom"
    TOOL_RESULT = "tool_result"
    ROLE_SPOOFING = "role_spoofing"
    MISLEADING_WORKFLOW_NOTICE = "misleading_workflow_notice"
    LINK_OR_REDIRECT = "link_or_redirect"
    FORM_SUBMISSION = "form_submission"
    SUBRESOURCE_EMBED = "subresource_embed"


class SafetyConstraint(StrEnum):
    SYNTHETIC_DATA_ONLY = "synthetic_data_only"
    LAB_HOSTS_ONLY = "lab_hosts_only"
    NO_REAL_CREDENTIALS = "no_real_credentials"
    NON_DESTRUCTIVE = "non_destructive"
    NO_OUTBOUND_NETWORK = "no_outbound_network"


class FindingState(StrEnum):
    CONFIRMED = "confirmed"
    NEEDS_VALIDATION = "needs_validation"
    REJECTED = "rejected"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Mitigation(StrEnum):
    """The ONLY mitigations an investigator may recommend (a catalog, never free text)."""

    BLOCK_ONLY = "BLOCK_ONLY"
    PAUSE_AND_CONFIRM = "PAUSE_AND_CONFIRM"
    STRIP_UNTRUSTED_INSTRUCTION = "STRIP_UNTRUSTED_INSTRUCTION"
    LIMIT_NAVIGATION = "LIMIT_NAVIGATION"
    ROLLBACK_AND_RETRY = "ROLLBACK_AND_RETRY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    ADD_SHIELD_RULE = "ADD_SHIELD_RULE"
    ESCALATE_TO_HUMAN = "ESCALATE_TO_HUMAN"


class ModelMode(StrEnum):
    LIVE = "LIVE"
    RECORDED = "RECORDED"
    UNAVAILABLE = "UNAVAILABLE"
    NONE = "NONE"  # no model was used (e.g. a scripted containment branch)


class ShieldStatus(StrEnum):
    PROPOSED = "PROPOSED"
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REMOVED = "REMOVED"
    REJECTED = "REJECTED"


class EscalationStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class IntentLabel(StrEnum):
    RECON = "RECON"
    CREDENTIAL_GUESSING = "CREDENTIAL_GUESSING"
    DATA_ENUMERATION = "DATA_ENUMERATION"
    INJECTION_PROBE = "INJECTION_PROBE"
    ADMIN_PROBE = "ADMIN_PROBE"
    EXFIL_ATTEMPT = "EXFIL_ATTEMPT"


class TargetStatus(StrEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REVOKED = "REVOKED"


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ActorRole(StrEnum):
    SYSTEM = "SYSTEM"
    OPERATOR = "OPERATOR"  # a human
    AGENT = "AGENT"  # the agent under test or any model-driven component
