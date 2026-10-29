"""Shared pieces for the check library: the Check protocol, the fixed severity rule table
(never set by the model), and helpers for building redacted, truncated candidate excerpts.

Every check function takes a `ScanContext` and returns `list[Candidate]`. A check NEVER marks its
own output "confirmed": that word is reserved for `sentinelx.scanner.verify`, which re-runs an
independent, minimal proof in a fresh session."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sentinelx.common_schemas import Severity, VulnClass
from sentinelx.policy.redaction import redact

from ..context import ScanContext
from ..models import Candidate, Endpoint

EXCERPT_LIMIT = 300


def looks_like_a_secret(text: str) -> bool:
    """True if the shared redactor (sentinelx.policy.redaction) would flag `text`, including
    quoted source-code assignments such as `const SECRET = 'xxx'` or `define('APP_SECRET', 'xxx')`
    (that pattern lives in the shared redactor, not here, since redaction is a safety concern
    both the scanner and the independent verifier must apply identically)."""
    return redact(text).count > 0

# Fixed rule table: severity depends only on the vulnerability class, never on confidence, never
# chosen by a model.
SEVERITY_BY_CLASS: dict[VulnClass, Severity] = {
    VulnClass.SQL_INJECTION: Severity.HIGH,
    VulnClass.REFLECTED_XSS: Severity.MEDIUM,
    VulnClass.BROKEN_OBJECT_AUTHORIZATION: Severity.HIGH,
    VulnClass.MISSING_AUTHENTICATION: Severity.HIGH,
    VulnClass.SENSITIVE_FILE_EXPOSURE: Severity.HIGH,
    VulnClass.MISSING_RATE_LIMIT: Severity.MEDIUM,
    VulnClass.SECURITY_HEADERS_AND_COOKIES: Severity.MEDIUM,
    VulnClass.PERMISSIVE_CORS: Severity.MEDIUM,
    VulnClass.VERBOSE_ERRORS: Severity.LOW,
    VulnClass.WEAK_UPLOAD_VALIDATION: Severity.HIGH,
    VulnClass.DEBUG_EXPOSURE: Severity.HIGH,
}


def severity_for(vuln_class: VulnClass) -> Severity:
    return SEVERITY_BY_CLASS[vuln_class]


@dataclass(frozen=True)
class CheckSpec:
    id: str
    vuln_class: VulnClass
    owasp_category: str
    preconditions: str  # what must be true in the inventory/discovery for this check to apply
    safe_strategy: str  # the exact harmless observation this check makes


CheckFn = Callable[[ScanContext], list["Candidate"]]
ApplicableFn = Callable[[ScanContext], list[str]]


@dataclass(frozen=True)
class Check:
    spec: CheckSpec
    run: CheckFn
    # endpoint templates (or fixed paths) this check WOULD examine, used only to build the
    # coverage ledger; it must not make any request of its own
    applicable: ApplicableFn


def excerpt(text: str, *, limit: int = EXCERPT_LIMIT) -> str:
    """Redact, then truncate. Safe to put in a report or an evidence payload."""
    return str(redact(text[: limit * 4]).value)[:limit]


_counter = itertools.count(1)


def candidate_id(check_id: str) -> str:
    return f"cand_{check_id}_{next(_counter):04d}"


def set_query_param(path_and_query: str, name: str, value: str) -> str:
    """Replace (or add) exactly one query parameter, keeping every other parameter as it was."""
    parts = urlsplit(path_and_query)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunsplit(("", "", parts.path, urlencode(pairs), ""))


def get_query_param(path_and_query: str, name: str) -> str | None:
    """The current value of one query parameter in a concrete, previously-seen path+query, or
    None if it is not present there."""
    parts = urlsplit(path_and_query)
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if k == name:
            return v
    return None


PREFERRED_PERSONA_ORDER = ("user_a", "user_b", "admin_guesser", "anonymous")


def pick_sample(ctx: ScanContext, ep: Endpoint) -> tuple[str, str]:
    """A concrete, previously-seen path+query for this endpoint, with the persona that saw it;
    falls back to a synthetic query built from the endpoint's own known parameter names."""
    for persona in PREFERRED_PERSONA_ORDER:
        samples = ep.samples.get(persona)
        if samples:
            return persona, samples[0]
    query = "&".join(f"{p}=1" for p in ep.params)
    return "anonymous", ep.template + (f"?{query}" if query else "")
