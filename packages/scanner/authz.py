"""Site Guard authorization gate: pure logic (no sockets, no HTTP).

Every scanner request must pass through ``sentinelx.scanner.http.GuardedClient``, which asks this
module for every decision. A target is scanned only if (a) it is a LAB target whose hosts are all
loopback / `*.lab.test` names, or (b) - disabled by default, never used in demos - the user proved
ownership by serving a random token at `/.well-known/sentinelx-verify.txt`, acknowledged the scan
in writing and the operator enabled non-lab targets.

Nothing a model, a scanned page or a request can say changes these rules: the configuration is a
frozen object set by the operator and recorded in the evidence at scan start.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from sentinelx.common_schemas import TargetAuthorization, TargetScope, TargetStatus
from sentinelx.policy.urls import check_url, normalize_url

WELL_KNOWN_PATH = "/.well-known/sentinelx-verify.txt"
ACK_PHRASE = "I OWN THIS TARGET AND I AUTHORIZE SENTINEL X TO SCAN IT"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})
LAB_SUFFIX = ".lab.test"
METADATA_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal", "fd00:ec2::254",
                            "100.100.100.200"})


class Refusal(StrEnum):
    UNVERIFIED_TARGET = "UNVERIFIED_TARGET"
    OUT_OF_SCOPE_HOST = "OUT_OF_SCOPE_HOST"
    OUT_OF_SCOPE_REDIRECT = "OUT_OF_SCOPE_REDIRECT"
    PRIVATE_ADDRESS = "PRIVATE_ADDRESS"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    KILL_SWITCH = "KILL_SWITCH"
    EXPIRED_VERIFICATION = "EXPIRED_VERIFICATION"
    USERINFO_IN_URL = "USERINFO_IN_URL"
    BODY_TOO_LARGE = "BODY_TOO_LARGE"
    # extra, still structured
    NON_LAB_DISABLED = "NON_LAB_DISABLED"
    BAD_URL = "BAD_URL"
    STATE_CHANGE_UNDECLARED = "STATE_CHANGE_UNDECLARED"
    NO_ADDRESS = "NO_ADDRESS"


FATAL = frozenset({Refusal.BUDGET_EXCEEDED, Refusal.KILL_SWITCH, Refusal.EXPIRED_VERIFICATION})


class TargetRegistrationError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code, self.detail = code, detail
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str  # a Refusal value, or "ALLOWED"
    rule: str  # which rule decided
    detail: str = ""

    @property
    def fatal(self) -> bool:
        return not self.allowed and self.reason in {r.value for r in FATAL}


ALLOW = Decision(True, "ALLOWED", "authz.allow")


class AuthzConfig(BaseModel):
    """Operator configuration. Frozen: nothing at scan time can change it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allow_non_lab_targets: bool = False  # ALLOW_NON_LAB_TARGETS; OFF in every default and demo
    verification_ttl_hours: Annotated[float, Field(gt=0)] = 24.0
    allow_state_changing_in_labs: bool = True  # operator switch; still needs a declared profile
    requests_per_second: Annotated[float, Field(gt=0)] = 10.0
    burst: Annotated[int, Field(ge=1)] = 10
    max_rate_wait_s: Annotated[float, Field(ge=0)] = 2.0
    request_budget: Annotated[int, Field(ge=1)] = 500
    per_host_concurrency: Annotated[int, Field(ge=1)] = 2
    request_timeout_s: Annotated[float, Field(gt=0)] = 10.0
    scan_wall_clock_s: Annotated[float, Field(gt=0)] = 600.0
    max_body_bytes: Annotated[int, Field(ge=0)] = 65_536
    max_response_bytes: Annotated[int, Field(ge=1)] = 1_000_000
    max_redirects: Annotated[int, Field(ge=0, le=10)] = 5


def config_from_env(env: dict[str, str] | None = None) -> AuthzConfig:
    env = os.environ if env is None else env
    return AuthzConfig(allow_non_lab_targets=env.get("ALLOW_NON_LAB_TARGETS", "").lower() in
                       {"1", "true", "yes"})


class ScanProfile(BaseModel):
    """What a scan declares up front. Created by operator code, never by model or page text."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = "read-only"
    state_changing_methods: tuple[str, ...] = ()  # e.g. ("POST",): lab targets only
    synthetic_accounts: tuple[str, ...] = ()  # the only accounts a state change may act as


class KillSwitch:
    """Global stop: an in-process flag and/or a file whose existence means STOP."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._flag = threading.Event()
        self.reason = ""

    def trip(self, reason: str = "operator") -> None:
        self.reason = reason
        self._flag.set()

    def reset(self) -> None:
        self._flag.clear()

    @property
    def active(self) -> bool:
        return self._flag.is_set() or bool(self.path and self.path.exists())


class RateLimiter:
    """Token bucket; `acquire` waits up to `max_wait` seconds, else refuses (no silent sleeping)."""

    def __init__(self, rps: float, burst: int, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.rps, self.capacity, self._clock, self._sleep = rps, float(burst), clock, sleep
        self._tokens, self._last = float(burst), clock()
        self._lock = threading.Lock()

    def acquire(self, max_wait: float) -> bool:
        with self._lock:
            now = self._clock()
            self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rps)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            wait = (1.0 - self._tokens) / self.rps
            if wait > max_wait:
                return False
            self._sleep(wait)
            self._last = self._clock()
            self._tokens = 0.0
            return True


# ------------------------------------------------------------------ hosts and addresses
def is_lab_host(host: str) -> bool:
    h = host.lower().strip("[]")
    if h in LOOPBACK_NAMES:
        return True
    return h.endswith(LAB_SUFFIX) and len(h) > len(LAB_SUFFIX) and all(
        part and part.replace("-", "").isalnum() for part in h[: -len(LAB_SUFFIX)].split("."))


def lab_address(host: str) -> str:
    """Lab hosts map to loopback without any DNS lookup."""
    return "::1" if host.strip("[]") == "::1" else "127.0.0.1"


def forbidden_address(ip: str) -> str | None:
    """Why a (non-lab) scan must never connect to `ip`, or None. IPv4 and IPv6."""
    try:
        addr = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return "not an IP address"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if str(addr) in METADATA_HOSTS:
        return "cloud metadata address"
    checks = (("loopback", addr.is_loopback), ("private", addr.is_private),
              ("link-local", addr.is_link_local), ("multicast", addr.is_multicast),
              ("reserved", addr.is_reserved), ("unspecified", addr.is_unspecified),
              ("not globally routable", not addr.is_global))
    for label, hit in checks:
        if hit:
            return label
    return None


# ------------------------------------------------------------------ registration
def _scope(schemes: Iterable[str], hosts: Iterable[str], ports: Iterable[int]) -> TargetScope:
    return TargetScope(schemes=list(schemes), hosts=list(hosts), ports=list(ports))  # type: ignore[arg-type]


def register_lab_target(target_id: str, hosts: Iterable[str], ports: Iterable[int],
                        schemes: Iterable[str] = ("http",), *, now: datetime | None = None
                        ) -> TargetAuthorization:
    """Lab targets: every host must be loopback or `*.lab.test`; auto-verified with method lab."""
    hosts = [h.lower() for h in hosts]
    bad = [h for h in hosts if not is_lab_host(h)]
    if bad:
        raise TargetRegistrationError("LAB_FLAG_NOT_ALLOWED",
                                      f"lab=true needs loopback/.lab.test hosts, got {bad}")
    scope = _scope(schemes, hosts, ports)
    base = f"{scope.schemes[0]}://{hosts[0]}:{scope.ports[0]}"
    return TargetAuthorization(
        target_id=target_id, base_url=base, scope=scope, lab=True, ownership_method="lab",
        verification_token_hash="lab", verified_at=now or datetime.now(UTC),
        status=TargetStatus.VERIFIED)


def register_non_lab_target(config: AuthzConfig, target_id: str, host: str, port: int,
                            scheme: str = "https") -> TargetAuthorization:
    """Non-lab targets start PENDING (UNVERIFIED) and need ALLOW_NON_LAB_TARGETS + verification."""
    if not config.allow_non_lab_targets:
        raise TargetRegistrationError("NON_LAB_DISABLED",
                                      "non-lab targets are disabled (ALLOW_NON_LAB_TARGETS)")
    host = host.lower()
    if is_lab_host(host):
        raise TargetRegistrationError("LAB_HOST_AS_NON_LAB", "use register_lab_target")
    if not host or any(c in host for c in "*/@: \\") or host in METADATA_HOSTS:
        raise TargetRegistrationError("BAD_HOST", host[:60])
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:  # an IP literal can be loopback/private/metadata in disguise: names only
        raise TargetRegistrationError("IP_LITERAL_NOT_ALLOWED", host[:60])
    return TargetAuthorization(
        target_id=target_id, base_url=f"{scheme}://{host}:{port}",
        scope=_scope([scheme], [host], [port]), lab=False, ownership_method="well-known-file",
        verification_token_hash="unissued", verified_at=None, status=TargetStatus.PENDING)


def new_verification_token() -> tuple[str, str]:
    """(token to give the owner, sha256 hash to store). The token itself is never stored."""
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_matches(stored_hash: str, served: str) -> bool:
    given = hashlib.sha256(served.strip().encode("utf-8")).hexdigest()
    return bool(stored_hash) and hmac.compare_digest(given, stored_hash)


def with_token_hash(t: TargetAuthorization, token_hash: str) -> TargetAuthorization:
    return t.model_copy(update={"verification_token_hash": token_hash})


def mark_verified(config: AuthzConfig, t: TargetAuthorization, acknowledgement: str,
                  now: datetime | None = None) -> TargetAuthorization:
    if acknowledgement.strip() != ACK_PHRASE:
        raise TargetRegistrationError("ACKNOWLEDGEMENT_MISSING",
                                      "the owner's acknowledgement string is required")
    now = now or datetime.now(UTC)
    return t.model_copy(update={
        "status": TargetStatus.VERIFIED, "verified_at": now, "acknowledgement": ACK_PHRASE,
        "verification_expires_at": now + timedelta(hours=config.verification_ttl_hours)})


# ------------------------------------------------------------------ per-request decision
def _authority(raw: str) -> str:
    rest = raw.split("://", 1)[1] if "://" in raw else raw
    for ch in "/?#":
        rest = rest.split(ch, 1)[0]
    return rest


def check_target_state(config: AuthzConfig, t: TargetAuthorization, now: datetime
                       ) -> Decision | None:
    if t.status is not TargetStatus.VERIFIED or t.verified_at is None:
        return Decision(False, Refusal.UNVERIFIED_TARGET, "authz.verified", t.status.value)
    if not t.lab:
        if not config.allow_non_lab_targets:
            return Decision(False, Refusal.NON_LAB_DISABLED, "authz.non_lab_disabled")
        if t.verification_expires_at is None or now >= t.verification_expires_at:
            return Decision(False, Refusal.EXPIRED_VERIFICATION, "authz.expiry")
    return None


def check_scope(t: TargetAuthorization, raw_url: str, *, redirect: bool = False
                ) -> tuple[Decision | None, str | None, str | None, int | None]:
    """Exact scheme/host/port against the target's scope. Returns (refusal, host, scheme, port)."""
    out_of_scope = Refusal.OUT_OF_SCOPE_REDIRECT if redirect else Refusal.OUT_OF_SCOPE_HOST
    if not isinstance(raw_url, str) or "@" in _authority(raw_url):
        return Decision(False, Refusal.USERINFO_IN_URL, "authz.userinfo"), None, None, None
    n = normalize_url(raw_url)
    if not n.ok or n.host is None or n.port is None or n.scheme is None:
        return Decision(False, Refusal.BAD_URL, "authz.url", n.reason_code), None, None, None
    if n.scheme not in t.scope.schemes:
        return (Decision(False, out_of_scope, "authz.scope.scheme", n.scheme),
                n.host, n.scheme, n.port)
    allowed = [f"{h}:{p}" for h in t.scope.hosts for p in t.scope.ports]
    res = check_url(raw_url, allowed)
    if not res.ok:
        return (Decision(False, out_of_scope, "authz.scope.host", res.reason_code),
                n.host, n.scheme, n.port)
    return None, n.host, n.scheme, n.port


def check_method(config: AuthzConfig, t: TargetAuthorization, profile: ScanProfile, method: str,
                 reason: str | None, account: str | None) -> Decision | None:
    m = method.upper()
    if m in SAFE_METHODS:
        return None
    if m not in STATE_CHANGING:
        return Decision(False, Refusal.METHOD_NOT_ALLOWED, "authz.method", m)
    if not t.lab:
        return Decision(False, Refusal.METHOD_NOT_ALLOWED, "authz.method.non_lab", m)
    if not config.allow_state_changing_in_labs:
        return Decision(False, Refusal.METHOD_NOT_ALLOWED, "authz.method.operator_off", m)
    if m not in profile.state_changing_methods:
        return Decision(False, Refusal.STATE_CHANGE_UNDECLARED, "authz.method.profile", m)
    if not reason or account not in profile.synthetic_accounts:
        return Decision(False, Refusal.METHOD_NOT_ALLOWED, "authz.method.account_or_reason",
                        "needs a reason and a declared synthetic test account")
    return None


def check_body(config: AuthzConfig, body: bytes | str | None) -> Decision | None:
    size = len(body.encode("utf-8") if isinstance(body, str) else body or b"")
    if size > config.max_body_bytes:
        return Decision(False, Refusal.BODY_TOO_LARGE, "authz.body", f"{size} bytes")
    return None


def check_addresses(addresses: list[str]) -> Decision | None:
    if not addresses:
        return Decision(False, Refusal.NO_ADDRESS, "authz.resolve")
    for ip in addresses:
        why = forbidden_address(ip)
        if why:
            return Decision(False, Refusal.PRIVATE_ADDRESS, "authz.address", f"{ip}: {why}")
    return None


@dataclass
class ScanCounters:
    """Mutable per-scan budget state."""

    started: float
    requests: int = 0
    refused: int = 0
    stopped: Decision | None = None
    by_reason: dict[str, int] = field(default_factory=dict)


def check_budget(config: AuthzConfig, c: ScanCounters, now: float) -> Decision | None:
    if c.stopped is not None:
        return c.stopped
    if c.requests >= config.request_budget:
        return Decision(False, Refusal.BUDGET_EXCEEDED, "authz.budget.requests",
                        f"{config.request_budget} requests")
    if now - c.started > config.scan_wall_clock_s:
        return Decision(False, Refusal.BUDGET_EXCEEDED, "authz.budget.wall_clock",
                        f"{config.scan_wall_clock_s}s")
    return None


def origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"
