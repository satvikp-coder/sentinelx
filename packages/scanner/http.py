"""The ONLY approved HTTP client for scanner code.

``GuardedClient.request`` enforces, for every request AND every redirect hop: the kill switch,
target verification, exact scheme/host/port scope, no userinfo, method policy, body cap, the
request budget and wall-clock, a rate limit, and - for non-lab targets - a one-time DNS
resolution that rejects private/loopback/link-local/metadata addresses and PINS the connection to
the resolved IP (DNS rebinding cannot change it mid-scan). Every attempt, allowed or refused, is
appended to the evidence store. A test fails if scanner code reaches the network any other way.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    EvidenceState,
    SessionKind,
    TargetAuthorization,
)
from sentinelx.evidence.records import RecordStore
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.policy.redaction import redact

from .authz import (
    ALLOW,
    WELL_KNOWN_PATH,
    AuthzConfig,
    Decision,
    KillSwitch,
    RateLimiter,
    Refusal,
    ScanCounters,
    ScanProfile,
    check_addresses,
    check_body,
    check_budget,
    check_method,
    check_scope,
    check_target_state,
    lab_address,
    token_matches,
)

Resolver = Callable[[str], list[str]]
REDIRECTS = {301, 302, 303, 307, 308}
SECRET_KEYS = re.compile(r"token|secret|passw|pwd|api[_-]?key|auth|session|sig|credential|key",
                         re.IGNORECASE)
SCANNER = Actor(id="site_guard_scanner", role=ActorRole.SYSTEM)


def system_resolver(host: str) -> list[str]:
    """Default DNS resolver (the only place the scanner package touches DNS)."""
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(i[4][0] for i in infos))


def redact_url(url: str) -> str:
    """Evidence-safe URL: no userinfo, no fragment, secret-looking query values masked."""
    p = urlsplit(url)
    netloc = p.netloc.rsplit("@", 1)[-1]
    pairs = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        looks = bool(SECRET_KEYS.search(k)) or redact(v).count > 0 or (
            len(v) >= 24 and re.fullmatch(r"[A-Za-z0-9_\-+/=.]+", v) is not None)
        pairs.append((k, "[REDACTED]" if looks else v))
    cleaned = urlunsplit((p.scheme, netloc, p.path, urlencode(pairs, safe="[]"), ""))
    return str(redact(cleaned).value)[:500]


@dataclass
class Outcome:
    allowed: bool
    reason: str
    rule: str
    detail: str = ""
    status: int | None = None
    body: bytes = b""
    truncated: bool = False
    final_url: str | None = None
    hops: int = 0
    event_id: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)  # every Set-Cookie header, in order
    elapsed_ms: float = 0.0

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def start_scan_session(conn: Any, target: TargetAuthorization, config: AuthzConfig,
                       profile: ScanProfile, session_id: str | None = None) -> str:
    """Create the SCAN session and record the operator configuration in the evidence."""
    if RecordStore(conn).get(TargetAuthorization, target.target_id) is None:
        RecordStore(conn).insert(target)
    session, _ = SessionService(conn).create(
        SessionKind.SCAN, "authz-1", SCANNER, target_id=target.target_id, session_id=session_id)
    EvidenceStore(conn).append(session.id, "SCAN_CONFIG", EvidenceState.OBSERVED,
                               "scanner.authz", {
                                   "target_id": target.target_id, "lab": target.lab,
                                   "scope": target.scope.model_dump(mode="json"),
                                   "config": config.model_dump(mode="json"),
                                   "profile": profile.model_dump(mode="json"),
                                   "note": "operator configuration; fixed for the whole scan"})
    return session.id


class GuardedClient:
    def __init__(
        self, target: TargetAuthorization, *, conn: Any, session_id: str,
        config: AuthzConfig | None = None, profile: ScanProfile | None = None,
        resolver: Resolver = system_resolver, transport: httpx.BaseTransport | None = None,
        kill: KillSwitch | None = None, clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC), verify_only: bool = False,
    ) -> None:
        self.target, self.conn, self.session_id = target, conn, session_id
        self.config, self.profile = config or AuthzConfig(), profile or ScanProfile()
        self._resolver, self._kill = resolver, kill or KillSwitch()
        self._clock, self._now, self._verify_only = clock, now, verify_only
        self.counters = ScanCounters(started=clock())
        self._limiter = RateLimiter(self.config.requests_per_second, self.config.burst, clock,
                                    sleep)
        self._pins: dict[str, str] = {}
        self._sems: dict[str, threading.BoundedSemaphore] = defaultdict(
            lambda: threading.BoundedSemaphore(self.config.per_host_concurrency))
        self._http = httpx.Client(transport=transport,
                                  timeout=httpx.Timeout(self.config.request_timeout_s))
        self._store = EvidenceStore(conn)
        self._verify_fetches = 0

    # ------------------------------------------------------------------ evidence
    def _event(self, kind: str, payload: dict[str, Any]) -> str:
        return self._store.append(self.session_id, kind, EvidenceState.OBSERVED,
                                  "scanner.authz", payload).id

    def _refuse(self, d: Decision, method: str, url: str, hop: int) -> Outcome:
        self.counters.refused += 1
        self.counters.by_reason[d.reason] = self.counters.by_reason.get(d.reason, 0) + 1
        if d.fatal and self.counters.stopped is None:
            self.counters.stopped = d
            self._event("SCAN_STOPPED", {"target_id": self.target.target_id, "reason": d.reason,
                                         "rule": d.rule, "detail": d.detail})
        eid = self._event("SCAN_REQUEST_REFUSED", {
            "target_id": self.target.target_id, "method": method.upper(),
            "url": redact_url(url) if isinstance(url, str) else "<non-string>",
            "reason": d.reason, "rule": d.rule, "detail": d.detail[:200], "hop": hop})
        return Outcome(False, d.reason, d.rule, d.detail, event_id=eid, hops=hop)

    # ------------------------------------------------------------------ decision
    def _decide(self, method: str, url: str, body: Any, reason: str | None,
                account: str | None, redirect: bool, hop: int) -> tuple[Decision, str | None]:
        """Returns (decision, pinned ip). Order: kill, state, scope, method, body, budget, address,
        rate."""
        if self._kill.active:
            return Decision(False, Refusal.KILL_SWITCH, "authz.kill_switch",
                            self._kill.reason or "kill switch is on"), None
        if self.counters.stopped is not None:
            return self.counters.stopped, None
        if not self._verify_only:
            state = check_target_state(self.config, self.target, self._now())
            if state is not None:
                return state, None
        scope, host, scheme, port = check_scope(self.target, url, redirect=redirect)
        if scope is not None:
            return scope, None
        assert host is not None
        m = check_method(self.config, self.target, self.profile, method, reason, account)
        if m is not None and not self._verify_only:
            return m, None
        if self._verify_only and method.upper() != "GET":
            return Decision(False, Refusal.METHOD_NOT_ALLOWED, "authz.verify_only", method), None
        b = check_body(self.config, body)
        if b is not None:
            return b, None
        bud = check_budget(self.config, self.counters, self._clock())
        if bud is not None:
            return bud, None
        ip = self._pin(host)
        if isinstance(ip, Decision):
            return ip, None
        if not self._limiter.acquire(self.config.max_rate_wait_s):
            return Decision(False, Refusal.RATE_LIMITED, "authz.rate", "rate limit"), None
        return ALLOW, ip

    def _pin(self, host: str) -> str | Decision:
        if host in self._pins:
            return self._pins[host]  # resolved once; rebinding cannot change it
        if self.target.lab:
            ip = lab_address(host)
        else:
            try:
                addresses = self._resolver(host)
            except OSError as exc:
                return Decision(False, Refusal.NO_ADDRESS, "authz.resolve", type(exc).__name__)
            bad = check_addresses(addresses)
            if bad is not None:
                return bad
            ip = addresses[0]
        self._pins[host] = ip
        return ip

    # ------------------------------------------------------------------ request
    def request(self, method: str, url: str, *, body: bytes | str | None = None,
                headers: dict[str, str] | None = None, reason: str | None = None,
                account: str | None = None, follow_redirects: bool = True) -> Outcome:
        method = method.upper()
        current, hop, redirect = url, 0, False
        while True:
            decision, ip = self._decide(method, current, body, reason, account, redirect, hop)
            if not decision.allowed:
                return self._refuse(decision, method, current, hop)
            assert ip is not None
            outcome = self._send(method, current, ip, body, headers, reason, account, hop)
            location = outcome.headers.get("location")
            if (follow_redirects and outcome.status in REDIRECTS and location):
                hop += 1
                if hop > self.config.max_redirects:
                    return self._refuse(Decision(False, Refusal.OUT_OF_SCOPE_REDIRECT,
                                                 "authz.redirects", "too many redirects"),
                                        method, current, hop)
                current = urljoin(current, location)
                if outcome.status == 303 or (outcome.status in {301, 302} and method == "POST"):
                    method, body = "GET", None
                redirect = True
                continue
            outcome.hops = hop
            return outcome

    def _send(self, method: str, url: str, ip: str, body: Any, headers: dict[str, str] | None,
              reason: str | None, account: str | None, hop: int) -> Outcome:
        p = urlsplit(url)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else 80)
        ip_part = f"[{ip}]" if ":" in ip else ip
        connect_url = f"{p.scheme}://{ip_part}:{port}{p.path or '/'}" + (
            f"?{p.query}" if p.query else "")
        send_headers = {k: v for k, v in (headers or {}).items() if k.lower() != "host"}
        default = 443 if p.scheme == "https" else 80
        send_headers["Host"] = host if port == default else f"{host}:{port}"
        data = body.encode("utf-8") if isinstance(body, str) else body
        request = self._http.build_request(method, connect_url, headers=send_headers, content=data,
                                           extensions={"sni_hostname": host})
        self.counters.requests += 1
        started = self._clock()
        chunks: list[bytes] = []
        size, truncated = 0, False
        sem = self._sems[host]
        with sem:
            try:
                response = self._http.send(request, stream=True, follow_redirects=False)
            except httpx.HTTPError as exc:
                eid = self._event("SCAN_REQUEST", {
                    "target_id": self.target.target_id, "method": method, "url": redact_url(url),
                    "status": None, "size": 0, "error": type(exc).__name__,
                    "duration_ms": round((self._clock() - started) * 1000, 1),
                    "rule": ALLOW.rule, "hop": hop, "pinned_ip": ip})
                return Outcome(True, "TRANSPORT_ERROR", ALLOW.rule, type(exc).__name__,
                               event_id=eid, final_url=url)
            try:
                for chunk in response.iter_bytes():
                    room = self.config.max_response_bytes - size
                    if len(chunk) > room:
                        chunks.append(chunk[:room])
                        size, truncated = size + room, True
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if self._clock() - started > self.config.request_timeout_s:
                        truncated = True
                        break
            finally:
                response.close()
        duration = (self._clock() - started) * 1000
        payload: dict[str, Any] = {
            "target_id": self.target.target_id, "method": method, "url": redact_url(url),
            "status": response.status_code, "size": size, "truncated": truncated,
            "duration_ms": round(duration, 1), "rule": ALLOW.rule, "hop": hop, "pinned_ip": ip,
            "request_header_names": sorted(send_headers), "body_bytes": len(data or b"")}
        if method not in {"GET", "HEAD", "OPTIONS"}:
            payload["state_changing"] = {"reason": reason, "account": account}
        eid = self._event("SCAN_REQUEST", payload)
        return Outcome(True, "ALLOWED", ALLOW.rule, status=response.status_code,
                       body=b"".join(chunks), truncated=truncated, final_url=url, event_id=eid,
                       headers={k.lower(): v for k, v in response.headers.items()},
                       set_cookies=response.headers.get_list("set-cookie"), elapsed_ms=duration)

    # ------------------------------------------------------------------ ownership proof
    def fetch_verification_file(self, expected_hash: str) -> tuple[bool, Outcome]:
        """GET the well-known file ONCE on the target's exact origin and compare in constant
        time. Only a client created with verify_only=True may do this."""
        if not self._verify_only or self._verify_fetches >= 1:
            raise RuntimeError("verification fetch is single-use and verify_only")
        self._verify_fetches += 1
        out = self.request("GET", self.target.base_url.rstrip("/") + WELL_KNOWN_PATH)
        ok = bool(out.allowed and out.status == 200 and token_matches(expected_hash, out.text))
        self._event("SCAN_OWNERSHIP_CHECK", {"target_id": self.target.target_id, "ok": ok,
                                             "status": out.status, "reason": out.reason})
        return ok, out

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> GuardedClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
