"""The Site Guard authorization gate. Real sockets only on 127.0.0.1 (local stub servers). The
"non-lab owner's site" is a stub reached through a transport that maps a public-looking pinned IP
to the stub, so the non-lab path (DNS resolution, pinning, private-address refusal) really runs."""

from __future__ import annotations

import ast
import json
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from sentinelx.common_schemas import TargetStatus
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.store import EvidenceStore
from sentinelx.scanner.authz import (
    ACK_PHRASE,
    WELL_KNOWN_PATH,
    AuthzConfig,
    KillSwitch,
    ScanProfile,
    TargetRegistrationError,
    forbidden_address,
    mark_verified,
    new_verification_token,
    register_lab_target,
    register_non_lab_target,
    token_matches,
    with_token_hash,
)
from sentinelx.scanner.http import GuardedClient, redact_url, start_scan_session

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_IP = "93.184.216.34"
SECRET = "synth_tok_0123456789abcdef0123"


class Stub:
    """A tiny HTTP server on 127.0.0.1 with scripted routes: path -> (status, headers, body)."""

    def __init__(self, routes: dict[str, tuple[int, dict[str, str], bytes]]) -> None:
        self.routes, self.seen = routes, []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def _serve(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                stub.seen.append((self.command, self.path, dict(self.headers)))
                path = self.path.split("?")[0]
                status, headers, body = stub.routes.get(path, (404, {}, b"not found"))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = do_POST = do_HEAD = do_OPTIONS = _serve

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Stub:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


class Reroute(httpx.BaseTransport):
    """Maps (pinned ip, port) -> a local stub; records which IP the client actually connected to."""

    def __init__(self, mapping: dict[tuple[str, int], int]) -> None:
        self.mapping, self.connected, self.inner = mapping, [], httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        key = (request.url.host, request.url.port or 80)
        self.connected.append(key[0])
        real = self.mapping[key]
        forwarded = httpx.Request(request.method, f"http://127.0.0.1:{real}{request.url.raw_path.decode()}",
                                  headers=request.headers, content=request.content)
        return self.inner.handle_request(forwarded)


@pytest.fixture()
def conn(tmp_path: Path):
    c = connect(tmp_path / "a.db")
    migrate(c)
    yield c
    c.close()


def lab_client(conn: Any, port: int, **kw: Any) -> tuple[GuardedClient, str]:
    target = register_lab_target("lab1", ["127.0.0.1"], [port])
    config, profile = kw.pop("config", AuthzConfig()), kw.pop("profile", ScanProfile())
    sid = start_scan_session(conn, target, config, profile)
    return GuardedClient(target, conn=conn, session_id=sid, config=config, profile=profile,
                         **kw), sid


def events(conn: Any, sid: str, kind: str | None = None) -> list:
    return [e for e in EvidenceStore(conn).list_session(sid) if kind is None or e.kind == kind]


# ------------------------------------------------------------------ registration
def test_lab_flag_is_only_for_loopback_and_lab_test_hosts() -> None:
    ok = register_lab_target("t", ["127.0.0.1", "localhost", "shop.lab.test"], [18080])
    assert ok.lab and ok.status is TargetStatus.VERIFIED and ok.ownership_method == "lab"
    for hosts in (["example.com"], ["127.0.0.1", "10.0.0.5"], ["evil.lab.test.example.com"],
                  ["lab.test"], [".lab.test"], ["192.168.1.10"]):
        with pytest.raises(TargetRegistrationError) as err:
            register_lab_target("t", hosts, [80])
        assert err.value.code == "LAB_FLAG_NOT_ALLOWED", hosts


def test_non_lab_targets_are_disabled_by_default_and_start_unverified() -> None:
    with pytest.raises(TargetRegistrationError) as err:
        register_non_lab_target(AuthzConfig(), "t", "owner.example.net", 443)
    assert err.value.code == "NON_LAB_DISABLED"
    cfg = AuthzConfig(allow_non_lab_targets=True)
    t = register_non_lab_target(cfg, "t", "owner.example.net", 443)
    assert t.status is TargetStatus.PENDING and not t.lab and t.verified_at is None
    for host in ("169.254.169.254", "93.184.216.34", "[::1]", "metadata.google.internal"):
        with pytest.raises(TargetRegistrationError):
            register_non_lab_target(cfg, "t", host, 80)
    with pytest.raises(TargetRegistrationError) as err:
        register_non_lab_target(cfg, "t", "shop.lab.test", 80)
    assert err.value.code == "LAB_HOST_AS_NON_LAB"


@pytest.mark.parametrize(("ip", "forbidden"), [
    ("127.0.0.1", True), ("10.1.2.3", True), ("172.16.0.1", True), ("192.168.0.1", True),
    ("169.254.169.254", True), ("100.64.0.1", True), ("224.0.0.1", True), ("0.0.0.0", True),
    ("240.0.0.1", True), ("::1", True), ("fe80::1", True), ("fd00:ec2::254", True),
    ("::ffff:127.0.0.1", True), ("::ffff:10.0.0.1", True), ("ff02::1", True), ("fc00::1", True),
    ("93.184.216.34", False), ("8.8.8.8", False), ("2606:4700:4700::1111", False),
])
def test_forbidden_address_classes(ip: str, forbidden: bool) -> None:
    assert (forbidden_address(ip) is not None) is forbidden


# ------------------------------------------------------------------ lab requests
def test_allowed_get_on_a_verified_lab_target_is_recorded(conn: Any) -> None:
    with Stub({"/ok": (200, {}, b"hello")}) as stub:
        client, sid = lab_client(conn, stub.port)
        out = client.request("GET", f"http://127.0.0.1:{stub.port}/ok?q=widgets")
        assert out.allowed and out.status == 200 and out.text == "hello"
        head = client.request("HEAD", f"http://127.0.0.1:{stub.port}/ok")
        opt = client.request("OPTIONS", f"http://127.0.0.1:{stub.port}/ok")
        assert head.allowed and opt.allowed
    evs = events(conn, sid, "SCAN_REQUEST")
    assert len(evs) == 3 and evs[0].payload["url"].endswith("/ok?q=widgets")
    assert evs[0].payload["rule"] == "authz.allow" and evs[0].payload["target_id"] == "lab1"


def test_refuses_an_unverified_target_and_scope_violations(conn: Any) -> None:
    with Stub({"/": (200, {}, b"x")}) as stub:
        client, _ = lab_client(conn, stub.port)
        base = f"127.0.0.1:{stub.port}"
        cases = {
            "OUT_OF_SCOPE_HOST": [f"http://localhost:{stub.port}/", "http://example.com/",
                                  f"http://127.0.0.2:{stub.port}/", "http://[::1]/"],
            "USERINFO_IN_URL": [f"http://user:pw@{base}/", f"http://{base}@evil.example/",
                                f"http://evil.example@{base}/", f"http://127.0.0.1@{base}/"],
        }
        for reason, urls in cases.items():
            for url in urls:
                out = client.request("GET", url)
                assert not out.allowed and out.reason == reason, (url, out.reason)
        wrong_port = client.request("GET", f"http://127.0.0.1:{stub.port + 1}/")
        assert wrong_port.reason == "OUT_OF_SCOPE_HOST"
        wrong_scheme = client.request("GET", f"https://127.0.0.1:{stub.port}/")
        assert wrong_scheme.reason == "OUT_OF_SCOPE_HOST"
        for bad in ("ftp://127.0.0.1/", "file:///etc/passwd", "gopher://127.0.0.1/", "//x/",
                    "javascript:alert(1)", ""):
            assert not client.request("GET", bad).allowed
        pending = register_non_lab_target(AuthzConfig(allow_non_lab_targets=True), "n",
                                          "owner.example.net", 80, "http")
        sid = start_scan_session(conn, pending, AuthzConfig(), ScanProfile())
        gc = GuardedClient(pending, conn=conn, session_id=sid)
        out = gc.request("GET", "http://owner.example.net/")
        assert not out.allowed and out.reason == "UNVERIFIED_TARGET"


def test_a_redirect_off_scope_is_refused_even_to_a_lab_looking_host(conn: Any) -> None:
    with Stub({"/other": (200, {}, b"inside")}) as other, Stub({}) as main:
        main.routes["/r1"] = (302, {"Location": f"http://127.0.0.1:{other.port}/other"}, b"")
        main.routes["/r2"] = (302, {"Location": "http://example.com/x"}, b"")
        main.routes["/r3"] = (302, {"Location": f"http://user@127.0.0.1:{main.port}/ok"}, b"")
        main.routes["/ok"] = (200, {}, b"fine")
        main.routes["/r4"] = (302, {"Location": "/ok"}, b"")
        client, sid = lab_client(conn, main.port)
        for path in ("/r1", "/r2", "/r3"):
            out = client.request("GET", f"http://127.0.0.1:{main.port}{path}")
            assert not out.allowed and out.reason in {"OUT_OF_SCOPE_REDIRECT", "USERINFO_IN_URL"}
        assert client.request("GET", f"http://127.0.0.1:{main.port}/r1").reason == (
            "OUT_OF_SCOPE_REDIRECT")
        assert other.seen == [], "the off-scope hop was never requested"
        inside = client.request("GET", f"http://127.0.0.1:{main.port}/r4")
        assert inside.allowed and inside.text == "fine" and inside.hops == 1
    refused = events(conn, sid, "SCAN_REQUEST_REFUSED")
    assert any(e.payload["hop"] == 1 for e in refused)


def test_state_changing_methods_need_a_lab_a_declaration_a_reason_and_a_test_account(
        conn: Any) -> None:
    with Stub({"/api": (200, {}, b"done")}) as stub:
        url = f"http://127.0.0.1:{stub.port}/api"
        default, _ = lab_client(conn, stub.port)
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            out = default.request(method, url, reason="r", account="alice")
            assert out.reason in {"STATE_CHANGE_UNDECLARED", "METHOD_NOT_ALLOWED"}, method
        assert default.request("TRACE", url).reason == "METHOD_NOT_ALLOWED"
        assert stub.seen == []
        profile = ScanProfile(name="lab-write", state_changing_methods=("POST",),
                              synthetic_accounts=("alice",))
        declared, sid = lab_client(conn, stub.port, profile=profile)
        assert declared.request("POST", url, body=b"x=1", reason="check form handling",
                                account="alice").allowed
        assert declared.request("POST", url).reason == "METHOD_NOT_ALLOWED", "no reason/account"
        assert declared.request("POST", url, reason="r", account="mallory").reason == (
            "METHOD_NOT_ALLOWED")
        assert declared.request("DELETE", url, reason="r", account="alice").reason == (
            "STATE_CHANGE_UNDECLARED")
        off, _ = lab_client(conn, stub.port, profile=profile,
                            config=AuthzConfig(allow_state_changing_in_labs=False))
        assert off.request("POST", url, reason="r", account="alice").reason == (
            "METHOD_NOT_ALLOWED")
    logged = [e for e in events(conn, sid, "SCAN_REQUEST") if e.payload["method"] == "POST"]
    assert logged and logged[0].payload["state_changing"] == {
        "reason": "check form handling", "account": "alice"}


def test_body_and_response_size_caps(conn: Any) -> None:
    with Stub({"/big": (200, {}, b"A" * 5000)}) as stub:
        client, _ = lab_client(conn, stub.port, config=AuthzConfig(
            max_body_bytes=10, max_response_bytes=1000), profile=ScanProfile(
            state_changing_methods=("POST",), synthetic_accounts=("a",)))
        too_big = client.request("POST", f"http://127.0.0.1:{stub.port}/big", body=b"x" * 11,
                                 reason="r", account="a")
        assert too_big.reason == "BODY_TOO_LARGE"
        out = client.request("GET", f"http://127.0.0.1:{stub.port}/big")
        assert out.allowed and out.truncated and len(out.body) == 1000


# ------------------------------------------------------------------ budgets, rate, kill switch
class FakeClock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


def test_request_budget_stops_the_scan_with_an_explicit_reason(conn: Any) -> None:
    with Stub({"/": (200, {}, b"x")}) as stub:
        client, sid = lab_client(conn, stub.port, config=AuthzConfig(request_budget=3,
                                                                     requests_per_second=1000,
                                                                     burst=1000))
        url = f"http://127.0.0.1:{stub.port}/"
        results = [client.request("GET", url) for _ in range(6)]
        assert [r.allowed for r in results] == [True, True, True, False, False, False]
        assert {r.reason for r in results[3:]} == {"BUDGET_EXCEEDED"}
        assert len(stub.seen) == 3, "nothing is sent after the budget"
    stopped = events(conn, sid, "SCAN_STOPPED")
    assert len(stopped) == 1 and stopped[0].payload["reason"] == "BUDGET_EXCEEDED"


def test_wall_clock_budget(conn: Any) -> None:
    clock = FakeClock()
    with Stub({"/": (200, {}, b"x")}) as stub:
        client, _ = lab_client(conn, stub.port, clock=clock, sleep=clock.sleep,
                               config=AuthzConfig(scan_wall_clock_s=30, requests_per_second=1000,
                                                  burst=1000))
        url = f"http://127.0.0.1:{stub.port}/"
        assert client.request("GET", url).allowed
        clock.t += 31
        out = client.request("GET", url)
        assert out.reason == "BUDGET_EXCEEDED" and out.rule == "authz.budget.wall_clock"


def test_rate_limit_is_enforced_and_reported(conn: Any) -> None:
    clock = FakeClock()
    with Stub({"/": (200, {}, b"x")}) as stub:
        client, sid = lab_client(conn, stub.port, clock=clock, sleep=clock.sleep,
                                 config=AuthzConfig(requests_per_second=1.0, burst=2,
                                                    max_rate_wait_s=0.0))
        url = f"http://127.0.0.1:{stub.port}/"
        assert client.request("GET", url).allowed and client.request("GET", url).allowed
        limited = client.request("GET", url)
        assert not limited.allowed and limited.reason == "RATE_LIMITED"
        clock.t += 1.1  # a token refills; the scan was not stopped by a rate limit
        assert client.request("GET", url).allowed
        waiting, _ = lab_client(conn, stub.port, clock=clock, sleep=clock.sleep,
                                config=AuthzConfig(requests_per_second=2.0, burst=1,
                                                   max_rate_wait_s=5.0))
        before = clock.t
        waiting.request("GET", url)
        waiting.request("GET", url)
        assert clock.t - before >= 0.4, "the limiter waits instead of bursting"
    assert events(conn, sid, "SCAN_REQUEST_REFUSED")[0].payload["reason"] == "RATE_LIMITED"


def test_kill_switch_flag_and_file_stop_a_running_scan_within_one_request(
        conn: Any, tmp_path: Path) -> None:
    with Stub({"/": (200, {}, b"x")}) as stub:
        kill = KillSwitch(tmp_path / "STOP")
        client, sid = lab_client(conn, stub.port, kill=kill,
                                 config=AuthzConfig(requests_per_second=1000, burst=1000))
        url = f"http://127.0.0.1:{stub.port}/"
        sent = 0
        for i in range(50):  # a fake scan loop
            if i == 3:
                kill.trip("operator pressed stop")
            out = client.request("GET", url)
            if not out.allowed:
                assert out.reason == "KILL_SWITCH"
                break
            sent += 1
        assert sent == 3 and len(stub.seen) == 3
        kill.reset()
        assert client.request("GET", url).reason == "KILL_SWITCH", "a stopped scan stays stopped"
        client2, _ = lab_client(conn, stub.port, kill=kill)
        (tmp_path / "STOP").write_text("stop", encoding="utf-8")
        assert client2.request("GET", url).reason == "KILL_SWITCH"
    assert events(conn, sid, "SCAN_STOPPED")[0].payload["reason"] == "KILL_SWITCH"


# ------------------------------------------------------------------ non-lab path (stub owner site)
def non_lab(stub_ports: dict[int, int], resolver: Callable[[str], list[str]], *,
            host: str = "owner.example.net", now: datetime | None = None, **cfg: Any):
    config = AuthzConfig(allow_non_lab_targets=True, **cfg)
    target = register_non_lab_target(config, "owner", host, 80, "http")
    transport = Reroute({(PUBLIC_IP, 80): next(iter(stub_ports.values()))})
    return config, target, transport


def test_ownership_verification_against_the_local_stub(conn: Any) -> None:
    token, token_hash = new_verification_token()
    assert token not in token_hash and len(token_hash) == 64
    with Stub({WELL_KNOWN_PATH: (200, {}, (token + "\n").encode())}) as stub:
        config, target, transport = non_lab({80: stub.port}, lambda h: [PUBLIC_IP])
        target = with_token_hash(target, token_hash)
        sid = start_scan_session(conn, target, config, ScanProfile())
        client = GuardedClient(target, conn=conn, session_id=sid, config=config,
                               resolver=lambda h: [PUBLIC_IP], transport=transport,
                               verify_only=True)
        ok, out = client.fetch_verification_file(token_hash)
        assert ok and out.status == 200 and transport.connected == [PUBLIC_IP]
        with pytest.raises(RuntimeError):
            client.fetch_verification_file(token_hash)  # single use
        with pytest.raises(TargetRegistrationError):
            mark_verified(config, target, "yes I own it")
        verified = mark_verified(config, target, ACK_PHRASE)
        assert verified.status is TargetStatus.VERIFIED and verified.acknowledgement == ACK_PHRASE
        assert verified.verification_expires_at is not None
        assert verified.verification_token_hash == token_hash != token
        sid2 = start_scan_session(conn, verified.model_copy(update={"target_id": "owner2"}),
                                  config, ScanProfile())
        scan = GuardedClient(verified.model_copy(update={"target_id": "owner2"}), conn=conn,
                             session_id=sid2, config=config, resolver=lambda h: [PUBLIC_IP],
                             transport=Reroute({(PUBLIC_IP, 80): stub.port}))
        got = scan.request("GET", "http://owner.example.net/")
        assert got.allowed is True or got.reason == "ALLOWED"
        check = events(conn, sid, "SCAN_OWNERSHIP_CHECK")[0]
        assert check.payload["ok"] is True
    assert EvidenceStore(conn).verify_chain(sid).ok


def test_wrong_token_and_wrong_origin_do_not_verify(conn: Any) -> None:
    _, token_hash = new_verification_token()
    assert not token_matches(token_hash, "not-the-token") and not token_matches("", "")
    with Stub({WELL_KNOWN_PATH: (200, {}, b"some-other-token")}) as stub:
        config, target, transport = non_lab({80: stub.port}, lambda h: [PUBLIC_IP])
        target = with_token_hash(target, token_hash)
        sid = start_scan_session(conn, target, config, ScanProfile())
        client = GuardedClient(target, conn=conn, session_id=sid, config=config,
                               resolver=lambda h: [PUBLIC_IP], transport=transport,
                               verify_only=True)
        ok, _ = client.fetch_verification_file(token_hash)
        assert ok is False
    token, token_hash = new_verification_token()
    with Stub({WELL_KNOWN_PATH: (200, {}, token.encode())}) as elsewhere, Stub({}) as owner:
        owner.routes[WELL_KNOWN_PATH] = (302, {"Location": "http://owner.example.net:8081"
                                               + WELL_KNOWN_PATH}, b"")
        config, target, _ = non_lab({80: owner.port}, lambda h: [PUBLIC_IP])
        target = with_token_hash(target, token_hash)
        transport = Reroute({(PUBLIC_IP, 80): owner.port, (PUBLIC_IP, 8081): elsewhere.port})
        sid = start_scan_session(conn, target.model_copy(update={"target_id": "o2"}), config,
                                 ScanProfile())
        client = GuardedClient(target.model_copy(update={"target_id": "o2"}), conn=conn,
                               session_id=sid, config=config, resolver=lambda h: [PUBLIC_IP],
                               transport=transport, verify_only=True)
        ok, out = client.fetch_verification_file(token_hash)
        assert ok is False and out.reason == "OUT_OF_SCOPE_REDIRECT"
        assert elsewhere.seen == [], "the token on another origin was never fetched"


def test_an_expired_verification_is_refused(conn: Any) -> None:
    _, token_hash = new_verification_token()
    config, target, transport = non_lab({80: 1}, lambda h: [PUBLIC_IP])
    verified_at = datetime.now(UTC) - timedelta(hours=25)
    target = mark_verified(config, with_token_hash(target, token_hash), ACK_PHRASE, verified_at)
    sid = start_scan_session(conn, target, config, ScanProfile())
    client = GuardedClient(target, conn=conn, session_id=sid, config=config,
                           resolver=lambda h: [PUBLIC_IP], transport=transport)
    out = client.request("GET", "http://owner.example.net/")
    assert out.reason == "EXPIRED_VERIFICATION"
    assert events(conn, sid, "SCAN_STOPPED"), "an expired verification stops the scan"


def test_a_non_lab_target_is_refused_when_the_operator_switch_is_off(conn: Any) -> None:
    on = AuthzConfig(allow_non_lab_targets=True)
    target = mark_verified(on, with_token_hash(
        register_non_lab_target(on, "n", "owner.example.net", 80, "http"), "h" * 64), ACK_PHRASE)
    sid = start_scan_session(conn, target, AuthzConfig(), ScanProfile())
    client = GuardedClient(target, conn=conn, session_id=sid, config=AuthzConfig(),
                           resolver=lambda h: [PUBLIC_IP])
    assert client.request("GET", "http://owner.example.net/").reason == "NON_LAB_DISABLED"


def verified_non_lab(conn: Any, resolver: Callable[[str], list[str]], stub_port: int,
                     hosts: tuple[str, ...] = ("owner.example.net",)):
    config = AuthzConfig(allow_non_lab_targets=True, requests_per_second=1000, burst=1000)
    t = register_non_lab_target(config, "owner", hosts[0], 80, "http")
    t = t.model_copy(update={"scope": t.scope.model_copy(update={"hosts": list(hosts)})})
    t = mark_verified(config, with_token_hash(t, "h" * 64), ACK_PHRASE)
    sid = start_scan_session(conn, t, config, ScanProfile())
    transport = Reroute({(PUBLIC_IP, 80): stub_port})
    return GuardedClient(t, conn=conn, session_id=sid, config=config, resolver=resolver,
                         transport=transport), transport, sid


def test_non_lab_private_loopback_and_metadata_resolutions_are_refused(conn: Any) -> None:
    for bad in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1", "::1", "fe80::1",
                "::ffff:10.0.0.5", "fd00:ec2::254", "100.64.0.1"):
        client, transport, sid = verified_non_lab(conn, lambda h, b=bad: [b], 1)
        out = client.request("GET", "http://owner.example.net/")
        assert not out.allowed and out.reason == "PRIVATE_ADDRESS", bad
        assert transport.connected == [], "no connection was attempted"
        assert sid
    mixed, transport, _ = verified_non_lab(conn, lambda h: [PUBLIC_IP, "10.0.0.5"], 1)
    assert mixed.request("GET", "http://owner.example.net/").reason == "PRIVATE_ADDRESS"
    other = mixed.request("GET", "http://169.254.169.254/latest/meta-data/")
    assert other.reason == "OUT_OF_SCOPE_HOST"


def test_a_redirect_to_a_private_address_is_refused_for_non_lab(conn: Any) -> None:
    with Stub({}) as stub:
        stub.routes["/go"] = (302, {"Location": "http://10.0.0.5/admin"}, b"")
        stub.routes["/meta"] = (302, {"Location": "http://169.254.169.254/latest/"}, b"")
        stub.routes["/sibling"] = (302, {"Location": "http://internal.example.net/"}, b"")
        resolver = {"owner.example.net": [PUBLIC_IP], "internal.example.net": ["10.9.9.9"]}
        client, transport, _ = verified_non_lab(conn, lambda h: resolver[h], stub.port,
                                                ("owner.example.net", "internal.example.net"))
        for path in ("/go", "/meta"):
            out = client.request("GET", f"http://owner.example.net{path}")
            assert out.reason == "OUT_OF_SCOPE_REDIRECT", path
        out = client.request("GET", "http://owner.example.net/sibling")
        assert out.reason == "PRIVATE_ADDRESS", "an in-scope name that resolves privately"
        assert set(transport.connected) == {PUBLIC_IP}


def test_dns_rebinding_cannot_change_the_pinned_address(conn: Any) -> None:
    answers = iter([[PUBLIC_IP], ["127.0.0.1"], ["10.0.0.5"], ["169.254.169.254"]])
    calls: list[str] = []

    def rebinding(host: str) -> list[str]:
        calls.append(host)
        return next(answers)

    with Stub({"/": (200, {}, b"hi")}) as stub:
        client, transport, _ = verified_non_lab(conn, rebinding, stub.port)
        for _ in range(4):
            out = client.request("GET", "http://owner.example.net/")
            assert out.allowed and out.status == 200
        assert calls == ["owner.example.net"], "resolved exactly once per scan"
        assert transport.connected == [PUBLIC_IP] * 4, "every request used the pinned IP"
        assert stub.seen[0][2]["Host"] == "owner.example.net", "the Host header is the real name"


# ------------------------------------------------------------------ evidence and secrets
def test_every_attempt_is_evidence_and_no_secret_is_stored(conn: Any) -> None:
    with Stub({"/p": (200, {}, b"x")}) as stub:
        client, sid = lab_client(conn, stub.port, config=AuthzConfig(
            request_budget=100, requests_per_second=1000, burst=1000))
        base = f"http://127.0.0.1:{stub.port}"
        attempts = [
            client.request("GET", f"{base}/p?token={SECRET}&apikey=AKIA{'A1B2C3D4E5F6G7H8'}&q=ok",
                           headers={"Authorization": f"Bearer {SECRET}",
                                    "Cookie": f"session={SECRET}"}),
            client.request("GET", f"{base}/p?note=sk-{'Zz9Yy8Xx' * 4}"),
            client.request("GET", "http://example.com/"),
            client.request("POST", f"{base}/p"),
            client.request("GET", f"http://u:{SECRET}@127.0.0.1:{stub.port}/"),
        ]
    assert [a.allowed for a in attempts] == [True, True, False, False, False]
    allowed = events(conn, sid, "SCAN_REQUEST")
    refused = events(conn, sid, "SCAN_REQUEST_REFUSED")
    assert len(allowed) + len(refused) == len(attempts) == 5
    blob = json.dumps([e.payload for e in EvidenceStore(conn).list_session(sid)])
    assert SECRET not in blob and "AKIAA1B2" not in blob and "sk-Zz9Yy8Xx" not in blob
    assert "ok" in allowed[0].payload["url"] and "[REDACTED]" in allowed[0].payload["url"]
    assert "authorization" in [h.lower() for h in allowed[0].payload["request_header_names"]]
    assert all(e.payload["target_id"] == "lab1" for e in [*allowed, *refused])
    assert EvidenceStore(conn).verify_chain(sid).ok
    assert redact_url("http://a:b@h/x?z=1#frag") == "http://h/x?z=1"


def test_the_config_is_recorded_and_cannot_be_changed_by_a_request(conn: Any) -> None:
    with Stub({"/": (200, {}, b"x")}) as stub:
        client, sid = lab_client(conn, stub.port)
        with pytest.raises(ValidationError):
            client.config.allow_state_changing_in_labs = False  # type: ignore[misc]
        with pytest.raises(ValidationError):
            client.profile.state_changing_methods = ("POST",)  # type: ignore[misc]
        cfg = events(conn, sid, "SCAN_CONFIG")[0]
        assert cfg.payload["profile"]["state_changing_methods"] == []
        assert cfg.payload["config"]["allow_non_lab_targets"] is False


# ------------------------------------------------------------------ static: one way out
def test_scanner_code_reaches_the_network_only_through_guarded_client() -> None:
    forbidden = re.compile(r"^(httpx|requests|urllib3|aiohttp|socket|http\.client|ftplib|smtplib"
                           r"|telnetlib|urllib\.request|websockets|websocket|ssl)(\.|$)")
    offenders: list[str] = []
    for path in sorted((ROOT / "packages" / "scanner").glob("*.py")):
        if path.name == "http.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module or ""]
                if node.module == "urllib":
                    mods += [f"urllib.{a.name}" for a in node.names]
            offenders += [f"{path.name}: {m}" for m in mods if forbidden.match(m)]
    assert offenders == [], offenders


def test_authz_module_is_pure_logic() -> None:
    text = (ROOT / "packages" / "scanner" / "authz.py").read_text(encoding="utf-8")
    assert "import httpx" not in text and "import socket" not in text
    assert "resolver" not in text.lower() or "getaddrinfo" not in text

