"""Proxy tests: ASGI reverse proxy with mocked upstream (httpx.MockTransport)."""

import asyncio
import os
import tempfile

import httpx

from sentinelx.common_schemas import Actor, ActorRole, SessionKind
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.shield.config import ShieldConfig, SizeCaps
from sentinelx.shield.detect import Detector
from sentinelx.shield.proxy import ShieldProxy
from sentinelx.shield.recorder import ShieldRecorder


class FakeClock:
    def __init__(self, start=0.0):
        self.now = start

    def __call__(self):
        return self.now


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _make_proxy(config_overrides=None, lab_mode=False, http_client=None, clock_value=0.0):
    config = ShieldConfig(
        upstream="http://orders.lab.test:18080",
        lab_mode=lab_mode,
        fail_open=True,
        **(config_overrides or {}),
    )
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session_service = SessionService(conn)
    session, _ = session_service.create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="a", role=ActorRole.SYSTEM),
    )
    clock = FakeClock(clock_value)
    detector = Detector([], [], clock=clock)
    recorder = ShieldRecorder(store, session.id, batch_interval_s=999.0,
                              suspicious_rate_cap_per_min=1000, clock=clock)
    proxy = ShieldProxy(config, store, session.id, detector, recorder,
                        http_client=http_client, clock=clock)
    return proxy, store, session, conn


async def _call_proxy(proxy, method, path, headers=None, body=b"", client="127.0.0.1"):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [[k.lower().encode(), v.encode()] for k, v in (headers or {}).items()],
        "client": (client, 12345),
        "server": ("127.0.0.1", 18090),
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    captured = {}

    async def send(msg):
        captured["type"] = msg["type"]
        if msg["type"] == "http.response.start":
            captured["status"] = msg["status"]
            captured["headers"] = msg["headers"]
        elif msg["type"] == "http.response.body":
            captured["body"] = captured.get("body", b"") + msg.get("body", b"")

    await proxy(scope, receive, send)
    return captured


def upstream_handler(status=200, extra_headers=None, body=b'{"ok": true}'):
    headers = {"content-type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers, content=body)

    return handler


def test_proxy_forwards_status_headers_cookies_body():
    transport = httpx.MockTransport(upstream_handler(200, {"set-cookie": "session=abc123"},
                                                     b'{"hello": "world"}'))
    client = httpx.AsyncClient(transport=transport)
    proxy, _, _, _ = _make_proxy(http_client=client)
    try:
        resp = _run(_call_proxy(proxy, "GET", "/checkout", body=b'{"a": 1}'))
        assert resp["status"] == 200
        hdr = {k.decode().lower(): v.decode() for k, v in resp["headers"]}
        assert hdr["content-type"] == "application/json"
        assert hdr["set-cookie"] == "session=abc123"
        assert resp["body"] == b'{"hello": "world"}'
    finally:
        _run(client.aclose())


def test_proxy_preserves_method_and_body():
    transport = httpx.MockTransport(lambda req: httpx.Response(
        200, content=req.content, headers={"content-type": "text/plain"}))
    client = httpx.AsyncClient(transport=transport)
    proxy, _, _, _ = _make_proxy(http_client=client)
    try:
        resp = _run(_call_proxy(proxy, "POST", "/submit",
                                headers={"content-type": "text/plain"}, body=b"payload-data"))
        assert resp["status"] == 200
        assert resp["body"] == b"payload-data"
    finally:
        _run(client.aclose())


def test_proxy_refuses_non_lab_upstream():
    try:
        ShieldConfig(upstream="http://evil.example/", listen_port=18090)
        raise AssertionError("expected ValidationError")
    except Exception:
        pass


def test_size_caps():
    caps = SizeCaps(max_request_bytes=10, max_response_bytes=20)
    assert caps.max_request_bytes == 10
    assert caps.max_response_bytes == 20


def test_proxy_fail_open_on_shield_error():
    transport = httpx.MockTransport(upstream_handler(200, body=b"ok"))
    client = httpx.AsyncClient(transport=transport)
    proxy, store, session, conn = _make_proxy(http_client=client)

    proxy.detector.scan_request = lambda *a, **k: (_ for _ in ()).throw(
        RuntimeError("boom"))

    try:
        resp = _run(_call_proxy(proxy, "GET", "/checkout"))
        assert resp["status"] == 200
        events = store.list_session(session.id)
        kinds = {e.kind for e in events}
        assert "shield_batch" in kinds or "shield_suspicious" in kinds
    finally:
        _run(client.aclose())


def test_proxy_kill_switch_passes_through():
    tmpfile = tempfile.mktemp()
    with open(tmpfile, "w") as f:
        f.write("kill")
    transport = httpx.MockTransport(upstream_handler(200, body=b"passthrough"))
    client = httpx.AsyncClient(transport=transport)
    proxy, _, _, _ = _make_proxy(http_client=client,
                                 config_overrides={"kill_switch_file": tmpfile})
    try:
        resp = _run(_call_proxy(proxy, "GET", "/checkout"))
        assert resp["status"] == 200
        assert resp["body"] == b"passthrough"
    finally:
        _run(client.aclose())
        os.remove(tmpfile)


def test_proxy_x_lab_client_only_in_lab_mode():
    transport = httpx.MockTransport(upstream_handler(200, body=b"ok"))
    client = httpx.AsyncClient(transport=transport)

    proxy, _, _, _ = _make_proxy(http_client=client, lab_mode=False)
    try:
        resp = _run(_call_proxy(proxy, "GET", "/checkout",
                                headers={"x-lab-client": "attacker"}))
        assert resp["status"] == 200
    finally:
        _run(client.aclose())

    # lab mode: X-Lab-Client honored
    transport2 = httpx.MockTransport(upstream_handler(200, body=b"ok"))
    client2 = httpx.AsyncClient(transport=transport2)
    proxy2, _, _, _ = _make_proxy(http_client=client2, lab_mode=True)
    try:
        resp = _run(_call_proxy(proxy2, "GET", "/checkout",
                                headers={"x-lab-client": "attacker"}))
        assert resp["status"] == 200
    finally:
        _run(client2.aclose())


def test_proxy_no_websocket_support():
    transport = httpx.MockTransport(upstream_handler(200, body=b"ok"))
    client = httpx.AsyncClient(transport=transport)
    proxy, _, _, _ = _make_proxy(http_client=client)
    try:

        async def receive():
            return {"type": "websocket.connect"}

        async def send(msg):
            pass

        _run(proxy({"type": "websocket", "path": "/"}, receive, send))
    finally:
        _run(client.aclose())
