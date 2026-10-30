"""The shield proxy over real HTTP on an ephemeral port, in front of a tiny in-process upstream."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import httpx
import uvicorn

from sentinelx.common_schemas import EvidenceState, ShieldRule, ShieldScope, ShieldStatus
from sentinelx.shield.config import ShieldConfig
from sentinelx.shield.recorder import hash_client_key
from sentinelx.shield.rules import BenignReplayGate
from sentinelx.shield.server import ShieldApp, build_app


class Upstream:
    def __init__(self) -> None:
        self.hits = 0

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        self.hits += 1
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"upstream ok"})


@contextmanager
def serve(factory: Callable[[], Any]) -> Iterator[str]:
    """Serve ``factory()`` on an ephemeral port. The app is built inside the server thread, so
    the proxy's in-memory sqlite evidence store is only ever used from that one thread."""
    server = uvicorn.Server(uvicorn.Config(factory, factory=True, host="127.0.0.1", port=0,
                                           log_level="warning", lifespan="off"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.02)
    assert server.started, "test server did not start"
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def proxy_factory(upstream_url: str, mode: str, benign: list[dict] | None,
                  steps: list[tuple[str, str, str]], holder: list[ShieldApp]
                  ) -> Callable[[], ShieldApp]:
    """steps: (client, intent, path) auto-shield proposals made before traffic starts."""
    def build() -> ShieldApp:
        config = ShieldConfig(upstream=upstream_url, mode=mode, auto_shield=mode == "enforce",
                              lab_mode=True)
        app = build_app(config, benign)
        p = app.proxy
        eid = p.store.append(p.session_id, "shield_intent", EvidenceState.INFERRED, "test",
                             {"intent": "RECON"}).id
        for client, intent, path in steps:
            p._auto_shield(hash_client_key(client), intent, path, {}, eid)
        holder.append(app)
        return app
    return build


def test_monitor_blocks_nothing_enforce_blocks_with_marker() -> None:
    attacker = {"X-Lab-Client": "attacker"}
    for mode in ("monitor", "enforce"):
        up = Upstream()
        holder: list[ShieldApp] = []
        with serve(lambda up=up: up) as up_url:
            # a matching ACTIVE rule exists in both modes; only enforce may act on it
            factory = proxy_factory(up_url, mode, None, [("attacker", "RECON", "/.env")], holder)
            with serve(factory) as url:
                r = httpx.get(f"{url}/.env", headers=attacker)
                ok = httpx.get(f"{url}/health", headers=attacker)
                benign = httpx.get(f"{url}/api/notes/1", headers={"X-Lab-Client": "benign"})
                counter = httpx.get(f"{url}/__shield/counter").json()
        assert holder[0].proxy.counts["activated"] == 1
        assert ok.status_code == 200 and "x-sentinel-shield" not in ok.headers
        assert benign.status_code == 200 and "x-sentinel-shield" not in benign.headers
        if mode == "monitor":
            assert r.status_code == 200 and "x-sentinel-shield" not in r.headers
            assert counter["blocked"] == 0
        else:
            assert r.status_code == 403
            assert r.headers["x-sentinel-shield"] == "blocked"
            assert counter["blocked"] == 1
            assert up.hits == 2  # /health and /api/notes/1 only; the blocked one never arrived


def test_gate_rejects_rule_that_blocks_benign_request() -> None:
    benign = [{"method": "GET", "path": "/api/notes/1", "params": {}, "headers": {}}]
    holder: list[ShieldApp] = []
    up = Upstream()
    with serve(lambda: up) as up_url:
        factory = proxy_factory(up_url, "enforce", benign,
                                [("attacker", "DATA_ENUMERATION", "/api/notes/5"),  # /api/notes/*
                                 ("attacker", "RECON", "/.env")], holder)  # no benign use
        with serve(factory) as url:
            httpx.get(f"{url}/.env", headers={"X-Lab-Client": "attacker"})
    counts = holder[0].proxy.counts
    assert counts["proposed"] == 2 and counts["rejected_by_gate"] == 1
    assert counts["escalations"] == 1 and counts["activated"] == 1
    assert [r.scope.route for r in holder[0].proxy.rules.list_rules()] == ["/.env"]


def test_gate_unit_rejects_unscoped_rule() -> None:
    app = build_app(ShieldConfig(upstream="http://127.0.0.1:1", mode="enforce", lab_mode=True))
    p = app.proxy
    eid = p.store.append(p.session_id, "shield_intent", EvidenceState.INFERRED, "test",
                         {"intent": "RECON"}).id
    rule = ShieldRule(
        id="rule_t1", target_id="t", scope=ShieldScope(route="/api/notes/*"),
        action="block_route_pattern", reason="r", intent_event_ids=[eid], owner="test",
        created_at="2099-01-01T00:00:00Z", expires_at="2099-01-01T01:00:00Z",
        status=ShieldStatus.PROPOSED)
    gate = BenignReplayGate(app.proxy.store, app.proxy.session_id,
                            [{"method": "GET", "path": "/api/notes/1", "params": {}}])
    result = gate.check(rule)
    assert not result.passed and result.benign_blocked == 1
    assert result.escalation_ticket is not None
