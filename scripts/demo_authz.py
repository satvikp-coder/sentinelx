"""Authorization-gate demo: 3 allowed requests, then 8 refused ones, with evidence event ids.

Starts both labs (127.0.0.1 only), registers them as LAB targets, and prints a table. The
non-lab/private-address row uses a FAKE resolver and a FAKE transport (no network): non-lab targets
stay OFF in every default, and nothing here ever contacts a non-lab host.
Usage: python scripts/demo_authz.py
"""

import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from apps import labctl  # noqa: E402
from sentinelx.common_schemas import TargetStatus  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.evidence.store import EvidenceStore  # noqa: E402
from sentinelx.scanner.authz import (  # noqa: E402
    ACK_PHRASE,
    AuthzConfig,
    KillSwitch,
    ScanProfile,
    mark_verified,
    register_lab_target,
    register_non_lab_target,
    with_token_hash,
)
from sentinelx.scanner.http import GuardedClient, start_scan_session  # noqa: E402


class Redirector(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(302)
        self.send_header("Location", "http://example.com/stolen")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


class NoNetwork(httpx.BaseTransport):
    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raise AssertionError("the demo must never connect for the refused non-lab request")


def main() -> int:
    for name in ("vibe_shop_php", "vibe_notes_node"):
        lab = labctl.up(name)
        proof = labctl.assert_loopback_only(name)
        print(f"{name}: {lab.base_url} published {proof['published']}")
    shop, notes = labctl.get("vibe_shop_php"), labctl.get("vibe_notes_node")
    redirector = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=redirector.serve_forever, daemon=True).start()
    red_port = redirector.server_address[1]

    conn = connect(Path(tempfile.mkdtemp(prefix="demo-authz-")) / "demo.db")
    migrate(conn)
    rows: list[tuple[str, str, str, str]] = []
    sessions: list[str] = []

    def client(target_id: str, ports: list[int], config: AuthzConfig | None = None, **kw: object):
        target = kw.pop("target", None) or register_lab_target(target_id, ["127.0.0.1"], ports)
        cfg = config or AuthzConfig(requests_per_second=100, burst=100)
        sid = start_scan_session(conn, target, cfg, ScanProfile())
        sessions.append(sid)
        return GuardedClient(target, conn=conn, session_id=sid, config=cfg, **kw)  # type: ignore[arg-type]

    def attempt(label: str, c: GuardedClient, method: str, url: str, **kw: object) -> None:
        out = c.request(method, url, **kw)  # type: ignore[arg-type]
        decision = "ALLOWED" if out.allowed else "REFUSED"
        reason = f"HTTP {out.status}" if out.allowed else out.reason
        rows.append((label, decision, reason, (out.event_id or "")[:28]))

    scan = client("lab-shop-and-notes", [shop.port, notes.port])
    attempt("1 GET shop /index.php (in scope)", scan, "GET", f"{shop.base_url}/index.php")
    attempt("2 GET notes /health (in scope)", scan, "GET", f"{notes.base_url}/health")
    attempt("3 GET shop /api.php (in scope)", scan, "GET", f"{shop.base_url}/api.php?x=1")

    pending = register_lab_target("pending-demo", ["127.0.0.1"], [shop.port]).model_copy(
        update={"status": TargetStatus.PENDING, "verified_at": None})
    attempt("4 target not verified", client("p", [shop.port], target=pending), "GET",
            f"{shop.base_url}/index.php")
    attempt("5 off-scope host", scan, "GET", "http://example.com/")
    red = client("redir", [red_port])
    attempt("6 redirect leaves scope", red, "GET", f"http://127.0.0.1:{red_port}/go")

    fake_cfg = AuthzConfig(allow_non_lab_targets=True, requests_per_second=100, burst=100)
    nl = register_non_lab_target(fake_cfg, "fake-non-lab", "owner.example.net", 80, "http")
    nl = mark_verified(fake_cfg, with_token_hash(nl, "h" * 64), ACK_PHRASE)
    attempt("7 non-lab host resolving to a private address (FAKE resolver)",
            client("nl", [80], fake_cfg, target=nl, resolver=lambda h: ["10.0.0.5"],
                   transport=NoNetwork()), "GET", "http://owner.example.net/")
    attempt("8 POST in default mode", scan, "POST", f"{shop.base_url}/contact.php",
            body=b"name=x&message=y", reason="demo", account="alice")
    budget = client("budget", [shop.port], AuthzConfig(request_budget=1, requests_per_second=100,
                                                        burst=100))
    budget.request("GET", f"{shop.base_url}/health.php")
    attempt("9 over the request budget (budget=1)", budget, "GET", f"{shop.base_url}/health.php")
    kill = KillSwitch()
    killed = client("kill", [shop.port], kill=kill)
    kill.trip("operator pressed stop")
    attempt("10 kill switch on", killed, "GET", f"{shop.base_url}/health.php")
    attempt("11 userinfo trick", scan, "GET", f"http://{shop.base_url[7:]}@evil.example/")

    w = [max(len(r[i]) for r in rows) for i in range(4)]
    print(f"\n{'attempt':{w[0]}}  {'decision':8}  {'reason':{w[2]}}  evidence event id")
    for r in rows:
        print(f"{r[0]:{w[0]}}  {r[1]:8}  {r[2]:{w[2]}}  {r[3]}")
    store = EvidenceStore(conn)
    ok = all(store.verify_chain(s).ok for s in sessions)
    allowed = sum(r[1] == "ALLOWED" for r in rows)
    print(f"\n{allowed} allowed, {len(rows) - allowed} refused; verify_chain "
          f"{'OK' if ok else 'FAILED'} on {len(sessions)} scan sessions; "
          "non-lab targets are OFF by default (the private-address row used a FAKE resolver)")
    redirector.shutdown()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
