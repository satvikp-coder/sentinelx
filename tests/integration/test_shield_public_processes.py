"""Real public API, proxy and upstream in separate localhost processes.

No model, mock transport, private approvals, or lifecycle mutation.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import psutil

ROOT = Path(__file__).resolve().parents[2]


def _port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _stop(process):
    if process.poll() is not None:
        return
    try:
        parent = psutil.Process(process.pid)
        owned = parent.children(recursive=True) + [parent]
        for child in reversed(owned):
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(owned, timeout=5)
        for child in alive:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
    except psutil.NoSuchProcess:
        pass
    process.wait(timeout=10)


def test_public_processes_recover_enforce_and_remove(tmp_path):
    hits = []

    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"synthetic upstream")

        def log_message(self, *args):
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    api_port, proxy_port = _port(), _port()
    api_url, proxy_url = f"http://127.0.0.1:{api_port}", f"http://127.0.0.1:{proxy_port}"
    entry = tmp_path / "entry.py"
    entry.write_text(
        """import sys,os
from pathlib import Path
sys.path.insert(0,os.environ["SX_SOURCE"])
def guard(event,args):
    if (event=="open" and isinstance(args[0],(str,bytes))
            and Path(os.fsdecode(args[0])).name==".env"):
        raise PermissionError("credential files disabled in local integration test")
sys.addaudithook(guard)
import uvicorn
uvicorn.run(os.environ["SX_APP"],factory=os.environ["SX_FACTORY"]=="1",
    host="127.0.0.1",port=int(os.environ["SX_PORT"]),log_level="error",access_log=False)
""",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "SX_SOURCE": str(ROOT),
        "SHIELD_UPSTREAM": f"http://127.0.0.1:{upstream.server_port}",
        "SHIELD_MODE": "enforce",
        "SHIELD_AUTO_SHIELD": "0",
        "SHIELD_LAB_MODE": "1",
        "SHIELD_RUNTIME_DB": str(tmp_path / "runtime.db"),
        "SHIELD_EVIDENCE_DB": str(tmp_path / "shield-evidence.db"),
        "SENTINELX_API_EVIDENCE_DB": str(tmp_path / "api-evidence.db"),
        "SENTINELX_SCAN_EVIDENCE_DB": str(tmp_path / "scan-evidence.db"),
        "SHIELD_KILL_SWITCH_FILE": str(tmp_path / "kill"),
        "SENTINELX_DEMO_TOKEN": "synthetic-process-test-token",
        "MODEL_PROVIDER": "recorded",
    }
    launched, logs = [], []

    def start(kind, mode="enforce"):
        port = api_port if kind == "api" else proxy_port
        app = "apps.api.main:app" if kind == "api" else "sentinelx.shield.server:create_shield_app"
        log = (tmp_path / f"{kind}-{len(launched)}.log").open("w")
        logs.append(log)
        process = subprocess.Popen(
            [sys.executable, str(entry)],
            cwd=ROOT,
            env={
                **env,
                "SX_PORT": str(port),
                "SX_APP": app,
                "SX_FACTORY": "0" if kind == "api" else "1",
                "SHIELD_MODE": mode,
            },
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        launched.append(process)
        url = api_url + "/health" if kind == "api" else proxy_url + "/__shield/health"
        for _ in range(150):
            assert process.poll() is None, f"{kind} failed; see isolated process log"
            try:
                if httpx.get(url, timeout=0.25, trust_env=False).status_code == 200:
                    return process
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        raise AssertionError(f"{kind} startup timeout")

    try:
        api_process, proxy_process = start("api"), start("proxy")
        with (
            httpx.Client(
                base_url=api_url,
                headers={"Authorization": "Bearer synthetic-process-test-token"},
                trust_env=False,
                timeout=10,
            ) as api,
            httpx.Client(base_url=proxy_url, trust_env=False, timeout=5) as traffic,
        ):
            session = api.post(
                "/api/v1/sessions", json={"scenario_id": "S1", "lab": "synthetic", "arm": "A"}
            ).json()["id"]

            def propose(route, mode="enforce", client_id=None):
                body = {
                    "route_pattern": route,
                    "intent": "RECON",
                    "mode": mode,
                    "reason": "Synthetic process regression",
                    "ttl_minutes": 1,
                }
                if client_id:
                    body["client_id"] = client_id
                response = api.post("/api/v1/shield/rules", json=body)
                assert response.status_code == 200, response.text
                return response.json()["rule_id"]

            def approval(rid, decision="approve"):
                r = api.post(
                    "/api/v1/approvals",
                    json={
                        "session_id": session,
                        "action_id": rid,
                        "tool": "shield_rule",
                        "arguments": {},
                        "reviewer": "synthetic operator",
                        "rationale": "Process regression",
                        "decision": decision,
                    },
                )
                assert r.status_code == 200, r.text

            def activate(rid):
                return api.post(
                    f"/api/v1/shield/rules/{rid}/approve",
                    json={"session_id": session, "action_id": rid, "tool": "shield_rule"},
                )

            assert traffic.get("/health").status_code == 200
            rid = propose("/process-blocked", client_id="client-A")
            assert (
                traffic.get("/process-blocked", headers={"X-Lab-Client": "client-A"}).status_code
                == 200
            )
            assert activate(rid).status_code == 400
            approval(rid)
            active = activate(rid)
            assert active.status_code == 200 and active.json()["state"] == "ACTIVE"
            before = len(hits)
            assert (
                traffic.get("/process-blocked", headers={"X-Lab-Client": "client-A"}).status_code
                == 403
            )
            assert len(hits) == before
            assert (
                traffic.get("/process-blocked", headers={"X-Lab-Client": "client-B"}).status_code
                == 200
            )
            assert traffic.get("/health").status_code == 200
            natural = propose("/process-natural")
            approval(natural)
            assert activate(natural).status_code == 200
            assert traffic.get("/process-natural").status_code == 403
            expire = propose("/process-expire")
            approval(expire)
            assert activate(expire).status_code == 200
            assert traffic.get("/process-expire").status_code == 403
            assert api.post(f"/api/v1/shield/rules/{expire}/expire").status_code == 200
            assert traffic.get("/process-expire").status_code == 200
            killed = propose("/process-kill")
            approval(killed)
            (tmp_path / "kill").write_text("synthetic operator kill switch")
            assert activate(killed).status_code == 400
            assert traffic.get("/process-natural").status_code == 200
            (tmp_path / "kill").unlink()
            with api.stream("GET", "/api/v1/events/stream") as stream:
                assert stream.status_code == 200
                delivered = False
                for line in stream.iter_lines():
                    if line.startswith("data:"):
                        event = json.loads(line[5:])
                        if (
                            event["payload"].get("rule_id") == rid
                            and event["payload"].get("state") == "ACTIVE"
                        ):
                            delivered = True
                            break
                assert delivered
            monitor = propose("/process-monitor", mode="monitor")
            approval(monitor)
            assert activate(monitor).status_code == 200
            assert traffic.get("/process-monitor").status_code == 200
            revoked = propose("/process-revoked")
            approval(revoked)
            approval(revoked, "revoke")
            assert activate(revoked).status_code == 400
            _stop(proxy_process)
            proxy_process = start("proxy", "monitor")
            assert (
                traffic.get("/process-blocked", headers={"X-Lab-Client": "client-A"}).status_code
                == 200
            )
            _stop(proxy_process)
            proxy_process = start("proxy")
            assert (
                traffic.get("/process-blocked", headers={"X-Lab-Client": "client-A"}).status_code
                == 403
            )
            _stop(api_process)
            api_process = start("api")
            listed = api.get("/api/v1/shield/rules")
            assert listed.status_code == 200
            assert any(r["rule_id"] == rid and r["state"] == "ACTIVE" for r in listed.json())
            assert api.delete(f"/api/v1/shield/rules/{rid}").status_code == 200
            assert (
                traffic.get("/process-blocked", headers={"X-Lab-Client": "client-A"}).status_code
                == 200
            )
            _stop(proxy_process)
            proxy_process = start("proxy")
            assert (
                traffic.get("/process-blocked", headers={"X-Lab-Client": "client-A"}).status_code
                == 200
            )
            deadline = time.monotonic() + 65
            while traffic.get("/process-natural").status_code == 403:
                assert time.monotonic() < deadline, "natural TTL did not stop real enforcement"
                time.sleep(.2)
            assert traffic.get("/process-natural").status_code == 200
            audit = api.get("/api/v1/shield/evidence")
            assert audit.status_code == 200 and audit.json()["ok"]
            assert any(e["kind"] == "SHIELD_RULE_ACTIVATED" for e in audit.json()["events"])
            from sentinelx.shield.runtime import ShieldRuntimeStore

            runtime = ShieldRuntimeStore(tmp_path / "runtime.db")
            try:
                assert runtime.get(rid)[1] == "REMOVED"
                assert runtime.evidence.verify_chain("shield-runtime-v2").ok
            finally:
                runtime.close()
    finally:
        for process in reversed(launched):
            _stop(process)
        for log in logs:
            log.close()
        upstream.shutdown()
        upstream.server_close()
