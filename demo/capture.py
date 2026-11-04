"""Capture real offline commands and public API/proxy HTTP in disposable state.

Run with the known worker venv Python from MAIN. Does not call providers.
"""

from __future__ import annotations

import hashlib
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

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "demo/out"
OUT.mkdir(parents=True, exist_ok=True)
ENTRY = ROOT / "demo/runtime_entry.py"
ENV = {
    k: v for k, v in os.environ.items() if not any(w in k.upper() for w in ("API_KEY", "API_TOKEN"))
}
ENV.update(DOTENV_DISABLED="1", PYTHONIOENCODING="utf-8")
RECORDS = []


def command(name, kind, target, *args, timeout=240):
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, str(ENTRY), kind, target, *args],
        cwd=ROOT,
        env=ENV,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    raw = result.stdout + result.stderr
    (OUT / f"{name}.txt").write_text(raw, encoding="utf-8")
    RECORDS.append(
        {
            "name": name,
            "command": [kind, target, *args],
            "exit": result.returncode,
            "seconds": round(time.monotonic() - started, 3),
            "sha256": hashlib.sha256(raw.encode()).hexdigest(),
        }
    )
    print(name, "exit", result.returncode, flush=True)
    if result.returncode:
        raise RuntimeError(f"{name} failed; inspect ignored capture log")
    return raw


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Upstream(BaseHTTPRequestHandler):
    count = 0

    def do_GET(self):
        type(self).count += 1
        body = b"synthetic upstream ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def shield():
    state = OUT / "shield-state"
    state.mkdir(exist_ok=True)
    # Refuse stale state: every capture uses a distinct database.
    stamp = str(time.time_ns())
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    api_port, proxy_port = free_port(), free_port()
    env = {
        **ENV,
        "SHIELD_UPSTREAM": f"http://127.0.0.1:{upstream.server_port}",
        "SHIELD_MODE": "enforce",
        "SHIELD_LAB_MODE": "1",
        "SHIELD_RUNTIME_DB": str(state / f"runtime-{stamp}.db"),
        "SHIELD_EVIDENCE_DB": str(state / f"evidence-{stamp}.db"),
        "SHIELD_KILL_SWITCH_FILE": str(state / "kill-not-set"),
    }
    processes, handles, lines = [], [], []
    try:
        for name, module, app, port in [
            ("api", "uvicorn", "apps.api.main:app", api_port),
            ("proxy", "uvicorn", "sentinelx.shield.server:create_shield_app", proxy_port),
        ]:
            handle = (OUT / f"{name}-server.txt").open("w", encoding="utf-8")
            handles.append(handle)
            processes.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        str(ENTRY),
                        "module",
                        module,
                        app,
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--log-level",
                        "warning",
                        "--no-access-log",
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                )
            )
        api = f"http://127.0.0.1:{api_port}/api/v1"
        proxy = f"http://127.0.0.1:{proxy_port}"
        # Synthetic built-in demo principal; never show its token or headers.
        auth = {"Authorization": "Bearer sentinelx-demo-local-only"}
        with httpx.Client(timeout=8, trust_env=False) as client:
            for base in (api + "/health", proxy + "/__shield/health"):
                for _ in range(100):
                    try:
                        response = client.get(base)
                        if response.status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.2)
                else:
                    raise RuntimeError("loopback service startup failed")

            def post(path, payload):
                r = client.post(api + path, json=payload, headers=auth)
                lines.append(f"POST {path} -> HTTP {r.status_code}")
                if r.status_code != 200:
                    (OUT / "shield-error.json").write_text(r.text, encoding="utf-8")
                    raise RuntimeError(f"shield API {path}: HTTP {r.status_code}")
                return r.json()

            before = client.get(proxy + "/api/demo-private")
            lines.append(f"Before activation: GET /api/demo-private -> HTTP {before.status_code}")
            sid = post("/sessions", {"scenario_id": "S1", "lab": "vibe_notes_node", "arm": "A"})[
                "id"
            ]
            started = time.monotonic()
            rule = post(
                "/shield/rules",
                {
                    "route_pattern": "/api/demo-private",
                    "intent": "recon",
                    "mode": "enforce",
                    "ttl_minutes": 5,
                    "reason": "synthetic demo",
                },
            )
            rid = rule["rule_id"]
            lines.append(f"Rule {rid}: {rule['state']}")
            approval = {
                "session_id": sid,
                "action_id": rid,
                "tool": "shield_rule",
                "arguments": {},
                "reviewer": "local demo operator",
                "rationale": "approve exact synthetic lab rule",
                "decision": "approve",
            }
            post("/approvals", approval)
            active = post(f"/shield/rules/{rid}/approve", approval)
            activation_ms = round((time.monotonic() - started) * 1000)
            lines.append(
                f"Runtime state: {active['state']}; proposal-to-active: {activation_ms} ms"
            )
            count = Upstream.count
            blocked = client.get(proxy + "/api/demo-private")
            delta = Upstream.count - count
            lines.append(
                f"Matching request -> HTTP {blocked.status_code}; upstream request delta: {delta}"
            )
            benign = client.get(proxy + "/health")
            lines.append(f"Benign GET /health -> HTTP {benign.status_code}")
            removed = client.delete(api + f"/shield/rules/{rid}", headers=auth)
            lines.append(f"DELETE /shield/rules/{rid} -> HTTP {removed.status_code}")
            after = client.get(proxy + "/api/demo-private")
            lines.append(f"After removal: GET /api/demo-private -> HTTP {after.status_code}")
            assert active["state"] == "ACTIVE" and blocked.status_code == 403 and delta == 0
            assert (
                before.status_code
                == benign.status_code
                == removed.status_code
                == after.status_code
                == 200
            )
            (OUT / "shield-summary.json").write_text(
                json.dumps(
                    {
                        "api_separate_process": True,
                        "proxy_separate_process": True,
                        "real_upstream": True,
                        "activation_ms": activation_ms,
                        "blocked_http": blocked.status_code,
                        "blocked_upstream_delta": delta,
                        "benign_http": benign.status_code,
                        "after_removal_http": after.status_code,
                        "rule_id": rid,
                        "runtime_db": str(state / f"runtime-{stamp}.db"),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
    finally:
        (OUT / "shield.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        for proc in processes:
            proc.terminate()
        for proc in processes:
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        for handle in handles:
            handle.close()
        upstream.shutdown()
        upstream.server_close()
    print("shield real HTTP capture PASS", flush=True)


def main():
    if "--shield-only" in sys.argv:
        shield()
        return
    command("report-build", "module", "sentinelx_cli.main", "report", "build")
    command("agent-enforce", "script", "examples/agent_guard_basic.py", "enforce")
    command("agent-monitor", "script", "examples/agent_guard_basic.py", "monitor")
    command("evidence", "script", "scripts/demo_evidence_chain.py")
    command(
        "scan",
        "script",
        "scripts/run_scan.py",
        "--target",
        "vibe_notes_node",
        "--out",
        str(OUT / "scan"),
    )
    shield()
    ports = {}
    for port in (18081, 18090):
        with socket.socket() as sock:
            ports[str(port)] = sock.connect_ex(("127.0.0.1", port)) != 0
    (OUT / "capture-manifest.json").write_text(
        json.dumps(
            {
                "commands": RECORDS,
                "ports_free": ports,
                "model_calls": "NOT RUN",
                "docker": "daemon unavailable",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    assert all(ports.values()), "a demo port remains open"
    print("Capture complete; ports free", flush=True)


if __name__ == "__main__":
    main()
