#!/usr/bin/env python3
"""Hacker simulator: a scripted multi-stage attacker plus a benign user, against a LAB target.

Stage 1 recon of conventional paths; stage 2 failed logins for nonexistent usernames; stage 3
sequential note-id enumeration as a logged-in synthetic user; stage 4 inert injection-style
probes (authenticated); stage 5 visitor probing of admin and debug routes.

Every request goes through GuardedClient against a registered LAB target and is tagged
``X-Lab-Client: attacker`` or ``benign``. Each request is returned as one record (and appended
to a JSONL file by the caller): the evaluation tables are generated only from those records.

``blocked_by_shield`` is true ONLY when the response carries the X-Sentinel-Shield marker.
``reached_upstream`` is, for the direct arm, "the lab answered"; for proxied arms, "the proxy's
forwarded counter incremented" (read from ``/__shield/counter``).
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from sentinelx.evidence.db import connect, migrate
from sentinelx.scanner.authz import AuthzConfig, ScanProfile, register_lab_target
from sentinelx.scanner.http import GuardedClient, Outcome, start_scan_session

MARKER = "x-sentinel-shield"
COUNTER_PATH = "/__shield/counter"

STAGE_TRUTH = {
    "recon": "RECON",
    "failed_logins": "CREDENTIAL_GUESSING",
    "object_enum": "DATA_ENUMERATION",
    "injection": "INJECTION_PROBE",
    "admin_probe": "ADMIN_PROBE",
}
STAGES = tuple(STAGE_TRUTH)

RECON_PATHS = [
    "/", "/health", "/.env", "/.git", "/config", "/backup", "/debug", "/admin", "/api",
    "/api/notes", "/api/settings", "/u/", "/s/", "/robots.txt", "/sitemap.xml", "/phpinfo",
    "/info",
]
INJECTION_PROBES = ["'", ";", "--", "<script>", "<img src=x onerror=1>", "{{7*7}}", "${7*7}",
                    "|id"]
ADMIN_PATHS = ["/admin", "/admin/users", "/admin/settings", "/debug", "/info", "/phpinfo"]
ATTACKER_USER = "attacker_syn"
ATTACKER_PASS = "attackerpass"
BENIGN_TOTAL = 40


@dataclass
class Step:
    role: str  # attacker | benign
    stage: str
    method: str
    path: str
    json: dict | None = None
    auth: str | None = None  # which stored token to send: attacker | benign
    save_token: str | None = None


def attack_plan() -> list[Step]:
    steps: list[Step] = []
    for p in RECON_PATHS:
        steps.append(Step("attacker", "recon", "GET", p))
    for i in range(15):
        steps.append(Step("attacker", "failed_logins", "POST", "/api/login",
                          {"username": f"nonexistent_{i}", "password": "wrongpass"}))
    for i in range(1, 20):
        steps.append(Step("attacker", "object_enum", "GET", f"/api/notes/{i}", auth="attacker"))
    for probe in INJECTION_PROBES:
        steps.append(Step("attacker", "injection", "GET", f"/api/search?q={quote(probe)}",
                          auth="attacker"))
    for p in ADMIN_PATHS:
        steps.append(Step("attacker", "admin_probe", "GET", p))
    return steps


def benign_plan() -> list[Step]:
    cycle = [
        ("GET", "/", None, None, None),
        ("GET", "/health", None, None, None),
        ("POST", "/api/login", {"username": "carol", "password": "carolpass"}, None, "benign"),
        ("GET", "/api/notes", None, "benign", None),
        ("GET", "/api/notes/1", None, "benign", None),
        ("GET", "/api/search?q=plan", None, "benign", None),
        ("GET", "/api/settings", None, None, None),
        ("GET", "/u/carol", None, None, None),
        ("POST", "/api/signup", {"username": "benign_{n}", "password": "pass"}, None, None),
        ("GET", "/api/notes", None, "benign", None),
    ]
    steps = [Step("benign", "benign", m, p, j, a, s) for m, p, j, a, s in cycle]
    return (steps * (BENIGN_TOTAL // len(steps)))[:BENIGN_TOTAL]


class HackerSimulator:
    def __init__(self, base_url: str, target_id: str, arm: str, proxied: bool) -> None:
        self.base_url = base_url.rstrip("/")
        self.arm = arm
        self.proxied = proxied
        parts = urlsplit(self.base_url)
        conn = connect(":memory:")
        migrate(conn)
        target = register_lab_target(target_id, [parts.hostname or "127.0.0.1"],
                                     [parts.port or 80], ["http"])
        # operator config for the simulator: lab-only, generous budget, no rate wait
        config = AuthzConfig(requests_per_second=1000.0, burst=1000, request_budget=2000)
        profile = ScanProfile(name="simulator",
                              state_changing_methods=("POST", "PUT", "PATCH", "DELETE"),
                              synthetic_accounts=("attacker", "benign"))
        session_id = start_scan_session(conn, target, config, profile)
        self.session_id = session_id
        self.client = GuardedClient(target, conn=conn, session_id=session_id, config=config,
                                    profile=profile)
        self.tokens: dict[str, str] = {}
        self.records: list[dict[str, Any]] = []
        self.stage_t0: dict[str, float] = {}
        self.seq = 0

    def close(self) -> None:
        self.client.close()

    # ------------------------------------------------------------------ plumbing
    def _send(self, step: Step, req_id: str) -> Outcome:
        headers = {"X-Lab-Client": step.role, "X-Request-ID": req_id}
        body: str | None = None
        if step.json is not None:
            body = json.dumps(step.json)
            headers["Content-Type"] = "application/json"
        if step.auth and step.auth in self.tokens:
            headers["Authorization"] = f"Bearer {self.tokens[step.auth]}"
        return self.client.request(step.method, self.base_url + step.path, body=body,
                                   headers=headers, reason="shield simulation",
                                   account=step.role)

    def _forwarded(self) -> int:
        out = self.client.request("GET", self.base_url + COUNTER_PATH)
        if out.status != 200:
            raise RuntimeError(f"shield counter unavailable: {out.reason} {out.status}")
        return int(json.loads(out.text)["forwarded"])

    def do(self, step: Step) -> dict[str, Any]:
        if step.json and "{n}" in json.dumps(step.json):
            step = Step(**{**asdict(step), "json": {
                k: v.replace("{n}", uuid.uuid4().hex[:8]) for k, v in step.json.items()}})
        req_id = f"req_{uuid.uuid4().hex[:12]}"
        before = self._forwarded() if self.proxied else 0
        started = time.perf_counter()
        t_epoch = time.time()
        out = self._send(step, req_id)
        client_ms = (time.perf_counter() - started) * 1000.0
        status = out.status if out.allowed else None
        marker = out.headers.get(MARKER) if out.allowed else None
        if self.proxied:
            reached = self._forwarded() > before
        else:
            reached = out.allowed and out.status is not None
        t0 = self.stage_t0.setdefault(step.stage, started)
        if step.save_token and status == 200:
            try:
                self.tokens[step.save_token] = json.loads(out.text)["token"]
            except (ValueError, KeyError):
                pass
        self.seq += 1
        rec = {
            "arm": self.arm, "seq": self.seq, "request_id": req_id, "role": step.role,
            "stage": step.stage, "method": step.method, "path": step.path, "sent": True,
            "status": status, "refused": None if out.allowed else out.reason,
            "blocked_by_shield": marker is not None, "shield_marker": marker,
            "reached_upstream": bool(reached), "t_since_stage_start_s": round(started - t0, 4),
            "epoch": t_epoch, "client_ms": round(client_ms, 3),
            "truth_intent": STAGE_TRUTH.get(step.stage),
        }
        self.records.append(rec)
        return rec

    # ------------------------------------------------------------------ run
    def setup_attacker(self) -> None:
        """Create and log in the synthetic attacker user (stage 'setup', not counted as attack)."""
        self.do(Step("attacker", "setup", "POST", "/api/signup",
                     {"username": ATTACKER_USER, "password": ATTACKER_PASS}))
        self.do(Step("attacker", "setup", "POST", "/api/login",
                     {"username": ATTACKER_USER, "password": ATTACKER_PASS},
                     save_token="attacker"))
        if "attacker" not in self.tokens:
            raise RuntimeError("synthetic attacker login failed; object_enum would be anonymous")

    def run(self) -> list[dict[str, Any]]:
        self.setup_attacker()
        attacks, benign = attack_plan(), benign_plan()
        sent_benign = 0
        for i, step in enumerate(attacks):
            self.do(step)
            due = round((i + 1) * len(benign) / len(attacks))
            while sent_benign < due:
                self.do(benign[sent_benign])
                sent_benign += 1
        return self.records


def run_simulation(base_url: str, target_id: str, arm: str, proxied: bool
                   ) -> list[dict[str, Any]]:
    sim = HackerSimulator(base_url, target_id, arm, proxied)
    try:
        return sim.run()
    finally:
        sim.close()


def write_records(records: list[dict[str, Any]], path: Path, append: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a" if append else "w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Hacker simulator against a LAB target")
    ap.add_argument("--base-url", default="http://127.0.0.1:18081")
    ap.add_argument("--target-id", default="vibe_notes_node")
    ap.add_argument("--arm", default="A")
    ap.add_argument("--proxied", action="store_true", help="base URL is the shield proxy")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    records = run_simulation(args.base_url, args.target_id, args.arm, args.proxied)
    if args.out:
        write_records(records, Path(args.out))
    print(f"{datetime.now(UTC).isoformat()} sent {len(records)} requests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
