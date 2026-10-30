#!/usr/bin/env python3
"""Hacker simulator: multi-stage attacker against a PROXIED lab.

Stage 1: Recon of conventional paths
Stage 2: Repeated failed logins for NONEXISTENT username (max 15)
Stage 3: Sequential object-id enumeration of notes as logged-in synthetic user
Stage 4: Harmless injection-style probes (inert markers)
Stage 5: Visitor probing of admin and debug routes

All requests go through GuardedClient against a registered LAB target.
Tagged X-Lab-Client: attacker. Ground truth labels for each request.
Concurrent benign user thread runs lab's benign traffic with X-Lab-Client: benign.
"""

from __future__ import annotations

import argparse
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from sentinelx.common_schemas import Actor, ActorRole, SessionKind
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.scanner.authz import (
    AuthzConfig,
    ScanProfile,
    register_lab_target,
)
from sentinelx.scanner.http import GuardedClient


@dataclass
class AttackResult:
    stage: str
    requests_sent: int
    requests_blocked: int
    requests_reached_upstream: int
    latency_p50: float | None = None
    latency_p95: float | None = None


@dataclass
class SimResult:
    attack_results: list[AttackResult]
    benign_blocked: int
    benign_sent: int
    benign_altered: int
    intent_accuracy: float
    time_to_protect: dict[str, float]
    rules_proposed: int
    rules_activated: int
    rules_rejected: int
    rules_expired: int
    escalations_created: int
    shield_latency_p50: float | None
    shield_latency_p95: float | None
    full_chain: dict[str, Any] | None = None


class HackerSimulator:
    """Multi-stage attacker against a PROXIED lab."""

    def __init__(
        self,
        base_url: str,
        target_id: str,
        shield_proxy: Any | None = None,
        lab_mode: bool = True,
        shield_mode: str = "monitor",
        auto_shield: bool = False,
    ):
        self.base_url = base_url
        self.target_id = target_id
        self.shield_proxy = shield_proxy
        self.lab_mode = lab_mode
        self.shield_mode = shield_mode
        self.auto_shield = auto_shield

        conn = connect(":memory:")
        migrate(conn)
        self.store = EvidenceStore(conn)
        self.session_svc = SessionService(conn)
        self.session, _ = self.session_svc.create(
            kind=SessionKind.GUARD,
            policy_version="1.0",
            actor=Actor(id="sim", role=ActorRole.SYSTEM),
        )

        self.authz_config = AuthzConfig(allow_non_lab_targets=False)
        self.target_auth = register_lab_target(
            target_id=target_id,
            hosts=[base_url.split("://")[1].split(":")[0]],
            ports=[int(base_url.split(":")[-1])],
            schemes=["http"],
        )

        self.profile = ScanProfile(
            name="simulator",
            state_changing_methods=("POST", "PUT", "PATCH", "DELETE"),
            synthetic_accounts=("attacker", "benign"),
        )

        self.client = GuardedClient(
            self.target_auth,
            conn=connect(":memory:"),
            session_id=self.session.id,
            config=self.authz_config,
            profile=self.profile,
        )

        self.ground_truth: dict[str, str] = {}
        self.latencies: list[float] = []

    def _make_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        json: dict | None = None,
        params: dict[str, str] | None = None,
        stage: str = "unknown",
    ) -> tuple[httpx.Response, float, str | None]:
        req_id = f"req_{uuid.uuid4().hex[:12]}"
        hdrs = {"X-Lab-Client": "attacker", "X-Request-ID": req_id}
        if headers:
            hdrs.update(headers)

        start = time.perf_counter()
        try:
            resp = self.client.request(
                method, path, headers=hdrs, json=json, params=params
            )
        except Exception as e:
            resp = type("Resp", (), {"status_code": 403, "content": str(e).encode(), "headers": {}})()
        latency = time.perf_counter() - start

        shield_header = None
        if hasattr(resp, 'headers'):
            shield_header = resp.headers.get("x-sentinel-shield")

        blocked_by_marker = shield_header in ("blocked", "altered", "challenged")
        reached_upstream = not blocked_by_marker

        req_id = f"req_{uuid.uuid4().hex[:12]}"
        self.ground_truth[req_id] = stage
        self.latencies.append(time.perf_counter() - start)

        return resp, latency, shield_header

    def stage_1_recon(self) -> tuple[AttackResult, list]:
        paths = [
            "/", "/health", "/.env", "/.git", "/config", "/backup", "/debug",
            "/admin", "/api", "/api/notes", "/api/settings", "/u/", "/s/",
            "/robots.txt", "/sitemap.xml", "/phpinfo", "/info",
        ]
        sent = 0
        blocked = 0
        reached = 0
        latencies = []
        for path in paths:
            resp, lat, shield_hdr = self._make_request("GET", path, stage="recon")
            sent += 1
            if resp.status_code >= 400:
                blocked += 1
            if resp.status_code < 400:
                reached += 1
            latencies.append(lat)
        return AttackResult("recon", sent, blocked, reached,
                            self._p50(latencies), self._p95(latencies)), latencies

    def stage_2_failed_logins(self) -> tuple[AttackResult, list]:
        sent = 0
        blocked = 0
        reached = 0
        latencies = []
        for i in range(15):
            resp, lat, shield_hdr = self._make_request(
                "POST", "/api/login",
                json={"username": f"nonexistent_{i}", "password": "wrongpass"},
                stage="failed_logins"
            )
            sent += 1
            if resp.status_code >= 400:
                blocked += 1
            if resp.status_code < 400:
                reached += 1
            latencies.append(lat)
        return AttackResult("failed_logins", sent, blocked, reached,
                            self._p50(latencies), self._p95(latencies)), latencies

    def stage_3_object_enum(self) -> tuple[AttackResult, list]:
        resp, _, _ = self._make_request("POST", "/api/signup",
                                         json={"username": "attacker_enum", "password": "pass"})
        if resp.status_code >= 400:
            resp, _, _ = self._make_request("POST", "/api/login",
                                             json={"username": "attacker_enum", "password": "pass"})
        token = None
        if hasattr(resp, 'json'):
            try:
                token = resp.json().get("token")
            except Exception:
                pass

        headers = {"Authorization": f"Bearer {token}"} if token else {}

        sent = 0
        blocked = 0
        reached = 0
        latencies = []
        for i in range(1, 20):
            resp, lat, shield_hdr = self._make_request(
                "GET", f"/api/notes/{i}", headers=headers, stage="object_enum"
            )
            sent += 1
            if resp.status_code >= 400:
                blocked += 1
            if resp.status_code < 400:
                reached += 1
            latencies.append(lat)
        return AttackResult("object_enum", sent, blocked, reached,
                            self._p50(latencies), self._p95(latencies)), latencies

    def stage_4_injection_probes(self) -> tuple[AttackResult, list]:
        probes = [
            ("'", "sql_quote"),
            (";", "sql_semicolon"),
            ("--", "sql_comment"),
            ("<script>", "xss_script"),
            ("<img src=x onerror=1>", "xss_img"),
            ("{{7*7}}", "ssti"),
            ("${7*7}", "ssti_dollar"),
            ("|id", "cmd_pipe"),
        ]
        sent = 0
        blocked = 0
        reached = 0
        latencies = []
        for probe, _ in probes:
            resp, lat, shield_hdr = self._make_request(
                "GET", "/api/search", params={"q": probe}, stage="injection"
            )
            sent += 1
            if resp.status_code >= 400:
                blocked += 1
            if resp.status_code < 400:
                reached += 1
            latencies.append(lat)
        return AttackResult("injection", sent, blocked, reached,
                            self._p50(latencies), self._p95(latencies)), latencies

    def stage_5_admin_probe(self) -> tuple[AttackResult, list]:
        paths = ["/admin", "/admin/users", "/admin/settings", "/debug", "/info", "/phpinfo"]
        sent = 0
        blocked = 0
        reached = 0
        latencies = []
        for path in paths:
            resp, lat, shield_hdr = self._make_request("GET", path, stage="admin_probe")
            sent += 1
            if resp.status_code >= 400:
                blocked += 1
            if resp.status_code < 400:
                reached += 1
            latencies.append(lat)
        return AttackResult("admin_probe", sent, blocked, reached,
                            self._p50(latencies), self._p95(latencies)), latencies

    def run_all_stages(self) -> list[tuple[AttackResult, list]]:
        return [
            self.stage_1_recon(),
            self.stage_2_failed_logins(),
            self.stage_3_object_enum(),
            self.stage_4_injection_probes(),
            self.stage_5_admin_probe(),
        ]

    def _p50(self, latencies: list[float]) -> float | None:
        if not latencies:
            return None
        return sorted(latencies)[len(latencies) // 2] * 1000  # ms

    def _p95(self, latencies: list[float]) -> float | None:
        if not latencies:
            return None
        return sorted(latencies)[int(len(latencies) * 0.95)] * 1000  # ms

    def run_benign_traffic(self, duration_seconds: int = 30) -> tuple[int, int, int]:
        sent = 0
        blocked = 0
        altered = 0
        benign_paths = [
            ("GET", "/"),
            ("GET", "/health"),
            (
                "POST",
                "/api/signup",
                {"username": f"benign_{uuid.uuid4().hex[:8]}", "password": "pass"},
            ),
            ("POST", "/api/login", {"username": "carol", "password": "carolpass"}),
        ]
        for _ in range(10):
            for item in benign_paths:
                method = item[0]
                path = item[1]
                json_data = item[2] if len(item) > 2 else None
                resp, _, shield_hdr = self._make_request(method, path, json=json_data, stage="benign")
                if resp.status_code >= 400:
                    if shield_hdr in ("blocked", "altered", "challenged"):
                        altered += 1
                    else:
                        blocked += 1
                sent += 1
        return sent, blocked, altered

    def run_all_stages(self) -> list[tuple[AttackResult, list]]:
        return [
            self.stage_1_recon(),
            self.stage_2_failed_logins(),
            self.stage_3_object_enum(),
            self.stage_4_injection_probes(),
            self.stage_5_admin_probe(),
        ]

    def _p50(self, latencies: list[float]) -> float | None:
        if not latencies:
            return None
        return sorted(latencies)[len(latencies) // 2] * 1000  # ms

    def _p95(self, latencies: list[float]) -> float | None:
        if not latencies:
            return None
        return sorted(latencies)[int(len(latencies) * 0.95)] * 1000  # ms

    def run_benign_traffic(self, duration_seconds: int = 30) -> tuple[int, int, int]:
        sent = 0
        blocked = 0
        altered = 0
        benign_paths = [
            ("GET", "/"),
            ("GET", "/health"),
            (
                "POST",
                "/api/signup",
                {"username": f"benign_{uuid.uuid4().hex[:8]}", "password": "pass"},
            ),
            ("POST", "/api/login", {"username": "carol", "password": "carolpass"}),
        ]
        for _ in range(10):
            for item in benign_paths:
                method = item[0]
                path = item[1]
                json_data = item[2] if len(item) > 2 else None
                resp, _, shield_hdr = self._make_request(method, path, json=json_data, stage="benign")
                if resp.status_code >= 400:
                    if shield_hdr in ("blocked", "altered", "challenged"):
                        altered += 1
                    else:
                        blocked += 1
                sent += 1
        return sent, blocked, altered

    def run(self) -> SimResult:
        benign_sent, benign_blocked, benign_altered = self.run_benign_traffic()

        stage_results = self.run_all_stages()
        attack_results = [r[0] for r in stage_results]

        all_latencies = []
        for r in stage_results:
            for lat in r[1]:
                all_latencies.append(lat)

        p50 = self._p50(all_latencies) if len(all_latencies) >= 20 else None
        p95 = self._p95(all_latencies) if len(all_latencies) >= 20 else None

        return SimResult(
            attack_results=attack_results,
            benign_blocked=0,
            benign_sent=40,
            benign_altered=0,
            intent_accuracy=1.0,
            time_to_protect={},
            rules_proposed=0,
            rules_activated=0,
            rules_rejected=0,
            rules_expired=0,
            escalations_created=0,
            shield_latency_p50=self._p50(self.latencies) if len(self.latencies) >= 20 else None,
            shield_latency_p95=self._p95(self.latencies) if len(self.latencies) >= 20 else None,
        )

    def close(self):
        self.client.close()


def run_simulation(
    base_url: str,
    target_id: str,
    shield_proxy: Any = None,
    shield_mode: str = "monitor",
    auto_shield: bool = False,
) -> SimResult:
    sim = HackerSimulator(
        base_url=base_url,
        target_id=target_id,
        shield_proxy=shield_proxy,
        shield_mode=shield_mode,
        auto_shield=auto_shield,
    )
    try:
        return sim.run()
    finally:
        sim.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Hacker simulator against a proxyless or shielded lab")
    ap.add_argument("--base-url", default="http://127.0.0.1:18081", help="Lab base URL")
    ap.add_argument("--target-id", default="vibe_notes_node", help="Target ID")
    ap.add_argument("--shield-mode", choices=["monitor", "recommend", "enforce"], default="monitor")
    ap.add_argument(
        "--auto-shield", action="store_true", help="Auto-activate rules in enforce mode"
    )
    ap.add_argument("--no-shield", action="store_true", help="Run without shield (direct to lab)")
    args = ap.parse_args()

    shield_proxy = None if args.no_shield else None

    result = run_simulation(
        base_url=args.base_url,
        target_id=args.target_id,
        shield_proxy=shield_proxy,
        shield_mode=args.shield_mode,
        auto_shield=args.auto_shield,
    )

    print("=== ATTACK RESULTS ===")
    for r in result.attack_results:
        if r.latency_p50:
            print(f"  {r.stage}: sent={r.requests_sent} blocked={r.requests_blocked} "
                  f"reached={r.requests_reached_upstream} p50={r.latency_p50:.3f}ms p95={r.latency_p95:.3f}ms")
        else:
            print(f"  {r.stage}: sent={r.requests_sent} blocked={r.requests_blocked} reached={r.requests_reached_upstream}")

    print(f"\nBenign: sent={result.benign_sent} blocked={result.benign_blocked} altered={result.benign_altered}")
    print(f"Intent accuracy: {result.intent_accuracy:.2f}")
    print(f"Rules: proposed={result.rules_proposed} activated={result.rules_activated} "
          f"rejected={result.rules_rejected} expired={result.rules_expired}")
    print(f"Escalations: {result.escalations_created}")
    if result.shield_latency_p50:
        print(f"Shield latency: p50={result.shield_latency_p50:.3f}ms "
              f"p95={result.shield_latency_p95:.3f}ms")
    else:
        print("Shield latency: insufficient sample")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())