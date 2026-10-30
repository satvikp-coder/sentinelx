#!/usr/bin/env python3
"""Three-way shield evaluation against vibe_notes_node, through a REAL proxy subprocess.

Arm A: attacker and benign traffic go DIRECT to the lab (18081). Arms B and C: a real uvicorn
shield proxy on 127.0.0.1:18090 forwards to the lab; B is monitor mode, C is enforce mode with
auto_shield and lab_mode. The lab is reset (and its state hash asserted) before each arm. Every
request is written to evaluations/example_shield_report/requests.jsonl and the report tables are
generated ONLY from that file plus the proxy's own stats. If the lab or proxy cannot be started
the run stops without reporting results.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.hacker_sim import STAGE_TRUTH, STAGES, run_simulation, write_records  # noqa: E402
from sentinelx.shield.recorder import hash_client_key  # noqa: E402
from sentinelx.shield.rules import _scope_matches  # noqa: E402

LAB = "vibe_notes_node"
LAB_URL = "http://127.0.0.1:18081"
PROXY_HOST, PROXY_PORT = "127.0.0.1", 18090
PROXY_URL = f"http://{PROXY_HOST}:{PROXY_PORT}"
OUT = ROOT / "evaluations" / "example_shield_report"
ARMS = {
    "A": {"label": "A: no shield", "proxy": None},
    "B": {"label": "B: monitor", "proxy": {"mode": "monitor", "auto": "false"}},
    "C": {"label": "C: enforce + auto_shield", "proxy": {"mode": "enforce", "auto": "true"}},
}


class RunError(RuntimeError):
    pass


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def lab_script(name: str, *args: str) -> str:
    res = subprocess.run([sys.executable, str(ROOT / "scripts" / name), *args],
                         capture_output=True, text=True, timeout=180, cwd=ROOT)
    if res.returncode != 0:
        raise RunError(f"{name} failed: {res.stderr.strip()[-400:] or res.stdout.strip()[-400:]}")
    return res.stdout.strip()


def reset_lab(baseline: list[str]) -> str:
    out = lab_script("lab_reset.py", LAB)
    state = out.rsplit("state hash", 1)[-1].strip()
    if not state:
        raise RunError(f"no state hash in reset output: {out!r}")
    if baseline and state != baseline[0]:
        raise RunError(f"lab state hash {state} != seeded baseline {baseline[0]}")
    if not baseline:
        baseline.append(state)
    return state


class Proxy:
    def __init__(self, mode: str, auto: str) -> None:
        self.env = {**os.environ, "SHIELD_UPSTREAM": LAB_URL, "SHIELD_MODE": mode,
                    "SHIELD_AUTO_SHIELD": auto, "SHIELD_LAB_MODE": "true",
                    "SHIELD_BENIGN_FILE": str(ROOT / "labs" / LAB / "benign_traffic.py"),
                    "PYTHONPATH": str(ROOT)}
        self.proc: subprocess.Popen | None = None
        self.log = tempfile.NamedTemporaryFile("w+b", suffix=".log", delete=False)

    def start(self) -> None:
        if port_open(PROXY_PORT):
            raise RunError(f"port {PROXY_PORT} already in use; refusing to start the proxy")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "sentinelx.shield.server:create_shield_app",
             "--factory", "--host", PROXY_HOST, "--port", str(PROXY_PORT),
             "--log-level", "warning"],
            env=self.env, stdout=self.log, stderr=subprocess.STDOUT, cwd=ROOT)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RunError(f"proxy exited early (code {self.proc.returncode}): {self.tail()}")
            try:
                if httpx.get(f"{PROXY_URL}/__shield/health", timeout=2).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.3)
        raise RunError(f"proxy health check timed out: {self.tail()}")

    def tail(self) -> str:
        self.log.flush()
        return Path(self.log.name).read_bytes()[-500:].decode("utf-8", "replace")

    def stats(self) -> dict:
        return httpx.get(f"{PROXY_URL}/__shield/stats", timeout=10).json()

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)
            self.proc = None
        self.log.close()
        Path(self.log.name).unlink(missing_ok=True)
        for _ in range(20):
            if not port_open(PROXY_PORT):
                return
            time.sleep(0.25)
        raise RunError(f"port {PROXY_PORT} still open after proxy stop")


# ---------------------------------------------------------------------- metrics (from records)
def pct(sorted_vals: list[float], q: float) -> float:
    return sorted_vals[min(len(sorted_vals) - 1, int(len(sorted_vals) * q))]


def latency(values: list[float]) -> dict | str:
    if len(values) < 20:
        return "insufficient sample"
    v = sorted(values)
    return {"n": len(v), "p50_ms": round(pct(v, 0.5), 3), "p95_ms": round(pct(v, 0.95), 3)}


def stage_counts(recs: list[dict]) -> dict:
    out = {}
    for stage in STAGES:
        rs = [r for r in recs if r["role"] == "attacker" and r["stage"] == stage]
        out[stage] = {
            "sent": len(rs),
            "reached_upstream": sum(r["reached_upstream"] for r in rs),
            "blocked_by_shield": sum(r["blocked_by_shield"] for r in rs),
            "lab_4xx_5xx": sum(1 for r in rs if r["reached_upstream"]
                               and not r["blocked_by_shield"] and (r["status"] or 0) >= 400),
        }
    return out


def intent_accuracy(recs: list[dict], stats: dict | None) -> dict | str:
    if stats is None:
        return "n/a"
    by_id = {e["request_id"]: e for e in stats["requests"]}
    out = {}
    for stage in STAGES:
        rs = [r for r in recs if r["role"] == "attacker" and r["stage"] == stage]
        truth = STAGE_TRUTH[stage]
        ok = sum(1 for r in rs if by_id.get(r["request_id"], {}).get("intent") == truth)
        labelled = sum(1 for r in rs if by_id.get(r["request_id"], {}).get("intent"))
        out[stage] = {"correct": ok, "labelled": labelled, "sent": len(rs),
                      "accuracy": round(ok / len(rs), 3) if rs else None}
    return out


def time_to_protect(recs: list[dict], stats: dict) -> dict:
    by_id = {e["request_id"]: e for e in stats["requests"]}
    rules = sorted((r for r in stats["rules"] if r["activated_epoch"]),
                   key=lambda r: r["activated_epoch"])
    out = {}
    for stage in STAGES:
        rs = [r for r in recs if r["role"] == "attacker" and r["stage"] == stage]
        first = min(r["epoch"] for r in rs)
        best = None
        for rule in rules:
            scope = {"route": rule["route"], "parameter": rule["parameter"],
                     "client": rule["client_key"]}
            covered = False
            for r in rs:
                parts = urlsplit(r["path"])
                req = {"path": parts.path, "params": dict(parse_qsl(parts.query)),
                       "client_key": by_id.get(r["request_id"], {}).get("client_key", "")}
                if _scope_matches(type("S", (), scope)(), req):
                    covered = True
                    break
            if covered:
                best = rule
                break
        if best is None:
            out[stage] = "not protected"
        else:
            delta = best["activated_epoch"] - first
            out[stage] = {"seconds": round(max(delta, 0.0), 3), "rule": best["rule_id"],
                          "pre_activated": delta < 0}
    return out


def arm_metrics(arm: str, recs: list[dict], stats: dict | None) -> dict:
    attacks = [r for r in recs if r["role"] == "attacker" and r["stage"] in STAGES]
    benign = [r for r in recs if r["role"] == "benign"]
    refused = [r for r in recs if r["refused"]]
    m = {
        "records": len(recs), "refused_by_guarded_client": len(refused),
        "attack": {"total": {
            "sent": len(attacks),
            "reached_upstream": sum(r["reached_upstream"] for r in attacks),
            "blocked_by_shield": sum(r["blocked_by_shield"] for r in attacks),
            "lab_4xx_5xx": sum(1 for r in attacks if r["reached_upstream"]
                               and not r["blocked_by_shield"] and (r["status"] or 0) >= 400)},
            "per_stage": stage_counts(recs)},
        "benign": {"sent": len(benign),
                   "blocked_or_altered_by_shield": sum(r["blocked_by_shield"] for r in benign),
                   "lab_4xx_5xx": sum(1 for r in benign if (r["status"] or 0) >= 400
                                      and not r["blocked_by_shield"]),
                   "blocked_by_rule": sorted({by["rule_id"] for by in (stats or {}).get(
                       "requests", []) if by.get("blocked") and by["client_key"]
                       == hash_client_key("benign") and by.get("rule_id")})},
        "intent_accuracy": intent_accuracy(recs, stats),
    }
    if stats is None:
        m["shield_latency"] = "n/a"
        m["rules"] = "n/a"
        m["time_to_protect"] = "n/a"
    else:
        m["shield_latency"] = latency([e["overhead_ms"] for e in stats["requests"]
                                       if "overhead_ms" in e])
        c = stats["counts"]
        m["rules"] = {"proposed": c["proposed"], "activated": c["activated"],
                      "rejected_by_gate": c["rejected_by_gate"],
                      "escalations": c["escalations"], "compile_rejected": c["compile_rejected"],
                      "for_benign_client": sum(1 for d in stats["rules"]
                                               if d["client_key"] == hash_client_key("benign")),
                      "detail": stats["rules"]}
        m["time_to_protect"] = (time_to_protect(recs, stats) if arm == "C"
                                else "n/a (monitor mode never activates rules)")
    m["client_e2e_latency"] = latency([r["client_ms"] for r in recs])
    return m


def suspicious(results: dict) -> list[str]:
    notes = []
    for arm, m in results.items():
        t = m["attack"]["total"]
        if arm in ("A", "B") and t["blocked_by_shield"]:
            notes.append(f"arm {arm}: {t['blocked_by_shield']} marker blocks without enforcement")
        if t["sent"] and t["blocked_by_shield"] == t["sent"]:
            notes.append(f"arm {arm}: 100% of attacks blocked, implausible; check the run")
        ia = m["intent_accuracy"]
        if isinstance(ia, dict):
            for stage, v in ia.items():
                if v["sent"] and v["correct"] == v["sent"]:
                    notes.append(f"arm {arm} stage {stage}: intent accuracy 100% with no misses "
                                 "(too good to present as a result)")
        if m["benign"]["sent"] and not m["benign"]["blocked_or_altered_by_shield"] and arm == "C":
            notes.append("arm C: 0 benign false blocks is by construction: every rule is scoped "
                         "to the attacker's client key, and benign traffic uses another key")
        if m["refused_by_guarded_client"]:
            notes.append(f"arm {arm}: {m['refused_by_guarded_client']} requests refused by "
                         "GuardedClient (not sent)")
    return notes


# ---------------------------------------------------------------------- report
def render_md(results: dict, notes: list[str], stamp: str) -> str:
    L = ["# Shield evaluation: three-way run through a real proxy", "",
         f"Generated {stamp}. Lab `{LAB}`, reset before each arm. Tables are generated only from "
         "`requests.jsonl` and the proxy's own stats endpoint.", "",
         "Columns: sent / reached upstream / **blocked by shield (X-Sentinel-Shield marker)** / "
         "lab responded 4xx-5xx (informational, NOT counted as blocked).", "",
         "## Attack traffic, per arm", "",
         "| Arm | sent | reached upstream | blocked by shield | lab 4xx/5xx | records |",
         "|---|---|---|---|---|---|"]
    for arm, m in results.items():
        t = m["attack"]["total"]
        L.append(f"| {ARMS[arm]['label']} | {t['sent']} | {t['reached_upstream']} | "
                 f"{t['blocked_by_shield']} | {t['lab_4xx_5xx']} | {m['records']} |")
    L += ["", "## Per stage (sent / reached / blocked by shield / lab 4xx-5xx)", "",
          "| Stage | " + " | ".join(ARMS[a]["label"] for a in results) + " |",
          "|---|" + "---|" * len(results)]
    for stage in STAGES:
        cells = []
        for m in results.values():
            s = m["attack"]["per_stage"][stage]
            cells.append(f"{s['sent']} / {s['reached_upstream']} / {s['blocked_by_shield']} / "
                         f"{s['lab_4xx_5xx']}")
        L.append(f"| {stage} | " + " | ".join(cells) + " |")
    L += ["", "## Intent accuracy (shield's own labels vs stage ground truth; unlabelled = miss)",
          "", "| Stage | " + " | ".join(ARMS[a]["label"] for a in results) + " |",
          "|---|" + "---|" * len(results)]
    for stage in STAGES:
        cells = []
        for m in results.values():
            ia = m["intent_accuracy"]
            cells.append("n/a" if not isinstance(ia, dict) else
                         f"{ia[stage]['correct']}/{ia[stage]['sent']} correct "
                         f"({ia[stage]['labelled']} labelled)")
        L.append(f"| {stage} | " + " | ".join(cells) + " |")
    c = results.get("C")
    if c:
        r = c["rules"]
        L += ["", "## Arm C: rules and time-to-protect", "",
              f"Proposed {r['proposed']}, activated {r['activated']}, rejected by the "
              f"benign-replay "
              f"gate {r['rejected_by_gate']}, escalations {r['escalations']}, rejected by the "
              f"compiler {r['compile_rejected']}. Rules proposed against the BENIGN client "
              f"(false-positive detections): {r['for_benign_client']}.", "",
              "| Stage | time-to-protect (s from stage's first request to first ACTIVE rule "
              "covering it) |", "|---|---|"]
        for stage in STAGES:
            v = c["time_to_protect"][stage]
            L.append(f"| {stage} | " + (v if isinstance(v, str) else
                     f"{v['seconds']}" + (" (rule already active before the stage began)"
                                          if v["pre_activated"] else "")) + " |")
        L += ["", "Activated rules:", ""]
        for d in r["detail"]:
            tag = "ACTIVE" if d["gate_passed"] else "REJECTED by gate"
            L.append(f"- {tag}: `{d['action']}` route `{d['route']}`"
                     + (f" param `{d['parameter']}`" if d["parameter"] else "")
                     + f" ({d['intent']})")
    L += ["", "## Benign traffic", "",
          "| Arm | sent | falsely blocked or altered (marker) | lab 4xx/5xx |", "|---|---|---|---|"]
    for arm, m in results.items():
        b = m["benign"]
        rule = (", rule " + ", ".join(b["blocked_by_rule"])) if b["blocked_by_rule"] else ""
        L.append(f"| {ARMS[arm]['label']} | {b['sent']} | "
                 f"{b['blocked_or_altered_by_shield']}{rule} | {b['lab_4xx_5xx']} |")
    L += ["", "## Latency (ms, shield overhead measured in the proxy over real HTTP)", "",
          "| Arm | shield p50 / p95 | client end-to-end p50 / p95 |", "|---|---|---|"]
    for arm, m in results.items():
        def fmt(v):
            return v if isinstance(v, str) else f"{v['p50_ms']} / {v['p95_ms']} (n={v['n']})"
        L.append(f"| {ARMS[arm]['label']} | {fmt(m['shield_latency'])} | "
                 f"{fmt(m['client_e2e_latency'])} |")
    L += ["", "## Suspiciously good numbers / caveats raised by the run", ""]
    L += [f"- {n}" for n in notes] or ["- none raised"]
    L += ["", "## Limitations", "",
          "- One scripted attacker, one run per arm, no repetition: no confidence intervals.",
          "- The per-request intent label comes from deterministic signals; requests that fire no "
          "signal are unlabelled and count as misses.",
          "- Rules take effect only after enough requests to fire a signal (behavioural signals "
          "need 5 to 10 requests), so early requests of a stage reach the lab before activation.",
          "- Every rule is scoped to the flagged client key (the `X-Lab-Client` header in lab "
          "mode), so benign false blocks of 0 reflect that scoping, not a general guarantee.",
          "- The benign-replay gate replays the benign set as if it came from the flagged client; "
          "rules on routes the benign set also uses are rejected and escalated, not activated.",
          "- Window signals are sticky per client: after the failed-login stage every later "
          "request from the same client still carries `repeated_failed_logins`, so object_enum "
          "and injection requests are labelled CREDENTIAL_GUESSING and get per-path "
          "`rate_limit_client` rules. Those rules block the right traffic for the wrong reason; "
          "the intent table shows the mislabelling.",
          "- `admin_probe` needs 5 hits on `/admin*` inside one window; this script sends 4, so "
          "that signal never fires and admin routes are labelled RECON.",
          "- `rate_limit_client` is enforced as a hard block on its route for that client "
          "(no counting window yet).",
          "- Lab 4xx/5xx counts include lab authentication errors and are not shield action.",
          "- Local loopback only; latency figures do not represent a networked deployment."]
    return "\n".join(L) + "\n"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    baseline: list[str] = []
    all_records: list[dict] = []
    results: dict[str, dict] = {}
    proxy: Proxy | None = None
    try:
        print(lab_script("lab_up.py", LAB))
        for arm, spec in ARMS.items():
            state = reset_lab(baseline)
            print(f"arm {arm}: lab reset, state hash {state}")
            stats = None
            if spec["proxy"]:
                proxy = Proxy(**spec["proxy"])
                proxy.start()
                print(f"arm {arm}: proxy healthy on {PROXY_URL} ({spec['proxy']['mode']})")
            recs = run_simulation(PROXY_URL if proxy else LAB_URL, LAB, arm, proxy is not None)
            if proxy:
                stats = proxy.stats()
                proxy.stop()
                proxy = None
            all_records += recs
            results[arm] = arm_metrics(arm, recs, stats)
            print(f"arm {arm}: {len(recs)} records")
    except Exception as exc:  # noqa: BLE001 - stop loudly, report nothing
        print(f"RUN FAILED, no results reported: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        if proxy is not None:
            try:
                proxy.stop()
            except RunError as exc:
                print(f"cleanup: {exc}", file=sys.stderr)
        try:
            lab_script("lab_down.py", LAB)
        except RunError as exc:
            print(f"cleanup: {exc}", file=sys.stderr)
        for port in (18081, PROXY_PORT):
            if port_open(port):
                print(f"WARNING: port {port} still open after cleanup", file=sys.stderr)
    write_records(all_records, OUT / "requests.jsonl")
    notes = suspicious(results)
    stamp = datetime.now(UTC).isoformat(timespec="seconds")
    (OUT / "report.json").write_text(json.dumps(
        {"generated": stamp, "lab": LAB, "lab_state_hash": baseline[0], "arms": results,
         "caveats": notes}, indent=2, default=str), encoding="utf-8", newline="\n")
    (OUT / "report.md").write_text(render_md(results, notes, stamp), encoding="utf-8",
                                    newline="\n")
    print(f"wrote {len(all_records)} records to {OUT / 'requests.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
