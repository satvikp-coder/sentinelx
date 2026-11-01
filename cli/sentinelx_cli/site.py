#!/usr/bin/env python3
"""sentinelx site - manage Site Guard targets (lab targets only in this version)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from sentinelx.scanner.authz import (
    AuthzConfig,
    is_lab_host,
    new_verification_token,
    register_lab_target,
    register_non_lab_target,
)

from .repo import repo_root, run_script

TARGETS_FILE = Path("sentinelx.targets.json")
LABS = {  # known lab ports (from apps/labctl.py); lab-only version
    18080: "vibe_shop_php", 18081: "vibe_notes_node",
    18082: "vibe_shop_php_reference", 18083: "vibe_notes_node_reference",
}
STATE_LABELS = {"confirmed": "VERIFIED", "needs_validation": "INFERRED",
                "rejected": "REJECTED"}


def _load_targets() -> dict:
    if TARGETS_FILE.is_file():
        try:
            return json.loads(TARGETS_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save_targets(targets: dict) -> None:
    TARGETS_FILE.write_text(json.dumps(targets, indent=2, sort_keys=True), encoding="utf-8")


def _allow_non_lab() -> bool:
    import os

    return os.environ.get("ALLOW_NON_LAB_TARGETS", "").lower() in ("1", "true", "yes")


def site_cmd(args, subcmd: str) -> int:
    handlers = {
        "add": _add, "verify": _verify, "scan": _scan,
        "fix": _fix, "guard": _guard, "report": _report,
    }
    if subcmd not in handlers:
        print(f"Unknown site command: {subcmd}", file=sys.stderr)
        return 1
    return handlers[subcmd](args)


def _add(args) -> int:
    parsed = urlparse(args.url)
    host = parsed.hostname or ""
    if not host:
        print(f"ERROR: could not parse a host from {args.url!r}", file=sys.stderr)
        return 2
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if args.lab:
        if not is_lab_host(host):
            print(f"ERROR: --lab only allowed for localhost, 127.0.0.1, ::1 or *.lab.test "
                  f"(got {host!r})", file=sys.stderr)
            return 2
        target_id = LABS.get(port, host)
        register_lab_target(target_id, [host], [port], schemes=[parsed.scheme or "http"])
        targets = _load_targets()
        targets[target_id] = {"url": args.url, "lab": True}
        _save_targets(targets)
        print(f"registered lab target: {target_id} -> {args.url} (auto-verified)")
        return 0

    # Non-lab: print ownership token + instructions; never scan here.
    token, _token_hash = new_verification_token()
    well_known = f"{parsed.scheme}://{host}:{port}/.well-known/sentinelx-verify.txt"
    print(f"ownership token: {token}")
    print(f"serve exactly this token at: {well_known}")
    if _allow_non_lab():
        config = AuthzConfig(allow_non_lab_targets=True)
        target = register_non_lab_target(config, host, host, port, scheme=parsed.scheme or "https")
        _ = target  # starts PENDING; served token + `site verify` would complete verification
        print("ALLOW_NON_LAB_TARGETS is enabled; target registered as PENDING (verify to finish)")
    else:
        print("non-lab scanning is DISABLED unless ALLOW_NON_LAB_TARGETS=true")
        print("nothing was scanned or registered")
    return 0


def _verify(args) -> int:
    targets = _load_targets()
    entry = targets.get(args.target_id)
    if entry is None:
        print(f"ERROR: unknown target {args.target_id!r} (run `sentinelx site add`)",
              file=sys.stderr)
        return 1
    if entry.get("lab"):
        print(f"{args.target_id}: lab targets are auto-verified at registration")
        return 0
    print(f"{args.target_id}: non-lab verification needs the served well-known token fetch; "
          "not implemented in this lab-only version", file=sys.stderr)
    return 1


def _scan(args) -> int:
    target_id = args.target_id
    if target_id not in LABS.values():
        print(f"ERROR: scan needs a known lab target name "
              f"({', '.join(sorted(set(LABS.values())))})", file=sys.stderr)
        return 1
    print(f"scanning {target_id} via scripts/run_scan.py ...")
    return run_script("run_scan.py", ["--target", target_id])


def _fix(args) -> int:
    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"ERROR: --repo must be an existing local directory: {args.repo}", file=sys.stderr)
        return 1
    report = _latest_scan_report(args.target_id)
    if report is None:
        print(f"ERROR: no scan report for {args.target_id!r}; run `sentinelx site scan` first",
              file=sys.stderr)
        return 1
    print(f"fixing {args.target_id} from {report}")
    print("note: the fix engine works on a disposable copy of the lab source "
          "(--repo validated only)")
    argv = ["--target", args.target_id, "--scan-report", str(report)]
    if getattr(args, "patch_format", None):
        argv += ["--patch-format", args.patch_format]
    return run_script("run_fix.py", argv)


def _guard(args) -> int:
    parsed = urlparse(args.upstream)
    host = parsed.hostname or ""
    if not is_lab_host(host):
        print(f"ERROR: upstream must be a lab target (localhost / 127.0.0.1 / *.lab.test), "
              f"got {host!r}", file=sys.stderr)
        return 2
    listen = args.listen
    lhost, _, lport = listen.rpartition(":")
    if not lhost or not lport.isdigit():
        print(f"ERROR: --listen must be host:port, got {listen!r}", file=sys.stderr)
        return 2
    import os

    env = dict(os.environ)
    env["SHIELD_UPSTREAM"] = args.upstream
    env["SHIELD_MODE"] = args.mode
    env["SHIELD_AUTO_SHIELD"] = "1" if args.auto_shield else "0"
    env["SHIELD_LAB_MODE"] = "1"
    root = repo_root()
    print(f"starting shield (uvicorn) on {listen} -> {args.upstream} "
          f"[mode={args.mode} auto_shield={args.auto_shield}]")
    cmd = [sys.executable, "-m", "uvicorn", "packages.shield.server:create_shield_app",
           "--factory", "--host", lhost, "--port", lport, "--log-level", "info"]
    try:
        return subprocess.run(cmd, cwd=root, env=env).returncode
    except KeyboardInterrupt:
        return 0


def _latest_scan_report(target_id: str) -> Path | None:
    root = repo_root() / "evaluations" / "scan_runs"
    best: tuple[float, Path] | None = None
    for report in root.glob("*/report.json"):
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("provenance", {}).get("target_id") == target_id:
            mtime = report.stat().st_mtime
            if best is None or mtime > best[0]:
                best = (mtime, report)
    return best[1] if best else None


def _report(args) -> int:
    report = _latest_scan_report(args.target_id)
    if report is None:
        print(f"no scan report for {args.target_id!r}", file=sys.stderr)
        return 1
    data = json.loads(report.read_text(encoding="utf-8"))
    prov = data.get("provenance", {})
    print(f"scan: {prov.get('date_utc')} session={prov.get('session_id')} "
          f"coverage={prov.get('coverage_percent')}% stop={prov.get('stop_reason')}")
    for f in data.get("findings", []):
        cand = f.get("candidate", {})
        state = f.get("verification", {}).get("state", "?")
        label = STATE_LABELS.get(state, state.upper())
        print(f"  {cand.get('id')} {cand.get('vuln_class')} {cand.get('method', '')} "
              f"{cand.get('endpoint', '')} state={state} [{label}]")
    fix_db = repo_root() / "evaluations" / "fix_runs" / "fix.sqlite"
    if fix_db.is_file():
        import sqlite3

        try:
            con = sqlite3.connect(f"file:{fix_db.as_posix()}?mode=ro", uri=True)
            rows = con.execute("SELECT body FROM escalations").fetchall()
            states = {}
            for (body,) in rows:
                status = json.loads(body).get("status", "?")
                states[status] = states.get(status, 0) + 1
            con.close()
            summary = ", ".join(f"{k}={v}" for k, v in sorted(states.items())) or "none"
            print(f"fix escalations: {len(rows)} ({summary})")
        except sqlite3.Error as exc:
            print(f"fix escalations: unreadable ({exc})")
    else:
        print("fix escalations: no fix runs yet")
    return 0
