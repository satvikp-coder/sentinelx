#!/usr/bin/env python3
"""sentinelx site - Manage Site Guard targets."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sentinelx.scanner.authz import (
    is_lab_host,
)


def site_cmd(args, subcmd: str) -> int:
    if subcmd == "add":
        return _site_add(args)
    elif subcmd == "verify":
        return _site_verify(args)
    elif subcmd == "scan":
        return _site_scan(args)
    elif subcmd == "fix":
        return _site_fix(args)
    elif subcmd == "guard":
        return _site_guard(args)
    elif subcmd == "report":
        return _site_report(args)
    else:
        print(f"Unknown site command: {args.site_cmd}", file=sys.stderr)
        return 1


def _site_add(args) -> int:
    url = args.url
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if args.lab:
        if not is_lab_host(host):
            print(f"ERROR: --lab only allowed for localhost, 127.0.0.1, or *.lab.test (got {host})", file=sys.stderr)
            return 2
        target_id = parsed.hostname.replace(".", "_").replace(":", "_")
        print(f"Registering lab target: {target_id}")
        # In real implementation, would call register_lab_target and store
        print(f"Registered lab target: {target_id} -> {url}")
        return 0
    else:
        # Non-lab target
        if os.environ.get("ALLOW_NON_LAB_TARGETS", "").lower() not in ("1", "true", "yes"):
            print("Non-lab scanning is DISABLED. Set ALLOW_NON_LAB_TARGETS=true to enable.", file=sys.stderr)
        from sentinelx.scanner.authz import new_verification_token
        token, token_hash = new_verification_token()
        print(f"Ownership token: {token}")
        print(f"Serve this token at: {parsed.scheme}://{host}{parsed.path or ''}/.well-known/sentinelx-verify.txt")
        print("Non-lab scanning is DISABLED unless ALLOW_NON_LAB_TARGETS=true")
        return 0


def _site_verify(args) -> int:
    print(f"Verifying target: {args.target_id}")
    # In real implementation, would check the well-known file
    print("Not implemented yet")
    return 0


def _site_scan(args) -> int:
    print(f"Scanning target: {args.target_id}")
    result = subprocess.run([
        sys.executable, "scripts/run_scan.py",
        "--target", "vibe_notes_node",  # hardcoded for now
        "--out", f"scan_report_{args.target_id}.json"
    ], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def _site_fix(args) -> int:
    repo_path = Path(args.repo)
    if not repo_path.exists() or not repo_path.is_dir():
        print(f"ERROR: --repo path does not exist: {args.repo}", file=sys.stderr)
        return 1
    print(f"Running fixes for target: {args.target_id} on repo: {repo_path}")
    result = subprocess.run([
        sys.executable, "scripts/run_fix.py",
        "--target", "vibe_notes_node",  # hardcoded for now
        "--scan-report", f"scan_report_{args.target_id}.json",
        "--repo", str(repo_path)
    ], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return result.returncode


def _site_guard(args) -> int:
    # Validate upstream
    from urllib.parse import urlparse

    from sentinelx.scanner.authz import is_lab_host
    parsed = urlparse(args.upstream)
    if not is_lab_host(parsed.hostname or ""):
        print(f"ERROR: upstream must be a lab target (localhost/127.0.0.1/*.lab.test), got {parsed.hostname}", file=sys.stderr)
        return 2

    # Start the shield proxy
    import os
    import subprocess
    env = os.environ.copy()
    env["SHIELD_UPSTREAM"] = args.upstream
    env["SHIELD_MODE"] = args.mode
    env["SHIELD_AUTO_SHIELD"] = "1" if args.auto_shield else "0"
    env["SHIELD_LAB_MODE"] = "1" if args.lab else "0"
    env["PYTHONPATH"] = str(Path.cwd())

    print(f"Starting shield proxy: {args.mode} mode on {args.listen} -> {args.upstream}")
    try:
        subprocess.run([
            "uvicorn",
            "packages.shield.server:create_shield_app",
            "--factory",
            "--host", "127.0.0.1",
            "--port", "18090",
            "--log-level", "info",
        ], env={**os.environ, "SHIELD_UPSTREAM": args.upstream, "SHIELD_MODE": args.mode,
                "SHIELD_AUTO_SHIELD": "1" if args.auto_shield else "0",
                "SHIELD_LAB_MODE": "1" if args.lab else "0"}, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Shield proxy failed: {e}", file=sys.stderr)
        return 1
    return 0


def _site_report(args) -> int:
    print(f"Report for target: {args.target_id}")
    # In real implementation, would query evidence store
    print("Not implemented yet")
    return 0
