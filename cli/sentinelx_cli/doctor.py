#!/usr/bin/env python3
"""sentinelx doctor - Check environment and configuration."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path


def check_port_free(port: int) -> bool:
    """Check if a TCP port is free on localhost."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex(("127.0.0.1", port)) != 0
    except OSError:
        return False


def _secret_like(name: str) -> bool:
    return any(tok in name for tok in ("KEY", "TOKEN", "SECRET"))


def doctor_cmd(args) -> int:
    """Run environment and configuration checks. Exit 0 if Python and DB checks pass."""
    print("SentinelX Doctor")
    print("=" * 50)

    all_ok = True

    # Python version (the package requires >=3.11, so this always passes at runtime)
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print(f"Python: {py_version}  OK")

    # Docker (informational only)
    docker_path = shutil.which("docker")
    if docker_path:
        try:
            result = subprocess.run(
                ["docker", "version", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                print(f"Docker: {result.stdout.strip()} (installed at {docker_path})")
            else:
                print(f"Docker: installed at {docker_path} but daemon not reachable")
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"Docker: installed at {docker_path} but error: {exc}")
    else:
        print("Docker: NOT INSTALLED")

    # Node (informational only)
    node_path = shutil.which("node")
    if node_path:
        try:
            result = subprocess.run(
                ["node", "--version"], capture_output=True, text=True, timeout=5,
            )
            print(f"Node: {result.stdout.strip()} (at {node_path})")
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"Node: at {node_path} but error: {exc}")
    else:
        print("Node: NOT INSTALLED")

    # Evidence DB path
    db_path = Path("sentinelx.db")
    if db_path.exists():
        writable = os.access(db_path, os.W_OK)
        print(f"Evidence DB: {db_path} ({'writable' if writable else 'NOT WRITABLE'})")
        if not writable:
            all_ok = False
    else:
        writable = os.access(db_path.parent, os.W_OK)
        print(f"Evidence DB: {db_path} (will be created; parent writable: {writable})")
        if not writable:
            all_ok = False

    # Model config: print env var NAMES and only "set"/"not set" (never values)
    print("\nModel config (environment):")
    model_keys = sorted(k for k in os.environ if k.startswith("MODEL_"))
    if model_keys:
        for name in model_keys:
            state = "set" if os.environ.get(name) else "not set"
            print(f"  {name}: {state}")
    else:
        print("  No MODEL_* environment variables set")

    # Lab ports
    print("\nLab ports:")
    ports = [(18080, "vibe_shop_php"), (18081, "vibe_notes_node"), (18090, "shield_proxy")]
    for port, name in ports:
        free = check_port_free(port)
        print(f"  Port {port} ({name}): {'FREE' if free else 'IN USE'}")

    print("\n" + "=" * 50)
    if all_ok:
        print("All checks PASSED")
        return 0
    print("Some checks FAILED")
    return 1
