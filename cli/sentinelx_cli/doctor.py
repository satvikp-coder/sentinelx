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


def doctor_cmd(args) -> int:
    """Run environment and configuration checks."""
    print("SentinelX Doctor")
    print("=" * 50)

    all_ok = True

    # Python version
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    print(f"Python: {py_version}")
    if sys.version_info < (3, 11):
        print("  ERROR: Python 3.11+ required")
        all_ok = False
    else:
        print("  OK")

    # Docker
    docker_path = shutil.which("docker")
    if docker_path:
        try:
            result = subprocess.run(["docker", "version", "--format", "{{.ServerVersion}}"],
                                    capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"Docker: {result.stdout.strip()} (installed at {docker_path})")
            else:
                print(f"Docker: installed at {docker_path} but daemon not reachable")
        except Exception as e:
            print(f"Docker: installed at {docker_path} but error: {e}")
    else:
        print("Docker: NOT INSTALLED")

    # Node
    node_path = shutil.which("node")
    if node_path:
        try:
            result = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"Node: {result.stdout.strip()} (at {node_path})")
            else:
                print(f"Node: at {node_path} but version check failed")
        except Exception as e:
            print(f"Node: at {node_path} but error: {e}")
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
        print(f"Evidence DB: {db_path} (will be created)")
        # Check parent directory writable
        parent_writable = os.access(db_path.parent, os.W_OK)
        if not parent_writable:
            print("  WARNING: parent directory not writable")
            all_ok = False

    # Model profile from environment
    print("\nModel config (from environment):")
    model_vars = {
        "MODEL_PROVIDER": "provider",
        "MODEL_BASE_URL": "base_url",
        "MODEL_NAME": "model",
        "MODEL_API_KEY": "api_key",
        "MODEL_PROVIDER": "provider",
    }
    # Check for any MODEL_* env vars
    model_keys = [k for k in os.environ if k.startswith("MODEL_")]
    if model_keys:
        for k in sorted(model_keys):
            v = os.environ[k]
            if "KEY" in k or "TOKEN" in k or "SECRET" in k:
                display = "set" if v else "NOT set"
            else:
                display = v if v else "NOT set"
            print(f"  {k}: {display}")
    else:
        print("  No MODEL_* environment variables set")

    # Lab ports
    print("\nLab ports:")
    for port, name in [(18080, "vibe_shop_php"), (18081, "vibe_notes_node"), (18090, "shield_proxy")]:
        free = check_port_free(port)
        print(f"  Port {port} ({name}): {'FREE' if free else 'IN USE'}")

    print("\n" + "=" * 50)
    if all_ok:
        print("All checks PASSED")
        return 0
    else:
        print("Some checks FAILED")
        return 1
