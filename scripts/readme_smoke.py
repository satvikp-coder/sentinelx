#!/usr/bin/env python3
"""Run the exact commands from README.md's two quickstart sections, end to end.

Agent section: pip installs, the SDK example, `sentinelx agent check`.
Site section (Node lab): lab up, reset, init, site add --lab, site verify, site scan,
lab up again, `sentinelx site guard` in monitor mode + one benign request through it,
site report, shield list, lab down.

Exits 0 only if every step succeeds. Always stops the lab and the proxy (no leftover
listeners on 18081 or 18090), even on failure. No model calls, no network beyond localhost.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
LAB = "vibe_notes_node"
UPSTREAM = "http://127.0.0.1:18081"
GUARD_LISTEN = "127.0.0.1:18090"


class SmokeFailure(RuntimeError):
    pass


def cli_exe() -> list[str]:
    """The installed `sentinelx` console script (falls back to module invocation)."""
    name = "sentinelx.exe" if os.name == "nt" else "sentinelx"
    exe = Path(PY).with_name(name)
    if exe.is_file():
        return [str(exe)]
    return [PY, "-c", "import sys; from sentinelx_cli.main import main; sys.exit(main())"]


def run(args: list[str], cwd: Path | None = None, timeout: int = 900,
        expect_zero: bool = True) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(args)}", flush=True)
    result = subprocess.run(args, cwd=str(cwd or ROOT), capture_output=True, text=True,
                            timeout=timeout)
    tail = (result.stdout or "")[-1200:]
    if tail:
        print(tail, flush=True)
    if expect_zero and result.returncode != 0:
        raise SmokeFailure(f"command failed ({result.returncode}): {' '.join(args)}\n"
                           f"stderr: {(result.stderr or '')[-800:]}")
    return result


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_port(port: int, up: bool, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open(port) is up:
            return True
        time.sleep(0.3)
    return False


_GUARD_PROC: subprocess.Popen | None = None


def kill_tree(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        import psutil

        parent = psutil.Process(proc.pid)
        children = parent.children(recursive=True)
        for child in children:
            child.terminate()
        parent.terminate()
        gone, alive = psutil.wait_procs([parent, *children], timeout=8)
        for p in alive:
            p.kill()
    except Exception:  # best effort; the final port check reports the truth
        proc.terminate()


def cleanup() -> None:
    global _GUARD_PROC
    kill_tree(_GUARD_PROC)
    _GUARD_PROC = None
    run([PY, "scripts/lab_down.py", LAB], expect_zero=False)
    for port in (18081, 18090):
        if port_open(port) and not wait_port(port, up=False, timeout=10):
            print(f"WARNING: port {port} still open after cleanup", flush=True)


def agent_section(tmp: Path) -> None:
    run([PY, "-m", "pip", "install", "-e", "."], timeout=600)
    run([PY, "-m", "pip", "install", "-e", "sdk/python"], timeout=600)
    example = run([PY, "examples/agent_guard_basic.py"])
    assert "BLOCKED:" in example.stdout and "COMPLETED:" in example.stdout, \
        "example did not print BLOCKED/COMPLETED"
    action = tmp / "action.json"
    action.write_text(
        '{"tool": "navigate", "arguments": {"url": "http://orders.lab.test/cart"}, '
        '"allowed_hosts": ["orders.lab.test"]}\n', encoding="utf-8")
    check = run([*cli_exe(), "agent", "check", "--policy",
                 str(ROOT / "configs" / "policy" / "default.yaml"),
                 "--action", str(action)])
    assert "decision: ALLOW" in check.stdout, "agent check did not ALLOW the in-scope action"


def site_section(tmp: Path) -> None:
    global _GUARD_PROC
    run([PY, "scripts/lab_up.py", LAB], timeout=300)
    run([PY, "scripts/lab_reset.py", LAB], timeout=300)
    run([*cli_exe(), "init"], cwd=tmp)
    run([*cli_exe(), "site", "add", UPSTREAM, "--lab"], cwd=tmp)
    run([*cli_exe(), "site", "verify", LAB], cwd=tmp)
    run([*cli_exe(), "site", "scan", LAB], cwd=tmp, timeout=900)
    # run_scan stops the lab when it finishes; bring it back for the guard demo
    run([PY, "scripts/lab_up.py", LAB], timeout=300)

    print(f"$ sentinelx site guard --upstream {UPSTREAM} --listen {GUARD_LISTEN} --mode monitor"
          "   (background)", flush=True)
    _GUARD_PROC = subprocess.Popen(
        [*cli_exe(), "site", "guard", "--upstream", UPSTREAM, "--listen", GUARD_LISTEN,
         "--mode", "monitor"],
        cwd=str(tmp), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if not wait_port(18090, up=True, timeout=40):
        raise SmokeFailure("shield proxy did not open 127.0.0.1:18090")

    import httpx

    response = httpx.get("http://127.0.0.1:18090/health", timeout=15)
    print(f"benign request through the shield: HTTP {response.status_code}", flush=True)
    if response.status_code != 200:
        raise SmokeFailure(f"benign request through the shield failed: {response.status_code}")
    kill_tree(_GUARD_PROC)
    _GUARD_PROC = None
    if not wait_port(18090, up=False, timeout=15):
        raise SmokeFailure("shield proxy did not stop on 18090")

    run([*cli_exe(), "site", "report", LAB], cwd=tmp)
    run([*cli_exe(), "shield", "list"], cwd=tmp)
    run([PY, "scripts/lab_down.py", LAB])


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sentinelx-smoke-"))
    print(f"work dir: {tmp}", flush=True)
    try:
        agent_section(tmp)
        site_section(tmp)
    except SmokeFailure as exc:
        print(f"\nSMOKE FAILED: {exc}", file=sys.stderr, flush=True)
        return 1
    except Exception as exc:  # noqa: BLE001 - any crash must still clean up
        print(f"\nSMOKE CRASHED: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 1
    finally:
        cleanup()
    print("\nREADME smoke: all steps passed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
