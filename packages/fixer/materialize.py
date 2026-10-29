"""Part D helper: turn a (patched) fix scope back into a RUNNABLE lab instance, on its own
loopback port, for independent verification. Never touches the original lab directory or its
running instance; this is a disposable, throwaway copy that is torn down afterward."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx

from apps.labctl import docker_running

from .models import RepoScope

REPO_ROOT = Path(__file__).resolve().parents[2]
LABS_ROOT = REPO_ROOT / "labs"
# Mirrors apps/labctl.py's own exclusions for what is NOT source (plus PLANTED.json and
# *_reference, which this module must never read either).
_EXCLUDE = {"node_modules", "data", "__pycache__", ".git", "lab.log", "PLANTED.json"}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class VerifyInstance:
    lab: str
    kind: str  # "docker" | "node"
    base_url: str
    health: str
    work_dir: Path
    _process: subprocess.Popen | None = None
    _compose_project: str | None = None

    def stop(self) -> None:
        if self.kind == "node" and self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
        elif self.kind == "docker" and self._compose_project is not None:
            subprocess.run(["docker", "compose", "-p", self._compose_project, "down",
                           "--remove-orphans", "-v"], cwd=self.work_dir, capture_output=True,
                           text=True, timeout=120, check=False)
        shutil.rmtree(self.work_dir, ignore_errors=True)


def _copy_lab_shell(lab: str, dest: Path) -> None:
    source = LABS_ROOT / lab
    dest.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        if item.name in _EXCLUDE:
            continue
        target = dest / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def _overlay_scope(scope: RepoScope, dest_source_dir: Path) -> None:
    """Copy the (possibly patched) fix scope's current files over the materialized copy's
    matching source location."""
    for item in scope.work_dir.rglob("*"):
        if item.is_dir() or ".git" in item.parts:
            continue
        rel = item.relative_to(scope.work_dir)
        target = dest_source_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target)


def materialize_php(scope: RepoScope, *, timeout: float = 90.0) -> VerifyInstance:
    if not docker_running():
        raise RuntimeError("Docker is not running - PHP verification needs it")
    work_dir = Path(tempfile.mkdtemp(prefix="sentinelx_verify_"))
    _copy_lab_shell(scope.lab, work_dir)
    _overlay_scope(scope, work_dir / "app")
    port = _free_port()
    project = f"sxfix{uuid.uuid4().hex[:10]}"
    r = subprocess.run(["docker", "compose", "-p", project, "up", "-d", "--build"],
                      cwd=work_dir, env={**os.environ, "SHOP_PORT": str(port)},
                      capture_output=True, text=True, timeout=300)
    inst = VerifyInstance(lab=scope.lab, kind="docker", base_url=f"http://127.0.0.1:{port}",
                         health="/health.php", work_dir=work_dir, _compose_project=project)
    if r.returncode != 0:
        inst.stop()
        raise RuntimeError(f"docker compose up failed: {r.stderr[-1500:]}")
    _wait_healthy(inst, timeout)
    return inst


def materialize_node(scope: RepoScope, *, timeout: float = 60.0) -> VerifyInstance:
    work_dir = Path(tempfile.mkdtemp(prefix="sentinelx_verify_"))
    _copy_lab_shell(scope.lab, work_dir)
    _overlay_scope(scope, work_dir)
    port = _free_port()
    original_node_modules = LABS_ROOT / scope.lab / "node_modules"
    data_dir = work_dir / "data"
    data_dir.mkdir(exist_ok=True)
    log = (work_dir / "verify.log").open("ab")
    proc = subprocess.Popen(
        [shutil.which("node") or "node", "--no-warnings", "server.js"], cwd=work_dir,
        stdout=log, stderr=log,
        env={**os.environ, "NOTES_PORT": str(port), "NOTES_DB": str(data_dir / "notes.db"),
            "NODE_PATH": str(original_node_modules)},
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0)
    inst = VerifyInstance(lab=scope.lab, kind="node", base_url=f"http://127.0.0.1:{port}",
                         health="/health", work_dir=work_dir, _process=proc)
    _wait_healthy(inst, timeout)
    return inst


def _wait_healthy(inst: VerifyInstance, timeout: float) -> None:
    deadline, last = time.monotonic() + timeout, "no answer"
    while time.monotonic() < deadline:
        try:
            r = httpx.get(inst.base_url + inst.health, timeout=3)
            if r.status_code == 200:
                return
            last = f"HTTP {r.status_code}"
        except httpx.HTTPError as exc:
            last = type(exc).__name__
        time.sleep(0.5)
    inst.stop()
    raise RuntimeError(f"verification instance never became healthy: {last}")


def materialize(scope: RepoScope, **kwargs) -> VerifyInstance:
    is_php = (LABS_ROOT / scope.lab / "app").is_dir()
    return materialize_php(scope, **kwargs) if is_php else materialize_node(scope, **kwargs)
