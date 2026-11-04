"""Start, stop, reset, health-check and fingerprint the Site Guard labs.

Only processes and containers this module started (recorded in a pid file / compose project) are
ever stopped. Every lab listens on 127.0.0.1 ONLY; `assert_loopback_only` proves it by checking
the published binding and by trying to connect through every non-loopback address of this PC.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import psutil

ROOT = Path(__file__).resolve().parents[1]
LABS_DIR = ROOT / "labs"


@dataclass(frozen=True)
class Lab:
    name: str
    kind: str  # "docker" | "node"
    port: int
    project: str  # compose project name (docker only)
    db_name: str
    health: str = "/health.php"

    @property
    def dir(self) -> Path:
        return LABS_DIR / self.name

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def data_dir(self) -> Path:
        return self.dir / "data"

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_name


LABS: dict[str, Lab] = {lab.name: lab for lab in (
    Lab("vibe_shop_php", "docker", 18080, "vibe_shop", "shop.db", "/health.php"),
    Lab("vibe_shop_php_reference", "docker", 18082, "vibe_shop_ref", "shop.db", "/health.php"),
    Lab("vibe_notes_node", "node", 18081, "", "notes.db", "/health"),
    Lab("vibe_notes_node_reference", "node", 18083, "", "notes.db", "/health"),
)}


class LabError(RuntimeError):
    pass


def get(name: str) -> Lab:
    if name not in LABS:
        raise LabError(f"unknown lab {name!r}; choose one of {sorted(LABS)}")
    return LABS[name]


def _run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None, timeout: int = 600
         ) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, env={**os.environ, **(env or {})}, capture_output=True,
                          text=True, timeout=timeout, check=False)


def docker_running() -> bool:
    try:
        r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and bool(r.stdout.strip())


# ------------------------------------------------------------------ up / down
def _pid_file(lab: Lab) -> Path:
    return lab.dir / ".lab.pid"


def _node_exe() -> str:
    return shutil.which("node") or "node"


def _prepare_docker_data(lab: Lab) -> None:
    """Prepare only registered synthetic lab scratch storage for Apache's UID."""
    uploads = lab.data_dir / "uploads"
    expected = lab.dir.resolve() / "data"
    if (lab.dir.resolve().parent != LABS_DIR.resolve()
            or lab.data_dir.resolve() != expected or uploads.resolve() != expected / "uploads"):
        raise LabError("lab data directories must not redirect outside the lab")
    uploads.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        # The bind mount hides the image's /data ownership. This is synthetic
        # scratch data only: both Apache's container UID and the host runner
        # must write/remove fixture files. No source or production path is changed.
        lab.data_dir.chmod(0o777)
        uploads.chmod(0o777)


def up(name: str, timeout: float = 90.0) -> Lab:
    lab = get(name)
    if lab.kind == "docker":
        # the image symlinks its upload directory to /data/uploads, and ./data is bind-mounted
        # over /data at container start; without this, a fresh/reset ./data has no "uploads"
        # subfolder yet, so the symlink inside the container points nowhere and Apache serves
        # every path under it as 403 Forbidden instead of actually storing/serving a file.
        _prepare_docker_data(lab)
        r = _run(["docker", "compose", "-p", lab.project, "up", "-d", "--build"], lab.dir,
                 {"SHOP_PORT": str(lab.port)})
        if r.returncode != 0:
            raise LabError(f"docker compose up failed:\n{r.stderr[-1500:]}")
        probe = _run([
            "docker", "compose", "-p", lab.project, "exec", "-T", "--user", "www-data",
            "shop", "php", "-r",
            'if (!in_array("sqlite", PDO::getAvailableDrivers(), true)) '
            '{fwrite(STDERR,"SQLITE_DRIVER_MISSING");exit(2);} '
            'if (!is_writable("/data") || !is_writable("/data/uploads")) '
            '{fwrite(STDERR,"LAB_DATA_NOT_WRITABLE");exit(3);}',
        ], lab.dir, {"SHOP_PORT": str(lab.port)})
        if probe.returncode != 0:
            category = next((c for c in ("SQLITE_DRIVER_MISSING", "LAB_DATA_NOT_WRITABLE")
                             if c in probe.stderr), "CONTAINER_PREFLIGHT_FAILED")
            raise LabError(f"{name}: {category}")
    else:
        if not (lab.dir / "node_modules").is_dir():
            npm = shutil.which("npm") or "npm"
            r = _run([npm, "install", "--omit=dev", "--no-audit", "--no-fund"], lab.dir)
            if r.returncode != 0:
                raise LabError(f"npm install failed:\n{r.stderr[-1500:]}")
        if _node_alive(lab):
            return wait_healthy(lab, timeout)
        lab.data_dir.mkdir(exist_ok=True)
        log = open(lab.dir / "lab.log", "ab")  # noqa: SIM115 (kept open for the child)
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        proc = subprocess.Popen(
            [_node_exe(), "--no-warnings", "server.js"], cwd=lab.dir, stdout=log, stderr=log,
            env={**os.environ, "NOTES_PORT": str(lab.port), "NOTES_DB": str(lab.db_path)},
            creationflags=flags)
        _pid_file(lab).write_text(str(proc.pid), encoding="utf-8")
    return wait_healthy(lab, timeout)


def _is_lab_process(proc: psutil.Process, lab: Lab) -> bool:
    """A PID file alone is not ownership proof after PID reuse."""
    if "node" not in proc.name().lower() or Path(proc.cwd()).resolve() != lab.dir.resolve():
        return False
    expected = (lab.dir / "server.js").resolve()
    return any((lab.dir / arg).resolve() == expected for arg in proc.cmdline()[1:]
               if not arg.startswith("-"))


def _node_alive(lab: Lab) -> bool:
    pf = _pid_file(lab)
    if not pf.exists():
        return False
    try:
        proc = psutil.Process(int(pf.read_text(encoding="utf-8")))
        return proc.is_running() and _is_lab_process(proc, lab)
    except (psutil.Error, ValueError):
        return False


def down(name: str) -> None:
    lab = get(name)
    if lab.kind == "docker":
        _run(["docker", "compose", "-p", lab.project, "down", "--remove-orphans"], lab.dir,
             {"SHOP_PORT": str(lab.port)})
        return
    pf = _pid_file(lab)
    if pf.exists():
        try:
            proc = psutil.Process(int(pf.read_text(encoding="utf-8")))
            if _is_lab_process(proc, lab):
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except psutil.TimeoutExpired:
                    proc.kill()
            else:
                raise LabError(f"{name}: recorded PID is not this lab; refusing termination")
        except (psutil.Error, ValueError):
            pass
        pf.unlink(missing_ok=True)


def wait_healthy(lab: Lab, timeout: float = 90.0) -> Lab:
    deadline, last = time.monotonic() + timeout, "no answer"
    while time.monotonic() < deadline:
        try:
            r = httpx.get(lab.base_url + lab.health, timeout=3)
            if r.status_code == 200:
                return lab
            last = f"HTTP {r.status_code}"
        except httpx.HTTPError as exc:
            last = type(exc).__name__
        time.sleep(0.5)
    raise LabError(f"{lab.name} did not become healthy on {lab.base_url}: {last}")


# ------------------------------------------------------------------ loopback proof
def non_loopback_addresses() -> list[str]:
    out: list[str] = []
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
                out.append(a.address)
    return sorted(set(out))


def _socket_owner_pid(port: int, host: str = "127.0.0.1") -> int | None:
    """Return the PID that owns a TCP listening socket on ``host:port``, or
    None.

    Uses psutil to inspect each process's connections. On Windows,
    netstat -ano often reports PID 0 for kernel-owned sockets, and
    psutil.net_connections() does not reliably report LISTEN sockets, so
    we check each process's connections for a TCP (SOCK_STREAM) socket in
    LISTEN state on the target host:port.

    UDP sockets, non-LISTEN TCP connections, and connections on unrelated
    addresses (different local address or address family) are explicitly
    ignored: they do not establish listener ownership. Returns None only
    when ownership cannot be determined.
    """
    for _attempt in range(20):
        try:
            for proc in psutil.process_iter(["pid"]):
                try:
                    conns = proc.net_connections(kind="inet")
                    for c in conns:
                        if c.laddr[1] != port or c.laddr[0] != host:
                            continue
                        # Require TCP (SOCK_STREAM) and LISTEN state.
                        # On Windows, psutil reports listening sockets with
                        # status CONN_NONE ('NONE') rather than CONN_LISTEN
                        # ('LISTEN'), so accept both.
                        if c.type != socket.SOCK_STREAM:
                            continue
                        if c.status not in (
                            psutil.CONN_LISTEN,
                            psutil.CONN_NONE,
                        ):
                            continue
                        return proc.info["pid"]
                except (psutil.AccessDenied, psutil.NoSuchProcess,
                        psutil.ZombieProcess):
                    continue
        except Exception:
            pass
        time.sleep(0.5)
    return None
def assert_loopback_only(name: str) -> dict[str, object]:
    """Raise unless the lab is bound to 127.0.0.1 and refuses every non-loopback address."""
    lab = get(name)
    if lab.kind == "docker":
        r = _run(["docker", "compose", "-p", lab.project, "ps", "-q"], lab.dir,
                 {"SHOP_PORT": str(lab.port)})
        cid = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
        if not cid:
            raise LabError(f"{name}: no running container")
        info = json.loads(_run(["docker", "inspect", cid], lab.dir).stdout)[0]
        bindings = info["HostConfig"]["PortBindings"]
        hosts = {b["HostIp"] for v in bindings.values() for b in v}
        if hosts != {"127.0.0.1"}:
            raise LabError(f"{name}: published on {hosts}, expected only 127.0.0.1")
        published = {f'{b["HostIp"]}:{b["HostPort"]}' for v in bindings.values() for b in v}
    else:
        pf = _pid_file(lab)
        if not pf.exists():
            raise LabError(f"{name}: not started by labctl")
        pid = int(pf.read_text(encoding="utf-8"))
        proc = psutil.Process(pid)
        # Verify the recorded process is our node server (not a stray process).
        if not _is_lab_process(proc, lab):
            raise LabError(f"{name}: recorded PID is not the lab server")
        # Prove process ownership: the pid-file PID must own the listening socket
        # on the lab's expected host:port (127.0.0.1:port), not merely any socket
        # on that port number.
        socket_owner_pid = _socket_owner_pid(lab.port, host="127.0.0.1")
        if socket_owner_pid is None:
            raise LabError(
                f"{name}: could not determine socket-owning PID for "
                f"127.0.0.1:{lab.port}; "
                f"refusing to assert loopback-only without process-ownership proof"
            )
        if socket_owner_pid != pid:
            raise LabError(
                f"{name}: socket on 127.0.0.1:{lab.port} owned by PID "
                f"{socket_owner_pid}, but pid file records PID {pid}"
            )
        # A wildcard bind conflicts with a loopback listener on Linux too;
        # bind failure cannot distinguish the two. Inspect the verified owner's
        # actual listening addresses instead, and still probe local interfaces.
        try:
            listeners = {c.laddr[0] for c in proc.net_connections(kind="inet")
                         if c.type == socket.SOCK_STREAM and c.laddr
                         and c.laddr[1] == lab.port
                         and c.status in (psutil.CONN_LISTEN, psutil.CONN_NONE)}
        except (psutil.Error, OSError) as exc:
            raise LabError(f"{name}: cannot inspect owned listeners") from exc
        if listeners != {"127.0.0.1"}:
            raise LabError(f"{name}: unexpected listening addresses: {sorted(listeners)}")
        published = {f"127.0.0.1:{lab.port}"}
    refused: dict[str, str] = {}
    for ip in non_loopback_addresses():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            code = s.connect_ex((ip, lab.port))
        finally:
            s.close()
        if code == 0:
            raise LabError(f"{name}: reachable through non-loopback address {ip}:{lab.port}")
        refused[ip] = f"refused/unreachable (errno {code})"
    return {"published": sorted(published), "non_loopback_checked": refused}


# ------------------------------------------------------------------ state hash and reset
SKIP_COLUMNS = {"pass_hash"}  # salted hashes differ per seeding
SKIP_TABLES = {"login_attempts", "sqlite_sequence"}


def state_hash(name: str) -> str:
    """SHA-256 over every table of the lab database (ordered; salted password hashes excluded)
    plus the sorted names of uploaded files."""
    lab = get(name)
    if not lab.db_path.exists():
        raise LabError(f"{name}: no database yet at {lab.db_path}")
    con = sqlite3.connect(f"file:{lab.db_path.as_posix()}?mode=ro", uri=True)
    try:
        h = hashlib.sha256()
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        for t in tables:
            if t in SKIP_TABLES:
                continue
            info = con.execute(f"PRAGMA table_info({t})")
            cols = [c[1] for c in info if c[1] not in SKIP_COLUMNS]
            h.update(f"table:{t}:{cols}\n".encode())
            order = ", ".join(cols)
            for row in con.execute(f"SELECT {order} FROM {t} ORDER BY {order}"):  # noqa: S608
                h.update(json.dumps(row, default=str).encode() + b"\n")
    finally:
        con.close()
    uploads = lab.data_dir / "uploads"
    names = sorted(p.name for p in uploads.iterdir()) if uploads.is_dir() else []
    h.update(json.dumps(names).encode())
    return h.hexdigest()


def reset(name: str) -> str:
    """Restore the seeded state (fresh database + empty uploads) and return the state hash."""
    lab = get(name)
    down(name)
    if lab.data_dir.exists():
        shutil.rmtree(lab.data_dir, ignore_errors=False)
    lab.data_dir.mkdir(parents=True, exist_ok=True)
    up(name)
    return state_hash(name)
