"""Run the lab on 127.0.0.1 with an OS-chosen port (port 0), in a background thread."""

from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

import uvicorn

from .app import create_app
from .state import LabState

ADMIN_TOKEN_ENV = "SENTINELX_LAB_ADMIN_TOKEN"


class LabServer:
    """Starts/stops the lab. The admin token comes from the environment, else it is random."""

    def __init__(self, ledger_dir: Path, admin_token: str | None = None) -> None:
        token = admin_token or os.environ.get(ADMIN_TOKEN_ENV) or secrets.token_hex(16)
        self.state = LabState(ledger_dir, token)
        self.app = create_app(self.state)
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self.state.port

    @property
    def admin_token(self) -> str:
        return self.state.admin_token

    def start(self, timeout: float = 15.0) -> LabServer:
        config = uvicorn.Config(self.app, host="127.0.0.1", port=0, log_level="warning",
                                access_log=False, lifespan="off")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, name="lab-server", daemon=True)
        thread.start()
        deadline = time.monotonic() + timeout
        while not server.started:
            if time.monotonic() > deadline or not thread.is_alive():
                raise RuntimeError("lab server failed to start")
            time.sleep(0.02)
        sockets: Any = server.servers[0].sockets
        self.state.port = sockets[0].getsockname()[1]
        self._server, self._thread = server, thread
        return self

    def stop(self, timeout: float = 10.0) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout)
        self._server = self._thread = None

    def __enter__(self) -> LabServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ---- LabHandle surface used by the runtime (see sentinelx.agent_runtime.lab) ----------
    def reset(self, scenario_id: str, seed: int | None = None) -> str:
        return self.state.reset(scenario_id, seed)

    @property
    def fixture_hash(self) -> str:
        return self.state.fixture_hash

    def read_ledger(self) -> list[dict[str, Any]]:
        return self.state.read_ledger()
