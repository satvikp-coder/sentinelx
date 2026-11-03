"""ASGI factory that runs the shield as a real HTTP reverse proxy (``uvicorn --factory``).

Configuration comes from ``configs/shield/default.yaml`` with environment overrides
(SHIELD_UPSTREAM, SHIELD_MODE, SHIELD_AUTO_SHIELD, SHIELD_LAB_MODE, SHIELD_BENIGN_FILE).
Control plane (never forwarded): ``/__shield/health`` and ``/__shield/stats``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml

from sentinelx.common_schemas import Actor, ActorRole, SessionKind
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore

from .benign import load_benign_requests
from .config import ShieldConfig
from .detect import Detector
from .proxy import ShieldProxy
from .recorder import ShieldRecorder

ROOT = Path(__file__).resolve().parents[2]
CONTROL = "/__shield/"


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    return default if raw is None else raw.lower() in {"1", "true", "yes"}


def build_config() -> ShieldConfig:
    data = yaml.safe_load((ROOT / "configs/shield/default.yaml").read_text(encoding="utf-8"))
    data["upstream"] = os.environ.get("SHIELD_UPSTREAM", data["upstream"])
    data["mode"] = os.environ.get("SHIELD_MODE", data["mode"])
    data["auto_shield"] = _flag("SHIELD_AUTO_SHIELD", data["auto_shield"])
    data["lab_mode"] = _flag("SHIELD_LAB_MODE", data["lab_mode"])
    return ShieldConfig.model_validate(data)


class ShieldApp:
    def __init__(self, proxy: ShieldProxy) -> None:
        self.proxy = proxy

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                else:
                    await self.proxy.aclose()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] == "http" and scope["path"].startswith(CONTROL):
            name = scope["path"][len(CONTROL):]
            if name == "health":
                body: dict[str, Any] | None = {"ok": True, "mode": self.proxy.config.mode}
            elif name == "counter":
                body = {"forwarded": self.proxy.forwarded, "blocked": self.proxy.blocked}
            elif name == "stats":
                body = self.proxy.stats()
            else:
                body = None
            await send({"type": "http.response.start", "status": 200 if body else 404,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body",
                        "body": json.dumps(body or {"error": "not found"}).encode()})
            return
        await self.proxy(scope, receive, send)


def build_app(config: ShieldConfig, benign: list[dict[str, Any]] | None = None,
              runtime_store: Any = None) -> ShieldApp:
    conn = connect(":memory:")
    migrate(conn)
    store = EvidenceStore(conn)
    session, _ = SessionService(conn).create(
        kind=SessionKind.GUARD, policy_version="1.0",
        actor=Actor(id="shield", role=ActorRole.SYSTEM))
    detector = Detector.load(str(ROOT / "configs/shield/signals.yaml"))
    recorder = ShieldRecorder(store, session.id, config.evidence_batch_interval_s,
                              config.suspicious_rate_cap_per_min)
    return ShieldApp(ShieldProxy(config, store, session.id, detector, recorder,
                                 benign_requests=benign, runtime_store=runtime_store))


def create_shield_app() -> ShieldApp:
    benign_file = os.environ.get("SHIELD_BENIGN_FILE")
    from .runtime import ShieldRuntimeStore, default_runtime_db

    runtime = ShieldRuntimeStore(default_runtime_db(os.environ.get("SHIELD_RUNTIME_DB")))
    return build_app(build_config(),
                     load_benign_requests(benign_file) if benign_file else [],
                     runtime_store=runtime)
