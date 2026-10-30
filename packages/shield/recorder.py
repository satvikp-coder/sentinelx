"""Evidence recording for the shield: batched benign summaries + rate-capped suspicious events.

Benign per-request summaries are accumulated and flushed as one compact aggregate event every
N seconds. Individual events are written only for suspicious requests, subject to a per-minute
rate cap so the hash chain is not flooded. All payloads pass through the existing redaction
before storage; only method, path template, status, size, latency, hashed client key and
signals are stored.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from collections.abc import Callable

from sentinelx.common_schemas import EvidenceState
from sentinelx.evidence.store import EvidenceStore


def hash_client_key(client_id: str) -> str:
    return "sk_" + hashlib.sha256(client_id.encode("utf-8")).hexdigest()[:32]


def path_template(path: str) -> str:
    import re

    return re.sub(r"/\d+", "/{}", path)


class ShieldRecorder:
    def __init__(self, store: EvidenceStore, session_id: str, batch_interval_s: float = 5.0,
                 suspicious_rate_cap_per_min: int = 20, clock: Callable[[], float] = time.monotonic
                 ) -> None:
        self.store = store
        self.session_id = session_id
        self.batch_interval_s = batch_interval_s
        self.suspicious_rate_cap_per_min = suspicious_rate_cap_per_min
        self.clock = clock
        self._batch: list[dict] = []
        self._last_flush = clock()
        self._suspicious_count = 0
        self._suspicious_window_start = clock()

    # ------------------------------------------------------------------ public API
    def record(self, client_key: str, method: str, path: str, status: int, size: int,
               latency_ms: float, signals: list, suspicious: bool, shield_error: bool = False
               ) -> None:
        now = self.clock()
        entry = {
            "client_key": client_key,
            "method": method,
            "path_template": path_template(path),
            "status": status,
            "size": size,
            "latency_ms": round(latency_ms, 2),
            "signals": [{"name": s.name, "category": s.category} for s in signals],
            "suspicious": suspicious,
            "shield_error": shield_error,
        }
        if suspicious or shield_error:
            self._maybe_write_individual(entry, now)
        else:
            self._batch.append(entry)
        self._maybe_flush(now)

    def flush(self) -> None:
        now = self.clock()
        self._maybe_flush(now, force=True)

    # ------------------------------------------------------------------ internals
    def _maybe_write_individual(self, entry: dict, now: float) -> None:
        if self.suspicious_rate_cap_per_min <= 0:
            return
        if now - self._suspicious_window_start >= 60.0:
            self._suspicious_window_start = now
            self._suspicious_count = 0
        if self._suspicious_count >= self.suspicious_rate_cap_per_min:
            return
        self._suspicious_count += 1
        self.store.append(
            self.session_id, "shield_suspicious", EvidenceState.OBSERVED, "sentinelx.shield",
            entry,
        )

    def _maybe_flush(self, now: float, force: bool = False) -> None:
        if not force and (now - self._last_flush) < self.batch_interval_s:
            return
        if not self._batch:
            self._last_flush = now
            return
        aggregate = {
            "count": len(self._batch),
            "method_counts": {str(k): v for k, v in defaultdict(int, {}).items()},
            "status_counts": {},
            "total_size": 0,
            "total_latency_ms": 0.0,
            "signal_counts": {},
            "requests": self._batch,
        }
        mc: dict[str, int] = {}
        sc: dict[str, int] = {}
        sigc: dict[str, int] = {}
        for e in self._batch:
            mc[e["method"]] = mc.get(e["method"], 0) + 1
            sc[str(e["status"])] = sc.get(str(e["status"]), 0) + 1
            aggregate["total_size"] += e["size"]
            aggregate["total_latency_ms"] += e["latency_ms"]
            for sig in e["signals"]:
                sigc[sig["name"]] = sigc.get(sig["name"], 0) + 1
        aggregate["method_counts"] = mc
        aggregate["status_counts"] = sc
        aggregate["signal_counts"] = sigc
        self.store.append(
            self.session_id, "shield_batch", EvidenceState.OBSERVED, "sentinelx.shield",
            dict(aggregate),
        )
        self._batch = []
        self._last_flush = now
