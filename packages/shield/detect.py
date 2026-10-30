"""Deterministic request/response signals and per-client sliding windows.

All detection is rule-based and data-driven from ``configs/shield/signals.yaml``. No model is
involved in the request path. Time is injected through a clock callable so windows are
deterministic in tests.
"""

from __future__ import annotations

import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Annotated

import yaml
from pydantic import BaseModel, ConfigDict, Field


@dataclass(frozen=True)
class Signal:
    name: str
    category: str
    detail: str
    confidence: float = 0.5


class SignalRule(BaseModel):
    """One data-driven signal rule from signals.yaml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    category: str
    pattern: str | None = None
    location: str = "path"
    max_param_length: int | None = None
    path: str | None = None
    path_prefix: str | None = None
    requires_session: bool = False
    method: str | None = None


class WindowRule(BaseModel):
    """One sliding-window behavior rule from signals.yaml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    category: str = "behavior"
    max_requests: int | None = None
    max_failed_logins: int | None = None
    max_404_ratio: float | None = None
    min_requests: int = 1
    max_sequential_ids: int | None = None
    max_admin_hits: int | None = None
    window_seconds: Annotated[float, Field(gt=0)] = 60.0
    path: str | None = None
    path_prefix: str | None = None
    object_path_pattern: str | None = None
    method: str | None = None


@dataclass
class ClientWindow:
    """Sliding-window state for one client key."""

    window_seconds: float
    clock: Callable[[], float] = time.monotonic
    hits: deque[float] = field(default_factory=deque)
    statuses: deque[tuple[float, int]] = field(default_factory=deque)
    failed_logins: deque[float] = field(default_factory=deque)
    object_ids: deque[tuple[float, str, int]] = field(default_factory=deque)
    admin_hits: deque[float] = field(default_factory=deque)

    def _trim(self, d: deque, now: float) -> None:
        cutoff = now - self.window_seconds
        while d:
            head = d[0]
            t = head[0] if isinstance(head, tuple) else head
            if t < cutoff:
                d.popleft()
            else:
                break

    def record_request(self, path: str, status: int, now: float) -> None:
        self.hits.append(now)
        self.statuses.append((now, status))
        self._trim(self.hits, now)
        self._trim(self.statuses, now)
        if path == "/login" and status in (401, 403):
            self.failed_logins.append(now)
            self._trim(self.failed_logins, now)
        if path.startswith("/admin"):
            self.admin_hits.append(now)
            self._trim(self.admin_hits, now)
        m = re.search(r"/(order|item|user|product)/(\d+)", path)
        if m:
            self.object_ids.append((now, m.group(1), int(m.group(2))))
            self._trim(self.object_ids, now)

    def behavior_signals(self, now: float) -> list[tuple[str, str, float]]:
        out: list[tuple[str, str, float]] = []
        self._trim(self.hits, now)
        self._trim(self.statuses, now)
        self._trim(self.failed_logins, now)
        self._trim(self.admin_hits, now)
        self._trim(self.object_ids, now)

        total = len(self.hits)
        not_found = sum(1 for _, s in self.statuses if s == 404)
        if total >= 20 and not_found / max(total, 1) >= 0.5:
            out.append(("high_404_rate", f"{not_found}/{total} 404s in window", 0.6))
        if len(self.failed_logins) >= 5:
            out.append(("repeated_failed_logins", f"{len(self.failed_logins)} failed logins", 0.8))
        if len(self.admin_hits) >= 5:
            out.append(("admin_probe", f"{len(self.admin_hits)} admin hits", 0.8))
        if len(self.object_ids) >= 10:
            ids = [oid for _, _, oid in self.object_ids]
            sequential = (
                len(ids) > 1
                and all(b == a + 1 for a, b in zip(ids, ids[1:], strict=False))
            )
            if sequential:
                out.append(("object_id_enumeration", f"{len(ids)} sequential object ids", 0.7))
        return out


class Detector:
    """Scans requests for signals and tracks per-client sliding windows."""

    def __init__(self, rules: list[SignalRule], windows: list[WindowRule],
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.rules = list(rules)
        self.windows = list(windows)
        self.clock = clock
        self._compiled: dict[str, re.Pattern[str]] = {}
        for rule in self.rules:
            if rule.pattern:
                self._compiled[rule.name] = re.compile(rule.pattern, re.I)
        self._default_window_seconds = 60.0
        for w in self.windows:
            self._default_window_seconds = w.window_seconds
            break
        self._windows_state: dict[str, ClientWindow] = {}

    @classmethod
    def load(cls, path: str, clock: Callable[[], float] = time.monotonic) -> Detector:
        from pathlib import Path

        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules = [SignalRule.model_validate(r) for r in data.get("signals", [])]
        windows = [
            WindowRule.model_validate({**v, "name": k}) for k, v in data.get("windows", {}).items()
        ]
        return cls(rules, windows, clock=clock)

    def _window_for(self, client_key: str, now: float) -> ClientWindow:
        window = self._windows_state.get(client_key)
        if window is None:
            window = ClientWindow(self._default_window_seconds, clock=self.clock)
            self._windows_state[client_key] = window
        return window

    # ------------------------------------------------------------------ request scan
    def scan_request(self, client_key: str, method: str, path: str,
                     params: dict[str, str], headers: dict[str, str], body: str,
                     has_session: bool, now: float) -> list[Signal]:
        signals: list[Signal] = []
        path_l = path.lower()
        ua = headers.get("user-agent") or headers.get("User-Agent", "")

        for rule in self.rules:
            fired = False
            detail = ""
            if rule.location == "path" and rule.pattern:
                if self._compiled[rule.name].search(path):
                    fired = True
                    detail = rule.pattern
            elif rule.location == "path" and rule.path:
                if path_l == rule.path.lower():
                    fired = True
                    detail = rule.path
            elif rule.location == "params" and rule.pattern:
                for key, val in params.items():
                    pat = self._compiled[rule.name]
                    if pat.search(val) or pat.search(key):
                        fired = True
                        detail = f"{key}={val}"
                        break
            if rule.location == "params" and rule.max_param_length is not None and not fired:
                for key, val in params.items():
                    if len(val) > rule.max_param_length:
                        fired = True
                        detail = f"oversized {key}"
                        break
            elif rule.location == "params_reflected" and rule.pattern:
                for key, val in params.items():
                    if self._compiled[rule.name].search(val) and val in body:
                        fired = True
                        detail = f"reflected {key}"
                        break
            elif rule.location == "user_agent" and rule.pattern:
                if self._compiled[rule.name].search(ua):
                    fired = True
                    detail = ua
            elif rule.location == "path" and rule.path_prefix and rule.requires_session:
                if path_l.startswith(rule.path_prefix.lower()) and not has_session:
                    fired = True
                    detail = rule.path_prefix
            if fired:
                signals.append(Signal(rule.name, rule.category, detail, 0.5))

        # per-client window behavior
        window = self._window_for(client_key, now)
        window.record_request(path, 200, now)
        for name, detail, conf in window.behavior_signals(now):
            signals.append(Signal(name, "behavior", detail, conf))

        return signals

    def record_response(self, client_key: str, path: str, status: int, now: float) -> None:
        window = self._window_for(client_key, now)
        # Correct the status of the in-progress request recorded by scan_request.
        # Do not re-add hits or object_ids (already recorded); just fix the status.
        if window.statuses:
            window.statuses.pop()
        window.statuses.append((now, status))
        if path == "/login" and status in (401, 403):
            window.failed_logins.append(now)
            cutoff = now - window.window_seconds
            while window.failed_logins and window.failed_logins[0] < cutoff:
                window.failed_logins.popleft()
