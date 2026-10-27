"""Client-side rate limiter (token bucket) and a circuit breaker. Clock and sleep are injectable
so the behaviour is testable without waiting."""

from __future__ import annotations

import time
from collections.abc import Callable


class TokenBucket:
    """`rpm` requests per minute, small burst. acquire() sleeps until a token is available."""

    def __init__(self, rpm: int, *, burst: int | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.rate = rpm / 60.0
        self.capacity = float(burst if burst is not None else max(1, min(rpm, 3)))
        self._tokens = self.capacity
        self._clock, self._sleep = clock, sleep
        self._last = clock()
        self.waited_s = 0.0

    def acquire(self) -> float:
        """Take one token, sleeping if needed. Returns the seconds waited."""
        waited = 0.0
        while True:
            now = self._clock()
            self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens >= 1.0 - 1e-9:  # tolerate float rounding (avoids a livelock)
                self._tokens = max(0.0, self._tokens - 1.0)
                self.waited_s += waited
                return waited
            delay = max(1e-6, (1.0 - self._tokens) / self.rate)
            self._sleep(delay)
            waited += delay


class CircuitBreaker:
    """Opens after `threshold` consecutive infrastructure failures; half-opens after `cooldown_s`
    (one trial call). Success closes it. While open, callers must NOT call the model."""

    def __init__(self, threshold: int, cooldown_s: float,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.threshold, self.cooldown_s, self._clock = threshold, cooldown_s, clock
        self.failures = 0
        self._opened_at: float | None = None
        self.trips = 0

    @property
    def state(self) -> str:
        if self._opened_at is None:
            return "closed"
        if self._clock() - self._opened_at >= self.cooldown_s:
            return "half_open"
        return "open"

    def allow(self) -> bool:
        return self.state != "open"

    def record_success(self) -> None:
        self.failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self.failures += 1
        if self.state == "half_open" or self.failures >= self.threshold:
            if self._opened_at is None or self.state == "half_open":
                self.trips += 1
            self._opened_at = self._clock()
