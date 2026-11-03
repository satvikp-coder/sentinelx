"""Request/time budgets for external scanner operations.

Enforces per-scanner request and time budgets to prevent runaway scans.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class BudgetTracker:
    """Tracks request and time usage for a scanner session."""

    request_budget: int
    time_budget_seconds: int
    requests_used: int = 0
    start_time: float = field(default_factory=time.monotonic)

    def can_make_request(self) -> bool:
        """Return True if a request can be made within budget."""
        if self.requests_used >= self.request_budget:
            return False
        elapsed = time.monotonic() - self.start_time
        if elapsed >= self.time_budget_seconds:
            return False
        return True

    def record_request(self) -> None:
        """Record that a request was made."""
        self.requests_used += 1

    def elapsed_seconds(self) -> float:
        """Return elapsed time since the tracker started."""
        return time.monotonic() - self.start_time

    def remaining_requests(self) -> int:
        """Return remaining request budget."""
        return max(0, self.request_budget - self.requests_used)

    def remaining_time(self) -> float:
        """Return remaining time budget in seconds."""
        return max(0, self.time_budget_seconds - self.elapsed_seconds())

    def check(self) -> None:
        """Raise if budget is exhausted."""
        if not self.can_make_request():
            if self.requests_used >= self.request_budget:
                msg = "request budget exhausted: " \
                    + str(self.requests_used) + "/" + str(self.request_budget)
                raise RuntimeError(msg)
            msg = "time budget exhausted: " \
                + str(self.elapsed_seconds()) + "s/" \
                + str(self.time_budget_seconds) + "s"
            raise RuntimeError(msg)
