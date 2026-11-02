"""Kill switch for external scanner operations.

Provides a process-wide stop that halts all external scanner activity
when triggered. Once triggered, no new scanner operations may proceed.
"""

from __future__ import annotations

import threading


class KillSwitch:
    """A process-wide stop for external scanner operations."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def trigger(self) -> None:
        """Trigger the kill switch. All operations must stop."""
        self._event.set()

    @property
    def active(self) -> bool:
        """True if the kill switch has been triggered."""
        return self._event.is_set()

    def reset(self) -> None:
        """Reset the kill switch (human action required)."""
        self._event.clear()

    def check(self) -> None:
        """Raise if the kill switch is active."""
        if self.active:
            raise RuntimeError(
                "kill switch is active; external scanner operations are halted"
            )


# Module-level kill switch singleton
kill_switch = KillSwitch()
