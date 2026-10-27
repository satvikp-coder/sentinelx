"""Sandbox boundary: a hard network fence that is SEPARATE from the policy gateway.

The gateway decides what the agent MAY do. The sandbox guarantees what it CAN reach: in BOTH
arms, a request is aborted unless it is plain http to a ``*.lab.test`` host on the lab port.
So even the unprotected arm cannot touch the real internet, an IP literal, or another port.
This module shares no code with sentinelx.policy on purpose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_LAB_HOST = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+lab\.test$")


@dataclass(frozen=True)
class SandboxBoundary:
    lab_port: int

    def check(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason). Reasons are stable codes for SANDBOX_BLOCKED events."""
        if not isinstance(url, str) or any(c.isspace() or c == "\\" for c in url):
            return False, "MALFORMED_URL"
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return False, "MALFORMED_URL"
        if parts.scheme != "http":
            return False, "SCHEME_NOT_ALLOWED"
        if parts.username is not None or parts.password is not None or "@" in parts.netloc:
            return False, "USERINFO_NOT_ALLOWED"
        host = (parts.hostname or "").lower()
        if not _LAB_HOST.match(host):
            return False, "HOST_NOT_IN_LAB"
        if port != self.lab_port:
            return False, "PORT_NOT_LAB_PORT"
        return True, "OK"
