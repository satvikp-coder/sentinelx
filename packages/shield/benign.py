"""Benign request set for the benign-replay gate, read as DATA from a lab's benign_traffic.py.

The file is never imported or executed: literal ``check(rep, c, "feature", METHOD, "/path", ...)``
calls are parsed with a regex. Paths built at runtime (for example a share URL) are skipped.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

_CALL = re.compile(
    r'check\(\s*rep\s*,\s*c\s*,\s*"[^"]*"\s*,\s*"(GET|POST|PUT|PATCH|DELETE)"\s*,\s*f?"(/[^"]*)"')


def load_benign_requests(path: str | Path) -> list[dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8")
    out: list[dict[str, Any]] = []
    for method, raw in _CALL.findall(text):
        raw = re.sub(r"\{[a-z_]+\}", "1", raw)
        parts = urlsplit(raw)
        out.append({"method": method, "path": parts.path,
                    "params": dict(parse_qsl(parts.query)), "headers": {}})
    return out
