"""Cassettes: recorded model replies, keyed by a hash of the (redacted) request.

RECORDED mode replays them. A LIVE call never reads a cassette, so a failed live call can never
silently turn into a recording. Reasoning text is never stored (only the answer content)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import REPO_ROOT

DEFAULT_DIR = REPO_ROOT / "fixtures" / "recorded_model"


def request_key(provider: str, model: str, task: str, messages: list[dict[str, str]],
                options: dict[str, Any]) -> str:
    doc = json.dumps({"provider": provider, "model": model, "task": task, "messages": messages,
                      "options": options}, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False)
    return hashlib.sha256(doc.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Recorded:
    content: str
    finish_reason: str | None
    tokens_in: int
    tokens_out: int
    request_id: str | None


class CassetteMiss(LookupError):
    pass


class CassetteStore:
    def __init__(self, directory: Path = DEFAULT_DIR) -> None:
        self.directory = Path(directory)

    def _path(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def load(self, key: str) -> Recorded:
        path = self._path(key)
        if not path.is_file():
            raise CassetteMiss(f"no recording for request {key[:12]}")
        d = json.loads(path.read_text(encoding="utf-8"))
        return Recorded(d["content"], d.get("finish_reason"), int(d.get("tokens_in", 0)),
                        int(d.get("tokens_out", 0)), d.get("request_id"))

    def save(self, key: str, *, provider: str, model: str, task: str, rec: Recorded) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        doc = {"key": key, "provider": provider, "model": model, "task": task,
               "recorded_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "content": rec.content, "finish_reason": rec.finish_reason,
               "tokens_in": rec.tokens_in, "tokens_out": rec.tokens_out,
               "request_id": rec.request_id}
        path = self._path(key)
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
        return path
