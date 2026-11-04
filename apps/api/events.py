"""Server-Sent Events stream with sequence numbers and reconnect support.

Clients connect to GET /api/v1/events/stream and receive events as SSE.
Each event carries a monotonically increasing sequence number. On reconnect,
the client sends ``Last-Event-ID`` with the last seq it saw, and the server
resends all events after that seq (bounded by a replay window).

The store is in-memory and bounded (oldest events dropped when the window
fills). This is a local demo backend - no cross-process persistence.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import Request
from fastapi.responses import StreamingResponse

from sentinelx.policy.redaction import redact

from .schemas import EventKind, EventStreamMessage


@dataclass
class StoredEvent:
    id: UUID
    seq: int
    kind: EventKind
    payload: dict[str, Any]
    timestamp: datetime


class EventStream:
    """Asyncio-safe event store + broadcast bus.

    * ``append(kind, payload, run_id)`` stores and broadcasts an event.
    * ``subscribe()`` returns an async queue of events (from seq+1 onward).
    * ``replay(after_seq)`` returns stored events with seq > after_seq.
    """

    def __init__(self, max_stored: int = 10000) -> None:
        self._events: deque[StoredEvent] = deque(maxlen=max_stored)
        self._seq = 0
        self._subscribers: set[asyncio.Queue[StoredEvent | None]] = set()
        self._lock = asyncio.Lock()

    async def append(
        self,
        kind: EventKind,
        payload: dict[str, Any],
        run_id: UUID | None = None,
    ) -> StoredEvent:
        async with self._lock:
            self._seq += 1
            ev = StoredEvent(
                id=uuid4(),
                seq=self._seq,
                kind=kind,
                payload=redact(payload).value,
                timestamp=datetime.now(UTC),
            )
            self._events.append(ev)
            dead: set[asyncio.Queue[StoredEvent | None]] = set()
            for q in self._subscribers:
                try:
                    q.put_nowait(ev)
                except asyncio.QueueFull:
                    dead.add(q)
            self._subscribers -= dead
            return ev

    def replay(self, after_seq: int) -> list[StoredEvent]:
        """Return stored events with seq > after_seq (bounded by deque)."""
        return [e for e in self._events if e.seq > after_seq]

    def current_seq(self) -> int:
        return self._seq

    async def subscribe(self) -> asyncio.Queue[StoredEvent | None]:
        q: asyncio.Queue[StoredEvent | None] = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[StoredEvent | None]) -> None:
        async with self._lock:
            self._subscribers.discard(q)


# module-level singleton (one event bus for the demo backend)
event_stream = EventStream()


def _sse_line(event: str, data: str, ev_id: str | None = None, retry: int = 3000) -> str:
    # Do NOT send an "event:" line: all events arrive as unnamed "message"
    # events so that clients listening on `onmessage` receive them. The event
    # kind is carried inside the JSON payload (ev.kind).
    parts: list[str] = []
    if ev_id is not None:
        parts.append(f"id: {ev_id}\n")
    parts.append(f"retry: {retry}\n")
    for line in data.splitlines() or [""]:
        parts.append(f"data: {line}\n")
    parts.append("\n")
    return "".join(parts)


async def sse_stream_generator(request: Request, after_seq: int = 0):
    """SSE stream generator. Replays missed events, then forwards new ones.

    The client sends ``Last-Event-ID`` (mapped to ``after_seq``) to reconnect
    and resume from the last seen sequence.
    """
    # Subscribe before replay: appends while the consumer reads replay are
    # queued. Sequence filtering removes overlap without losing the boundary.
    q = await event_stream.subscribe()
    try:
        for ev in event_stream.replay(after_seq):
            msg = EventStreamMessage(
                seq=ev.seq, id=ev.id, kind=ev.kind.value,
                payload=redact(ev.payload).value, timestamp=ev.timestamp.isoformat(),
            )
            after_seq = ev.seq
            yield _sse_line(ev.kind.value, msg.model_dump_json(), ev_id=str(ev.seq))
        while True:
            if await request.is_disconnected():
                break
            try:
                ev = await asyncio.wait_for(q.get(), timeout=30.0)
            except TimeoutError:
                # heartbeat comment to keep the connection alive
                yield ": heartbeat\n\n"
                continue
            if ev is None:
                break
            if ev.seq <= after_seq:
                continue
            after_seq = ev.seq
            redacted_payload = redact(ev.payload).value
            msg = EventStreamMessage(
                seq=ev.seq,
                id=ev.id,
                kind=ev.kind.value,
                payload=redacted_payload,
                timestamp=ev.timestamp.isoformat(),
            )
            yield _sse_line(ev.kind.value, msg.model_dump_json(), ev_id=str(ev.seq))
    finally:
        await event_stream.unsubscribe(q)


def sse_response(request: Request, after_seq: int = 0) -> StreamingResponse:
    return StreamingResponse(
        sse_stream_generator(request, after_seq),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
