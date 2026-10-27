"""Shared pieces of the benign-traffic generators: one record per request with a golden marker.

These generators exercise every LEGITIMATE feature of a lab with its synthetic users. They are the
regression suite for later fix verification (does a fix break normal use?) and the false-block
measurement for the live shield. They never send anything that looks like an attack."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

import httpx

# 1x1 transparent PNG: a valid, tiny, ordinary image for the avatar upload
TINY_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c6360f8ffff3f0005fe02fea7d6c3cb0000000049454e44ae426082")


@dataclass
class Step:
    feature: str
    method: str
    path: str
    expected_status: int
    status: int | None = None
    marker: str = ""  # golden content marker that must appear in the response
    marker_found: bool = False
    expected_location: str | None = None
    location: str | None = None
    ok: bool = False
    note: str = ""


@dataclass
class Report:
    lab: str
    base_url: str
    steps: list[Step] = field(default_factory=list)

    @property
    def features(self) -> int:
        return len({s.feature for s in self.steps})

    @property
    def requests(self) -> int:
        return len(self.steps)

    @property
    def passed(self) -> bool:
        return all(s.ok for s in self.steps)

    def failures(self) -> list[Step]:
        return [s for s in self.steps if not s.ok]

    def to_json(self) -> str:
        return json.dumps({"lab": self.lab, "base_url": self.base_url, "features": self.features,
                           "requests": self.requests, "passed": self.passed,
                           "steps": [asdict(s) for s in self.steps]}, indent=2)


def check(report: Report, client: httpx.Client, feature: str, method: str, path: str,
          status: int, marker: str = "", *, location_contains: str | None = None,
          **kwargs: object) -> httpx.Response:
    """Send one legitimate request and record whether status, redirect target and marker match."""
    step = Step(feature, method, path, status, marker=marker, expected_location=location_contains)
    r = client.request(method, path, **kwargs)  # type: ignore[arg-type]
    step.status = r.status_code
    step.location = r.headers.get("location")
    step.marker_found = (marker in r.text) if marker else True
    loc_ok = location_contains is None or (step.location is not None
                                           and location_contains in step.location)
    step.ok = r.status_code == status and step.marker_found and loc_ok
    if not step.ok:
        step.note = (f"got {r.status_code}; marker {'found' if step.marker_found else 'MISSING'}; "
                     f"location {step.location}")
    report.steps.append(step)
    return r
