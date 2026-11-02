"""License/attribution inventory for external scanners.

Tracks third-party components used by the external scanner QA harness.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThirdPartyComponent:
    """A third-party component in the external scanner inventory."""

    name: str
    version: str | None
    license: str
    homepage: str
    purpose: str


THIRD_PARTY_INVENTORY = [
    ThirdPartyComponent(
        name="Strix",
        version=None,
        license="unknown",
        homepage="unknown",
        purpose="External web application scanner (optional integration)",
    ),
    ThirdPartyComponent(
        name="PentAGI",
        version=None,
        license="unknown",
        homepage="unknown",
        purpose="External AGI security scanner (optional integration)",
    ),
]


def get_inventory():
    """Return the third-party component inventory."""
    return list(THIRD_PARTY_INVENTORY)
