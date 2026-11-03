"""Independent Sentinel finding verification for external scanner results.

External scanner findings must NOT automatically become CONFIRMED.
They require independent verification by Sentinel's own checks before
being treated as confirmed findings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class VerificationResult:
    """Result of independently verifying an external scanner finding."""

    external_finding_id: str
    scanner_name: str
    confirmed: bool
    verification_method: str
    evidence_match: bool
    reason: str
    sentinel_finding_id: str | None = None


def verify_external_finding(
    external_finding: Any,
    sentinel_evidence: dict[str, Any],
) -> VerificationResult:
    """Independently verify an external scanner finding against Sentinel evidence.

    Returns a VerificationResult. The finding is NOT confirmed unless
    independent Sentinel evidence corroborates it.
    """
    confirmed = False
    reason = "external finding not independently verified by Sentinel"
    evidence_match = False

    ext_target = getattr(external_finding, "target", "")
    sentinel_targets = sentinel_evidence.get("targets", [])

    for st in sentinel_targets:
        if st == ext_target or st in ext_target:
            evidence_match = True
            reason = "target matches Sentinel-observed lab target"
            break

    if evidence_match:
        confirmed = False
        reason = "target matches Sentinel evidence; requires human confirmation"

    return VerificationResult(
        external_finding_id=getattr(external_finding, "finding_id", "unknown"),
        scanner_name=getattr(external_finding, "scanner_name", "unknown"),
        confirmed=confirmed,
        verification_method="sentinel_independent_check",
        evidence_match=evidence_match,
        reason=reason,
    )
