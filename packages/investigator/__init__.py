"""Sentinel X evidence-cited investigator and independent finding verifier.

The model may explain and classify; every factual claim is structured, cites real event ids and is
checked by deterministic code (``verify``) that never trusts the model. Without a model the
deterministic baseline gives the same kind of finding."""

from .baseline import baseline_investigate, severity_for
from .facts import Fact, build_facts
from .model_investigator import PROMPT_VERSION, SYSTEM_PROMPT_V1, InvestigatorOutput
from .service import Investigation, citation_fidelity, investigate
from .timeline import Timeline, build_timeline
from .verify import (
    FINDING_VERIFIER_VERSION,
    ClaimVerification,
    FindingVerification,
    verify_finding,
)

__all__ = [
    "FINDING_VERIFIER_VERSION", "PROMPT_VERSION", "SYSTEM_PROMPT_V1", "ClaimVerification",
    "Fact", "FindingVerification", "Investigation", "InvestigatorOutput", "Timeline",
    "baseline_investigate", "build_facts", "build_timeline", "citation_fidelity", "investigate",
    "severity_for", "verify_finding",
]
