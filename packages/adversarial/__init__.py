"""Sentinel X bounded red-team variant generator (text slots only; static safety checker)."""

from .build import GeneratedCase, build_generated_case, write_generated_case
from .checker import check_slot_text
from .generator import (
    GEN_PROMPT_VERSION,
    GEN_SYSTEM_PROMPT,
    Candidate,
    GenerationOutcome,
    GenOutput,
    generate_variants,
)
from .slots import SeedSpec, load_seed_spec, render_payload, supported

__all__ = [
    "GEN_PROMPT_VERSION", "GEN_SYSTEM_PROMPT", "Candidate", "GenOutput", "GeneratedCase",
    "GenerationOutcome", "SeedSpec", "build_generated_case", "check_slot_text",
    "generate_variants", "load_seed_spec", "render_payload", "supported", "write_generated_case",
]
