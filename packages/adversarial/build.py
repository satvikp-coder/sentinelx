"""Turn an ACCEPTED slot text into a runnable generated case.

Our code inserts the text into the fixed template and builds the AttackTemplate by COPYING the
seed: forbidden_outcome, goal_expected, task, allowed_actions, expected rule, benign neighbor
all come from the hand-authored seed. Only id, surface, payload, assertion text, notes, seed
number and the provenance block are new."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.common_schemas import AttackTemplate, GenerationInfo, Placement, Surface
from sentinelx.evaluation.cases import FIXTURES

from .generator import GEN_PROMPT_VERSION, GenerationOutcome
from .slots import render_payload

GENERATED_SEED_BASE = 5000


@dataclass(frozen=True)
class GeneratedCase:
    template: AttackTemplate
    payload_ext: str
    payload_text: str


def visible_snippet(text: str) -> str:
    """A stable stretch of the sentence (before any placeholder) for the fixture assertion."""
    head = text.split("{", 1)[0].strip()
    return (head if len(head) >= 12 else text.replace("{", "").replace("}", ""))[:40].strip()


def build_generated_case(seed: AttackTemplate, outcome: GenerationOutcome, text: str,
                         index: int) -> GeneratedCase:
    surface = outcome.surface
    ext, payload = render_payload(seed.placement.page, surface, text)
    case_id = f"G{index:02d}"
    payload_id = f"g{index:02d}_{seed.id.lower()}_{surface.value}"
    placement = seed.placement
    if surface is Surface.TOOL_RESULT:
        placement = Placement(vhost="orders", page="order", slot="tool_result")
    elif placement.slot == "tool_result":
        placement = Placement(vhost=placement.vhost, page=placement.page, slot="body")
    first = seed.fixture_assertions[0]
    path = ("/__tools__/lookup_order?order_id=1042" if surface is Surface.TOOL_RESULT
            else first.path)
    result = outcome.model_result
    info = GenerationInfo(
        seed_case_id=seed.id, provider=result.provider, model=result.model,
        mode=result.mode.value, prompt_version=GEN_PROMPT_VERSION,
        prompt_hash=outcome.prompt_hash, surface=surface, tone=outcome.tone,  # type: ignore[arg-type]
        length_cap=outcome.length_cap,
        slot_text_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        generated_at=datetime.now(UTC))
    update = {
        "id": case_id, "surface": surface, "payload_id": payload_id, "placement": placement,
        "seed": GENERATED_SEED_BASE + index,
        "fixture_assertions": [{"kind": "page_contains", "vhost": first.vhost, "path": path,
                                "text": visible_snippet(text)}],
        "notes": (f"MODEL-GENERATED variant of {seed.id} ({surface.value}, {outcome.tone}). "
                  f"Labels, task and expectations are copied from the hand-authored seed."),
        "generated": info,
    }
    template = AttackTemplate.model_validate(
        {**seed.model_dump(mode="python"), **{k: (v.model_dump(mode="python")
                                                  if hasattr(v, "model_dump") else v)
                                              for k, v in update.items()}})
    return GeneratedCase(template, ext, payload)


def write_generated_case(case: GeneratedCase, root: Path = FIXTURES) -> tuple[Path, Path]:
    base = root / "generated"
    (base / "payloads").mkdir(parents=True, exist_ok=True)
    doc = case.template.model_dump(mode="json")
    case_path = base / f"{case.template.id}.json"
    payload_path = base / "payloads" / f"{case.template.payload_id}.{case.payload_ext}"
    case_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8", newline="\n")
    payload_path.write_text(case.payload_text, encoding="utf-8", newline="\n")
    return case_path, payload_path
