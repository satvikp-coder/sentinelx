"""Hand-authored attack and benign cases: loading, scenario construction, content hashing.

Labels (attack / benign), forbidden outcomes and goal assertions are written by hand in
fixtures/attacks/*.json and fixtures/benign/*.json and are independent of any model.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from sentinelx.common_schemas import AttackTemplate, BenignTemplate, ScenarioSpec

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
FAMILY_FIXTURE = {"S1": "orders", "S2": "calendar", "S3": "support"}
FIXTURE_VERSION = "2"


@dataclass(frozen=True)
class Case:
    id: str
    label: str  # "attack" | "benign"
    template: AttackTemplate | BenignTemplate
    scenario: ScenarioSpec

    @property
    def is_attack(self) -> bool:
        return self.label == "attack"

    @property
    def neighbor_id(self) -> str:
        t = self.template
        return t.benign_neighbor_id if isinstance(t, AttackTemplate) else t.attack_neighbor_id


def scenario_from_template(t: AttackTemplate | BenignTemplate) -> ScenarioSpec:
    """The runnable ScenarioSpec for a case (the lab and the verifier both use this)."""
    return ScenarioSpec(
        id=t.id, seed=t.seed, fixture_id=FAMILY_FIXTURE[t.family], fixture_version=FIXTURE_VERSION,
        goal=t.authorized_goal, allowed_hosts=[t.permitted_lab_target],
        allowed_actions=list(t.allowed_actions), attack_surface=t.surface.value,
        attack_payload_id=t.payload_id, forbidden_outcome=t.forbidden_outcome,
        goal_assertion={"type": "answer_contains", "expected": list(t.goal_expected)},
    )


def _load_dir(root: Path, sub: str, model: type[AttackTemplate] | type[BenignTemplate],
              label: str) -> list[Case]:
    if not (root / sub).is_dir():
        return []
    cases = []
    for path in sorted((root / sub).glob("*.json")):
        template = model.model_validate_json(path.read_text(encoding="utf-8"))
        if path.stem != template.id:
            raise ValueError(f"{path.name}: file name must equal the case id {template.id!r}")
        cases.append(Case(template.id, label, template, scenario_from_template(template)))
    return cases


def load_all_cases(root: Path = FIXTURES, include_generated: bool = False) -> list[Case]:
    """The hand-authored cases; MODEL-GENERATED ones (fixtures/generated) only on request, so the
    hand-authored manifest, its hash and its validation tests never see them."""
    cases = _load_dir(root, "attacks", AttackTemplate, "attack")
    cases += _load_dir(root, "benign", BenignTemplate, "benign")
    if include_generated:
        cases += _load_dir(root, "generated", AttackTemplate, "attack")
    ids = [c.id for c in cases]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate case ids")
    return sorted(cases, key=lambda c: c.id)


def load_case(case_id: str, root: Path = FIXTURES) -> Case | None:
    """Return the case with this id, or None (ids are never used as paths)."""
    for case in load_all_cases(root, include_generated=True):
        if case.id == case_id:
            return case
    return None


def payload_path(t: AttackTemplate | BenignTemplate, root: Path = FIXTURES) -> Path:
    for folder in ("payloads", "generated/payloads"):
        for ext in ("html", "json"):
            p = root / folder / f"{t.payload_id}.{ext}"
            if p.is_file():
                return p
    raise FileNotFoundError(f"payload {t.payload_id!r} for case {t.id}")


def case_hash(case: Case, root: Path = FIXTURES) -> str:
    """SHA-256 over the case template (canonical JSON) and its payload bytes."""
    h = hashlib.sha256()
    doc = case.template.model_dump(mode="json")
    if doc.get("generated") is None:  # keep every hand-authored case_hash exactly as sealed
        doc.pop("generated", None)
    h.update(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode())
    h.update(payload_path(case.template, root).read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()
