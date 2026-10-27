"""The immutable experiment manifest and its hash.

``manifest_hash`` is the SHA-256 of the canonical manifest content (everything except the hash
itself). Each case entry carries ``case_hash`` (case template + payload bytes) and the manifest
pins the static policy's ``policy_version``, so editing a case, its payload, the case list, the
budgets or the policy after results exist changes (or invalidates) the hash. The runner refuses
to run on any mismatch.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Annotated, Literal

from pydantic import ConfigDict, Field

from sentinelx.common_schemas import SXModel
from sentinelx.policy import load_policy

from .cases import FIXTURES, Case, case_hash, load_all_cases

REPO_ROOT = Path(__file__).resolve().parents[2]
ARM_DESCRIPTIONS = {
    "A": "no gateway (sandbox boundary only)",
    "B": "static least-privilege gateway policy (configs/policy/lab.yaml) + page-egress policy",
}
RESERVED_ARM = "C"  # EVCS containment (Prompt 7): a seam only, deliberately not implemented here


class ManifestError(ValueError):
    pass


class ManifestHashMismatch(ManifestError):
    """The manifest content does not match its recorded hash (or the run header's hash)."""


class ManifestDriftError(ManifestError):
    """A case file, payload or the policy changed after the manifest was sealed."""


class RunHeaderMismatch(ManifestError):
    pass


class Budgets(SXModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    max_steps: Annotated[int, Field(ge=1)] = 20
    wall_clock_seconds: Annotated[float, Field(gt=0)] = 90.0
    op_timeout: Annotated[float, Field(gt=0)] = 8.0


class ManifestCase(SXModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    scenario: Literal["S1", "S2", "S3"]
    variant: str
    seed: int
    label: Literal["attack", "benign"]
    surface: str
    case_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Manifest(SXModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_version: Literal["1"] = "1"
    # "generated": includes MODEL-GENERATED attack cases (fixtures/generated); kept separate
    source: Literal["hand_authored", "generated"] = "hand_authored"
    name: str
    order_seed: int  # fixed seed for the recorded run order (order effects are reproducible)
    arms: Annotated[list[Literal["A", "B"]], Field(min_length=1)]
    repetitions: Annotated[int, Field(ge=1)] = 1
    policy_file: str  # relative to the repo root
    policy_version: str  # pinned policy_version of policy_file
    planner: Literal["scripted-naive"] = "scripted-naive"
    budgets: Budgets = Budgets()
    cases: Annotated[list[ManifestCase], Field(min_length=1)]
    manifest_hash: str = ""


def canonical_bytes(m: Manifest) -> bytes:
    doc = m.model_dump(mode="json", exclude={"manifest_hash"})
    if doc.get("source") == "hand_authored":  # default value: keep sealed hashes unchanged
        doc.pop("source", None)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def compute_manifest_hash(m: Manifest) -> str:
    return hashlib.sha256(canonical_bytes(m)).hexdigest()


def seal(m: Manifest) -> Manifest:
    return m.model_copy(update={"manifest_hash": compute_manifest_hash(m)})


def build_manifest(
    *, name: str, order_seed: int, case_ids: list[str] | None = None, arms: list[str] | None = None,
    repetitions: int = 1, policy_file: str = "configs/policy/lab.yaml",
    budgets: Budgets | None = None, fixtures: Path = FIXTURES, source: str = "hand_authored",
) -> Manifest:
    cases = [c for c in load_all_cases(fixtures, include_generated=source == "generated")
             if case_ids is None or c.id in case_ids]
    if case_ids is not None and {c.id for c in cases} != set(case_ids):
        raise ManifestError("unknown case id requested")
    policy = load_policy(REPO_ROOT / policy_file)
    entries = [
        ManifestCase(
            case_id=c.id, scenario=c.template.family,
            variant=re.sub(r"^[ab]\d+_", "", c.template.payload_id), seed=c.template.seed,
            label=c.label, surface=c.template.surface.value, case_hash=case_hash(c, fixtures))
        for c in cases
    ]
    m = Manifest(source=source,  # type: ignore[arg-type]
                 name=name, order_seed=order_seed, arms=arms or ["A", "B"],  # type: ignore[arg-type]
                 repetitions=repetitions, policy_file=policy_file,
                 policy_version=policy.policy_version, budgets=budgets or Budgets(), cases=entries)
    return seal(m)


def load_manifest(path: str | Path, *, fixtures: Path = FIXTURES, check_fixtures: bool = True
                  ) -> Manifest:
    """Load and VERIFY: embedded hash, then (optionally) every case file and the policy."""
    m = Manifest.model_validate_json(Path(path).read_text(encoding="utf-8"))
    if not m.manifest_hash or compute_manifest_hash(m) != m.manifest_hash:
        raise ManifestHashMismatch(
            f"manifest content does not match its recorded hash {m.manifest_hash[:12] or '(none)'}")
    if check_fixtures:
        verify_fixtures(m, fixtures)
    return m


def verify_fixtures(m: Manifest, fixtures: Path = FIXTURES) -> dict[str, Case]:
    current = {c.id: c for c in load_all_cases(fixtures, include_generated=m.source == "generated")}
    for entry in m.cases:
        case = current.get(entry.case_id)
        if case is None:
            raise ManifestDriftError(f"case {entry.case_id} no longer exists")
        if case_hash(case, fixtures) != entry.case_hash:
            raise ManifestDriftError(f"case {entry.case_id} (or its payload) changed after sealing")
        if (case.template.family, case.label, case.template.seed) != (
                entry.scenario, entry.label, entry.seed):
            raise ManifestDriftError(f"case {entry.case_id} metadata changed after sealing")
    policy = load_policy(REPO_ROOT / m.policy_file)
    if policy.policy_version != m.policy_version:
        raise ManifestDriftError(
            f"policy changed after sealing: {policy.policy_version} != {m.policy_version}")
    return current


def write_manifest(m: Manifest, path: str | Path) -> None:
    Path(path).write_text(json.dumps(m.model_dump(mode="json"), indent=2) + "\n",
                          encoding="utf-8", newline="\n")
