"""Ground truth of the two labs: PLANTED.json validity, coverage and reference-copy differences,
plus the rule that nothing under packages/ may read the *_reference copies."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from sentinelx.common_schemas import PlantedManifest

ROOT = Path(__file__).resolve().parents[2]
LABS = ROOT / "labs"
PAIRS = [("vibe_shop_php", "vibe_shop_php_reference"),
         ("vibe_notes_node", "vibe_notes_node_reference")]


def load(lab: str) -> PlantedManifest:
    return PlantedManifest.model_validate_json((LABS / lab / "PLANTED.json").read_text("utf-8"))


@pytest.mark.parametrize(("lab", "ref"), PAIRS)
def test_planted_manifest_is_valid_and_has_a_mix(lab: str, ref: str) -> None:
    m = load(lab)
    assert m.lab == lab
    ids = [w.id for w in m.weaknesses]
    assert len(ids) == len(set(ids)), "ids are unique"
    assert 8 <= len(m.weaknesses) <= 10
    assert sum(w.requires_human_decision for w in m.weaknesses) >= 2
    assert len({w.vuln_class for w in m.weaknesses}) >= 8, "a spread of classes"
    for w in m.weaknesses:
        assert (LABS / lab / w.file).is_file(), (w.id, w.file)
        n_lines = len((LABS / lab / w.file).read_text("utf-8").splitlines())
        assert 1 <= w.line_start <= w.line_end <= n_lines, (w.id, w.line_start, w.line_end, n_lines)


@pytest.mark.parametrize(("lab", "ref"), PAIRS)
def test_every_planted_location_differs_in_the_reference_copy(lab: str, ref: str) -> None:
    for w in load(lab).weaknesses:
        vuln_lines = (LABS / lab / w.file).read_text("utf-8").splitlines()
        snippet = "\n".join(vuln_lines[w.line_start - 1: w.line_end])
        ref_file = LABS / ref / w.file
        if not ref_file.exists():
            continue  # the fix removed the file
        assert snippet not in ref_file.read_text("utf-8"), f"{w.id}: unchanged in the reference"


@pytest.mark.parametrize(("lab", "ref"), PAIRS)
def test_exposed_backup_files_are_gone_from_the_reference(lab: str, ref: str) -> None:
    exposed = {"vibe_shop_php": "app/config.php.bak",
               "vibe_notes_node": "public/backup/server.js.bak"}
    assert (LABS / lab / exposed[lab]).is_file()
    assert not (LABS / ref / exposed[lab]).exists()
    secret = re.compile(r"labsecret_\w+")
    for path in (LABS / ref).rglob("*"):
        if path.is_file() and "node_modules" not in path.parts and path.suffix in {".php", ".js"}:
            assert not secret.search(path.read_text("utf-8")), f"hardcoded secret in {path.name}"


def test_planted_descriptions_contain_no_ready_made_attack_payloads() -> None:
    bad = re.compile(r"<script|union\s+select|or\s+1\s*=\s*1|\.\./\.\./|drop\s+table|;\s*--"
                     r"|javascript:", re.IGNORECASE)
    for lab, _ in PAIRS:
        for w in load(lab).weaknesses:
            assert not bad.search(w.description + " " + w.safe_confirmation_strategy), w.id


def test_summary_counts_for_the_report() -> None:
    for lab, _ in PAIRS:
        m = load(lab)
        counts = Counter(w.vuln_class for w in m.weaknesses)
        assert sum(counts.values()) == len(m.weaknesses)
        print(lab, dict(counts), "human:", sum(w.requires_human_decision for w in m.weaknesses))


# ------------------------------------------------------------------ reference isolation
def test_nothing_under_packages_references_the_reference_copies() -> None:
    """No package may mention a *_reference copy, ever. `labs[/\\\\]` is the same blanket ban
    EXCEPT in packages/fixer, which by design (Prompt 9 Part A) reads a lab's OWN source
    directory from disk - its own, separate static test (test_fixer_safety.py) is what
    actually proves it never reaches PLANTED.json or a *_reference copy."""
    offenders: list[str] = []
    for path in (ROOT / "packages").rglob("*"):
        if not path.is_file() or path.suffix in {".pyc", ".db"} or "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text("utf-8")
        except UnicodeDecodeError:
            continue
        if re.search(r"_reference\b", text):
            offenders.append(str(path.relative_to(ROOT)))
            continue
        if "fixer" in path.parts:
            continue
        if re.search(r"labs[/\\]", text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], f"packages/ must not read lab or reference paths: {offenders}"


def test_reference_copies_are_not_importable_as_packages_data() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text("utf-8")
    assert "_reference" not in pyproject and "labs" not in pyproject.split("[tool.ruff")[0].split(
        "[tool.setuptools")[-1]
    assert json.loads(json.dumps({"ok": True}))["ok"]


# ------------------------------------------------------------------ fake secret leakage
# The exact fake-secret literals planted in the lab source (never real credentials - the
# strings themselves say "FAKE"). A committed evaluation report containing one of these
# unredacted means the shared redactor missed a shape; this test exists so that regresses
# loudly instead of needing a human to notice it in a diff.
FAKE_SECRET_MARKERS = (
    "labsecret_shop_FAKE_0f3a9c71d2e84b65",
    "labsecret_notes_FAKE_7b21c9e4a05d3f68",
    "labadmin_FAKE_pass_2026",
)


def test_no_committed_evaluation_report_leaks_a_fake_secret_unredacted() -> None:
    import subprocess

    tracked = subprocess.run(["git", "ls-files", "evaluations"], cwd=ROOT, check=True,
                             capture_output=True, text=True).stdout.splitlines()
    offenders: list[str] = []
    for rel in tracked:
        path = ROOT / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text("utf-8")
        except UnicodeDecodeError:
            continue
        if any(marker in text for marker in FAKE_SECRET_MARKERS):
            offenders.append(rel)
    assert offenders == [], f"unredacted fake secret in committed evaluation report(s): {offenders}"
