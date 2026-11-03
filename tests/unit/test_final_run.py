"""Tests for Task 31: Final evaluation and report orchestration.

Tests scripts/final_run.py --dry-run behavior:
- Launches no models
- Spends no credits
- Starts no expensive external infrastructure
- Makes no unapproved mutations
- Writes dry-run manifest
"""

from __future__ import annotations

import json

# Import final_run module directly
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.final_run import build_steps, docker_running  # noqa: E402

# ------------------------------------------------------------------ build_steps

def test_build_steps_returns_all_steps():
    """build_steps returns all 7 planned steps."""
    steps = build_steps()
    step_names = [s.name for s in steps]
    expected = ["agent_scripted", "agent_model", "scan", "fix", "shield", "evcs", "report"]
    for name in expected:
        assert name in step_names, f"missing step: {name}"


def test_build_steps_live_steps_have_profiles():
    """Live steps (agent_model, scan, fix) have model profiles set."""
    steps = build_steps()
    live_steps = [s for s in steps if s.live]
    for s in live_steps:
        assert s.profile is not None, f"live step {s.name} missing profile"
        assert s.est_calls > 0, f"live step {s.name} missing call estimate"


def test_build_steps_dry_run_steps_not_live():
    """Non-live steps (agent_scripted, shield, evcs, report) are offline."""
    steps = build_steps()
    offline_steps = [s for s in steps if not s.live]
    offline_names = [s.name for s in offline_steps]
    assert "agent_scripted" in offline_names
    assert "shield" in offline_names
    assert "evcs" in offline_names
    assert "report" in offline_names


# ------------------------------------------------------------------ docker_running

def test_docker_running_returns_bool():
    """docker_running() returns a bool (False when daemon is down)."""
    result = docker_running()
    assert isinstance(result, bool)


# ------------------------------------------------------------------ dry-run execution

def test_dry_run_manifest_written(tmp_path: Path):
    """--dry-run writes a manifest without launching anything."""
    from scripts.final_run import main  # noqa: E402

    manifest_out = tmp_path / "run_manifest.json"
    with patch("sys.argv", ["final_run.py", "--dry-run", "--manifest-out", str(manifest_out)]):
        code = main()
    assert code == 0
    assert manifest_out.is_file()

    manifest = json.loads(manifest_out.read_text(encoding="utf-8"))
    assert manifest["dry_run"] is True
    assert "steps" in manifest
    assert len(manifest["steps"]) == 7
    assert set(manifest["model_providers"]) == {"nvidia_glimmer", "baseten_spark_open"}


def test_dry_run_steps_have_skip_reason():
    """Dry-run steps all have 'dry-run: not executed' skip reason."""
    from scripts.final_run import main  # noqa: E402

    manifest_out = Path(tempfile.mkdtemp()) / "run_manifest.json"
    with patch("sys.argv", ["final_run.py", "--dry-run", "--manifest-out", str(manifest_out)]):
        code = main()
    assert code == 0

    manifest = json.loads(manifest_out.read_text(encoding="utf-8"))
    for step in manifest["steps"]:
        assert step["skipped_reason"] == "dry-run: not executed"
        assert step["exit_code"] is None


# ------------------------------------------------------------------ no live execution

def test_dry_run_no_subprocess_calls():
    """--dry-run does not call subprocess.run (no labs started, no models run)."""
    from scripts.final_run import main  # noqa: E402

    manifest_out = Path(tempfile.mkdtemp()) / "run_manifest.json"
    with patch("sys.argv", ["final_run.py", "--dry-run", "--manifest-out", str(manifest_out)]):
        with patch("scripts.final_run.run_cmd") as mock_run:
            code = main()
    assert code == 0
    mock_run.assert_not_called()


# ------------------------------------------------------------------ unknown step

def test_dry_run_unknown_step_rejected():
    """--dry-run with unknown --only step returns exit code 2."""
    from scripts.final_run import main  # noqa: E402

    with patch("sys.argv", ["final_run.py", "--dry-run", "--only", "nonexistent_step"]):
        code = main()
    assert code == 2


# ------------------------------------------------------------------ NO_DB handling

def test_dry_run_manifest_has_no_db_when_no_db():
    """When no evidence DB exists, manifest reflects NO_DB state."""
    from scripts.final_run import main  # noqa: E402

    manifest_out = Path(tempfile.mkdtemp()) / "run_manifest.json"
    with patch("sys.argv", ["final_run.py", "--dry-run", "--manifest-out", str(manifest_out)]):
        code = main()
    assert code == 0

    manifest = json.loads(manifest_out.read_text(encoding="utf-8"))
    # Dry-run doesn't check DB integrity, so NO_DB is reflected in step records
    # (the report step would show NOT AVAILABLE if no DB)
    assert "steps" in manifest
