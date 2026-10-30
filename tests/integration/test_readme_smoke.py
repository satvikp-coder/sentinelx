"""Slow integration wrapper: runs the README quickstart smoke against the Node lab."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.mark.slow
def test_readme_smoke():
    result = subprocess.run(
        [sys.executable, "scripts/readme_smoke.py"], cwd=REPO,
        capture_output=True, text=True, timeout=1800)
    assert result.returncode == 0, (
        f"readme_smoke failed ({result.returncode})\n"
        f"stdout tail:\n{result.stdout[-3000:]}\nstderr tail:\n{result.stderr[-2000:]}")
