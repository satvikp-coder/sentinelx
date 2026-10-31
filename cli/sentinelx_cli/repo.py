#!/usr/bin/env python3
"""Locate repository scripts and run them as fixed-argument subprocesses (no shell strings)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    """Repo root, derived from the installed sentinelx package location."""
    import sentinelx

    return Path(sentinelx.__file__).resolve().parents[1]


def run_script(script: str, argv: list[str]) -> int:
    """Run scripts/<script> with argv; inherit stdio; return its exit code."""
    root = repo_root()
    cmd = [sys.executable, str(root / "scripts" / script), *argv]
    return subprocess.run(cmd, cwd=root).returncode
