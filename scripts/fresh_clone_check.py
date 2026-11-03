#!/usr/bin/env python3
"""Fresh-clone smoke test: verifies the repo builds and runs from a clean clone.

Creates a temporary copy of the repository (excluding .git, .venv, node_modules,
build artifacts), installs Python dependencies, runs ruff and a subset of tests,
and confirms the CLI is importable. Does NOT push, publish, or modify the original
repo.

Exit codes:
  0 - fresh clone smoke test passed
  1 - smoke test failed
  2 - error
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(".").resolve()
EXCLUDE_NAMES = {
    ".git", ".venv", "node_modules", "dist", "build",
    "__pycache__", ".pytest_cache", ".ruff_cache", ".env",
}


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=cwd)


def copy_repo(src: Path, dst: Path) -> None:
    """Copy the repo excluding build artifacts and VCS."""
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*EXCLUDE_NAMES))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sentinelx_fresh_clone_"))
    clone = tmp / "sentinelx"
    try:
        print(f"Copying repo to {clone} ...")
        copy_repo(REPO_ROOT, clone)

        # Create a fresh venv in the clone so we never touch the caller's
        # Python environment or install into the caller's site-packages.
        venv_dir = clone / ".venv"
        print(f"Creating fresh venv at {venv_dir} ...")
        r = run([sys.executable, "-m", "venv", str(venv_dir)])
        if r.returncode != 0:
            print(f"venv creation failed: {r.stderr}", file=sys.stderr)
            return 1
        if sys.platform == "win32":
            venv_python = venv_dir / "Scripts" / "python.exe"
        else:
            venv_python = venv_dir / "bin" / "python"

        # Check Python availability
        python = str(venv_python)
        print(f"Using Python: {python}")

        # Install dependencies into the fresh venv
        print("Installing dependencies...")
        r = run([python, "-m", "pip", "install", "-e", ".[dev]"], cwd=clone)
        if r.returncode != 0:
            print(f"pip install failed: {r.stderr[-500:]}", file=sys.stderr)
            return 1

        # Run ruff
        print("Running ruff...")
        r = run([python, "-m", "ruff", "check", "."], cwd=clone)
        if r.returncode != 0:
            print(f"ruff failed: {r.stdout} {r.stderr}", file=sys.stderr)
            return 1
        print("ruff: OK")

        # Run a fast test subset
        print("Running fast test suite...")
        r = run([python, "-m", "pytest", "-q", "-m", "not slow"], cwd=clone)
        if r.returncode != 0:
            print(f"pytest failed: {r.stdout[-500:]} {r.stderr[-500:]}", file=sys.stderr)
            return 1
        print("pytest: OK")

        # Verify CLI import
        print("Verifying CLI import...")
        r = run(
            [python, "-c", "from sentinelx_cli.main import main; print('CLI import OK')"],
            cwd=clone,
        )
        if r.returncode != 0:
            print(f"CLI import failed: {r.stderr}", file=sys.stderr)
            return 1
        print("CLI import: OK")

        print("\nFresh-clone smoke test PASSED.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
