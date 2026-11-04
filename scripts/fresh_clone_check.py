#!/usr/bin/env python3
"""Fresh-clone smoke test: verifies the repo builds and runs from a clean clone.

Creates an isolated local Git clone of the current committed branch (never copies
working-tree credentials), installs Python dependencies, runs ruff and fast tests,
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
from argparse import ArgumentParser
from pathlib import Path

REPO_ROOT = Path(".").resolve()
EXCLUDE_NAMES = {
    ".git", ".venv", "node_modules", "dist", "build",
    "__pycache__", ".pytest_cache", ".ruff_cache", ".env", ".env.local",
    ".env.*",
}


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def copy_repo(src: Path, dst: Path) -> None:
    """Copy the repo excluding build artifacts and VCS."""
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*EXCLUDE_NAMES))


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true",
                        help="fresh-environment core tests; default runs the full fast suite")
    args = parser.parse_args()
    tmp = Path(tempfile.mkdtemp(prefix="sentinelx_fresh_clone_"))
    clone = tmp / "sentinelx"
    try:
        clean = run(["git", "diff", "--quiet", "HEAD"], cwd=REPO_ROOT)
        if clean.returncode != 0:
            print("Commit tracked changes before the clean-clone check.", file=sys.stderr)
            return 1
        branch = run(["git", "symbolic-ref", "--short", "HEAD"], cwd=REPO_ROOT)
        if branch.returncode != 0:
            print("Clean-clone check requires a named branch.", file=sys.stderr)
            return 1
        print(f"Cloning committed source to {clone} ...", flush=True)
        result = run(["git", "clone", "--local", "--no-hardlinks", "--branch",
                      branch.stdout.strip(), str(REPO_ROOT), str(clone)])
        if result.returncode != 0:
            print("Local Git clone failed.", file=sys.stderr)
            return 1

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
        r = run([python, "-m", "pip", "install", "-e", "sdk/python"], cwd=clone)
        if r.returncode != 0:
            print("Python SDK installation failed", file=sys.stderr)
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
        tests = (["tests/unit/test_schemas.py", "tests/unit/test_policy_engine.py",
                  "tests/unit/test_fixer_edits.py", "tests/unit/test_agent_guard_sdk.py",
                  "tests/unit/test_shield_completion_regressions.py"] if args.smoke else [])
        r = run([python, "-m", "pytest", "-q", "-m", "not slow", *tests,
                 "--basetemp", str(tmp / "pytest"), "-p", "no:cacheprovider"],
                cwd=clone, timeout=1800)
        if r.returncode != 0:
            print(f"pytest failed: {r.stdout[-500:]} {r.stderr[-500:]}", file=sys.stderr)
            return 1
        print("pytest: OK")
        print("\n".join(r.stdout.strip().splitlines()[-4:]), flush=True)

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
        resolved = tmp.resolve()
        if (resolved.parent == Path(tempfile.gettempdir()).resolve()
                and resolved.name.startswith("sentinelx_fresh_clone_")):
            shutil.rmtree(resolved, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
