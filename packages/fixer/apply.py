"""Apply an ALREADY-VALIDATED unified diff to a fix scope with our own applier: `git apply`
given a real file path, never a shell string built from model text. Call this only after
`diff_validator.validate_diff` has returned ok=True."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from .models import RepoScope


class ApplyError(Exception):
    pass


def check_applies(scope: RepoScope, diff_text: str) -> tuple[bool, str]:
    """Dry-run check (git apply --check), no filesystem change."""
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False,
                                     encoding="utf-8", newline="\n") as fh:
        fh.write(diff_text)
        patch_path = Path(fh.name)
    try:
        r = subprocess.run(["git", "apply", "--check", str(patch_path)], cwd=scope.work_dir,
                          capture_output=True, text=True)
        return r.returncode == 0, r.stderr
    finally:
        patch_path.unlink(missing_ok=True)


def apply_diff(scope: RepoScope, diff_text: str, *, commit_message: str) -> str:
    """Applies the diff and commits it in the scope's own disposable git repo. Returns the new
    commit hash. Raises ApplyError (never applies partially) if `git apply` fails."""
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False,
                                     encoding="utf-8", newline="\n") as fh:
        fh.write(diff_text)
        patch_path = Path(fh.name)
    try:
        r = subprocess.run(["git", "apply", str(patch_path)], cwd=scope.work_dir,
                          capture_output=True, text=True)
        if r.returncode != 0:
            raise ApplyError(f"git apply failed: {r.stderr}")
    finally:
        patch_path.unlink(missing_ok=True)
    subprocess.run(["git", "add", "-A"], cwd=scope.work_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", commit_message], cwd=scope.work_dir, check=True,
                   capture_output=True)
    out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=scope.work_dir, check=True,
                         capture_output=True, text=True)
    return out.stdout.strip()
