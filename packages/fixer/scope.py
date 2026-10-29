"""The fixer's repo scope: a disposable, git-initialized copy of ONE lab's own source
directory. The fixer works ONLY inside this copy; the original lab directory is never written
to. Never reads the lab's ground-truth manifest or any hand-fixed sibling copy (see
tests/unit/test_fixer_safety.py for the static check that enforces this)."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import RepoScope

REPO_ROOT = Path(__file__).resolve().parents[2]
LABS_ROOT = REPO_ROOT / "labs"

# Which part of each lab's directory the fixer is allowed to see. PHP's app/ is self-contained
# (PLANTED.json lives one level up, outside it). Node's source files live in the lab root
# ALONGSIDE PLANTED.json, node_modules and data - all three must be excluded: node_modules is
# huge and third-party, data is runtime state, and PLANTED.json is the one file the fixer must
# never read (same hard rule as the scanner). See tests/unit/test_fixer_safety.py.
_PHP_SUBDIR = "app"
_NODE_EXCLUDE = {"node_modules", "data", "__pycache__", ".git", "lab.log", "PLANTED.json"}


def _is_php(lab: str) -> bool:
    return (LABS_ROOT / lab / _PHP_SUBDIR).is_dir()


def source_dir_for(lab: str, labs_root: Path = LABS_ROOT) -> Path:
    base = labs_root / lab
    return (base / _PHP_SUBDIR) if (base / _PHP_SUBDIR).is_dir() else base


def _copy_node_source(source: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        if item.name in _NODE_EXCLUDE:
            continue
        target = dest / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def create_scope(lab: str, *, labs_root: Path = LABS_ROOT,
                 work_root: Path | None = None) -> RepoScope:
    """Copy `lab`'s own source into a fresh disposable directory and `git init` it there. The
    ORIGINAL lab directory under `labs_root` is read, never written."""
    source = source_dir_for(lab, labs_root)
    if not source.is_dir():
        raise ValueError(f"no source directory found for lab {lab!r}")
    work_dir = Path(work_root) if work_root is not None else Path(
        tempfile.mkdtemp(prefix="sentinelx_fix_"))
    work_dir.mkdir(parents=True, exist_ok=True)
    if _is_php(lab):
        shutil.copytree(source, work_dir, dirs_exist_ok=True)
    else:
        _copy_node_source(source, work_dir)
    subprocess.run(["git", "init", "-q"], cwd=work_dir, check=True)
    subprocess.run(["git", "config", "user.email", "fixer@sentinelx.local"], cwd=work_dir,
                   check=True)
    subprocess.run(["git", "config", "user.name", "sentinelx-fixer"], cwd=work_dir, check=True)
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=work_dir, check=True)
    subprocess.run(["git", "add", "-A"], cwd=work_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "seed: fix scope baseline", "--allow-empty"],
                   cwd=work_dir, check=True)
    return RepoScope(lab=lab, source_dir=source, work_dir=work_dir)


def destroy_scope(scope: RepoScope) -> None:
    shutil.rmtree(scope.work_dir, ignore_errors=True)
