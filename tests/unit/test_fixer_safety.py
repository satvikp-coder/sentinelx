"""Hard safety rules for the fix engine (Prompt 9 Part A), mirroring the scanner's own static
tests: the fixer never reads ground truth, and path-traversal is refused."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXER_DIR = ROOT / "packages" / "fixer"
# scope.py is the ONE file allowed to mention PLANTED.json by name - its job is to EXCLUDE it
# when copying a lab's source into the disposable fix scope. It must never open/read it.
_EXCLUSION_FILE = "scope.py"


def test_fixer_never_opens_planted_or_reference_paths() -> None:
    offenders: list[str] = []
    for path in FIXER_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if path.name == _EXCLUSION_FILE:
            continue
        if "_reference" in text or "PLANTED" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], offenders


def test_the_one_file_that_mentions_planted_only_excludes_it_never_reads_it() -> None:
    """scope.py's own exclusion list for copying a lab's source must name PLANTED.json (to skip
    it); this test instead proves it never flows into a read - no open()/read_text()/read_bytes
    call anywhere in the file is built from an expression containing the string "PLANTED"."""
    path = FIXER_DIR / _EXCLUSION_FILE
    text = path.read_text(encoding="utf-8")
    assert "PLANTED" in text, "test is stale: scope.py no longer mentions PLANTED.json"
    tree = ast.parse(text)
    read_calls = {"open", "read_text", "read_bytes"}
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = (node.func.id if isinstance(node.func, ast.Name) else
                    node.func.attr if isinstance(node.func, ast.Attribute) else None)
            if name in read_calls and "PLANTED" in ast.unparse(node):
                offenders.append(ast.unparse(node))
    assert offenders == [], f"scope.py reads a path built from PLANTED: {offenders}"


def test_fixer_safety_module_has_the_coverage_it_claims() -> None:
    """Catches the test itself silently covering zero files (e.g. a rename)."""
    files = list(FIXER_DIR.rglob("*.py"))
    assert len(files) >= 2, "packages/fixer has fewer files than expected - update this test"


@pytest.mark.parametrize("bad", ["../../etc/passwd", "/etc/passwd", "..\\..\\windows\\system32"])
def test_resolve_in_scope_refuses_path_traversal(bad: str, tmp_path: Path) -> None:
    from sentinelx.fixer.models import RepoScope

    scope = RepoScope(lab="x", source_dir=tmp_path, work_dir=tmp_path / "work")
    scope.work_dir.mkdir()
    with pytest.raises(ValueError, match="escapes"):
        scope.resolve_in_scope(bad)


def test_resolve_in_scope_accepts_a_path_inside_the_scope(tmp_path: Path) -> None:
    from sentinelx.fixer.models import RepoScope

    scope = RepoScope(lab="x", source_dir=tmp_path, work_dir=tmp_path / "work")
    scope.work_dir.mkdir()
    resolved = scope.resolve_in_scope("sub/dir/file.php")
    assert resolved == (scope.work_dir / "sub" / "dir" / "file.php").resolve()
