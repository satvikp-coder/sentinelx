"""Tests for packages.fixer.edits"""

from sentinelx.fixer.diff_validator import validate_diff
from sentinelx.fixer.edits import Edit, PatchEdits, apply_edits
from sentinelx.fixer.models import FixCategory


def _make_patch(edits):
    return PatchEdits(
        fix_category=FixCategory.PARAMETERIZED_QUERY,
        explanation="test",
        edits=edits,
    )


def test_single_edit_success(tmp_path):
    scope = tmp_path
    files = {"a.py": "x = 1\n"}
    edits = _make_patch([Edit(file="a.py", find="x = 1", replace="x = 2")])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert res.ok
    assert res.new_contents["a.py"] == "x = 2\n"
    assert "--- a/a.py" in res.unified_diff


def test_multi_edit_success(tmp_path):
    scope = tmp_path
    files = {"a.py": "a\nb\nc\n"}
    edits = _make_patch([
        Edit(file="a.py", find="a\n", replace="A\n"),
        Edit(file="a.py", find="b\n", replace="B\n"),
    ])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert res.ok
    assert res.new_contents["a.py"] == "A\nB\nc\n"


def test_find_missing(tmp_path):
    scope = tmp_path
    files = {"a.py": "x\n"}
    edits = _make_patch([Edit(file="a.py", find="y", replace="z")])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert not res.ok
    assert "occurs 0 times" in res.error
    # error message must not contain more than 600 chars of file text
    assert len(res.error) < 700


def test_find_ambiguous(tmp_path):
    scope = tmp_path
    files = {"a.py": "dup\ndup\n"}
    edits = _make_patch([Edit(file="a.py", find="dup", replace="x")])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert not res.ok
    assert "ambiguous" in res.error


def test_file_not_allowed(tmp_path):
    scope = tmp_path
    files = {"a.py": "x\n"}
    edits = _make_patch([Edit(file="b.py", find="x", replace="y")])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert not res.ok
    assert "not in allowed files" in res.error


def test_path_traversal(tmp_path):
    scope = tmp_path
    files = {"a.py": "x\n"}
    edits = _make_patch([Edit(file="../b.py", find="x", replace="y")])
    res = apply_edits(scope, files, edits, {"../b.py"}, 60)
    assert not res.ok
    assert "unsafe path" in res.error


def test_crlf_preserved(tmp_path):
    scope = tmp_path
    files = {"a.py": "x = 1\r\n"}
    edits = _make_patch([Edit(file="a.py", find="x = 1", replace="x = 2")])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert res.ok
    assert "\r\n" in res.new_contents["a.py"]


def test_diff_too_large(tmp_path):
    scope = tmp_path
    files = {"a.py": "\n".join(f"line{i}" for i in range(10)) + "\n"}
    find_text = "\n".join(f"line{i}" for i in range(10)) + "\n"
    edits = _make_patch([Edit(file="a.py", find=find_text, replace="new\n")])
    res = apply_edits(scope, files, edits, {"a.py"}, 5)
    assert not res.ok
    assert "diff too large" in res.error


def test_all_or_nothing(tmp_path):
    scope = tmp_path
    files = {"a.py": "a\nb\n"}
    edits = _make_patch([
        Edit(file="a.py", find="a", replace="A"),
        Edit(file="a.py", find="missing", replace="X"),
    ])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert not res.ok
    assert res.new_contents == {}


def test_validate_diff_good(tmp_path):
    scope = tmp_path
    files = {"a.py": "x=1\n"}
    edits = _make_patch([Edit(file="a.py", find="x=1", replace="x=2")])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert res.ok
    from sentinelx.fixer.models import RepoScope
    repo = RepoScope(lab="lab", source_dir=tmp_path, work_dir=tmp_path)
    v = validate_diff(res.unified_diff, repo, {"a.py"}, max_changed_lines=60)
    assert v.ok


def test_validate_diff_rejects_network(tmp_path):
    scope = tmp_path
    files = {"a.py": "a\n"}
    edits = _make_patch([Edit(file="a.py", find="a", replace="fetch('http://evil')")])
    res = apply_edits(scope, files, edits, {"a.py"}, 60)
    assert res.ok
    from sentinelx.fixer.models import RepoScope
    repo = RepoScope(lab="lab", source_dir=tmp_path, work_dir=tmp_path)
    v = validate_diff(res.unified_diff, repo, {"a.py"}, max_changed_lines=60)
    assert not v.ok
    assert any("network" in r.lower() for r in v.reasons)
    assert "fetch" in res.unified_diff
