"""Edit-based patch applier.

Pure in-memory apply of exact-text edits. No model calls, no I/O except the
optional write helper. Reuses scope checks from apply.py.

"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .models import FixCategory


class Edit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str = Field(min_length=1)
    find: str = Field(min_length=1, max_length=4000)
    replace: str = Field(max_length=4000)


class PatchEdits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fix_category: FixCategory
    explanation: str = Field(max_length=300)
    edits: list[Edit] = Field(min_length=1, max_length=6)


@dataclass(frozen=True)
class EditResult:
    ok: bool
    error: str | None
    new_contents: dict[str, str]
    unified_diff: str


def _is_safe_path(scope_root: Path, rel_path: str) -> bool:
    if not rel_path or rel_path.startswith("/") or rel_path.startswith("\\"):
        return False
    p = Path(rel_path)
    if p.is_absolute():
        return False
    if ".." in p.parts:
        return False
    try:
        target = (scope_root / p).resolve()
        root = scope_root.resolve()
        return target.is_relative_to(root)
    except Exception:
        return False


def _normalize_line_endings(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _preserve_eol(original: str, new: str) -> str:
    if "\r\n" in original:
        new = new.replace("\n", "\r\n")
    if original.endswith("\n") and not new.endswith("\n"):
        new += "\n"
    if not original.endswith("\n") and new.endswith("\n"):
        new = new.rstrip("\n")
    return new


def apply_edits(
    scope_root: Path,
    original_files: dict[str, str],
    edits: PatchEdits,
    allowed_files: set[str],
    max_changed_lines: int,
) -> EditResult:
    new_contents: dict[str, str] = {}
    current = {k: _normalize_line_endings(v) for k, v in original_files.items()}

    for idx, edit in enumerate(edits.edits, start=1):
        rel = edit.file
        if rel not in allowed_files:
            return EditResult(
                False, f"edit {idx}: INVALID_EDIT_TARGET: file '{rel}' not in allowed files",
                {}, "",
            )
        if not _is_safe_path(scope_root, rel):
            return EditResult(
                False, f"edit {idx}: INVALID_EDIT_TARGET: unsafe path '{rel}'", {}, ""
            )
        if rel not in current:
            return EditResult(
                False, f"edit {idx}: INVALID_EDIT_TARGET: file '{rel}' not in original files",
                {}, "",
            )
        file_text = current[rel]
        find_norm = _normalize_line_endings(edit.find)
        replace_norm = _normalize_line_endings(edit.replace)

        count = 0
        start = 0
        while True:
            i = file_text.find(find_norm, start)
            if i == -1:
                break
            count += 1
            start = i + 1
        if count == 0:
            return EditResult(
                False, f"edit {idx}: SEARCH_BLOCK_NOT_FOUND: find text occurs 0 times", {}, ""
            )
        if count > 1:
            return EditResult(
                False, f"edit {idx}: AMBIGUOUS_SEARCH_BLOCK: find text occurs {count} times "
                       "(ambiguous)", {}, ""
            )

        new_file = file_text.replace(find_norm, replace_norm, 1)
        new_contents[rel] = new_file
        current[rel] = new_file

    diff_lines: list[str] = []
    total_changed = 0
    for path, new_text in current.items():
        original_text = _normalize_line_endings(original_files.get(path, ""))
        if original_text == new_text:
            continue
        orig_lines = original_text.splitlines(keepends=True)
        new_lines = new_text.splitlines(keepends=True)
        for d in difflib.unified_diff(
            orig_lines, new_lines, fromfile=f"a/{path}", tofile=f"b/{path}", lineterm=""
        ):
            is_change = d.startswith("+") or d.startswith("-")
            is_header = d.startswith("+++") or d.startswith("---")
            if is_change and not is_header:
                total_changed += 1
        diff = "\n".join(
            difflib.unified_diff(
                original_text.splitlines(keepends=True),
                new_text.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                lineterm="",
            )
        )
        diff_lines.append(diff)

    unified_diff = "\n".join(diff_lines)
    if total_changed > max_changed_lines:
        return EditResult(
            False,
            f"edit {idx}: EDIT_VALIDATION_FAILED: diff too large "
            f"({total_changed} lines, max {max_changed_lines})",
            {}, "",
        )

    final_contents: dict[str, str] = {}
    for path, text in current.items():
        orig = original_files.get(path, "")
        final_contents[path] = _preserve_eol(orig, text)

    return EditResult(True, None, final_contents, unified_diff)


def write_edits(scope_root: Path, new_contents: dict[str, str]) -> None:
    for rel, text in new_contents.items():
        if not _is_safe_path(scope_root, rel):
            raise ValueError(f"unsafe path '{rel}'")
        target = scope_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
