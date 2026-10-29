"""Part C.2: a pure-code (no model) unified-diff validator. Parses the diff ourselves - never
trusts `git apply` to tell us what a diff does before we have already decided it is safe to
apply. A diff that fails ANY check here is REJECTED before any run, patch_file is never written
to disk from unchecked model text."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sentinelx.policy.redaction import redact

from .models import RepoScope

MAX_CHANGED_LINES_DEFAULT = 60
_FILE_HEADER_RE = re.compile(r"^(---|\+\+\+)\s+(?:(a|b)/)?(\S+)")
_HUNK_HEADER_RE = re.compile(r"^@@ ")
_BINARY_MARKERS = ("Binary files ", "GIT binary patch")
_NETWORK_CALL_RE = re.compile(
    # (?<!->) / (?<!::) so PHP/JS method calls like ->fetch(...) (e.g. PDOStatement::fetch())
    # are not confused with a bare fetch(...) call (the browser/Node Fetch API)
    r"(?<!->)(?<!::)\b(fetch\s*\(|curl_init\s*\(|curl_exec\s*\(|"
    r"file_get_contents\s*\(\s*['\"]https?://|http\.request\s*\(|https\.request\s*\(|"
    r"requests\.(get|post|put|delete)\s*\(|urlopen\s*\(|XMLHttpRequest\s*\(|"
    r"new\s+WebSocket\s*\()", re.IGNORECASE)
_SHELL_EVAL_RE = re.compile(
    r"\b(eval\s*\(|exec\s*\(|system\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|"
    r"proc_open\s*\(|subprocess\.\w+\s*\(|os\.system\s*\(|child_process\b|"
    r"`[^`]*`)", re.IGNORECASE)
_SECURITY_CONTROL_RE = re.compile(
    r"\b(password_hash|bcrypt|csrf|require_login|auth\s*\(|htmlspecialchars|prepare\s*\(|"
    r"bindParam|bindValue|requireAuth|authenticate|verify_signature|hash_hmac)\b",
    re.IGNORECASE)
_PROTECTED_PATH_HINTS = ("test_", "_test.", "tests/", "tests\\", "benign_traffic")


@dataclass(frozen=True)
class ParsedDiff:
    files: list[str]
    added_lines: list[str]  # text only, no leading '+'
    removed_lines: list[str]  # text only, no leading '-'
    changed_line_count: int
    is_binary: bool


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    parsed: ParsedDiff | None = None


def parse_unified_diff(diff_text: str) -> ParsedDiff:
    files: list[str] = []
    added: list[str] = []
    removed: list[str] = []
    is_binary = any(marker in diff_text for marker in _BINARY_MARKERS)
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith(("--- ", "+++ ")):
            m = _FILE_HEADER_RE.match(line)
            if m:
                path = m.group(3)
                if path not in ("/dev/null",) and path not in files:
                    files.append(path)
            in_hunk = False
            continue
        if _HUNK_HEADER_RE.match(line):
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    return ParsedDiff(files=files, added_lines=added, removed_lines=removed,
                      changed_line_count=len(added) + len(removed), is_binary=is_binary)


def validate_diff(diff_text: str, scope: RepoScope, allowed_files: set[str], *,
                  max_changed_lines: int = MAX_CHANGED_LINES_DEFAULT) -> ValidationResult:
    reasons: list[str] = []
    if not diff_text.strip():
        return ValidationResult(False, ["empty diff"])
    parsed = parse_unified_diff(diff_text)
    if parsed.is_binary:
        reasons.append("diff contains a binary change")
    if not parsed.files:
        reasons.append("diff touches no recognizable file")
    for path in parsed.files:
        try:
            scope.resolve_in_scope(path)
        except ValueError:
            reasons.append(f"path outside the fix scope: {path!r}")
            continue
        if path not in allowed_files:
            reasons.append(f"file not in the allowed set for this finding: {path!r}")
        if any(hint in path.replace("\\", "/").lower() for hint in _PROTECTED_PATH_HINTS):
            reasons.append(f"diff touches a protected test/benign-traffic path: {path!r}")
    if parsed.changed_line_count > max_changed_lines:
        reasons.append(f"diff changes {parsed.changed_line_count} lines, "
                       f"over the limit of {max_changed_lines}")
    added_text = "\n".join(parsed.added_lines)
    removed_text = "\n".join(parsed.removed_lines)
    if _NETWORK_CALL_RE.search(added_text):
        reasons.append("diff adds a new network call")
    if _SHELL_EVAL_RE.search(added_text):
        reasons.append("diff adds shell/eval/subprocess use")
    if redact(added_text).count > 0:
        reasons.append("diff adds a secret-shaped literal")
    if _SECURITY_CONTROL_RE.search(removed_text) and not _SECURITY_CONTROL_RE.search(added_text):
        reasons.append("diff removes a security-control call without adding an equivalent one")
    return ValidationResult(ok=not reasons, reasons=reasons, parsed=parsed)
