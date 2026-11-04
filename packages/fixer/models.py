"""Fixer-local types. FixCategory is deliberately a SEPARATE enum from the lab ground-truth
ledger's own fix-category field (which the fixer must never read) - the same general idea,
written independently from standard security remediation practice, not copied from or aligned
to that ground truth."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath

from pydantic import BaseModel, ConfigDict

from sentinelx.common_schemas import VulnClass


class FixCategory(StrEnum):
    PARAMETERIZED_QUERY = "parameterized_query"
    OUTPUT_ENCODING = "output_encoding"
    OWNERSHIP_CHECK = "ownership_check"
    SECURITY_HEADERS = "security_headers"
    CORS_CONFIG = "cors_config"
    RATE_LIMIT_MIDDLEWARE = "rate_limit_middleware"
    SECRET_TO_ENV = "secret_to_env"
    REMOVE_EXPOSED_FILE = "remove_exposed_file"
    REQUIRE_AUTH = "require_auth"
    SAFE_ERROR_HANDLING = "safe_error_handling"
    UPLOAD_VALIDATION = "upload_validation"
    DISABLE_DEBUG = "disable_debug"


class FixPolicyEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fix_category: FixCategory
    decision: str  # "AUTO" | "NEEDS_HUMAN"


class FixPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_version: str
    entries: dict[str, FixPolicyEntry]  # keyed by VulnClass value
    patch_format: str = "diff"

    def for_class(self, vuln_class: VulnClass) -> FixPolicyEntry | None:
        return self.entries.get(vuln_class.value)


class DiagnosedLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str  # path relative to the scope root
    line_start: int
    line_end: int
    reasoning: str


class RepoScope(BaseModel):
    """A disposable, git-initialized copy of ONE lab's source. `work_dir` is the only
    directory the fixer is allowed to read or write; `source_dir` (the real lab) is never
    modified. Pydantic model (not a dataclass) so it serializes cleanly into evidence."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)
    lab: str
    source_dir: Path
    work_dir: Path

    def resolve_in_scope(self, relative_path: str) -> Path:
        """A path guaranteed to be inside work_dir, or raises - the only way fixer code should
        ever turn a model- or diff-supplied relative path into a real filesystem path."""
        portable = relative_path.replace("\\", "/")
        if (PureWindowsPath(relative_path).drive or PurePosixPath(portable).is_absolute()
                or ".." in PurePosixPath(portable).parts or "\x00" in portable):
            raise ValueError("path escapes the fix scope")
        candidate = (self.work_dir / portable).resolve()
        root = self.work_dir.resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError("path escapes the fix scope")
        return candidate
