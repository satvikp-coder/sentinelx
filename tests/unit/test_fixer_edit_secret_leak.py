"""Security regression tests for the structured-edit rejection-and-retry path.

The edit validator previously embedded fuzzy-matched lines from UNREDACTED source
files into rejection diagnostics, and the edit generator forwarded those
diagnostics to the model on retry - leaking arbitrary sensitive source content
(including API keys) into model prompts and returned reasons.

These tests capture the ACTUAL request messages sent through the production
request-construction path (generate_patch_edits -> client.complete) with a fake
model client. Nothing is mocked away.

The sensitive canary is placed OUTSIDE the redacted excerpt window so it is not
present in any request legitimately; any appearance in a retry request or in the
returned reasons is the leak under test.

Canaries: sk-FAKE1234567890abcdefghij / deadbeef-cafe-1337-secret (synthetic,
never real keys).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinelx.common_schemas import ModelMode
from sentinelx.evidence.db import connect, migrate
from sentinelx.fixer import ladder
from sentinelx.fixer.diagnose import DiagnosedLocation
from sentinelx.fixer.diff_validator import validate_diff
from sentinelx.fixer.edits import Edit, PatchEdits
from sentinelx.fixer.models import FixCategory, RepoScope
from sentinelx.fixer.patch_gen import PatchGenOutput, generate_patch, generate_patch_edits
from sentinelx.model_clients import ModelCallStatus, ModelResult

CANARY_KEY = "sk-FAKE1234567890abcdefghij"   # synthetic canary embedded in source
CANARY_MEMO = "deadbeef-cafe-1337-secret"    # arbitrary marker, no standard key shape

# Diagnosed weakness is near the top; the canary line sits far below the
# excerpt window (15 lines of context), so it is not in any request
# legitimately. Pre-fix, the candidate-line extraction leaked it into retry
# feedback from the WHOLE file.
def long_source_with(canary_line: str) -> str:
    lines = [
        "import db",
        "",
        "def show_user(uid):",
        '    cur = db.execute("SELECT * FROM users WHERE id = " + uid)',
        "    return cur.fetchall()",
        "",
    ]
    lines += [f"    # filler line {i}" for i in range(20)]
    lines.append(canary_line)
    return "\n".join(lines) + "\n"


KEY_SOURCE = long_source_with(f'API_KEY = "{CANARY_KEY}"')
# near-identical to the canary line but not exact: 0 exact matches, and the
# close-match candidate extraction (pre-fix) leaks the canary line into feedback.
NEAR_KEY_FIND = f'API_KEY = "{CANARY_KEY}X"'

MEMO_SOURCE = long_source_with(f'INTERNAL_MEMO = "{CANARY_MEMO}"')
NEAR_MEMO_FIND = f'INTERNAL_MEMO = "{CANARY_MEMO}X"'

AMBIG_SOURCE = (
    "import db\n"
    "\n"
    "def show_user(uid):\n"
    '    cur = db.execute("SELECT * FROM users WHERE id = " + uid)\n'
    "    return cur.fetchall()\n"
    "\n"
    + "\n".join([f'    # filler line {i}' for i in range(20)])
    + f"\n    TOKEN = \"{CANARY_MEMO}\"\n    TOKEN = \"{CANARY_MEMO}\"\n"
)

GOOD_SOURCE = (
    "import db\n"
    "\n"
    'def show_user(uid):\n'
    '    cur = db.execute("SELECT * FROM users WHERE id = " + uid)\n'
    "    return cur.fetchall()\n"
)
GOOD_FIND = 'cur = db.execute("SELECT * FROM users WHERE id = " + uid)'
GOOD_REPLACE = 'cur = db.execute("SELECT * FROM users WHERE id = ?", (uid,))'


def make_scope(tmp_path: Path, content: str) -> RepoScope:
    src, work = tmp_path / "src", tmp_path / "work"
    src.mkdir(parents=True)
    work.mkdir(parents=True)
    (src / "app.py").write_text(content, encoding="utf-8", newline="")
    (work / "app.py").write_text(content, encoding="utf-8", newline="")
    return RepoScope(lab="t", source_dir=src, work_dir=work)


def make_loc(line_start: int = 4, line_end: int = 4) -> DiagnosedLocation:
    return DiagnosedLocation(file="app.py", line_start=line_start, line_end=line_end,
                             reasoning="concatenated query string")


def missing_edit(find: str) -> PatchEdits:
    return PatchEdits(fix_category=FixCategory.PARAMETERIZED_QUERY, explanation="e",
                      edits=[Edit(file="app.py", find=find, replace="y")])


def valid_edit() -> PatchEdits:
    return PatchEdits(fix_category=FixCategory.PARAMETERIZED_QUERY, explanation="parameterize",
                      edits=[Edit(file="app.py", find=GOOD_FIND, replace=GOOD_REPLACE)])


def ambiguous_edit() -> PatchEdits:
    return PatchEdits(fix_category=FixCategory.PARAMETERIZED_QUERY, explanation="e",
                      edits=[Edit(file="app.py", find=f'TOKEN = "{CANARY_MEMO}"', replace="y")])


class RecordingModelClient:
    """Fake model client capturing the ACTUAL request messages through the
    production request-construction path. No live calls, no network."""

    def __init__(self, responses: list[ModelResult]) -> None:
        self.requests: list[tuple[str, list[dict[str, Any]]]] = []
        self._responses = list(responses)

    def complete(self, task: str, messages: list[dict[str, Any]], schema: Any,
                 options: Any = None) -> ModelResult:
        self.requests.append((task, list(messages)))
        return self._responses[min(len(self.requests) - 1, len(self._responses) - 1)]


def ok_result(parsed: Any) -> ModelResult:
    return ModelResult(status=ModelCallStatus.OK, provider="fake", model="fake",
                       mode=ModelMode.RECORDED, parsed=parsed)


def all_request_bodies(client: RecordingModelClient) -> str:
    return "\n".join(json.dumps(messages) for _, messages in client.requests)


def run_edits(scope: RepoScope, client: RecordingModelClient,
              loc: DiagnosedLocation | None = None) -> Any:
    return generate_patch_edits(scope, loc or make_loc(), vuln_class="sql_injection",
                                method="GET", endpoint="/user", summary="s", client=client)


# ------------------------------------------------------------------
# TEST A: missing-match retry with synthetic API key embedded in source,
#         outside the excerpt window
# ------------------------------------------------------------------

def test_missing_match_retry_does_not_leak_embedded_api_key(tmp_path):
    client = RecordingModelClient([ok_result(missing_edit(NEAR_KEY_FIND))])
    scope = make_scope(tmp_path, KEY_SOURCE)
    res = run_edits(scope, client)

    assert res.status == "REJECTED", res.reasons
    assert res.retries_used == 2          # 1 initial + MAX_RETRIES=2, then stop
    assert len(client.requests) == 3      # model call bound respected

    bodies = all_request_bodies(client)
    assert CANARY_KEY not in bodies       # retry request must not contain the key
    assert CANARY_KEY not in "\n".join(res.reasons)  # returned reasons must not contain it
    # failed edits never touch the disposable copy
    assert (scope.work_dir / "app.py").read_text(encoding="utf-8") == KEY_SOURCE


# ------------------------------------------------------------------
# TEST B: missing-match retry with an arbitrary secret marker
# ------------------------------------------------------------------

def test_missing_match_retry_does_not_leak_arbitrary_marker(tmp_path):
    client = RecordingModelClient([ok_result(missing_edit(NEAR_MEMO_FIND))])
    scope = make_scope(tmp_path, MEMO_SOURCE)
    res = run_edits(scope, client)

    assert res.status == "REJECTED", res.reasons
    bodies = all_request_bodies(client)
    assert CANARY_MEMO not in bodies
    assert CANARY_MEMO not in "\n".join(res.reasons)
    assert (scope.work_dir / "app.py").read_text(encoding="utf-8") == MEMO_SOURCE


# ------------------------------------------------------------------
# TEST C: ambiguous search with sensitive source
# ------------------------------------------------------------------

def test_ambiguous_search_does_not_leak_sensitive_source(tmp_path):
    client = RecordingModelClient([ok_result(ambiguous_edit())])
    scope = make_scope(tmp_path, AMBIG_SOURCE)
    res = run_edits(scope, client)

    assert res.status == "REJECTED", res.reasons
    reasons_text = "\n".join(res.reasons)
    assert any("AMBIGUOUS_SEARCH_BLOCK" in r for r in res.reasons)
    assert any("occurs 2 times" in r for r in res.reasons)
    bodies = all_request_bodies(client)
    assert CANARY_MEMO not in bodies
    assert CANARY_MEMO not in reasons_text
    assert (scope.work_dir / "app.py").read_text(encoding="utf-8") == AMBIG_SOURCE


# ------------------------------------------------------------------
# TEST D: repeated failure reaches the retry limit and escalates
# ------------------------------------------------------------------

def test_exhausted_edit_retries_escalate(tmp_path):
    client = RecordingModelClient([ok_result(missing_edit(NEAR_KEY_FIND))])
    scope = make_scope(tmp_path, KEY_SOURCE)
    res = run_edits(scope, client)
    assert res.status == "REJECTED"
    assert res.retries_used == 2
    assert len(client.requests) == 3

    c = connect(tmp_path / "db.sqlite")
    migrate(c)
    outcome = ladder.decide(c, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=None, patch=res, verification=None,
                            rejected_count=0, evidence_event_ids=[], files_touched=["app.py"])
    assert outcome.status == "ESCALATED"
    assert outcome.ticket_id is not None
    assert c.execute("SELECT COUNT(*) FROM escalations").fetchone()[0] == 1
    assert c.execute("SELECT COUNT(*) FROM patches").fetchone()[0] == 0
    ticket_body = json.loads(c.execute("SELECT body FROM escalations WHERE id = ?",
                                       (outcome.ticket_id,)).fetchone()["body"])
    assert "REJECTED" in ticket_body["explanation"]   # real status, not fabricated


# ------------------------------------------------------------------
# TEST E: safe rejection reason propagation (captured requests + results)
# ------------------------------------------------------------------

def test_rejection_reasons_are_safe_structured_codes(tmp_path):
    client = RecordingModelClient([ok_result(missing_edit(NEAR_KEY_FIND))])
    scope = make_scope(tmp_path, KEY_SOURCE)
    res = run_edits(scope, client)

    assert res.status == "REJECTED"
    assert any("SEARCH_BLOCK_NOT_FOUND" in r for r in res.reasons)
    reasons_text = "\n".join(res.reasons)
    assert CANARY_KEY not in reasons_text
    assert "API_KEY" not in reasons_text

    # the retry feedback contains only safe, bounded diagnostic info
    retry_body = json.dumps(client.requests[1][1])
    assert "SEARCH_BLOCK_NOT_FOUND" in retry_body
    assert CANARY_KEY not in retry_body
    assert NEAR_KEY_FIND not in retry_body  # raw search string not echoed


# ------------------------------------------------------------------
# TEST F: successful structured edit still works (no regression)
# ------------------------------------------------------------------

def test_successful_structured_edit_applies_and_validates(tmp_path):
    client = RecordingModelClient([ok_result(valid_edit())])
    scope = make_scope(tmp_path, GOOD_SOURCE)
    res = run_edits(scope, client)

    assert res.status == "VALIDATED", res.reasons
    assert res.retries_used == 0
    assert len(client.requests) == 1
    assert validate_diff(res.diff, scope, {"app.py"}).ok
    # the disposable copy is patched; the ORIGINAL source dir is untouched
    work_text = (scope.work_dir / "app.py").read_text(encoding="utf-8")
    src_text = (scope.source_dir / "app.py").read_text(encoding="utf-8")
    assert GOOD_REPLACE in work_text
    assert GOOD_FIND not in work_text
    assert src_text == GOOD_SOURCE


# ------------------------------------------------------------------
# TEST G: legacy unified-diff path still works
# ------------------------------------------------------------------

def test_legacy_diff_path_still_works(tmp_path):
    diff = ("--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -4,1 +4,1 @@\n"
            " def show_user(uid):\n"
            "-    cur = db.execute(\"SELECT * FROM users WHERE id = \" + uid)\n"
            "+    cur = db.execute(\"SELECT * FROM users WHERE id = ?\", (uid,))\n"
            "     return cur.fetchall()\n")
    client = RecordingModelClient([ok_result(PatchGenOutput(
        diff=diff, explanation="parameterize",
        files_touched=["app.py"], fix_category=FixCategory.PARAMETERIZED_QUERY))])
    scope = make_scope(tmp_path, GOOD_SOURCE)
    res = generate_patch(scope, make_loc(), vuln_class="sql_injection", method="GET",
                         endpoint="/user", summary="s", client=client)
    assert res.status == "VALIDATED", res.reasons
    assert validate_diff(res.diff, scope, {"app.py"}).ok
