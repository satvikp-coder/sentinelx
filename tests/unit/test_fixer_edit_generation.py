"""Tests for generate_patch_edits (edit-based patch generation) with a mocked model client.

The mock follows the established pattern from tests/unit/test_investigator.py: a ModelClient
over httpx.MockTransport returning queued assistant contents. No live model calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from sentinelx.evidence.db import connect, migrate
from sentinelx.fixer import ladder
from sentinelx.fixer import verify as verify_module
from sentinelx.fixer.diff_validator import validate_diff
from sentinelx.fixer.models import (
    DiagnosedLocation,
    FixCategory,
    FixPolicy,
    FixPolicyEntry,
    RepoScope,
)
from sentinelx.fixer.orchestrate import select_generator
from sentinelx.fixer.patch_gen import generate_patch, generate_patch_edits
from sentinelx.fixer.verify import verify_patch
from sentinelx.model_clients import ModelClient, ModelConfig

VULN_APP = (
    "import db\n"
    "\n"
    "def show_user(uid):\n"
    "    cur = db.execute(\"SELECT * FROM users WHERE id = \" + uid)\n"
    "    return cur.fetchall()\n"
)
GOOD_FIND = 'db.execute("SELECT * FROM users WHERE id = " + uid)'
GOOD_REPLACE = 'db.execute("SELECT * FROM users WHERE id = ?", (uid,))'

AMBIG_APP = "x = 1\ny = 2\ny = 2\n"


def make_scope(tmp_path: Path, content: str) -> RepoScope:
    (tmp_path / "app.py").write_text(content, encoding="utf-8", newline="")
    return RepoScope(lab="t", source_dir=tmp_path, work_dir=tmp_path)


def make_loc() -> DiagnosedLocation:
    return DiagnosedLocation(file="app.py", line_start=4, line_end=4,
                             reasoning="concatenated query string")


def edits_json(find: str, replace: str, explanation: str = "parameterized the query") -> str:
    return json.dumps({"fix_category": "parameterized_query", "explanation": explanation,
                       "edits": [{"file": "app.py", "find": find, "replace": replace}]})


def mock_client(responses: list[str]) -> tuple[ModelClient, list[dict[str, Any]]]:
    seen: list[dict[str, Any]] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        idx = min(len(seen) - 1, len(responses) - 1)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": responses[idx]}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 400, "completion_tokens": 120}})

    cfg = ModelConfig(provider="nvidia", base_url="https://api.example.test/v1",
                      model="meta/mock", api_key=SecretStr("sk-fake-test-key-000"),
                      max_rpm=6000, max_retries=0)
    return ModelClient(cfg, transport=httpx.MockTransport(wrapped), sleep=lambda s: None), seen


def run(scope: RepoScope, client: ModelClient):
    return generate_patch_edits(scope, make_loc(), vuln_class="sql_injection",
                                method="GET", endpoint="/user", summary="SQL injection",
                                client=client)


def test_valid_edits_applied_and_diff_validates(tmp_path):
    # one surrounding code fence: allowed leniency, exactly as the existing diff path parses
    client, seen = mock_client(["```json\n" + edits_json(GOOD_FIND, GOOD_REPLACE) + "\n```"])
    scope = make_scope(tmp_path, VULN_APP)
    res = run(scope, client)
    assert res.status == "VALIDATED", res.reasons
    assert res.retries_used == 0
    assert len(seen) == 1  # single model call, no re-ask needed
    assert validate_diff(res.diff, scope, {"app.py"}).ok
    # write_edits ran: the file on disk now has the parameterized query
    assert 'uid,))' in (scope.work_dir / "app.py").read_text(encoding="utf-8")


def test_invalid_json_retries_then_invalid_output(tmp_path):
    # (a) invalid JSON once -> the client's ONE re-ask feeds the error back -> valid on retry
    client, seen = mock_client(["not json at all", edits_json(GOOD_FIND, GOOD_REPLACE)])
    scope = make_scope(tmp_path, VULN_APP)
    res = run(scope, client)
    assert res.status == "VALIDATED", res.reasons
    assert len(seen) == 2  # original + the client's single validation re-ask

    # (b) invalid twice -> the client gives up with INVALID_OUTPUT; we mirror the existing
    # diff path's behavior (MODEL_UNAVAILABLE result whose reason names INVALID_OUTPUT)
    client2, seen2 = mock_client(["nope", "still nope"])
    scope2 = make_scope(tmp_path / "b" if (tmp_path / "b").mkdir() else tmp_path / "b", VULN_APP)
    res2 = run(scope2, client2)
    assert res2.status == "MODEL_UNAVAILABLE"
    assert "INVALID_OUTPUT" in res2.reasons[0]
    assert len(seen2) == 2
    # nothing was written to disk
    assert (scope2.work_dir / "app.py").read_text(encoding="utf-8") == VULN_APP


def test_ambiguous_find_feedback_has_count_and_no_labels(tmp_path):
    client, seen = mock_client([
        edits_json("y = 2", "y = 3", explanation="FIRST EXPLANATION MUST NOT COME BACK"),
        edits_json("y = 2\ny = 2", "y = 3\ny = 3"),
    ])
    scope = make_scope(tmp_path, AMBIG_APP)
    loc = DiagnosedLocation(file="app.py", line_start=2, line_end=3, reasoning="dup lines")
    res = generate_patch_edits(scope, loc, vuln_class="sql_injection", method="GET",
                               endpoint="/user", summary="s", client=client)
    assert res.status == "VALIDATED", res.reasons
    assert res.retries_used == 1
    second_prompt = seen[1]["messages"][-1]["content"]
    # deterministic edit feedback: edit number + count
    assert "occurs 2 times" in second_prompt
    # never the model's earlier explanation...
    assert "FIRST EXPLANATION MUST NOT COME BACK" not in second_prompt
    # ...and never any ground-truth/verifier label text
    for label in ("PLANTED", "ground truth", "forbidden_outcome", "goal_assertion",
                  "VERIFIED", "verifier"):
        assert label not in second_prompt


def test_prose_wrapped_code_fence_rejected(tmp_path):
    prose = ("Here is the patch you asked for:\n```json\n" + edits_json(GOOD_FIND, GOOD_REPLACE)
             + "\n```\nHope that helps!")
    client, seen = mock_client([prose, prose])
    scope = make_scope(tmp_path, VULN_APP)
    res = run(scope, client)
    # prose around the fence defeats the one-fence leniency -> INVALID_OUTPUT after the
    # client's single re-ask, mirrored into the same result shape the diff path returns
    assert res.status == "MODEL_UNAVAILABLE"
    assert "INVALID_OUTPUT" in res.reasons[0]
    assert len(seen) == 2
    assert (scope.work_dir / "app.py").read_text(encoding="utf-8") == VULN_APP


# --------------------------------------------------------------------------
# STEP 2.2: end-to-end (edits path -> real verify control flow -> real ladder)
# The environment-touching leaf checks of verify_patch (docker php -l / node
# --check, lab server materialization, benign traffic module, full scan) are
# replaced by deterministic in-process fakes; verify_patch's own control flow,
# check names and status derivation run for real, as do apply_edits,
# validate_diff, write_edits and ladder.decide.
# --------------------------------------------------------------------------

E2E_APP = (
    "import db\n"
    "\n"
    "def greet(name):\n"
    "    return \"hello \" + name\n"
    "\n"
    "def show_user(uid):\n"
    "    cur = db.execute(\"SELECT * FROM users WHERE id = \" + uid)\n"
    "    return cur.fetchall()\n"
)
WEAKNESS_MARK = 'WHERE id = " + uid'
BENIGN_MARK = '"hello "'
ORIGINAL_FINDINGS = [{"candidate": {"vuln_class": "sql_injection", "endpoint": "/user",
                                    "method": "GET"},
                      "verification": {"state": "confirmed"}}]


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "db.sqlite")
    migrate(c)
    return c


def _e2e_run(tmp_path, monkeypatch, response: str):
    """Fresh src/work pair, one mocked model response, faked verify leaf checks.
    Returns (src, work, PatchGenResult, VerificationReport)."""
    src, work = tmp_path / "src", tmp_path / "work"
    src.mkdir()
    work.mkdir()
    (src / "app.py").write_text(E2E_APP, encoding="utf-8", newline="")
    (work / "app.py").write_text(E2E_APP, encoding="utf-8", newline="")
    scope = RepoScope(lab="t", source_dir=src, work_dir=work)
    holder: dict[str, Any] = {"scope": scope}

    def fake_syntax(_scope, _file):
        return True, "syntax check faked for unit test"

    def fake_benign(_inst):
        ok = BENIGN_MARK in holder["scope"].resolve_in_scope("app.py").read_text(encoding="utf-8")
        return ok, ("greet feature ok" if ok else "greet feature broke")

    def fake_full_scan(_inst, _findings, _key):
        text = holder["scope"].resolve_in_scope("app.py").read_text(encoding="utf-8")
        still = WEAKNESS_MARK in text
        return (not still), f"still_broken={still}", []

    monkeypatch.setattr(verify_module, "materialize",
                        lambda _scope: SimpleNamespace(base_url="http://127.0.0.1:1",
                                                       lab="t", stop=lambda: None))
    monkeypatch.setattr(verify_module, "_syntax_check", fake_syntax)
    monkeypatch.setattr(verify_module, "_benign_traffic_check", fake_benign)
    monkeypatch.setattr(verify_module, "_full_scan_check", fake_full_scan)

    def wrapped(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": response}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 400, "completion_tokens": 120}})

    cfg = ModelConfig(provider="nvidia", base_url="https://api.example.test/v1",
                      model="meta/mock", api_key=SecretStr("sk-fake-test-key-000"),
                      max_rpm=6000, max_retries=0)
    client = ModelClient(cfg, transport=httpx.MockTransport(wrapped), sleep=lambda s: None)
    loc = DiagnosedLocation(file="app.py", line_start=7, line_end=7,
                            reasoning="concatenated query string")
    res = generate_patch_edits(scope, loc, vuln_class="sql_injection", method="GET",
                               endpoint="/user", summary="SQL injection", client=client)
    report = verify_patch(scope, patch_id="t", diff_text=res.diff, allowed_files={"app.py"},
                          diagnosed_file="app.py", vuln_class="sql_injection",
                          endpoint="/user", method="GET",
                          original_findings=ORIGINAL_FINDINGS)
    return src, work, res, report


def test_e2e_correct_edit_verified_and_awaits_approval(tmp_path, monkeypatch, conn):
    src, work, res, report = _e2e_run(
        tmp_path, monkeypatch, edits_json(GOOD_FIND, GOOD_REPLACE))
    assert res.status == "VALIDATED", res.reasons
    assert report.status.name == "VERIFIED"
    policy_entry = FixPolicyEntry(fix_category=FixCategory.PARAMETERIZED_QUERY,
                                  decision="AUTO")
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=policy_entry, patch=res, verification=report,
                            rejected_count=0, evidence_event_ids=[], files_touched=["app.py"])
    assert outcome.status == "AWAITING_APPROVAL"
    # a verified patch is still only a PROPOSAL: no approval recorded, nothing applied
    assert conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0
    # the disposable copy is patched; the ORIGINAL source dir is untouched
    assert WEAKNESS_MARK not in (work / "app.py").read_text(encoding="utf-8")
    assert WEAKNESS_MARK in (src / "app.py").read_text(encoding="utf-8")


def test_e2e_benign_breaking_edit_rejected(tmp_path, monkeypatch, conn):
    src, work, res, report = _e2e_run(
        tmp_path, monkeypatch,
        edits_json('return "hello " + name', 'return "goodbye"',
                   explanation="oops, broke greet"))
    assert res.status == "VALIDATED"  # the edit applies, but that is not enough
    failed = [c.result.name for c in report.checks if not c.result.passed]
    assert "benign_traffic" in failed
    assert report.status.name == "REJECTED"
    policy_entry = FixPolicyEntry(fix_category=FixCategory.PARAMETERIZED_QUERY,
                                  decision="AUTO")
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=policy_entry, patch=res, verification=report,
                            rejected_count=0, evidence_event_ids=[], files_touched=["app.py"])
    assert outcome.status == "REJECTED_RETRY"  # never VERIFIED, approval never recorded
    assert conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM patches").fetchone()[0] == 1  # proposal kept
    # the original source dir still has everything (no partial modification leaked)
    assert (src / "app.py").read_text(encoding="utf-8") == E2E_APP
    assert "goodbye" not in (src / "app.py").read_text(encoding="utf-8")


def test_e2e_weakness_left_in_place_rejected(tmp_path, monkeypatch, conn):
    # an edit that applies and keeps benign behavior, but does not touch the weakness
    src, work, res, report = _e2e_run(
        tmp_path, monkeypatch,
        edits_json("import db", "import db  # reviewed", explanation="cosmetic only"))
    assert res.status == "VALIDATED", res.reasons
    failed = [c.result.name for c in report.checks if not c.result.passed]
    assert any("exploit_no_longer_reproduces" in n for n in failed)
    assert report.status.name == "REJECTED"
    policy_entry = FixPolicyEntry(fix_category=FixCategory.PARAMETERIZED_QUERY,
                                  decision="AUTO")
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=policy_entry, patch=res, verification=report,
                            rejected_count=0, evidence_event_ids=[], files_touched=["app.py"])
    assert outcome.status == "REJECTED_RETRY"
    # the weakness is still in the disposable copy too (honest state, not a fake success)
    assert WEAKNESS_MARK in (work / "app.py").read_text(encoding="utf-8")


def test_exhausted_edit_retries_escalate_with_ticket(tmp_path, conn):
    # every attempt returns the same ambiguous find -> 3 attempts (1 + MAX_RETRIES=2)
    # all fail -> REJECTED -> the ladder escalates instead of recording a fake success
    client, seen = mock_client([edits_json("y = 2", "y = 3")])
    scope = make_scope(tmp_path, AMBIG_APP)
    loc = DiagnosedLocation(file="app.py", line_start=2, line_end=3, reasoning="dup lines")
    res = generate_patch_edits(scope, loc, vuln_class="sql_injection", method="GET",
                               endpoint="/user", summary="s", client=client)
    assert res.status == "REJECTED"
    assert res.retries_used == 2
    assert len(seen) == 3  # exactly 1 + MAX_RETRIES model calls, then it stops
    outcome = ladder.decide(conn, finding_id="f1", vuln_class="sql_injection",
                            policy_entry=None, patch=res, verification=None,
                            rejected_count=0, evidence_event_ids=[], files_touched=["app.py"])
    assert outcome.status == "ESCALATED"
    assert outcome.ticket_id is not None
    assert conn.execute("SELECT COUNT(*) FROM escalations").fetchone()[0] == 1
    body = json.loads(conn.execute("SELECT body FROM escalations WHERE id = ?",
                                   (outcome.ticket_id,)).fetchone()["body"])
    assert "REJECTED" in body["explanation"]  # the real status, not a fabricated success
    assert conn.execute("SELECT COUNT(*) FROM patches").fetchone()[0] == 0


def test_fake_api_key_never_reaches_any_prompt(tmp_path, monkeypatch):
    canary = "sk-FAKE1234567890abcdefghij"
    monkeypatch.setenv("MODEL_API_KEY", canary)
    client, seen = mock_client([edits_json(GOOD_FIND, GOOD_REPLACE)])
    scope = make_scope(tmp_path, VULN_APP)
    res = run(scope, client)
    assert res.status == "VALIDATED", res.reasons
    for body in seen:  # every captured prompt (as actually sent)
        assert canary not in json.dumps(body)
    assert canary not in res.diff
    assert canary not in res.explanation
    assert canary not in (scope.work_dir / "app.py").read_text(encoding="utf-8")


def test_patch_format_switch_selects_the_right_generator():
    # default with no override stays "diff"
    policy_default = FixPolicy(policy_version="t", entries={})
    assert policy_default.patch_format == "diff"
    assert select_generator(policy_default) is generate_patch
    # config says edits
    policy_edits = FixPolicy(policy_version="t", entries={}, patch_format="edits")
    assert select_generator(policy_edits) is generate_patch_edits
    # explicit override wins over the config, in both directions
    assert select_generator(policy_default, patch_format="edits") is generate_patch_edits
    assert select_generator(policy_edits, patch_format="diff") is generate_patch
    # unknown formats fail loudly instead of silently running a different mode
    with pytest.raises(ValueError, match="unknown patch_format"):
        select_generator(policy_default, patch_format="bogus")
