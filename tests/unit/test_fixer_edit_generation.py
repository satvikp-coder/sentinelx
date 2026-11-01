"""Tests for generate_patch_edits (edit-based patch generation) with a mocked model client.

The mock follows the established pattern from tests/unit/test_investigator.py: a ModelClient
over httpx.MockTransport returning queued assistant contents. No live model calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from pydantic import SecretStr

from sentinelx.fixer.diff_validator import validate_diff
from sentinelx.fixer.models import DiagnosedLocation, RepoScope
from sentinelx.fixer.patch_gen import generate_patch_edits
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
