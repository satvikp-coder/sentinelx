"""Hard safety rules for sentinelx.scanner: login-burst cap, declared methods only, persona
credentials refused for non-lab targets, PLANTED.json/_reference unreachable, the model cannot
add a request or confirm anything, and a stopped scan makes no further request."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from sentinelx.model_clients import ModelClient, ModelConfig
from sentinelx.scanner import model_assist
from sentinelx.scanner.checks.rate_limit import HARD_CAP
from sentinelx.scanner.models import SiteScanProfile

ROOT = Path(__file__).resolve().parents[2]


def test_login_burst_is_hard_capped_at_15_regardless_of_the_profile() -> None:
    assert HARD_CAP == 15
    with pytest.raises(ValidationError):
        SiteScanProfile.model_validate({
            "profile_version": "v", "name": "n", "checks": ["missing_rate_limit"],
            "login_burst": 16, "personas": ["anonymous"]})
    # the field itself clamps to the catalog's own hard ceiling
    ok = SiteScanProfile.model_validate({
        "profile_version": "v", "name": "n", "checks": ["missing_rate_limit"], "login_burst": 15,
        "personas": ["anonymous"]})
    assert ok.login_burst == 15 == HARD_CAP


def test_scanner_never_imports_or_opens_planted_or_reference_paths() -> None:
    offenders: list[str] = []
    for path in (ROOT / "packages" / "scanner").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "_reference" in text or "PLANTED" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], offenders


def test_scanner_code_never_reaches_the_network_except_through_guardedclient() -> None:
    forbidden = {"httpx", "requests", "urllib3", "aiohttp", "socket", "ftplib", "smtplib",
                "telnetlib", "websockets", "websocket"}
    offenders: list[str] = []
    for path in (ROOT / "packages" / "scanner").rglob("*.py"):
        if path.name == "http.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module.split(".")[0]]
            offenders += [f"{path.relative_to(ROOT)}: {m}" for m in mods if m in forbidden]
    assert offenders == [], offenders


def test_persona_credentials_are_refused_for_a_non_lab_target() -> None:
    from sentinelx.scanner.authz import AuthzConfig, register_non_lab_target
    from sentinelx.scanner.models import Credentials, Persona
    from sentinelx.scanner.session import PersonaCredentialError, new_session

    target = register_non_lab_target(AuthzConfig(allow_non_lab_targets=True), "n",
                                      "owner.example.net", 443, "https")
    persona = Persona(name="user_a", role="user",
                      credentials=Credentials(username="a", password="b"))
    with pytest.raises(PersonaCredentialError):
        new_session(target, persona)


def mock_model(handler) -> tuple[ModelClient, list[dict]]:
    seen: list[dict] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        out = handler(len(seen))
        if isinstance(out, httpx.Response):
            return out
        content = out if isinstance(out, str) else json.dumps(out)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10}})

    cfg = ModelConfig(provider="nvidia", base_url="https://api.example.test/v1",
                      model="meta/mock", api_key=SecretStr("nvapi-" + "D8e9F0g1" * 5),
                      max_rpm=6000, max_retries=0)
    return ModelClient(cfg, transport=httpx.MockTransport(wrapped), sleep=lambda s: None), seen


@pytest.fixture()
def fake_ctx(tmp_path: Path):
    from sentinelx.evidence.db import connect, migrate

    conn = connect(tmp_path / "m.db")
    migrate(conn)

    class FakeCtx:
        inventory: dict = {}
        discovery: dict = {}
        scripts: dict = {}
        personas_file = type("P", (), {"personas": [], "credentials": None})()
        client = type("C", (), {"conn": conn})()

    return FakeCtx()


def test_a_model_suggested_unknown_check_id_is_rejected_and_falls_back_to_the_default(
        fake_ctx) -> None:
    default = ["sql_injection", "missing_rate_limit"]
    client, seen = mock_model(lambda n: {"checks": ["sql_injection", "drop_all_tables"]})
    out = model_assist.suggest_plan(fake_ctx, default, client, "s1")
    assert out.used_model is False and out.checks == default and "unknown check id" in out.note
    assert len(seen) == 1


def test_model_cannot_add_a_request_the_plan_only_orders_the_fixed_catalog(fake_ctx) -> None:
    default = ["sql_injection", "missing_rate_limit", "permissive_cors"]
    client, seen = mock_model(lambda n: {"checks": ["permissive_cors", "sql_injection"]})
    out = model_assist.suggest_plan(fake_ctx, default, client, "s1")
    assert out.used_model and set(out.checks) <= set(default)
    assert out.checks == ["permissive_cors", "sql_injection"]
    assert "http://" not in json.dumps(seen)  # the plan carries no URL, ever


def test_model_unavailable_falls_back_to_the_default_plan(fake_ctx) -> None:
    client, seen = mock_model(lambda n: httpx.Response(503, text="down"))
    default = ["sql_injection"]
    out = model_assist.suggest_plan(fake_ctx, default, client, "s1")
    assert out.used_model is False and out.checks == default and "unavailable" in out.note
    assert len(seen) <= 1


def test_explanations_are_labelled_and_never_invented_for_unconfirmed_findings() -> None:
    from sentinelx.common_schemas import Severity, VulnClass
    from sentinelx.scanner.models import Candidate, Finding, Verification

    confirmed = Candidate(
        id="cand_x_0001", check_id="sql_injection", vuln_class=VulnClass.SQL_INJECTION,
        severity=Severity.HIGH, confidence="high", method="GET", endpoint="/p", endpoints=["/p"],
        persona="anonymous", summary="s", evidence_event_ids=[], excerpt="")
    rejected = confirmed.model_copy(update={"id": "cand_x_0002"})
    findings = [
        Finding(candidate=confirmed, verification=Verification(state="confirmed", detail="d",
                                                               fresh_session=True)),
        Finding(candidate=rejected, verification=Verification(state="rejected", detail="d",
                                                              fresh_session=True)),
    ]
    client, seen = mock_model(lambda n: {"explanations": [
        {"finding_id": "cand_x_0001", "text": "plain language"},
        {"finding_id": "cand_x_0002", "text": "should be ignored"}]})
    out = model_assist.explain_confirmed(findings, client)
    assert out.used_model and out.explanations == {"cand_x_0001": "plain language"}
    assert "cand_x_0002" not in out.explanations
    assert len(seen) == 1


def test_no_explanation_call_is_made_when_nothing_is_confirmed() -> None:
    client, seen = mock_model(lambda n: {"explanations": []})
    out = model_assist.explain_confirmed([], client)
    assert not out.used_model and seen == []


def test_a_quoted_source_code_secret_is_redacted_in_the_excerpt() -> None:
    """The shared redactor's kv_secret pattern stops at a quote character, so source code like
    `const SECRET = 'xxx'` or PHP's `define('APP_SECRET', 'xxx')` slips through it unredacted;
    the scanner must still mask it, without mangling the surrounding quotes."""
    from sentinelx.scanner.checks.base import excerpt, looks_like_a_secret

    js = "const SECRET = 'labsecret_notes_FAKE_7b21c9e4a05d3f68';"
    php = "define('APP_SECRET', 'labsecret_shop_FAKE_0f3a9c71d2e84b65');"
    php2 = "define('ADMIN_PASSWORD', 'labadmin_FAKE_pass_2026');"
    assert looks_like_a_secret(js) and looks_like_a_secret(php) and looks_like_a_secret(php2)
    assert excerpt(js) == "const SECRET = '[REDACTED:secret]';"
    assert excerpt(php) == "define('APP_SECRET', '[REDACTED:secret]');"
    assert excerpt(php2) == "define('ADMIN_PASSWORD', '[REDACTED:secret]');"
    assert not looks_like_a_secret("const GREETING = 'hello there';")
    assert not looks_like_a_secret("const SECRETARY = 'not a secret';")
