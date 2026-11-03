"""Tests for Task 23 scanner improvements: stored_xss and authz_post checks.

All tests use a mock ScanContext (no real server, no Docker). The check functions are
pure: they take a ScanContext and return list[Candidate]. We mock ctx.get() and ctx.call()
to return deterministic Outcome objects.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from sentinelx.common_schemas import Severity, VulnClass
from sentinelx.scanner.checks.authz_post import SPEC as AUTHZ_POST_SPEC
from sentinelx.scanner.checks.authz_post import run as run_authz_post
from sentinelx.scanner.checks.stored_xss import SPEC as STORED_XSS_SPEC
from sentinelx.scanner.checks.stored_xss import run as run_stored_xss


class FakeOutcome:
    """Minimal stand-in for sentinelx.scanner.http.Outcome."""
    def __init__(self, allowed: bool = True, status: int = 200, text: str = "",
                 event_id: str = "evt_test", headers: dict | None = None):
        self.allowed = allowed
        self.status = status
        self.body = text.encode("utf-8") if text else b""
        self.event_id = event_id
        self.headers = headers or {}
        self.reason = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class FakeCtx:
    """Minimal stand-in for sentinelx.scanner.context.ScanContext."""

    def __init__(self) -> None:
        self.get_results: dict[str, FakeOutcome] = {}
        self.call_results: dict[tuple[str, str, str], FakeOutcome] = {}
        self.personas_file = SimpleNamespace(
            login=SimpleNamespace(method="POST", path="/api/login", encoding="json",
                                  username_field="username", password_field="password",
                                  token_key="token"),
            failed_login_username="ghost_nonexistent",
            personas=[
                SimpleNamespace(name="anonymous", role="visitor", credentials=None),
                SimpleNamespace(name="user_a", role="user",
                                credentials=SimpleNamespace(
                                    username="carol", password="carolpass")),
                SimpleNamespace(name="user_b", role="user",
                                credentials=SimpleNamespace(username="dave", password="davepass")),
                SimpleNamespace(name="admin_guesser", role="visitor", credentials=None),
            ],
        )
        self.profile = SimpleNamespace(state_changing=True)
        self.cookies: dict[str, str] = {}
        # A minimal fake client whose .request() returns a successful outcome,
        # so that session.login() works without a real HTTP server.
        self.client = SimpleNamespace(
            request=lambda method, url, headers=None, body=None, **kwargs: FakeOutcome(
                allowed=True, status=200, text='{"ok":true}', event_id="evt_login"),
        )
        self.base_url = "http://127.0.0.1:18081"

    def headers(self) -> dict[str, str]:
        return {}

    def ensure_persona(self, persona: str, *, fresh: bool = False) -> FakeCtx:
        return self

    def get(self, persona: str, path: str, **kwargs: Any) -> FakeOutcome:
        return self.get_results.get((persona, path), FakeOutcome(allowed=False, status=0))

    def call(self, persona: str, method: str, path: str, **kwargs: Any) -> FakeOutcome:
        key = (persona, method.upper(), path)
        return self.call_results.get(key, FakeOutcome(allowed=False, status=0))


def make_ctx() -> FakeCtx:
    return FakeCtx()


# ------------------------------------------------------------------ stored_xss tests

def test_stored_xss_marker_reflected_unencoded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stored XSS marker set via POST /api/profile is reflected unencoded on /u/carol."""
    ctx = make_ctx()
    # user_a sets bio (state-changing PUT)
    ctx.call_results[("user_a", "PUT", "/api/profile")] = FakeOutcome(
        allowed=True, status=200, text='{"ok":true}', event_id="evt_put_bio")
    # anonymous fetches public profile - marker IS reflected unencoded
    ctx.get_results[("anonymous", "/u/carol")] = FakeOutcome(
        allowed=True, status=200,
        text='<h1>Profile: carol</h1><p>sx_stored_xss_<"\'>&z</p>',
        event_id="evt_get_profile")

    monkeypatch.setattr(
        "sentinelx.scanner.session.login",
        lambda client, base_url, session, spec: True,
    )

    results = run_stored_xss(ctx)
    assert len(results) == 1
    c = results[0]
    assert c.check_id == STORED_XSS_SPEC.id
    assert c.vuln_class == VulnClass.XSS_STORED
    assert c.severity == Severity.MEDIUM
    assert c.method == "GET"
    assert c.endpoint == "/u/:username"
    assert c.persona == "anonymous"
    assert "unencoded" in c.summary
    assert "evt_put_bio" in c.evidence_event_ids or "evt_get_profile" in c.evidence_event_ids


def test_stored_xss_marker_encoded_not_vulnerable(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the marker is HTML-encoded on the profile page, no finding."""
    ctx = make_ctx()
    ctx.call_results[("user_a", "PUT", "/api/profile")] = FakeOutcome(
        allowed=True, status=200, text='{"ok":true}', event_id="evt_put_bio")
    ctx.get_results[("anonymous", "/u/carol")] = FakeOutcome(
        allowed=True, status=200,
        text='<h1>Profile: carol</h1><p>sx_stored_xss_&lt;&quot;&gt;&amp;&z</p>',
        event_id="evt_get_profile")

    monkeypatch.setattr(
        "sentinelx.scanner.session.login",
        lambda client, base_url, session, spec: True,
    )

    results = run_stored_xss(ctx)
    assert len(results) == 0


def test_stored_xss_profile_update_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the profile update is refused, no finding."""
    ctx = make_ctx()
    ctx.call_results[("user_a", "PUT", "/api/profile")] = FakeOutcome(
        allowed=False, status=403, text="forbidden", event_id="evt_put_refused")

    monkeypatch.setattr(
        "sentinelx.scanner.session.login",
        lambda client, base_url, session, spec: True,
    )

    results = run_stored_xss(ctx)
    assert len(results) == 0


# ------------------------------------------------------------------ authz_post tests

def test_authz_post_user_b_can_modify_user_a_note(monkeypatch: pytest.MonkeyPatch) -> None:
    """user_b can modify user_a's note via PUT /api/notes/:id (BOLA)."""
    ctx = make_ctx()
    # user_a creates note
    ctx.call_results[("user_a", "POST", "/api/notes")] = FakeOutcome(
        allowed=True, status=201,
        text='{"id":42,"title":"sx_authz_post_xxx","body":"user_a private note"}',
        event_id="evt_create_note")
    # user_b modifies note via PUT
    ctx.call_results[("user_b", "PUT", "/api/notes/42")] = FakeOutcome(
        allowed=True, status=200, text='{"ok":true}', event_id="evt_put_note")

    monkeypatch.setattr(
        "sentinelx.scanner.session.login",
        lambda client, base_url, session, spec: True,
    )

    results = run_authz_post(ctx)
    assert len(results) == 1
    c = results[0]
    assert c.check_id == AUTHZ_POST_SPEC.id
    assert c.vuln_class == VulnClass.BROKEN_OBJECT_AUTHORIZATION
    assert c.severity == Severity.HIGH
    assert c.method == "PUT"
    assert c.endpoint == "/api/notes/:id"
    assert c.persona == "user_b"
    assert "modify user_a's note" in c.summary
    assert "evt_create_note" in c.evidence_event_ids or "evt_put_note" in c.evidence_event_ids


def test_authz_post_user_b_cannot_modify(monkeypatch: pytest.MonkeyPatch) -> None:
    """user_b cannot modify user_a's note (ownership enforced)."""
    ctx = make_ctx()
    ctx.call_results[("user_a", "POST", "/api/notes")] = FakeOutcome(
        allowed=True, status=201,
        text='{"id":42,"title":"sx_authz_post_xxx","body":"user_a private note"}',
        event_id="evt_create_note")
    # user_b's PUT is refused (403)
    ctx.call_results[("user_b", "PUT", "/api/notes/42")] = FakeOutcome(
        allowed=False, status=403, text='{"error":"forbidden"}', event_id="evt_put_refused")

    monkeypatch.setattr(
        "sentinelx.scanner.session.login",
        lambda client, base_url, session, spec: True,
    )

    results = run_authz_post(ctx)
    assert len(results) == 0


def test_authz_post_note_creation_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """If user_a cannot create a note, no finding."""
    ctx = make_ctx()
    ctx.call_results[("user_a", "POST", "/api/notes")] = FakeOutcome(
        allowed=False, status=403, text="forbidden", event_id="evt_create_refused")

    monkeypatch.setattr(
        "sentinelx.scanner.session.login",
        lambda client, base_url, session, spec: True,
    )

    results = run_authz_post(ctx)
    assert len(results) == 0


# ------------------------------------------------------------------ severity table updated

def test_severity_table_includes_xss_stored() -> None:
    from sentinelx.scanner.checks.base import SEVERITY_BY_CLASS
    assert SEVERITY_BY_CLASS[VulnClass.XSS_STORED] == Severity.MEDIUM


def test_catalog_includes_new_checks() -> None:
    from sentinelx.scanner.checks import CATALOG
    assert "stored_xss" in CATALOG
    assert "authz_post" in CATALOG
    assert CATALOG["stored_xss"].spec.id == "stored_xss"
    assert CATALOG["authz_post"].spec.id == "authz_post"


# ------------------------------------------------------------------ verify new checks import

def test_stored_xss_importable() -> None:
    from sentinelx.scanner.checks.stored_xss import run
    assert callable(run)


def test_authz_post_importable() -> None:
    from sentinelx.scanner.checks.authz_post import run
    assert callable(run)
