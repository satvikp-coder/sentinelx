"""Redaction tests use SYNTHETIC fake secrets only (clearly non-functional values)."""

import pytest

from sentinelx.policy.redaction import redact

FAKE_NVAPI = "nvapi-" + "A1b2C3d4" * 5
FAKE_SK = "sk-" + "Zz9Yy8Xx" * 4
FAKE_GHP = "ghp_" + "a1B2c3D4e5" * 3 + "abcdef"
FAKE_AKIA = "AKIA" + "FAKEFAKEFAKEFAKE"
FAKE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.ZmFrZXNpZw"
FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\nZmFrZWZha2VmYWtlZmFrZQ==\n-----END RSA PRIVATE KEY-----"
)


@pytest.mark.parametrize(
    "secret",
    [FAKE_NVAPI, FAKE_SK, FAKE_GHP, FAKE_AKIA, FAKE_JWT, FAKE_PEM],
    ids=["nvapi", "sk", "ghp", "akia", "jwt", "pem"],
)
def test_prefixed_secrets_removed(secret: str) -> None:
    res = redact(f"before {secret} after")
    assert secret not in res.value
    assert res.value.startswith("before ") and res.value.endswith(" after")
    assert res.count == 1


def test_bearer_token_removed() -> None:
    res = redact("Authorization: Bearer abc123DEF456ghi789")
    assert "abc123DEF456ghi789" not in res.value
    assert res.count >= 1


def test_cookie_and_set_cookie_values_removed() -> None:
    res = redact("Cookie: session=fakevalue123; theme=dark\nSet-Cookie: sid=fakesid999; HttpOnly")
    assert "fakevalue123" not in res.value and "fakesid999" not in res.value
    assert "Cookie:" in res.value and "Set-Cookie:" in res.value
    assert res.count == 2


def test_password_kv_in_string() -> None:
    res = redact("login failed password=hunter2fake for user bob")
    assert "hunter2fake" not in res.value
    assert "user bob" in res.value
    assert res.count == 1


def test_dict_sensitive_keys_and_nesting() -> None:
    data = {
        "user": "bob",
        "password": "hunter2fake",
        "headers": {"Authorization": "Bearer zzz", "Accept": "text/html"},
        "items": [{"api_key": "k-fake-1"}, "plain", {"note": f"key {FAKE_SK}"}],
        "n": 5,
    }
    res = redact(data)
    out = res.value
    assert out["user"] == "bob" and out["n"] == 5
    assert out["password"] != "hunter2fake"
    assert out["headers"]["Accept"] == "text/html"
    assert out["headers"]["Authorization"] != "Bearer zzz"
    assert out["items"][0]["api_key"] != "k-fake-1"
    assert FAKE_SK not in str(out)
    assert out["items"][1] == "plain"
    assert res.count == 4
    assert data["password"] == "hunter2fake"  # input is not mutated


def test_ordinary_text_untouched() -> None:
    text = "The skill of a task-driven agent; password policy docs; Bearer of news."
    res = redact(text)
    assert res.value == text
    assert res.count == 0
    obj = {"a": [1, 2.5, None, True, "hello world"], "b": {"c": "d"}}
    assert redact(obj).value == obj and redact(obj).count == 0


def test_idempotent() -> None:
    once = redact(f"x {FAKE_JWT} y password=abc12345").value
    again = redact(once)
    assert again.value == once and again.count == 0
