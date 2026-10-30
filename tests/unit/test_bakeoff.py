"""Focused checks for URL normalisation and allowlist matching."""

from sentinelx.policy.urls import check_url

ALLOWED = ["orders.lab.test"]


def test_allowed_host_is_accepted():
    res = check_url("http://orders.lab.test/checkout", ALLOWED)
    assert res.ok
    assert res.host == "orders.lab.test"
    assert res.normalized_url == "http://orders.lab.test/checkout"


def test_userinfo_trick_is_rejected():
    res = check_url("http://orders.lab.test@evil.example/", ALLOWED)
    assert not res.ok
    assert res.reason_code == "USERINFO_IN_URL"


def test_look_alike_host_is_rejected():
    res = check_url("http://orders.lab.test.evil.example/", ALLOWED)
    assert not res.ok
    assert res.reason_code == "HOST_NOT_ALLOWED"
    assert res.host == "orders.lab.test.evil.example"
