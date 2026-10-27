"""Table-driven URL / destination tests. No DNS, no network."""

import pytest

from sentinelx.policy.urls import check_redirect, check_url, normalize_url, parse_host_entry

ALLOWED = ["orders.lab.test", "api.lab.test:8080"]
PAGE = "http://orders.lab.test/cart"

# (url, expected reason_code) -- every one of these must NOT be ok
BYPASSES = [
    ("http://orders.lab.test@evil.example/", "USERINFO_IN_URL"),
    ("http://orders.lab.test:pw@orders.lab.test/", "USERINFO_IN_URL"),
    ("http://orders.lab.test.evil.example/", "HOST_NOT_ALLOWED"),
    ("http://evil.example/orders.lab.test", "HOST_NOT_ALLOWED"),
    ("http://evil.example/?h=orders.lab.test", "HOST_NOT_ALLOWED"),
    ("http://EVIL.EXAMPLE/", "HOST_NOT_ALLOWED"),
    ("HtTp://Evil.Example/", "HOST_NOT_ALLOWED"),
    ("http://xorders.lab.test/", "HOST_NOT_ALLOWED"),
    ("http://lab.test/", "HOST_NOT_ALLOWED"),
    ("http://orders.lab.test./", "TRAILING_DOT"),
    ("http://orders.lab.test:8080/", "PORT_NOT_ALLOWED"),
    ("https://orders.lab.test:443x/", "INVALID_PORT"),
    ("http://orders.lab.test:99999/", "INVALID_PORT"),
    ("http://api.lab.test/", "PORT_NOT_ALLOWED"),
    ("http://api.lab.test:80/", "PORT_NOT_ALLOWED"),
    ("http://127.0.0.1/", "IP_LITERAL_NOT_ALLOWED"),
    ("http://2130706433/", "NONCANONICAL_IP"),
    ("http://0x7f000001/", "NONCANONICAL_IP"),
    ("http://0177.0.0.1/", "NONCANONICAL_IP"),
    ("http://127.1/", "NONCANONICAL_IP"),
    ("http://[::1]/", "IP_LITERAL_NOT_ALLOWED"),
    ("http://[0:0:0:0:0:0:0:1]/", "NONCANONICAL_IP"),
    ("http://[::ffff:127.0.0.1]/", "NONCANONICAL_IP"),
    ("http://1.2.3.4.5/", "INVALID_IP_HOST"),
    ("http://xn--rders-iye.lab.test/", "HOST_NOT_ALLOWED"),
    ("http://оrders.lab.test/", "IDN_HOST_NOT_ALLOWED"),  # Cyrillic o
    ("http://orders.lab.tеst/", "IDN_HOST_NOT_ALLOWED"),  # Cyrillic e
    ("http://ｏrders.lab.test/", "IDN_NORMALIZES_TO_ASCII"),  # fullwidth o
    ("javascript:alert(1)", "SCHEME_NOT_ALLOWED"),
    ("JaVaScRiPt:alert(1)", "SCHEME_NOT_ALLOWED"),
    ("data:text/html,<script>1</script>", "SCHEME_NOT_ALLOWED"),
    ("file:///etc/passwd", "SCHEME_NOT_ALLOWED"),
    ("blob:http://orders.lab.test/uuid", "SCHEME_NOT_ALLOWED"),
    ("ftp://orders.lab.test/", "SCHEME_NOT_ALLOWED"),
    ("chrome://settings", "SCHEME_NOT_ALLOWED"),
    ("view-source:http://orders.lab.test/", "SCHEME_NOT_ALLOWED"),
    ("about:blank", "SCHEME_NOT_ALLOWED"),  # only if configured
    ("//evil.example/x", "HOST_NOT_ALLOWED"),  # protocol-relative, resolved against page
    ("///evil.example/x", "EMPTY_HOST"),
    ("http:evil.example", "MALFORMED_AUTHORITY"),
    ("http:///evil.example/", "EMPTY_HOST"),
    ("http:\\\\evil.example", "BACKSLASH_IN_URL"),
    ("http://evil.example\\@orders.lab.test/", "BACKSLASH_IN_URL"),
    ("/\\evil.example", "BACKSLASH_IN_URL"),
    ("http://evil.example%2f.orders.lab.test/", "ENCODED_AUTHORITY"),
    ("http://orders.lab.test%2f@evil.example/", "USERINFO_IN_URL"),
    ("http://%65vil.example/", "ENCODED_AUTHORITY"),
    ("http://orders.lab.test%00.evil.example/", "ENCODED_AUTHORITY"),
    ("http://orders.lab.test\t.evil.example/", "CONTROL_OR_WHITESPACE"),
    ("http://orders.lab.test\n/", "CONTROL_OR_WHITESPACE"),
    (" http://orders.lab.test/", "CONTROL_OR_WHITESPACE"),
    ("http://orders.lab.test:80:80/", "MALFORMED_AUTHORITY"),
    ("http://[::1/", "MALFORMED_AUTHORITY"),
    ("http://", "EMPTY_HOST"),
    ("", "EMPTY_URL"),
    ("http://" + "a" * 70 + ".lab.test/", "INVALID_HOST"),
    ("http://a..lab.test/", "INVALID_HOST"),
    ("http://under_score.lab.test/", "INVALID_HOST"),
    (None, "URL_NOT_A_STRING"),
    (42, "URL_NOT_A_STRING"),
    ("http://orders.lab.test/" + "a" * 3000, "URL_TOO_LONG"),
    ("../../../etc/passwd?x", "HOST_NOT_ALLOWED"),  # relative: resolves, but see below
]


@pytest.mark.parametrize(("url", "code"), BYPASSES, ids=[repr(u)[:50] for u, _ in BYPASSES])
def test_bypass_attempts_are_rejected_with_precise_reason(url, code) -> None:
    res = check_url(url, ALLOWED, base=PAGE)
    if url == "../../../etc/passwd?x":  # stays on the allowed page host: legitimately in scope
        assert res.ok and res.host == "orders.lab.test"
        return
    assert not res.ok, f"{url!r} must not be ok"
    assert res.reason_code == code


def test_relative_url_resolving_off_scope_is_rejected() -> None:
    # the *page* is on an allowed host, but a relative link that resolves elsewhere is not
    assert not check_url("//evil.example/a", ALLOWED, base=PAGE).ok
    assert check_url("/checkout?x=1", ALLOWED, base=PAGE).host == "orders.lab.test"
    off_page = "http://evil.example/page"
    assert not check_url("/checkout", ALLOWED, base=off_page).ok
    assert check_url("/checkout", ALLOWED, base=None).reason_code == "RELATIVE_URL_WITHOUT_BASE"
    assert check_url("/x", ALLOWED, base="javascript:1").reason_code == "INVALID_BASE_URL"


OK_CASES = [
    ("http://orders.lab.test/", "orders.lab.test", 80),
    ("https://orders.lab.test/a/b?q=1#frag", "orders.lab.test", 443),
    ("HTTP://ORDERS.LAB.TEST/", "orders.lab.test", 80),
    ("http://orders.lab.test:80/", "orders.lab.test", 80),
    ("http://api.lab.test:8080/v1", "api.lab.test", 8080),
]


@pytest.mark.parametrize(("url", "host", "port"), OK_CASES)
def test_in_scope_urls_ok(url, host, port) -> None:
    res = check_url(url, ALLOWED)
    assert res.ok and res.host == host and res.port == port and res.reason_code == "OK"
    assert "#" not in (res.normalized_url or "")


def test_ip_literals_only_when_listed_and_only_canonical() -> None:
    allowed = ["127.0.0.1:9000", "[::1]:9001"]
    assert check_url("http://127.0.0.1:9000/", allowed).ok
    assert check_url("http://[::1]:9001/", allowed).ok
    assert not check_url("http://127.0.0.1:9001/", allowed).ok
    for variant in ("http://2130706433:9000/", "http://0x7f000001:9000/", "http://127.1:9000/"):
        assert check_url(variant, allowed).reason_code == "NONCANONICAL_IP"
    assert not check_url("http://[0::1]:9001/", allowed).ok


def test_listed_idn_must_be_listed_as_punycode() -> None:
    puny = "оrders.lab.test".encode("idna").decode("ascii")
    assert puny == "xn--rders-iye.lab.test"
    assert check_url("http://оrders.lab.test/", [puny]).ok
    assert not check_url("http://оrders.lab.test/", ["orders.lab.test"]).ok


def test_trailing_dot_normalised_only_when_configured() -> None:
    assert not check_url("http://orders.lab.test./", ALLOWED).ok
    assert check_url("http://orders.lab.test./", ALLOWED, trailing_dot="normalize").ok
    assert not check_url("http://orders.lab.test../", ALLOWED, trailing_dot="normalize").ok


def test_about_blank_only_when_configured() -> None:
    assert not check_url("about:blank", ALLOWED).ok
    assert check_url("about:blank", ALLOWED, allow_about_blank=True).ok
    assert not check_url("about:srcdoc", ALLOWED, allow_about_blank=True).ok


def test_no_wildcards_or_suffix_matching_in_entries() -> None:
    bad_entries = ("*.lab.test", "lab.test/*", "orders.lab.test.", " orders.lab.test", "a@b", "")
    for bad in (*bad_entries, None):
        assert parse_host_entry(bad) is None
    assert not check_url("http://orders.lab.test/", ["*.lab.test"]).ok
    assert not check_url("http://orders.lab.test/", ["lab.test"]).ok
    assert not check_url("http://orders.lab.test/", ["rders.lab.test"]).ok


def test_redirect_hops_use_same_rules() -> None:
    src = "http://orders.lab.test/start"
    assert check_redirect(src, "/next", ALLOWED).ok
    assert check_redirect(src, "http://api.lab.test:8080/x", ALLOWED).ok
    assert not check_redirect(src, "http://evil.example/", ALLOWED).ok
    assert not check_redirect(src, "//evil.example/", ALLOWED).ok
    assert not check_redirect(src, "javascript:alert(1)", ALLOWED).ok
    assert not check_redirect("http://evil.example/", "/next", ALLOWED).ok


def test_normalize_returns_structured_result() -> None:
    res = normalize_url("HTTPS://Orders.Lab.Test:8443/a?b=c#d")
    assert (res.ok, res.scheme, res.host, res.port) == (True, "https", "orders.lab.test", 8443)
    assert res.normalized_url == "https://orders.lab.test:8443/a?b=c"
