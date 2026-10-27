"""Property tests (hypothesis): the gateway never allows an off-scope host, is deterministic, and
never raises on junk input."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sentinelx.common_schemas import Decision
from sentinelx.policy import check_url, evaluate
from tests.unit.test_policy_engine import DEFAULT, PAGE, ctx, req, scenario

SETTINGS = settings(
    max_examples=1000, deadline=None, suppress_health_check=[HealthCheck.too_slow]
)
ALLOWED_HOSTS = {"orders.lab.test", "api.lab.test"}
SCN = scenario()
CTX = ctx()

URL_ALPHABET = "htps:/.@%\\[]-_0123456789abcdefxXEVILorders.lab.test\t оｏ?#=&;"
url_text = st.builds(
    lambda prefix, body: prefix + body,
    st.sampled_from(["http://", "https://", "//", "/", "", "HTTP://", "http:", "javascript:"]),
    st.text(alphabet=URL_ALPHABET, max_size=60),
)


@SETTINGS
@given(url_text)
def test_allow_implies_host_is_in_allowlist(url: str) -> None:
    d = evaluate(req("navigate", url=url), SCN, DEFAULT, CTX)
    if d.decision is Decision.ALLOW:
        host = urlsplit(urljoin(PAGE, url)).hostname
        assert host in ALLOWED_HOSTS, (url, host)
        assert check_url(url, SCN.allowed_hosts, PAGE).ok


@SETTINGS
@given(url_text)
def test_url_not_ok_means_never_allow(url: str) -> None:
    if not check_url(url, SCN.allowed_hosts, PAGE).ok:
        d = evaluate(req("navigate", url=url), SCN, DEFAULT, CTX)
        assert d.decision is not Decision.ALLOW


# Independent oracle: build URLs from known parts and compute the expected verdict by hand.
HOSTS = ["orders.lab.test", "ORDERS.LAB.TEST", "orders.lab.test.", "api.lab.test", "evil.example",
         "orders.lab.test.evil.example", "127.0.0.1", "2130706433", "[::1]",
         "xn--rders-iye.lab.test", "lab.test", "оrders.lab.test"]
USERINFO = ["", "u@", "orders.lab.test@", "u:p@"]
PORTS = ["", ":80", ":443", ":8080", ":9999"]
PATHS = ["", "/", "/x?y=1", "/a%2fb", "\\x", "/\\x"]


def oracle(scheme: str, userinfo: str, host: str, port: str, path: str) -> bool:
    if userinfo or "\\" in path or host.endswith("."):
        return False
    h = host.lower()
    default = ":80" if scheme == "http" else ":443"
    if h == "orders.lab.test":
        return port in ("", default)
    if h == "api.lab.test":
        return port == ":8080"
    return False


@SETTINGS
@given(st.sampled_from(["http", "https"]), st.sampled_from(USERINFO), st.sampled_from(HOSTS),
       st.sampled_from(PORTS), st.sampled_from(PATHS))
def test_composed_urls_match_independent_oracle(scheme, userinfo, host, port, path) -> None:
    url = f"{scheme}://{userinfo}{host}{port}{path}"
    d = evaluate(req("navigate", url=url), SCN, DEFAULT, CTX)
    assert (d.decision is Decision.ALLOW) == oracle(scheme, userinfo, host, port, path), url


def _json_junk() -> st.SearchStrategy[Any]:
    leaf = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True),
                     st.text(max_size=30), st.binary(max_size=8))
    return st.recursive(
        leaf,
        lambda inner: st.one_of(st.lists(inner, max_size=4),
                                st.dictionaries(st.text(max_size=12), inner, max_size=5)),
        max_leaves=15,
    )


junk = _json_junk()


@SETTINGS
@given(junk, junk, junk)
def test_evaluate_never_raises_on_junk(request: Any, scn: Any, context: Any) -> None:
    d = evaluate(request, scn, DEFAULT, context)
    assert d.decision is Decision.BLOCK
    assert d.reason_code == "MALFORMED_REQUEST"
    assert d.effective_action is Decision.BLOCK


@SETTINGS
@given(junk, junk)
def test_junk_scenario_or_context_with_valid_request_blocks(scn: Any, context: Any) -> None:
    d = evaluate(req("read_page"), scn, DEFAULT, context)
    assert d.decision is Decision.BLOCK
    assert d.reason_code in {"SCENARIO_INVALID", "CONTEXT_INVALID"}


@SETTINGS
@given(junk, junk)
def test_junk_policy_blocks(policy: Any, context: Any) -> None:
    d = evaluate(req("read_page"), SCN, policy, context)
    assert d.decision is Decision.BLOCK and d.reason_code == "POLICY_INVALID"


tool_names = st.sampled_from(
    ["navigate", "read_page", "click", "type", "send", "delete", "exec_shell", "teleport", ""]
)
arg_values = st.one_of(st.text(max_size=40), st.integers(), st.none(), st.booleans(), url_text)
random_requests = st.fixed_dictionaries(
    {
        "tool": tool_names,
        "step": st.integers(min_value=0, max_value=30),
        "arguments": st.dictionaries(
            st.sampled_from(["url", "selector", "text", "body", "x"]), arg_values, max_size=3
        ),
    }
)


@SETTINGS
@given(random_requests, st.booleans(), st.integers(0, 70))
def test_evaluate_is_deterministic(r: dict[str, Any], kill: bool, rpm: int) -> None:
    full = req(r["tool"], r["step"], **r["arguments"])
    context = ctx(kill_switch=kill, requests_last_minute=rpm)
    first = evaluate(full, SCN, DEFAULT, context)
    second = evaluate(full, SCN, DEFAULT, context)
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    if kill:
        assert first.decision is Decision.BLOCK


@SETTINGS
@given(random_requests, st.text(max_size=80))
def test_page_text_never_changes_the_decision(r: dict[str, Any], page_text: str) -> None:
    from sentinelx.policy import UntrustedText

    full = req(r["tool"], r["step"], **r["arguments"])
    plain = evaluate(full, SCN, DEFAULT, CTX)
    texty = evaluate(
        full, SCN, DEFAULT, ctx(untrusted_texts=(UntrustedText(source="page", text=page_text),))
    )
    assert (plain.decision, plain.reason_code, plain.rule_ids, plain.effective_action) == (
        texty.decision, texty.reason_code, texty.rule_ids, texty.effective_action)
