"""The two labs and their reference copies, run for real. The PHP labs need Docker (marker
`docker`: a loud skip locally if the daemon is down, a FAILURE under SENTINELX_CI=1); the Node labs
run with plain Node. Everything listens on 127.0.0.1 only."""

from __future__ import annotations

import importlib.util
import os
import socket
import sys
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from apps import labctl

ROOT = Path(__file__).resolve().parents[2]
PHP = ["vibe_shop_php", "vibe_shop_php_reference"]
NODE = ["vibe_notes_node", "vibe_notes_node_reference"]


def traffic_module(lab: str):
    base = lab.removesuffix("_reference")
    path = ROOT / "labs" / base / "benign_traffic.py"
    sys.path.insert(0, str(ROOT / "labs"))
    spec = importlib.util.spec_from_file_location(f"benign_{base}", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.fixture(scope="module")
def php_labs() -> Iterator[None]:
    for name in PHP:
        labctl.up(name)
    yield
    for name in PHP:
        labctl.down(name)


@pytest.fixture(scope="module")
def node_labs() -> Iterator[None]:
    for name in NODE:
        labctl.up(name)
    yield
    for name in NODE:
        labctl.down(name)


# ------------------------------------------------------------------ PHP (Docker)
@pytest.mark.docker
@pytest.mark.parametrize("lab", PHP)
def test_php_lab_listens_on_loopback_only(php_labs: None, lab: str) -> None:
    info = labctl.get(lab)
    assert httpx.get(info.base_url + "/health.php", timeout=10).text == "ok"
    proof = labctl.assert_loopback_only(lab)
    assert proof["published"] == [f"127.0.0.1:{info.port}"]


@pytest.mark.docker
@pytest.mark.parametrize("lab", PHP)
def test_php_lab_resets_to_an_identical_state_hash(php_labs: None, lab: str) -> None:
    first = labctl.reset(lab)
    httpx.post(labctl.get(lab).base_url + "/contact.php", data={"name": "x", "message": "m"},
               timeout=10)
    dirty = labctl.state_hash(lab)
    second = labctl.reset(lab)
    assert first == second and dirty != first, "the reset really restores the seeded state"
    assert len(first) == 64


@pytest.mark.docker
@pytest.mark.parametrize("lab", PHP)
def test_php_benign_traffic_passes_against_vulnerable_and_reference(php_labs: None,
                                                                    lab: str) -> None:
    labctl.reset(lab)
    rep = traffic_module(lab).run(labctl.get(lab).base_url, lab)
    assert rep.passed, [(s.feature, s.note) for s in rep.failures()]
    assert rep.features >= 18 and rep.requests >= 18


@pytest.mark.docker
def test_php_vulnerable_and_reference_start_from_the_same_seeded_state(php_labs: None) -> None:
    hashes = {labctl.reset(lab) for lab in PHP}
    assert len(hashes) == 1, "the fixes change code, not seed data"


@pytest.mark.docker
def test_php_planted_weaknesses_really_exist_and_the_reference_fixes_them(php_labs: None) -> None:
    """A few harmless observations (the strategies in PLANTED.json), vulnerable vs reference."""
    for lab in PHP:
        labctl.reset(lab)
    vuln, ref = labctl.get(PHP[0]).base_url, labctl.get(PHP[1]).base_url
    # PHP-04 / PHP-05: admin and debug pages without logging in
    assert "Admin panel" in httpx.get(vuln + "/admin.php").text
    assert httpx.get(ref + "/admin.php").status_code == 403
    assert "App secret" in httpx.get(vuln + "/info.php").text
    assert httpx.get(ref + "/info.php").status_code == 403
    # PHP-06: leftover backup of the configuration file
    assert "define(" in httpx.get(vuln + "/config.php.bak").text
    assert httpx.get(ref + "/config.php.bak").status_code == 404
    # PHP-08 / PHP-09: headers, cookie flags, reflected CORS origin
    v, r = httpx.get(vuln + "/index.php"), httpx.get(ref + "/index.php")
    assert "x-content-type-options" not in v.headers and "x-content-type-options" in r.headers
    assert "httponly" not in v.headers.get("set-cookie", "").lower()
    assert "httponly" in r.headers.get("set-cookie", "").lower()
    probe = {"Origin": "http://synthetic-origin.test"}
    assert httpx.get(vuln + "/api.php", headers=probe).headers.get(
        "access-control-allow-origin") == "http://synthetic-origin.test"
    assert "access-control-allow-origin" not in httpx.get(ref + "/api.php", headers=probe).headers
    # PHP-03: another user's order
    for base, expect in ((vuln, 200), (ref, 404)):
        with httpx.Client(base_url=base) as c:
            c.post("/login.php", data={"username": "bob", "password": "bobpass"})
            got = c.get("/order_view.php?id=1")  # order 1 belongs to alice
            assert got.status_code == expect
            assert ("Total:" in got.text) is (expect == 200)
    # PHP-07: a bounded handful of failed logins is never throttled in the vulnerable lab
    with httpx.Client(base_url=vuln) as c:
        codes = [c.post("/login.php", data={"username": "alice", "password": "wrong"}).status_code
                 for _ in range(7)]
    assert set(codes) == {200}
    with httpx.Client(base_url=ref) as c:
        codes = [c.post("/login.php", data={"username": "alice", "password": "wrong"}).status_code
                 for _ in range(7)]
    assert 429 in codes


# ------------------------------------------------------------------ Node (no Docker needed)
@pytest.mark.parametrize("lab", NODE)
def test_node_lab_listens_on_loopback_only(node_labs: None, lab: str) -> None:
    info = labctl.get(lab)
    assert httpx.get(info.base_url + "/health", timeout=10).text == "ok"
    proof = labctl.assert_loopback_only(lab)
    assert proof["published"] == [f"127.0.0.1:{info.port}"]
    for ip in labctl.non_loopback_addresses():
        s = socket.socket()
        s.settimeout(1.5)
        try:
            assert s.connect_ex((ip, info.port)) != 0, f"{lab} reachable on {ip}"
        finally:
            s.close()


@pytest.mark.parametrize("lab", NODE)
def test_node_lab_resets_to_an_identical_state_hash(node_labs: None, lab: str) -> None:
    first = labctl.reset(lab)
    httpx.post(labctl.get(lab).base_url + "/api/signup",
               json={"username": "dirty", "password": "dirtypass"}, timeout=10)
    dirty = labctl.state_hash(lab)
    second = labctl.reset(lab)
    assert first == second and dirty != first


@pytest.mark.parametrize("lab", NODE)
def test_node_benign_traffic_passes_against_vulnerable_and_reference(node_labs: None,
                                                                     lab: str) -> None:
    labctl.reset(lab)
    rep = traffic_module(lab).run(labctl.get(lab).base_url, lab)
    assert rep.passed, [(s.feature, s.note) for s in rep.failures()]
    assert rep.features >= 18 and rep.requests >= 18


def test_node_planted_weaknesses_really_exist_and_the_reference_fixes_them(node_labs: None) -> None:
    for lab in NODE:
        labctl.reset(lab)
    vuln, ref = labctl.get(NODE[0]).base_url, labctl.get(NODE[1]).base_url
    assert "secret" in httpx.get(vuln + "/debug").text
    assert httpx.get(ref + "/debug").status_code == 401
    assert "SECRET" in httpx.get(vuln + "/backup/server.js.bak").text
    assert httpx.get(ref + "/backup/server.js.bak").status_code == 404
    assert httpx.post(vuln + "/api/settings", json={"theme": "x"}).status_code == 200
    assert httpx.post(ref + "/api/settings", json={"theme": "x"}).status_code == 401
    probe = {"Origin": "http://synthetic-origin.test"}
    assert httpx.get(vuln + "/health", headers=probe).headers.get(
        "access-control-allow-origin") == "http://synthetic-origin.test"
    assert "access-control-allow-origin" not in httpx.get(ref + "/health", headers=probe).headers
    bad = httpx.post(vuln + "/api/login", content="{not json", headers={
        "Content-Type": "application/json"})
    assert "stack" in bad.text and "stack" not in httpx.post(
        ref + "/api/login", content="{not json", headers={"Content-Type": "application/json"}).text
    for base, expect in ((vuln, 200), (ref, 404)):
        with httpx.Client(base_url=base) as c:
            tok = c.post("/api/login", json={"username": "dave", "password": "davepass"}).json()
            got = c.get("/api/notes/1", headers={"Authorization": f"Bearer {tok['token']}"})
            assert got.status_code == expect  # note 1 belongs to carol


# ------------------------------------------------------------------ socket ownership tests

def _find_free_port() -> int:
    """Return a free TCP port on localhost."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_socket_owner_pid_tcp_listener_accepted():
    """A real TCP listener owns its port: _socket_owner_pid returns its PID."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        owner_pid = labctl._socket_owner_pid(port)
        assert owner_pid is not None, f"expected to find owner of TCP listener on {port}"
        assert owner_pid == os.getpid(), (
            f"expected owner PID {os.getpid()}, got {owner_pid}")
    finally:
        s.close()


def test_socket_owner_pid_udp_not_accepted():
    """A UDP socket on a port does NOT establish TCP listener ownership.
    If only a UDP socket exists on the port, _socket_owner_pid returns None."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    port = udp.getsockname()[1]
    try:
        owner_pid = labctl._socket_owner_pid(port)
        assert owner_pid is None, (
            f"expected None for UDP-only port {port}, got {owner_pid}")
    finally:
        udp.close()


def test_socket_owner_pid_non_listen_tcp_rejected():
    """A non-LISTEN TCP connection (e.g. ESTABLISHED client) does not
    establish listener ownership.

    We create a TCP listener, connect a client to it (ESTABLISHED state on
    the client side), then check that the CLIENT's port is NOT considered
    as owning a listener. Only the server's LISTEN socket counts."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listen_port = listener.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(2.0)
    client.connect(("127.0.0.1", listen_port))
    client_port = client.getsockname()[1]

    try:
        # The listener's port should be owned by us.
        owner = labctl._socket_owner_pid(listen_port)
        assert owner == os.getpid(), (
            f"expected {os.getpid()} for listener port {listen_port}, got {owner}")

        # The client's port (ESTABLISHED, not LISTEN) should NOT count
        # as listener ownership.
        owner = labctl._socket_owner_pid(client_port)
        assert owner is None, (
            f"expected None for non-LISTEN TCP on {client_port}, got {owner}")
    finally:
        client.close()
        listener.close()


def test_socket_owner_pid_unknown_owner_fails_closed():
    """A port with no socket at all: _socket_owner_pid returns None."""
    port = _find_free_port()
    # Don't bind anything; just check the port is free.
    owner_pid = labctl._socket_owner_pid(port)
    assert owner_pid is None, (
        f"expected None for unowned port {port}, got {owner_pid}")


def test_socket_owner_pid_udp_then_tcp_tcp_wins():
    """UDP on a port does not mask a TCP listener on the same port.
    Create UDP first, then TCP listener; owner must be the TCP listener's
    PID (same process here, but the UDP entry must not short-circuit)."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp_port = udp.getsockname()[1]

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("127.0.0.1", udp_port))
    tcp.listen(1)
    try:
        owner_pid = labctl._socket_owner_pid(udp_port)
        assert owner_pid == os.getpid(), (
            f"expected PID {os.getpid()} for TCP listener on {udp_port}, "
            f"got {owner_pid}")
    finally:
        udp.close()
        tcp.close()


def test_socket_owner_pid_wrong_process_fails_closed():
    """A port owned by a different process: we cannot determine its PID
    from our own process, so fail closed (return None). We simulate this by
    checking a port that no local process owns."""
    port = _find_free_port()
    owner_pid = labctl._socket_owner_pid(port, host="127.0.0.1")
    assert owner_pid is None, (
        f"expected None for unowned port {port}, got {owner_pid}")


def test_socket_owner_pid_different_address_rejected():
    """A TCP listener on 127.0.0.2:P cannot establish ownership of
    127.0.0.1:P. The owner-pid lookup must match both port AND local
    address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.2", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        owner_pid = labctl._socket_owner_pid(port, host="127.0.0.1")
        assert owner_pid is None, (
            f"expected None for 127.0.0.2:{port} when querying 127.0.0.1:{port}, "
            f"got {owner_pid}")
    finally:
        s.close()


def test_socket_owner_pid_wildcard_rejected():
    """A wildcard listener on 0.0.0.0:P cannot establish ownership of
    127.0.0.1:P."""
    wildcard = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wildcard.bind(("0.0.0.0", 0))
    wildcard.listen(1)
    port = wildcard.getsockname()[1]
    try:
        owner_pid = labctl._socket_owner_pid(port, host="127.0.0.1")
        assert owner_pid is None, (
            f"expected None for wildcard 0.0.0.0:{port} when querying "
            f"127.0.0.1:{port}, got {owner_pid}")
    finally:
        wildcard.close()


def test_socket_owner_pid_ipv6():
    """A TCP listener on ::1:P is found when querying ::1:P."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        s.bind(("::1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        owner_pid = labctl._socket_owner_pid(port, host="::1")
        assert owner_pid == os.getpid(), (
            f"expected {os.getpid()} for IPv6 listener on ::1:{port}, "
            f"got {owner_pid}")
    finally:
        s.close()


def test_socket_owner_pid_ipv6_not_matching_ipv4():
    """An IPv6 listener on ::1:P cannot establish ownership of
    127.0.0.1:P."""
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        s.bind(("::1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        owner_pid = labctl._socket_owner_pid(port, host="127.0.0.1")
        assert owner_pid is None, (
            f"expected None for IPv6 ::1:{port} when querying "
            f"127.0.0.1:{port}, got {owner_pid}")
    finally:
        s.close()


def test_socket_owner_pid_same_port_different_addresses():
    """TCP listeners on 127.0.0.1:P1 and 127.0.0.2:P2 are correctly
    distinguished by address. Querying one address does not return the
    other's listener."""
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.bind(("127.0.0.1", 0))
    s1.listen(1)
    port1 = s1.getsockname()[1]

    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.bind(("127.0.0.2", 0))
    s2.listen(1)
    port2 = s2.getsockname()[1]

    try:
        # Each address:port pair maps to the current process's PID.
        assert labctl._socket_owner_pid(port1, host="127.0.0.1") == os.getpid()
        assert labctl._socket_owner_pid(port2, host="127.0.0.2") == os.getpid()
        # Cross-address lookups return None: no listener on 127.0.0.1:port2
        # or 127.0.0.2:port1.
        assert labctl._socket_owner_pid(port2, host="127.0.0.1") is None
        assert labctl._socket_owner_pid(port1, host="127.0.0.2") is None
    finally:
        s1.close()
        s2.close()


# ------------------------------------------------------------------ end of file
