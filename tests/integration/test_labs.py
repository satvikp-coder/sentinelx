"""The two labs and their reference copies, run for real. The PHP labs need Docker (marker
`docker`: a loud skip locally if the daemon is down, a FAILURE under SENTINELX_CI=1); the Node labs
run with plain Node. Everything listens on 127.0.0.1 only."""

from __future__ import annotations

import importlib.util
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
