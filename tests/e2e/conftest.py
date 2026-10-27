"""Browser e2e fixtures: one lab, one database, every scenario x arm run once."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from sentinelx.agent_runtime import RunConfig, RunResult, ScriptedNaivePlanner, run_session_sync
from sentinelx.common_schemas import Arm, EvidenceEvent, ScenarioSpec
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.store import EvidenceStore
from sentinelx.policy import LoadedPolicy, load_policy

ROOT = Path(__file__).resolve().parents[2]
ALL_SCENARIOS = ["S1", "S1_TOOL", "S2", "S2_HIDDEN", "S3", "B1", "B2", "B3"]
ATTACKS = ["S1", "S1_TOOL", "S2", "S2_HIDDEN", "S3"]
BENIGN = ["B1", "B2", "B3"]


def load_spec(sid: str) -> ScenarioSpec:
    raw = (ROOT / "fixtures" / "scenarios" / f"{sid}.json").read_text(encoding="utf-8")
    return ScenarioSpec.model_validate_json(raw)


@dataclass
class RunData:
    result: RunResult
    events: list[EvidenceEvent]
    ledger: list[dict[str, Any]]
    token: str
    fixture_hash: str


@pytest.fixture(scope="session")
def lab_policy() -> LoadedPolicy:
    return load_policy(ROOT / "configs" / "policy" / "lab.yaml")


@pytest.fixture(scope="session")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator:
    from apps.fixture_lab.server import LabServer

    server = LabServer(tmp_path_factory.mktemp("lab-ledger")).start()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def db(tmp_path_factory: pytest.TempPathFactory) -> Iterator:
    conn = connect(tmp_path_factory.mktemp("runs") / "runs.db")
    migrate(conn)
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def all_runs(lab, db, lab_policy) -> dict[tuple[str, Arm], RunData]:
    runs: dict[tuple[str, Arm], RunData] = {}
    for sid in ALL_SCENARIOS:
        for arm in (Arm.UNPROTECTED, Arm.PROTECTED):
            result = run_session_sync(
                db, lab, load_spec(sid), ScriptedNaivePlanner(sid, lab.port),
                RunConfig(arm=arm), lab_policy,
            )
            runs[(sid, arm)] = RunData(
                result, EvidenceStore(db).list_session(result.session_id), lab.read_ledger(),
                lab.state.data["token"], lab.fixture_hash,
            )
    return runs


def kinds(events: list[EvidenceEvent]) -> list[str]:
    return [e.kind for e in events]


def dump(obj: Any) -> str:
    return json.dumps(obj, default=str)


_ = tempfile  # (kept for ad-hoc debugging)
