"""Demo: run all six scenarios x both arms in the lab and print a comparison table.

The agent is a SCRIPTED, deliberately gullible planner: SIMULATED, not an LLM.
Ground truth (forbidden side effects) comes from the lab ledger via the independent verifier.

Usage: python scripts/demo_agent_lab.py [--keep-db PATH]
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # `apps` is imported from the repo root, not installed

from apps.fixture_lab.server import LabServer  # noqa: E402
from sentinelx.agent_runtime import RunConfig, ScriptedNaivePlanner, run_session_sync  # noqa: E402
from sentinelx.common_schemas import Arm, ScenarioSpec  # noqa: E402
from sentinelx.evidence.db import connect, migrate  # noqa: E402
from sentinelx.evidence.store import EvidenceStore  # noqa: E402
from sentinelx.policy import load_policy  # noqa: E402

SCENARIOS = ["S1", "S2", "S3", "B1", "B2", "B3"]
COLUMNS = ("scenario", "arm", "attempted", "executed", "blocked", "goal", "false_blk",
           "rule ids that fired", "fixture", "session")


def load_spec(sid: str) -> ScenarioSpec:
    raw = (ROOT / "fixtures" / "scenarios" / f"{sid}.json").read_text(encoding="utf-8")
    return ScenarioSpec.model_validate_json(raw)


def fired_rules(events) -> str:
    rules: list[str] = []
    for e in events:
        if e.kind == "ACTION_DECIDED" and e.payload["decision"]["decision"] != "ALLOW":
            rules.append(e.payload["decision"]["rule_ids"][-1])
    return ",".join(dict.fromkeys(rules)) or "-"


def main() -> None:
    policy = load_policy(ROOT / "configs" / "policy" / "lab.yaml")
    with tempfile.TemporaryDirectory() as tmp:
        lab = LabServer(Path(tmp) / "ledger").start()
        conn = connect(Path(tmp) / "demo.db")
        migrate(conn)
        store = EvidenceStore(conn)
        print(f"Agent Guard lab demo | planner: SIMULATED scripted naive agent (not an LLM) | "
              f"policy {policy.policy_version} | lab 127.0.0.1:{lab.port}\n")
        rows: list[tuple[str, ...]] = []
        s1_pair: dict[Arm, str] = {}
        try:
            for sid in SCENARIOS:
                for arm in (Arm.UNPROTECTED, Arm.PROTECTED):
                    result = run_session_sync(conn, lab, load_spec(sid),
                                              ScriptedNaivePlanner(sid, lab.port),
                                              RunConfig(arm=arm), policy)
                    v = result.verifier
                    assert v is not None, "verifier did not run"
                    yn = lambda b: "yes" if b else "no"  # noqa: E731
                    rows.append((
                        sid, "A unprotected" if arm is Arm.UNPROTECTED else "B protected",
                        yn(v.attempted_forbidden), yn(v.executed_forbidden),
                        yn(v.blocked_forbidden), yn(v.goal_met), str(v.false_blocks),
                        fired_rules(store.list_session(result.session_id)),
                        result.fixture_hash[:10], result.session_id[-8:],
                    ))
                    if sid == "S1":
                        s1_pair[arm] = result.session_id
        finally:
            lab.stop()
        widths = [max(len(COLUMNS[i]), *(len(r[i]) for r in rows)) for i in range(len(COLUMNS))]
        line = "  ".join(c.ljust(w) for c, w in zip(COLUMNS, widths, strict=True))
        print(line)
        print("-" * len(line))
        for r in rows:
            print("  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)))
        print("\nforbidden side effects are judged from the lab ledger, not the agent.")
        print("\nFull evidence for the S1 pair:")
        for arm, sid in s1_pair.items():
            events = store.list_session(sid)
            check = store.verify_chain(sid)
            print(f"\n  {arm.value} session {sid}  verify_chain: {check.status.value} "
                  f"({check.events_checked} events)")
            print("  " + " > ".join(e.kind for e in events))
        conn.close()


if __name__ == "__main__":
    main()
