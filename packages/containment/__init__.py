"""IncidentTwin containment: Evidence-Verified Containment Search (EVCS).

A "digital twin" here is a bounded, resettable replica of OUR lab fixtures - not of any real site -
and a "branch" is a RE-EXECUTION of the SIMULATED scripted planner from a controlled checkpoint
(scenario, seed, fixture hash, policy), not a rollback of anything real."""

from .branch import BranchResult, Checkpoint, ParentRun, run_branch, run_parent
from .evcs import EvcsCase, run_evcs_case
from .mitigations import CATALOG, MitigationSpec
from .selection import Recommendation, Weights, load_weights, select

__all__ = [
    "CATALOG", "BranchResult", "Checkpoint", "EvcsCase", "MitigationSpec", "ParentRun",
    "Recommendation", "Weights", "load_weights", "run_branch", "run_evcs_case", "run_parent",
    "select",
]
