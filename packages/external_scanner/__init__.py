"""Sentinel X External Scanner QA Harness.

Optional, disabled-by-default integration support for external scanners
(Strix, PentAGI). Does NOT execute external scans or install privileged
services unattended. All scanner interaction is opt-in, lab-only, and
requires explicit human approval before any external scanner operation.

External scanner findings must NOT automatically become CONFIRMED - they
require independent Sentinel verification.
"""

from __future__ import annotations

from .authorization import AuthorizationError, check_authorization, is_authorized
from .budgets import BudgetTracker
from .config import ExternalScannerConfig, ScannerConfig, is_local_lab_url
from .dry_run import DryRunPlan, build_dry_run_plan, print_dry_run_plan
from .evidence import ExternalEvidenceStore, ExternalFinding
from .import_results import import_external_results
from .kill_switch import KillSwitch, kill_switch
from .verification import VerificationResult, verify_external_finding

__version__ = "0.1.0"
__disabled_by_default__ = True

# Supported external scanners (pinned version metadata)
SUPPORTED_SCANNERS = {
    "strix": {
        "description": "Strix external scanner",
        "pinned_version": None,
        "license": "unknown",
        "homepage": "unknown",
    },
    "pentagi": {
        "description": "PentAGI external scanner",
        "pinned_version": None,
        "license": "unknown",
        "homepage": "unknown",
    },
}

__all__ = [
    "__version__",
    "__disabled_by_default__",
    "SUPPORTED_SCANNERS",
    "AuthorizationError",
    "check_authorization",
    "is_authorized",
    "BudgetTracker",
    "ExternalScannerConfig",
    "ScannerConfig",
    "is_local_lab_url",
    "DryRunPlan",
    "build_dry_run_plan",
    "print_dry_run_plan",
    "ExternalEvidenceStore",
    "ExternalFinding",
    "import_external_results",
    "KillSwitch",
    "kill_switch",
    "VerificationResult",
    "verify_external_finding",
]
