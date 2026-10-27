"""Sentinel X evaluation: hand-authored cases, manifests, paired runs, metrics, reports.

Import `sentinelx.evaluation.runner` explicitly for the browser-driven runner; the rest is pure.
"""

from .cases import Case, case_hash, load_all_cases, load_case, scenario_from_template
from .manifest import (
    Manifest,
    ManifestDriftError,
    ManifestHashMismatch,
    RunHeaderMismatch,
    build_manifest,
    load_manifest,
    seal,
    write_manifest,
)
from .metrics import MetricError, Rate, compute_arm_metrics, rate
from .records import RunRecord
from .report import ReportIncomplete, build_report, write_report

__all__ = [
    "Case", "Manifest", "ManifestDriftError", "ManifestHashMismatch", "MetricError", "Rate",
    "ReportIncomplete", "RunHeaderMismatch", "RunRecord", "build_manifest", "build_report",
    "case_hash", "compute_arm_metrics", "load_all_cases", "load_case", "load_manifest", "rate",
    "scenario_from_template", "seal", "write_manifest", "write_report",
]
