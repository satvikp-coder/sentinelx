"""Sentinel X evaluation: hand-authored cases, manifests, paired runs, metrics, reports.

Import `sentinelx.evaluation.runner` explicitly for the browser-driven runner; the rest is pure.
"""

from .cases import Case, case_hash, load_all_cases, load_case, scenario_from_template

__all__ = ["Case", "case_hash", "load_all_cases", "load_case", "scenario_from_template"]
