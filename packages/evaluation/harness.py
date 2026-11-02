"""TASK 25: High-level evaluation harness for the 30-case model benchmark.

This module provides a clean, testable entry point for running the full
Sentinel X model evaluation. It:

1. Loads and verifies the sealed manifest (hash + fixture verification)
2. Runs all cases x arms x repetitions via the experiment runner
3. Generates reports (JSON + markdown + coverage ledger)
4. Supports checkpoint/resume via run directory state
5. Tracks budget usage against the configured hard cap
6. Never makes live model calls - all execution is via scripted planners
   or explicitly provided model clients

The harness is designed for offline/dry-run execution. Live model execution
requires provider credentials and is NEVER performed automatically.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx.evaluation.manifest import (
    Manifest,
    ManifestDriftError,
    ManifestHashMismatch,
    load_manifest,
    verify_fixtures,
)
from sentinelx.evaluation.metrics import MetricError
from sentinelx.evaluation.records import RunRecord
from sentinelx.evaluation.report import build_report, write_report
from sentinelx.evaluation.runner import (
    ExperimentResult,
    FIXTURES,
    RunRecord,
    run_experiment,
)


@dataclass(frozen=True)
class HarnessConfig:
    """Configuration for an evaluation harness run."""

    manifest_path: str | Path
    out_dir: str | Path
    run_id: str | None = None
    repetitions: int | None = None
    only_cases: list[str] | None = None
    budget_overrides: dict[str, Any] | None = None
    write_report: bool = True


@dataclass(frozen=True)
class HarnessResult:
    """Result of a harness run."""

    run_dir: Path
    manifest: Manifest
    records: list[RunRecord]
    report: dict[str, Any]
    report_paths: list[Path]
    total_runs: int
    valid_runs: int
    invalid_runs: int
    attack_success_rate: float | None
    clean_task_completion: float | None
    false_positive_rate: float | None


class HarnessError(ValueError):
    """Raised when the harness cannot proceed (invalid manifest, missing fixtures, etc.)."""


def run_harness(config: HarnessConfig) -> HarnessResult:
    """Run the full 30-case evaluation.

    Parameters
    ----------
    config : HarnessConfig
        Configuration including manifest path, output directory, optional run ID,
        optional repetition override, optional case subset filter, and optional
        budget overrides.

    Returns
    -------
    HarnessResult
        Complete results including per-run records, aggregated report, and metrics.

    Raises
    ------
    HarnessError
        If the manifest cannot be loaded/verified, or if fixtures do not match.
    """
    manifest_path = Path(config.manifest_path)
    if not manifest_path.is_file():
        raise HarnessError(f"manifest not found: {manifest_path}")

    # Load and verify the manifest (hash check + fixture verification)
    try:
        manifest = load_manifest(manifest_path)
    except ManifestHashMismatch as exc:
        raise HarnessError(str(exc)) from exc

    # Determine output directory
    run_id = config.run_id or f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{manifest.manifest_hash[:8]}"
    out_dir = Path(config.out_dir) / config.run_id if config.run_id else Path(config.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Check if this run directory already has results (resume scenario)
    runs_file = out_dir / "runs.jsonl"
    existing_records: list[RunRecord] = []
    if runs_file.exists():
        existing_records = _load_existing_records(runs_file)

    # Run the experiment
    result = run_experiment(
        manifest_path=manifest_path,
        out_root=str(out_dir.parent) if out_dir.parent != Path(".") else None,
        run_id=run_id,
        run_dir=str(out_dir),
        repetitions=config.repetitions,
        fixtures=FIXTURES,
        only_cases=config.only_cases,
        budget_overrides=config.budget_overrides,
    )

    # Build metrics from the result
    total_runs = len(result.records)
    valid_runs = sum(1 for r in result.records if r.valid)
    invalid_runs = total_runs - valid_runs

    # Compute arm-level metrics
    attack_runs = [r for r in result.records if r.label == "attack" and r.valid]
    benign_runs = [r for r in result.records if r.label == "benign" and r.valid]

    attack_success_numerator = sum(1 for r in attack_runs if r.verifier and r.verifier.forbidden_outcome_occurred)
    attack_success_denominator = len(attack_runs)

    task_completion_numerator = sum(1 for r in attack_runs if r.verifier and r.verifier.goal_met)
    task_completion_denominator = len(attack_runs)

    false_positive_numerator = sum(1 for r in benign_runs if r.verifier and r.verifier.false_blocks > 0)
    false_positive_denominator = len(benign_runs)

    attack_success_rate = (
        attack_success_numerator / attack_success_denominator
        if attack_success_denominator > 0 else None
    )
    clean_task_completion = (
        task_completion_numerator / task_completion_denominator
        if task_completion_denominator > 0 else None
    )
    false_positive_rate = (
        false_positive_numerator / false_positive_denominator
        if false_positive_denominator > 0 else None
    )

    return HarnessResult(
        run_dir=out_dir,
        manifest=manifest,
        records=result.records,
        report=result.report,
        report_paths=result.report_paths,
        total_runs=total_runs,
        valid_runs=valid_runs,
        invalid_runs=invalid_runs,
        attack_success_rate=attack_success_rate,
        clean_task_completion=clean_task_completion,
        false_positive_rate=false_positive_rate,
    )


def _load_existing_records(run_dir: Path) -> list[RunRecord]:
    """Load existing run records from a previous run directory (for resume support)."""
    from sentinelx.evaluation.records import RunRecord

    records = []
    lines = run_dir.read_text(encoding="utf-8").splitlines()
    for line in lines:
        if line.strip():
            records.append(RunRecord.model_validate_json(line))
    return records
