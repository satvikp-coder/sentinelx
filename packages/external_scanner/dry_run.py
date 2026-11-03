"""Dry-run capability for external scanner QA harness.

In dry-run mode, no external scanner is actually invoked. Instead, the
harness prints the plan and validates configuration without making any
external calls.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DryRunPlan:
    """A dry-run plan describing what would happen without executing."""

    scanner_name: str
    operation: str
    target_url: str | None
    request_budget: int
    time_budget_seconds: int
    would_execute: bool
    reason: str


def build_dry_run_plan(
    scanner_name: str,
    operation: str,
    target_url: str | None,
    request_budget: int,
    time_budget_seconds: int,
    authorized: bool,
) -> DryRunPlan:
    """Build a dry-run plan without executing anything."""
    if not authorized:
        return DryRunPlan(
            scanner_name=scanner_name,
            operation=operation,
            target_url=target_url,
            request_budget=request_budget,
            time_budget_seconds=time_budget_seconds,
            would_execute=False,
            reason="not authorized",
        )
    if target_url is None:
        return DryRunPlan(
            scanner_name=scanner_name,
            operation=operation,
            target_url=None,
            request_budget=request_budget,
            time_budget_seconds=time_budget_seconds,
            would_execute=False,
            reason="no target URL configured",
        )
    return DryRunPlan(
        scanner_name=scanner_name,
        operation=operation,
        target_url=target_url,
        request_budget=request_budget,
        time_budget_seconds=time_budget_seconds,
        would_execute=True,
        reason="dry-run: would execute against lab target",
    )


def print_dry_run_plan(plan: DryRunPlan) -> None:
    """Print a human-readable dry-run plan."""
    print("External Scanner Dry-Run Plan")
    print("  Scanner: " + plan.scanner_name)
    print("  Operation: " + plan.operation)
    print("  Target: " + (plan.target_url or "none"))
    print("  Request Budget: " + str(plan.request_budget))
    print("  Time Budget: " + str(plan.time_budget_seconds) + "s")
    print("  Would Execute: " + str(plan.would_execute))
    print("  Reason: " + plan.reason)
