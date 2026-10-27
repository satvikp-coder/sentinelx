"""Shared pytest config: browser-test gating that can never skip silently in CI."""

from __future__ import annotations

import os
from functools import cache
from pathlib import Path

import pytest

BROWSER_COUNTS = {"passed": 0, "failed": 0, "skipped": 0}


@cache
def browser_ready() -> tuple[bool, str]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, "playwright is not installed (pip install -e '.[dev,browser]')"
    try:
        with sync_playwright() as p:
            if Path(p.chromium.executable_path).exists():
                return True, ""
    except Exception as exc:  # pragma: no cover - environment specific
        return False, f"Playwright could not start: {exc}"
    return False, "Chromium is not installed: run `python scripts/setup_browsers.py`"


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("browser") is None:
        return
    ok, message = browser_ready()
    if ok:
        return
    if os.environ.get("SENTINELX_CI") == "1":
        pytest.fail(f"BROWSER TESTS CANNOT RUN IN CI MODE: {message}", pytrace=False)
    pytest.skip(f"browser test skipped: {message}")


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if "browser" not in report.keywords:
        return
    if report.when == "call":
        BROWSER_COUNTS["passed" if report.passed else "failed"] += 1
    elif report.when == "setup" and report.skipped:
        BROWSER_COUNTS["skipped"] += 1


def pytest_terminal_summary(terminalreporter) -> None:
    c = BROWSER_COUNTS
    terminalreporter.write_line(
        f"browser tests actually ran: {c['passed'] + c['failed']} "
        f"({c['passed']} passed, {c['failed']} failed, {c['skipped']} skipped)"
    )
