"""Shared pytest config: browser-test gating that can never skip silently in CI."""

from __future__ import annotations

import os
from functools import cache
from pathlib import Path

import pytest

BROWSER_COUNTS = {"passed": 0, "failed": 0, "skipped": 0}
LIVE_SKIPPED: list[str] = []


def pytest_configure(config: pytest.Config) -> None:
    config.live_notes = []  # type: ignore[attr-defined]  # filled by live tests, printed below


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


def live_model_configured() -> tuple[bool, str]:
    from sentinelx.model_clients import load_config

    cfg = load_config()
    if cfg.provider in {"recorded", "meta_api"}:
        return False, f"MODEL_PROVIDER={cfg.provider} is not a live provider"
    if cfg.requires_key and not cfg.api_key.get_secret_value():
        return False, "MODEL_API_KEY is not set in .env"
    if not cfg.base_url or not cfg.model:
        return False, "MODEL_BASE_URL / MODEL_NAME are not set in .env"
    return True, ""


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("live") is not None:
        ok, why = live_model_configured()
        if not ok:
            LIVE_SKIPPED.append(item.nodeid)
            pytest.skip(f"LIVE MODEL TEST SKIPPED: {why}")
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


def pytest_terminal_summary(terminalreporter, config) -> None:
    c = BROWSER_COUNTS
    for line in getattr(config, "live_notes", []):
        terminalreporter.write_line(f"LIVE MODEL TEST: {line}")
    if LIVE_SKIPPED:
        terminalreporter.write_line("")
        terminalreporter.write_line("!" * 78, red=True, bold=True)
        terminalreporter.write_line(
            f"!! {len(LIVE_SKIPPED)} LIVE MODEL TEST(S) WERE SKIPPED: no usable model key is "
            "configured.", red=True, bold=True)
        terminalreporter.write_line("!! Nothing in this run exercised a real model.", red=True,
                                    bold=True)
        terminalreporter.write_line("!" * 78, red=True, bold=True)
    terminalreporter.write_line(
        f"browser tests actually ran: {c['passed'] + c['failed']} "
        f"({c['passed']} passed, {c['failed']} failed, {c['skipped']} skipped)"
    )
