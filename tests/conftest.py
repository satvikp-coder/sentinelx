"""Shared pytest config: browser-test gating that can never skip silently in CI."""

from __future__ import annotations

import os
from functools import cache
from pathlib import Path

import pytest

BROWSER_COUNTS = {"passed": 0, "failed": 0, "skipped": 0}
LIVE_SKIPPED: list[str] = []
DOCKER_COUNTS = {"passed": 0, "failed": 0, "skipped": 0}
DOCKER_SKIPPED: list[str] = []


def pytest_configure(config: pytest.Config) -> None:
    config.live_notes = []  # type: ignore[attr-defined]  # filled by live tests, printed below


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Every browser/docker/live test is also "slow" (no per-test edits needed): the fast dev
    loop is `pytest -m "not slow"`; CI runs everything, unmarked, as before."""
    for item in items:
        if any(item.get_closest_marker(m) for m in ("browser", "docker", "live")):
            item.add_marker(pytest.mark.slow)


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


@cache
def docker_ready() -> tuple[bool, str]:
    from apps.labctl import docker_running

    if docker_running():
        return True, ""
    return False, "the Docker daemon is not running (start Docker Desktop)"


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
    if item.get_closest_marker("docker") is not None:
        ok, why = docker_ready()
        if not ok:
            if os.environ.get("SENTINELX_CI") == "1":
                pytest.fail(f"DOCKER TESTS CANNOT RUN IN CI MODE: {why}", pytrace=False)
            DOCKER_SKIPPED.append(item.nodeid)
            pytest.skip(f"DOCKER TEST SKIPPED: {why}")
    if item.get_closest_marker("browser") is None:
        return
    ok, message = browser_ready()
    if ok:
        return
    if os.environ.get("SENTINELX_CI") == "1":
        pytest.fail(f"BROWSER TESTS CANNOT RUN IN CI MODE: {message}", pytrace=False)
    pytest.skip(f"browser test skipped: {message}")


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if "docker" in report.keywords:
        if report.when == "call":
            DOCKER_COUNTS["passed" if report.passed else "failed"] += 1
        elif report.when == "setup" and report.skipped:
            DOCKER_COUNTS["skipped"] += 1
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
    if DOCKER_SKIPPED:
        terminalreporter.write_line("")
        terminalreporter.write_line("!" * 78, red=True, bold=True)
        terminalreporter.write_line(
            f"!! {len(DOCKER_SKIPPED)} DOCKER-DEPENDENT TEST(S) WERE SKIPPED: the Docker daemon is "
            "not running.", red=True, bold=True)
        terminalreporter.write_line("!" * 78, red=True, bold=True)
    d = DOCKER_COUNTS
    terminalreporter.write_line(
        f"docker-dependent tests actually ran: {d['passed'] + d['failed']} "
        f"({d['passed']} passed, {d['failed']} failed, {d['skipped']} skipped)")
    terminalreporter.write_line(
        f"browser tests actually ran: {c['passed'] + c['failed']} "
        f"({c['passed']} passed, {c['failed']} failed, {c['skipped']} skipped)"
    )
