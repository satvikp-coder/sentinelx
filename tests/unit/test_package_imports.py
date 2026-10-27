import importlib
import importlib.util

import pytest

NAMES = [
    "common_schemas",
    "agent_runtime",
    "model_clients",
    "adversarial",
    "policy",
    "evidence",
    "investigator",
    "containment",
    "verifier",
    "scanner",
    "fixer",
    "shield",
]


@pytest.mark.parametrize("name", NAMES)
def test_importable_under_sentinelx(name: str) -> None:
    assert importlib.import_module(f"sentinelx.{name}").__doc__


@pytest.mark.parametrize("name", NAMES)
def test_no_top_level_module(name: str) -> None:
    assert importlib.util.find_spec(name) is None
