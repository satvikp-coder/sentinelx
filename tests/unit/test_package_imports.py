import importlib

import pytest

PACKAGES = [
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


@pytest.mark.parametrize("name", PACKAGES)
def test_package_imports(name: str) -> None:
    assert importlib.import_module(name).__doc__
