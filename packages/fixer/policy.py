"""Load configs/fix/policy.yaml (strict)."""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import FixPolicy

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = REPO_ROOT / "configs" / "fix" / "policy.yaml"


def load_fix_policy(path: Path = DEFAULT_POLICY_PATH) -> FixPolicy:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return FixPolicy.model_validate(raw)
