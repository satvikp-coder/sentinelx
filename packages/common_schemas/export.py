"""JSON Schema export. Files live in packages/common_schemas/schemas/ and are test-checked."""

from __future__ import annotations

import json
from pathlib import Path

from .models import ALL_MODELS

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"


def render_schema_files() -> dict[str, str]:
    """Return {filename: text} for every top-level contract (deterministic)."""
    out: dict[str, str] = {}
    for model in ALL_MODELS:
        schema = model.model_json_schema()
        text = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False)
        out[f"{model.__name__}.schema.json"] = text + "\n"
    return out


def write_schema_files() -> list[Path]:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    for stale in SCHEMA_DIR.glob("*.schema.json"):
        stale.unlink()
    written = []
    for name, text in render_schema_files().items():
        path = SCHEMA_DIR / name
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path)
    return written
