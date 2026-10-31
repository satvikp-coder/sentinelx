#!/usr/bin/env python3
"""sentinelx init - write sentinelx.site.yaml and sentinelx.agent.yaml from templates."""

from __future__ import annotations

import sys
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent / "templates"

OUTPUTS = {
    "site.yaml": "sentinelx.site.yaml",
    "agent.yaml": "sentinelx.agent.yaml",
}


def init_cmd(args) -> int:
    """Create the two config files (refuses to overwrite unless --force)."""
    existing = [out for out in OUTPUTS.values() if Path(out).exists()]
    if existing and not args.force:
        names = ", ".join(existing)
        print(f"ERROR: {names} already exist. Use --force to overwrite.", file=sys.stderr)
        return 1

    for template_name, out_name in OUTPUTS.items():
        text = (TEMPLATES / template_name).read_text(encoding="utf-8")
        Path(out_name).write_text(text, encoding="utf-8")
        print(f"Created: {out_name}")
    return 0
