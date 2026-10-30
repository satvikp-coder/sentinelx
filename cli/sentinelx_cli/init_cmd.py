#!/usr/bin/env python3
"""sentinelx init - Create sentinelx.site.yaml and sentinelx.agent.yaml from templates."""

from __future__ import annotations

import sys
from pathlib import Path

from .templates import AGENT_TEMPLATE, SITE_TEMPLATE


def init_cmd(args) -> int:
    """Create sentinelx.site.yaml and sentinelx.agent.yaml from templates."""
    site_path = Path("sentinelx.site.yaml")
    agent_path = Path("sentinelx.agent.yaml")

    # Check if files exist and --force not given
    if (site_path.exists() or agent_path.exists()) and not args.force:
        existing = []
        if site_path.exists():
            existing.append("sentinelx.site.yaml")
        if agent_path.exists():
            existing.append("sentinelx.agent.yaml")
        print(f"ERROR: {', '.join(existing)} already exist. Use --force to overwrite.", file=sys.stderr)
        return 1

    # Write sentinelx.site.yaml
    site_path.write_text(SITE_TEMPLATE, encoding="utf-8")
    print(f"Created: {site_path}")

    # Write sentinelx.agent.yaml
    agent_path.write_text(AGENT_TEMPLATE, encoding="utf-8")
    print(f"Created: {agent_path}")

    return 0
