#!/usr/bin/env python3
"""sentinelx shield - thin wrappers over scripts/shield_rules.py (real arguments)."""

from __future__ import annotations

import sys

from .repo import run_script


def shield_cmd(args, subcmd: str) -> int:
    """Translate CLI args to scripts/shield_rules.py argv (--db first) and run it."""
    db_argv = ["--db", args.db] if getattr(args, "db", None) else []
    if subcmd == "list":
        argv = [*db_argv, "list"]
    elif subcmd == "show":
        argv = [*db_argv, "show", args.rule_id]
    elif subcmd == "remove":
        argv = [*db_argv, "remove", args.rule_id, "--reason", args.reason]
    elif subcmd == "extend":
        argv = [*db_argv, "extend", args.rule_id, "--minutes", str(args.minutes)]
    elif subcmd == "approve":
        argv = [*db_argv, "approve", args.rule_id, "--reviewer", args.reviewer,
                "--reason", args.reason]
        if getattr(args, "benign_file", None):
            argv += ["--benign-file", args.benign_file]
    else:
        print(f"Unknown shield command: {subcmd}", file=sys.stderr)
        return 1
    return run_script("shield_rules.py", argv)
