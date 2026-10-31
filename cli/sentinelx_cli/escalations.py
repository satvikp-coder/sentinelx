#!/usr/bin/env python3
"""sentinelx escalations - thin wrappers over scripts/escalations.py (real arguments)."""

from __future__ import annotations

import sys

from .repo import run_script


def escalations_cmd(args, subcmd: str) -> int:
    """Translate CLI args to scripts/escalations.py argv and run it.

    When --db is not given, the script's own default DB is used.
    """
    db_argv = ["--db", args.db] if getattr(args, "db", None) else []
    if subcmd == "list":
        argv = ["list", *db_argv]
    elif subcmd == "ack":
        argv = ["ack", args.ticket_id, *db_argv]
    elif subcmd == "resolve":
        argv = ["resolve", args.ticket_id, "--reviewer", args.reviewer,
                "--decision", args.decision, "--rationale", args.rationale, *db_argv]
    else:
        print(f"Unknown escalations command: {subcmd}", file=sys.stderr)
        return 1
    return run_script("escalations.py", argv)
