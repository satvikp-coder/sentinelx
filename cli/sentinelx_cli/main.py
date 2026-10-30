#!/usr/bin/env python3
"""SentinelX CLI - Security Digital Twin CLI."""

from __future__ import annotations

import argparse
import sys

from .agent_cmd import agent_cmd
from .doctor import doctor_cmd
from .escalations import escalations_cmd
from .init_cmd import init_cmd
from .shield_cmd import shield_cmd
from .site import site_cmd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelx",
        description="SentinelX - Agent Security Digital Twin CLI",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.0.0")

    subparsers = parser.add_subparsers(dest="cmd", required=True, help="Subcommand")

    # doctor
    p_doctor = subparsers.add_parser("doctor", help="Check environment and configuration")
    p_doctor.set_defaults(func=doctor_cmd)

    # init
    p_init = subparsers.add_parser("init", help="Create sentinelx.site.yaml and sentinelx.agent.yaml from templates")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing files")
    p_init.set_defaults(func=init_cmd)

    # site
    p_site = subparsers.add_parser("site", help="Manage Site Guard targets")
    site_sub = p_site.add_subparsers(dest="site_cmd", required=True)

    p_add = site_sub.add_parser("add", help="Register a target")
    p_add.add_argument("url", help="Target URL")
    p_add.add_argument("--lab", action="store_true", help="Register as lab target (localhost/127.0.0.1/*.lab.test only)")
    p_add.set_defaults(func=lambda args: site_cmd(args, "add"))

    p_verify = site_sub.add_parser("verify", help="Verify ownership of a non-lab target")
    p_verify.add_argument("target_id", help="Target ID")
    p_verify.set_defaults(func=lambda args: site_cmd(args, "verify"))

    p_scan = site_sub.add_parser("scan", help="Run a scan against a target")
    p_scan.add_argument("target_id", help="Target ID")
    p_scan.set_defaults(func=lambda args: site_cmd(args, "scan"))

    p_fix = site_sub.add_parser("fix", help="Run fixes for a target")
    p_fix.add_argument("target_id", help="Target ID")
    p_fix.add_argument("--repo", required=True, help="Path to local repository")
    p_fix.set_defaults(func=lambda args: site_cmd(args, "fix"))

    p_guard = site_sub.add_parser("guard", help="Run shield proxy in front of a target")
    p_guard.add_argument("--upstream", required=True, help="Upstream URL (must be lab target)")
    p_guard.add_argument("--listen", default="127.0.0.1:18090", help="Listen host:port")
    p_guard.add_argument("--mode", choices=["monitor", "recommend", "enforce"], default="monitor")
    p_guard.add_argument("--auto-shield", action="store_true", help="Auto-activate rules")
    p_guard.set_defaults(func=lambda args: site_cmd(args, "guard"))

    p_report = site_sub.add_parser("report", help="Print scan/fix summary from evidence store")
    p_report.add_argument("target_id", help="Target ID")
    p_report.set_defaults(func=lambda args: site_cmd(args, "report"))

    # shield
    p_shield = subparsers.add_parser("shield", help="Manage shield rules")
    shield_sub = p_shield.add_subparsers(dest="shield_cmd", required=True)
    for sub in ["list", "show", "remove", "extend", "approve"]:
        p = shield_sub.add_parser(sub)
        if sub != "list":
            p.add_argument("rule_id", nargs="?")
        p.add_argument("--db", default=":memory:", help="SQLite database path")
        if sub == "extend":
            p.add_argument("--minutes", type=int, required=True)
        if sub == "approve":
            pass  # just rule_id
        p.set_defaults(func=lambda args, s=sub: shield_cmd(args, s))

    # escalations
    p_esc = subparsers.add_parser("escalations", help="Manage escalations")
    esc_sub = p_esc.add_subparsers(dest="esc_cmd", required=True)
    for sub in ["list", "ack", "resolve"]:
        p = esc_sub.add_parser(sub)
        if sub != "list":
            p.add_argument("ticket_id")
            if sub == "resolve":
                p.add_argument("--reviewer", required=True)
                p.add_argument("--decision", choices=["approve", "reject"], required=True)
                p.add_argument("--rationale", required=True)
        p.add_argument("--db", default=":memory:")
        p.set_defaults(func=lambda args, s=sub: escalations_cmd(args, s))

    # agent
    p_agent = subparsers.add_parser("agent", help="Agent Guard SDK commands")
    agent_sub = p_agent.add_subparsers(dest="agent_cmd", required=True)
    p_check = agent_sub.add_parser("check", help="Evaluate one action against a policy")
    p_check.add_argument("--policy", required=True, help="Policy YAML file")
    p_check.add_argument("--action", required=True, help="Action JSON file")
    p_check.set_defaults(func=agent_cmd)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        return args.func(args)
    except SystemExit as e:
        return e.code
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
