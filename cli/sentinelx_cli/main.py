#!/usr/bin/env python3
"""SentinelX CLI - Security Digital Twin CLI."""

from __future__ import annotations

import argparse
import sys

from .agent_cmd import agent_cmd
from .doctor import doctor_cmd
from .escalations import escalations_cmd
from .init_cmd import init_cmd
from .report_cmd import report_cmd
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
    p_init = subparsers.add_parser("init", help="Write sentinelx.site.yaml / sentinelx.agent.yaml")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing files")
    p_init.set_defaults(func=init_cmd)

    # site
    p_site = subparsers.add_parser("site", help="Manage Site Guard targets")
    site_sub = p_site.add_subparsers(dest="site_cmd", required=True)

    p_add = site_sub.add_parser("add", help="Register a target")
    p_add.add_argument("url", help="Target URL")
    p_add.add_argument("--lab", action="store_true",
                       help="Lab target only (localhost / 127.0.0.1 / *.lab.test)")
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
    p_fix.add_argument("--patch-format", choices=["diff", "edits"], default=None,
                       help="Patch format for this run (default: configured patch_format, "
                            "currently 'diff')")
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

    # shield (thin wrapper over scripts/shield_rules.py; args mirror that script)
    p_shield = subparsers.add_parser("shield", help="Manage shield rules")
    shield_sub = p_shield.add_subparsers(dest="shield_cmd", required=True)

    p = shield_sub.add_parser("list", help="List all rules")
    p.add_argument("--db", default=None, help="SQLite DB path (default: in-memory)")
    p.set_defaults(func=lambda args, s="list": shield_cmd(args, s))

    p = shield_sub.add_parser("show", help="Show rule details")
    p.add_argument("rule_id")
    p.add_argument("--db", default=None)
    p.set_defaults(func=lambda args, s="show": shield_cmd(args, s))

    p = shield_sub.add_parser("remove", help="Remove a rule")
    p.add_argument("rule_id")
    p.add_argument("--reason", required=True, help="Removal reason")
    p.add_argument("--db", default=None)
    p.set_defaults(func=lambda args, s="remove": shield_cmd(args, s))

    p = shield_sub.add_parser("extend", help="Extend rule TTL")
    p.add_argument("rule_id")
    p.add_argument("--minutes", type=int, required=True)
    p.add_argument("--db", default=None)
    p.set_defaults(func=lambda args, s="extend": shield_cmd(args, s))

    p = shield_sub.add_parser("approve", help="Approve a PROPOSED rule (benign gate is re-run)")
    p.add_argument("rule_id")
    p.add_argument("--reviewer", required=True, help="Approving human")
    p.add_argument("--reason", required=True, help="Approval rationale")
    p.add_argument("--benign-file", default=None, help="benign_traffic.py read as data")
    p.add_argument("--db", default=None)
    p.set_defaults(func=lambda args, s="approve": shield_cmd(args, s))

    # escalations (thin wrapper over scripts/escalations.py)
    p_esc = subparsers.add_parser("escalations", help="Manage escalation tickets")
    esc_sub = p_esc.add_subparsers(dest="esc_cmd", required=True)

    p = esc_sub.add_parser("list", help="List escalation tickets")
    p.add_argument("--db", default=None, help="SQLite DB path (default: fix_runs DB)")
    p.set_defaults(func=lambda args, s="list": escalations_cmd(args, s))

    p = esc_sub.add_parser("ack", help="Acknowledge a ticket")
    p.add_argument("ticket_id")
    p.add_argument("--db", default=None)
    p.set_defaults(func=lambda args, s="ack": escalations_cmd(args, s))

    p = esc_sub.add_parser("resolve", help="Resolve a ticket (records an ApprovalRecord)")
    p.add_argument("ticket_id")
    p.add_argument("--reviewer", required=True)
    p.add_argument("--decision", choices=["approve", "reject"], required=True)
    p.add_argument("--rationale", default="")
    p.add_argument("--db", default=None)
    p.set_defaults(func=lambda args, s="resolve": escalations_cmd(args, s))

    # agent
    p_agent = subparsers.add_parser("agent", help="Agent Guard SDK commands")
    agent_sub = p_agent.add_subparsers(dest="agent_cmd", required=True)
    p_check = agent_sub.add_parser("check", help="Evaluate one action against a policy")
    p_check.add_argument("--policy", required=True, help="Policy YAML file")
    p_check.add_argument("--action", required=True, help="Action JSON file")
    p_check.set_defaults(func=agent_cmd)

    # report
    p_report = subparsers.add_parser("report", help="Build the static results report")
    report_sub = p_report.add_subparsers(dest="report_cmd", required=True)
    p_build = report_sub.add_parser("build", help="Build report/index.html from stored results")
    p_build.add_argument("--out", default="report/index.html", help="Output HTML path")
    p_build.add_argument("--evaluations", default="evaluations",
                         help="Evaluations directory with the example_* report folders")
    p_build.add_argument("--db", default=None,
                         help="Evidence SQLite DB for the integrity check (default: search)")
    p_build.set_defaults(func=report_cmd)

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
