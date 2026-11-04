#!/usr/bin/env python3
"""Final-run orchestrator: runs the live evaluations in order (or --only one of them).

Steps: agent_scripted, agent_model, scan (Node + PHP-via-Docker), fix, shield, evcs, report.
Every LIVE step is preceded by scripts/estimate_cost.py; a nonzero estimate (over budget)
refuses the run - the spend guard stays authoritative. --dry-run prints the full plan, the
exact commands, expected model calls and worst-case dollars, and runs nothing. Writes
evaluations/final/run_manifest.json. Never reads .env, never prints a key; labs/proxies are
shut down best-effort even on failure.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.model_clients import estimate_cost, load_models_config
from sentinelx.policy import redaction as _redact

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
LABS = ("vibe_notes_node", "vibe_shop_php")
WORST_CASE_RE = re.compile(r"\$([0-9.]+) worst case")


def _redact_text(s: str) -> str:
    if not isinstance(s, str):
        return ""
    return _redact.redact(s).value


def _redact_cmd(cmd: list[str]) -> list[str]:
    return [_redact_text(str(c)) for c in cmd]


def _build_child_env(live: bool) -> dict[str, str]:
    # allowlist minimal env + model vars only for live steps
    allowed = {"PATH", "HOME", "USER", "USERNAME", "LANG", "PYTHONPATH"}
    base = {k: v for k, v in os.environ.items() if k in allowed}
    env = dict(base)
    # redact values whose names contain KEY/TOKEN/SECRET
    redacted = {}
    for k, _v in list(env.items()):
        if re.search(r"(KEY|TOKEN|SECRET)", k, re.IGNORECASE):
            redacted[k] = "[REDACTED]"
    env.update(redacted)
    if live:
        for k in list(os.environ.keys()):
            if k.startswith("MODEL_") or k.startswith("BASETEN_"):
                env[k] = os.environ.get(k, "")
                # mask if name matches pattern
                if re.search(r"(KEY|TOKEN|SECRET)", k, re.IGNORECASE):
                    env[k] = "[REDACTED]"
    return env


def _worst_case_usd_pure(step: PlannedStep) -> str | None:
    if not step.live or not step.profile:
        return None
    try:
        cfg = load_models_config()
        prof = cfg.profiles.get(step.profile)
        if prof is None:
            return None
        per_call = estimate_cost(prof, step.est_tokens_in, step.est_tokens_out)
        total = per_call * step.est_calls
        return f"{total:.4f}"
    except Exception:
        return None


@dataclass
class PlannedStep:
    name: str
    commands: list[list[str]]  # each is a fixed-argv list (no shell strings)
    live: bool = False
    profile: str | None = None
    est_calls: int = 0
    est_tokens_in: int = 0
    est_tokens_out: int = 0
    needs_docker: bool = False
    note: str = ""
    scan_report_root: Path | None = None


@dataclass
class StepRecord:
    name: str
    commands: list[list[str]]
    exit_code: int | None = None
    duration_s: float | None = None
    skipped_reason: str | None = None
    estimated: dict = field(default_factory=dict)
    output_tail: str = ""

    def to_json(self) -> dict:
        # redact commands and limit output tail
        redacted_cmds = []
        for cmd in self.commands:
            redacted_cmds.append(_redact_cmd(cmd))
        # limit output tail to last 20 lines, each <=300 chars
        tail = self.output_tail or ""
        lines = tail.splitlines()
        limited = lines[-20:] if len(lines) > 20 else lines
        limited = [line[:300] for line in limited]
        output_tail = "\n".join(limited)
        return {"name": self.name, "commands": redacted_cmds,
                "exit_code": self.exit_code, "duration_s": self.duration_s,
                "skipped_reason": self.skipped_reason, "estimated": self.estimated,
                "output_tail": output_tail}


def cli_cmd() -> list[str]:
    name = "sentinelx.exe" if sys.platform == "win32" else "sentinelx"
    exe = Path(PY).with_name(name)
    if exe.is_file():
        return [str(exe)]
    return [PY, "-c", "import sys; from sentinelx_cli.main import main; sys.exit(main())"]


def git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                             text=True, timeout=15)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def latest_scan_report(evaluations: Path, target: str) -> Path | None:
    root = evaluations / "scan_runs"
    best: tuple[float, Path] | None = None
    for report in root.glob("*/report.json"):
        try:
            prov = json.loads(report.read_text(encoding="utf-8")).get("provenance", {})
        except (OSError, ValueError):
            continue
        if prov.get("target_id") == target:
            mtime = report.stat().st_mtime
            if best is None or mtime > best[0]:
                best = (mtime, report)
    return best[1] if best else None


def docker_running() -> bool:
    try:
        r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                           cwd=ROOT, capture_output=True, text=True, timeout=30)
        return r.returncode == 0 and bool(r.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return False


def _fix_commands(report: Path | None) -> list[list[str]]:
    return ([[PY, "scripts/run_fix.py", "--target", "vibe_notes_node",
              "--scan-report", str(report)]] if report is not None else [])


def build_steps(evaluations: Path | None = None) -> list[PlannedStep]:
    ev = Path(evaluations) if evaluations else ROOT / "evaluations"
    manifest = ev / "manifest.json"
    subset = ev / "manifest_subset.json"
    subset_calls = 10
    if subset.is_file():
        try:
            cases = json.loads(subset.read_text(encoding="utf-8")).get("cases") or []
            subset_calls = max(1, len(cases))
        except (OSError, ValueError):
            pass
    fix_report = latest_scan_report(ev, "vibe_notes_node")
    steps = [
        PlannedStep("agent_scripted",
                    [[PY, "scripts/run_experiment.py", "--manifest", str(manifest),
                      "--run-id", "final-scripted"]]),
        PlannedStep("agent_model",
                    [[PY, "scripts/run_model_experiment.py", "--manifest", str(subset),
                      "--run-id", "final-model"]],
                    live=True, profile="nvidia_glimmer", est_calls=subset_calls,
                    est_tokens_in=2000, est_tokens_out=1200),
        PlannedStep("scan",
                    [[PY, "scripts/run_scan.py", "--target", "vibe_notes_node", "--model"],
                     [PY, "scripts/run_scan.py", "--target", "vibe_shop_php", "--model"]],
                    live=True, profile="nvidia_glimmer", est_calls=12,
                    est_tokens_in=2000, est_tokens_out=800),
        PlannedStep("fix",
                    _fix_commands(fix_report),
                    live=True, profile="baseten_spark_open", est_calls=6,
                    est_tokens_in=3000, est_tokens_out=1500,
                    note="" if fix_report else "no scan report for vibe_notes_node yet",
                    scan_report_root=ev),
        PlannedStep("shield", [[PY, "scripts/run_three_way.py"]]),
        PlannedStep("evcs", [[PY, "scripts/run_evcs_all.py"]]),
        PlannedStep("report", [[*cli_cmd(), "report", "build"]]),
    ]
    return steps


def run_cmd(
    cmd: list[str],
    timeout: int = 3600,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=env)
    # redact captured output before returning
    proc.stdout = _redact_text(proc.stdout)
    proc.stderr = _redact_text(proc.stderr)
    return proc


def estimate_spend(step: PlannedStep) -> tuple[int, str | None]:
    """Run the spend guard for a live step. Returns (exit_code, worst_case_usd_or_None)."""
    result = run_cmd([PY, "scripts/estimate_cost.py", "--profile", step.profile,
                      "--calls", str(step.est_calls),
                      "--tokens-in", str(step.est_tokens_in),
                      "--tokens-out", str(step.est_tokens_out)], timeout=120)
    match = WORST_CASE_RE.search(result.stdout or "")
    worst = match.group(1) if match else None
    return result.returncode, worst


def shutdown_labs() -> None:
    for lab in LABS:
        result = run_cmd([PY, "scripts/lab_down.py", lab], timeout=120)
        print(f"cleanup: {lab} down (exit {result.returncode})", flush=True)


def execute(steps: list[PlannedStep], *, dry_run: bool, only: str | None,
            continue_on_error: bool, manifest_path: Path) -> int:
    started = datetime.now(UTC)
    records: list[StepRecord] = []
    if only and not any(s.name == only for s in steps):
        print(f"ERROR: unknown step {only!r}; choose one of "
              f"{', '.join(s.name for s in steps)}", file=sys.stderr)
        return 2

    # Early dry-run path: print plan with pure-Python worst-case estimates, no subprocess
    if dry_run:
        print("DRY-RUN PLAN")
        for step in steps:
            if only and step.name != only:
                continue
            if step.live:
                live_desc = f"LIVE model={step.profile} expected_calls={step.est_calls}"
            else:
                live_desc = "offline (no model)"
            print(f"  {step.name}: {live_desc}")
            for cmd in step.commands:
                print(f"      $ {' '.join(cmd)}")
            if step.live:
                worst = _worst_case_usd_pure(step)
                if worst is not None:
                    print(f"      worst-case estimate: ${worst}")
                else:
                    print("      worst-case estimate: not computed in dry-run")
        # Build records for manifest without launching anything
        for step in steps:
            if only and step.name != only:
                continue
            rec = StepRecord(step.name, step.commands)
            rec.skipped_reason = "dry-run: not executed"
            if step.live:
                worst = _worst_case_usd_pure(step)
                rec.estimated = {"profile": step.profile,
                                 "expected_model_calls": step.est_calls,
                                 "worst_case_usd": worst,
                                 "guard_exit_code": None,
                                 "prerequisite_note": step.note or None}
            records.append(rec)
        # write manifest without subprocess (no git_commit)
        manifest = {
            "git_commit": "unknown",
            "started_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ended_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dry_run": True,
            "steps": [r.to_json() for r in records],
            "model_providers": sorted({r.estimated.get("profile") for r in records
                                       if r.estimated.get("profile")}),
            "estimated_spend_usd_total": round(sum(
                float(r.estimated["worst_case_usd"]) for r in records
                if r.estimated.get("worst_case_usd") is not None), 4),
        }
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"\ndry-run finished; manifest: {manifest_path.as_posix()}", flush=True)
        return 0

    started_labs = False
    for step in steps:
        if only and step.name != only:
            continue
        if step.scan_report_root is not None:
            # The scan earlier in THIS plan may have created a report. Resolve
            # at execution time rather than permanently skipping a fresh run.
            report = latest_scan_report(step.scan_report_root, "vibe_notes_node")
            step.commands = _fix_commands(report)
            step.note = "" if report else "no scan report for vibe_notes_node yet"
        record = StepRecord(step.name, step.commands)
        if step.note:
            record.skipped_reason = step.note
        elif step.needs_docker and not docker_running():
            record.skipped_reason = "Docker daemon not running; PHP lab skipped"
            print(f"--- {step.name}: SKIPPED ({record.skipped_reason})", flush=True)
            records.append(record)
            continue

        if step.live:
            code, worst = estimate_spend(step)
            record.estimated = {"profile": step.profile, "expected_model_calls": step.est_calls,
                                "worst_case_usd": worst, "guard_exit_code": code}
            if code != 0:
                print(f"SPEND GUARD REFUSED step {step.name}: estimate_cost exited {code} "
                      f"(worst case ${worst}); remaining budget minus reserve exceeded.",
                      file=sys.stderr, flush=True)
                records.append(record)
                _write_manifest(manifest_path, started, records, dry_run=dry_run)
                if started_labs:
                    shutdown_labs()
                return 3
            print(f"--- {step.name}: spend guard OK (worst case ${worst}, "
                  f"{step.est_calls} expected calls)", flush=True)

        # print commands with redaction
        env = _build_child_env(step.live)
        for cmd in step.commands:
            redacted_cmd = _redact_cmd(cmd)
            print(f"--- {step.name}: $ {' '.join(redacted_cmd)}", flush=True)

        started_labs = True
        started_at = time.monotonic()
        last: subprocess.CompletedProcess | None = None
        failed = False
        for cmd in step.commands:
            try:
                last = run_cmd(cmd, env=env)
            except (OSError, subprocess.SubprocessError) as exc:
                record.exit_code = -1
                record.output_tail = _redact_text(f"{type(exc).__name__}: {exc}")
                failed = True
                break
            # print redacted stdout tail
            out = (last.stdout or "")[-1200:]
            print(out, flush=True)
            if last.returncode != 0:
                # store redacted stderr tail
                record.output_tail = _redact_text(last.stderr or "")
                failed = True
                break
        record.duration_s = round(time.monotonic() - started_at, 1)
        record.exit_code = 0 if not failed else (last.returncode if last else -1)
        records.append(record)
        if failed:
            _write_manifest(manifest_path, started, records, dry_run=dry_run)
            print(f"STEP FAILED: {step.name} (exit {record.exit_code})", file=sys.stderr,
                  flush=True)
            if started_labs:
                shutdown_labs()
            if not continue_on_error:
                return 1

    _write_manifest(manifest_path, started, records, dry_run=dry_run)
    print(f"\nplan {'(dry-run) ' if dry_run else ''}finished; manifest: "
          f"{manifest_path.as_posix()}", flush=True)
    if started_labs:
        shutdown_labs()
    return 0


def _write_manifest(manifest_path: Path, started: datetime, records: list[StepRecord],
                    *, dry_run: bool) -> None:
    manifest = {
        "git_commit": git_commit(),
        "started_utc": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ended_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dry_run": dry_run,
        "steps": [r.to_json() for r in records],
        "model_providers": sorted({r.estimated.get("profile") for r in records
                                   if r.estimated.get("profile")}),
        "estimated_spend_usd_total": round(sum(
            float(r.estimated["worst_case_usd"]) for r in records
            if r.estimated.get("worst_case_usd") is not None), 4),
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="print the plan; run nothing")
    ap.add_argument("--only", help="run a single step by name")
    ap.add_argument("--continue", dest="keep_going", action="store_true",
                    help="keep going after a failed step")
    ap.add_argument("--evaluations", default=str(ROOT / "evaluations"))
    ap.add_argument("--manifest-out", default=str(ROOT / "evaluations" / "final" /
                                                  "run_manifest.json"))
    args = ap.parse_args(argv)

    print("FINAL RUN PLAN" + (" (dry-run)" if args.dry_run else ""), flush=True)
    steps = build_steps(Path(args.evaluations))
    for step in steps:
        live = f"LIVE model={step.profile} expected_calls={step.est_calls}" if step.live \
            else "offline (no model)"
        print(f"  {step.name}: {live}")
        for cmd in step.commands:
            print(f"      $ {' '.join(cmd)}")
    print(flush=True)

    return execute(steps, dry_run=args.dry_run, only=args.only,
                   continue_on_error=args.keep_going, manifest_path=Path(args.manifest_out))


if __name__ == "__main__":
    raise SystemExit(main())
