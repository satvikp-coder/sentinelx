"""Part D: independent verification. NO model import anywhere in this module - a patch is
never reported fixed because the model says so. Every check re-derives its own evidence by
actually running the patched copy; nothing here trusts the patch's own explanation."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from sentinelx.common_schemas import CheckResult, VerificationStatus
from sentinelx.evidence.db import connect, migrate
from sentinelx.scanner.authz import register_lab_target
from sentinelx.scanner.models import load_profile
from sentinelx.scanner.orchestrate import run_scan

from .diff_validator import validate_diff
from .materialize import VerifyInstance, materialize
from .models import RepoScope

REPO_ROOT = Path(__file__).resolve().parents[2]
LABS_ROOT = REPO_ROOT / "labs"
DEFAULT_PROFILE_PATH = REPO_ROOT / "configs" / "scan" / "lab_default.yaml"


@dataclass(frozen=True)
class TimedCheck:
    result: CheckResult
    duration_ms: int


@dataclass
class VerificationReport:
    patch_id: str
    checks: list[TimedCheck] = field(default_factory=list)
    status: VerificationStatus = VerificationStatus.REJECTED

    @property
    def check_results(self) -> list[CheckResult]:
        return [c.result for c in self.checks]

    @property
    def total_duration_ms(self) -> int:
        return sum(c.duration_ms for c in self.checks)


def _timed(name: str, fn) -> TimedCheck:
    start = time.monotonic()
    try:
        passed, excerpt = fn()
    except Exception as exc:  # noqa: BLE001 - a verifier failure is honestly REJECTED
        passed, excerpt = False, f"verifier raised {type(exc).__name__}: {exc}"
    duration_ms = int((time.monotonic() - start) * 1000)
    return TimedCheck(CheckResult(name=name, passed=passed, output_excerpt=excerpt[:500]),
                      duration_ms)


def _syntax_check(scope: RepoScope, file: str) -> tuple[bool, str]:
    is_php = (LABS_ROOT / scope.lab / "app").is_dir()
    target = scope.resolve_in_scope(file)
    if is_php:
        r = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{scope.work_dir}:/app:ro", "php:8.5.12-apache",
             "php", "-l", f"/app/{file}"], capture_output=True, text=True, timeout=120)
        return r.returncode == 0, (r.stdout + r.stderr)
    r = subprocess.run([shutil.which("node") or "node", "--check", str(target)],
                      capture_output=True, text=True, timeout=30)
    return r.returncode == 0, (r.stdout + r.stderr)


def _benign_traffic_check(inst: VerifyInstance) -> tuple[bool, str]:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "benign_traffic_verify", LABS_ROOT / inst.lab / "benign_traffic.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.run(base_url=inst.base_url, lab=inst.lab)
    failures = [f"{s.feature}: {s.note}" for s in report.failures()]
    return report.passed, (f"{report.features} features / {report.requests} requests; "
                          f"failures: {failures}" if failures else
                          f"{report.features} features / {report.requests} requests, all passed")


def _confirmed_set(findings: list) -> set[tuple[str, str, str]]:
    return {(f["candidate"]["vuln_class"], f["candidate"]["endpoint"], f["candidate"]["method"])
           for f in findings if f["verification"]["state"] == "confirmed"}


def _full_scan_check(inst: VerifyInstance, original_findings: list, fixed_key: tuple
                     ) -> tuple[bool, str, list]:
    """Returns (ok, excerpt, new_findings_list). ok requires BOTH: the fixed finding no longer
    confirms, AND no NEW (vuln_class, endpoint, method) confirms that wasn't already confirmed
    in the original scan (other than the one just fixed)."""
    profile = load_profile(str(DEFAULT_PROFILE_PATH))
    port = int(inst.base_url.rsplit(":", 1)[1])
    target = register_lab_target(f"{inst.lab}-verify", ["127.0.0.1"], [port])
    conn = connect(Path(tempfile.mkdtemp(prefix="sentinelx-verify-db-")) / "verify.db")
    migrate(conn)
    result = run_scan(target, profile, LABS_ROOT, inst.lab, conn)
    new_findings = [f.model_dump(mode="json") for f in result.findings]
    new_confirmed = _confirmed_set(new_findings)
    original_confirmed = _confirmed_set(original_findings)
    still_broken = fixed_key in new_confirmed
    newly_introduced = new_confirmed - original_confirmed - {fixed_key}
    ok = not still_broken and not newly_introduced
    excerpt = (f"still_broken={still_broken} newly_introduced={sorted(newly_introduced)}")
    return ok, excerpt, new_findings


def verify_patch(scope: RepoScope, *, patch_id: str, diff_text: str, allowed_files: set[str],
                 diagnosed_file: str, vuln_class: str, endpoint: str, method: str,
                 original_findings: list) -> VerificationReport:
    def _diff_review() -> tuple[bool, str]:
        v = validate_diff(diff_text, scope, allowed_files)
        return v.ok, ("; ".join(v.reasons) or "ok")

    report = VerificationReport(patch_id=patch_id)
    report.checks.append(_timed("diff_review", _diff_review))
    if not report.checks[-1].result.passed:
        report.status = VerificationStatus.REJECTED
        return report
    report.checks.append(_timed("syntax", lambda: _syntax_check(scope, diagnosed_file)))
    if not report.checks[-1].result.passed:
        report.status = VerificationStatus.REJECTED
        return report
    inst = materialize(scope)
    try:
        report.checks.append(_timed("benign_traffic", lambda: _benign_traffic_check(inst)))
        fixed_key = (vuln_class, endpoint, method)
        full_scan_result: list = []

        def _scan() -> tuple[bool, str]:
            ok, excerpt, findings = _full_scan_check(inst, original_findings, fixed_key)
            full_scan_result.extend(findings)
            return ok, excerpt

        report.checks.append(_timed("exploit_no_longer_reproduces_and_no_new_finding", _scan))
    finally:
        inst.stop()
    report.status = (VerificationStatus.VERIFIED if all(c.result.passed for c in report.checks)
                     else VerificationStatus.REJECTED)
    return report
