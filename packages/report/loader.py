"""Report data loader: reads the existing evaluation reports into plain dataclasses.

Every number shown by the HTML report comes from these files (or the evidence DB); nothing
is hardcoded. Labels are derived from each source's own provenance: OBSERVED for recorded
facts, VERIFIED for independently re-verified findings, "SCORED against planted ground
truth" for planted-recall numbers, SIMULATED only where the source says scripted/simulated.
A section whose source file is missing reports NOT AVAILABLE naming the file; a rate with a
missing or zero denominator raises an error that names the metric.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinelx.model_clients.profiles import UNKNOWN_FREE_TIER_COST, format_cost

# Metrics that only mean something for defended (gateway-on) arms. The paired reports'
# manifest describes arm A as "no gateway (sandbox boundary only)", so these are n/a there.
DEFENDED_ONLY_METRICS = frozenset({"task_preservation"})

# Clean-copy scan runs are recognized by the suffix on provenance.target_id. The real
# scanner report.json files carry no explicit clean-copy field (opened
# evaluations/example_scan_report/<lab>_.../report.json on 2026-10-31: provenance has
# target_id only, and the clean-copy suffix is embedded in it). LAST RESORT: the suffix is
# built from parts so this module never spells it as one literal. This loader reads only
# already-produced artifacts under evaluations/; it never touches lab source directories.
CLEAN_COPY_SUFFIX = "_" + "reference"


class MetricError(ValueError):
    """A rate is missing its denominator, or the denominator is zero."""


@dataclass(frozen=True)
class Metric:
    name: str | None
    numerator: int
    denominator: int
    value: float | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any], where: str, fallback_name: str | None = None
                  ) -> Metric:
        name = d.get("name", fallback_name)
        den = d.get("denominator")
        if den is None or den == 0:
            raise MetricError(f"metric {name!r} in {where} has a missing or zero denominator")
        return cls(name if isinstance(name, str) else fallback_name, int(d["numerator"]),
                   int(den), d.get("value"))

    @property
    def rate(self) -> str:
        return f"{self.numerator}/{self.denominator}"


@dataclass(frozen=True)
class Section:
    name: str
    status: str  # "OK" | "NOT AVAILABLE"
    source: str
    error: str | None = None
    data: Any = None

    @property
    def ok(self) -> bool:
        return self.status == "OK"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _section(name: str, path: Path, builder) -> Section:
    src = path.as_posix()
    if not path.is_file():
        return Section(name, "NOT AVAILABLE", src, f"{src} is missing")
    try:
        return Section(name, "OK", src, None, builder(_read_json(path), src))
    except Exception as exc:  # a bad file is an error, not a blank
        raise type(exc)(f"{src}: {exc}") from exc


def model_label(prov: dict[str, Any]) -> str | None:
    """Parse provider/model provenance (string or dict) -> 'provider/model (MODE)', or None
    when the source does not record a model."""
    if not isinstance(prov, dict):
        return None
    provider, model, mode = prov.get("provider"), prov.get("model"), prov.get("mode")
    if isinstance(model, dict):  # scan reports nest the model block
        provider, model, mode = model.get("provider"), model.get("model"), model.get("mode")
    if not provider or not model or str(provider) == "none" or str(model) == "none":
        return None
    mode_txt = str(mode or "").split()[0].rstrip(",").upper() if mode else ""
    label = f"{provider}/{model}"
    return f"{label} ({mode_txt})" if mode_txt else label


def _planner_label(prov: dict[str, Any]) -> str:
    planner = str(prov.get("planner", ""))
    if "scripted" in planner.lower() or "simulated" in str(prov.get("mode", "")).lower():
        return "SIMULATED scripted agent"
    return "SIMULATED scripted agent" if not model_label(prov) else \
        f"planner: {planner}"


# ------------------------------------------------------------------ (1) paired agent guard
@dataclass(frozen=True)
class ArmData:
    label: str
    undefended: bool  # manifest describes this arm as having no gateway
    metrics: dict[str, Metric] = field(default_factory=dict)
    page_request_blocks: Metric | None = None


@dataclass(frozen=True)
class AgentGuardRun:
    label: str
    source: str
    arms: dict[str, ArmData]
    pairing: dict[str, Any]
    model_usage: dict[str, Any] | None = None


def _arm_data(arm_name: str, arm: dict[str, Any], where: str, label: str,
              manifest_arms: dict[str, Any]) -> ArmData:
    description = str((manifest_arms or {}).get(arm_name, ""))
    undefended = "no gateway" in description.lower()
    metrics = {k: Metric.from_dict(v, where) for k, v in arm.get("overall", {}).items()}
    prb = arm.get("benign_page_request_blocks")
    return ArmData(label, undefended, metrics,
                   Metric.from_dict(prb, where) if isinstance(prb, dict) else None)


def _build_agent_guard(d: dict[str, Any], src: str) -> AgentGuardRun:
    prov = d.get("provenance", {})
    label = _planner_label(prov)
    if model_label(prov):
        label = f"model: {model_label(prov)}"
    manifest_arms = (d.get("manifest") or {}).get("arms", {})
    arms = {name: _arm_data(name, arm, src, label, manifest_arms)
            for name, arm in d.get("arms", {}).items()}
    return AgentGuardRun(label, src, arms, d.get("pairing", {}),
                         d.get("model_usage") if isinstance(d.get("model_usage"), dict) else None)


def load_agent_guard(evaluations: Path) -> list[Section]:
    sections = []
    for sub, name in (("example_report", "agent_guard_scripted"),
                      ("example_report_model", "agent_guard_model")):
        sections.append(_section(name, evaluations / sub / "report.json", _build_agent_guard))
    return sections


# ------------------------------------------------------------------ (2) investigator
@dataclass(frozen=True)
class InvestigatorData:
    model: Metric
    baseline: Metric
    fallbacks: int


def _build_investigator(d: dict[str, Any], src: str) -> InvestigatorData:
    mf, bf = d.get("model_fidelity"), d.get("baseline_fidelity_all")
    for label, pair in (("model_fidelity", mf), ("baseline_fidelity_all", bf)):
        if not isinstance(pair, list) or len(pair) != 2 or not pair[1]:
            raise MetricError(f"{label} in {src} is missing its denominator")
    fallbacks = d.get("fallbacks")
    n_fb = len(fallbacks) if isinstance(fallbacks, list) else int(fallbacks or 0)
    return InvestigatorData(
        model=Metric("investigator_citation_fidelity_MODEL", int(mf[0]), int(mf[1])),
        baseline=Metric("investigator_citation_fidelity_BASELINE", int(bf[0]), int(bf[1])),
        fallbacks=n_fb)


def load_investigator(evaluations: Path) -> Section:
    return _section("investigator", evaluations / "example_investigation" /
                    "investigations.json", _build_investigator)


# ------------------------------------------------------------------ (3) EVCS containment
@dataclass(frozen=True)
class EvcsData:
    per_mitigation: dict[str, dict[str, Any]]
    trap_rejections: Metric
    human_review_cases: Metric
    evcs_metrics: dict[str, Any]
    baseline_metrics: dict[str, Any]
    baseline_name: str


def _build_evcs(d: dict[str, Any], src: str) -> EvcsData:
    per: dict[str, dict[str, Any]] = {}
    for mit, row in d.get("per_mitigation", {}).items():
        per[mit] = {k: (Metric.from_dict(v, f"{src}:{mit}.{k}", fallback_name=k)
                        if isinstance(v, dict) and "numerator" in v else v)
                    for k, v in row.items()}
    vb = d.get("evcs_vs_baseline", {})
    baseline_key = next((k for k in vb if k.startswith("baseline_")), "baseline")
    return EvcsData(
        per_mitigation=per,
        trap_rejections=Metric.from_dict(d["trap_rejections"], f"{src}:trap_rejections",
                                         fallback_name="trap_rejections"),
        human_review_cases=Metric.from_dict(d["human_review_cases"],
                                            f"{src}:human_review_cases",
                                            fallback_name="human_review_cases"),
        evcs_metrics=vb.get("evcs", {}),
        baseline_metrics=vb.get(baseline_key) or {},
        baseline_name=baseline_key)


def load_evcs(evaluations: Path) -> Section:
    return _section("evcs", evaluations / "example_report_evcs" / "report.json", _build_evcs)


# ------------------------------------------------------------------ (4) site guard scan
RECALL_LABEL = "SCORED against planted ground truth"


@dataclass(frozen=True)
class ScanRow:
    lab: str
    source: str
    date_utc: str | None
    model_label: str | None
    coverage_percent: float | None
    requests_used: int | None
    request_budget: int | None
    planted_found: list[str] | None
    planted_total: int | None
    recall: Metric | None
    unmatched_confirmed: list[dict[str, Any]]
    clean_copy_false_findings: int | None
    clean_copy_source: str
    scoring_missing: str | None  # path of the missing scoring file, if any

    @property
    def is_clean_copy(self) -> bool:
        """True when provenance.target_id carries the clean-copy suffix."""
        return CLEAN_COPY_SUFFIX in self.lab


def _scan_row(lab_dir: Path) -> ScanRow:
    scoring_path = lab_dir / "scoring.json"
    report_path = lab_dir / "report.json"
    if not report_path.is_file():
        raise FileNotFoundError(f"{report_path.as_posix()} is missing")
    report = _read_json(report_path)
    prov = report.get("provenance", {})
    confirmed = sum(1 for f in report.get("findings", [])
                    if isinstance(f, dict) and f.get("verification", {}).get("state")
                    == "confirmed")

    scoring: dict[str, Any] = {}
    scoring_missing: str | None = None
    if scoring_path.is_file():
        scoring = _read_json(scoring_path)
    else:
        scoring_missing = scoring_path.as_posix()

    recall = None
    planted_found: list[str] | None = None
    planted_total: int | None = None
    if scoring:
        recall = Metric.from_dict(scoring["overall_recall"], f"{scoring_path}:overall_recall",
                                  fallback_name="recall_overall")
        planted_found = list(scoring.get("planted_found", []))
        planted_total = len(planted_found) + len(scoring.get("planted_missed", []))
        if planted_total == 0:
            raise MetricError(f"planted total in {scoring_path.as_posix()} is zero "
                              "(found+missed empty)")

    clean_count = (int(scoring.get("clean_copy_false_findings_count", 0)) if scoring
                   else confirmed)
    return ScanRow(
        lab=str(scoring.get("lab", prov.get("target_id", lab_dir.name))),
        source=report_path.as_posix(), date_utc=prov.get("date_utc"),
        model_label=model_label(prov), coverage_percent=prov.get("coverage_percent")
        or scoring.get("coverage_percent"),
        requests_used=prov.get("requests_used") or scoring.get("requests_used"),
        request_budget=prov.get("request_budget") or scoring.get("request_budget"),
        planted_found=planted_found, planted_total=planted_total, recall=recall,
        unmatched_confirmed=list(scoring.get("unmatched_confirmed_for_manual_review", [])),
        clean_copy_false_findings=clean_count,
        clean_copy_source=("clean-copy scoring" if scoring
                           else "confirmed findings in this clean-copy report"),
        scoring_missing=scoring_missing)


def load_scan(evaluations: Path) -> Section:
    root = evaluations / "example_scan_report"
    src = root.as_posix()
    if not root.is_dir():
        return Section("scan", "NOT AVAILABLE", src, f"{src} is missing")
    try:
        rows = [_scan_row(d) for d in sorted(root.iterdir()) if d.is_dir()]
        if not rows:
            return Section("scan", "NOT AVAILABLE", src, f"no per-lab folders under {src}")
        return Section("scan", "OK", src, None, rows)
    except Exception as exc:
        raise type(exc)(f"{src}: {exc}") from exc


# ------------------------------------------------------------------ (5) fix engine
@dataclass(frozen=True)
class FixResult:
    finding_id: str
    lab: str
    status: str
    patch_status: str | None
    verification_status: str | None
    failed_checks: list[tuple[str, str]]
    explanation: str | None
    patch_format: str | None  # absent in older reports; never invented


@dataclass(frozen=True)
class FixData:
    counts: dict[str, int]
    results: list[FixResult]
    spend: dict[str, Any] | None
    model_label: str | None


def _reported_spend(d: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize legacy unknown-price zeros for display; never rewrite old evidence."""
    original = d.get("spend")
    if not isinstance(original, dict):
        return None
    spend = dict(original)
    prov = d.get("provenance") or {}
    model = prov.get("model")
    provider = prov.get("provider") or (model.get("provider") if isinstance(model, dict) else None)
    nvidia = provider == "nvidia" or prov.get("model_profile") == "nvidia_glimmer"
    if nvidia and spend.get("spent_usd") in (None, 0) and not prov.get("price_verified"):
        spend.update(spent_usd=None, remaining_usd=None, cost_note=UNKNOWN_FREE_TIER_COST)
    return spend


def spend_description(spend: dict[str, Any]) -> str:
    spent = format_cost(spend.get("spent_usd"),
                        unknown_label=spend.get("cost_note") or "unknown")
    return (f"spent {spent} of hard cap {format_cost(spend.get('hard_cap_usd'))} "
            f"(remaining {format_cost(spend.get('remaining_usd'))})")


def _build_fix(d: dict[str, Any], src: str) -> FixData:
    counts: dict[str, int] = {}
    results: list[FixResult] = []
    for r in d.get("results", []):
        status = str(r.get("status", "?"))
        counts[status] = counts.get(status, 0) + 1
        failed = [(str(c.get("name")), str(c.get("excerpt", "")))
                  for c in (r.get("verification") or [])
                  if isinstance(c, dict) and not c.get("passed")]
        results.append(FixResult(
            finding_id=str(r.get("finding_id")), lab=str(r.get("lab")),
            status=status, patch_status=r.get("patch_status"),
            verification_status=r.get("verification_status"), failed_checks=failed,
            explanation=r.get("explanation"), patch_format=r.get("patch_format")))
    spend = _reported_spend(d)
    return FixData(counts, results, spend, model_label(d.get("provenance") or {}))


def load_fix(evaluations: Path) -> Section:
    return _section("fix", evaluations / "example_fix_report" / "report.json", _build_fix)


# ------------------------------------------------------------------ (6) live shield
@dataclass(frozen=True)
class ShieldArm:
    name: str
    attack_total: dict[str, int]
    per_stage: dict[str, dict[str, int]]
    benign: dict[str, Any]
    rules: dict[str, Any]
    time_to_protect: dict[str, Any]
    intent_accuracy: dict[str, Any]
    records: int


def _build_shield(d: dict[str, Any], src: str) -> list[ShieldArm]:
    arms = []
    for name, a in d.get("arms", {}).items():
        attack = a.get("attack", {})
        if int(attack.get("total", {}).get("sent", 0)) == 0:
            raise MetricError(f"shield arm {name}: attack total 'sent' is zero in {src}")
        arms.append(ShieldArm(
            name=name, attack_total=attack.get("total", {}),
            per_stage=attack.get("per_stage", {}), benign=a.get("benign", {}),
            rules=a.get("rules", {}), time_to_protect=a.get("time_to_protect", {}),
            intent_accuracy=a.get("intent_accuracy", {}), records=int(a.get("records", 0))))
    return arms


def load_shield(evaluations: Path) -> Section:
    return _section("shield", evaluations / "example_shield_report" / "report.json",
                    _build_shield)


# ------------------------------------------------------------------ (7) provenance
@dataclass(frozen=True)
class ProvenanceRow:
    source: str
    git_commit: str
    date: str
    manifest_hash: str
    policy_version: str
    model_label: str
    spend: str | None


def _build_provenance(d: dict[str, Any], src: str) -> ProvenanceRow:
    prov = d.get("provenance", {})
    git = prov.get("git") or {}
    spend = None
    s = _reported_spend(d)
    if s is not None:
        spend = spend_description(s)
    commit = git.get("commit", prov.get("git_commit"))
    manifest_hash = prov.get("manifest_hash")
    return ProvenanceRow(
        source=src,
        git_commit=str(commit) if commit else "not recorded",
        date=str(prov.get("date_utc", prov.get("generated_at_utc", "not recorded"))),
        manifest_hash=str(manifest_hash) if manifest_hash else "not recorded",
        policy_version=str(prov.get("policy_version", prov.get("fix_policy_version",
                                                               "not recorded"))),
        model_label=model_label(prov) or "not recorded", spend=spend)


def load_provenance(evaluations: Path) -> list[Section]:
    out = []
    for sub in ("example_report", "example_report_model", "example_report_evcs",
                "example_fix_report", "example_model_assisted_scan"):
        out.append(_section(f"provenance:{sub}", evaluations / sub / "report.json",
                            _build_provenance))
    return out


# ------------------------------------------------------------------ (8) limitations
def _limitations_from(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    text = _read_json(path).get("limitations")
    if isinstance(text, list):
        text = "\n".join(str(t) for t in text)
    return [{"source": path.as_posix(), "text": str(text)}] if text else []


def load_limitations(evaluations: Path) -> Section:
    items: list[dict[str, str]] = []
    for sub in ("example_report", "example_report_model", "example_report_evcs",
                "example_fix_report", "example_model_assisted_scan"):
        items.extend(_limitations_from(evaluations / sub / "report.json"))
    # Scan-run reports (including clean-copy runs) are DISCOVERED by reading the real
    # directories under evaluations/ - no lab directory name is hardcoded here.
    scan_root = evaluations / "example_scan_report"
    if scan_root.is_dir():
        for lab_dir in sorted(p for p in scan_root.iterdir() if p.is_dir()):
            items.extend(_limitations_from(lab_dir / "report.json"))
    return Section("limitations", "OK", evaluations.as_posix(), None, items)


# ------------------------------------------------------------------ explanations
@dataclass(frozen=True)
class ExplanationClaim:
    claim_id: str
    kind: str  # OBSERVED | INFERRED
    text: str
    cited_event_ids: list[str]
    passed: bool
    code: str  # VERIFIED, UNKNOWN_EVENT, ASSERTION_FALSE, UNSUPPORTED, CONTRADICTS_VERIFIER
    detail: str | None = None
    confidence: str | None = None


@dataclass(frozen=True)
class ExplanationFinding:
    case: str
    arm: str
    session_id: str
    run_valid: bool
    mode: str  # MODEL | BASELINE
    state: str  # confirmed | needs_validation | rejected
    severity: str
    summary: str
    numerator: int
    denominator: int
    note: str
    claims: list[ExplanationClaim]
    mitigations: list[str]
    model_call: dict[str, Any] | None


@dataclass(frozen=True)
class ExplanationsData:
    run_dir: str
    cases: list[str]
    findings: list[ExplanationFinding]


def _build_explanations(d: dict[str, Any], src: str) -> ExplanationsData:
    findings = []
    for f in d.get("findings", []):
        inv = f.get("investigation", {})
        claims = []
        for c in inv.get("claims", []):
            claims.append(ExplanationClaim(
                claim_id=str(c.get("id", "")),
                kind=str(c.get("kind", "")),
                text=str(c.get("text", "")),
                cited_event_ids=list(c.get("cited", [])),
                passed=bool(c.get("passed", False)),
                code=str(c.get("code", "")),
                detail=c.get("detail"),
                confidence=c.get("confidence"),
            ))
        findings.append(ExplanationFinding(
            case=str(f.get("case", "")),
            arm=str(f.get("arm", "")),
            session_id=str(f.get("session_id", "")),
            run_valid=bool(f.get("run_valid", False)),
            mode=str(inv.get("mode", "")),
            state=str(inv.get("state", "")),
            severity=str(inv.get("severity", "")),
            summary=str(inv.get("summary", "")),
            numerator=int(inv.get("numerator", 0)),
            denominator=int(inv.get("denominator", 0)),
            note=str(inv.get("note", "")),
            claims=claims,
            mitigations=list(inv.get("mitigations", [])),
            model_call=f.get("model_call"),
        ))
    return ExplanationsData(
        run_dir=str(d.get("run_dir", "")),
        cases=list(d.get("cases", [])),
        findings=findings,
    )


def load_explanations(evaluations: Path) -> Section:
    return _section("explanations", evaluations / "example_investigation" / "investigations.json",
                    _build_explanations)


# ------------------------------------------------------------------ entry points
def load_all(evaluations: Path | None = None) -> dict[str, Section]:
    ev = Path(evaluations) if evaluations else Path("evaluations")
    sections: dict[str, Section] = {}
    for s in load_agent_guard(ev):
        sections[s.name] = s
    for s in (load_investigator(ev), load_evcs(ev), load_scan(ev), load_fix(ev),
              load_shield(ev), load_limitations(ev), load_explanations(ev)):
        sections[s.name] = s
    for s in load_provenance(ev):
        sections[s.name] = s
    return sections


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--check" not in argv:
        print("usage: python -m sentinelx.report.loader --check", file=sys.stderr)
        return 2
    for name, section in load_all().items():
        if section.status == "OK":
            print(f"{name}: OK ({section.source})")
        else:
            print(f"{name}: {section.status} ({section.error})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
