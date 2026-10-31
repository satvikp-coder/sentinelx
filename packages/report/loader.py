"""Report data loader: reads the existing evaluation reports into plain dataclasses.

Every number shown by the HTML report comes from these files (or the evidence DB); nothing
is hardcoded. A section whose source file is missing reports NOT AVAILABLE naming the file;
a rate with a missing or zero denominator raises an error that names the metric.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class MetricError(ValueError):
    """A rate is missing its denominator, or the denominator is zero."""


@dataclass(frozen=True)
class Metric:
    name: str
    numerator: int
    denominator: int
    value: float | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any], where: str) -> Metric:
        name = str(d.get("name", "?"))
        den = d.get("denominator")
        if den is None or den == 0:
            raise MetricError(f"metric {name!r} in {where} has a missing or zero denominator")
        return cls(name, int(d["numerator"]), int(den), d.get("value"))

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


def _model_label(prov: dict[str, Any]) -> str:
    planner = str(prov.get("planner", ""))
    if "MODEL" not in planner.upper() and str(prov.get("mode", "")).startswith("SIMULATED"):
        return "SIMULATED scripted agent"
    provider = prov.get("provider", "?")
    model = prov.get("model", "?")
    mode = "LIVE" if "LIVE" in str(prov.get("mode", "")).upper() else \
        str(prov.get("mode", "?")).upper()
    return f"model: {provider}/{model} {mode}"


# ------------------------------------------------------------------ (1) paired agent guard
@dataclass(frozen=True)
class ArmData:
    label: str
    metrics: dict[str, Metric] = field(default_factory=dict)
    page_request_blocks: Metric | None = None


@dataclass(frozen=True)
class AgentGuardRun:
    label: str
    source: str
    arms: dict[str, ArmData]
    pairing: dict[str, Any]
    model_usage: dict[str, Any] | None = None


def _arm_data(arm: dict[str, Any], where: str, label: str) -> ArmData:
    metrics = {k: Metric.from_dict(v, where) for k, v in arm.get("overall", {}).items()}
    prb = arm.get("benign_page_request_blocks")
    return ArmData(label, metrics,
                   Metric.from_dict(prb, where) if isinstance(prb, dict) else None)


def _build_agent_guard(d: dict[str, Any], src: str) -> AgentGuardRun:
    prov = d.get("provenance", {})
    label = _model_label(prov)
    arms = {name: _arm_data(arm, src, label) for name, arm in d.get("arms", {}).items()}
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
    vs_baseline: dict[str, Any]


def _build_evcs(d: dict[str, Any], src: str) -> EvcsData:
    per = {}
    for mit, row in d.get("per_mitigation", {}).items():
        per[mit] = {k: (Metric.from_dict(v, f"{src}:{mit}.{k}")
                        if isinstance(v, dict) and "numerator" in v else v)
                    for k, v in row.items()}
    return EvcsData(
        per_mitigation=per,
        trap_rejections=Metric.from_dict(d["trap_rejections"], f"{src}:trap_rejections"),
        human_review_cases=Metric.from_dict(d["human_review_cases"], f"{src}:human_review_cases"),
        vs_baseline=d.get("evcs_vs_baseline", {}))


def load_evcs(evaluations: Path) -> Section:
    return _section("evcs", evaluations / "example_report_evcs" / "report.json", _build_evcs)


# ------------------------------------------------------------------ (4) site guard scan
@dataclass(frozen=True)
class ScanRow:
    lab: str
    source: str
    planted_found: list[str]
    planted_total: int
    recall: Metric
    unmatched_confirmed: list[str]
    clean_copy_false_findings: int
    coverage_percent: float | None
    requests_used: int | None
    request_budget: int | None
    model_label: str


@dataclass(frozen=True)
class ScanRowNA:
    """A lab whose scoring.json is missing: honest NOT AVAILABLE row, no defaults."""

    lab: str
    source: str
    error: str


def _scan_row(lab_dir: Path) -> ScanRow:
    scoring_path = lab_dir / "scoring.json"
    report_path = lab_dir / "report.json"
    src = scoring_path.as_posix()
    if not scoring_path.is_file():
        raise FileNotFoundError(f"{src} is missing")
    s = _read_json(scoring_path)
    recall = Metric.from_dict(s["overall_recall"], f"{src}:overall_recall")
    prov = _read_json(report_path).get("provenance", {}) if report_path.is_file() else {}
    planted_total = len(s.get("planted_found", [])) + len(s.get("planted_missed", []))
    if planted_total == 0:
        raise MetricError(f"planted total in {src} is zero (found+missed empty)")
    model = prov.get("model") or {}
    label = ("SIMULATED scripted agent" if str(model.get("mode", "none")) == "none"
             else f"model: {model.get('provider')}/{model.get('model')} {model.get('mode')}")
    return ScanRow(
        lab=str(s.get("lab", lab_dir.name)), source=src,
        planted_found=list(s.get("planted_found", [])), planted_total=planted_total,
        recall=recall, unmatched_confirmed=list(s.get("unmatched_confirmed_for_manual_review", [])),
        clean_copy_false_findings=int(s.get("clean_copy_false_findings_count", 0)),
        coverage_percent=prov.get("coverage_percent", s.get("coverage_percent")),
        requests_used=prov.get("requests_used", s.get("requests_used")),
        request_budget=prov.get("request_budget", s.get("request_budget")),
        model_label=label)


def load_scan(evaluations: Path) -> Section:
    root = evaluations / "example_scan_report"
    src = root.as_posix()
    if not root.is_dir():
        return Section("scan", "NOT AVAILABLE", src, f"{src} is missing")
    try:
        rows: list[ScanRow | ScanRowNA] = []
        for d in sorted(root.iterdir()):
            if not d.is_dir():
                continue
            if (d / "scoring.json").is_file():
                rows.append(_scan_row(d))
            else:
                rows.append(ScanRowNA(d.name, (d / "scoring.json").as_posix(),
                                      f"{(d / 'scoring.json').as_posix()} is missing"))
        if not rows:
            return Section("scan", "NOT AVAILABLE", src, f"no per-lab folders under {src}")
        return Section("scan", "OK", src, None, rows)
    except Exception as exc:
        raise type(exc)(f"{src}: {exc}") from exc


# ------------------------------------------------------------------ (5) fix engine
@dataclass(frozen=True)
class FixData:
    counts: dict[str, int]
    reasons: list[dict[str, Any]]
    spend: dict[str, Any] | None


def _build_fix(d: dict[str, Any], src: str) -> FixData:
    counts: dict[str, int] = {}
    reasons = []
    for r in d.get("results", []):
        status = str(r.get("status", "?"))
        counts[status] = counts.get(status, 0) + 1
        reasons.append({"finding_id": r.get("finding_id"), "status": status,
                        "patch_status": r.get("patch_status"),
                        "verification_status": r.get("verification_status"),
                        "reasons": r.get("patch_reasons") or r.get("explanation")})
    return FixData(counts, reasons, d.get("spend") if isinstance(d.get("spend"), dict) else None)


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
        for key in ("sent",):
            if int(attack.get("total", {}).get(key, 0)) == 0:
                raise MetricError(f"shield arm {name}: attack total {key!r} is zero in {src}")
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
    if isinstance(d.get("spend"), dict):
        s = d["spend"]
        spend = (f"spent ${s.get('spent_usd')} of hard cap ${s.get('hard_cap_usd')} "
                 f"(remaining ${s.get('remaining_usd')})")
    return ProvenanceRow(
        source=src, git_commit=str(git.get("commit", prov.get("git_commit", "n/a"))),
        date=str(prov.get("date_utc", prov.get("generated_at_utc", "n/a"))),
        manifest_hash=str(prov.get("manifest_hash", "n/a")),
        policy_version=str(prov.get("policy_version", prov.get("fix_policy_version", "n/a"))),
        model_label=_model_label(prov) if prov else "n/a", spend=spend)


def load_provenance(evaluations: Path) -> list[Section]:
    out = []
    for sub in ("example_report", "example_report_model", "example_report_evcs",
                "example_fix_report", "example_model_assisted_scan"):
        out.append(_section(f"provenance:{sub}", evaluations / sub / "report.json",
                            _build_provenance))
    return out


# ------------------------------------------------------------------ (8) limitations
def load_limitations(evaluations: Path) -> Section:
    root = evaluations
    src = root.as_posix()
    items: list[dict[str, str]] = []
    for sub in ("example_report", "example_report_model", "example_report_evcs",
                "example_fix_report", "example_model_assisted_scan",
                "example_scan_report/vibe_notes_node",
                "example_scan_report/vibe_notes_node_reference"):
        p = root / sub / "report.json"
        if p.is_file():
            text = _read_json(p).get("limitations")
            if isinstance(text, list):
                text = "\n".join(str(t) for t in text)
            if text:
                items.append({"source": p.as_posix(), "text": str(text)})
    return Section("limitations", "OK", src, None, items)


# ------------------------------------------------------------------ entry points
def load_all(evaluations: Path | None = None) -> dict[str, Section]:
    ev = Path(evaluations) if evaluations else Path("evaluations")
    sections: dict[str, Section] = {}
    for s in load_agent_guard(ev):
        sections[s.name] = s
    for s in (load_investigator(ev), load_evcs(ev), load_scan(ev), load_fix(ev),
              load_shield(ev), load_limitations(ev)):
        sections[s.name] = s
    for s in load_provenance(ev):
        sections[s.name] = s
    return sections


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--check" not in argv:
        print("usage: python -m sentinelx.report.loader --check", file=sys.stderr)
        return 2
    failed = False
    for name, section in load_all().items():
        if section.status == "OK":
            print(f"{name}: OK ({section.source})")
        else:
            print(f"{name}: {section.status} ({section.error})")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
