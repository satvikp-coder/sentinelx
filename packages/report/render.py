"""HTML renderer for the static Sentinel X report (self-contained, CSP-strict).

Every string that originates in a report file or the evidence DB is HTML-escaped here;
the data contains hostile page text. No JavaScript, no external resources: the CSP meta
tag in the template disallows everything except the inline stylesheet. Labels come from
each source's own provenance/state, never invented.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from string import Template

from .integrity import IntegrityReport
from .loader import (
    RECALL_LABEL,
    AgentGuardRun,
    FixData,
    Metric,
    Section,
)

_TEMPLATE = Path(__file__).resolve().parent / "templates" / "report.html"

INTRO = (
    "Sentinel X watches AI agents and web sites the same way a security guard watches a "
    "building: every action an agent proposes is checked against a strict written policy "
    "before it runs, and every request a web site receives is inspected by a reverse proxy. "
    "Everything the system sees is stored in a tamper-evident evidence chain, and a separate "
    "verifier - never the model that proposed the action - scores what actually happened. "
    "This page is generated only from stored result files, so every number below can be "
    "traced back to its source."
)

HOW_TO_READ = (
    "ATTEMPTED vs EXECUTED: a blocked attack was ATTEMPTED, not EXECUTED - the gateway "
    "refused it before the tool ran, so no forbidden outcome occurred. State labels: "
    "OBSERVED = directly recorded, INFERRED = derived by our rules, SIMULATED = produced by "
    "our scripted stand-ins, VERIFIED = independently re-checked. Shield rules are TEMPORARY "
    "SHIELD, NOT A FIX: they buy time for a human; only an applied, verified patch is a fix."
)

NO_PATCH = "no patch produced"
NOT_RECORDED = "not recorded"


def esc(value: object) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def label_chip(label: str) -> str:
    kind = label.split()[0].replace(",", "")
    cls = f"lbl-{kind}" if kind in ("OBSERVED", "INFERRED", "SIMULATED", "VERIFIED") else ""
    return f'<span class="label {cls}">{esc(label)}</span>'


def metric_card(metric: Metric, extra_label: str = "") -> str:
    name = metric.name or ""
    return (f'<div class="card"><div class="name">{esc(name)}</div>'
            f'<div class="metric">{esc(metric.rate)}</div>'
            f'{label_chip(extra_label) if extra_label else ""}</div>')


def na_card(title: str, error: str | None) -> str:
    return (f'<div class="card"><div class="name">{esc(title)}</div>'
            f'<span class="label lbl-NOTAVAILABLE">NOT AVAILABLE</span>'
            f'<div class="muted">{esc(error or "")}</div></div>')


def section_na(name: str, section: Section) -> str:
    return (f"<h2>{esc(name)}</h2><div class='card'>"
            f"<span class='label lbl-NOTAVAILABLE'>NOT AVAILABLE</span>"
            f"<div class='muted'>{esc(section.error or '')}</div></div>")


def _bar(pct: float) -> str:
    width = max(0.0, min(100.0, pct * 100.0))
    return f'<div class="bar"><span style="width:{width:.1f}%"></span></div>'


# ------------------------------------------------------------------ (1) agent guard
def render_agent_guard(sections: dict[str, Section]) -> str:
    parts = ["<h2>Agent Guard results (paired runs)</h2>"]
    runs: list[AgentGuardRun] = []
    for name in ("agent_guard_scripted", "agent_guard_model"):
        s = sections.get(name)
        if s and s.ok:
            runs.append(s.data)
        elif s:
            parts.append(na_card(name, s.error))
    if not runs:
        return "".join(parts)

    for run in runs:
        chip = label_chip("SIMULATED" if "SIMULATED" in run.label else "OBSERVED")
        parts.append(f"<h3>{chip} <span class='muted'>{esc(run.label)} &middot; "
                     f"{esc(run.source)}</span></h3>")
        rows = []
        cards = []
        for arm_name, arm in sorted(run.arms.items()):
            for metric_name, m in sorted(arm.metrics.items()):
                if arm.undefended and metric_name in ("task_preservation",):
                    rows.append(f"<tr><td>arm {esc(arm_name)}</td><td>{esc(m.name)}</td>"
                                "<td>n/a (defended runs only)</td><td></td></tr>")
                else:
                    rows.append(f"<tr><td>arm {esc(arm_name)}</td><td>{esc(m.name)}</td>"
                                f"<td>{esc(m.rate)}</td><td>{_bar(m.value or 0.0)}</td></tr>")
        if rows:
            parts.append("<table><tr><th>arm</th><th>metric</th><th>n/den</th><th></th></tr>"
                         + "".join(rows) + "</table>")
        for arm_name, arm in sorted(run.arms.items()):
            for m in arm.metrics.values():
                if arm.undefended and m.name in ("task_preservation",):
                    continue
                cards.append(metric_card(m, f"arm {arm_name}"))
        if run.model_usage:
            for arm_name, usage in sorted(run.model_usage.items()):
                cards.append(
                    f'<div class="card"><div class="name">model calls (arm {esc(arm_name)})'
                    f"</div><div class=\"metric\">{esc(usage.get('model_http_calls', ''))}"
                    f"</div><div class=\"muted\">tokens in/out: "
                    f"{esc(usage.get('tokens_in', ''))}/{esc(usage.get('tokens_out', ''))}"
                    "</div>")
        parts.append('<div class="grid">' + "".join(cards) + "</div>")
    return "".join(parts)


# ------------------------------------------------------------------ (3) EVCS
def _rate(v: object) -> str:
    if isinstance(v, Metric):
        return v.rate
    return esc(v)


def render_evcs(section: Section) -> str:
    if not section.ok:
        return section_na("Containment (EVCS)", section)
    data = section.data
    parts = ["<h2>Containment (EVCS)</h2>", label_chip("SIMULATED")]
    rows = []
    for mit, row in sorted(data.per_mitigation.items()):
        rows.append(
            f"<tr><td>{esc(mit)}</td><td>{esc(row.get('kind', ''))}</td>"
            f"<td>{_rate(row.get('unauthorized_executed'))}</td>"
            f"<td>{_rate(row.get('task_completed'))}</td>"
            f"<td>{_rate(row.get('containment_success'))}</td>"
            f"<td>{esc(row.get('mean_disruption_cost', ''))}</td></tr>")
    parts.append("<table><tr><th>mitigation</th><th>kind</th><th>unauthorized executed</th>"
                 "<th>task completed</th><th>containment success</th>"
                 "<th>mean disruption cost</th></tr>" + "".join(rows) + "</table>")
    parts.append("<table><tr><th>counter (source key)</th><th>n/den</th></tr>"
                 f"<tr><td>{esc(data.trap_rejections.name)}</td>"
                 f"<td>{esc(data.trap_rejections.rate)}</td></tr>"
                 f"<tr><td>{esc(data.human_review_cases.name)}</td>"
                 f"<td>{esc(data.human_review_cases.rate)}</td></tr></table>")

    # EVCS vs baseline: metric | EVCS n/den | baseline n/den | tie?
    parts.append(f"<h3>EVCS vs baseline ({esc(data.baseline_name)})</h3>")
    metric_names = sorted(set(data.evcs_metrics) | set(data.baseline_metrics))
    rows = []
    for name in metric_names:
        ev = data.evcs_metrics.get(name)
        bl = data.baseline_metrics.get(name)
        if isinstance(ev, dict) and "numerator" in ev:
            ev_txt, ev_val = Metric.from_dict(ev, "evcs").rate, ev.get("value")
        else:
            ev_txt, ev_val = esc(ev), ev
        if isinstance(bl, dict) and "numerator" in bl:
            bl_txt, bl_val = Metric.from_dict(bl, "baseline").rate, bl.get("value")
        else:
            bl_txt, bl_val = esc(bl), bl
        tie = "yes" if ev_val is not None and ev_val == bl_val else ""
        rows.append(f"<tr><td>{esc(name)}</td><td>{ev_txt}</td><td>{bl_txt}</td>"
                    f"<td>{tie}</td></tr>")
    parts.append("<table><tr><th>metric</th><th>EVCS</th><th>baseline</th><th>tie</th></tr>"
                 + "".join(rows) + "</table>")
    return "".join(parts)


# ------------------------------------------------------------------ (4) scan
def render_scan(section: Section) -> str:
    if not section.ok:
        return section_na("Site Guard scan", section)
    parts = ["<h2>Site Guard scan</h2>"]
    for row in section.data:
        parts.append(f"<h3>{esc(row.lab)} "
                     f"<span class='muted'>report date {esc(row.date_utc or NOT_RECORDED)}"
                     f"</span></h3>")
        if row.scoring_missing:
            parts.append(na_card(f"{row.lab} planted-recall scoring", row.scoring_missing))
        model = row.model_label or f"model {NOT_RECORDED} in this report"
        parts.append(f"<div class='muted'>{esc(model)}</div>")
        cov = (f"coverage {row.coverage_percent}% &middot; requests "
               f"{row.requests_used}/{row.request_budget}")
        parts.append(f"<div>{label_chip('OBSERVED')} <span class='muted'>{esc(cov)}</span>"
                     "</div>")
        cards = []
        if row.recall is not None and row.planted_total:
            cards.append(metric_card(Metric("planted_found", len(row.planted_found or []),
                                            row.planted_total,
                                            len(row.planted_found or []) / row.planted_total),
                                     RECALL_LABEL))
            cards.append(metric_card(row.recall, RECALL_LABEL))
        clean = row.clean_copy_false_findings
        if clean is not None:
            cards.append(f'<div class="card"><div class="name">'
                         f"clean_copy_false_findings ({esc(row.clean_copy_source)})"
                         f"</div><div class=\"metric\">{esc(clean)}</div>"
                         f"{label_chip('OBSERVED')}</div>")
        if cards:
            parts.append('<div class="grid">' + "".join(cards) + "</div>")
        if row.unmatched_confirmed:
            lines = []
            for item in row.unmatched_confirmed:
                if isinstance(item, dict):
                    lines.append(f"  {item.get('finding_id')} {item.get('vuln_class')} "
                                 f"{item.get('method')} {item.get('endpoint')}: "
                                 f"{item.get('summary')}")
                else:
                    lines.append(str(item))
            parts.append("<h3>confirmed-unmatched (manual review)</h3><pre>"
                         + esc("\n".join(lines)) + "</pre>")
    return "".join(parts)


# ------------------------------------------------------------------ (5) fix
def render_fix(section: Section) -> str:
    if not section.ok:
        return section_na("Fix engine", section)
    data: FixData = section.data
    total = sum(data.counts.values())
    parts = ["<h2>Fix engine</h2>"]
    model = data.model_label or f"model {NOT_RECORDED} in this report"
    parts.append(f"<div class='muted'>{esc(model)}</div>")
    if total == 0:
        return "".join(parts) + na_card("fix results", "no fix results recorded")
    cards = []
    for status, count in sorted(data.counts.items()):
        cards.append(metric_card(Metric(f"fix_{status}", count, total, count / total),
                                 "OBSERVED"))
    parts.append('<div class="grid">' + "".join(cards) + "</div>")
    parts.append("<table><tr><th>lab</th><th>finding</th><th>state</th>"
                 "<th>verification verdict</th><th>patch</th><th>rejected: failing check</th>"
                 "</tr>")
    for r in data.results:
        if r.verification_status == "REJECTED" and r.failed_checks:
            reason = "; ".join(f"{name}: {excerpt}" for name, excerpt in r.failed_checks)
        elif r.verification_status == "REJECTED":
            reason = "verification failed (no check detail recorded)"
        else:
            reason = ""
        patch = r.patch_status if r.patch_status else NO_PATCH
        parts.append(f"<tr><td>{esc(r.lab)}</td><td>{esc(r.finding_id)}</td>"
                     f"<td>{esc(r.status)}</td><td>{esc(r.verification_status or 'not run')}"
                     f"</td><td>{esc(patch)}</td><td>{esc(reason)}</td></tr>")
    parts.append("</table>")
    parts.append("<h3>model's description of its proposed patch (not verified)</h3>")
    expl = "".join(f"<li>{esc(r.finding_id)}: {esc(r.explanation)}</li>"
                   for r in data.results if r.explanation)
    parts.append(f"<ul>{expl}</ul>" if expl else "<p class='muted'>none recorded</p>")
    if data.spend:
        parts.append(f'<div class="muted">spend: {esc(data.spend.get("spent_usd"))} USD of '
                     f'hard cap {esc(data.spend.get("hard_cap_usd"))} USD</div>')
    return "".join(parts)


# ------------------------------------------------------------------ (6) shield
def render_shield(section: Section) -> str:
    if not section.ok:
        return section_na("Live shield (three-way)", section)
    parts = ["<h2>Live shield (three-way)</h2>", label_chip("OBSERVED")]
    header = ("<tr><th>arm</th><th>sent</th><th>reached upstream</th>"
              "<th>blocked by shield (marker)</th><th>lab 4xx/5xx</th></tr>")
    rows = []
    for arm in section.data:
        t = arm.attack_total
        rows.append(f"<tr><td>{esc(arm.name)}</td><td>{esc(t.get('sent', 0))}</td>"
                    f"<td>{esc(t.get('reached_upstream', 0))}</td>"
                    f"<td>{esc(t.get('blocked_by_shield', 0))}</td>"
                    f"<td>{esc(t.get('lab_4xx_5xx', 0))}</td></tr>")
    parts.append("<table>" + header + "".join(rows) + "</table>")
    parts.append("<div class='box'>TEMPORARY SHIELD, NOT A FIX: shield rules are narrow, "
                 "time-limited and never edit code; they buy time for a human.</div>")

    for arm in section.data:
        parts.append(f"<h3>arm {esc(arm.name)}</h3>")
        stage_rows = "".join(
            f"<tr><td>{esc(stage)}</td><td>{esc(s.get('sent', 0))}</td>"
            f"<td>{esc(s.get('reached_upstream', 0))}</td>"
            f"<td>{esc(s.get('blocked_by_shield', 0))}</td></tr>"
            for stage, s in sorted(arm.per_stage.items()))
        if stage_rows:
            parts.append("<table><tr><th>stage</th><th>sent</th><th>reached</th>"
                         "<th>blocked</th></tr>" + stage_rows + "</table>")
        r = arm.rules
        if isinstance(r, dict) and r:
            parts.append(
                f'<div class="muted">rules: proposed {esc(r.get("proposed", 0))}, '
                f'activated {esc(r.get("activated", 0))}, rejected by gate '
                f'{esc(r.get("rejected_by_gate", 0))}, escalations '
                f'{esc(r.get("escalations", 0))}</div>')
        b = arm.benign
        if isinstance(b, dict) and b:
            parts.append(f'<div class="muted">benign: sent {esc(b.get("sent", 0))}, falsely '
                         f'blocked/altered {esc(b.get("blocked_or_altered_by_shield", 0))}'
                         f"</div>")
            if arm.name in ("B", "C") and isinstance(r, dict) and r:
                gate_rejected = r.get("rejected_by_gate", 0)
                parts.append(
                    "<div class='box'>0 falsely blocked is partly by construction: shield "
                    "rules are scoped to the attacker's client key; the benign-replay gate "
                    f"(which rejected {esc(gate_rejected)} rules) is the real protection."
                    "</div>")
        if isinstance(arm.time_to_protect, dict) and arm.time_to_protect:
            ttp_rows = []
            for stage, v in sorted(arm.time_to_protect.items()):
                if isinstance(v, dict):
                    seconds = f"{v.get('seconds', 'not protected')}s" \
                        if isinstance(v.get("seconds"), (int, float)) else "not protected"
                    ttp_rows.append(f"<tr><td>{esc(stage)}</td><td>{esc(seconds)}</td>"
                                    f"<td>{esc(v.get('rule', ''))}</td>"
                                    f"<td>{esc(v.get('pre_activated', ''))}</td></tr>")
                else:
                    ttp_rows.append(f"<tr><td>{esc(stage)}</td><td>{esc(v)}</td>"
                                    "<td></td><td></td></tr>")
            parts.append("<table><tr><th>stage</th><th>time-to-protect</th><th>rule</th>"
                         "<th>pre-activated</th></tr>" + "".join(ttp_rows) + "</table>")
        if isinstance(arm.intent_accuracy, dict) and arm.intent_accuracy:
            ia_rows = []
            for stage, v in sorted(arm.intent_accuracy.items()):
                correct = int(v.get("correct", 0))
                sent = int(v.get("sent", 0))
                accuracy = correct / sent if sent else 0.0
                src_accuracy = v.get("accuracy")
                consistent = (src_accuracy is not None
                              and abs(float(src_accuracy) - accuracy) <= 0.005)
                acc_txt = f"{accuracy:.3f}"
                note = "" if consistent else " (source denominator: labelled)"
                ia_rows.append(f"<tr><td>{esc(stage)}</td><td>{esc(correct)}</td>"
                               f"<td>{esc(sent)}</td><td>{esc(acc_txt)}{esc(note)}</td></tr>")
            parts.append("<table><tr><th>stage</th><th>correct</th>"
                         "<th>stage requests</th><th>accuracy</th></tr>" + "".join(ia_rows)
                         + "</table>")
            parts.append("<div class='muted'>intent accuracy is low in several stages; "
                         "labels were not tuned. accuracy = correct / stage requests.</div>")
    return "".join(parts)


# ------------------------------------------------------------------ (7) integrity
def render_integrity(report: IntegrityReport) -> str:
    rows = "".join(
        f"<tr><td>{esc(r.session_id)}</td><td>{esc(r.status)}</td><td>{esc(r.detail)}</td>"
        f"<td class='muted'>{esc(r.source)}</td></tr>"
        for r in report.rows)
    table = ("<table><tr><th>session</th><th>status</th><th>detail</th><th>source</th></tr>"
             + rows + "</table>") if rows else "<p class='muted'>no session ids referenced</p>"
    banner = ""
    if report.db_path is None:
        banner = ("<div class='box warn'><strong>no evidence database found in this build; "
                  "run the build from the folder that holds the database</strong></div>")
    return (
        "<h2>Evidence integrity</h2>" + banner
        + f"<p class='muted'>{esc(report.note)} &middot; built "
        + f"{esc(report.built_at_utc)} &middot; db: {esc(report.db_path or NOT_RECORDED)}</p>"
        + f"<p>sessions checked: <strong>{len(report.rows)}</strong> &middot; "
        + f"OK: <strong>{report.ok_count}</strong> &middot; "
        + f"failed/missing: <strong>{len(report.failed)}</strong></p>{table}")


# ------------------------------------------------------------------ (8) limitations
def render_limitations(section: Section) -> str:
    parts = ["<h2>Limitations</h2>"]
    if not section.ok:
        return "".join(parts) + na_card(section.name, section.error)
    for item in section.data:
        parts.append(f"<h3 class='muted'>{esc(item['source'])}</h3><pre>"
                     f"{esc(item['text'])}</pre>")
    return "".join(parts)


# ------------------------------------------------------------------ (9) provenance
def render_provenance(sections: list[Section]) -> str:
    parts = ["<h2>Provenance</h2>"]
    rows = []
    for s in sections:
        if s.ok:
            p = s.data
            rows.append(f"<tr><td>{esc(s.source)}</td><td>{esc(p.git_commit)}</td>"
                        f"<td>{esc(p.date)}</td><td>{esc(p.manifest_hash)}</td>"
                        f"<td>{esc(p.policy_version)}</td><td>{esc(p.model_label)}</td>"
                        f"<td>{esc(p.spend or '-')}</td></tr>")
        else:
            rows.append(f"<tr><td>{esc(s.source)}</td>"
                        "<td colspan='6'><span class='label lbl-NOTAVAILABLE'>"
                        f"NOT AVAILABLE</span> {esc(s.error or '')}</td></tr>")
    parts.append("<table><tr><th>source</th><th>git commit</th><th>date</th>"
                 "<th>manifest hash</th><th>policy version</th><th>model</th>"
                 "<th>spend</th></tr>" + "".join(rows) + "</table>")
    return "".join(parts)


@dataclass(frozen=True)
class BuildResult:
    out_path: Path
    size_bytes: int
    not_available: list[str]


def _has_not_available(sections: dict[str, Section]) -> bool:
    for section in sections.values():
        if not section.ok:
            return True
        data = section.data
        if section.name == "scan" and isinstance(data, list):
            if any(getattr(row, "scoring_missing", None) for row in data):
                return True
    return False


def render_index(sections: dict[str, Section], integrity: IntegrityReport,
                 out_path: Path) -> BuildResult:
    body = [
        "<h1>Sentinel X &mdash; results</h1>",
        f'<div class="box"><strong>What Sentinel X is.</strong> {esc(INTRO)}</div>',
        '<div class="box warn"><strong>How to read this.</strong> '
        + esc(HOW_TO_READ) + "</div>",
        render_agent_guard(sections),
        render_evcs(sections.get("evcs", Section("evcs", "NOT AVAILABLE", "", "not loaded"))),
        render_scan(sections.get("scan", Section("scan", "NOT AVAILABLE", "", "not loaded"))),
        render_fix(sections.get("fix", Section("fix", "NOT AVAILABLE", "", "not loaded"))),
        render_shield(sections.get("shield", Section("shield", "NOT AVAILABLE", "",
                                                     "not loaded"))),
        render_integrity(integrity),
        render_limitations(sections.get("limitations", Section("limitations", "NOT AVAILABLE",
                                                               "", "not loaded"))),
        render_provenance([s for name, s in sorted(sections.items())
                           if name.startswith("provenance:")]),
    ]
    not_available = [name for name, s in sections.items() if not s.ok]
    if _has_not_available(sections):
        availability = "some sections not available"
    else:
        availability = "all sections available"
    footer = (f"generated {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} from stored "
              f"report files only; build-time evidence integrity check, not a live check; "
              f"{availability}"
              + (f": {', '.join(sorted(not_available))}" if not_available else ""))
    html_text = Template(_TEMPLATE.read_text(encoding="utf-8")).substitute(
        title="Sentinel X results", body="".join(body), footer=esc(footer))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_text, encoding="utf-8")
    return BuildResult(out_path, out_path.stat().st_size, not_available)
