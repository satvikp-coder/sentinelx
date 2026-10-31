"""HTML renderer for the static Sentinel X report (self-contained, CSP-strict).

Every string that originates in a report file or the evidence DB is HTML-escaped here;
the data contains hostile page text. No JavaScript, no external resources: the CSP meta
tag in the template disallows everything except the inline stylesheet.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from string import Template

from .integrity import IntegrityReport
from .loader import (
    AgentGuardRun,
    Metric,
    ScanRowNA,
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


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def label_chip(label: str) -> str:
    kind = label.split()[0].replace(",", "")
    cls = f"lbl-{kind}" if kind in ("OBSERVED", "INFERRED", "SIMULATED", "VERIFIED") else ""
    return f'<span class="label {cls}">{esc(label)}</span>'


def metric_card(metric: Metric, extra_label: str = "") -> str:
    return (f'<div class="card"><div class="name">{esc(metric.name)}</div>'
            f'<div class="metric">{esc(metric.rate)}</div>'
            f'{label_chip(extra_label) if extra_label else ""}</div>')


def na_card(section: Section) -> str:
    return (f'<div class="card"><div class="name">{esc(section.name)}</div>'
            f'<span class="label lbl-NOTAVAILABLE">NOT AVAILABLE</span>'
            f'<div class="muted">{esc(section.error or "")}</div></div>')


def section_heading(name: str, section: Section, state_label: str = "") -> str:
    if section.ok:
        return f"<h2>{esc(name)}</h2>"
    return (f'<h2>{esc(name)}</h2><div class="card">'
            f'<span class="label lbl-NOTAVAILABLE">NOT AVAILABLE</span>'
            f'<div class="muted">{esc(section.error or "")}</div></div>')


def _bar(pct: float) -> str:
    width = max(0.0, min(100.0, pct * 100.0))
    return f'<div class="bar"><span style="width:{width:.1f}%"></span></div>'


# ------------------------------------------------------------------ (1) agent guard
def render_agent_guard(sections: dict[str, Section]) -> str:
    parts = [section_heading("Agent Guard results (paired A/B runs)", Section("x", "OK", ""))]
    runs: list[AgentGuardRun] = []
    for name in ("agent_guard_scripted", "agent_guard_model"):
        s = sections.get(name)
        if s and s.ok:
            runs.append(s.data)
        elif s:
            parts.append(na_card(s))
    if not runs:
        return "".join(parts)

    # paired-arm bars: attack_block_rate and false_block_rate per run/arm
    for run in runs:
        chip = label_chip("SIMULATED" if "SIMULATED" in run.label else "OBSERVED")
        src = f'<span class="muted">{esc(run.label)} &middot; {esc(run.source)}</span>'
        parts.append(f"<h3>{chip} {src}</h3>")
        rows = []
        for arm_name, arm in sorted(run.arms.items()):
            for metric_name in ("attack_block_rate", "false_block_rate",
                                "clean_task_completion", "attack_success_rate"):
                m = arm.metrics.get(metric_name)
                if m is not None:
                    rows.append(f"<tr><td>arm {esc(arm_name)}</td><td>{esc(m.name)}</td>"
                                f"<td>{esc(m.rate)}</td><td>{_bar(m.value or 0.0)}</td></tr>")
        if rows:
            parts.append('<table><tr><th>arm</th><th>metric</th><th>n/den</th><th></th></tr>'
                         + "".join(rows) + "</table>")
        cards = []
        for arm_name, arm in sorted(run.arms.items()):
            for m in arm.metrics.values():
                cards.append(metric_card(m, f"arm {arm_name}"))
        if run.model_usage:
            for arm_name, usage in sorted(run.model_usage.items()):
                calls = usage.get("model_http_calls", "?")
                tin = usage.get("tokens_in", "?")
                tout = usage.get("tokens_out", "?")
                cards.append(f'<div class="card"><div class="name">model calls (arm '
                             f'{esc(arm_name)})</div><div class="metric">{esc(calls)}</div>'
                             f'<div class="muted">tokens in/out: {esc(tin)}/{esc(tout)}</div>'
                             f"</div>")
        parts.append('<div class="grid">' + "".join(cards) + "</div>")
    return "".join(parts)


# ------------------------------------------------------------------ (3) EVCS
def render_evcs(section: Section) -> str:
    if not section.ok:
        return section_heading("Containment (EVCS)", section)
    data = section.data
    parts = [section_heading("Containment (EVCS)", section, "SIMULATED")]
    rows = []
    for mit, row in sorted(data.per_mitigation.items()):
        ue = row.get("unauthorized_executed")
        tc = row.get("task_completed")
        ue_txt = esc(ue.rate) if isinstance(ue, Metric) else esc(ue)
        tc_txt = esc(tc.rate) if isinstance(tc, Metric) else esc(tc)
        rows.append(f"<tr><td>{esc(mit)}</td><td>{esc(row.get('kind', ''))}</td>"
                    f"<td>{esc(row.get('branches_run', ''))}</td>"
                    f"<td>{ue_txt}</td><td>{tc_txt}</td></tr>")
    parts.append('<table><tr><th>mitigation</th><th>kind</th><th>branches</th>'
                 "<th>unauthorized executed</th><th>task completed</th></tr>"
                 + "".join(rows) + "</table>")
    parts.append('<div class="grid">'
                 + metric_card(data.trap_rejections, "SIMULATED")
                 + metric_card(data.human_review_cases, "SIMULATED")
                 + "</div>")
    parts.append(f"<h3>EVCS vs baseline (block-all-sensitive)</h3><pre>"
                 f"{esc(json_compact(data.vs_baseline))}</pre>")
    return "".join(parts)


def json_compact(data: object) -> str:
    import json

    return json.dumps(data, indent=1, sort_keys=True, default=str)


# ------------------------------------------------------------------ (4) scan
def render_scan(section: Section) -> str:
    if not section.ok:
        return section_heading("Site Guard scan", section)
    parts = [section_heading("Site Guard scan", section)]
    for row in section.data:
        if isinstance(row, ScanRowNA):
            parts.append(f'<div class="card"><div class="name">{esc(row.lab)}</div>'
                         f'<span class="label lbl-NOTAVAILABLE">NOT AVAILABLE</span>'
                         f'<div class="muted">{esc(row.error)}</div></div>')
            continue
        state = "SIMULATED" if "SIMULATED" in row.model_label else "OBSERVED"
        parts.append(f"<h3>{esc(row.lab)} {label_chip(state)} "
                     f'<span class="muted">{esc(row.model_label)}</span></h3>')
        parts.append('<div class="grid">'
                     + metric_card(Metric("planted_found", len(row.planted_found),
                                          row.planted_total,
                                          len(row.planted_found) / max(row.planted_total, 1)),
                                   state)
                     + metric_card(row.recall, state)
                     + f'<div class="card"><div class="name">clean_copy_false_findings</div>'
                       f'<div class="metric">{esc(row.clean_copy_false_findings)}</div>'
                       f'{label_chip(state)}</div>'
                     + "</div>")
        cov = (f"coverage {row.coverage_percent}% &middot; requests "
               f"{row.requests_used}/{row.request_budget}" if row.coverage_percent is not None
               else "coverage/requests: not in report")
        parts.append(f'<div class="muted">{cov}</div>')
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
        return section_heading("Fix engine", section)
    data = section.data
    total = sum(data.counts.values())
    parts = [section_heading("Fix engine", section)]
    if total == 0:
        return "".join(parts) + '<div class="card"><span class="label lbl-NOTAVAILABLE">' \
            "NOT AVAILABLE</span><div class=\"muted\">no fix results recorded</div></div>"
    cards = []
    for status, count in sorted(data.counts.items()):
        cards.append(metric_card(Metric(f"fix_{status}", count, total, count / total),
                                 "OBSERVED"))
    parts.append('<div class="grid">' + "".join(cards) + "</div>")
    reasons = "".join(
        f"<li>{esc(r['finding_id'])}: {esc(r['status'])} / patch={esc(r['patch_status'])} "
        f"verify={esc(r['verification_status'])} &mdash; {esc(r['reasons'])}</li>"
        for r in data.reasons)
    parts.append(f"<ul>{reasons}</ul>")
    if data.spend:
        parts.append(f'<div class="muted">spend: {esc(data.spend.get("spent_usd"))} USD of '
                     f'hard cap {esc(data.spend.get("hard_cap_usd"))} USD</div>')
    return "".join(parts)


# ------------------------------------------------------------------ (6) shield
def render_shield(section: Section) -> str:
    if not section.ok:
        return section_heading("Live shield (three-way)", section)
    parts = [section_heading("Live shield (three-way)", section, "OBSERVED")]
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
    parts.append('<div class="box">TEMPORARY SHIELD, NOT A FIX: shield rules are narrow, '
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
            parts.append(f'<div class="muted">rules: proposed {esc(r.get("proposed", 0))}, '
                         f'activated {esc(r.get("activated", 0))}, rejected by gate '
                         f'{esc(r.get("rejected_by_gate", 0))}, escalations '
                         f'{esc(r.get("escalations", 0))}</div>')
        b = arm.benign
        if isinstance(b, dict) and b:
            parts.append(f'<div class="muted">benign: sent {esc(b.get("sent", 0))}, falsely '
                         f'blocked/altered {esc(b.get("blocked_or_altered_by_shield", 0))}'
                         f"</div>")
        ttp_rows = ""
        if isinstance(arm.time_to_protect, dict):
            ttp_rows = "".join(
                f"<tr><td>{esc(stage)}</td>"
                f"<td>{esc(v.get('seconds', 'not protected') if isinstance(v, dict) else v)}s</td>"
                f"<td>{esc(v.get('rule', '') if isinstance(v, dict) else '')}</td>"
                f"<td>{esc(v.get('pre_activated', '') if isinstance(v, dict) else '')}</td></tr>"
                for stage, v in sorted(arm.time_to_protect.items()))
        if ttp_rows:
            parts.append("<table><tr><th>stage</th><th>time-to-protect (s)</th><th>rule</th>"
                         "<th>pre-activated</th></tr>" + ttp_rows + "</table>")
        ia_rows = ""
        if isinstance(arm.intent_accuracy, dict):
            ia_rows = "".join(
                f"<tr><td>{esc(stage)}</td><td>{esc(v.get('correct', 0))}/"
                f"{esc(v.get('labelled', 0))}</td><td>{esc(v.get('accuracy', 0))}</td></tr>"
                for stage, v in sorted(arm.intent_accuracy.items()))
        if ia_rows:
            parts.append("<table><tr><th>stage</th><th>intent correct/labelled</th>"
                         "<th>accuracy</th></tr>" + ia_rows + "</table>")
    return "".join(parts)


# ------------------------------------------------------------------ (7) integrity
def render_integrity(report: IntegrityReport) -> str:
    rows = "".join(
        f"<tr><td>{esc(r.session_id)}</td><td>{esc(r.status)}</td><td>{esc(r.detail)}</td>"
        f"<td class='muted'>{esc(r.source)}</td></tr>"
        for r in report.rows)
    table = ("<table><tr><th>session</th><th>status</th><th>detail</th><th>source</th></tr>"
             + rows + "</table>") if rows else "<p class='muted'>no session ids referenced</p>"
    return (
        "<h2>Evidence integrity</h2>"
        f"<p class='muted'>{esc(report.note)} &middot; built "
        f"{esc(report.built_at_utc)} &middot; db: {esc(report.db_path or 'none found')}</p>"
        f"<p>sessions checked: <strong>{len(report.rows)}</strong> &middot; "
        f"OK: <strong>{report.ok_count}</strong> &middot; "
        f"failed/missing: <strong>{len(report.failed)}</strong></p>{table}")


# ------------------------------------------------------------------ (8) limitations
def render_limitations(section: Section) -> str:
    parts = ["<h2>Limitations</h2>"]
    if not section.ok:
        return "".join(parts) + na_card(section)
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
    footer = (f"generated {datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} from stored "
              "report files only; build-time evidence integrity check, not a live check"
              + (f"; sections NOT AVAILABLE: {', '.join(sorted(not_available))}"
                 if not_available else "; all sections available"))
    html_text = Template(_TEMPLATE.read_text(encoding="utf-8")).substitute(
        title="Sentinel X results", body="".join(body), footer=esc(footer))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_text, encoding="utf-8")
    return BuildResult(out_path, out_path.stat().st_size, not_available)
