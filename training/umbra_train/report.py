"""Static HTML dashboard: run coverage, outcomes, feasibility results."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path

from . import tracker
from .config import REPORTS_DIR
from .scenarios import load_all

CSS = """
:root{--bg:#fafaf8;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;--card:#fff;--good:#1f7a4d;
--warn:#a35b00;--bad:#b3261e;--accent:#3346b8;--bar:#c9cff2}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--fg:#ecebe6;--muted:#9a9993;--line:#2c2c29;
--card:#1c1c1a;--good:#5cc28f;--warn:#e0a24f;--bad:#f07c72;--accent:#8f9cf5;--bar:#33396b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 16px 64px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 10px}
.sub{color:var(--muted);margin:0 0 20px}.card{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:14px 16px;margin:10px 0;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--muted);font-weight:500;font-size:12px}
.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.muted{color:var(--muted)}
.bar{display:inline-block;height:8px;background:var(--accent);border-radius:4px;vertical-align:middle}
.track{display:inline-block;width:160px;height:8px;background:var(--bar);border-radius:4px;
position:relative;vertical-align:middle;margin-right:8px}
.track .bar{position:absolute;left:0;top:0}.track .chance{position:absolute;top:-3px;width:2px;height:14px;
background:var(--fg);opacity:.5}
.kpis{display:flex;gap:10px;flex-wrap:wrap}.kpi{flex:1 1 150px}.kpi b{display:block;font-size:22px}
svg text{fill:var(--muted);font-size:10px}
"""


def _esc(x) -> str:
    return html.escape(str(x))


def _coverage() -> str:
    actors, scen, cells = tracker.matrix()
    if not actors:
        return "<p class=muted>No runs yet. Start with <code>umbra-train run --actor script --scenario all</code>.</p>"
    head = "".join(f"<th>{_esc(a)}</th>" for a in actors)
    rows = []
    labels = {s.id: s.label for s in load_all().values()}
    for s in scen:
        tds = []
        for a in actors:
            c = cells.get((a, s))
            if not c:
                tds.append("<td class=muted>·</td>")
                continue
            cls = "good" if c["completed"] == c["n"] else ("warn" if c["completed"] else "bad")
            ref = f" · {c['refused']} refused" if c["refused"] else ""
            tds.append(f"<td><span class={cls}>{c['completed']}/{c['n']} done</span>"
                       f"<span class=muted> · {c['captured']} captured{ref}</span></td>")
        lab = labels.get(s, "?")
        tag = "good" if lab == "approved" else "bad"
        rows.append(f"<tr><td>{_esc(s)} <span class={tag}>{lab}</span></td>{''.join(tds)}</tr>")
    return f"<table><tr><th>scenario</th>{head}</tr>{''.join(rows)}</table>"


def _runs_table() -> str:
    runs = tracker.all_runs()[-60:][::-1]
    if not runs:
        return ""
    out = ["<table><tr><th>run</th><th>actor</th><th>scenario</th><th>status</th><th>outcome</th>"
           "<th>checks</th><th>dur s</th><th>fs events</th><th>packets</th></tr>"]
    for r in runs:
        oc = {"completed": "good", "refused": "warn"}.get(r["outcome"], "bad")
        st = "good" if r["status"] == "ok" else "bad"
        out.append(f"<tr><td>{_esc(r['run_id'])}</td><td>{_esc(r['actor'])}</td><td>{_esc(r['scenario'])}</td>"
                   f"<td class={st}>{_esc(r['status'])}{'' if r['captured'] else ' (no capture)'}</td>"
                   f"<td class={oc}>{_esc(r['outcome'])}</td><td>{r['checks_passed']}/{r['checks_total']}</td>"
                   f"<td>{r['duration_s'] or ''}</td><td>{r['fs_events'] or 0}</td><td>{r['net_packets'] or 0}</td></tr>")
    out.append("</table>")
    return "".join(out)


def _experiments(res: dict) -> str:
    if not res.get("experiments"):
        return "<p class=muted>No captured runs yet, so nothing to train on. Run <code>umbra-train train</code> after capturing.</p>"
    parts = []
    for exp in res["experiments"]:
        rows = []
        for v in exp["variants"]:
            if "skipped" in v:
                rows.append(f"<tr><td>{_esc(v['features'])}</td><td colspan=4 class=muted>skipped: {_esc(v['skipped'])}</td></tr>")
                continue
            ba, ch = v["balanced_accuracy"], v["chance"]
            cls = "good" if ba >= max(0.8, ch + 0.3) else ("warn" if ba > ch + 0.1 else "bad")
            feats = ", ".join(f"{c} ({w})" for c, w in v["top_features"][:4])
            rows.append(
                f"<tr><td>{_esc(v['features'])}</td><td><span class=track><span class=bar style='width:{ba*100:.0f}%'></span>"
                f"<span class=chance style='left:{ch*100:.0f}%'></span></span><b class={cls}>{ba:.2f}</b></td>"
                f"<td class=muted>{ch:.2f}</td><td>{v['n']} runs / {v['n_scenarios']} scenarios</td>"
                f"<td class=muted style='white-space:normal'>{_esc(feats)}</td></tr>")
        rb = exp.get("rule_baseline")
        rb_html = (f"<p class=muted>Rule baseline ({_esc(rb['rule'])}): accuracy {rb['accuracy']:.2f}</p>" if rb else "")
        parts.append(
            f"<div class=card><b>{_esc(exp['question'])}</b>"
            f"<table><tr><th>features</th><th>balanced accuracy (held-out scenarios)</th><th>chance</th><th>data</th>"
            f"<th>top features</th></tr>{''.join(rows)}</table>{rb_html}</div>")
    return "".join(parts)


def _timelines(res: dict) -> str:
    tl = res.get("timelines") or {}
    if not tl:
        return "<p class=muted>Appears once there are captured agent and non-agent runs.</p>"
    cards = []
    for run_id, t in list(tl.items())[-24:]:
        pts = t["points"]
        if not pts:
            continue
        xmax = max(p[0] for p in pts) or 1
        w, h = 260, 60
        path = " ".join(f"{'M' if i == 0 else 'L'}{6 + (x / xmax) * (w - 12):.1f},{h - 8 - y * (h - 16):.1f}"
                        for i, (x, y) in enumerate(pts))
        color = "var(--bad)" if t["actor"] in ("claude_code", "codex") else "var(--good)"
        cards.append(
            f"<div class='card kpi'><div><b style='font-size:13px;display:inline'>{_esc(t['actor'])}</b> "
            f"<span class=muted>{_esc(t['scenario'])}</span></div>"
            f"<svg viewBox='0 0 {w} {h}' width='100%' role=img aria-label='P(agent) over time'>"
            f"<line x1=6 x2={w-6} y1={h/2} y2={h/2} stroke='var(--line)' stroke-dasharray='3 3'/>"
            f"<path d='{path}' fill=none stroke='{color}' stroke-width=2/>"
            f"<text x=6 y=10>P(agent)=1</text><text x=6 y={h-1}>0</text><text x={w-40} y={h-1}>{xmax:.0f}s</text></svg></div>")
    return f"<div class=kpis>{''.join(cards)}</div>"


def write_report(results: dict | None = None) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if results is None and (REPORTS_DIR / "feasibility.json").exists():
        results = json.loads((REPORTS_DIR / "feasibility.json").read_text())
    results = results or {}
    runs = tracker.all_runs()
    n_cap = sum(1 for r in runs if r["captured"] and r["status"] == "ok")
    n_done = sum(1 for r in runs if r["outcome"] == "completed")
    n_ref = sum(1 for r in runs if r["outcome"] == "refused")
    wm = results.get("window_model") or {}
    wm_txt = f"{wm['balanced_accuracy']:.2f}" if "balanced_accuracy" in wm else "–"
    body = f"""
<main>
<h1>Umbra training lab</h1>
<p class=sub>Can network and filesystem events alone tell Claude Code, Codex and a human apart, and
approved actions from unapproved ones? Generated {time.strftime('%Y-%m-%d %H:%M')}.</p>
<div class=kpis>
 <div class='card kpi'><span class=muted>runs</span><b>{len(runs)}</b></div>
 <div class='card kpi'><span class=muted>captured</span><b>{n_cap}</b></div>
 <div class='card kpi'><span class=muted>task completed</span><b>{n_done}</b></div>
 <div class='card kpi'><span class=muted>agent refused</span><b>{n_ref}</b></div>
 <div class='card kpi'><span class=muted>live agent score, balanced acc.</span><b>{wm_txt}</b></div>
</div>
<h2>Feasibility results</h2>
<p class=muted>Every number is measured on scenarios the model never saw in training (grouped by scenario).
The tick on each bar marks chance. "No markers" drops LLM domains, agent env vars, harness folders and
sandbox-exec, so only behavior is left.</p>
{_experiments(results)}
<h2>Live agent score per run</h2>
<p class=muted>Out-of-fold P(agent) on 30-second windows, using behavior only. Agents should climb, humans and scripts should stay low.</p>
{_timelines(results)}
<h2>Coverage: scenario × actor</h2>
<div class=card>{_coverage()}</div>
<h2>Recent runs</h2>
<div class=card>{_runs_table()}</div>
</main>"""
    page = (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
            f"content='width=device-width,initial-scale=1'><title>Umbra training lab</title>"
            f"<style>{CSS}</style></head><body>{body}</body></html>")
    out = REPORTS_DIR / "index.html"
    out.write_text(page)
    return out
