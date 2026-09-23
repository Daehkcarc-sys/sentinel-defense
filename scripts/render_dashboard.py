#!/usr/bin/env python3
# ruff: noqa: E501
"""Render a single, self-contained, interactive HTML dashboard covering MULTIPLE SENTINEL runs,
grouped into categories a jury can switch between without leaving the page.

Reuses render_report.py's parsing and per-run rendering (`build_run`, `CSS`, `JS`,
`mechanism_glossary_html`) so the single-run report and the dashboard never drift apart -- one
implementation of "what a run looks like," two ways to present it.

Usage:
    python scripts/render_dashboard.py MANIFEST.json -o dashboard.html

MANIFEST.json is a list of entries, each either a run:
    {"category": "Object-identity attacks", "label": "SOC: wrong-alert redirect",
     "jsonl": "artifacts/.../run.jsonl", "yaml": "scenarios/self_authored/soc_....yaml"}
("yaml" is optional, same as render_report.py's own CLI.) Categories are shown in the order their
first entry appears; entries within a category keep manifest order. The first entry becomes the
initially-shown scenario.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from render_report import (
    CSS,
    JS,
    build_run,
    esc,
    find_summary,
    load_jsonl,
    load_scenario,
    mechanism_glossary_html,
)

_load_scenario_yaml = load_scenario

DASHBOARD_CSS = """
body.dashboard { display: flex; min-height: 100vh; margin: 0; }
.dash-nav { width: 300px; flex: 0 0 300px; background: var(--panel); border-right: 1px solid var(--border);
  padding: 1rem; overflow-y: auto; position: sticky; top: 0; height: 100vh; }
.dash-nav h1 { font-size: 1.05rem; margin: 0 0 .2rem; }
.dash-nav .sub { color: var(--muted); font-size: .78rem; margin-bottom: 1rem; }
.dash-cat { margin-bottom: 1.1rem; }
.dash-cat-name { font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted);
  margin: 0 0 .4rem; padding-left: .3rem; }
.dash-item { display: flex; align-items: center; gap: .5rem; width: 100%; text-align: left; background: none;
  border: none; border-radius: 8px; padding: .5rem .6rem; margin-bottom: .15rem; cursor: pointer;
  color: var(--text); font-size: .85rem; font-family: inherit; }
.dash-item:hover { background: var(--bg); }
.dash-item.active { background: var(--accent); color: white; }
.dash-item .dot { width: 9px; height: 9px; border-radius: 50%; flex: 0 0 9px; }
.dash-item .dot.allow { background: var(--allow); }
.dash-item .dot.block { background: var(--block); }
.dash-item .dot.neutral { background: var(--muted); }
.dash-item .dot.bad { background: var(--block); }
.dash-main { flex: 1 1 auto; min-width: 0; }
.dash-topbar { background: var(--panel); border-bottom: 1px solid var(--border); padding: 1rem 1.5rem;
  position: sticky; top: 0; z-index: 5; }
.dash-topbar h2 { margin: 0 0 .2rem; font-size: 1.25rem; }
.dash-run-panel { display: none; padding: 1rem 1.5rem 3rem; }
.dash-run-panel.active { display: block; }
.dash-theme-toggle { float: right; }
@media (max-width: 900px) {
  body.dashboard { flex-direction: column; }
  .dash-nav { width: auto; flex: none; height: auto; position: relative; border-right: none; border-bottom: 1px solid var(--border); }
}
"""

DASHBOARD_JS = """
function showRun(id) {
  document.querySelectorAll('.dash-run-panel').forEach(function (el) { el.classList.remove('active'); });
  document.querySelectorAll('.dash-item').forEach(function (el) { el.classList.remove('active'); });
  var panel = document.getElementById('run-' + id);
  var item = document.getElementById('nav-' + id);
  if (panel) panel.classList.add('active');
  if (item) item.classList.add('active');
  if (panel) {
    var h = panel.querySelector('.dash-run-title');
    document.getElementById('dash-current-title').textContent = h ? h.textContent : '';
  }
  try { localStorage.setItem('sentinel-dashboard-run', id); } catch (e) {}
  window.scrollTo(0, 0);
}
"""


def status_dot(run: dict[str, Any]) -> str:
    if run.get("critical_violation"):
        return "bad"
    if run.get("attack_present") and run.get("attack_success") is True:
        return "bad"
    if run.get("attack_present") and run.get("attack_success") is False:
        return "allow" if run.get("task_success") is True else "neutral"
    if run.get("task_success") is True:
        return "allow"
    return "neutral"


def status_label(run: dict[str, Any]) -> str:
    bits = []
    if run.get("attack_present"):
        attack_success = run.get("attack_success")
        if attack_success is False:
            bits.append("attack did not succeed")
        elif attack_success is True:
            bits.append("attack succeeded")
        else:
            bits.append("attack scenario")
    else:
        bits.append("benign")
    if run.get("task_success") is False:
        bits.append("task failed")
    return " · ".join(bits)


def build_dashboard(manifest: list[dict[str, Any]]) -> str:
    categories: dict[str, list[dict[str, Any]]] = {}
    for run_id_counter, entry in enumerate(manifest, start=1):
        events = load_jsonl(Path(entry["jsonl"]))
        summary = find_summary(Path(entry["jsonl"]))
        scenario = _load_scenario_yaml(Path(entry["yaml"])) if entry.get("yaml") else None
        run = build_run(events, summary, scenario)
        run["dash_id"] = f"r{run_id_counter}"
        run["label"] = entry.get("label") or run["title"]
        cat = entry.get("category") or "Scenarios"
        categories.setdefault(cat, []).append(run)

    nav_html = []
    panels_html = []
    first_id = None
    for cat, runs in categories.items():
        items = []
        for run in runs:
            if first_id is None:
                first_id = run["dash_id"]
            items.append(
                f'<button class="dash-item" id="nav-{run["dash_id"]}" onclick="showRun(\'{run["dash_id"]}\')">'
                f'<span class="dot {status_dot(run)}"></span>'
                f'<span>{esc(run["label"])}</span></button>'
            )
        nav_html.append(
            f'<div class="dash-cat"><div class="dash-cat-name">{esc(cat)}</div>{"".join(items)}</div>'
        )
        for run in runs:
            panels_html.append(
                f'<div class="dash-run-panel" id="run-{run["dash_id"]}">'
                f'<div class="dash-run-title" style="display:none">{esc(run["title"])}</div>'
                f'<div class="meta-line">scenario <code>{esc(run["scenario_id"])}</code> &middot; '
                f'domain <code>{esc(run["domain"])}</code> &middot; defense <code>{esc(run["defense_name"])}</code> '
                f'&middot; {esc(status_label(run))}</div>'
                f'{run["content_html"]}</div>'
            )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL Hybrid &middot; observability dashboard</title>
<style>{CSS}{DASHBOARD_CSS}</style>
</head>
<body class="dashboard">
<nav class="dash-nav">
  <button class="theme-toggle dash-theme-toggle" onclick="toggleTheme()">&#9788;</button>
  <h1>SENTINEL Hybrid</h1>
  <div class="sub"><code>sentinel_hybrid</code> &middot; Authority Core + typed provenance + safe repair</div>
  {mechanism_glossary_html()}
  {"".join(nav_html)}
</nav>
<main class="dash-main">
  <div class="dash-topbar"><h2 id="dash-current-title">&nbsp;</h2></div>
  {"".join(panels_html)}
</main>
<script>{JS}{DASHBOARD_JS}
(function () {{
  var saved = null;
  try {{ saved = localStorage.getItem('sentinel-dashboard-run'); }} catch (e) {{}}
  showRun((saved && document.getElementById('run-' + saved)) ? saved : '{first_id}');
}})();
</script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("-o", "--out", type=Path, default=None)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    html_out = build_dashboard(manifest)
    out = args.out or args.manifest.with_suffix(".dashboard.html")
    out.write_text(html_out, encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
