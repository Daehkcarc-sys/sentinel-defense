#!/usr/bin/env python3
# ruff: noqa: E501
"""Render a single-file HTML timeline report from a SENTINEL run artifact.

The stock ``sentinel replay`` CLI prints a plain terminal timeline. This script builds a richer,
jury-facing HTML report from the same JSONL event artifact (see ``src/sentinel/evaluator/replay.py``
and ``src/sentinel/core/events.py`` for the event schema this is built on), optionally enriched with:

  * the run's sibling ``<run_id>.summary.json`` (written by ``sentinel run`` / ``sentinel eval``
    next to the JSONL artifact) for evaluator-only ground truth: which actions were legitimate,
    grader results, attack-surface mutations, and the final outcome; and
  * the scenario's own YAML file, for the attack objective/surfaces/payload text and the
    human-readable task goal.

Usage:
    python scripts/render_report.py <run.jsonl> [<scenario.yaml>] [-o report.html]

Only the standard library and PyYAML (already a project dependency, used only if a scenario YAML
is given) are used. The output is a single self-contained HTML file: inline CSS, inline vanilla JS,
no external network calls, no build step.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------------------------


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    events = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    events.sort(key=lambda e: e.get("seq", 0))
    return events


def find_summary(artifact: Path) -> dict[str, Any] | None:
    """The run summary is written next to the artifact as ``<run_id>.summary.json``."""
    candidate = artifact.with_name(artifact.name.replace(".jsonl", ".summary.json"))
    if candidate.exists():
        try:
            return json.loads(candidate.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def load_scenario(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        import yaml
    except ImportError:
        print(f"warning: PyYAML not installed; rendering without scenario context ({path})", file=sys.stderr)
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, Exception) as exc:  # yaml errors subclass Exception broadly
        print(f"warning: could not read scenario {path}: {exc}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------------------------

DECISION_META = {
    "allow": {"label": "ALLOW", "icon": "✓", "css": "allow"},
    "block": {"label": "BLOCK", "icon": "✕", "css": "block"},
    "escalate": {"label": "ESCALATE", "icon": "⚠", "css": "escalate"},
    "rewrite": {"label": "REWRITE", "icon": "↺", "css": "rewrite"},
}

# Plain-language explanation of every reason code the defense can emit, and which mechanism
# produced it. Shown as a tooltip on each reason-code badge and in the "How this defense works"
# panel, so a viewer with zero prior context can see not just WHAT was decided but WHY, in terms
# of a specific, named piece of the architecture -- not a black box.
REASON_CODE_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "STRUCTURALLY_AUTHORIZED": (
        "Default (no mechanism intervened)",
        "No check found a reason to act: the tool was allowed, no confirmation was missing, and "
        "no untrusted, restricted, or inconsistent content was touched.",
    ),
    "TOOL_NOT_ALLOWED": (
        "Component A -- hard policy core",
        "This tool is outside the task's declared allowed-tools set. Authority comes only from "
        "that structural fact, never from how convincing the request sounds.",
    ),
    "SENSITIVE_TO_UNTRUSTED_SINK": (
        "Component A -- hard policy core",
        "Sensitive content is addressed to an external, untrusted recipient. Checked by comparing "
        "provenance sensitivity tags against the destination, not by reading intent.",
    ),
    "MISSING_CONFIRMATION": (
        "Component A -- hard policy core",
        "A consequential action (one with real-world effect) was proposed with no prior human "
        "confirmation on record for this exact action.",
    ),
    "CONFIRMATION_REQUESTED": (
        "Component A -- hard policy core",
        "The agent is explicitly asking a human to confirm a consequential action before it runs.",
    ),
    "RESTRICTED_DATA_DISCLOSURE": (
        "Destination-independent RESTRICTED-sensitivity check",
        "This value's source is tagged RESTRICTED sensitivity, which this benchmark declares as "
        "never safely disclosable to ANY destination -- not the user's own reply, not an internal "
        "record. Blocks regardless of which tool or action carries it.",
    ),
    "AUTHORIZATION_ALREADY_CONSUMED": (
        "Mechanism A -- authorization binding",
        "This exact action (same tool, same arguments) already executed once earlier this run. A "
        "repeat isn't re-authorized just because it's proposed again -- BLOCKs rather than asking "
        "again, since a repeat request can't be trusted to get a meaningfully different review.",
    ),
    "EPISTEMIC_UNVERIFIED_FACT": (
        "Component C -- evidence fidelity",
        "This value has no source anywhere in this turn's conversation except untrusted content. "
        "It's mentioned, not yet acted on operationally, so this only escalates for review.",
    ),
    "DECISION_RELEVANT_UNVERIFIED_FACT": (
        "Mechanism C -- decision-relevance tiering",
        "Same untrusted-only value as above, but here it operationally parameterizes a "
        "consequential action's own arguments, not just a passing mention -- treated as more "
        "serious.",
    ),
    "OBJECT_NOT_DECLARED_IN_REQUEST": (
        "Mechanism E -- goal-declared object consistency",
        "This action targets an object (an id like AL-3003, CASE-7002, ...) that the authenticated "
        "user's own request never named, and nothing trusted in this turn corroborates it. Derived "
        "per-request from the user's own words, never from a standing global rule.",
    ),
    "PREREQUISITE_NOT_MET_FOR_OBJECT": (
        "Component B -- object-scoped state (historical; disabled by default)",
        "A required prior step for this specific object never succeeded. This component was built, "
        "tested, and killed after it regressed a real benign scenario -- kept in code only as an "
        "honest record of what was tried.",
    ),
    "ACTION_ALREADY_EXECUTED_FOR_OBJECT": (
        "Component B -- object-scoped state (historical; disabled by default)",
        "This tool already succeeded once for this object. See the note above -- disabled by "
        "default.",
    ),
    "REWRITE_FAILED_SELF_VALIDATION": (
        "Rewrite self-validation",
        "A safer rewrite was proposed, but re-running the full decision pipeline on the rewrite "
        "itself did not independently clear it -- falls back to a safer decision rather than "
        "handing the harness an unvalidated rewrite.",
    ),
    "REWRITE_DEPTH_EXCEEDED": (
        "Rewrite self-validation",
        "A rewrite of a rewrite was about to be produced -- capped at one level, so this falls "
        "back rather than chaining indefinitely.",
    ),
    "HYBRID_UNTRUSTED_CONTROL_SELECTOR": (
        "Selective Hybrid policy -- control integrity",
        "An operational selector is supported only by untrusted evidence. Authority Core allowed "
        "the structurally valid call, but the Hybrid control layer blocks the attacker-only "
        "parameter rather than letting observed text establish operational control.",
    ),
    "HYBRID_UNTRUSTED_OPERATIONAL_EXPANSION": (
        "Selective Hybrid policy -- task-local object control",
        "Untrusted content introduced a new operational object and the task-local workflow also "
        "classified the write as an object expansion requiring review. The conjunction, not either "
        "signal alone, triggers the block.",
    ),
    "HYBRID_ATTACKER_SELECTED_SENSITIVE_SINK": (
        "Selective Hybrid policy -- provenance/data-flow conjunction",
        "Sensitive lineage is being sent to a destination selected only by untrusted content. The "
        "Hybrid policy blocks that attacker-selected sink.",
    ),
    "HYBRID_RESTRICTED_FLOW_REDACTED": (
        "Safe repair -- restricted-response recovery",
        "Authority Core rejected a final response containing RESTRICTED lineage. Hybrid removed "
        "only the recognized restricted representation and returned the rewrite only after the "
        "rewritten response independently passed the full Core + Hybrid policy again.",
    ),
    "HYBRID_GROUNDED_CONTROL_REPAIR": (
        "Safe repair -- grounded closed-vocabulary control",
        "An attacker-only control selector was replaced with the unique different legal value "
        "independently grounded in trusted/runtime evidence. The repaired call then passed full "
        "Core + Hybrid validation before execution.",
    ),
    "HYBRID_REWRITE_FAILED_VALIDATION": (
        "Hybrid rewrite self-validation",
        "Authority Core proposed a rewrite, but the rewritten action still violated a validated "
        "Hybrid invariant. The defense therefore refused to release the rewrite.",
    ),
    "HYBRID_CONTROL_REPAIR_FAILED_VALIDATION": (
        "Grounded control repair self-validation",
        "A candidate grounded control repair was found, but the rewritten request did not clear "
        "full validation. The defense falls back to blocking instead of guessing.",
    ),
}

MECHANISM_OVERVIEW: list[tuple[str, str]] = [
    (
        "Production path",
        "SENTINEL Hybrid is one deterministic path: canonical provenance and task-control facts "
        "feed Authority Core, then only narrow validated Hybrid conjunctions may block or safely "
        "repair. There is no weighted voting layer and no LLM judge in the security path.",
    ),
    (
        "Canonical provenance",
        "Core and Hybrid consume one field-addressable source index. Trust, sensitivity, source "
        "type, and concrete provenance ids are resolved once so the two layers cannot silently "
        "disagree about where a value came from.",
    ),
    (
        "Authority Core",
        "The hard-policy kernel owns structural tool authorization, confirmation requirements, "
        "restricted disclosure, authorization binding, field-aware evidence fidelity, and "
        "goal/object consistency.",
    ),
    (
        "Task / control facts",
        "Authenticated intent and successful history define a task-local control context. Tool "
        "content may contribute information, but untrusted text cannot independently establish "
        "operational control parameters.",
    ),
    (
        "Sensitive lineage",
        "The provenance/data-flow plane tracks request-visible CONFIDENTIAL or RESTRICTED values "
        "into candidate sinks, including the narrow encoded representations validated in the "
        "benchmark.",
    ),
    (
        "Selective Hybrid policy",
        "Only high-confidence conjunctions survived falsification: attacker-only control selectors, "
        "task-local untrusted object expansion, and attacker-selected sensitive sinks. Generic "
        "untrusted text or echo does not become an automatic block.",
    ),
    (
        "Restricted-response recovery",
        "If Core blocks a final answer for exact RESTRICTED disclosure, Hybrid can redact only the "
        "recognized restricted representation and return REWRITE only after the rewritten response "
        "passes the full policy again.",
    ),
    (
        "Grounded control repair",
        "For one attacker-only closed-vocabulary selector, Hybrid repairs only when exactly one "
        "different legal value is independently supported by trusted/runtime evidence. No unique "
        "alternative means no guess.",
    ),
    (
        "Full self-validation",
        "Every released repair is re-run through Authority Core and the selective Hybrid policy. "
        "A repair that cannot independently clear both layers is rejected.",
    ),
]


def mechanism_glossary_html() -> str:
    rows = "".join(
        f'<div class="glossary-row"><div class="glossary-name">{esc(name)}</div>'
        f'<div class="glossary-desc">{esc(desc)}</div></div>'
        for name, desc in MECHANISM_OVERVIEW
    )
    return (
        '<details class="card glossary"><summary><h2 style="display:inline">'
        "How this defense works</h2> <span class=\"glossary-hint\">(click to expand -- "
        "what each mechanism below does, in plain language)</span></summary>"
        f'<div class="glossary-body">{rows}</div></details>'
    )


def reason_code_badge(code: str) -> str:
    mechanism, why = REASON_CODE_EXPLANATIONS.get(code, ("Unrecognized code", "No explanation available."))
    tip = f"{mechanism} — {why}"
    return f'<span class="rc-tip" data-tip="{esc(tip)}">{esc(code)}</span>'


HYBRID_DECISION_PATHS: dict[str, tuple[str, str, str]] = {
    "HYBRID_RESTRICTED_FLOW_REDACTED": (
        "BLOCK · restricted disclosure",
        "deterministic redaction + full re-validation",
        "REWRITE",
    ),
    "HYBRID_GROUNDED_CONTROL_REPAIR": (
        "ALLOW",
        "Replace attacker-only selector with the unique independently grounded legal alternative",
        "REWRITE",
    ),
    "HYBRID_UNTRUSTED_CONTROL_SELECTOR": (
        "ALLOW",
        "Block attacker-only operational selector",
        "BLOCK",
    ),
    "HYBRID_UNTRUSTED_OPERATIONAL_EXPANSION": (
        "ALLOW",
        "Block validated task-local untrusted object expansion",
        "BLOCK",
    ),
    "HYBRID_ATTACKER_SELECTED_SENSITIVE_SINK": (
        "ALLOW",
        "Block attacker-selected sensitive sink",
        "BLOCK",
    ),
    "HYBRID_REWRITE_FAILED_VALIDATION": (
        "REWRITE",
        "Reject Core rewrite that fails Hybrid validation",
        "BLOCK",
    ),
    "HYBRID_CONTROL_REPAIR_FAILED_VALIDATION": (
        "ALLOW",
        "Candidate grounded repair failed full validation",
        "BLOCK",
    ),
}


def decision_path_html(reason_codes: list[str], final_decision: str | None) -> str:
    """Render explicit Core -> Hybrid -> final control flow."""

    hybrid_code = next(
        (code for code in reason_codes if code in HYBRID_DECISION_PATHS),
        None,
    )
    final = (final_decision or "unknown").upper()

    if hybrid_code is None:
        core = final
        hybrid = "No Hybrid intervention"
    else:
        core, hybrid, mapped_final = HYBRID_DECISION_PATHS[hybrid_code]
        final = mapped_final

    return (
        '<div class="decision-path">'
        '<div class="path-caption">Decision path '
        '<span>(explicit reason codes + deterministic policy branch)</span></div>'
        '<div class="path-flow">'
        '<div class="path-node"><div class="path-kicker">Authority Core</div>'
        f'<div class="path-value">{esc(core)}</div></div>'
        '<div class="path-arrow">&#8594;</div>'
        '<div class="path-node"><div class="path-kicker">Hybrid intervention</div>'
        f'<div class="path-value">{esc(hybrid)}</div></div>'
        '<div class="path-arrow">&#8594;</div>'
        '<div class="path-node"><div class="path-kicker">Final decision</div>'
        f'<div class="path-value">{esc(final)}</div></div>'
        '</div></div>'
    )


def esc(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def pretty(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, str):
        return value
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)


def action_summary(action: dict[str, Any] | None) -> str:
    """One-line human summary of a CandidateAction dict."""
    if not action:
        return ""
    kind = action.get("type")
    if kind == "tool_call":
        tool = action.get("tool") or "?"
        args = action.get("arguments") or {}
        arg_str = ", ".join(f"{k}={_short(v)}" for k, v in args.items())
        return f"{tool}({arg_str})"
    if kind == "respond":
        final = " [final]" if action.get("final") else ""
        return f"respond{final}: {_short(action.get('content'), 200)}"
    if kind == "memory_write":
        return f"memory_write: {_short(action.get('content'), 200)}"
    if kind == "request_confirmation":
        target = action.get("confirmation_for") or {}
        return f"request_confirmation for {target.get('tool') or target.get('type')}"
    return kind or ""


def _short(value: Any, limit: int = 120) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


REDACTION_MARKER = "[REDACTED RESTRICTED VALUE]"
DISPLAY_MASK = "[MASKED RESTRICTED VALUE]"


def discover_restricted_display_values(events: list[dict[str, Any]]) -> list[str]:
    """Recover values explicitly removed by restricted-response recovery."""
    values: list[str] = []
    for event in events:
        if event.get("type") != "defense_decision":
            continue
        payload = event.get("payload") or {}
        if "HYBRID_RESTRICTED_FLOW_REDACTED" not in (payload.get("reason_codes") or []):
            continue
        original = ((payload.get("action") or {}).get("content"))
        rewritten = ((payload.get("rewritten_action") or {}).get("content"))
        if not isinstance(original, str) or not isinstance(rewritten, str):
            continue
        if REDACTION_MARKER not in rewritten:
            continue
        prefix, suffix = rewritten.split(REDACTION_MARKER, 1)
        if not original.startswith(prefix) or not original.endswith(suffix):
            continue
        end = len(original) - len(suffix) if suffix else len(original)
        value = original[len(prefix):end]
        if value and value not in values:
            values.append(value)
    return values


def mask_restricted_for_display(text: str, values: list[str]) -> str:
    """Mask restricted values in generated HTML; raw JSONL stays unchanged."""
    masked = text
    for value in sorted(values, key=len, reverse=True):
        masked = masked.replace(value, DISPLAY_MASK)
    return masked


def discover_control_repairs(events: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    """Return (argument, original, repaired) for grounded control rewrites."""
    repairs: list[tuple[str, str, str]] = []
    for event in events:
        if event.get("type") != "defense_decision":
            continue
        payload = event.get("payload") or {}
        if "HYBRID_GROUNDED_CONTROL_REPAIR" not in (payload.get("reason_codes") or []):
            continue
        before = ((payload.get("action") or {}).get("arguments") or {})
        after = ((payload.get("rewritten_action") or {}).get("arguments") or {})
        for argument, original in before.items():
            repaired = after.get(argument)
            if isinstance(original, str) and isinstance(repaired, str) and original != repaired:
                repairs.append((argument, original, repaired))
    return repairs


def stale_repair_narration(
    content: str,
    repairs: list[tuple[str, str, str]],
) -> tuple[str, str, str] | None:
    """Detect final narration that repeats a pre-repair selector."""
    lowered = content.lower()
    for argument, original, repaired in repairs:
        original_forms = {original.lower(), original.replace("_", " ").lower()}
        repaired_forms = {repaired.lower(), repaired.replace("_", " ").lower()}
        if any(form in lowered for form in original_forms) and not any(
            form in lowered for form in repaired_forms
        ):
            return argument, original, repaired
    return None


def evaluator_action_verdict(decision: str | None) -> str:
    """Post-run label for a proposal the evaluator marks illegitimate."""
    if decision in ("block", "escalate"):
        return "blocked"
    if decision == "rewrite":
        return "neutralized by rewrite"
    return "allowed"


def iter_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_strings(v)


def highlight_payload(text: str, needles: list[str]) -> str:
    """Escape text for HTML, wrapping any attack-payload substring in <mark>."""
    escaped_needle_spans: list[tuple[int, int]] = []
    for needle in needles:
        if not needle:
            continue
        start = text.find(needle)
        while start != -1:
            escaped_needle_spans.append((start, start + len(needle)))
            start = text.find(needle, start + 1)
    if not escaped_needle_spans:
        return esc(text)
    escaped_needle_spans.sort()
    merged: list[list[int]] = []
    for s, e in escaped_needle_spans:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out = []
    cursor = 0
    for s, e in merged:
        out.append(esc(text[cursor:s]))
        out.append(f'<mark class="attack-mark">{esc(text[s:e])}</mark>')
        cursor = e
    out.append(esc(text[cursor:]))
    return "".join(out)


def build_attack_context(scenario: dict[str, Any] | None) -> dict[str, Any]:
    if not scenario:
        return {}
    attack = scenario.get("attack") or {}
    if not attack.get("present"):
        return {"present": False}
    payload_texts = [p.get("text", "") for p in attack.get("payloads", [])]
    surface_ids = {s.get("id"): s for s in attack.get("surfaces", [])}
    return {
        "present": True,
        "family": attack.get("family"),
        "difficulty": attack.get("difficulty"),
        "objective": attack.get("objective"),
        "surfaces": attack.get("surfaces", []),
        "payloads": attack.get("payloads", []),
        "payload_texts": [t for t in payload_texts if t],
        "surface_ids": surface_ids,
    }


# ---------------------------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------------------------

CSS = """
:root {
  --bg: #f6f7fb; --panel: #ffffff; --text: #1a1d29; --muted: #5b6270; --border: #e2e5ec;
  --allow: #1e8e5a; --allow-bg: #e8f7ef;
  --block: #c8352e; --block-bg: #fdeceb;
  --escalate: #b8720a; --escalate-bg: #fff4e0;
  --rewrite: #5b3fd6; --rewrite-bg: #efeaff;
  --attack: #c8352e; --attack-bg: #fff0ee;
  --mark-bg: #ffd54a; --mark-fg: #241a00;
  --accent: #2d5bff;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #14161f; --panel: #1c1f2b; --text: #e9ebf3; --muted: #9aa1b3; --border: #2c3040;
    --allow: #3fd189; --allow-bg: #10321f;
    --block: #ff6b64; --block-bg: #3a1613;
    --escalate: #ffb347; --escalate-bg: #3a2a08;
    --rewrite: #b3a1ff; --rewrite-bg: #241c47;
    --attack: #ff6b64; --attack-bg: #33110f;
    --mark-bg: #7a5d00; --mark-fg: #ffe9a8;
    --accent: #6f8bff;
  }
}
:root[data-theme="dark"] {
  --bg: #14161f; --panel: #1c1f2b; --text: #e9ebf3; --muted: #9aa1b3; --border: #2c3040;
  --allow: #3fd189; --allow-bg: #10321f;
  --block: #ff6b64; --block-bg: #3a1613;
  --escalate: #ffb347; --escalate-bg: #3a2a08;
  --rewrite: #b3a1ff; --rewrite-bg: #241c47;
  --attack: #ff6b64; --attack-bg: #33110f;
  --mark-bg: #7a5d00; --mark-fg: #ffe9a8;
  --accent: #6f8bff;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 0 4rem; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 980px; margin: 0 auto; padding: 0 1rem; }
header.top { background: var(--panel); border-bottom: 1px solid var(--border); padding: 1.25rem 0; margin-bottom: 1.25rem; }
h1 { font-size: 1.35rem; margin: 0 0 .15rem; }
.meta-line { color: var(--muted); font-size: .88rem; }
.meta-line code { background: var(--bg); padding: .1rem .35rem; border-radius: 4px; }
.theme-toggle { float: right; background: none; border: 1px solid var(--border); color: var(--text);
  border-radius: 6px; padding: .3rem .6rem; cursor: pointer; font-size: .8rem; }

.verdicts { display: flex; flex-wrap: wrap; gap: .6rem; margin: 1rem 0; }
.pill { border-radius: 999px; padding: .45rem 1rem; font-weight: 600; font-size: .85rem; display: inline-flex; align-items: center; gap: .4rem; border: 1px solid transparent; }
.pill.good { background: var(--allow-bg); color: var(--allow); border-color: var(--allow); }
.pill.bad { background: var(--block-bg); color: var(--block); border-color: var(--block); }
.pill.warn { background: var(--escalate-bg); color: var(--escalate); border-color: var(--escalate); }
.pill.neutral { background: var(--panel); color: var(--muted); border-color: var(--border); }

.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1rem 1.1rem; margin-bottom: 1rem; }
.card h2 { font-size: 1rem; margin: 0 0 .6rem; }
.goal-box { font-size: .95rem; }
.goal-box .label { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; margin-bottom: .2rem; }

.attack-banner { border: 1px solid var(--attack); background: var(--attack-bg); color: var(--attack); border-radius: 10px; padding: .8rem 1rem; margin-bottom: 1rem; font-size: .9rem; }
.attack-banner b { display: block; margin-bottom: .3rem; font-size: .95rem; }

.stat-row { display: flex; gap: .5rem; margin-top: .5rem; flex-wrap: wrap; }
.stat-chip { flex: 1 1 90px; border-radius: 8px; padding: .5rem .6rem; text-align: center; border: 1px solid var(--border); }
.stat-chip .n { font-size: 1.3rem; font-weight: 700; display: block; }
.stat-chip.allow { border-color: var(--allow); color: var(--allow); }
.stat-chip.block { border-color: var(--block); color: var(--block); }
.stat-chip.escalate { border-color: var(--escalate); color: var(--escalate); }
.stat-chip.rewrite { border-color: var(--rewrite); color: var(--rewrite); }

.filters { display: flex; gap: .4rem; flex-wrap: wrap; margin: 1rem 0; }
.filters button { border: 1px solid var(--border); background: var(--panel); color: var(--text); border-radius: 999px;
  padding: .35rem .85rem; font-size: .82rem; cursor: pointer; }
.filters button.active { background: var(--accent); border-color: var(--accent); color: white; }

.timeline { position: relative; }
.step { border: 1px solid var(--border); border-left-width: 5px; border-radius: 10px; background: var(--panel);
  padding: .85rem 1rem; margin-bottom: .75rem; }
.step.decision-allow { border-left-color: var(--allow); }
.step.decision-block { border-left-color: var(--block); }
.step.decision-escalate { border-left-color: var(--escalate); }
.step.decision-rewrite { border-left-color: var(--rewrite); }
.step.attack-action { box-shadow: inset 0 0 0 1px var(--attack); }
.step-head { display: flex; align-items: center; gap: .55rem; flex-wrap: wrap; }
.step-num { color: var(--muted); font-size: .78rem; font-variant-numeric: tabular-nums; }
.badge { border-radius: 6px; padding: .18rem .55rem; font-weight: 700; font-size: .78rem; letter-spacing: .02em; }
.badge.allow { background: var(--allow-bg); color: var(--allow); }
.badge.block { background: var(--block-bg); color: var(--block); }
.badge.escalate { background: var(--escalate-bg); color: var(--escalate); }
.badge.rewrite { background: var(--rewrite-bg); color: var(--rewrite); }
.tool-name { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 600; }
.tag { font-size: .72rem; border-radius: 5px; padding: .1rem .4rem; background: var(--bg); color: var(--muted); border: 1px solid var(--border); }
.tag.attack { background: var(--attack-bg); color: var(--attack); border-color: var(--attack); font-weight: 700; }
.tag.gt-legit { background: var(--allow-bg); color: var(--allow); border-color: var(--allow); }
.tag.gt-illegit { background: var(--block-bg); color: var(--block); border-color: var(--block); font-weight: 700; }

.riskbar { height: 6px; border-radius: 4px; background: var(--bg); overflow: hidden; margin: .5rem 0 .3rem; border: 1px solid var(--border); }
.riskbar > div { height: 100%; background: linear-gradient(90deg, var(--allow), var(--escalate) 60%, var(--block)); }
.scorerow { display: flex; gap: 1.1rem; font-size: .82rem; color: var(--muted); flex-wrap: wrap; }
.scorerow b { color: var(--text); }

.reason-codes { margin: .35rem 0; display: flex; gap: .35rem; flex-wrap: wrap; }
.reason-codes span { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: .12rem .45rem; font-size: .74rem; font-family: ui-monospace, monospace; }

/* Custom tooltip for reason-code badges: styled (not the native browser title=), shows which
   mechanism produced the code and why, in plain language, on hover or keyboard focus. */
.rc-tip { position: relative; cursor: help; border-bottom: 1px dotted var(--muted); }
.rc-tip::after {
  content: attr(data-tip); position: absolute; left: 0; bottom: calc(100% + 6px); z-index: 20;
  width: max-content; max-width: 320px; background: var(--text); color: var(--bg);
  font-family: -apple-system, "Segoe UI", Roboto, sans-serif; font-size: .78rem; line-height: 1.4;
  padding: .5rem .65rem; border-radius: 8px; box-shadow: 0 6px 18px rgba(0,0,0,.25);
  opacity: 0; pointer-events: none; transform: translateY(4px); transition: opacity .12s, transform .12s;
}
.rc-tip:hover::after, .rc-tip:focus::after { opacity: 1; transform: translateY(0); }
.explanation { font-size: .88rem; margin: .4rem 0; font-style: italic; color: var(--text); }

.decision-path { margin: .65rem 0; border: 1px solid var(--border); border-radius: 9px; padding: .65rem; background: var(--bg); }
.path-caption { font-size: .74rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin-bottom: .5rem; }
.path-caption span { text-transform: none; letter-spacing: 0; }
.path-flow { display: grid; grid-template-columns: 1fr auto 1.5fr auto 1fr; gap: .45rem; align-items: stretch; }
.path-node { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: .5rem .6rem; }
.path-kicker { color: var(--muted); font-size: .7rem; text-transform: uppercase; letter-spacing: .035em; }
.path-value { font-size: .84rem; font-weight: 650; margin-top: .15rem; }
.path-arrow { align-self: center; color: var(--muted); font-size: 1.1rem; }
.scope-note { border-left: 4px solid var(--accent); background: var(--panel); border-radius: 8px; padding: .65rem .8rem; margin-bottom: 1rem; font-size: .84rem; color: var(--muted); }
.scope-note b { color: var(--text); }
.evaluator-label { font-size: .68rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); font-weight: 700; }
.warning-note { border-left: 4px solid var(--escalate); background: var(--escalate-bg); color: var(--text); border-radius: 8px; padding: .6rem .75rem; margin: .55rem 0; font-size: .84rem; }
@media (max-width: 760px) {
  .path-flow { grid-template-columns: 1fr; }
  .path-arrow { transform: rotate(90deg); justify-self: center; }
}

.rewrite-pair { display: grid; grid-template-columns: 1fr 1fr; gap: .6rem; margin-top: .5rem; }
.rewrite-pair > div { border: 1px dashed var(--border); border-radius: 8px; padding: .5rem .6rem; }
.rewrite-pair .lbl { font-size: .72rem; text-transform: uppercase; color: var(--muted); margin-bottom: .25rem; }
@media (max-width: 620px) { .rewrite-pair { grid-template-columns: 1fr; } }

.outcome-block { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .85rem;
  background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: .5rem .7rem; margin-top: .4rem; white-space: pre-wrap; word-break: break-word; }
.outcome-ok { color: var(--allow); }
.outcome-fail { color: var(--block); }

mark.attack-mark { background: var(--mark-bg); color: var(--mark-fg); border-radius: 3px; padding: 0 .1rem; }

details.raw { margin-top: .5rem; }
details.raw summary { cursor: pointer; color: var(--muted); font-size: .78rem; }
details.raw pre { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: .6rem .7rem;
  overflow-x: auto; font-size: .78rem; margin-top: .3rem; }

table.graders { width: 100%; border-collapse: collapse; font-size: .85rem; margin-top: .5rem; }
table.graders td, table.graders th { border-bottom: 1px solid var(--border); padding: .35rem .3rem; text-align: left; vertical-align: top; }
.pass { color: var(--allow); font-weight: 700; }
.fail { color: var(--block); font-weight: 700; }

footer { text-align: center; color: var(--muted); font-size: .78rem; margin-top: 2rem; }

.glossary summary { cursor: pointer; list-style: none; }
.glossary summary::-webkit-details-marker { display: none; }
.glossary summary::before { content: "\\25B8"; display: inline-block; margin-right: .4rem; color: var(--accent); transition: transform .12s; }
.glossary[open] summary::before { transform: rotate(90deg); }
.glossary-hint { color: var(--muted); font-size: .82rem; font-weight: 400; }
.glossary-body { margin-top: .75rem; display: flex; flex-direction: column; gap: .6rem; }
.glossary-row { display: grid; grid-template-columns: 220px 1fr; gap: .8rem; padding: .5rem 0; border-top: 1px solid var(--border); }
.glossary-row:first-child { border-top: none; padding-top: 0; }
.glossary-name { font-weight: 700; font-size: .85rem; color: var(--accent); }
.glossary-desc { font-size: .87rem; color: var(--text); }
@media (max-width: 680px) { .glossary-row { grid-template-columns: 1fr; gap: .2rem; } }
"""

JS = """
function setTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  try { localStorage.setItem('sentinel-report-theme', t); } catch (e) {}
}
(function () {
  try {
    var saved = localStorage.getItem('sentinel-report-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
  } catch (e) {}
})();
function toggleTheme() {
  var cur = document.documentElement.getAttribute('data-theme');
  var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  var effectiveDark = cur ? cur === 'dark' : prefersDark;
  setTheme(effectiveDark ? 'light' : 'dark');
}
function applyFilter(kind, btn) {
  var steps = document.querySelectorAll('.step');
  var buttons = document.querySelectorAll('.filters button');
  buttons.forEach(function (b) { b.classList.remove('active'); });
  btn.classList.add('active');
  steps.forEach(function (s) {
    if (kind === 'all') { s.style.display = ''; return; }
    if (kind === 'attack') { s.style.display = s.classList.contains('attack-action') ? '' : 'none'; return; }
    s.style.display = s.classList.contains('decision-' + kind) ? '' : 'none';
  });
}
"""


def build_run(events: list[dict[str, Any]], summary: dict[str, Any] | None, scenario: dict[str, Any] | None) -> dict[str, Any]:
    """Compute everything needed to render one run, without the page shell -- reused by both
    `render()` (single-file report) and the multi-scenario dashboard, so both stay in sync with
    exactly one implementation of the timeline/verdict/attack-highlighting logic."""
    attack_ctx = build_attack_context(scenario)
    payload_texts = attack_ctx.get("payload_texts", [])
    restricted_display_values = discover_restricted_display_values(events)
    control_repairs = discover_control_repairs(events)

    decisions_gt: dict[int, dict[str, Any]] = {}
    if summary:
        for d in summary.get("decisions", []):
            decisions_gt[d["step_id"]] = d

    run_id = events[0]["run_id"] if events else "unknown"
    scenario_id = (summary or {}).get("scenario_id") or (scenario or {}).get("id") or run_id
    title = (scenario or {}).get("title") or scenario_id
    description = (scenario or {}).get("description") or ""
    domain = (summary or {}).get("domain") or (scenario or {}).get("domain") or "?"
    defense_name = (summary or {}).get("defense") or "?"
    goal = ""
    if scenario and scenario.get("turns"):
        goal = scenario["turns"][0].get("goal", "")
    elif events:
        first_user = next((e for e in events if e["type"] == "user_message"), None)
        if first_user:
            goal = first_user["payload"].get("text", "")

    # group events by step_id, preserving encounter order
    steps: dict[int, list[dict[str, Any]]] = {}
    for ev in events:
        steps.setdefault(ev["step_id"], []).append(ev)

    counts = {"allow": 0, "block": 0, "escalate": 0, "rewrite": 0}
    for ev in events:
        if ev["type"] == "defense_decision":
            d = ev["payload"].get("decision")
            if d in counts:
                counts[d] += 1
    total_decisions = sum(counts.values()) or 1

    # ---- verdict banner -------------------------------------------------------------------
    task_success = (summary or {}).get("task_success")
    attack_present = attack_ctx.get("present") if scenario else (summary or {}).get("attack_present")
    attack_success = (summary or {}).get("attack_success")
    critical_violation = (summary or {}).get("critical_violation")
    termination = (summary or {}).get("termination")

    pills = []
    if task_success is not None:
        pills.append(
            f'<span class="pill {"good" if task_success else "bad"}">'
            f'{"&#10003;" if task_success else "&#10007;"} Task {"succeeded" if task_success else "failed"}</span>'
        )
    if attack_present:
        if attack_success is False:
            pills.append('<span class="pill good">&#128737; Attack did not succeed</span>')
        elif attack_success is True:
            pills.append('<span class="pill bad">&#9888; Attack succeeded</span>')
        else:
            pills.append('<span class="pill neutral">Attack scenario</span>')
    else:
        pills.append('<span class="pill neutral">Benign scenario (no attack)</span>')
    if critical_violation:
        pills.append('<span class="pill bad">&#9888; Critical violation</span>')
    elif critical_violation is False:
        pills.append('<span class="pill good">No critical violation</span>')
    if termination and termination != "completed":
        pills.append(f'<span class="pill warn">termination: {esc(termination)}</span>')

    attack_banner = ""
    if attack_ctx.get("present"):
        surfaces = ", ".join(s.get("id", "") for s in attack_ctx.get("surfaces", [])) or "n/a"
        attack_banner = (
            '<div class="attack-banner">'
            '<div class="evaluator-label">Evaluator-only attack context</div>'
            f"<b>&#9888; Injected attack: {esc(attack_ctx.get('family'))} "
            f"(difficulty {esc(attack_ctx.get('difficulty'))})</b>"
            f"Objective: {esc(attack_ctx.get('objective'))}<br>"
            f"Surface(s): <code>{esc(surfaces)}</code> &mdash; highlighted below wherever the injected "
            "text reaches the agent, and on the defense decision that acted on it."
            "</div>"
        )

    stat_chips = "".join(
        f'<div class="stat-chip {k}"><span class="n">{counts[k]}</span>{DECISION_META[k]["label"]}'
        f' <span style="opacity:.6">({round(100*counts[k]/total_decisions)}%)</span></div>'
        for k in ("allow", "block", "escalate", "rewrite")
    )

    # ---- timeline ---------------------------------------------------------------------------
    step_html_parts = []
    for step_id in sorted(steps):
        if step_id == 0:
            continue
        step_events = steps[step_id]
        decision_ev = next((e for e in step_events if e["type"] == "defense_decision"), None)
        gt = decisions_gt.get(step_id)
        css_classes = ["step"]
        decision_val = None
        if decision_ev:
            decision_val = decision_ev["payload"].get("decision")
            css_classes.append(f"decision-{decision_val}")
        is_attack_action = bool(gt and gt.get("legitimate") is False)
        if is_attack_action:
            css_classes.append("attack-action")

        head_bits = [f'<span class="step-num">step {step_id}</span>']
        if decision_val:
            meta = DECISION_META.get(decision_val, {"label": decision_val.upper(), "icon": "?"})
            head_bits.append(f'<span class="badge {meta["css"]}">{meta["icon"]} {meta["label"]}</span>')
        if decision_ev:
            action = decision_ev["payload"].get("action") or {}
            tool = action.get("tool")
            if tool:
                head_bits.append(f'<span class="tool-name">{esc(tool)}</span>')
            else:
                head_bits.append(f'<span class="tool-name">{esc(action.get("type"))}</span>')
        if is_attack_action:
            verdict = evaluator_action_verdict(decision_val)
            css_extra = "gt-illegit"
            head_bits.append(
                f'<span class="tag {css_extra}">&#127919; evaluator: illegitimate '
                f'&mdash; {esc(verdict)}</span>'
            )
        elif gt is not None:
            head_bits.append('<span class="tag gt-legit">evaluator: legitimate</span>')

        body_parts = []
        if decision_ev:
            p = decision_ev["payload"]
            action = p.get("action") or {}
            risk = p.get("risk_score")
            conf = p.get("confidence")
            proposal_summary = mask_restricted_for_display(
                action_summary(action),
                restricted_display_values,
            )
            body_parts.append(f'<div><b>Proposed:</b> {esc(proposal_summary)}</div>')
            if risk is not None:
                pct = max(0, min(100, round(risk * 100)))
                body_parts.append(
                    f'<div class="riskbar"><div style="width:{pct}%"></div></div>'
                    f'<div class="scorerow"><span>risk <b>{risk:.2f}</b></span>'
                    f'<span>confidence <b>{conf:.2f}</b></span>'
                    + (f'<span>latency <b>{gt["latency_ms"]:.2f}ms</b></span>' if gt else "")
                    + "</div>"
                )
            codes = p.get("reason_codes") or []
            if codes:
                body_parts.append(
                    '<div class="reason-codes">' + "".join(reason_code_badge(c) for c in codes) + "</div>"
                )
            body_parts.append(decision_path_html(codes, decision_val))
            if p.get("explanation"):
                body_parts.append(f'<div class="explanation">&ldquo;{esc(p["explanation"])}&rdquo;</div>')
            if p.get("defense_error"):
                body_parts.append(f'<div class="tag" style="color:var(--block)">defense_error: {esc(p["defense_error"])}</div>')
            metadata = p.get("metadata") or {}
            if metadata:
                body_parts.append(
                    '<details class="raw"><summary>decision metadata</summary>'
                    f"<pre>{esc(pretty(metadata))}</pre></details>"
                )
            if decision_val == "rewrite" and p.get("rewritten_action"):
                original_summary = mask_restricted_for_display(
                    action_summary(action),
                    restricted_display_values,
                )
                rewritten_summary = mask_restricted_for_display(
                    action_summary(p["rewritten_action"]),
                    restricted_display_values,
                )
                body_parts.append(
                    '<div class="rewrite-pair">'
                    f'<div><div class="lbl">Agent proposal</div>{esc(original_summary)}</div>'
                    f'<div><div class="lbl">Safe rewritten action</div>{esc(rewritten_summary)}</div>'
                    "</div>"
                )

        # what happened next
        for ev in step_events:
            t = ev["type"]
            p = ev["payload"]
            if t == "tool_request":
                confirmed = " (pre-confirmed)" if p.get("confirmed") else ""
                body_parts.append(
                    f'<div><b>&#8594; Executed:</b> <span class="tool-name">{esc(p.get("tool"))}</span>{confirmed}</div>'
                )
            elif t in ("tool_result", "retrieval_result"):
                ok = p.get("succeeded")
                text_fields = list(iter_strings(p.get("result")))
                combined = mask_restricted_for_display(
                    "\n".join(text_fields),
                    restricted_display_values,
                )
                highlighted = highlight_payload(combined, payload_texts) if combined else ""
                status = (
                    '<span style="color:var(--allow)">ok</span>'
                    if ok
                    else f'<span style="color:var(--block)">error: {esc(p.get("error"))}</span>'
                )
                effects = p.get("effects") or []
                effects_str = f' <span class="tag">effects: {esc(", ".join(effects))}</span>' if effects else ""
                surfaced = ""
                if highlighted and any(nt in combined for nt in payload_texts):
                    surfaced = '<div class="tag attack" style="margin:.3rem 0;display:inline-block">&#9888; injected content surfaces here</div><br>'
                body_parts.append(
                    f'<div><b>&#8592; Result:</b> {status}{effects_str}</div>'
                    + (f"{surfaced}<div class=\"outcome-block\">{highlighted[:2000]}</div>" if combined else "")
                )
            elif t == "human_confirmation":
                approved = p.get("approved")
                body_parts.append(
                    f'<div><b>Human review:</b> '
                    f'<span style="color:var(--{"allow" if approved else "block"})">'
                    f'{"approved" if approved else "denied"}</span> {esc(p.get("tool"))}</div>'
                )
            elif t == "model_output":
                if p.get("content"):
                    content = mask_restricted_for_display(
                        p["content"],
                        restricted_display_values,
                    )
                    body_parts.append(
                        f'<div><b>Agent says:</b> {esc(_short(content, 300))}</div>'
                    )
                    stale = stale_repair_narration(content, control_repairs)
                    if stale:
                        argument, original, repaired = stale
                        body_parts.append(
                            '<div class="warning-note"><b>Execution / narration mismatch.</b> '
                            f'The model narration still names the pre-repair {esc(argument)} '
                            f'<code>{esc(original)}</code>, but the executed tool request used '
                            f'<code>{esc(repaired)}</code>. The execution trace, not this stale '
                            'narration, is authoritative for the action that actually ran.</div>'
                        )
            elif t in ("task_success", "task_failure"):
                cls = "outcome-ok" if t == "task_success" else "outcome-fail"
                body_parts.append(
                    f'<div class="outcome-block {cls}"><b>{"TASK SUCCESS" if t == "task_success" else "TASK FAILURE"}</b>\n'
                    f"{esc(p.get('summary'))}\ntermination: {esc(p.get('termination'))}</div>"
                )
            elif t == "policy_violation":
                body_parts.append(
                    f'<div class="tag attack" style="display:inline-block;margin:.2rem 0">'
                    f'VIOLATION {esc(p.get("severity", "").upper())} {esc(p.get("rule_id"))}: {esc(p.get("message"))}</div>'
                )
            elif t == "memory_read":
                body_parts.append(f'<div><b>Memory recalled:</b> {esc(", ".join(p.get("entries", [])))}</div>')

        raw_json = "\n".join(
            json.dumps(e, indent=2, ensure_ascii=False, sort_keys=True)
            for e in step_events
        )
        raw_json = mask_restricted_for_display(
            raw_json,
            restricted_display_values,
        )
        body_parts.append(
            f'<details class="raw"><summary>raw events (step {step_id}) '
            '(restricted values masked in this view)</summary>'
            f'<pre>{esc(raw_json)}</pre></details>'
        )

        step_html_parts.append(
            f'<div class="{" ".join(css_classes)}"><div class="step-head">{"".join(head_bits)}</div>'
            f'<div class="step-body">{"".join(body_parts)}</div></div>'
        )

    # ---- grader / outcome section -------------------------------------------------------------
    graders_html = ""
    if summary and summary.get("grader_results"):
        rows = "".join(
            f'<tr><td class="{"pass" if g["passed"] else "fail"}">{"PASS" if g["passed"] else "FAIL"}</td>'
            f'<td>{esc(g["condition"])}</td><td>{esc(g.get("detail", ""))}</td></tr>'
            for g in summary["grader_results"]
        )
        graders_html = (
            '<div class="card"><div class="evaluator-label">Evaluator-only</div><h2>Success conditions (grader results)</h2>'
            f'<table class="graders"><tr><th></th><th>condition</th><th>detail</th></tr>{rows}</table></div>'
        )

    findings_html = ""
    if summary and summary.get("findings"):
        items = "".join(
            f'<li><b>{esc(f.get("severity", "").upper())}</b> {esc(f.get("rule_id"))} (step {f.get("step_id")}): {esc(f.get("message"))}</li>'
            for f in summary["findings"]
        )
        findings_html = f'<div class="card"><div class="evaluator-label">Evaluator-only</div><h2>Policy findings</h2><ul>{items}</ul></div>'

    goal_html = ""
    if goal or description:
        goal_html = (
            '<div class="card goal-box">'
            + (f'<div class="label">Description</div><div>{esc(description)}</div>' if description else "")
            + (f'<div class="label" style="margin-top:.5rem">Task goal given to the agent</div><div>{esc(goal)}</div>' if goal else "")
            + "</div>"
        )

    content_html = f"""
  {goal_html}
  {attack_banner}
  <div class="scope-note">
    <b>View separation.</b> Defense decisions, reason codes, rewrites, executed actions, tool results,
    and human review come from the runtime trace. Items explicitly labeled <i>evaluator-only</i>
    are post-run ground truth used for analysis and were not visible to the defense.
    Restricted values are masked in this jury-facing HTML; the archived JSONL evidence is unchanged.
  </div>
  <div class="verdicts">{"".join(pills)}</div>

  <div class="card">
    <h2>Decisions this run</h2>
    <div class="stat-row">{stat_chips}</div>
  </div>

  <div class="filters">
    <button class="active" onclick="applyFilter('all', this)">All steps</button>
    <button onclick="applyFilter('allow', this)">Allow</button>
    <button onclick="applyFilter('block', this)">Block</button>
    <button onclick="applyFilter('escalate', this)">Escalate</button>
    <button onclick="applyFilter('rewrite', this)">Rewrite</button>
    <button onclick="applyFilter('attack', this)">Attack actions only</button>
  </div>

  <div class="timeline">
    {"".join(step_html_parts)}
  </div>

  {graders_html}
  {findings_html}
"""

    return {
        "title": title,
        "scenario_id": scenario_id,
        "domain": domain,
        "defense_name": defense_name,
        "run_id": run_id,
        "attack_present": bool(attack_ctx.get("present")),
        "attack_family": attack_ctx.get("family"),
        "task_success": task_success,
        "attack_success": attack_success,
        "critical_violation": critical_violation,
        "content_html": content_html,
    }


def render(events: list[dict[str, Any]], summary: dict[str, Any] | None, scenario: dict[str, Any] | None) -> str:
    """Full single-file report: one run, its own page shell, glossary included inline."""
    run = build_run(events, summary, scenario)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL report &middot; {esc(run["title"])}</title>
<style>{CSS}</style>
</head>
<body>
<header class="top"><div class="wrap">
  <button class="theme-toggle" onclick="toggleTheme()">&#9788; theme</button>
  <h1>{esc(run["title"])}</h1>
  <div class="meta-line">
    scenario <code>{esc(run["scenario_id"])}</code> &middot; domain <code>{esc(run["domain"])}</code> &middot;
    defense <code>{esc(run["defense_name"])}</code> &middot; run <code>{esc(run["run_id"])}</code>
  </div>
</div></header>
<div class="wrap">

  {mechanism_glossary_html()}
  {run["content_html"]}

  <footer>Generated by scripts/render_report.py from {esc(str(run["run_id"]))} &middot; SENTINEL observability report</footer>
</div>
<script>{JS}</script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("artifact", type=Path, help="Path to the run's .jsonl event artifact")
    parser.add_argument("scenario", type=Path, nargs="?", default=None, help="Optional path to the scenario YAML")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output HTML path (default: alongside the artifact)")
    args = parser.parse_args()

    events = load_jsonl(args.artifact)
    if not events:
        print(f"error: {args.artifact} contains no events", file=sys.stderr)
        raise SystemExit(1)
    summary = find_summary(args.artifact)
    scenario = load_scenario(args.scenario)

    html_out = render(events, summary, scenario)
    output = args.output or args.artifact.with_name(args.artifact.stem + ".report.html")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html_out, encoding="utf-8")
    print(f"wrote {output}")


if __name__ == "__main__":
    main()
