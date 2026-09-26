#!/usr/bin/env python3
"""Local server that runs a real SENTINEL scenario and streams the defense's decisions to the
observability dashboard as they happen (Server-Sent Events), instead of only replaying a
pre-recorded JSONL artifact.

It reuses the existing, tested evaluator (`sentinel.evaluator.runner.run_scenario`) unchanged --
this file adds a side-channel by subclassing `EvaluationHooks` and monkeypatching the runner
module's reference to it in this process only. No file under `src/sentinel/` is modified. The
persisted JSONL artifact is still written exactly as `sentinel run` would write it.

Usage:
    uv run uvicorn scripts.live_run_server:app --reload --port 8787
or:
    uv run python scripts/live_run_server.py
"""

from __future__ import annotations

import json
import queue
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from sentinel.cli import _model_factory
from sentinel.config import find_root, load_competition
from sentinel.core.scenario import discover_scenarios, load_scenario
from sentinel.defenses.baselines import BASELINES
from sentinel.evaluator import runner as runner_mod
from sentinel.storage.runs import ArtifactStore

ROOT = find_root()
_END = object()
_local = threading.local()

app = FastAPI(title="SENTINEL live run server")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_RUNS: dict[str, queue.Queue] = {}


def _emit(payload: dict[str, Any]) -> None:
    q = getattr(_local, "queue", None)
    if q is not None:
        q.put(payload)


class LiveHooks(runner_mod.EvaluationHooks):
    def on_decision(self, step_id, turn_index, action, decision, latency_ms, error) -> None:  # type: ignore[override]
        super().on_decision(step_id, turn_index, action, decision, latency_ms, error)
        rewritten = decision.rewritten_action
        _emit(
            {
                "type": "decision",
                "step_id": step_id,
                "action_type": action.type.value,
                "tool": action.tool,
                "arguments": {k: v for k, v in action.arguments.items()},
                "content": action.content,
                "decision": decision.decision.value,
                "risk_score": decision.risk_score,
                "confidence": decision.confidence,
                "reason_codes": list(decision.reason_codes),
                "latency_ms": round(latency_ms, 3),
                "defense_error": error,
                "rewritten_content": rewritten.content if rewritten else None,
                "rewritten_arguments": ({k: v for k, v in rewritten.arguments.items()} if rewritten else None),
            }
        )

    def after_tool(self, step_id, turn_index, action, result, confirmed) -> None:  # type: ignore[override]
        super().after_tool(step_id, turn_index, action, result, confirmed)
        _emit(
            {
                "type": "tool_execution",
                "step_id": step_id,
                "tool": action.tool,
                "succeeded": bool(result.outcome.succeeded),
                "confirmed": confirmed,
            }
        )

    def on_sink(self, step_id, action, sink) -> None:  # type: ignore[override]
        super().on_sink(step_id, action, sink)
        _emit({"type": "sink", "step_id": step_id})


runner_mod.EvaluationHooks = LiveHooks


class RunRequest(BaseModel):
    scenario_id: str
    defense: str = "sentinel_hybrid"
    model: str = "mock"


class BulkRunRequest(BaseModel):
    defense: str = "sentinel_hybrid"
    model: str = "mock"
    scenario_ids: list[str] | None = None  # None = every scenario in the corpus


def _scenario_index() -> dict[str, Path]:
    index: dict[str, Path] = {}
    for base in ("public", "validation", "self_authored"):
        for f in discover_scenarios(ROOT / "scenarios" / base):
            index[load_scenario(f).id] = f
    return index


def _run_worker(run_id: str, req: RunRequest, q: queue.Queue) -> None:
    _local.queue = q
    try:
        from sentinel.evaluator.runner import AttackMode, RunConfig, eval_group_name, run_scenario

        index = _scenario_index()
        path = index.get(req.scenario_id)
        if path is None:
            q.put({"type": "error", "message": f"unknown scenario {req.scenario_id!r}"})
            return
        scenario = load_scenario(path)
        key = req.defense.replace("-", "_")
        if key not in BASELINES:
            q.put({"type": "error", "message": f"unknown defense {req.defense!r}"})
            return
        defense = BASELINES[key]()
        competition = load_competition(None, ROOT)
        store = ArtifactStore(ROOT / "artifacts" / "live_dashboard")
        group = store.unique_group(eval_group_name(f"live-{scenario.id}", defense.name))
        config = RunConfig(
            root=ROOT,
            competition=competition,
            attack_mode=AttackMode.STATIC if scenario.attack.present else AttackMode.NONE,
            model_factory=_model_factory(req.model),
            include_reference_plan=(req.model == "mock"),
            artifacts=store,
            artifact_group=group,
        )
        q.put(
            {
                "type": "start",
                "scenario_id": scenario.id,
                "domain": scenario.domain.value,
                "attack_present": scenario.attack.present,
                "defense": defense.name,
                "model": req.model,
            }
        )
        result = run_scenario(scenario, defense, config)
        q.put(
            {
                "type": "done",
                "task_success": result.outcome.task_success,
                "attack_success": result.outcome.attack_success,
                "critical_violation": result.outcome.critical_violation,
                "steps": result.outcome.steps,
                "termination": result.outcome.termination,
                "artifact": str(result.artifact) if result.artifact else None,
            }
        )
    except Exception as exc:  # noqa: BLE001 - surface any failure to the dashboard instead of hanging it
        q.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
    finally:
        q.put(_END)


def _bulk_worker(req: BulkRunRequest, q: queue.Queue) -> None:
    # Deliberately do NOT set _local.queue here: per-decision events would flood a 60+ scenario
    # bulk run, so LiveHooks._emit stays a no-op in this thread and only the per-scenario summary
    # (pushed manually below) reaches the dashboard.
    try:
        from sentinel.evaluator.runner import AttackMode, RunConfig, eval_group_name, run_scenario

        index = _scenario_index()
        ids = req.scenario_ids or sorted(index)
        key = req.defense.replace("-", "_")
        if key not in BASELINES:
            q.put({"type": "error", "message": f"unknown defense {req.defense!r}"})
            return
        competition = load_competition(None, ROOT)
        store = ArtifactStore(ROOT / "artifacts" / "live_bulk")
        results: list[dict[str, Any]] = []
        q.put({"type": "bulk_start", "total": len(ids), "defense": req.defense, "model": req.model})
        for i, sid in enumerate(ids, 1):
            path = index.get(sid)
            if path is None:
                row = {"type": "scenario_result", "index": i, "scenario_id": sid, "error": "unknown scenario"}
                results.append(row)
                q.put(row)
                continue
            scenario = load_scenario(path)
            defense = BASELINES[key]()
            group = store.unique_group(eval_group_name(f"bulk-{scenario.id}", defense.name))
            config = RunConfig(
                root=ROOT,
                competition=competition,
                attack_mode=AttackMode.STATIC if scenario.attack.present else AttackMode.NONE,
                model_factory=_model_factory(req.model),
                include_reference_plan=(req.model == "mock"),
                artifacts=store,
                artifact_group=group,
            )
            try:
                result = run_scenario(scenario, defense, config)
                decision_counts = {"allow": 0, "block": 0, "escalate": 0, "rewrite": 0}
                for d in result.outcome.decisions:
                    key_d = d.decision.value if hasattr(d.decision, "value") else str(d.decision)
                    if key_d in decision_counts:
                        decision_counts[key_d] += 1
                row = {
                    "type": "scenario_result",
                    "index": i,
                    "scenario_id": sid,
                    "domain": scenario.domain.value,
                    "attack_present": scenario.attack.present,
                    "task_success": result.outcome.task_success,
                    "attack_success": result.outcome.attack_success,
                    "critical_violation": result.outcome.critical_violation,
                    "steps": result.outcome.steps,
                    "decisions": decision_counts,
                }
            except Exception as exc:  # noqa: BLE001
                row = {
                    "type": "scenario_result",
                    "index": i,
                    "scenario_id": sid,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            results.append(row)
            q.put(row)

        ok = [r for r in results if "error" not in r]
        benign = [r for r in ok if not r["attack_present"]]
        attacks = [r for r in ok if r["attack_present"]]
        btu = sum(1 for r in benign if r["task_success"])
        dsr = sum(1 for r in attacks if r["attack_success"] is False)
        crit = sum(1 for r in ok if r["critical_violation"])
        decision_totals = {"allow": 0, "block": 0, "escalate": 0, "rewrite": 0}
        for r in ok:
            for k, v in r.get("decisions", {}).items():
                decision_totals[k] = decision_totals.get(k, 0) + v
        q.put(
            {
                "type": "bulk_done",
                "total": len(results),
                "errors": len(results) - len(ok),
                "benign_count": len(benign),
                "btu": btu,
                "attack_count": len(attacks),
                "dsr": dsr,
                "critical_violations": crit,
                "decision_counts": decision_totals,
            }
        )
    except Exception as exc:  # noqa: BLE001
        q.put({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
    finally:
        q.put(_END)


@app.get("/api/scenarios")
def list_scenarios() -> list[dict[str, Any]]:
    out = []
    for sid, path in sorted(_scenario_index().items()):
        scenario = load_scenario(path)
        out.append(
            {
                "id": sid,
                "domain": scenario.domain.value,
                "split": scenario.split.value,
                "attack_present": scenario.attack.present,
            }
        )
    return out


@app.get("/api/defenses")
def list_defenses() -> list[str]:
    preferred = ["allow_all", "provenance", "authority_core_v3_full", "sentinel_hybrid"]
    rest = sorted(set(BASELINES) - set(preferred))
    return preferred + rest


@app.post("/api/run")
def start_run(req: RunRequest) -> dict[str, str]:
    run_id = uuid.uuid4().hex[:12]
    q: queue.Queue = queue.Queue()
    _RUNS[run_id] = q
    thread = threading.Thread(target=_run_worker, args=(run_id, req, q), daemon=True)
    thread.start()
    return {"run_id": run_id}


@app.post("/api/bulk_run")
def start_bulk_run(req: BulkRunRequest) -> dict[str, str]:
    run_id = uuid.uuid4().hex[:12]
    q: queue.Queue = queue.Queue()
    _RUNS[run_id] = q
    thread = threading.Thread(target=_bulk_worker, args=(req, q), daemon=True)
    thread.start()
    return {"run_id": run_id}


@app.get("/api/stream/{run_id}")
def stream(run_id: str) -> StreamingResponse:
    q = _RUNS.get(run_id)
    if q is None:
        raise HTTPException(404, "unknown run_id")

    def gen():
        while True:
            item = q.get()
            if item is _END:
                break
            yield f"data: {json.dumps(item)}\n\n"
        _RUNS.pop(run_id, None)

    return StreamingResponse(gen(), media_type="text/event-stream")


# ---- pre-recorded evidence corpus (real Qwen3-8B runs captured earlier) -----------------------

_RESULTS_FILE = ROOT / "artifacts" / "qwen_full_corpus_results.json"


def _domain_of(sid: str) -> str:
    if sid.startswith(("ent_", "enterprise_")):
        return "enterprise"
    if sid.startswith(("fin_", "finance_")):
        return "finance"
    if sid.startswith("soc_"):
        return "soc"
    return "other"


@app.get("/api/corpus")
def corpus_manifest() -> list[dict[str, Any]]:
    if not _RESULTS_FILE.exists():
        return []
    results = json.loads(_RESULTS_FILE.read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = []
    for sid, entry in sorted(results.items()):
        for defense_key in ("authority_core_v3_full", "sentinel_hybrid"):
            row = entry.get(defense_key, {})
            artifact = row.get("artifact")
            if not artifact or "skipped" in row or "error" in row:
                continue
            entries.append(
                {
                    "scenario_id": sid,
                    "domain": _domain_of(sid),
                    "defense": defense_key,
                    "attack_present": entry.get("attack_present_declared", False),
                    "task_success": row.get("task_success"),
                    "attack_success": row.get("attack_success"),
                    "critical_violation": row.get("critical_violation"),
                    "jsonl": str(artifact).replace("\\", "/"),
                }
            )
    return entries


@app.get("/api/corpus/replay")
def corpus_replay(jsonl: str) -> list[dict[str, Any]]:
    path = (ROOT / jsonl).resolve()
    if not str(path).startswith(str(ROOT.resolve())) or not path.exists():
        raise HTTPException(404, "artifact not found")
    summary_path = path.with_name(path.stem + ".summary.json")
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}

    events_by_step: dict[int, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            raw = json.loads(line)
            if raw.get("type") == "defense_decision":
                action = raw["payload"].get("action", {})
                rewritten = raw["payload"].get("rewritten_action")
                events_by_step[raw["step_id"]] = {
                    "action_type": action.get("type"),
                    "tool": action.get("tool"),
                    "arguments": action.get("arguments", {}),
                    "content": action.get("content"),
                    "defense_error": raw["payload"].get("defense_error"),
                    "rewritten_content": rewritten.get("content") if rewritten else None,
                    "rewritten_arguments": rewritten.get("arguments") if rewritten else None,
                }

    out: list[dict[str, Any]] = [
        {
            "type": "start",
            "scenario_id": summary.get("scenario_id", path.stem),
            "domain": summary.get("domain", "?"),
            "attack_present": summary.get("attack_present", False),
            "defense": summary.get("defense", "?"),
            "model": "ollama:qwen3:8b (pre-recorded)",
        }
    ]
    for record in summary.get("decisions", []):
        extra = events_by_step.get(record["step_id"], {})
        out.append(
            {
                "type": "decision",
                "step_id": record["step_id"],
                "action_type": extra.get("action_type", record.get("action_type", "?")),
                "tool": record.get("tool"),
                "arguments": extra.get("arguments", {}),
                "content": extra.get("content"),
                "decision": record["decision"],
                "risk_score": record["risk_score"],
                "confidence": record["confidence"],
                "reason_codes": record["reason_codes"],
                "rewritten_content": extra.get("rewritten_content"),
                "rewritten_arguments": extra.get("rewritten_arguments"),
                "latency_ms": record["latency_ms"],
                "defense_error": record.get("defense_error"),
            }
        )
    for execu in summary.get("tool_executions", []):
        out.append(
            {
                "type": "tool_execution",
                "step_id": execu["step_id"],
                "tool": execu["tool"],
                "succeeded": execu["succeeded"],
                "confirmed": False,
            }
        )
    out.sort(key=lambda e: (e["step_id"] if "step_id" in e else -1, e["type"] != "decision"))
    out.append(
        {
            "type": "done",
            "task_success": summary.get("task_success"),
            "attack_success": summary.get("attack_success"),
            "critical_violation": summary.get("critical_violation"),
            "steps": summary.get("steps"),
            "termination": summary.get("termination"),
            "artifact": jsonl,
        }
    )
    return out


# ---- architecture / mechanism glossary (static, for the demo's info panel) --------------------

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


@app.get("/api/architecture")
def architecture() -> list[dict[str, str]]:
    return [{"name": name, "description": desc} for name, desc in MECHANISM_OVERVIEW]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8787)
