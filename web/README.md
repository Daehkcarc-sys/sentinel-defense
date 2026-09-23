# SENTINEL Hybrid -- live observability dashboard

A React + Vite dashboard for demonstrating the defense interactively: run any scenario live
(against `mock` or real `ollama:qwen3:8b`) and watch decisions stream in as the defense makes
them, replay pre-recorded real-Qwen3-8B evidence from the full corpus, bulk-evaluate all 62
scenarios with an aggregate chart summary, or read a jury-facing plain-language architecture
glossary. See `SENTINEL_TECHNICAL_REPORT.md` for the full written evidence this dashboard
visualizes.

## Run it

Two processes, from the repository root (`Sentinel_Starter_Kit/`):

```bash
# 1. the backend: a thin FastAPI side-channel over the existing, unmodified evaluator
uv run python scripts/live_run_server.py            # listens on 127.0.0.1:8787

# 2. the frontend
cd web/front
pnpm install
pnpm dev                                             # http://localhost:5173
```

`scripts/live_run_server.py` reuses `sentinel.evaluator.runner.run_scenario` unchanged --
it taps a side channel by subclassing `EvaluationHooks` in-process, so nothing under
`src/sentinel/` is modified and the JSONL artifact it writes is identical to what
`sentinel run` would write.

## What's here

- **Live run** -- pick a scenario, defense, and reference agent; decisions stream in over SSE
  as the defense makes them, in real time (a few seconds per scenario on real Qwen3-8B, instant
  on mock).
- **Bulk run** -- evaluate the full scenario corpus sequentially, with a per-scenario result row
  and a final BTU / DSR / critical-violation summary, charted.
- **Evidence corpus** -- replay any of the pre-recorded real-Qwen3-8B runs from
  `artifacts/qwen_full_corpus_results.json` exactly as captured (not a fresh run).
- **Architecture** -- a plain-language glossary of every mechanism in the shipped defense,
  cross-referenced to the technical report.

Three themes (dark / light / notebook), reason-code tooltips ported from the report's own
explanations, and GSAP/motion micro-interactions throughout.
