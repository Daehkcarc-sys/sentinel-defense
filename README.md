# SENTINEL: Adaptive Safety for Autonomous AI Agents

## Our team's defense (read this first)

This fork/clone tracks the organizer's [`Skan22/Sentinel_Starter_Kit`](https://github.com/Skan22/Sentinel_Starter_Kit)
starter kit unmodified, plus **our own defense implementation** on top of it. If you're picking this
up to help with the video, report, or further testing, start here.

**Where the code is:** `src/sentinel/defenses/baselines/authority_core.py`, registered in `BASELINES`
as `authority_core`, `authority_core_state`, `authority_core_evidence`, `authority_core_full`
(Phase 7/8 ablation arms), and `authority_core_auth`, `authority_core_field`,
`authority_core_decision`, `authority_core_v2_full`, `authority_core_decision_block`,
`authority_core_goal`, **`authority_core_v3_full`** (v2/v3 mechanisms — `v3_full` is the one to run
for the demo and the report).

**Run it:**

```bash
uv run sentinel run --scenario scenarios/self_authored/soc_incident_object_mismatch.yaml \
  --defense authority_core_v3_full
uv run sentinel replay artifacts/<eval-group>/<run_id>.jsonl
# against the real reference agent (needs weights + a GPU):
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense authority_core_v3_full --model qwen3-8b
```

**Current result** (full 36-scenario corpus: 19 public + 9 validation + 8 self-authored, under
`scenarios/self_authored/`): `authority_core_v3_full` holds **BTU=1.000, DSR=1.000, zero critical
violations** — every published and self-authored attack is stopped, with no benign-task regressions.

**What the defense actually does**, in one paragraph: authority to take an action comes only from
structural, verifiable facts (allowed tools, confirmations, policy) and never from the content of
what the agent has observed — content can determine *what* the agent wants to do, never *whether*
it's authorized. On top of that non-additive policy core sit four narrow, independently-toggleable
mechanisms: authorization-binding (an exact action can't be silently re-executed once it's already
run), field-level evidence (a value sourced only from an untrusted part of a mixed-trust response is
flagged even if the rest of that response is trusted), decision-relevance tiering (a flagged value
that operationally parameterizes a consequential action is treated more seriously than one that's
merely mentioned in a note), and goal-declared object consistency (an action can't silently retarget
a different object than the one the user's own authenticated request actually named).

**Why it looks this narrow:** every piece here survived a real falsification test against the full
scenario corpus — several more ambitious ideas (a global cross-tool prerequisite graph, a semantic
LLM monitor, task-contract-as-authorization) were built, tested, and explicitly killed because they
either regressed a real benign scenario or added no measurable detection power. That process, and
the full results/ablation tables, are written up in our research repo, not this one (kept separate
because this repo mirrors the organizer's own):
[`Daehkcarc-sys/Indaba`](https://github.com/Daehkcarc-sys/Indaba) — start with
`SENTINEL_RESEARCH_V2_ARCHITECTURE.md` (includes the v3 addendum with the latest results) and
`SENTINEL_RESEARCH_PHASE8_VALIDATION.md` (the falsification methodology).

**Tests:** `tests/unit/test_authority_core.py`, `test_authority_core_v2.py`, `test_authority_core_v3.py`
(54 tests). Run with `uv run pytest tests/unit/test_authority_core*.py -q`.

**Known open items** (see the research repo for detail): live Qwen3-8B validation is thin because of
a known tool-schema adapter bug (`qwen_eval/quantized_adapter.py`, not in this repo); the
decision-relevant BLOCK upgrade is implemented and unit-tested but never actually fires anywhere in
the real 36-scenario corpus, so it shouldn't be oversold as a proven detector; goal-declared object
consistency is only demonstrated in the SOC domain so far. No video or final technical report has
been produced yet — that's the next work.

---


SENTINEL is a research challenge for IndabaX Tunisia. Each team builds **one defense solution** —
built however they choose — that lets a tool-using LLM agent finish legitimate work while an
adversary manipulates its environment, plus an **observability layer** that makes the defense's
decisions legible.

It is not a prompt-injection classifier contest, and it is not a hidden-test competition. Every
scenario, attack family, and rule is published up front. SENTINEL is not a hidden-test competition:
the attacks are known; the challenge is to show how creatively, rigorously, and effectively you can
engineer an AI agent that survives them.

- Fully offline, synthetic data only (fictional people, organizations, accounts, and domains).
- Official reference agent: a preconfigured **Qwen3-8B** (`Qwen/Qwen3-8B`), run locally through this
  simulator. No required architecture, language, or interface for your defense.
- Deterministic: the same seed produces byte-identical event logs, so your own replays and report
  numbers are reproducible.
- Scoring is jury-judged from your video, observability layer, technical report, and GitHub
  repository — not an automated benchmark. See [docs/scoring.md](docs/scoring.md).

## Architecture

This repository is the simulator and reference tooling SENTINEL provides to every team: the
synthetic world, the attack mechanism that puts pressure on a scenario, the reference agent, and
local self-test commands. It is scaffolding for building and demonstrating your defense, not a
pipeline your submission is required to plug into or be judged by.

```mermaid
flowchart LR
    S[Scenario YAML<br/>+ fixture + policy] --> R[Simulator runner]
    R --> A[Reference agent]
    M[ModelAdapter<br/>mock / Qwen3-8B] --> A
    A -- candidate action --> D{Your defense solution}
    D -- allow / block / escalate / rewrite --> A
    A -- escalate --> H[Simulated human]
    A -- approved tool call --> G[Tool gateway]
    G --> W[(Synthetic world state<br/>enterprise / finance / SOC)]
    X[Scenario attack<br/>static / mutation] -- mutation --> V[Mutation validator]
    V -- declared surfaces only --> W
    A --> L[(Append-only JSONL events)]
    L --> OBS[Your observability layer]
```

The "scenario attack" is internal simulator machinery that puts pressure on a scenario the way the
threat model describes it (see [docs/threat-model.md](docs/threat-model.md)) — it is not something
you build; your only required deliverable on the attack side of things is the defense that survives
it, plus the observability layer that shows how. Details: [docs/architecture.md](docs/architecture.md).

## Quick start

Requires [uv](https://docs.astral.sh/uv/). Python 3.12 is installed by uv if needed.

```bash
uv sync                 # or: make setup
make test               # unit + integration + security tests, then starter-kit tests
make run-baseline       # one scenario with the provenance baseline, printed as a timeline
```

Every command runs offline. The mock model needs no downloads; running the reference Qwen3-8B agent
needs `uv sync --extra hf` and the weights downloaded ahead of time.

## Run a baseline

```bash
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense allow_all
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense provenance
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml --defense provenance --model qwen3-8b
uv run sentinel replay artifacts/<eval-group>/<run_id>.jsonl
```

Baselines: `allow_all`, `deny_sensitive`, `keyword`, `heuristic_risk`, `provenance`. `--model` selects
the reference agent's underlying model (`mock` by default, or `qwen3-8b`); `mock` is fast for
iterating on your decision logic, `qwen3-8b` is what your video and trace should be built on.

## Build your defense

```bash
cp -r starter-kits/python-defense ../my-defense   # or: cp -r starter-kits/learned-monitor ../my-defense
# edit the decision logic
cd ../my-defense && uv venv && uv pip install -r requirements.txt && uv run uvicorn app.main:app --port 8080
```

Then, from this repository, run it against the reference agent and record the trace your video and
report are built around:

```bash
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b
uv run sentinel replay artifacts/<run_id>.jsonl
```

See [docs/participant-guide.md](docs/participant-guide.md) and the starter kits:
[python-defense](starter-kits/python-defense) and [learned-monitor](starter-kits/learned-monitor).
Both are optional scaffolding for the one required deliverable: your defense solution and its
observability layer. Nothing here requires you to expose your defense as an HTTP service — build it
however you choose and wire your own observability layer around it.

## Self-test tooling

These commands are for your own development and evidence-gathering. There is no automated official
score; judges assess your submitted work against the published rubric:

| Command | What it does |
| --- | --- |
| `sentinel scenarios validate PATH` | Schema, fixture, policy, tool, and surface checks (`--json`) |
| `sentinel scenarios list PATH` | Scenario inventory (`--json`) |
| `sentinel run --scenario PATH --defense MODE [--model mock\|qwen3-8b]` | One scenario with timeline and artifact |
| `sentinel eval public --defense MODE\|--defense-url URL` | Metrics across the published scenario library, for your own report |
| `sentinel replay ARTIFACT` | Human-readable timeline (`--json`) — this is the evidence your video and report cite |
| `sentinel submission validate PATH_OR_IMAGE [--live-url URL]` | Optional static/contract checks, useful if you containerize |
| `sentinel fixtures generate [--scenarios]` | Regenerate deterministic fixtures and scenarios |
| `sentinel serve defense` | Local baseline-defense service, useful for development |

The metrics `sentinel eval` reports (BTU, ASR, CVR, FBR, UER, ...) are defined in
[docs/scoring.md](docs/scoring.md) and are good evidence for your technical report's results section
— they are not how judges score your submission. Judges score from your video, observability layer,
technical report, and repository against the published rubric.

## Repository map

```
src/sentinel/
  core/        provenance, actions, events, scenarios, world state, canaries, policies, results
  models/      ModelAdapter interface, deterministic MockModelAdapter, HF adapter (Qwen3-8B default)
  agent/       reference agent loop, memory, plan templating
  tools/       tool base class, registry (no network capability), gateway
  domains/     enterprise, finance, soc synthetic tools
  defenses/    Defense interface, HTTP client with fail modes, five baselines
  attackers/   internal scenario-attack mechanism: mutation validator, static and mutation baselines
  evaluator/   runner, labels, task/policy graders, leak detection, metrics, replay
  api/         FastAPI defense app (optional local development tooling)
  sandbox/     optional static validation of a defense directory or image
  storage/     JSONL run artifacts
scenarios/     the full published scenario library
fixtures/      synthetic world data per domain
policies/      machine-readable policy per domain
starter-kits/  python-defense, learned-monitor (optional scaffolding)
scripts/       fixture/scenario generators, submission validation
tests/         unit, integration, security
docs/          architecture, guides, threat and security models, scoring, authoring, report template
```

## Developer commands

`make setup`, `make lint`, `make format`, `make typecheck`, `make test`, `make test-security`,
`make test-kits`, `make run-baseline`, `make eval-public`, `make scenarios`, `make fixtures`,
`make schema`.

## Documentation

- [Architecture](docs/architecture.md)
- [Participant guide](docs/participant-guide.md)
- [Threat model](docs/threat-model.md)
- [Security model](docs/security-model.md)
- [Scoring](docs/scoring.md)
- [Scenario authoring](docs/scenario-authoring.md)
- [Research report template](docs/research-report-template.md)
- [Security policy](SECURITY.md)

## Important dates

Challenge release **17/09**, info session **18/09** (time TBA), submission deadline **22/09 23:59**.
Questions: **skander.yacoubi@supcom.tn**.

## License

Apache-2.0. See [LICENSE](LICENSE).
