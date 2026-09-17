# Organizer guide

SENTINEL is jury-judged: there is no official automated benchmark, hidden scenario split, or
leaderboard to run before the event. This guide covers preparing the repository and starter kits,
running the info session, and judging submissions.

## 1. Bootstrap

```bash
git clone <sentinel-bench> && cd sentinel-bench
uv sync
make test            # must pass before release
make run-baseline    # sanity check the reference agent and a baseline defense
```

## 2. Publish the scenario library

Everything is published up front — there is no held-out split and no surprise scenario. Before
release:

```bash
uv run sentinel scenarios validate scenarios/public
make test-kits        # starter kits still pass their own tests
make docker-build     # optional: starter-kit images still build
```

If you add or edit scenarios, follow [scenario-authoring.md](scenario-authoring.md) and confirm each
one satisfies the three properties it describes (task succeeds under `allow_all --attacker none`,
attack succeeds under `allow_all`, a sensible defense can stop the attack without failing the task).

## 3. Prepare the reference model

The official reference agent is a preconfigured **Qwen3-8B** (`Qwen/Qwen3-8B`), run locally via
`HFModelAdapter`. Confirm the weights are downloadable ahead of time
(`uv sync --extra hf && huggingface-cli download Qwen/Qwen3-8B`) and that
`uv run sentinel run --scenario ... --defense provenance --model qwen3-8b` works on the machines
teams will use, or document the compute participants need to run it themselves.

## 4. Run the info session (18/09)

Walk through: the three synthetic domains, the attack families and difficulty levels
([threat-model.md](threat-model.md)), the Defense Rules and four actions
([participant-guide.md](participant-guide.md)), the reference model, the starter kits, and the
scoring rubric ([scoring.md](scoring.md)). Publish the submission link to registered participants
and restate the deadline: **22/09 23:59**.

## 5. Judging a submission

There is no build-and-rerun step required for judging — the deliverable is the video, the
observability layer, the technical report, and the repository, read and watched as submitted. Per
team:

1. Watch the video demonstration (5–10 minutes): does the attack genuinely reach the defense, is the
   trace legible, does a benign task still complete, and is the defense precise (no needless
   blocking or escalation)?
2. Read the technical report: hypothesis, threat model, method, at least one ablation, and a concrete
   failure analysis.
3. Read the repository: does the code match what the report and video claim? Is it organized and
   readable end to end?
4. Score against the rubric in [scoring.md](scoring.md) (40 / 25 / 15 / 20).

Optional, if you want independent confirmation of a claim in the video or report:

```bash
cp -r submissions/team-a ../team-a-defense
cd ../team-a-defense && <follow the team's own setup instructions>
# from sentinel-bench:
uv run sentinel run --scenario scenarios/public/<the scenario they demonstrated> \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b
uv run sentinel replay artifacts/<run_id>.jsonl
```

This is a spot-check, not a re-scoring mechanism — nothing it produces overrides the rubric score.

## 6. Winners

The eight highest-scoring submissions are announced on event day and invited to pitch their solution
live. Three winners are selected from among the teams that pitch.

## 7. Sandbox and self-test tooling (optional)

If a team's defense is a container and you want to sanity-check it in isolation,
[security-model.md](security-model.md) documents the hardened `docker run` flags
`sentinel.sandbox` produces (`--network none`, `--read-only`, `--cap-drop ALL`, non-root, resource
limits). None of this is required of participants; it is here if you or a team want it.

## Open organizer decisions

- Judging panel composition and how ties for the eighth pitch slot are broken.
- Whether/how to verify the AgentDojo bonus-track results a team reports.
- Compute made available for teams who cannot run Qwen3-8B locally.
- Exact info-session time and pitch-day logistics.
- Disclosure procedure for any infrastructure vulnerability reported during the challenge.
