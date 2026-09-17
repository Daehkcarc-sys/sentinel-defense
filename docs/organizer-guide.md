# Organizer guide

## 1. Bootstrap

```bash
git clone <sentinel-bench> && cd sentinel-bench
uv sync
make test            # must pass on the evaluation host
make eval-public     # deterministic scorecard
cp competition.example.yaml competition.yaml   # git-ignored; edit before the event
```

## 2. Decide and freeze configuration

Open decisions are listed at the end of this guide. Record them in `competition.yaml`; set
`scoring.final: true` only when weights are published. Every scorecard reports `benchmark_version` and
`config_final`.

## 3. Prepare hidden scenarios

1. Create a private repository (for example `sentinel-private`) with `scenarios/` and, if needed, extra fixtures.
2. Author scenarios with `split: private` ([scenario-authoring.md](scenario-authoring.md)): vary templates,
   hold out whole attack families, compose known primitives, add benign distractors and hard negatives, and
   emphasize difficulty levels 3–5.
3. Validate and smoke-test on the evaluation host only:

```bash
export SENTINEL_PRIVATE_SCENARIOS=/secure/sentinel-private/scenarios
uv run sentinel scenarios validate "$SENTINEL_PRIVATE_SCENARIOS"
uv run sentinel eval private --defense allow_all --artifacts /secure/artifacts    # attacks must succeed
uv run sentinel eval private --defense deny_sensitive --artifacts /secure/artifacts   # utility should drop clearly
```

Private fixtures referenced by private scenarios must live under the benchmark root (for example a
git-ignored `fixtures/private/` mounted at run time), because fixture paths are resolved inside the root.

## 4. Participant release

```bash
make release-check   # fails if any file declares split: private
make release         # dist/sentinel-bench-participant-<version>.tar.gz
```

The release contains source, public and validation scenarios, fixtures, policies, starter kits, docs, and
tests. It excludes `competition.yaml`, artifacts, trained weights, and anything under a `private` directory.

## 5. Services

Local stack (organizer image, baseline services on an internal network, leaderboard on localhost):

```bash
make docker-build
export SENTINEL_ADMIN_TOKEN=$(openssl rand -hex 24)
docker compose up -d baseline-defense baseline-attacker leaderboard
docker compose --profile eval run --rm evaluator
```

Leaderboard API (writes need `Authorization: Bearer $SENTINEL_ADMIN_TOKEN`):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | HTML leaderboard |
| GET | `/api/submissions` | aggregate results as JSON |
| POST | `/api/submissions` | create `{name, benchmark_version, split}` (queued) |
| POST | `/api/submissions/{id}/status` | `{status: queued\|running\|succeeded\|failed, error?}` |
| POST | `/api/submissions/{id}/result` | upload `{metrics, score}`; any per-scenario data is ignored |

Or record directly from the CLI: `sentinel eval private ... --record-db /var/lib/sentinel/leaderboard.sqlite3 --submission-name team-a`.

`infra/systemd/` contains example units for a single-host deployment.

## 6. Evaluating a submission

```bash
# 1. static checks on the source directory
uv run sentinel submission validate /submissions/team-a/defense
# 2. build (network allowed only during build, on an isolated builder)
docker build -t sentinel-sub/team-a-defense:r1 /submissions/team-a/defense
uv run sentinel submission validate sentinel-sub/team-a-defense:r1
# 3. run hardened on an internal network, then contract-test and evaluate
docker network create --internal sentinel-internal
docker run -d --rm --name team-a-defense --network sentinel-internal --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m --cap-drop ALL --security-opt no-new-privileges:true \
  --user 10001:10001 --memory 2g --memory-swap 2g --cpus 1 --pids-limit 256 sentinel-sub/team-a-defense:r1
uv run sentinel eval private --defense-url http://team-a-defense:8080 --record-db /var/lib/sentinel/lb.sqlite3 \
  --submission-name team-a --artifacts /secure/artifacts --json
```

Run the evaluator inside the same internal network (see `docker-compose.yml`), or use
`sentinel.sandbox.runner.DockerSandboxRunner` with a `SandboxPolicy` from Python to produce the same
hardened command line programmatically. Rebuild finalists from source and compare digests.

## 7. Red-team arena

```bash
uv run sentinel arena run --scenarios /secure/arena-scenarios --defense-url http://team-a-defense:8080 \
  --attacker-url http://team-b-attacker:8080 --json
```

Anonymize target defenses, keep the query budget in `competition.yaml`, replay successful attacks for
confirmation, de-duplicate near-identical payloads, and add validated attacks to a private arena corpus
replayed against all finalists.

## 8. Reproducibility and audit

- Keep JSONL artifacts for every official run; `sentinel replay` renders them.
- Compare `deterministic_digest` across reruns of the same image and config.
- Disable the efficiency multiplier when checking exact score reproduction (latency varies).
- Record `benchmark_version`, `run_seed`, image digests, and `competition.yaml` with each result.

## 9. Pre-launch acceptance checklist

- [ ] `make test`, `make lint`, `make typecheck`, `make release-check` pass on the evaluation host.
- [ ] `make docker-build` succeeds; starter-kit images run with `--network none --read-only --cap-drop ALL`.
- [ ] Hidden scenarios validate, are absent from releases and images, and change rankings versus public.
- [ ] Every hidden task (except direct-instruction ones) succeeds with `allow_all --attacker none`, and every
      hidden attack succeeds with `allow_all`.
- [ ] Blanket or over-restrictive baselines (`deny_sensitive`, `keyword`) lose clearly on hidden data.
- [ ] Scores are deterministic for fixed seeds (digests match on rerun).
- [ ] Fail-closed behavior verified by stopping a defense mid-run.
- [ ] Leaderboard token set, database backed up, only aggregates visible.
- [ ] Responsible disclosure contact published.
- [ ] An internal red-team pilot found no trivial shortcuts (for example, matching canary formats or scenario ids).

## Open organizer decisions

- Official base model(s), and whether the reference agent uses a real model (`HFModelAdapter`) or the mock
  model for the main leaderboard.
- Whether teams may modify the base model on the main leaderboard.
- Resource profiles: memory, CPU, GPU, per-call latency budget, total run timeout.
- Final metric weights, escalation cost, critical penalty, utility gate, and OOD/efficiency settings.
- Team size, submission frequency, and the open-source/IP policy.
- Hidden benchmark size per split (IID, OOD, adaptive arena, hard negatives, long horizon) and domain mix.
- Arena query budget and novelty-scoring rules.
- External API policy and offline model availability.
- Hardware provided to teams, prize categories, report page limit, and the disclosure procedure.
