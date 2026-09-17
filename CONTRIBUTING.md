# Contributing

## Setup

```bash
uv sync
make lint typecheck test
```

All tests are offline. Do not add tests that download models or reach the network.

## Principles

- Keep modules small and typed; `mypy` must pass with the project settings.
- Core simulation logic must stay testable without HTTP or Docker.
- Depend on the seams (`ModelAdapter`, `Defense`, `Attacker`, `Tool`, graders, `ArtifactStore`,
  `SandboxRunner`), not on concrete implementations.
- Synthetic data only: fictional names and `*.example` domains, and no real credentials or personal data.
- Never add tools with network access, real-world exploit code, or anything that requires private reasoning traces.
- Never commit hidden (`split: private`) scenarios; `make release-check` must pass.

## Changes

| Change | Also do |
| --- | --- |
| New or changed scenario | `make scenarios`; regenerate generated ones with `make fixtures`; confirm the attack succeeds with `allow_all` |
| Scenario schema change | `make schema` and update `docs/scenario-authoring.md` |
| New metric or score input | unit tests for the formula and an update to `docs/scoring.md` |
| New tool or domain | policy profile, fixture, registry entry, tool tests, and a docs update |
| API contract change | update `api/schemas.py`, starter kits, `docs/participant-guide.md`, and contract tests |
| Security-relevant change | a regression test in `tests/security` |

## Commit checklist

- [ ] `make lint` and `make typecheck` pass.
- [ ] `make test` passes (including starter kits).
- [ ] `make eval-public` still produces a deterministic digest (run it twice).
- [ ] Docs updated.
