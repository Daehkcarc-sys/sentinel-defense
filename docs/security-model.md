# Security model

## Principles

1. **Synthetic only.** Every person, organization, account, domain (`*.example`), and secret is fictional.
   Canary values are generated per run from the scenario seed and the run seed.
2. **Offline by construction.** The tool registry refuses any tool that declares a capability outside
   `read`, `write`, `draft`, `message`, `state_change`; there is no `network` capability. Simulator modules
   import no networking or process libraries (enforced by `tests/security/test_offline_and_leaks.py`).
3. **Declared surfaces only.** Attackers change text only where scenarios allow, through one validator.
4. **Observable evidence, not chain-of-thought.** Events record actions, decisions, reason codes,
   provenance, tool traces, and state transitions. Defenses are never asked for private reasoning.
5. **Fail closed.** Defense timeouts, transport failures, bad status codes, and malformed responses block
   the action by default (`defense.fail_mode: closed`).
6. **Hidden material stays hidden.** Plans, labels, and payloads never enter defense requests; private
   scenarios never enter the repository, releases, or images.

## Sandbox

`sentinel.sandbox.policy.SandboxPolicy` is validated before any command is built, and
`sentinel.sandbox.docker.build_run_command` produces:

| Control | Flag |
| --- | --- |
| Non-root | `--user 10001:10001` (uid 0 rejected) |
| No network | `--network none` (official mode allows only `sentinel-internal*` networks; `host`/`bridge` rejected) |
| Memory | `--memory` and `--memory-swap` set to the same value |
| CPU | `--cpus` |
| Processes | `--pids-limit` |
| Filesystem | `--read-only` plus `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=...` |
| Capabilities | `--cap-drop ALL` |
| Privilege escalation | `--security-opt no-new-privileges:true` |
| Model weights | read-only `--volume src:dst:ro` only |
| Docker socket | never mounted; rejected at policy validation and again at command build |
| Host paths | `/`, `/proc`, `/sys`, `/dev`, `/etc`, `/run`, `/var/run`, `/root`, `/home` rejected as mount sources |
| Ports | published only on `127.0.0.1` and only with an internal network |
| Timeout | enforced by the runner (`timeout_s`) |

The unit tests check the generated command lines and do not need a Docker daemon. Organizers should
still run `make docker-build` and a manual `docker run` smoke test on the evaluation host before launch.

## Participant input handling

| Input | Safeguard |
| --- | --- |
| Scenario YAML | `yaml.safe_load` only; 256 KB limit; strict Pydantic models (`extra="forbid"`) |
| Fixture paths | relative, `.json`, no `..`, resolved within the benchmark root (symlink escapes rejected) |
| Policy profiles | name pattern, resolved within `policies/` |
| Defense responses | strict `DefenseDecision` schema, 64 KB limit, no redirects followed, reason code pattern, 4 KB metadata |
| Rewrites | cannot make an action final, cannot name an unknown tool; the policy engine still checks the result |
| Attacker mutations | declared surface, allowed operation, `max_chars`, no control characters, budget |
| Artifact names | sanitized to a single safe path component; files opened in exclusive-create mode |
| Leaderboard | bearer token (constant-time compare) for writes; HTML escaped; aggregates only |
| Submissions | Dockerfile non-root `USER`, no `docker.sock`/`--privileged`, manifest schema, secret patterns, private-scenario markers, escaping symlinks |

## Hidden evaluation hygiene

- Private scenarios are stored outside this repository and passed with `SENTINEL_PRIVATE_SCENARIOS` or
  `--scenarios`; `scenarios/private/` is git-ignored.
- `sentinel scenarios validate` rejects private scenarios found under a `public` directory.
- `scripts/build_release.py` refuses to package any file declaring `split: private`.
- `EvaluationReport.participant_view()` removes per-scenario outcomes and per-domain metrics for private runs;
  the leaderboard stores only aggregate metrics and score.
- Rotate the `run_seed` per official round so canary values change.
- If a hidden case leaks, retire or rotate it, and record the benchmark version with every score.

## Data handling

Artifacts contain only synthetic data, but they reveal hidden scenario content for private runs. Store them
on organizer-controlled storage, and publish only participant views.

## Responsible disclosure

See [SECURITY.md](../SECURITY.md). Report vulnerabilities in the platform privately to the organizers;
do not test them against shared infrastructure.
