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
6. **Evaluator-only ground truth stays evaluator-only.** Reference plans and legitimacy labels never
   enter defense requests, even though the scenario library itself is fully published. This is what
   lets `sentinel eval` work as an honest self-test rather than something you could accidentally
   hard-code to.

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
| Submissions | Dockerfile non-root `USER`, no `docker.sock`/`--privileged`, manifest schema, secret patterns, escaping symlinks |

## Avoiding accidental hard-coding in self-testing

There is no held-out scenario split in this challenge — everything under `scenarios/` is published.
That makes it easy to unintentionally overfit to the published library while using `sentinel eval` to
iterate. Per the Defense Rules ([participant-guide.md](participant-guide.md)), a decision must come
from the agent state, candidate action, provenance, policy, and observed content — never from a
scenario id, filename, or canary format. Judges reading your report and code will look for this; a
private `SandboxRunner`/`--scenarios` split (as `scripts/generate_public_scenarios.py` and
`sentinel scenarios validate` still support) is a reasonable way to sanity-check your own defense
against scenarios it did not see while you were tuning it, but it changes nothing about how you are
scored.

## Data handling

Artifacts contain only synthetic data. They are safe to include in your repository or technical
report as evidence for your video's trace.

## Responsible disclosure

See [SECURITY.md](../SECURITY.md). Report vulnerabilities in the platform privately to the organizers;
do not test them against shared infrastructure.
