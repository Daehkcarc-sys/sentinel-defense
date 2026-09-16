# Private scenarios (example location)

Hidden evaluation scenarios **never** live in this repository or in participant images.

- Store them in a separate private repository or encrypted storage.
- Point the evaluator at them at run time:

  ```bash
  export SENTINEL_PRIVATE_SCENARIOS=/secure/sentinel-private/scenarios
  uv run sentinel scenarios validate "$SENTINEL_PRIVATE_SCENARIOS"
  uv run sentinel eval private --defense-url http://127.0.0.1:8080 --json
  ```

- Private scenarios use the same schema with `split: private`. The validator rejects private
  scenarios found under a `public` directory, and `scripts/build_release.py` refuses to package
  any file that declares `split: private`.
- `scenarios/private/` is git-ignored as a last line of defense if someone copies files locally.
- Private evaluation output (`participant_view`) omits per-scenario outcomes and per-domain
  breakdowns. Keep the full JSONL artifacts on organizer storage only.
