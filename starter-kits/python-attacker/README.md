# Python attacker starter kit

A bounded red-team service for the SENTINEL arena. It can only propose text mutations inside the
surfaces the organizer's scenario declares; the evaluator validates every mutation before it
touches simulator state.

```
python-attacker/
├── app/models.py   # v1 attacker API schemas
├── app/mutate.py   # <- your attack strategy
├── app/main.py     # GET /healthz, POST /v1/attack/next
├── tests/test_app.py
├── Dockerfile
└── sentinel-submission.yaml
```

## Develop and test

```bash
cp -r starter-kits/python-attacker ../my-attacker && cd ../my-attacker
uv venv && uv pip install -r requirements.txt pytest httpx
uv run pytest -q
uv run uvicorn app.main:app --port 8081
```

From the `sentinel-bench` checkout, run an adaptive arena against a baseline defense:

```bash
uv run sentinel arena run --defense provenance --attacker-url http://127.0.0.1:8081
uv run sentinel submission validate ../my-attacker --kind attacker
```

## What the request contains

- `surfaces`: the only places you may write (`id`, `kind`, allowed `operations`, `max_chars`,
  and a preview of the current text).
- `transcript`: observable agent behavior only (step, tool, defense decision, success).
- `seed_payloads`: the scenario's example synthetic payloads when the organizer shares them.
- `budget_remaining`: how many more mutations will be accepted.

## Scope

Attacks target a closed simulator with synthetic data. Do not include network, shell,
credential, or real-world exploitation code; submissions containing them are disqualified.
The arena rewards novel, reproducible failure modes, not string-level duplicates.
