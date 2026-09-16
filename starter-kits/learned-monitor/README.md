# Learned monitor starter kit

A deliberately tiny machine-learning defense: logistic regression over hashed action text plus a
few provenance features. It trains in seconds on CPU and shows where a learned model plugs into
SENTINEL. It is **not** state of the art; treat it as scaffolding for your own model.

```
learned-monitor/
├── monitor/features.py   # request JSON -> sparse features (no sentinel dependency)
├── monitor/model.py      # train / save / load / decide with thresholds
├── monitor/dataset.py    # dev-only: label actions by running public scenarios
├── monitor/train.py      # train on public, report validation metrics, save model/monitor.joblib
├── monitor/evaluate.py   # in-process scorecard without HTTP
├── monitor/app.py        # FastAPI service for the container
├── tests/test_monitor.py
├── Dockerfile
└── sentinel-submission.yaml
```

## Train and evaluate (from the sentinel-bench checkout)

```bash
cd starter-kits/learned-monitor
uv run python -m monitor.train          # writes model/monitor.joblib
uv run python -m monitor.evaluate --split validation
uv run pytest -q tests
```

## Serve and evaluate over HTTP

```bash
uv run uvicorn monitor.app:create_app --factory --port 8080
# in another shell, from the repository root:
uv run sentinel eval validation --defense-url http://127.0.0.1:8080
```

## Where to go next

- Replace hashed n-grams with a small encoder and fine-tune on generated trajectories.
- Calibrate `risk_score` (the scorecard reports Brier score and ECE).
- Tune `BLOCK_AT` / `ESCALATE_AT`: blocking legitimate actions costs utility, and unnecessary
  escalations cost precision.
- Train on public data only. Hidden splits use different templates and unseen attack families.
