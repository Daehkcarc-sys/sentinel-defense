# SENTINEL research report template

Length: 4–6 pages excluding references and appendix. Report component metrics, not only the official score.
Include the benchmark version and scorecard digests you cite.

## 1. Abstract

100–200 words: the problem, your method, the main quantitative result (BTU, ASR, CVR, FBR on validation),
and the most important limitation.

## 2. Threat model

- Which attack families and surfaces does your defense target?
- What does the adversary know (payloads, your decisions, adaptivity)?
- What is explicitly out of scope?

## 3. Hypothesis

One or two falsifiable statements, for example: "Tracking which untrusted sources influenced an action's
arguments reduces ASR on indirect injection by at least half with less than 5% FBR."

## 4. Method

- Architecture diagram: where the defense sits (input, planning, retrieval, memory, tool authorization, output).
- Signals used (provenance, action structure, model internals, history) and how decisions are made.
- Training data, objectives, and hyperparameters for any learned component.
- How `risk_score` and `confidence` are produced and calibrated; when you escalate and when you rewrite.

## 5. Experiments

- Splits used (public for development, validation for reporting); never train on validation.
- Models, hardware, seeds, `competition.yaml` values, and benchmark version.
- Baselines compared: at least `allow_all`, `provenance`, and one other.

## 6. Results

| Defense | BTU | ASR | CVR | FBR | UER | TUI | DFI | Brier | ECE | p95 ms | Official |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| allow_all | | | | | | | | | | | |
| provenance | | | | | | | | | | | |
| ours | | | | | | | | | | | |

Also break results down by domain and attack family, and add arena results if applicable.

## 7. Ablations

Remove or modify at least one major component. Report the metric deltas and what they imply about the hypothesis.

## 8. Failure analysis

Concrete failure categories with replay excerpts (`sentinel replay`): missed attacks, false blocks,
unnecessary escalations, and calibration errors. Explain the root cause of each category.

## 9. Responsible AI and security considerations

- What the defense protects against and its known failure modes.
- Expected false-positive behavior and who bears its cost.
- What data the defense observes and whether any user content is stored.
- When humans should be consulted; how explanations and reason codes are generated.
- Performance differences across domains.
- Misuse risks of your attacker component outside the sandbox, and mitigations.

## 10. Reproducibility

- Repository commit, image digest, and `sentinel-submission.yaml`.
- Exact commands to build, test, and evaluate, for example:

```bash
docker build -t team-x/defense:final .
uv run sentinel submission validate team-x/defense:final
uv run sentinel eval validation --defense-url http://127.0.0.1:8080 --json > results/validation.json
```

- Declared external models and datasets, with licenses.
- Deterministic digests of the scorecards you report.
