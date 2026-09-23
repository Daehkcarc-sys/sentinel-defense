"""Run the full scenario corpus against real Qwen3-8B (ollama:qwen3:8b): first the organizer's
mandated allow_all sanity check per attack scenario, then authority_core_v3_full against every
scenario that's valid to demonstrate. Shells out to `sentinel run` per scenario (robust, matches
exactly what a human would run) and writes a JSON results summary as it goes, so progress survives
a crash/interrupt.

Usage: uv run python scripts/qwen_full_corpus_run.py [--limit N]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "artifacts" / "qwen_full_corpus_results.json"
MODEL = "ollama:qwen3:8b"


def run_one(scenario: Path, defense: str) -> dict:
    cmd = [
        "uv", "run", "sentinel", "run",
        "--scenario", str(scenario),
        "--defense", defense,
        "--model", MODEL,
        "--artifacts", "artifacts/qwen_full_corpus",
        "--json",
    ]
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=240)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "elapsed_s": round(time.time() - t0, 1)}
    elapsed = round(time.time() - t0, 1)
    if proc.returncode != 0:
        return {"error": (proc.stdout + proc.stderr)[-2000:], "elapsed_s": elapsed}
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return {"error": "unparseable output: " + proc.stdout[-1000:] + proc.stderr[-1000:], "elapsed_s": elapsed}
    outcome = data.get("outcome", {})
    return {
        "task_success": outcome.get("task_success"),
        "attack_success": outcome.get("attack_success"),
        "critical_violation": outcome.get("critical_violation"),
        "attack_present": outcome.get("attack_present"),
        "elapsed_s": elapsed,
        "artifact": data.get("artifact"),
    }


def load_results() -> dict:
    if RESULTS.exists():
        return json.loads(RESULTS.read_text())
    return {}


def save_results(results: dict) -> None:
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(json.dumps(results, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--defense", default="authority_core_v3_full")
    args = parser.parse_args()
    defense_key = args.defense

    scenarios = sorted(
        list((ROOT / "scenarios" / "public").rglob("*.yaml"))
        + list((ROOT / "scenarios" / "validation").rglob("*.yaml"))
        + list((ROOT / "scenarios" / "self_authored").rglob("*.yaml"))
    )
    if args.limit:
        scenarios = scenarios[: args.limit]

    results = load_results()
    total = len(scenarios)
    for i, scenario in enumerate(scenarios, 1):
        sid = scenario.stem
        if sid not in results:
            results[sid] = {}
        entry = results[sid]

        # Determine attack-present-ness cheaply by reading the YAML's own attack.present flag.
        import yaml

        spec = yaml.safe_load(scenario.read_text())
        attack_present = bool(spec.get("attack", {}).get("present"))
        entry["attack_present_declared"] = attack_present

        if attack_present and "allow_all" not in entry:
            print(f"[{i}/{total}] {sid}: allow_all sanity check...", flush=True)
            entry["allow_all"] = run_one(scenario, "allow_all")
            save_results(results)

        valid_for_live = (not attack_present) or entry.get("allow_all", {}).get("attack_success") is True
        entry["valid_for_live_demo"] = valid_for_live

        if defense_key not in entry:
            if valid_for_live:
                print(f"[{i}/{total}] {sid}: {defense_key}...", flush=True)
                entry[defense_key] = run_one(scenario, defense_key)
            else:
                entry[defense_key] = {"skipped": "allow_all did not reach attack_success=True on this hardware"}
            save_results(results)

    # Summary
    benign = [e for e in results.values() if not e["attack_present_declared"]]
    attacks_valid = [e for e in results.values() if e["attack_present_declared"] and e["valid_for_live_demo"]]
    attacks_invalid = [e for e in results.values() if e["attack_present_declared"] and not e["valid_for_live_demo"]]

    btu_hits = sum(1 for e in benign if e.get(defense_key, {}).get("task_success") is True)
    dsr_hits = sum(1 for e in attacks_valid if e.get(defense_key, {}).get("attack_success") is False)
    crit = sum(1 for e in results.values() if e.get(defense_key, {}).get("critical_violation") is True)

    print(f"\n=== SUMMARY ({defense_key}) ===")
    print(f"benign scenarios: {len(benign)}, live BTU = {btu_hits}/{len(benign)} = {btu_hits/max(1,len(benign)):.3f}")
    print(f"attack scenarios valid on this hardware: {len(attacks_valid)}/{len(attacks_valid)+len(attacks_invalid)}")
    print(f"live DSR (of valid attacks) = {dsr_hits}/{len(attacks_valid)} = {dsr_hits/max(1,len(attacks_valid)):.3f}")
    print(f"critical violations ({defense_key}, live): {crit}")
    print(f"invalid-on-this-hardware attack scenarios: {[k for k,e in results.items() if e['attack_present_declared'] and not e['valid_for_live_demo']]}")


if __name__ == "__main__":
    main()
