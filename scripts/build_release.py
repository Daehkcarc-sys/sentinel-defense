"""Build the participant-facing release archive and verify it contains no hidden material.

The archive includes source, public and validation scenarios, fixtures, policies, starter kits,
and docs. It never includes private scenarios, competition.yaml, artifacts, or trained weights.

Usage:
  uv run python scripts/build_release.py            # writes dist/sentinel-bench-participant-<version>.tar.gz
  uv run python scripts/build_release.py --check    # verify only, no archive
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE = [
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "pyproject.toml",
    "uv.lock",
    "Makefile",
    ".env.example",
    "docker-compose.yml",
    "competition.example.yaml",
    "docs",
    "src",
    "scenarios/public",
    "scenarios/validation",
    "scenarios/schemas",
    "scenarios/private.example",
    "policies",
    "fixtures",
    "starter-kits",
    "infra",
    "scripts",
    "tests",
]
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "artifacts", "dist", "private"}
EXCLUDED_NAMES = {"competition.yaml", ".env"}
EXCLUDED_SUFFIXES = {".joblib", ".pyc", ".sqlite3"}
PRIVATE_MARKER = re.compile(r"^\s*split:\s*private\s*$|\"split\"\s*:\s*\"private\"", re.MULTILINE)


def collect() -> list[Path]:
    files: list[Path] = []
    for entry in INCLUDE:
        path = ROOT / entry
        candidates = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
        for file in candidates:
            rel = file.relative_to(ROOT)
            if set(rel.parts) & EXCLUDED_PARTS or file.name in EXCLUDED_NAMES or file.suffix in EXCLUDED_SUFFIXES:
                continue
            files.append(file)
    return files


def verify(files: list[Path], root: Path = ROOT) -> list[str]:
    problems = []
    for file in files:
        rel = file.relative_to(root)
        if (
            file.suffix in (".yaml", ".yml", ".json")
            and "tests" not in rel.parts
            and PRIVATE_MARKER.search(file.read_text(errors="ignore"))
        ):
            problems.append(f"{rel}: looks like a private scenario")
    return problems


def version() -> str:
    match = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.MULTILINE)
    return match.group(1) if match else "0.0.0"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    files = collect()
    problems = verify(files)
    if problems:
        print("release verification failed:\n" + "\n".join(f"  - {p}" for p in problems))
        return 1
    print(f"release verification passed ({len(files)} files)")
    if args.check:
        return 0
    args.out.mkdir(parents=True, exist_ok=True)
    archive = args.out / f"sentinel-bench-participant-{version()}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for file in files:
            tar.add(file, arcname=f"sentinel-bench/{file.relative_to(ROOT)}")
    print(f"wrote {archive}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
