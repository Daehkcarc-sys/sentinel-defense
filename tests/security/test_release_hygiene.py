import runpy
from pathlib import Path

import pytest

from sentinel.core.scenario import Split
from sentinel.evaluator.scenario_checks import check_scenario
from tests.conftest import ROOT, load

pytestmark = pytest.mark.security


def test_gitignore_protects_hidden_material() -> None:
    ignored = (ROOT / ".gitignore").read_text().splitlines()
    for pattern in ("scenarios/private/", "competition.yaml", ".env", "artifacts/"):
        assert pattern in ignored


def test_repository_contains_no_private_scenarios() -> None:
    release = runpy.run_path(str(ROOT / "scripts" / "build_release.py"))
    files = release["collect"]()
    assert release["verify"](files) == []
    assert not any(
        "private" in p.relative_to(ROOT).parts
        for p in files
        if p.relative_to(ROOT).parts[:2] != ("scenarios", "private.example")
    )


def test_release_verification_catches_leaked_private_scenario(tmp_path: Path) -> None:
    release = runpy.run_path(str(ROOT / "scripts" / "build_release.py"))
    leaked = tmp_path / "scenarios" / "public" / "leak.yaml"
    leaked.parent.mkdir(parents=True)
    leaked.write_text("id: hidden_case\nsplit: private\n")
    assert release["verify"]([leaked], tmp_path)


def test_private_scenario_in_public_directory_is_flagged(tmp_path: Path) -> None:
    scenario = load("finance_false_approval").model_copy(update={"split": Split.PRIVATE})
    fake = tmp_path / "scenarios" / "public" / "finance_false_approval.yaml"
    fake.parent.mkdir(parents=True)
    fake.write_text("")
    assert any("must not live under a public" in p for p in check_scenario(scenario, ROOT, fake))
