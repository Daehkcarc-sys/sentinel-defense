from __future__ import annotations

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _report_module():
    return runpy.run_path(str(ROOT / "scripts/render_report.py"))


def test_all_production_hybrid_reason_codes_have_plain_language_explanations() -> None:
    module = _report_module()
    explanations = module["REASON_CODE_EXPLANATIONS"]

    expected = {
        "HYBRID_RESTRICTED_FLOW_REDACTED",
        "HYBRID_GROUNDED_CONTROL_REPAIR",
        "HYBRID_UNTRUSTED_CONTROL_SELECTOR",
        "HYBRID_UNTRUSTED_OPERATIONAL_EXPANSION",
        "HYBRID_ATTACKER_SELECTED_SENSITIVE_SINK",
        "HYBRID_REWRITE_FAILED_VALIDATION",
        "HYBRID_CONTROL_REPAIR_FAILED_VALIDATION",
    }
    assert expected <= set(explanations)


def test_recovery_story_exposes_core_hybrid_and_final_layers() -> None:
    module = _report_module()
    html = module["decision_path_html"](
        ["HYBRID_RESTRICTED_FLOW_REDACTED"],
        "rewrite",
    )

    assert "Authority Core" in html
    assert "Hybrid intervention" in html
    assert "Final decision" in html
    assert "restricted disclosure" in html
    assert "deterministic redaction" in html
    assert "REWRITE" in html


def test_grounded_repair_story_is_explicit() -> None:
    module = _report_module()
    html = module["decision_path_html"](
        ["HYBRID_GROUNDED_CONTROL_REPAIR"],
        "rewrite",
    )

    assert "ALLOW" in html
    assert "unique independently grounded legal alternative" in html
    assert "REWRITE" in html


def test_non_hybrid_decision_does_not_invent_an_intervention() -> None:
    module = _report_module()
    html = module["decision_path_html"](
        ["STRUCTURALLY_AUTHORIZED"],
        "allow",
    )

    assert "No Hybrid intervention" in html
    assert "ALLOW" in html


def test_dashboard_uses_production_name_and_non_overclaiming_status() -> None:
    dashboard = runpy.run_path(str(ROOT / "scripts/render_dashboard.py"))

    assert dashboard["status_label"](
        {
            "attack_present": True,
            "attack_success": False,
            "task_success": True,
        }
    ).startswith("attack did not succeed")

    source = (ROOT / "scripts/render_dashboard.py").read_text()
    assert "SENTINEL Hybrid" in source
    assert "authority_core_v3_full" not in source


def test_illegitimate_rewrite_is_labeled_neutralized() -> None:
    module = _report_module()
    assert module["evaluator_action_verdict"]("rewrite") == "neutralized by rewrite"
    assert module["evaluator_action_verdict"]("block") == "blocked"
    assert module["evaluator_action_verdict"]("allow") == "allowed"


def test_restricted_display_value_is_masked_without_mutating_source() -> None:
    module = _report_module()
    secret = "example-restricted-value"
    source_text = f"before {secret} after"
    masked = module["mask_restricted_for_display"](source_text, [secret])
    assert secret not in masked
    assert "[MASKED RESTRICTED VALUE]" in masked
    assert secret in source_text


def test_grounded_repair_stale_narration_is_detected() -> None:
    module = _report_module()
    repairs = [("action", "disable_monitoring", "block_domain")]
    stale = module["stale_repair_narration"](
        "The prepared action was disable monitoring.",
        repairs,
    )
    clean = module["stale_repair_narration"](
        "The prepared action was block domain.",
        repairs,
    )
    assert stale == ("action", "disable_monitoring", "block_domain")
    assert clean is None


def test_successfully_handled_attack_uses_positive_dashboard_dot() -> None:
    dashboard = runpy.run_path(str(ROOT / "scripts/render_dashboard.py"))
    assert dashboard["status_dot"](
        {
            "attack_present": True,
            "attack_success": False,
            "task_success": True,
            "critical_violation": False,
        }
    ) == "allow"
