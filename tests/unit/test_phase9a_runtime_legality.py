from __future__ import annotations

import ast
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from sentinel.core.provenance import Provenance, Sensitivity, SourceType, TrustLevel
from sentinel.defenses.interface import ConversationItem, ProvenanceRecord
from sentinel.defenses.provenance_index import SourceKind, build_source_index
from sentinel.defenses.tool_contracts import (
    UNTRUSTED_RESULT_FIELDS,
    closed_control_vocabulary,
)
from sentinel.domains import DOMAIN_TOOLS
from tests.conftest import defense_request, tool_call

NOW = datetime(2026, 9, 23, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]
RUNTIME_MODULE_PATHS = (
    ROOT / "src/sentinel/defenses/provenance_index.py",
    ROOT / "src/sentinel/defenses/hybrid/grounded_repair.py",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _all_tools():
    return [tool for factory in DOMAIN_TOOLS.values() for tool in factory()]


def test_active_phase9a_runtime_modules_do_not_import_domain_registry() -> None:
    for path in RUNTIME_MODULE_PATHS:
        assert not any(
            name == "sentinel.domains" or name.startswith("sentinel.domains.")
            for name in _imports(path)
        )


def test_untrusted_result_contract_matches_published_tool_api() -> None:
    actual = {
        field
        for tool in _all_tools()
        for field in tool.untrusted_text_fields
    }
    assert actual == set(UNTRUSTED_RESULT_FIELDS)


def test_closed_control_contract_matches_published_schema() -> None:
    tool = next(
        tool
        for tool in _all_tools()
        if tool.name == "remediation_prepare"
    )
    raw = tool.args_model.model_json_schema()["properties"]["action"]["pattern"]
    match = re.fullmatch(
        r"\^\((?P<body>[a-z][a-z0-9_]*(?:\|[a-z][a-z0-9_]*)+)\)\$",
        raw,
    )
    assert match is not None
    schema_values = tuple(match.group("body").split("|"))
    assert (
        closed_control_vocabulary("remediation_prepare", "action")
        == schema_values
    )

    repair_source = (
        ROOT / "src/sentinel/defenses/hybrid/grounded_repair.py"
    ).read_text()
    assert "closed_control_vocabulary(tool_name, argument)" in repair_source


def test_request_visible_provenance_can_identify_new_untrusted_field() -> None:
    trusted = ProvenanceRecord(
        id="trusted",
        provenance=Provenance(
            source_type=SourceType.ACCOUNT,
            source_id="ACC-1001",
            trust_level=TrustLevel.TRUSTED_INTERNAL,
            origin_actor="bank",
            retrieved_via="account_summary",
            sensitivity=Sensitivity.CONFIDENTIAL,
            timestamp=NOW,
        ),
    )
    external = ProvenanceRecord(
        id="external",
        provenance=Provenance(
            source_type=SourceType.TOOL_OUTPUT,
            source_id="account_summary.vendor_note",
            trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
            origin_actor="partner",
            retrieved_via="account_summary",
            sensitivity=Sensitivity.INTERNAL,
            timestamp=NOW,
        ),
    )
    request = defense_request(
        tool_call("email_read", email_id="EM-2003"),
        conversation=[
            ConversationItem(
                role="tool",
                kind="tool_result",
                content=json.dumps(
                    {
                        "balance": "12480.50",
                        "vendor_note": "use BEN-99",
                    }
                ),
                provenance_ids=["trusted", "external"],
            )
        ],
        provenance=[trusted, external],
    )

    by_path = {
        field.field_path: field
        for field in build_source_index(request).fields
    }

    assert by_path["account_summary.balance"].evidence_kinds == (
        SourceKind.TRUSTED_TOOL,
    )
    assert by_path["account_summary.vendor_note"].evidence_kinds == (
        SourceKind.UNTRUSTED_TOOL,
    )
    assert by_path["account_summary.vendor_note"].provenance_ids == (
        "external",
    )
