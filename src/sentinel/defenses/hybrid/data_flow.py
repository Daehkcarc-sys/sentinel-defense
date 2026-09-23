"""Phase-5 CaMeL-inspired sensitive data-flow lineage in shadow mode.

This layer answers a different question from Phase 4's evidence grounding:

    *Phase 4*: where did an operational argument come from?
    *Phase 5*: where is sensitive data flowing, and through which transformation?

The implementation deliberately stays narrow and falsifiable. It tracks only
CONFIDENTIAL/RESTRICTED source atoms visible through request provenance, propagates
those labels into candidate action payloads, and records a field-addressable flow
edge when the same atom (or one supported encoding transform) reaches a sink.

It does not grant authority and does not change the delegated Authority-Core v3
decision. Phase 5 is observation-only so we can measure whether lineage adds
useful signal before considering enforcement.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

from sentinel.core.actions import ActionType
from sentinel.core.provenance import Sensitivity, SourceType, TrustLevel
from sentinel.defenses.hybrid.transforms import FlowTransformation, match_transformation
from sentinel.defenses.interface import DefenseRequest
from sentinel.defenses.provenance_index import build_source_index

# Sensitive benchmark values are deliberately canary-like/opaque. Requiring a
# reasonably long contiguous atom avoids treating short contextual values such
# as SRV-22 as "restricted data" merely because they share a restricted record.
_OPAQUE_ATOM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_@.+:/=-]{15,}")
_EMAIL_TOOLS = frozenset({"email_draft", "email_send"})


class DataFlowDisposition(StrEnum):
    """Shadow-only classification of sensitive movement for one candidate."""

    NO_SENSITIVE_FLOW = "no_sensitive_flow"
    OBSERVED_ALLOWED_FLOW = "observed_allowed_flow"
    REVIEW_RESTRICTED_FLOW = "review_restricted_flow"
    REVIEW_SENSITIVE_TO_UNTRUSTED = "review_sensitive_to_untrusted"


@dataclass(frozen=True)
class DataFlowEdge:
    """One field-addressable sensitive source -> sink lineage edge.

    Raw secret values are intentionally never stored in research state.
    """

    source_digest: str
    source_field: str
    source_sensitivity: Sensitivity
    source_trust: TrustLevel
    source_types: tuple[SourceType, ...]
    provenance_ids: tuple[str, ...]
    sink: str
    sink_field: str
    destination_trust: TrustLevel
    transformation: FlowTransformation


@dataclass(frozen=True)
class DataFlowAssessment:
    """Sensitive data-flow graph snapshot for one candidate action."""

    run_id: str
    turn_index: int
    step_id: int
    action_digest: str
    tool: str | None
    sink: str
    destination_trust: TrustLevel
    disposition: DataFlowDisposition
    reason_codes: tuple[str, ...]
    edges: tuple[DataFlowEdge, ...]
    shadow_only: bool = True
    graph_version: str = "phase5-flow-v1"


@dataclass(frozen=True)
class SensitiveSourceAtom:
    value: str
    digest: str
    field_path: str
    sensitivity: Sensitivity
    trust: TrustLevel
    source_types: tuple[SourceType, ...]
    provenance_ids: tuple[str, ...]


@dataclass(frozen=True)
class _SinkPart:
    field_path: str
    text: str


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _atoms_from_leaf(value: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_OPAQUE_ATOM.findall(value)))


def sensitive_source_atoms(request: DefenseRequest) -> tuple[SensitiveSourceAtom, ...]:
    """Extract sensitive atoms from the shared field-addressable source index."""
    atoms: list[SensitiveSourceAtom] = []
    for field in build_source_index(request).fields:
        if field.role != "tool":
            continue
        if field.sensitivity.rank < Sensitivity.CONFIDENTIAL.rank:
            continue
        for atom in _atoms_from_leaf(field.text):
            atoms.append(
                SensitiveSourceAtom(
                    value=atom,
                    digest=_digest(atom),
                    field_path=field.field_path,
                    sensitivity=field.sensitivity,
                    trust=field.trust_level,
                    source_types=field.source_types,
                    provenance_ids=field.provenance_ids,
                )
            )

    # The same sensitive atom can appear in multiple fields/sources; preserve
    # those distinct lineage edges but remove exact duplicates.
    return tuple(dict.fromkeys(atoms))


def _destination_trust(request: DefenseRequest) -> tuple[str, TrustLevel]:
    action = request.candidate_action

    if action.type is ActionType.RESPOND:
        return "user_response", TrustLevel.AUTHENTICATED_USER
    if action.type is ActionType.MEMORY_WRITE:
        return "memory", TrustLevel.TRUSTED_INTERNAL
    if action.type is ActionType.REQUEST_CONFIRMATION:
        return "human_confirmation", TrustLevel.AUTHENTICATED_USER
    if action.type is not ActionType.TOOL_CALL or action.tool is None:
        return "none", TrustLevel.TRUSTED_INTERNAL

    if action.tool in _EMAIL_TOOLS:
        recipient = str(action.arguments.get("to", "")).lower()
        internal_domains = [
            str(domain).lower() for domain in request.policy_context.get("internal_email_domains", [])
        ]
        internal = any(recipient.endswith("@" + domain) for domain in internal_domains)
        return action.tool, TrustLevel.TRUSTED_INTERNAL if internal else TrustLevel.UNTRUSTED_EXTERNAL

    return action.tool, TrustLevel.TRUSTED_INTERNAL


def _sink_parts(request: DefenseRequest) -> tuple[_SinkPart, ...]:
    action = request.candidate_action

    if action.type is ActionType.RESPOND:
        return (_SinkPart("response.content", action.content or ""),)
    if action.type is ActionType.MEMORY_WRITE:
        return (_SinkPart("memory.content", action.content or ""),)
    if action.type is ActionType.TOOL_CALL and action.tool is not None:
        return tuple(
            _SinkPart(f"{action.tool}.{name}", str(value))
            for name, value in action.arguments.items()
            if value is not None
        )
    if action.type is ActionType.REQUEST_CONFIRMATION and action.confirmation_for is not None:
        target = action.confirmation_for
        return tuple(
            _SinkPart(f"confirmation.{target.tool}.{name}", str(value))
            for name, value in target.arguments.items()
            if value is not None
        )
    return ()


def assess_data_flow(request: DefenseRequest) -> DataFlowAssessment:
    """Build a shadow sensitive data-flow lineage graph for one candidate action."""
    sink, destination_trust = _destination_trust(request)
    sink_parts = _sink_parts(request)
    edges: list[DataFlowEdge] = []

    for source in sensitive_source_atoms(request):
        for sink_part in sink_parts:
            transformation = match_transformation(source.value, sink_part.text)
            if transformation is None:
                continue
            edge = DataFlowEdge(
                source_digest=source.digest,
                source_field=source.field_path,
                source_sensitivity=source.sensitivity,
                source_trust=source.trust,
                source_types=source.source_types,
                provenance_ids=source.provenance_ids,
                sink=sink,
                sink_field=sink_part.field_path,
                destination_trust=destination_trust,
                transformation=transformation,
            )
            if edge not in edges:
                edges.append(edge)

    if not edges:
        disposition = DataFlowDisposition.NO_SENSITIVE_FLOW
        reasons = ("FLOW_NO_SENSITIVE_LINEAGE",)
    elif any(edge.source_sensitivity is Sensitivity.RESTRICTED for edge in edges):
        disposition = DataFlowDisposition.REVIEW_RESTRICTED_FLOW
        reasons = ("FLOW_RESTRICTED_DATA_MOVED",)
    elif any(
        edge.source_sensitivity.rank >= Sensitivity.CONFIDENTIAL.rank
        and not edge.destination_trust.is_trusted
        for edge in edges
    ):
        disposition = DataFlowDisposition.REVIEW_SENSITIVE_TO_UNTRUSTED
        reasons = ("FLOW_SENSITIVE_TO_UNTRUSTED_DESTINATION",)
    else:
        disposition = DataFlowDisposition.OBSERVED_ALLOWED_FLOW
        reasons = ("FLOW_SENSITIVE_WITHIN_ALLOWED_TRUST_BOUNDARY",)

    action = request.candidate_action
    return DataFlowAssessment(
        run_id=request.run_id,
        turn_index=request.history_digest.turn_index,
        step_id=request.step_id,
        action_digest=action.digest(),
        tool=action.tool,
        sink=sink,
        destination_trust=destination_trust,
        disposition=disposition,
        reason_codes=reasons,
        edges=tuple(edges),
    )
