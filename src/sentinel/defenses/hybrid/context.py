"""Phase-5.5 integration kernel: fuse shadow analyses into typed security facts.

The earlier phases intentionally remained independent while their signals were
falsified.  Phase 5.5 does not add another detector.  It combines the surviving
TaskContract/DRIFT/ARGUS/CaMeL observations into a single ``SecurityContext`` and
explicitly marks cross-layer conjunctions that may be candidates for later,
separately validated enforcement.

No signal in this module changes a defense decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sentinel.defenses.hybrid.data_flow import DataFlowAssessment, DataFlowDisposition
from sentinel.defenses.hybrid.evidence import EvidenceAssessment, GroundingStatus
from sentinel.defenses.hybrid.task_contract import TaskContract
from sentinel.defenses.hybrid.workflow import WorkflowAssessment, WorkflowDisposition
from sentinel.defenses.interface import DefenseRequest
from sentinel.defenses.restricted_match import restricted_payload_hit


class SignalFamily(StrEnum):
    POLICY = "policy"
    OBJECT_SCOPE = "object_scope"
    EVIDENCE = "evidence"
    DATA_FLOW = "data_flow"
    FUSION = "fusion"


class SignalMaturity(StrEnum):
    """Research maturity, not an instruction to the policy kernel."""

    OBSERVE = "observe"
    ADVISE = "advise"
    ENFORCEMENT_CANDIDATE = "enforcement_candidate"


class SignalKind(StrEnum):
    POLICY_OUT_OF_SCOPE = "policy_out_of_scope"
    AUTHENTICATED_RESTRICTION = "authenticated_restriction"
    OBJECT_SCOPE_EXPANSION = "object_scope_expansion"
    CONSEQUENTIAL_REVIEW = "consequential_review"
    UNTRUSTED_ONLY_ARGUMENT = "untrusted_only_argument"
    UNSOURCED_ARGUMENT = "unsourced_argument"
    UNTRUSTED_ECHO = "untrusted_echo"
    RESTRICTED_FLOW = "restricted_flow"
    SENSITIVE_EXTERNAL_FLOW = "sensitive_external_flow"
    UNTRUSTED_OPERATIONAL_EXPANSION = "untrusted_operational_expansion"
    UNTRUSTED_DESTINATION = "untrusted_destination"
    UNTRUSTED_CONTROL_SELECTOR = "untrusted_control_selector"
    ATTACKER_SELECTED_SENSITIVE_SINK = "attacker_selected_sensitive_sink"


@dataclass(frozen=True)
class SecuritySignal:
    kind: SignalKind
    family: SignalFamily
    maturity: SignalMaturity
    layers: tuple[str, ...]
    reason_code: str
    argument: str | None = None
    objects: tuple[str, ...] = ()
    source_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityContext:
    run_id: str
    turn_index: int
    step_id: int
    action_digest: str
    tool: str | None
    contract: TaskContract
    workflow: WorkflowAssessment
    evidence: EvidenceAssessment
    data_flow: DataFlowAssessment
    signals: tuple[SecuritySignal, ...]
    shadow_only: bool = True
    context_version: str = "phase5_5-context-v1"

    def has(self, kind: SignalKind) -> bool:
        return any(signal.kind is kind for signal in self.signals)


def _source_fields_for_grounding(grounding: object) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            edge.field_path
            for edge in getattr(grounding, "edges", ())
            if getattr(edge, "field_path", None)
        )
    )


def _append_unique(signals: list[SecuritySignal], signal: SecuritySignal) -> None:
    if signal not in signals:
        signals.append(signal)


def build_security_context(
    request: DefenseRequest,
    contract: TaskContract,
    workflow: WorkflowAssessment,
    evidence: EvidenceAssessment,
    data_flow: DataFlowAssessment,
) -> SecurityContext:
    """Fuse existing shadow assessments without changing their individual semantics."""
    signals: list[SecuritySignal] = []

    if workflow.disposition is WorkflowDisposition.POLICY_OUT_OF_SCOPE:
        _append_unique(
            signals,
            SecuritySignal(
                SignalKind.POLICY_OUT_OF_SCOPE,
                SignalFamily.POLICY,
                SignalMaturity.ENFORCEMENT_CANDIDATE,
                ("workflow",),
                "CONTEXT_POLICY_OUT_OF_SCOPE",
            ),
        )
    elif workflow.disposition is WorkflowDisposition.EXPLICITLY_RESTRICTED:
        _append_unique(
            signals,
            SecuritySignal(
                SignalKind.AUTHENTICATED_RESTRICTION,
                SignalFamily.POLICY,
                SignalMaturity.ENFORCEMENT_CANDIDATE,
                ("task_contract", "workflow"),
                "CONTEXT_AUTHENTICATED_RESTRICTION",
            ),
        )
    elif workflow.disposition is WorkflowDisposition.REVIEW_OBJECT_EXPANSION:
        _append_unique(
            signals,
            SecuritySignal(
                SignalKind.OBJECT_SCOPE_EXPANSION,
                SignalFamily.OBJECT_SCOPE,
                SignalMaturity.ADVISE,
                ("task_contract", "workflow"),
                "CONTEXT_OBJECT_SCOPE_EXPANSION",
                objects=workflow.foreign_objects,
            ),
        )
    elif workflow.disposition is WorkflowDisposition.REVIEW_CONSEQUENTIAL:
        _append_unique(
            signals,
            SecuritySignal(
                SignalKind.CONSEQUENTIAL_REVIEW,
                SignalFamily.POLICY,
                SignalMaturity.OBSERVE,
                ("workflow",),
                "CONTEXT_CONSEQUENTIAL_REVIEW",
            ),
        )

    untrusted_destination = False
    untrusted_identity_arguments: set[str] = set()

    for grounding in evidence.groundings:
        fields = _source_fields_for_grounding(grounding)
        if grounding.status is GroundingStatus.UNTRUSTED_ONLY:
            _append_unique(
                signals,
                SecuritySignal(
                    SignalKind.UNTRUSTED_ONLY_ARGUMENT,
                    SignalFamily.EVIDENCE,
                    SignalMaturity.ADVISE,
                    ("evidence",),
                    "CONTEXT_UNTRUSTED_ONLY_ARGUMENT",
                    argument=grounding.argument,
                    source_fields=fields,
                ),
            )
            if grounding.value_kind == "identity":
                untrusted_identity_arguments.add(grounding.argument)
            if grounding.value_kind == "destination":
                untrusted_destination = True
                _append_unique(
                    signals,
                    SecuritySignal(
                        SignalKind.UNTRUSTED_DESTINATION,
                        SignalFamily.EVIDENCE,
                        SignalMaturity.ENFORCEMENT_CANDIDATE,
                        ("evidence",),
                        "CONTEXT_UNTRUSTED_DESTINATION",
                        argument=grounding.argument,
                        source_fields=fields,
                    ),
                )
            if grounding.value_kind == "action":
                _append_unique(
                    signals,
                    SecuritySignal(
                        SignalKind.UNTRUSTED_CONTROL_SELECTOR,
                        SignalFamily.FUSION,
                        SignalMaturity.ENFORCEMENT_CANDIDATE,
                        ("evidence",),
                        "CONTEXT_UNTRUSTED_CONTROL_SELECTOR",
                        argument=grounding.argument,
                        source_fields=fields,
                    ),
                )
        elif grounding.status is GroundingStatus.UNSOURCED:
            _append_unique(
                signals,
                SecuritySignal(
                    SignalKind.UNSOURCED_ARGUMENT,
                    SignalFamily.EVIDENCE,
                    SignalMaturity.ADVISE,
                    ("evidence",),
                    "CONTEXT_UNSOURCED_ARGUMENT",
                    argument=grounding.argument,
                ),
            )
        elif grounding.status is GroundingStatus.GROUNDED_WITH_UNTRUSTED_ECHO:
            _append_unique(
                signals,
                SecuritySignal(
                    SignalKind.UNTRUSTED_ECHO,
                    SignalFamily.EVIDENCE,
                    SignalMaturity.OBSERVE,
                    ("evidence",),
                    "CONTEXT_UNTRUSTED_ECHO",
                    argument=grounding.argument,
                    source_fields=fields,
                ),
            )

    if data_flow.disposition is DataFlowDisposition.REVIEW_RESTRICTED_FLOW:
        _append_unique(
            signals,
            SecuritySignal(
                SignalKind.RESTRICTED_FLOW,
                SignalFamily.DATA_FLOW,
                SignalMaturity.ENFORCEMENT_CANDIDATE,
                ("data_flow",),
                "CONTEXT_RESTRICTED_FLOW",
                source_fields=tuple(dict.fromkeys(edge.source_field for edge in data_flow.edges)),
            ),
        )
    elif restricted_payload_hit(
        request,
        request.candidate_action,
        enable_encoded=True,
    ):
        _append_unique(
            signals,
            SecuritySignal(
                SignalKind.RESTRICTED_FLOW,
                SignalFamily.DATA_FLOW,
                SignalMaturity.ENFORCEMENT_CANDIDATE,
                ("restricted_match",),
                "CONTEXT_RESTRICTED_MATCH_FALLBACK",
            ),
        )
    elif data_flow.disposition is DataFlowDisposition.REVIEW_SENSITIVE_TO_UNTRUSTED:
        _append_unique(
            signals,
            SecuritySignal(
                SignalKind.SENSITIVE_EXTERNAL_FLOW,
                SignalFamily.DATA_FLOW,
                SignalMaturity.ENFORCEMENT_CANDIDATE,
                ("data_flow",),
                "CONTEXT_SENSITIVE_EXTERNAL_FLOW",
                source_fields=tuple(dict.fromkeys(edge.source_field for edge in data_flow.edges)),
            ),
        )

    if workflow.foreign_objects and untrusted_identity_arguments:
        matched_objects: list[str] = []
        action = request.candidate_action
        for argument in untrusted_identity_arguments:
            value = action.arguments.get(argument)
            if value is None:
                continue
            matched_objects.extend(obj for obj in workflow.foreign_objects if obj in str(value))
        if matched_objects:
            _append_unique(
                signals,
                SecuritySignal(
                    SignalKind.UNTRUSTED_OPERATIONAL_EXPANSION,
                    SignalFamily.FUSION,
                    SignalMaturity.ENFORCEMENT_CANDIDATE,
                    ("task_contract", "workflow", "evidence"),
                    "CONTEXT_UNTRUSTED_OPERATIONAL_EXPANSION",
                    objects=tuple(dict.fromkeys(matched_objects)),
                ),
            )

    if untrusted_destination and data_flow.disposition in {
        DataFlowDisposition.REVIEW_RESTRICTED_FLOW,
        DataFlowDisposition.REVIEW_SENSITIVE_TO_UNTRUSTED,
    }:
        _append_unique(
            signals,
            SecuritySignal(
                SignalKind.ATTACKER_SELECTED_SENSITIVE_SINK,
                SignalFamily.FUSION,
                SignalMaturity.ENFORCEMENT_CANDIDATE,
                ("evidence", "data_flow"),
                "CONTEXT_ATTACKER_SELECTED_SENSITIVE_SINK",
            ),
        )

    action = request.candidate_action
    return SecurityContext(
        run_id=request.run_id,
        turn_index=contract.turn_index,
        step_id=request.step_id,
        action_digest=action.digest(),
        tool=action.tool,
        contract=contract,
        workflow=workflow,
        evidence=evidence,
        data_flow=data_flow,
        signals=tuple(signals),
    )
