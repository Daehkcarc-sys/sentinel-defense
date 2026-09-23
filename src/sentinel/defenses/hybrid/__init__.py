"""SENTINEL Hybrid public API: stable runtime facade plus research ablations."""

from __future__ import annotations

from sentinel.defenses.hybrid.context import (
    SecurityContext,
    SecuritySignal,
    SignalFamily,
    SignalKind,
    SignalMaturity,
    build_security_context,
)
from sentinel.defenses.hybrid.controller import (
    HybridPolicyAssessment,
    HybridPolicyDisposition,
    RecoveryAssessment,
    RecoveryStatus,
    analyze_security_context,
    assess_hybrid_policy,
    plan_restricted_response_recovery,
)
from sentinel.defenses.hybrid.data_flow import (
    DataFlowAssessment,
    DataFlowDisposition,
    DataFlowEdge,
    FlowTransformation,
    SensitiveSourceAtom,
    assess_data_flow,
    sensitive_source_atoms,
)
from sentinel.defenses.hybrid.defense import (
    HybridPhase1Defense,
    HybridPhase2ShadowDefense,
    HybridPhase3ShadowDefense,
    HybridPhase4ShadowDefense,
    HybridPhase5ShadowDefense,
    HybridPhase6Defense,
    HybridPhase55ShadowDefense,
    HybridPhase65Defense,
)
from sentinel.defenses.hybrid.evidence import (
    ArgumentGrounding,
    EvidenceAssessment,
    EvidenceDisposition,
    EvidenceEdge,
    EvidenceRelation,
    EvidenceSource,
    GroundingStatus,
    assess_evidence,
)
from sentinel.defenses.hybrid.grounded_repair import (
    ControlRepairAssessment,
    ControlRepairStatus,
    empty_control_repair_assessment,
    finalize_control_repair,
    plan_grounded_control_repair,
    schema_control_candidates,
)
from sentinel.defenses.hybrid.overlap import (
    OverlapAssessment,
    OverlapFamily,
    OverlapFinding,
    OverlapStatus,
    assess_overlap,
)
from sentinel.defenses.hybrid.runtime import SentinelHybridDefense, sentinel_hybrid
from sentinel.defenses.hybrid.task_contract import TaskContract, compile_task_contract
from sentinel.defenses.hybrid.transforms import transformation_variants
from sentinel.defenses.hybrid.workflow import WorkflowAssessment, WorkflowDisposition, assess_workflow
from sentinel.defenses.interface import Defense
from sentinel.defenses.provenance_index import (
    KNOWN_UNTRUSTED_FIELDS,
    SourceField,
    SourceIndex,
    SourceKind,
    build_source_index,
)


def hybrid_phase_1() -> Defense:
    return HybridPhase1Defense()


def hybrid_phase_2_shadow() -> Defense:
    return HybridPhase2ShadowDefense()


def hybrid_phase_3_shadow() -> Defense:
    return HybridPhase3ShadowDefense()


def hybrid_phase_4_shadow() -> Defense:
    return HybridPhase4ShadowDefense()


def hybrid_phase_5_shadow() -> Defense:
    return HybridPhase5ShadowDefense()


def hybrid_phase_5_5_shadow() -> Defense:
    return HybridPhase55ShadowDefense()


def hybrid_phase_6() -> Defense:
    return HybridPhase6Defense()


def hybrid_phase_6_5() -> Defense:
    return HybridPhase65Defense()


__all__ = [
    "KNOWN_UNTRUSTED_FIELDS",
    "ArgumentGrounding",
    "ControlRepairAssessment",
    "ControlRepairStatus",
    "DataFlowAssessment",
    "DataFlowDisposition",
    "DataFlowEdge",
    "EvidenceAssessment",
    "EvidenceDisposition",
    "EvidenceEdge",
    "EvidenceRelation",
    "EvidenceSource",
    "FlowTransformation",
    "GroundingStatus",
    "HybridPhase1Defense",
    "HybridPhase2ShadowDefense",
    "HybridPhase3ShadowDefense",
    "HybridPhase4ShadowDefense",
    "HybridPhase5ShadowDefense",
    "HybridPhase6Defense",
    "HybridPhase55ShadowDefense",
    "HybridPhase65Defense",
    "HybridPolicyAssessment",
    "HybridPolicyDisposition",
    "OverlapAssessment",
    "OverlapFamily",
    "OverlapFinding",
    "OverlapStatus",
    "RecoveryAssessment",
    "RecoveryStatus",
    "SecurityContext",
    "SecuritySignal",
    "SensitiveSourceAtom",
    "SentinelHybridDefense",
    "SignalFamily",
    "SignalKind",
    "SignalMaturity",
    "SourceField",
    "SourceIndex",
    "SourceKind",
    "TaskContract",
    "WorkflowAssessment",
    "WorkflowDisposition",
    "analyze_security_context",
    "assess_data_flow",
    "assess_evidence",
    "assess_hybrid_policy",
    "assess_overlap",
    "assess_workflow",
    "build_security_context",
    "build_source_index",
    "compile_task_contract",
    "empty_control_repair_assessment",
    "finalize_control_repair",
    "hybrid_phase_1",
    "hybrid_phase_2_shadow",
    "hybrid_phase_3_shadow",
    "hybrid_phase_4_shadow",
    "hybrid_phase_5_5_shadow",
    "hybrid_phase_5_shadow",
    "hybrid_phase_6",
    "hybrid_phase_6_5",
    "plan_grounded_control_repair",
    "plan_restricted_response_recovery",
    "schema_control_candidates",
    "sensitive_source_atoms",
    "sentinel_hybrid",
    "transformation_variants",
]
