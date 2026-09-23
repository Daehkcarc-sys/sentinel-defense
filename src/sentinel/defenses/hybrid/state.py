"""Typed per-run research and controller state for the hybrid defense."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.core.actions import Decision, DefenseDecision
from sentinel.defenses.hybrid.context import SecurityContext
from sentinel.defenses.hybrid.controller import HybridPolicyAssessment, RecoveryAssessment
from sentinel.defenses.hybrid.data_flow import DataFlowAssessment
from sentinel.defenses.hybrid.evidence import EvidenceAssessment
from sentinel.defenses.hybrid.grounded_repair import ControlRepairAssessment
from sentinel.defenses.hybrid.overlap import OverlapAssessment
from sentinel.defenses.hybrid.task_contract import TaskContract
from sentinel.defenses.hybrid.workflow import WorkflowAssessment
from sentinel.defenses.interface import DefenseRequest


@dataclass(frozen=True)
class DecisionTrace:
    """One compact, user-visible-safe record of a final defense decision."""

    run_id: str
    step_id: int
    action_digest: str
    delegate: str
    decision: Decision
    risk_score: float
    confidence: float
    reason_codes: tuple[str, ...]


@dataclass
class RunSecurityState:
    """Per-run typed state used by observation and selective-enforcement phases."""

    traces_by_run: dict[str, list[DecisionTrace]] = field(default_factory=dict)
    contracts_by_run: dict[str, dict[int, TaskContract]] = field(default_factory=dict)
    workflow_by_run: dict[str, list[WorkflowAssessment]] = field(default_factory=dict)
    evidence_by_run: dict[str, list[EvidenceAssessment]] = field(default_factory=dict)
    data_flow_by_run: dict[str, list[DataFlowAssessment]] = field(default_factory=dict)
    contexts_by_run: dict[str, list[SecurityContext]] = field(default_factory=dict)
    overlaps_by_run: dict[str, list[OverlapAssessment]] = field(default_factory=dict)
    policy_by_run: dict[str, list[HybridPolicyAssessment]] = field(default_factory=dict)
    recovery_by_run: dict[str, list[RecoveryAssessment]] = field(default_factory=dict)
    control_repair_by_run: dict[str, list[ControlRepairAssessment]] = field(default_factory=dict)

    def record(self, request: DefenseRequest, result: DefenseDecision, delegate: str) -> None:
        trace = DecisionTrace(
            run_id=request.run_id,
            step_id=request.step_id,
            action_digest=request.candidate_action.digest(),
            delegate=delegate,
            decision=result.decision,
            risk_score=result.risk_score,
            confidence=result.confidence,
            reason_codes=tuple(result.reason_codes),
        )
        self.traces_by_run.setdefault(request.run_id, []).append(trace)

    def record_contract(self, contract: TaskContract) -> None:
        self.contracts_by_run.setdefault(contract.run_id, {})[contract.turn_index] = contract

    def record_workflow(self, assessment: WorkflowAssessment) -> None:
        self.workflow_by_run.setdefault(assessment.run_id, []).append(assessment)

    def record_evidence(self, assessment: EvidenceAssessment) -> None:
        self.evidence_by_run.setdefault(assessment.run_id, []).append(assessment)

    def record_data_flow(self, assessment: DataFlowAssessment) -> None:
        self.data_flow_by_run.setdefault(assessment.run_id, []).append(assessment)

    def record_context(self, context: SecurityContext) -> None:
        self.contexts_by_run.setdefault(context.run_id, []).append(context)

    def record_overlap(self, assessment: OverlapAssessment) -> None:
        self.overlaps_by_run.setdefault(assessment.run_id, []).append(assessment)

    def record_policy(self, assessment: HybridPolicyAssessment) -> None:
        self.policy_by_run.setdefault(assessment.run_id, []).append(assessment)

    def record_recovery(self, assessment: RecoveryAssessment) -> None:
        self.recovery_by_run.setdefault(assessment.run_id, []).append(assessment)

    def record_control_repair(self, assessment: ControlRepairAssessment) -> None:
        self.control_repair_by_run.setdefault(assessment.run_id, []).append(assessment)

    def control_repairs(self, run_id: str) -> tuple[ControlRepairAssessment, ...]:
        return tuple(self.control_repair_by_run.get(run_id, ()))

    def recoveries(self, run_id: str) -> tuple[RecoveryAssessment, ...]:
        return tuple(self.recovery_by_run.get(run_id, ()))

    def policy(self, run_id: str) -> tuple[HybridPolicyAssessment, ...]:
        return tuple(self.policy_by_run.get(run_id, ()))

    def contexts(self, run_id: str) -> tuple[SecurityContext, ...]:
        return tuple(self.contexts_by_run.get(run_id, ()))

    def overlaps(self, run_id: str) -> tuple[OverlapAssessment, ...]:
        return tuple(self.overlaps_by_run.get(run_id, ()))

    def data_flow(self, run_id: str) -> tuple[DataFlowAssessment, ...]:
        return tuple(self.data_flow_by_run.get(run_id, ()))

    def evidence(self, run_id: str) -> tuple[EvidenceAssessment, ...]:
        return tuple(self.evidence_by_run.get(run_id, ()))

    def workflow(self, run_id: str) -> tuple[WorkflowAssessment, ...]:
        return tuple(self.workflow_by_run.get(run_id, ()))

    def traces(self, run_id: str) -> tuple[DecisionTrace, ...]:
        return tuple(self.traces_by_run.get(run_id, ()))

    def contract(self, run_id: str, turn_index: int = 0) -> TaskContract | None:
        return self.contracts_by_run.get(run_id, {}).get(turn_index)
