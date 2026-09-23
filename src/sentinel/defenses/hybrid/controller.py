"""Phase-6 selective hybrid policy and deterministic response recovery.

Research papers are inspiration, not runtime authorities.  This controller uses
only the typed facts that survived the previous falsification phases.  It never
votes across models or lets a semantic signal override a stricter Authority-Core
decision.

Phase 6 activates three narrow conjunctions:

* attacker-only control selectors (for example ``action=disable_monitoring``),
* attacker-only object expansion on non-read workflow actions, and
* attacker-selected destinations that simultaneously carry sensitive lineage.

It also supports one deliberately narrow recovery: when Authority-Core blocks a
final response because exact RESTRICTED data is present, lineage identifies the
source atom and the controller deterministically redacts recognized
representations.  The rewritten action must independently pass both
Authority-Core and the hybrid policy before it can be returned as ``REWRITE``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from sentinel.core.actions import ActionType, CandidateAction, DefenseDecision
from sentinel.defenses.hybrid.context import SecurityContext, SignalKind, build_security_context
from sentinel.defenses.hybrid.data_flow import assess_data_flow
from sentinel.defenses.hybrid.evidence import assess_evidence
from sentinel.defenses.hybrid.task_contract import compile_task_contract
from sentinel.defenses.hybrid.workflow import WorkflowDisposition, assess_workflow
from sentinel.defenses.interface import DefenseRequest
from sentinel.defenses.restricted_match import (
    redact_restricted_response,
    restricted_payload_hit,
)

_REDACTION = "[REDACTED RESTRICTED VALUE]"


class HybridPolicyDisposition(StrEnum):
    PASS = "pass"  # noqa: S105 - policy disposition, not a credential
    BLOCK = "block"


class RecoveryStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    NO_SAFE_REWRITE = "no_safe_rewrite"
    READY = "ready"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class HybridPolicyAssessment:
    run_id: str
    step_id: int
    action_digest: str
    disposition: HybridPolicyDisposition
    reason_codes: tuple[str, ...]
    matched_signals: tuple[SignalKind, ...]
    policy_version: str = "phase6-selective-v1"


@dataclass(frozen=True)
class RecoveryAssessment:
    run_id: str
    step_id: int
    original_action_digest: str
    status: RecoveryStatus
    rewritten_action_digest: str | None = None
    redacted_source_digests: tuple[str, ...] = ()
    validation_core_decision: str | None = None
    validation_reason_codes: tuple[str, ...] = ()
    recovery_version: str = "phase6-redaction-v1"


def analyze_security_context(request: DefenseRequest) -> SecurityContext:
    """Build the integrated context through one canonical path."""
    contract = compile_task_contract(request)
    workflow = assess_workflow(request, contract)
    evidence = assess_evidence(request, contract)
    data_flow = assess_data_flow(request)
    return build_security_context(request, contract, workflow, evidence, data_flow)


def assess_hybrid_policy(context: SecurityContext) -> HybridPolicyAssessment:
    """Select only high-confidence conjunctions for Phase-6 enforcement."""
    reasons: list[str] = []
    signals: list[SignalKind] = []

    if context.has(SignalKind.ATTACKER_SELECTED_SENSITIVE_SINK):
        reasons.append("HYBRID_ATTACKER_SELECTED_SENSITIVE_SINK")
        signals.append(SignalKind.ATTACKER_SELECTED_SENSITIVE_SINK)

    if context.has(SignalKind.UNTRUSTED_CONTROL_SELECTOR):
        reasons.append("HYBRID_UNTRUSTED_CONTROL_SELECTOR")
        signals.append(SignalKind.UNTRUSTED_CONTROL_SELECTOR)

    # Read-only adaptive discovery is intentionally not blocked.  The workflow
    # layer reserves REVIEW_OBJECT_EXPANSION for non-read operational expansion.
    if (
        context.has(SignalKind.UNTRUSTED_OPERATIONAL_EXPANSION)
        and context.workflow.disposition is WorkflowDisposition.REVIEW_OBJECT_EXPANSION
    ):
        reasons.append("HYBRID_UNTRUSTED_OPERATIONAL_EXPANSION")
        signals.append(SignalKind.UNTRUSTED_OPERATIONAL_EXPANSION)

    disposition = HybridPolicyDisposition.BLOCK if reasons else HybridPolicyDisposition.PASS
    return HybridPolicyAssessment(
        run_id=context.run_id,
        step_id=context.step_id,
        action_digest=context.action_digest,
        disposition=disposition,
        reason_codes=tuple(dict.fromkeys(reasons)),
        matched_signals=tuple(dict.fromkeys(signals)),
    )


def empty_recovery_assessment(request: DefenseRequest) -> RecoveryAssessment:
    return RecoveryAssessment(
        run_id=request.run_id,
        step_id=request.step_id,
        original_action_digest=request.candidate_action.digest(),
        status=RecoveryStatus.NOT_APPLICABLE,
    )


def plan_restricted_response_recovery(
    request: DefenseRequest,
    context: SecurityContext,
) -> tuple[RecoveryAssessment, CandidateAction | None]:
    """Propose bounded deterministic redaction for a blocked final response."""
    del context
    action = request.candidate_action
    base = empty_recovery_assessment(request)
    if action.type is not ActionType.RESPOND or action.content is None:
        return base, None
    if not restricted_payload_hit(request, action, enable_encoded=True):
        return base, None

    redaction = redact_restricted_response(request, action.content, enable_encoded=True)
    if redaction is None:
        return replace(base, status=RecoveryStatus.NO_SAFE_REWRITE), None

    rewritten = action.model_copy(update={"content": redaction.content})
    return (
        replace(
            base,
            status=RecoveryStatus.READY,
            rewritten_action_digest=rewritten.digest(),
            redacted_source_digests=redaction.source_digests,
        ),
        rewritten,
    )


def finalize_recovery(
    assessment: RecoveryAssessment,
    *,
    accepted: bool,
    validation: DefenseDecision,
) -> RecoveryAssessment:
    """Attach self-validation outcome without persisting rewritten content."""
    return replace(
        assessment,
        status=RecoveryStatus.ACCEPTED if accepted else RecoveryStatus.REJECTED,
        validation_core_decision=validation.decision.value,
        validation_reason_codes=tuple(validation.reason_codes),
    )
