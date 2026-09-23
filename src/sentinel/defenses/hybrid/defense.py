"""Hybrid defense phase wrappers and selectively enforcing hybrid controllers."""

from __future__ import annotations

from sentinel.core.actions import CandidateAction, Decision, DefenseDecision
from sentinel.defenses.baselines.authority_core import authority_core_v3_full
from sentinel.defenses.hybrid.context import SecurityContext, SignalKind
from sentinel.defenses.hybrid.controller import (
    HybridPolicyAssessment,
    HybridPolicyDisposition,
    RecoveryStatus,
    analyze_security_context,
    assess_hybrid_policy,
    empty_recovery_assessment,
    finalize_recovery,
    plan_restricted_response_recovery,
)
from sentinel.defenses.hybrid.data_flow import assess_data_flow
from sentinel.defenses.hybrid.evidence import assess_evidence
from sentinel.defenses.hybrid.grounded_repair import (
    ControlRepairAssessment,
    ControlRepairStatus,
    empty_control_repair_assessment,
    finalize_control_repair,
    plan_grounded_control_repair,
)
from sentinel.defenses.hybrid.overlap import assess_overlap
from sentinel.defenses.hybrid.state import RunSecurityState
from sentinel.defenses.hybrid.task_contract import compile_task_contract
from sentinel.defenses.hybrid.workflow import assess_workflow
from sentinel.defenses.interface import Defense, DefenseRequest


def _record_context_bundle(state: RunSecurityState, context: SecurityContext) -> None:
    state.record_contract(context.contract)
    state.record_workflow(context.workflow)
    state.record_evidence(context.evidence)
    state.record_data_flow(context.data_flow)
    state.record_context(context)


class HybridPhase1Defense(Defense):
    """Delegate every decision unchanged to the validated Authority-Core v3."""

    name = "hybrid_phase_1"

    def __init__(self, delegate: Defense | None = None) -> None:
        self._delegate = delegate or authority_core_v3_full()
        self.state = RunSecurityState()

    @property
    def delegate_name(self) -> str:
        return self._delegate.name

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        result = self._delegate.decide(request)
        self.state.record(request, result, self._delegate.name)
        return result

    def close(self) -> None:
        self._delegate.close()


class HybridPhase2ShadowDefense(HybridPhase1Defense):
    """Compile trusted task facts for observation, never for enforcement."""

    name = "hybrid_phase_2_shadow"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        self.state.record_contract(compile_task_contract(request))
        return super().decide(request)


class HybridPhase3ShadowDefense(HybridPhase1Defense):
    """Observe a task-local dynamic workflow without enforcing it."""

    name = "hybrid_phase_3_shadow"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        contract = compile_task_contract(request)
        self.state.record_contract(contract)
        self.state.record_workflow(assess_workflow(request, contract))
        return HybridPhase1Defense.decide(self, request)


class HybridPhase4ShadowDefense(HybridPhase1Defense):
    """Build workflow + evidence graphs without enforcing either one."""

    name = "hybrid_phase_4_shadow"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        contract = compile_task_contract(request)
        self.state.record_contract(contract)
        self.state.record_workflow(assess_workflow(request, contract))
        self.state.record_evidence(assess_evidence(request, contract))
        return HybridPhase1Defense.decide(self, request)


class HybridPhase5ShadowDefense(HybridPhase1Defense):
    """Build workflow, evidence, and sensitive data-flow graphs in shadow mode."""

    name = "hybrid_phase_5_shadow"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        contract = compile_task_contract(request)
        self.state.record_contract(contract)
        self.state.record_workflow(assess_workflow(request, contract))
        self.state.record_evidence(assess_evidence(request, contract))
        self.state.record_data_flow(assess_data_flow(request))
        return HybridPhase1Defense.decide(self, request)


class HybridPhase55ShadowDefense(HybridPhase1Defense):
    """Integrate surviving analyses into one context without changing decisions."""

    name = "hybrid_phase_5_5_shadow"

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        context = analyze_security_context(request)
        _record_context_bundle(self.state, context)

        result = HybridPhase1Defense.decide(self, request)
        self.state.record_overlap(assess_overlap(context, result))
        return result


class HybridPhase6Defense(HybridPhase1Defense):
    """Selective hybrid enforcement plus deterministic restricted-flow recovery.

    Authority-Core remains the hard-policy kernel. Phase 6 can only make an
    ``ALLOW`` stricter, reject an unsafe core-generated rewrite, or replace a
    restricted final response with a deterministic redaction that independently
    passes both policy layers. It never turns a core BLOCK/ESCALATE into ALLOW.

    Subclasses may propose a deterministic policy rewrite through
    ``_plan_policy_rewrite``. Phase 6 itself returns no such rewrite, preserving
    the validated Phase-6 behavior exactly.
    """

    name = "hybrid_phase_6"

    def _hybrid_block(
        self,
        policy: HybridPolicyAssessment,
        *,
        prefix: str | None = None,
    ) -> DefenseDecision:
        codes = list(policy.reason_codes)
        if prefix is not None:
            codes.insert(0, prefix)
        return DefenseDecision(
            decision=Decision.BLOCK,
            risk_score=0.9,
            confidence=0.85,
            reason_codes=codes[:16],
            explanation="high-confidence hybrid provenance/control invariant failed",
        )

    def _plan_policy_rewrite(
        self,
        request: DefenseRequest,
        context: SecurityContext,
        policy: HybridPolicyAssessment,
    ) -> tuple[ControlRepairAssessment, CandidateAction | None]:
        del context, policy
        return empty_control_repair_assessment(request), None

    def _validate_rewrite(
        self,
        request: DefenseRequest,
        rewritten: CandidateAction,
    ) -> tuple[bool, DefenseDecision]:
        rewritten_request = request.model_copy(update={"candidate_action": rewritten})
        rewritten_context = analyze_security_context(rewritten_request)
        rewritten_core = self._delegate.decide(rewritten_request)
        rewritten_policy = assess_hybrid_policy(rewritten_context)
        accepted = (
            rewritten_core.decision is Decision.ALLOW
            and rewritten_policy.disposition is HybridPolicyDisposition.PASS
        )
        return accepted, rewritten_core

    def decide(self, request: DefenseRequest) -> DefenseDecision:
        context = analyze_security_context(request)
        _record_context_bundle(self.state, context)

        core_result = self._delegate.decide(request)
        self.state.record_overlap(assess_overlap(context, core_result))

        policy = assess_hybrid_policy(context)
        self.state.record_policy(policy)
        recovery = empty_recovery_assessment(request)
        control_repair = empty_control_repair_assessment(request)
        final = core_result

        if core_result.decision is Decision.ALLOW and policy.disposition is HybridPolicyDisposition.BLOCK:
            control_repair, policy_rewrite = self._plan_policy_rewrite(request, context, policy)
            if control_repair.status is ControlRepairStatus.READY and policy_rewrite is not None:
                accepted, rewritten_core = self._validate_rewrite(request, policy_rewrite)
                control_repair = finalize_control_repair(
                    control_repair,
                    accepted=accepted,
                    validation=rewritten_core,
                )
                if accepted:
                    final = DefenseDecision(
                        decision=Decision.REWRITE,
                        risk_score=0.85,
                        confidence=0.9,
                        reason_codes=["HYBRID_GROUNDED_CONTROL_REPAIR"],
                        explanation=(
                            "an attacker-only control selector was replaced by the "
                            "unique schema-valid value independently grounded in trusted evidence"
                        ),
                        rewritten_action=policy_rewrite,
                    )
                else:
                    final = self._hybrid_block(
                        policy,
                        prefix="HYBRID_CONTROL_REPAIR_FAILED_VALIDATION",
                    )
            else:
                final = self._hybrid_block(policy)

        elif core_result.decision is Decision.REWRITE and core_result.rewritten_action is not None:
            # Authority-Core already self-validates its rewrite. Phase 6 adds the
            # integrated hybrid invariants before the rewritten action may leave.
            rewritten_request = request.model_copy(update={"candidate_action": core_result.rewritten_action})
            rewritten_context = analyze_security_context(rewritten_request)
            rewritten_policy = assess_hybrid_policy(rewritten_context)
            if rewritten_policy.disposition is HybridPolicyDisposition.BLOCK:
                final = self._hybrid_block(rewritten_policy, prefix="HYBRID_REWRITE_FAILED_VALIDATION")

        elif (
            core_result.decision is Decision.BLOCK
            and "RESTRICTED_DATA_DISCLOSURE" in core_result.reason_codes
        ):
            recovery, rewritten = plan_restricted_response_recovery(request, context)
            if recovery.status is RecoveryStatus.READY and rewritten is not None:
                accepted, rewritten_core = self._validate_rewrite(request, rewritten)
                recovery = finalize_recovery(
                    recovery,
                    accepted=accepted,
                    validation=rewritten_core,
                )
                if accepted:
                    final = DefenseDecision(
                        decision=Decision.REWRITE,
                        risk_score=core_result.risk_score,
                        confidence=0.9,
                        reason_codes=["HYBRID_RESTRICTED_FLOW_REDACTED"],
                        explanation=(
                            "restricted lineage was deterministically redacted; "
                            "the rewritten response passed full self-validation"
                        ),
                        rewritten_action=rewritten,
                    )

        self.state.record_recovery(recovery)
        self.state.record_control_repair(control_repair)
        self.state.record(request, final, self.name)
        return final


class HybridPhase65Defense(HybridPhase6Defense):
    """Phase 6.5: repair one attacker-selected closed-vocabulary control.

    Repair is intentionally narrower than blocking:
    * the only hybrid block reason must be an untrusted control selector,
    * the tool action must be non-consequential,
    * the tool schema must expose a closed literal vocabulary, and
    * exactly one different value must be independently supported by trusted
      or runtime tool evidence.

    Otherwise Phase-6 blocking behavior is preserved.
    """

    name = "hybrid_phase_6_5"

    def _plan_policy_rewrite(
        self,
        request: DefenseRequest,
        context: SecurityContext,
        policy: HybridPolicyAssessment,
    ) -> tuple[ControlRepairAssessment, CandidateAction | None]:
        if context.workflow.is_consequential:
            return empty_control_repair_assessment(request), None
        if set(policy.matched_signals) != {SignalKind.UNTRUSTED_CONTROL_SELECTOR}:
            return empty_control_repair_assessment(request), None
        return plan_grounded_control_repair(request, context)
