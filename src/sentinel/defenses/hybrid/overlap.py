"""Compare Authority-Core reasons with integrated hybrid signals precisely."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sentinel.core.actions import DefenseDecision
from sentinel.defenses.hybrid.context import SecurityContext, SignalFamily, SignalKind


class OverlapFamily(StrEnum):
    POLICY = "policy"
    OBJECT_SCOPE = "object_scope"
    EVIDENCE = "evidence"
    DATA_FLOW = "data_flow"
    FUSION = "fusion"


class OverlapStatus(StrEnum):
    ALIGNED = "aligned"
    REFINEMENT = "refinement"
    HYBRID_ONLY = "hybrid_only"
    CORE_ONLY = "core_only"


@dataclass(frozen=True)
class OverlapFinding:
    family: OverlapFamily
    status: OverlapStatus
    core_reason_codes: tuple[str, ...]
    hybrid_signals: tuple[SignalKind, ...]


@dataclass(frozen=True)
class OverlapAssessment:
    run_id: str
    step_id: int
    action_digest: str
    core_decision: str
    findings: tuple[OverlapFinding, ...]
    shadow_only: bool = True
    overlap_version: str = "phase7-overlap-v2"


_CORE_FAMILIES: dict[str, OverlapFamily] = {
    "TOOL_NOT_ALLOWED": OverlapFamily.POLICY,
    "MISSING_CONFIRMATION": OverlapFamily.POLICY,
    "AUTHORIZATION_ALREADY_CONSUMED": OverlapFamily.POLICY,
    "OBJECT_NOT_DECLARED_IN_REQUEST": OverlapFamily.OBJECT_SCOPE,
    "EPISTEMIC_UNVERIFIED_FACT": OverlapFamily.EVIDENCE,
    "DECISION_RELEVANT_UNVERIFIED_FACT": OverlapFamily.EVIDENCE,
    "RESTRICTED_DATA_DISCLOSURE": OverlapFamily.DATA_FLOW,
    "SENSITIVE_TO_UNTRUSTED_SINK": OverlapFamily.DATA_FLOW,
}

_HYBRID_FAMILIES: dict[SignalFamily, OverlapFamily] = {
    SignalFamily.POLICY: OverlapFamily.POLICY,
    SignalFamily.OBJECT_SCOPE: OverlapFamily.OBJECT_SCOPE,
    SignalFamily.EVIDENCE: OverlapFamily.EVIDENCE,
    SignalFamily.DATA_FLOW: OverlapFamily.DATA_FLOW,
    SignalFamily.FUSION: OverlapFamily.FUSION,
}

_COMPATIBLE: dict[SignalKind, frozenset[str]] = {
    SignalKind.POLICY_OUT_OF_SCOPE: frozenset({"TOOL_NOT_ALLOWED"}),
    SignalKind.OBJECT_SCOPE_EXPANSION: frozenset({"OBJECT_NOT_DECLARED_IN_REQUEST"}),
    SignalKind.UNTRUSTED_ONLY_ARGUMENT: frozenset(
        {"EPISTEMIC_UNVERIFIED_FACT", "DECISION_RELEVANT_UNVERIFIED_FACT"}
    ),
    SignalKind.UNSOURCED_ARGUMENT: frozenset({"EPISTEMIC_UNVERIFIED_FACT"}),
    SignalKind.RESTRICTED_FLOW: frozenset({"RESTRICTED_DATA_DISCLOSURE"}),
    SignalKind.SENSITIVE_EXTERNAL_FLOW: frozenset({"SENSITIVE_TO_UNTRUSTED_SINK"}),
}

_REFINES: dict[SignalKind, frozenset[str]] = {
    SignalKind.UNTRUSTED_OPERATIONAL_EXPANSION: frozenset(
        {"OBJECT_NOT_DECLARED_IN_REQUEST"}
    ),
    SignalKind.UNTRUSTED_CONTROL_SELECTOR: frozenset(
        {"DECISION_RELEVANT_UNVERIFIED_FACT", "EPISTEMIC_UNVERIFIED_FACT"}
    ),
    SignalKind.ATTACKER_SELECTED_SENSITIVE_SINK: frozenset(
        {"SENSITIVE_TO_UNTRUSTED_SINK"}
    ),
}

_NONCOMPARABLE = frozenset(
    {
        SignalKind.UNTRUSTED_ECHO,
        SignalKind.CONSEQUENTIAL_REVIEW,
        SignalKind.UNTRUSTED_DESTINATION,
    }
)


def _dedupe[T](values: list[T]) -> tuple[T, ...]:
    return tuple(dict.fromkeys(values))


def assess_overlap(context: SecurityContext, decision: DefenseDecision) -> OverlapAssessment:
    core_codes = [code for code in decision.reason_codes if code in _CORE_FAMILIES]
    hybrid_signals = [
        signal.kind
        for signal in context.signals
        if signal.kind not in _NONCOMPARABLE
    ]

    findings: list[OverlapFinding] = []
    used_core: set[str] = set()
    used_hybrid: set[SignalKind] = set()

    for signal in hybrid_signals:
        compatible = _COMPATIBLE.get(signal, frozenset())
        matched = [code for code in core_codes if code in compatible]
        if not matched:
            continue
        source_signal = next(item for item in context.signals if item.kind is signal)
        findings.append(
            OverlapFinding(
                family=_HYBRID_FAMILIES[source_signal.family],
                status=OverlapStatus.ALIGNED,
                core_reason_codes=_dedupe(matched),
                hybrid_signals=(signal,),
            )
        )
        used_core.update(matched)
        used_hybrid.add(signal)

    for signal in hybrid_signals:
        if signal in used_hybrid:
            continue
        refinements = _REFINES.get(signal, frozenset())
        matched = [code for code in core_codes if code in refinements]
        if not matched:
            continue
        findings.append(
            OverlapFinding(
                family=OverlapFamily.FUSION,
                status=OverlapStatus.REFINEMENT,
                core_reason_codes=_dedupe(matched),
                hybrid_signals=(signal,),
            )
        )
        used_hybrid.add(signal)

    remaining_hybrid: dict[OverlapFamily, list[SignalKind]] = {}
    for signal in hybrid_signals:
        if signal in used_hybrid:
            continue
        source_signal = next(item for item in context.signals if item.kind is signal)
        family = _HYBRID_FAMILIES[source_signal.family]
        remaining_hybrid.setdefault(family, []).append(signal)

    for family, signals in sorted(remaining_hybrid.items(), key=lambda item: item[0].value):
        findings.append(
            OverlapFinding(
                family=family,
                status=OverlapStatus.HYBRID_ONLY,
                core_reason_codes=(),
                hybrid_signals=_dedupe(signals),
            )
        )

    remaining_core: dict[OverlapFamily, list[str]] = {}
    for code in core_codes:
        if code in used_core:
            continue
        remaining_core.setdefault(_CORE_FAMILIES[code], []).append(code)

    for family, codes in sorted(remaining_core.items(), key=lambda item: item[0].value):
        findings.append(
            OverlapFinding(
                family=family,
                status=OverlapStatus.CORE_ONLY,
                core_reason_codes=_dedupe(codes),
                hybrid_signals=(),
            )
        )

    return OverlapAssessment(
        run_id=context.run_id,
        step_id=context.step_id,
        action_digest=context.action_digest,
        core_decision=decision.decision.value,
        findings=tuple(findings),
    )
