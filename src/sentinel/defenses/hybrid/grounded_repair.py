"""Phase-6.5 deterministic repair of attacker-selected control parameters.

This module is intentionally smaller than a planner.  It handles one narrow case:
an operational ``action`` selector is supported only by untrusted evidence, while
the tool schema exposes a closed set of legal values and exactly one *different*
value is independently supported by trusted/runtime tool evidence.

The defense never asks a model to invent a replacement.  No unique trusted
alternative means no repair.  The caller must still re-run the full Authority-Core
and hybrid policy over the rewritten action before execution.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from sentinel.core.actions import ActionType, CandidateAction, DefenseDecision
from sentinel.defenses.hybrid.context import SecurityContext, SignalKind
from sentinel.defenses.hybrid.evidence import GroundingStatus
from sentinel.defenses.interface import DefenseRequest
from sentinel.defenses.provenance_index import SourceKind, build_source_index
from sentinel.defenses.tool_contracts import closed_control_vocabulary

_NEGATION_TAIL = re.compile(r"\b(?:do not|don't|never|must not)\s+(?:\w+\s+){0,2}$")
_TRUSTED_EVIDENCE_KINDS = frozenset({SourceKind.TRUSTED_TOOL, SourceKind.RUNTIME_TOOL})


class ControlRepairStatus(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    NO_SCHEMA_CANDIDATES = "no_schema_candidates"
    NO_UNIQUE_TRUSTED_ALTERNATIVE = "no_unique_trusted_alternative"
    READY = "ready"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ControlRepairAssessment:
    """Persistent-safe repair trace; raw control values are never stored."""

    run_id: str
    step_id: int
    original_action_digest: str
    status: ControlRepairStatus
    argument: str | None = None
    original_value_digest: str | None = None
    replacement_value_digest: str | None = None
    rewritten_action_digest: str | None = None
    supporting_source_fields: tuple[str, ...] = ()
    schema_candidate_count: int = 0
    trusted_alternative_count: int = 0
    validation_core_decision: str | None = None
    validation_reason_codes: tuple[str, ...] = ()
    repair_version: str = "phase6_5-grounded-control-v1"


def _value_digest(value: str) -> str:
    normalized = " ".join(value.lower().split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def empty_control_repair_assessment(request: DefenseRequest) -> ControlRepairAssessment:
    return ControlRepairAssessment(
        run_id=request.run_id,
        step_id=request.step_id,
        original_action_digest=request.candidate_action.digest(),
        status=ControlRepairStatus.NOT_APPLICABLE,
    )


def schema_control_candidates(tool_name: str, argument: str) -> tuple[str, ...]:
    """Return a closed vocabulary from the bundled public tool contract.

    Runtime policy no longer introspects the simulator's ``DOMAIN_TOOLS``
    registry. The compact contract is checked against the published schema in
    unit tests and contains no scenario/evaluator data.
    """
    return closed_control_vocabulary(tool_name, argument)

def _normalized(text: str) -> str:
    return " ".join(text.lower().replace("-", " ").split())


def _candidate_pattern(value: str) -> re.Pattern[str]:
    tokens = [re.escape(token) for token in value.lower().split("_") if token]
    if not tokens:
        return re.compile(r"(?!x)x")
    # Accept schema form (block_domain) or ordinary prose (block the domain).
    machine = re.escape(value.lower())
    prose = r"(?:\s+(?:the\s+)?)".join(tokens)
    return re.compile(rf"(?<![a-z0-9_])(?:{machine}|{prose})(?![a-z0-9_])")


def _positive_literal_support(text: str, value: str) -> bool:
    normalized = _normalized(text)
    for match in _candidate_pattern(value).finditer(normalized):
        prefix = normalized[max(0, match.start() - 48) : match.start()]
        if _NEGATION_TAIL.search(prefix):
            continue
        return True
    return False


def _trusted_support_fields(request: DefenseRequest, value: str) -> tuple[str, ...]:
    fields: list[str] = []
    for field in build_source_index(request).fields:
        # Repair deliberately relies on tool/runtime evidence, not semantic
        # interpretation of a user's prose goal.
        if field.role != "tool" or not field.trust_level.is_trusted:
            continue
        if not any(kind in _TRUSTED_EVIDENCE_KINDS for kind in field.evidence_kinds):
            continue
        if _positive_literal_support(field.text, value):
            fields.append(field.field_path)
    return tuple(dict.fromkeys(fields))


def _untrusted_action_groundings(context: SecurityContext) -> tuple[Any, ...]:
    return tuple(
        grounding
        for grounding in context.evidence.groundings
        if grounding.value_kind == "action" and grounding.status is GroundingStatus.UNTRUSTED_ONLY
    )


def plan_grounded_control_repair(
    request: DefenseRequest,
    context: SecurityContext,
) -> tuple[ControlRepairAssessment, CandidateAction | None]:
    """Repair one attacker-only selector only when trusted evidence is unique."""

    base = empty_control_repair_assessment(request)
    action = request.candidate_action
    if (
        action.type is not ActionType.TOOL_CALL
        or action.tool is None
        or not context.has(SignalKind.UNTRUSTED_CONTROL_SELECTOR)
    ):
        return base, None

    groundings = _untrusted_action_groundings(context)
    if len(groundings) != 1:
        return base, None

    grounding = groundings[0]
    argument = grounding.argument
    raw_original = action.arguments.get(argument)
    if not isinstance(raw_original, str):
        return base, None

    candidates = schema_control_candidates(action.tool, argument)
    if not candidates:
        return (
            replace(
                base,
                status=ControlRepairStatus.NO_SCHEMA_CANDIDATES,
                argument=argument,
                original_value_digest=_value_digest(raw_original),
            ),
            None,
        )

    supported: list[tuple[str, tuple[str, ...]]] = []
    for candidate in candidates:
        if candidate == raw_original:
            continue
        fields = _trusted_support_fields(request, candidate)
        if fields:
            supported.append((candidate, fields))

    if len(supported) != 1:
        return (
            replace(
                base,
                status=ControlRepairStatus.NO_UNIQUE_TRUSTED_ALTERNATIVE,
                argument=argument,
                original_value_digest=_value_digest(raw_original),
                schema_candidate_count=len(candidates),
                trusted_alternative_count=len(supported),
            ),
            None,
        )

    replacement, supporting_fields = supported[0]
    arguments = dict(action.arguments)
    arguments[argument] = replacement
    rewritten = action.model_copy(update={"arguments": arguments})

    return (
        replace(
            base,
            status=ControlRepairStatus.READY,
            argument=argument,
            original_value_digest=_value_digest(raw_original),
            replacement_value_digest=_value_digest(replacement),
            rewritten_action_digest=rewritten.digest(),
            supporting_source_fields=supporting_fields,
            schema_candidate_count=len(candidates),
            trusted_alternative_count=1,
        ),
        rewritten,
    )


def finalize_control_repair(
    assessment: ControlRepairAssessment,
    *,
    accepted: bool,
    validation: DefenseDecision,
) -> ControlRepairAssessment:
    return replace(
        assessment,
        status=ControlRepairStatus.ACCEPTED if accepted else ControlRepairStatus.REJECTED,
        validation_core_decision=validation.decision.value,
        validation_reason_codes=tuple(validation.reason_codes),
    )
