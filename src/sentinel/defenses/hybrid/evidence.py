"""Phase-4 ARGUS-inspired evidence grounding in shadow mode.

This module builds a small Evidence Dependency Graph (EDG) for action arguments.
It answers a deliberately narrow question: *where did this consequential value
come from?*  It does not grant authority and it does not override the validated
Authority-Core v3 decision.

The graph keeps authority and evidence separate:

* authenticated user text can support a value,
* trusted/provenanced tool output can support a value,
* internally generated tool results with no provenance can support runtime ids,
* untrusted tool content is recorded as evidence but never upgraded to authority,
* memory/agent/safety text is not treated as trusted evidence in Phase 4, and
* free-text action fields are deliberately not parsed here; Phase 5 data-flow
  tracking will reason about content movement and transformations.

Only a small set of operational arguments is grounded in this phase: structural
``*_id`` fields, destinations/recipients, amounts, and explicit action selectors.
That scope is intentional so benign summaries/notes do not become noisy graphs.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sentinel.core.actions import ActionType
from sentinel.defenses.hybrid.task_contract import TaskContract
from sentinel.defenses.interface import DefenseRequest
from sentinel.defenses.provenance_index import (
    SourceKind,
    build_source_index,
)

_DESTINATION_FIELDS = frozenset({"to", "recipient", "destination", "email", "address"})
_AMOUNT_FIELDS = frozenset({"amount"})
_ACTION_FIELDS = frozenset({"action"})


class EvidenceSource(StrEnum):
    """Source classes used by the Evidence Dependency Graph."""

    AUTHENTICATED_GOAL = "authenticated_goal"
    AUTHENTICATED_CONVERSATION = "authenticated_conversation"
    TRUSTED_TOOL = "trusted_tool"
    RUNTIME_TOOL = "runtime_tool"
    UNTRUSTED_TOOL = "untrusted_tool"


class EvidenceRelation(StrEnum):
    """How one evidence edge contributes to the candidate value."""

    ANCHOR = "anchor"
    ECHO = "echo"
    INTRODUCTION = "introduction"


class GroundingStatus(StrEnum):
    """Trust status of one operational action argument."""

    AUTHENTICATED = "authenticated"
    TRUSTED = "trusted"
    GROUNDED_WITH_UNTRUSTED_ECHO = "grounded_with_untrusted_echo"
    # Kept for compatibility with Phase-4 traces; Phase 4A no longer emits it.
    MIXED = "mixed"
    UNTRUSTED_ONLY = "untrusted_only"
    UNSOURCED = "unsourced"


class EvidenceDisposition(StrEnum):
    """Shadow-only aggregate classification for one candidate action."""

    NON_TOOL = "non_tool"
    NO_GROUNDABLE_ARGUMENTS = "no_groundable_arguments"
    GROUNDED = "grounded"
    GROUNDED_WITH_UNTRUSTED_ECHO = "grounded_with_untrusted_echo"
    # Kept for compatibility with Phase-4 traces; Phase 4A no longer emits it.
    MIXED = "mixed"
    REVIEW_UNTRUSTED_ONLY = "review_untrusted_only"
    REVIEW_UNSOURCED = "review_unsourced"


@dataclass(frozen=True)
class EvidenceEdge:
    """A value-to-source edge. Raw values are intentionally not stored."""

    argument: str
    value_digest: str
    source: EvidenceSource
    relation: EvidenceRelation
    field_path: str | None = None
    provenance_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ArgumentGrounding:
    """Grounding result for one operationally relevant action argument."""

    argument: str
    value_kind: str
    value_digest: str
    status: GroundingStatus
    authenticated_support: bool
    trusted_support: bool
    untrusted_support: bool
    edges: tuple[EvidenceEdge, ...]


@dataclass(frozen=True)
class EvidenceAssessment:
    """Evidence Dependency Graph snapshot for one candidate action."""

    run_id: str
    turn_index: int
    step_id: int
    action_digest: str
    tool: str | None
    disposition: EvidenceDisposition
    reason_codes: tuple[str, ...]
    groundings: tuple[ArgumentGrounding, ...]
    shadow_only: bool = True
    graph_version: str = "phase4a-edg-v2"


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


def _value_digest(value: Any) -> str:
    return hashlib.sha256(_normalize(str(value)).encode()).hexdigest()[:16]


def _groundable_kind(name: str) -> str | None:
    if name == "id" or name.endswith("_id"):
        return "identity"
    if name in _DESTINATION_FIELDS:
        return "destination"
    if name in _AMOUNT_FIELDS:
        return "amount"
    if name in _ACTION_FIELDS:
        return "action"
    return None


def _forms(value: Any, kind: str) -> tuple[str, ...]:
    """Literal forms accepted as support; no semantic/LLM inference is performed."""
    raw = str(value).strip()
    forms: list[str] = [_normalize(raw)]

    if kind == "action" and "_" in raw:
        forms.append(_normalize(raw.replace("_", " ")))

    if kind == "amount" and isinstance(value, (int, float)):
        if isinstance(value, float) and not value.is_integer():
            forms.append(f"{value:,.2f}".lower())
        else:
            integer = int(value)
            forms.extend((str(integer), f"{integer:,}"))

    return tuple(dict.fromkeys(form for form in forms if form))


def _contains(text: str, forms: tuple[str, ...], kind: str) -> bool:
    normalized = _normalize(text)
    for form in forms:
        if kind == "amount" and form.replace(",", "").isdigit():
            # Avoid treating 12 as grounded merely because it occurs inside 1250.
            escaped = re.escape(form)
            if re.search(rf"(?<!\d){escaped}(?!\d)", normalized):
                return True
        elif form in normalized:
            return True
    return False


_SOURCE_TO_EVIDENCE = {
    SourceKind.AUTHENTICATED_GOAL: EvidenceSource.AUTHENTICATED_GOAL,
    SourceKind.AUTHENTICATED_CONVERSATION: EvidenceSource.AUTHENTICATED_CONVERSATION,
    SourceKind.TRUSTED_TOOL: EvidenceSource.TRUSTED_TOOL,
    SourceKind.RUNTIME_TOOL: EvidenceSource.RUNTIME_TOOL,
    SourceKind.UNTRUSTED_TOOL: EvidenceSource.UNTRUSTED_TOOL,
}


def _evidence_segments(
    request: DefenseRequest,
) -> tuple[tuple[str, EvidenceSource, str, tuple[str, ...]], ...]:
    """Project the shared source index into ARGUS evidence segments."""
    segments: list[tuple[str, EvidenceSource, str, tuple[str, ...]]] = []
    for field in build_source_index(request).fields:
        for kind in field.evidence_kinds:
            source = _SOURCE_TO_EVIDENCE.get(kind)
            if source is None:
                # Memory is intentionally not authority-supporting evidence in
                # Phase 4/5.5; it remains visible in the shared source index for
                # later persistence-lineage analysis.
                continue
            segment = (field.text, source, field.field_path, field.provenance_ids)
            if segment not in segments:
                segments.append(segment)
    return tuple(segments)


def _ground_argument(
    name: str,
    value: Any,
    kind: str,
    segments: tuple[tuple[str, EvidenceSource, str, tuple[str, ...]], ...],
) -> ArgumentGrounding:
    forms = _forms(value, kind)
    digest = _value_digest(value)
    raw_edges: list[tuple[EvidenceSource, str | None, tuple[str, ...]]] = []

    for text, source, field_path, provenance_ids in segments:
        if _contains(text, forms, kind):
            edge = (source, field_path, provenance_ids)
            if edge not in raw_edges:
                raw_edges.append(edge)

    sources = {source for source, _, _ in raw_edges}
    authenticated = bool(
        sources & {EvidenceSource.AUTHENTICATED_GOAL, EvidenceSource.AUTHENTICATED_CONVERSATION}
    )
    trusted = bool(sources & {EvidenceSource.TRUSTED_TOOL, EvidenceSource.RUNTIME_TOOL})
    untrusted = EvidenceSource.UNTRUSTED_TOOL in sources
    has_independent_anchor = authenticated or trusted

    edges: list[EvidenceEdge] = []
    for source, field_path, provenance_ids in raw_edges:
        if source is EvidenceSource.UNTRUSTED_TOOL:
            relation = EvidenceRelation.ECHO if has_independent_anchor else EvidenceRelation.INTRODUCTION
        else:
            relation = EvidenceRelation.ANCHOR
        edges.append(EvidenceEdge(name, digest, source, relation, field_path, provenance_ids))

    if has_independent_anchor and untrusted:
        status = GroundingStatus.GROUNDED_WITH_UNTRUSTED_ECHO
    elif authenticated:
        status = GroundingStatus.AUTHENTICATED
    elif trusted:
        status = GroundingStatus.TRUSTED
    elif untrusted:
        status = GroundingStatus.UNTRUSTED_ONLY
    else:
        status = GroundingStatus.UNSOURCED

    return ArgumentGrounding(
        argument=name,
        value_kind=kind,
        value_digest=digest,
        status=status,
        authenticated_support=authenticated,
        trusted_support=trusted,
        untrusted_support=untrusted,
        edges=tuple(edges),
    )


def assess_evidence(request: DefenseRequest, contract: TaskContract) -> EvidenceAssessment:
    """Build the Phase-4 Evidence Dependency Graph for one candidate action.

    This function is observation-only. A later enforcement experiment may use a
    narrow subset of these statuses, but Phase 4 never changes the delegated
    ``DefenseDecision``.
    """
    action = request.candidate_action
    if action.type is not ActionType.TOOL_CALL or action.tool is None:
        return EvidenceAssessment(
            run_id=request.run_id,
            turn_index=contract.turn_index,
            step_id=request.step_id,
            action_digest=action.digest(),
            tool=None,
            disposition=EvidenceDisposition.NON_TOOL,
            reason_codes=("EVIDENCE_NON_TOOL",),
            groundings=(),
        )

    segments = _evidence_segments(request)
    groundings = tuple(
        _ground_argument(name, value, kind, segments)
        for name, value in action.arguments.items()
        if value is not None and (kind := _groundable_kind(name)) is not None
    )

    statuses = {grounding.status for grounding in groundings}
    if not groundings:
        disposition = EvidenceDisposition.NO_GROUNDABLE_ARGUMENTS
        reasons = ("EVIDENCE_NO_GROUNDABLE_ARGUMENTS",)
    elif GroundingStatus.UNTRUSTED_ONLY in statuses:
        disposition = EvidenceDisposition.REVIEW_UNTRUSTED_ONLY
        reasons = ("EVIDENCE_UNTRUSTED_ONLY_ARGUMENT",)
    elif GroundingStatus.UNSOURCED in statuses:
        disposition = EvidenceDisposition.REVIEW_UNSOURCED
        reasons = ("EVIDENCE_UNSOURCED_ARGUMENT",)
    elif GroundingStatus.GROUNDED_WITH_UNTRUSTED_ECHO in statuses:
        disposition = EvidenceDisposition.GROUNDED_WITH_UNTRUSTED_ECHO
        reasons = ("EVIDENCE_TRUSTED_ANCHOR_WITH_UNTRUSTED_ECHO",)
    elif GroundingStatus.MIXED in statuses:
        # Compatibility path for old serialized traces; Phase 4A does not emit MIXED.
        disposition = EvidenceDisposition.MIXED
        reasons = ("EVIDENCE_MIXED_SUPPORT",)
    else:
        disposition = EvidenceDisposition.GROUNDED
        reasons = ("EVIDENCE_TRUSTED_SUPPORT",)

    return EvidenceAssessment(
        run_id=request.run_id,
        turn_index=contract.turn_index,
        step_id=request.step_id,
        action_digest=action.digest(),
        tool=action.tool,
        disposition=disposition,
        reason_codes=reasons,
        groundings=groundings,
    )
