"""Canonical participant-visible provenance index used by every defense layer.

Phase 8 removes a remaining source of accidental disagreement: Authority-Core
and the hybrid analyses used to parse request provenance independently.  This
module owns the shared representation and the two legacy text partitions needed
to keep Authority-Core's existing ablation semantics stable.

The index is intentionally descriptive.  It does not grant authority or emit a
DefenseDecision.  Raw field text exists only ephemerally during one decision;
persistent hybrid state continues to store digests/metadata.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sentinel.core.provenance import Sensitivity, SourceType, TrustLevel
from sentinel.defenses.interface import DefenseRequest
from sentinel.defenses.tool_contracts import UNTRUSTED_RESULT_FIELDS

# Compatibility export retained for older Core/Hybrid imports. It is no longer
# populated by importing the simulator's runtime domain registry.
KNOWN_UNTRUSTED_FIELDS = UNTRUSTED_RESULT_FIELDS


def discover_untrusted_fields() -> frozenset[str]:
    """Compatibility accessor for the canonical untrusted-field set."""

    return KNOWN_UNTRUSTED_FIELDS


def _request_untrusted_fields(request: DefenseRequest) -> frozenset[str]:
    """Recover mixed-trust field names from participant-visible provenance.

    The gateway attaches untrusted TOOL_OUTPUT provenance with source ids such
    as ``account_summary.advisory``. That gives the defense a request-local,
    provenance-backed mapping without consulting ``sentinel.domains`` at
    decision time. The bundled public tool contract is only a compatibility
    fallback for synthetic/partial requests that omit field-level provenance.
    """
    fields: set[str] = set()
    for record in request.provenance:
        prov = record.provenance
        if prov.source_type is not SourceType.TOOL_OUTPUT or prov.trust_level.is_trusted:
            continue
        source_id = str(prov.source_id)
        if "." not in source_id:
            continue
        tool_name, field_name = source_id.rsplit(".", 1)
        retrieved_via = str(prov.retrieved_via or "")
        if retrieved_via and retrieved_via != tool_name:
            continue
        if field_name:
            fields.add(field_name)
    return frozenset(fields) or KNOWN_UNTRUSTED_FIELDS


class SourceKind(StrEnum):
    """Logical source classes used by provenance/evidence consumers."""

    AUTHENTICATED_GOAL = "authenticated_goal"
    AUTHENTICATED_CONVERSATION = "authenticated_conversation"
    TRUSTED_TOOL = "trusted_tool"
    RUNTIME_TOOL = "runtime_tool"
    UNTRUSTED_TOOL = "untrusted_tool"
    MEMORY = "memory"


@dataclass(frozen=True)
class SourceField:
    """One field-addressable participant-visible source leaf."""

    role: str
    field_path: str
    text: str
    evidence_kinds: tuple[SourceKind, ...]
    trust_level: TrustLevel
    sensitivity: Sensitivity
    source_types: tuple[SourceType, ...]
    provenance_ids: tuple[str, ...]


@dataclass(frozen=True)
class SourceIndex:
    """Ephemeral canonical provenance view for one defense request."""

    run_id: str
    step_id: int
    fields: tuple[SourceField, ...]
    index_version: str = "phase9a-provenance-index-v2"


@dataclass(frozen=True)
class _Meta:
    trust_level: TrustLevel
    sensitivity: Sensitivity
    source_types: tuple[SourceType, ...]
    provenance_ids: tuple[str, ...]


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _tool_prefix(provs: list[Any]) -> str:
    names = {
        str(prov.retrieved_via)
        for prov in provs
        if getattr(prov, "retrieved_via", None)
    }
    if len(names) == 1:
        return next(iter(names))
    return "tool" if provs else "runtime_tool"


def _selected_pairs(
    pairs: list[tuple[str, Any]],
    *,
    untrusted_field: bool,
) -> list[tuple[str, Any]]:
    if not pairs:
        return []

    trusted = [(pid, prov) for pid, prov in pairs if prov.trust_level.is_trusted]
    untrusted = [(pid, prov) for pid, prov in pairs if not prov.trust_level.is_trusted]

    if untrusted_field:
        return untrusted or pairs
    if trusted:
        return trusted
    return pairs


def _meta(
    pairs: list[tuple[str, Any]],
    *,
    untrusted_field: bool,
) -> _Meta:
    selected = _selected_pairs(pairs, untrusted_field=untrusted_field)
    if not selected:
        return _Meta(
            trust_level=TrustLevel.TRUSTED_INTERNAL,
            sensitivity=Sensitivity.INTERNAL,
            source_types=(),
            provenance_ids=(),
        )

    trust = max(
        (prov for _, prov in selected),
        key=lambda prov: prov.trust_level.rank,
    ).trust_level
    sensitivity = max(
        (prov for _, prov in selected),
        key=lambda prov: prov.sensitivity.rank,
    ).sensitivity
    source_types = tuple(
        sorted(
            {prov.source_type for _, prov in selected},
            key=lambda item: item.value,
        )
    )
    provenance_ids = tuple(pid for pid, _ in selected)
    return _Meta(trust, sensitivity, source_types, provenance_ids)


def _leaf_fields(
    value: Any,
    *,
    role: str,
    field_path: str,
    evidence_kinds: tuple[SourceKind, ...],
    meta: _Meta,
) -> list[SourceField]:
    if isinstance(value, dict):
        out: list[SourceField] = []
        for key, child in value.items():
            out.extend(
                _leaf_fields(
                    child,
                    role=role,
                    field_path=f"{field_path}.{key}",
                    evidence_kinds=evidence_kinds,
                    meta=meta,
                )
            )
        return out

    if isinstance(value, list):
        out = []
        for index, child in enumerate(value):
            out.extend(
                _leaf_fields(
                    child,
                    role=role,
                    field_path=f"{field_path}[{index}]",
                    evidence_kinds=evidence_kinds,
                    meta=meta,
                )
            )
        return out

    return [
        SourceField(
            role=role,
            field_path=field_path,
            text=_json_text(value),
            evidence_kinds=evidence_kinds,
            trust_level=meta.trust_level,
            sensitivity=meta.sensitivity,
            source_types=meta.source_types,
            provenance_ids=meta.provenance_ids,
        )
    ]


def _tool_fields(
    item: Any,
    records: dict[str, Any],
    untrusted_fields: frozenset[str],
) -> list[SourceField]:
    pairs = [
        (pid, records[pid])
        for pid in item.provenance_ids
        if pid in records
    ]
    provs = [prov for _, prov in pairs]
    prefix = _tool_prefix(provs)

    try:
        parsed: object = json.loads(item.content)
    except (TypeError, ValueError):
        parsed = None

    if not pairs:
        meta = _meta([], untrusted_field=False)
        if isinstance(parsed, (dict, list)):
            return _leaf_fields(
                parsed,
                role="tool",
                field_path=prefix,
                evidence_kinds=(SourceKind.RUNTIME_TOOL,),
                meta=meta,
            )
        return [
            SourceField(
                role="tool",
                field_path=prefix,
                text=item.content,
                evidence_kinds=(SourceKind.RUNTIME_TOOL,),
                trust_level=meta.trust_level,
                sensitivity=meta.sensitivity,
                source_types=meta.source_types,
                provenance_ids=(),
            )
        ]

    base_trusted = any(prov.trust_level.is_trusted for prov in provs)
    base_untrusted = any(not prov.trust_level.is_trusted for prov in provs)

    if isinstance(parsed, dict):
        out: list[SourceField] = []
        has_declared_untrusted = any(
            key in untrusted_fields
            for key in parsed
        )
        for key, value in parsed.items():
            path = f"{prefix}.{key}"
            is_untrusted_field = (
                has_declared_untrusted
                and key in untrusted_fields
            )
            if is_untrusted_field:
                kinds = (SourceKind.UNTRUSTED_TOOL,)
            elif base_trusted:
                # Preserve the validated Phase-5.5 behavior for structured
                # siblings: a declared attacker field does not taint the
                # trusted sibling merely because provenance is item-shaped.
                kinds = (SourceKind.TRUSTED_TOOL,)
            elif base_untrusted:
                kinds = (SourceKind.UNTRUSTED_TOOL,)
            else:
                kinds = ()

            out.extend(
                _leaf_fields(
                    value,
                    role="tool",
                    field_path=path,
                    evidence_kinds=kinds,
                    meta=_meta(
                        pairs,
                        untrusted_field=is_untrusted_field,
                    ),
                )
            )
        return out

    kinds: list[SourceKind] = []
    if base_trusted:
        kinds.append(SourceKind.TRUSTED_TOOL)
    if base_untrusted:
        kinds.append(SourceKind.UNTRUSTED_TOOL)

    # Unstructured mixed provenance cannot be separated field-wise, so keep
    # all supporting IDs visible instead of pretending we know which substring
    # came from which record.
    selected_meta = _meta(pairs, untrusted_field=False)
    if len(kinds) > 1:
        selected_meta = _Meta(
            trust_level=selected_meta.trust_level,
            sensitivity=max(
                (prov.sensitivity for _, prov in pairs),
                key=lambda item: item.rank,
            ),
            source_types=tuple(
                sorted(
                    {prov.source_type for _, prov in pairs},
                    key=lambda item: item.value,
                )
            ),
            provenance_ids=tuple(pid for pid, _ in pairs),
        )

    if isinstance(parsed, list):
        return _leaf_fields(
            parsed,
            role="tool",
            field_path=prefix,
            evidence_kinds=tuple(kinds),
            meta=selected_meta,
        )

    return [
        SourceField(
            role="tool",
            field_path=prefix,
            text=item.content,
            evidence_kinds=tuple(kinds),
            trust_level=selected_meta.trust_level,
            sensitivity=selected_meta.sensitivity,
            source_types=selected_meta.source_types,
            provenance_ids=selected_meta.provenance_ids,
        )
    ]


def build_source_index(request: DefenseRequest) -> SourceIndex:
    """Build the canonical field-addressable provenance index."""

    records = {
        record.id: record.provenance
        for record in request.provenance
    }
    untrusted_fields = _request_untrusted_fields(request)
    fields: list[SourceField] = [
        SourceField(
            role="user",
            field_path="user_goal",
            text=request.user_goal,
            evidence_kinds=(SourceKind.AUTHENTICATED_GOAL,),
            trust_level=TrustLevel.AUTHENTICATED_USER,
            sensitivity=Sensitivity.INTERNAL,
            source_types=(SourceType.USER,),
            provenance_ids=(),
        )
    ]

    normalized_goal = _normalize(request.user_goal)
    for item in request.conversation:
        pairs = [
            (pid, records[pid])
            for pid in item.provenance_ids
            if pid in records
        ]
        if item.role == "user":
            if _normalize(item.content) == normalized_goal:
                continue
            fields.append(
                SourceField(
                    role="user",
                    field_path="conversation.user",
                    text=item.content,
                    evidence_kinds=(
                        SourceKind.AUTHENTICATED_CONVERSATION,
                    ),
                    trust_level=TrustLevel.AUTHENTICATED_USER,
                    sensitivity=Sensitivity.INTERNAL,
                    source_types=(SourceType.USER,),
                    provenance_ids=tuple(pid for pid, _ in pairs),
                )
            )
            continue

        if item.role == "tool":
            fields.extend(_tool_fields(item, records, untrusted_fields))
            continue

        if item.role == "memory":
            if pairs:
                trust = max(
                    (prov for _, prov in pairs),
                    key=lambda prov: prov.trust_level.rank,
                ).trust_level
                sensitivity = max(
                    (prov for _, prov in pairs),
                    key=lambda prov: prov.sensitivity.rank,
                ).sensitivity
                source_types = tuple(
                    sorted(
                        {prov.source_type for _, prov in pairs},
                        key=lambda source_type: source_type.value,
                    )
                )
                ids = tuple(pid for pid, _ in pairs)
            else:
                trust = TrustLevel.UNTRUSTED_INTERNAL
                sensitivity = Sensitivity.INTERNAL
                source_types = (SourceType.MEMORY,)
                ids = ()

            fields.append(
                SourceField(
                    role="memory",
                    field_path="memory.content",
                    text=item.content,
                    evidence_kinds=(SourceKind.MEMORY,),
                    trust_level=trust,
                    sensitivity=sensitivity,
                    source_types=source_types,
                    provenance_ids=ids,
                )
            )

    return SourceIndex(
        run_id=request.run_id,
        step_id=request.step_id,
        fields=tuple(fields),
    )


def partition_source_texts(
    request: DefenseRequest,
    *,
    field_aware: bool,
) -> tuple[list[str], list[str]]:
    """Preserve Authority-Core's existing evidence-partition semantics.

    ``field_aware=False`` reproduces the original item-level split.
    ``field_aware=True`` reproduces the validated named-field split.  Keeping
    both in this shared module preserves old ablation arms while eliminating
    independent parsing implementations.
    """

    records = {
        record.id: record.provenance
        for record in request.provenance
    }
    trusted: list[str] = []
    untrusted: list[str] = []
    untrusted_fields = _request_untrusted_fields(request)

    for item in request.conversation:
        provs = [
            records[pid]
            for pid in item.provenance_ids
            if pid in records
        ]
        base_trusted = (
            not provs
            or any(prov.trust_level.is_trusted for prov in provs)
        )
        base_untrusted = (
            bool(provs)
            and any(not prov.trust_level.is_trusted for prov in provs)
        )

        if not field_aware:
            if base_trusted:
                trusted.append(item.content)
            if base_untrusted:
                untrusted.append(item.content)
            continue

        try:
            parsed: object = json.loads(item.content)
        except (TypeError, ValueError):
            parsed = None

        if isinstance(parsed, dict) and any(
            key in untrusted_fields
            for key in parsed
        ):
            flagged = {
                key: value
                for key, value in parsed.items()
                if key in untrusted_fields
            }
            rest = {
                key: value
                for key, value in parsed.items()
                if key not in KNOWN_UNTRUSTED_FIELDS
            }
            untrusted.append(json.dumps(flagged))
            if base_trusted:
                trusted.append(json.dumps(rest))
            if base_untrusted:
                untrusted.append(json.dumps(rest))
            continue

        if base_trusted:
            trusted.append(item.content)
        if base_untrusted:
            untrusted.append(item.content)

    return trusted, untrusted
