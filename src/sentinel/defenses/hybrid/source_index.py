"""Compatibility re-export for the canonical Phase-8 provenance index.

New code should import from ``sentinel.defenses.provenance_index``.  This module
remains temporarily so Phase-4/5 research imports and external experiments do
not break while the architecture converges.
"""

from __future__ import annotations

from sentinel.defenses.provenance_index import (
    KNOWN_UNTRUSTED_FIELDS,
    SourceField,
    SourceIndex,
    SourceKind,
    build_source_index,
    discover_untrusted_fields,
    partition_source_texts,
)

__all__ = [
    "KNOWN_UNTRUSTED_FIELDS",
    "SourceField",
    "SourceIndex",
    "SourceKind",
    "build_source_index",
    "discover_untrusted_fields",
    "partition_source_texts",
]
