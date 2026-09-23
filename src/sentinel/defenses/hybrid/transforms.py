"""Canonical one-hop representations shared by hybrid and Authority-Core analyses."""

from __future__ import annotations

from sentinel.defenses.restricted_match import (
    FlowTransformation,
    match_transformation,
    transformation_variants,
)

__all__ = [
    "FlowTransformation",
    "match_transformation",
    "transformation_variants",
]
