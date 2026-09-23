"""Production-facing SENTINEL Hybrid defense.

The competition-facing name is intentionally stable and architecture-neutral.
Research phase classes remain available for ablations and reproducibility, but
new demos, reports, and integrations should use ``SentinelHybridDefense`` /
``sentinel_hybrid``.

Behavior is deliberately frozen to the validated Phase-6.5 implementation.
This module adds no policy rule and changes no decision semantics.
"""

from __future__ import annotations

from sentinel.defenses.hybrid.defense import HybridPhase65Defense
from sentinel.defenses.interface import Defense


class SentinelHybridDefense(HybridPhase65Defense):
    """Stable production facade over the validated hybrid policy."""

    name = "sentinel_hybrid"


def sentinel_hybrid() -> Defense:
    """Construct the production SENTINEL Hybrid defense."""

    return SentinelHybridDefense()


__all__ = ["SentinelHybridDefense", "sentinel_hybrid"]
