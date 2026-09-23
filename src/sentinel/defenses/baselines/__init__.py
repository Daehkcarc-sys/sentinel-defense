"""In-process baseline defenses."""

from __future__ import annotations

from collections.abc import Callable

from sentinel.defenses.baselines.allow_all import AllowAllDefense
from sentinel.defenses.baselines.authority_core import (
    authority_core,
    authority_core_auth,
    authority_core_decision,
    authority_core_decision_block,
    authority_core_evidence,
    authority_core_field,
    authority_core_full,
    authority_core_goal,
    authority_core_goal_block,
    authority_core_state,
    authority_core_v2_full,
    authority_core_v3_full,
)
from sentinel.defenses.baselines.deny_sensitive import DenySensitiveDefense
from sentinel.defenses.baselines.heuristic_risk import HeuristicRiskDefense
from sentinel.defenses.baselines.keyword import KeywordDefense
from sentinel.defenses.baselines.provenance import ProvenanceDefense
from sentinel.defenses.interface import Defense


def _hybrid_phase_1() -> Defense:
    from sentinel.defenses.hybrid import HybridPhase1Defense

    return HybridPhase1Defense()


def _hybrid_phase_2_shadow() -> Defense:
    from sentinel.defenses.hybrid import HybridPhase2ShadowDefense

    return HybridPhase2ShadowDefense()


def _hybrid_phase_3_shadow() -> Defense:
    from sentinel.defenses.hybrid import HybridPhase3ShadowDefense

    return HybridPhase3ShadowDefense()


def _hybrid_phase_4_shadow() -> Defense:
    from sentinel.defenses.hybrid import HybridPhase4ShadowDefense

    return HybridPhase4ShadowDefense()


def _hybrid_phase_5_shadow() -> Defense:
    from sentinel.defenses.hybrid import HybridPhase5ShadowDefense

    return HybridPhase5ShadowDefense()


def _hybrid_phase_5_5_shadow() -> Defense:
    from sentinel.defenses.hybrid import HybridPhase55ShadowDefense

    return HybridPhase55ShadowDefense()


def _hybrid_phase_6() -> Defense:
    from sentinel.defenses.hybrid import HybridPhase6Defense

    return HybridPhase6Defense()


def _hybrid_phase_6_5() -> Defense:
    from sentinel.defenses.hybrid import HybridPhase65Defense

    return HybridPhase65Defense()


def _sentinel_hybrid() -> Defense:
    from sentinel.defenses.hybrid import SentinelHybridDefense

    return SentinelHybridDefense()


BASELINES: dict[str, Callable[[], Defense]] = {
    "allow_all": AllowAllDefense,
    "deny_sensitive": DenySensitiveDefense,
    "keyword": KeywordDefense,
    "heuristic_risk": HeuristicRiskDefense,
    "provenance": ProvenanceDefense,
    "authority_core": authority_core,
    "authority_core_state": authority_core_state,
    "authority_core_evidence": authority_core_evidence,
    "authority_core_full": authority_core_full,
    "authority_core_auth": authority_core_auth,
    "authority_core_field": authority_core_field,
    "authority_core_decision": authority_core_decision,
    "authority_core_v2_full": authority_core_v2_full,
    "authority_core_decision_block": authority_core_decision_block,
    "authority_core_goal": authority_core_goal,
    "authority_core_goal_block": authority_core_goal_block,
    "authority_core_v3_full": authority_core_v3_full,
    "hybrid_phase_1": _hybrid_phase_1,
    "hybrid_phase_2_shadow": _hybrid_phase_2_shadow,
    "hybrid_phase_3_shadow": _hybrid_phase_3_shadow,
    "hybrid_phase_4_shadow": _hybrid_phase_4_shadow,
    "hybrid_phase_5_shadow": _hybrid_phase_5_shadow,
    "hybrid_phase_5_5_shadow": _hybrid_phase_5_5_shadow,
    "hybrid_phase_6": _hybrid_phase_6,
    "hybrid_phase_6_5": _hybrid_phase_6_5,
    "sentinel_hybrid": _sentinel_hybrid,
}


def get_baseline(name: str) -> Defense:
    key = name.replace("-", "_")
    if key not in BASELINES:
        raise KeyError(f"unknown baseline {name!r}; choose from {', '.join(sorted(BASELINES))}")
    return BASELINES[key]()
