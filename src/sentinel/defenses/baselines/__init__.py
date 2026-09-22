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
}


def get_baseline(name: str) -> Defense:
    key = name.replace("-", "_")
    if key not in BASELINES:
        raise KeyError(f"unknown baseline {name!r}; choose from {', '.join(sorted(BASELINES))}")
    return BASELINES[key]()
