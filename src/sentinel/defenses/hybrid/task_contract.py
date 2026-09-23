"""Authenticated task-contract compiler for Phase 2 shadow evaluation.

The compiler is deliberately conservative. It reads only the authenticated
``user_goal`` plus structural ``policy_context`` supplied by the harness. It
never reads tool output, memory, the current candidate action, or any other
untrusted conversation content. Phase 2 records the result for analysis only;
it does not authorize, block, escalate, or rewrite anything.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from sentinel.defenses.interface import DefenseRequest

_OBJECT_TOKEN = re.compile(r"\b[A-Z]{2,6}-\d{2,10}\b")
_RESTRICTION = re.compile(r"\b(?:do not|don't|never|must not|without)\b[^.!?;\n]*", re.IGNORECASE)


def _ordered_unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _string_list(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(sorted({item for item in value if isinstance(item, str)}))


def _goal_digest(goal: str) -> str:
    normalized = " ".join(goal.split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class TaskContract:
    """A shadow-only description of trusted task facts available this turn.

    ``explicit_restrictions`` intentionally stores literal authenticated-user
    clauses rather than converting them into tool permissions. Turning natural
    language into enforceable effects is a later hypothesis that must be tested,
    not silently assumed in the foundation compiler.
    """

    run_id: str
    turn_index: int
    goal_digest: str
    user_goal: str
    declared_objects: tuple[str, ...]
    policy_allowed_tools: tuple[str, ...]
    policy_consequential_tools: tuple[str, ...]
    explicit_restrictions: tuple[str, ...]
    source: str = "authenticated_user"
    enforcement_mode: str = "shadow"
    compiler_version: str = "phase2-v1"


def compile_task_contract(request: DefenseRequest) -> TaskContract:
    """Compile a deterministic, non-enforcing contract from trusted inputs only."""
    goal = " ".join(request.user_goal.split())
    declared_objects = _ordered_unique(_OBJECT_TOKEN.findall(goal))
    restrictions = _ordered_unique([" ".join(match.split()) for match in _RESTRICTION.findall(goal)])

    return TaskContract(
        run_id=request.run_id,
        turn_index=request.history_digest.turn_index,
        goal_digest=_goal_digest(goal),
        user_goal=goal,
        declared_objects=declared_objects,
        policy_allowed_tools=_string_list(request.policy_context.get("allowed_tools")),
        policy_consequential_tools=_string_list(request.policy_context.get("consequential_tools")),
        explicit_restrictions=restrictions,
    )
