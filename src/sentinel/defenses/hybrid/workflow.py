"""Phase-3 DRIFT-inspired task-local workflow validator in shadow mode.

This module deliberately does *not* build a global prerequisite graph. It derives a
small workflow envelope from the authenticated ``TaskContract`` for the current run
and the runtime history visible in ``DefenseRequest``. The result is diagnostic only
in Phase 3; Authority-Core v3 remains the sole decision authority.

The validator distinguishes low-risk adaptive reads from effect/object expansion:

* policy-allowed read-like actions may extend the task locally (``adaptive_read``),
* candidate objects not named by the authenticated user are surfaced for review,
* consequential actions that contradict an explicit authenticated restriction are
  surfaced as ``explicitly_restricted``, and
* only *successful* prior tool calls count as completed workflow progress.

No conversation/tool-output text is consulted here. Resolving whether a newly seen
value is actually supported by trusted evidence belongs to Phase 4 (ARGUS-style
argument grounding), not this workflow layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from sentinel.core.actions import ActionType
from sentinel.defenses.hybrid.task_contract import TaskContract
from sentinel.defenses.interface import DefenseRequest

_OBJECT_TOKEN = re.compile(r"\b[A-Z]{2,6}-\d{2,10}\b")
_IDENTITY_ARGUMENT_SUFFIX = "_id"
_READ_LIKE_SUFFIXES = ("_read", "_lookup", "_search", "_summary", "_get", "_list")
_RESTRICTION_EFFECT_WORDS = frozenset(
    {
        "send",
        "close",
        "confirm",
        "execute",
        "delete",
        "update",
        "create",
        "prepare",
        "draft",
        "write",
        "share",
        "forward",
        "publish",
        "isolate",
        "disable",
    }
)


class WorkflowDisposition(StrEnum):
    """Shadow-only classification of one candidate action."""

    NON_TOOL = "non_tool"
    POLICY_OUT_OF_SCOPE = "policy_out_of_scope"
    IN_SCOPE = "in_scope"
    ADAPTIVE_READ = "adaptive_read"
    REVIEW_OBJECT_EXPANSION = "review_object_expansion"
    REVIEW_CONSEQUENTIAL = "review_consequential"
    EXPLICITLY_RESTRICTED = "explicitly_restricted"


@dataclass(frozen=True)
class WorkflowAssessment:
    """Task-local workflow observation for one candidate action.

    ``successful_tools`` is intentionally derived only from history entries whose
    outcome is explicitly ``True``. Failed or unknown attempts never advance the
    workflow state.
    """

    run_id: str
    turn_index: int
    step_id: int
    action_digest: str
    tool: str | None
    disposition: WorkflowDisposition
    reason_codes: tuple[str, ...]
    candidate_objects: tuple[str, ...]
    foreign_objects: tuple[str, ...]
    successful_tools: tuple[str, ...]
    policy_allowed: bool
    is_consequential: bool
    shadow_only: bool = True
    validator_version: str = "phase3-v1"


def _ordered_unique(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _is_identity_argument(name: str) -> bool:
    """Whether an argument structurally names the action target/object.

    Free-text fields such as ``summary``, ``text``, ``body``, and ``reference``
    may legitimately *mention* ids learned during the task. Treating every id-like
    token inside those fields as a target-object expansion produced false workflow
    reviews in real corpus traces (for example a case note mentioning PAY-0001).
    Phase 3 therefore reasons only over structurally identity-bearing arguments;
    Phase 4 is responsible for grounding values mentioned inside free text.
    """
    return name == "id" or name.endswith(_IDENTITY_ARGUMENT_SUFFIX)


def _candidate_objects(request: DefenseRequest) -> tuple[str, ...]:
    values: list[str] = []
    action = request.candidate_action
    for name, value in action.arguments.items():
        if value is None or not _is_identity_argument(name):
            continue
        values.extend(_OBJECT_TOKEN.findall(str(value)))
    return _ordered_unique(values)


def _successful_tools(request: DefenseRequest) -> tuple[str, ...]:
    return _ordered_unique([call.tool for call in request.history_digest.tool_calls if call.succeeded is True])


def _is_read_like(tool: str) -> bool:
    return tool.endswith(_READ_LIKE_SUFFIXES)


def _restriction_blocks_tool(tool: str, restrictions: tuple[str, ...]) -> bool:
    """Conservatively map explicit negative clauses to obvious effect verbs.

    This is intentionally *not* a general natural-language planner. We only match
    action-name tokens such as ``confirm``/``execute``/``send`` that literally occur
    in an authenticated restriction clause. Ambiguous clauses remain observations,
    not invented permissions or prohibitions.
    """

    effect_tokens = {
        token
        for token in tool.lower().split("_")
        if token in _RESTRICTION_EFFECT_WORDS
    }
    if not effect_tokens:
        return False
    for clause in restrictions:
        words = set(re.findall(r"[a-z]+", clause.lower()))
        if effect_tokens & words:
            return True
    return False


def assess_workflow(request: DefenseRequest, contract: TaskContract) -> WorkflowAssessment:
    """Classify the candidate against a task-local workflow envelope.

    Phase 3 is observation-only: the returned assessment must never be used to
    override the delegated ``DefenseDecision``.
    """

    action = request.candidate_action
    candidate_objects = _candidate_objects(request)
    declared = set(contract.declared_objects)
    foreign_objects = tuple(obj for obj in candidate_objects if obj not in declared)
    successful_tools = _successful_tools(request)

    if action.type is not ActionType.TOOL_CALL or action.tool is None:
        return WorkflowAssessment(
            run_id=request.run_id,
            turn_index=contract.turn_index,
            step_id=request.step_id,
            action_digest=action.digest(),
            tool=None,
            disposition=WorkflowDisposition.NON_TOOL,
            reason_codes=("WORKFLOW_NON_TOOL",),
            candidate_objects=candidate_objects,
            foreign_objects=foreign_objects,
            successful_tools=successful_tools,
            policy_allowed=True,
            is_consequential=False,
        )

    tool = action.tool
    policy_allowed = tool in set(contract.policy_allowed_tools)
    is_consequential = tool in set(contract.policy_consequential_tools)

    if not policy_allowed:
        disposition = WorkflowDisposition.POLICY_OUT_OF_SCOPE
        reasons = ("WORKFLOW_TOOL_NOT_POLICY_ALLOWED",)
    elif is_consequential and _restriction_blocks_tool(tool, contract.explicit_restrictions):
        disposition = WorkflowDisposition.EXPLICITLY_RESTRICTED
        reasons = ("WORKFLOW_AUTHENTICATED_RESTRICTION",)
    elif _is_read_like(tool) and not is_consequential:
        if candidate_objects and not foreign_objects:
            disposition = WorkflowDisposition.IN_SCOPE
            reasons = ("WORKFLOW_DECLARED_OBJECT_READ",)
        else:
            disposition = WorkflowDisposition.ADAPTIVE_READ
            reasons = ("WORKFLOW_SAFE_READ_EXPANSION",)
    elif foreign_objects:
        disposition = WorkflowDisposition.REVIEW_OBJECT_EXPANSION
        reasons = ("WORKFLOW_UNDECLARED_OBJECT",)
    elif is_consequential:
        disposition = WorkflowDisposition.REVIEW_CONSEQUENTIAL
        reasons = ("WORKFLOW_CONSEQUENTIAL_REVIEW",)
    else:
        disposition = WorkflowDisposition.IN_SCOPE
        reasons = ("WORKFLOW_WITHIN_TASK_ENVELOPE",)

    return WorkflowAssessment(
        run_id=request.run_id,
        turn_index=contract.turn_index,
        step_id=request.step_id,
        action_digest=action.digest(),
        tool=tool,
        disposition=disposition,
        reason_codes=reasons,
        candidate_objects=candidate_objects,
        foreign_objects=foreign_objects,
        successful_tools=successful_tools,
        policy_allowed=policy_allowed,
        is_consequential=is_consequential,
    )
