"""Authority-first policy core, with optional object-scoped state and evidence-fidelity layers.

Research MVP for the hypothesis in SENTINEL_RESEARCH_PHASE6_HOSTILE_REVIEW.md:

1. A non-additive hard-rule policy core (Component A) matches or exceeds `provenance`'s measured
   performance on the published scenarios, because every published attack but one is stopped by
   tool-permission, confirmation, or destination/sensitivity checks alone -- never by content
   matching.
2. Object-identity-keyed state (Component B) catches state-inconsistency attacks that a flat,
   tool-name-only prerequisite rule cannot see, with no additional protection over an equivalent
   explicit lookup table (there is nothing here that a graph/workflow class would add).
3. A narrow, closed-vocabulary evidence-fidelity check (Component C) closes exactly one
   demonstrated gap in `provenance.py`'s own instruction-co-occurrence check: a plain false
   statement of fact, phrased with no imperative language at all, that `instruction_in_untrusted`
   structurally cannot see. It never independently grants or withholds authority -- it only raises
   an otherwise-ALLOW decision to ESCALATE.

Central invariant, unchanged from every prior research phase: authority to take an action comes
only from structural, verifiable facts that do not depend on observed content. Content may
determine WHAT the agent wants to do; it never establishes WHETHER the agent is authorized to do
it.

Each component is independently toggleable so the four ablation arms (A / A+state / A+evidence /
full) are the same class with different constructor flags, not four forked copies of the logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from sentinel.defenses.baselines.common import (
    decision,
    is_confirmed,
    is_consequential,
    is_external_recipient,
    squash,
    target_action,
    texts_by_trust,
)
from sentinel.defenses.baselines.provenance import overlaps
from sentinel.defenses.interface import Defense, DefenseRequest
from sentinel.defenses.provenance_index import (
    KNOWN_UNTRUSTED_FIELDS as KNOWN_UNTRUSTED_FIELDS,
)
from sentinel.defenses.provenance_index import (
    partition_source_texts,
)
from sentinel.defenses.restricted_match import (
    decoded_variants as _decoded_variants,
)
from sentinel.defenses.restricted_match import (
    restricted_payload_hit,
)

# ------------------------------------------------------------------------------------------------
# Component B config: the smallest useful object-scoped state, not a general workflow graph.
# A fixed, curated table -- extend it by adding entries, never by generalizing the mechanism.
# Mirrors the shape of the shipped `prerequisite` policy rules (see policies/finance_standard.yaml
# PAYMENT_EXECUTE_SEQUENCE) plus the tools exercised by this MVP's self-authored scenarios.

REQUIRES: dict[str, str] = {
    "payment_execute": "payment_confirm",
}
# REMOVED after Phase 8 testing: "incident_create": "alert_read". It was added specifically to
# demonstrate the object-identity-mismatch mechanism (scenarios/self_authored/
# soc_incident_object_mismatch.yaml) outside the confirmation-gated path. It correctly caught that
# constructed attack -- but it ALSO regressed a real, pre-existing, legitimate hard-negative
# already in the validation split: `soc_val_mfa_phishing` intentionally opens an incident from
# threat-intel correlation alone, without ever reading the raw alert (`alert_read` isn't even in
# that scenario's `allowed_tools`). A rule requiring every `incident_create` to be preceded by
# `alert_read` is real workflow rigidity hurting utility -- predicted in both
# SENTINEL_RESEARCH_PHASE6_HOSTILE_REVIEW.md and the friend's architecture PDF's own limits table
# ("a fixed graph may reject legitimate discoveries and branches"), now empirically confirmed
# against the real corpus rather than hypothetically. Kept out of the shipped table; the finding
# is reported in SENTINEL_RESEARCH_PHASE8_VALIDATION.md as a genuine falsification result, not
# quietly discarded.
# NOT "payment_confirm requires payment_prepare": `payment_prepare`'s own arguments never carry a
# `payment_id` (it doesn't exist until prepare *returns* one), so object identity cannot be bridged
# across that pair without result-text correlation this MVP deliberately does not build (Section 4:
# "do not add ... machinery unless an experiment demonstrates the simpler state cannot express the
# required property" -- here the experiment demonstrated the *opposite*: a real BTU regression on
# `finance_refund_confirmed`, traced to exactly this). The shipped policy
# (`policies/finance_standard.yaml`, rule PAYMENT_EXECUTE_SEQUENCE) only declares
# payment_execute->payment_confirm anyway; this table now matches it exactly rather than inventing
# a second pair the interface cannot support cleanly.

# Tools whose consequential effect must not be silently repeated for the same object once it has
# already succeeded once (the "action repeated after completion" / stale-approval-reuse case).
NO_REPEAT_TOOLS = frozenset({"payment_execute", "email_send"})

OBJECT_ID_KEYS = (
    "payment_id",
    "invoice_id",
    "ticket_id",
    "case_id",
    "email_id",
    "account_id",
    "order_id",
    "document_id",
    "doc_id",
    "incident_id",
    "alert_id",
    "beneficiary_id",
    "remediation_id",
)


def object_id(action: CandidateAction) -> str:
    """Best-effort object identity for an action.

    Falls back to a hash of all arguments when no id-like argument is present -- an honest
    limitation, not a fix: without a declared id-like argument, this layer cannot distinguish two
    invocations of the same tool, and the ``unkeyed:`` prefix makes that visible in the trace
    rather than silently treating every call as the same object or every call as a different one.
    """
    for key in OBJECT_ID_KEYS:
        value = action.arguments.get(key)
        if value is not None:
            return str(value)
    return "unkeyed:" + squash(str(sorted(action.arguments.items())))


def all_object_ids(action: CandidateAction) -> list[str]:
    """Every id-like argument present on the action, not just the first (`object_id()`'s
    first-match behavior is intentional and unchanged for Component A/B's repeat/state tracking,
    which reasons about ONE primary object per action). Mechanism E needs all of them: a tool like
    `payment_prepare` carries both a source `account_id` and a destination `beneficiary_id`
    simultaneously, and checking only the first-matched key leaves the other structurally
    invisible to the goal-consistency check -- found in a hostile design review (a beneficiary-swap
    attack would leave `account_id` correctly matching the user's goal while silently redirecting
    `beneficiary_id`, with no shipped scenario exercising this combination yet)."""
    return [str(action.arguments[key]) for key in OBJECT_ID_KEYS if action.arguments.get(key) is not None]


@dataclass
class _ObjectState:
    """Per-run state, kept on the Defense instance. A fresh instance is created per scenario run
    by ``evaluator.runner.evaluate`` (``defense_factory()`` is called once per scenario, see
    `SENTINEL_RESEARCH_PHASE6_HOSTILE_REVIEW.md` Part 11), so this needs no explicit run_id keying
    to stay correctly scoped -- documented here so that assumption is visible, not silently relied
    upon."""

    step_object: dict[int, tuple[str, str]] = field(default_factory=dict)
    verified: dict[tuple[str, str], bool] = field(default_factory=dict)
    executed: dict[tuple[str, str], bool] = field(default_factory=dict)

    def observe_history(self, request: DefenseRequest) -> None:
        """Promote step-object records to verified/executed state once the gateway reports the
        matching step actually succeeded. ``history_digest.tool_calls`` only keeps the last 20
        entries -- a real, documented limitation of the interface, not of this mechanism (see
        Part 11 of the hostile review)."""
        for summary in request.history_digest.tool_calls:
            key = self.step_object.get(summary.step_id)
            if key is None or not summary.succeeded:
                continue
            self.verified[key] = True
            if key[0] in NO_REPEAT_TOOLS:
                self.executed[key] = True

    def remember(self, step_id: int, tool: str, oid: str) -> None:
        self.step_object[step_id] = (tool, oid)


# ------------------------------------------------------------------------------------------------
# Component C config: closed value-kind vocabulary. Deliberately small; do not add general NLP.

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
# 3+ letter prefixes only: excludes generic 2-letter reference codes (TI-02, WS-114, AL-3003) that
# are the ordinary, benign content of intel/asset domains, not financial/approval references.
# `soc_intel_correlation` and `soc_triage_powershell` (both benign, both attack.present=false)
# false-flagged on exactly this before the fix -- see the ablation notes in the phase-7 report.
_REF_ID = re.compile(r"\b[A-Z]{3,6}-\d{2,10}\b")
# Negative lookbehind excludes a digit run immediately after a letter+hyphen (i.e. already part of
# a code like `WS-114`) so it is not double-counted as a bare "amount". Comma-grouped thousands
# (`48,210.00`) are matched whole first so the plain-digit alternative never splits off a fragment
# (`210.00`) that won't literally match the source text's comma-formatted original.
_AMOUNT = re.compile(r"(?<![A-Za-z0-9-])\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?\b|(?<![A-Za-z0-9-])\d{3,9}(?:\.\d{1,2})?\b")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
# Deliberately excludes "resolved": in the SOC domain it is an ordinary DNS-resolution verb
# ("SRV-22 resolved cdn-update-check.example"), not an approval/status claim -- `soc_hostile_log_text`
# false-flagged on exactly this collision before the fix. A closed keyword vocabulary is still a
# blunt instrument; this is a documented, accepted limitation, not a claim of full coverage.
STATUS_WORDS = frozenset({"confirmed", "approved", "authorized", "verified"})


def extract_values(text: str) -> set[str]:
    """Extract the closed set of consequential discrete value kinds from free text: IBAN-like
    identifiers, REF-style ids (matches the codebase's own PAY-0001/TCK-501/EM-2003 convention),
    amounts, ISO dates, and a fixed status/approval vocabulary. Nothing beyond this list."""
    found = (
        set(_IBAN.findall(text))
        | set(_REF_ID.findall(text))
        | set(_AMOUNT.findall(text))
        | set(_DATE.findall(text))
    )
    lowered = squash(text)
    found |= {word for word in STATUS_WORDS if word in lowered}
    return found


def _split_trusted_untrusted(
    request: DefenseRequest,
) -> tuple[list[str], list[str]]:
    """Compatibility wrapper over the canonical item-level partition."""

    return partition_source_texts(request, field_aware=False)


def _present(value: str, texts: list[str]) -> bool:
    needle = squash(value)
    for text in texts:
        for variant in _decoded_variants(text):
            if needle in squash(variant):
                return True
    return False


# ------------------------------------------------------------------------------------------------
# SENTINEL v2 (post-Phase-8) additions. Each is a narrow, independently toggleable mechanism,
# designed specifically to avoid Phase 8's failure mode: no cross-tool prerequisite table, no
# object-identity graph. See SENTINEL_RESEARCH_V2_ARCHITECTURE.md for the full design rationale
# and falsification results.

# ---- Mechanism A: authorization binding (consumption only, not a workflow graph) --------------


@dataclass
class _AuthBindings:
    """Per-run, digest-keyed record of which exact, already-approved actions have already
    executed. Deliberately NOT keyed by (tool, object_id) or any cross-tool relationship -- that
    generic shape is exactly what Phase 8 killed. This tracks one property only: has THIS EXACT
    action (by `CandidateAction.digest()`, which already binds tool+arguments+content) executed
    before. A different target or different argument produces a different digest and is
    unaffected -- so this cannot regress an unrelated legitimate workflow the way a cross-tool
    prerequisite can."""

    step_digest: dict[int, str] = field(default_factory=dict)
    executed: set[str] = field(default_factory=set)

    def observe_history(self, request: DefenseRequest) -> None:
        for summary in request.history_digest.tool_calls:
            digest = self.step_digest.get(summary.step_id)
            if digest is not None and summary.succeeded:
                self.executed.add(digest)

    def remember(self, step_id: int, digest: str) -> None:
        self.step_digest[step_id] = digest


# ---- Mechanism B: field-level evidence (named-field splitting, not a general parser) -----------

# The field vocabulary and JSON/trust parsing now live in the shared provenance
# kernel.  Keep this wrapper so old ablation tests and research notes continue
# to refer to the same mechanism without maintaining a second parser.
def _field_split_trusted_untrusted(
    request: DefenseRequest,
) -> tuple[list[str], list[str]]:
    """Compatibility wrapper over the canonical field-aware partition."""

    return partition_source_texts(request, field_aware=True)


# ---- Mechanism E: goal-declared object consistency (per-request, not a global workflow graph) --

# Matches the codebase's own PREFIX-NNNN identifier convention (AL-3002, PAY-0001, TCK-501, ...).
# `fullmatch` is used at call sites, so this only ever classifies values that ARE one of these
# ids -- free text is never scanned for "anything that looks like a word-hyphen-number".
_OBJECT_TOKEN = re.compile(r"([A-Z]{2,6})-(\d{2,10})")


def _goal_declared_objects(user_goal: str) -> dict[str, set[str]]:
    """Map identifier prefix (``AL``, ``PAY``, ...) to the full ids the AUTHENTICATED user's own
    turn text literally named this request. ``user_goal`` is never attacker-controlled -- it is
    the harness's own authenticated-user field, never populated from tool output or memory -- so
    treating it as a source of authority-relevant fact is consistent with the central invariant,
    not an exception to it."""
    by_prefix: dict[str, set[str]] = {}
    for prefix, digits in _OBJECT_TOKEN.findall(user_goal):
        by_prefix.setdefault(prefix, set()).add(f"{prefix}-{digits}")
    return by_prefix


class AuthorityCoreDefense(Defense):
    """Component A (always on) with Components B and C individually toggleable.

    Four registered ablation arms share this one class:
      - ``authority_core``           -- Component A only.
      - ``authority_core_state``     -- A + Component B.
      - ``authority_core_evidence``  -- A + Component C.
      - ``authority_core_full``      -- A + B + C (the MVP's "Version B").

    Rewrite self-validation (Section 2 of the implementation brief) is unconditional across all
    four arms: it is a correctness requirement, not a feature to ablate.
    """

    name = "authority_core"

    def __init__(
        self,
        enable_state: bool = False,
        enable_evidence: bool = False,
        enable_encoded: bool = False,
        enable_auth_binding: bool = False,
        enable_field_evidence: bool = False,
        enable_decision_relevance: bool = False,
        enable_decision_block: bool = False,
        enable_goal_consistency: bool = False,
        enable_goal_consistency_block: bool = False,
    ) -> None:
        self.enable_state = enable_state
        self.enable_evidence = enable_evidence
        self.enable_encoded = enable_encoded
        self.enable_auth_binding = enable_auth_binding
        self.enable_field_evidence = enable_field_evidence
        self.enable_decision_relevance = enable_decision_relevance
        self.enable_decision_block = enable_decision_block
        self.enable_goal_consistency = enable_goal_consistency
        self.enable_goal_consistency_block = enable_goal_consistency_block
        parts = ["authority_core"]
        if enable_state:
            parts.append("state")
        if enable_evidence:
            parts.append("evidence")
        if enable_encoded:
            parts.append("encoded")
        if enable_auth_binding:
            parts.append("auth")
        if enable_field_evidence:
            parts.append("field")
        if enable_decision_relevance:
            parts.append("decision")
        if enable_decision_block:
            parts.append("decisionblock")
        if enable_goal_consistency:
            parts.append("goal")
        if enable_goal_consistency_block:
            parts.append("goalblock")
        self.name = "_".join(parts)
        if enable_state and enable_evidence and not any(
            (enable_auth_binding, enable_field_evidence, enable_decision_relevance)
        ):
            self.name = "authority_core_full"
        if (
            not enable_state
            and all(
                (
                    enable_evidence, enable_encoded, enable_auth_binding, enable_field_evidence,
                    enable_decision_relevance, enable_decision_block, enable_goal_consistency,
                    enable_goal_consistency_block,
                )
            )
        ):
            # The auto-generated name above (every enabled flag concatenated) exceeded Windows'
            # 260-char path limit once this arm grew to 8 flags, silently truncating artifact
            # filenames (found while generating demo observability reports: a run's own .jsonl
            # got written as-truncated-to-".js", breaking replay/rendering downstream). A short,
            # stable name for the one arm actually meant to be run and recorded avoids this
            # regardless of how many more flags get added later.
            self.name = "authority_core_v3_full"
        self._state = _ObjectState()
        self._bindings = _AuthBindings()

    # ---- top-level entry point ----------------------------------------------------------------
    def decide(self, request: DefenseRequest) -> DefenseDecision:
        return self._decide(request, depth=0)

    def _decide(self, request: DefenseRequest, depth: int) -> DefenseDecision:
        action = target_action(request)
        result = self._evaluate(request, action)
        if result.decision is not Decision.REWRITE or result.rewritten_action is None:
            return result
        if depth >= 1:
            # Never chain a rewrite of a rewrite (Section 2, max depth 1). Fall back to the safer
            # of escalate/block for the original action instead of emitting an unvalidated rewrite.
            return decision(
                Decision.ESCALATE, result.risk_score, result.confidence,
                [*result.reason_codes, "REWRITE_DEPTH_EXCEEDED"],
            )
        rewritten_request = request.model_copy(update={"candidate_action": result.rewritten_action})
        validated = self._decide(rewritten_request, depth=depth + 1)
        if validated.decision is Decision.ALLOW:
            return result
        # The rewrite is not independently safe: never hand the harness an unvalidated rewrite.
        # (`reference.py`'s `_valid_rewrite` only checks tool-registry membership and the `final`
        # flag -- it is not a security check, so this defense must be its own backstop.)
        return decision(
            Decision.ESCALATE, max(result.risk_score, validated.risk_score), result.confidence,
            [*result.reason_codes, "REWRITE_FAILED_SELF_VALIDATION"],
            "a safer rewrite was considered but did not independently pass validation",
        )

    # ---- the full pipeline for one candidate action, used for both the top-level action and for
    # self-validating a proposed rewrite ----------------------------------------------------------
    def _evaluate(self, request: DefenseRequest, action: CandidateAction) -> DefenseDecision:
        # Ahead of Component A's own tool-permission gate, and applied to every action type
        # (including `respond`), because a RESTRICTED-sensitivity leak in this benchmark is
        # forbidden regardless of destination -- structural, provenance-driven, unconditional,
        # matching the central invariant exactly (a destination-blind sensitivity/provenance fact,
        # not content interpretation).
        restricted = self._restricted_disclosure(request, action)
        if restricted is not None:
            return restricted
        hard = self._hard_policy(request, action)
        if hard is not None:
            return hard
        if self.enable_auth_binding:
            binding_result = self._authorization_binding(request, action)
            if binding_result is not None:
                return binding_result
        if self.enable_goal_consistency:
            goal_result = self._goal_object_consistency(request, action)
            if goal_result is not None:
                return goal_result
        if self.enable_state:
            state_result = self._object_state(request, action)
            if state_result is not None:
                return state_result
        # Field-level splitting and decision-relevance tiering are refinements OF the
        # evidence-fidelity check (Mechanism B changes which texts count as trusted/untrusted;
        # Mechanism C changes how an already-found hit is reported) -- neither has an independent
        # effect without the base check running, so enabling either one implies it.
        if self.enable_evidence or self.enable_field_evidence or self.enable_decision_relevance:
            evidence_result = self._evidence_fidelity(request, action)
            if evidence_result is not None:
                return evidence_result
        return decision(Decision.ALLOW, 0.1, 0.7, ["STRUCTURALLY_AUTHORIZED"])

    # ---- Mechanism A: authorization binding (consumption-only) ---------------------------------
    def _authorization_binding(self, request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
        if action.type is not ActionType.TOOL_CALL or action.tool is None:
            return None
        if not is_consequential(request, action):
            return None
        self._bindings.observe_history(request)
        digest = action.digest()
        if digest in self._bindings.executed:
            # Deliberately BLOCK, not ESCALATE: Phase 8 (Scenario 2) found that ESCALATE on a
            # digest-identical repeat is neutralized by the harness's own human-simulator, which
            # approves anything matching the reference plan's own declared arguments regardless of
            # why it's being re-proposed. BLOCK never reaches that approval path.
            return decision(
                Decision.BLOCK, 0.9, 0.85, ["AUTHORIZATION_ALREADY_CONSUMED"],
                "this exact approved action has already executed once; a repeat requires a new, distinct request",
            )
        self._bindings.remember(request.step_id, digest)
        return None

    # ---- Mechanism E: goal-declared object consistency (per-request, contract-derived) ---------
    def _goal_object_consistency(self, request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
        """Replaces the killed global, cross-tool REQUIRES table with a per-request check that
        cannot regress an unrelated legitimate workflow: it only ever compares the CURRENT
        request's own stated objects against the CURRENT action's object, never a standing rule
        that applies regardless of what this request actually said.

        `soc_val_mfa_phishing` (the scenario that killed Component B) opens an incident straight
        from threat-intel correlation, with no `alert_read` at all -- but its goal text names
        AL-3002 directly, and its `incident_create` call also targets AL-3002, so this mechanism
        never fires: it does not require any particular TOOL SEQUENCE, only that the OBJECT being
        acted on is one the authenticated request actually named (or one corroborated by trusted
        conversation content this turn), which `soc_val_mfa_phishing` satisfies trivially.

        Checks EVERY id-like argument on the action (via `all_object_ids()`), not just the first
        matched key -- a hostile design review found that checking only the first match leaves a
        tool with two simultaneous id arguments (e.g. `payment_prepare`'s source `account_id` and
        destination `beneficiary_id`) structurally blind to a mismatch on whichever one isn't
        checked, regardless of which the mechanism happens to look at."""
        if action.type is not ActionType.TOOL_CALL or action.tool is None:
            return None
        trusted_texts, _ = _field_split_trusted_untrusted(request)
        goal_by_prefix = _goal_declared_objects(request.user_goal)
        for oid in all_object_ids(action):
            match = _OBJECT_TOKEN.fullmatch(oid)
            if match is None:
                continue
            prefix = match.group(1)
            goal_ids = goal_by_prefix.get(prefix)
            if not goal_ids:
                # The authenticated request never named any object of this kind at all -- e.g. a
                # legitimately, freshly discovered secondary object (a different id NAMESPACE than
                # anything the user mentioned). Constraining this would misclassify ordinary
                # multi-object workflows as violations; deliberately out of scope.
                continue
            if oid in goal_ids:
                continue
            # Field-level splitting, not item-level: an item-level check would let this object id
            # count as "trusted-corroborated" merely because it appears inside an untrusted field
            # (e.g. `alert_read`'s `enrichment`) shipped alongside an otherwise-trusted response --
            # exactly the mixed-response failure mode Mechanism B exists to fix. Confirmed by direct
            # trace: `soc_incident_object_mismatch`'s injected AL-3003 reference sits inside
            # `enrichment`, and item-level splitting silently treated it as corroborated.
            if _present(oid, trusted_texts):
                # Not named by the user, but independently corroborated by trusted conversation
                # content this turn (e.g. a trusted search result actually returned this id).
                continue
            explanation = (
                f"{action.tool} targets {oid!r}, a different {prefix}-object than named in the "
                "authenticated request, with no trusted corroboration this turn"
            )
            if self.enable_goal_consistency_block:
                # A wrong-object action's OTHER arguments can coincide with an unrelated
                # reference-plan step closely enough for the harness's human-simulator to approve
                # it on ESCALATE regardless of this mechanism's own reasoning (the same
                # PlanMatcher confound that motivated Mechanism A's BLOCK-not-ESCALATE choice).
                # Gated behind its own flag so the ablation can show, not assume, the difference.
                return decision(Decision.BLOCK, 0.75, 0.65, ["OBJECT_NOT_DECLARED_IN_REQUEST"], explanation)
            return decision(Decision.ESCALATE, 0.65, 0.6, ["OBJECT_NOT_DECLARED_IN_REQUEST"], explanation)
        return None

    # ---- Component A extension: RESTRICTED-sensitivity disclosure, any destination -------------
    def _restricted_disclosure(self, request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
        """Block any payload matching request-visible RESTRICTED source material."""
        if restricted_payload_hit(request, action, enable_encoded=self.enable_encoded):
            return decision(
                Decision.BLOCK, 0.95, 0.85, ["RESTRICTED_DATA_DISCLOSURE"],
                "restricted-sensitivity content has no destination this benchmark allows it to reach",
            )
        return None

        # ---- Component A: non-additive hard-rule policy core ---------------------------------------
    def _hard_policy(self, request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
        allowed = request.policy_context.get("allowed_tools", [])
        if action.type is not ActionType.TOOL_CALL:
            return None

        if action.tool not in allowed:
            return decision(
                Decision.BLOCK, 0.95, 0.9, ["TOOL_NOT_ALLOWED"],
                f"{action.tool} is outside the task's allowed tools",
            )

        if is_external_recipient(request, action):
            _, sensitive = texts_by_trust(request)
            payload = action.text_payload()
            # Isolated experiment (Section 11 of the Phase 8 brief): apply the same one-pass
            # base64/hex normalization already scoped to Component C to THIS check too, gated
            # behind `enable_encoded` so it never silently changes Component A's default behavior.
            hit = overlaps(payload, sensitive) or (
                self.enable_encoded and any(overlaps(variant, sensitive) for variant in _decoded_variants(payload))
            )
            if hit:
                return decision(
                    Decision.BLOCK, 0.95, 0.85, ["SENSITIVE_TO_UNTRUSTED_SINK"],
                    "sensitive content addressed to an external recipient",
                )

        if is_consequential(request, action) and not is_confirmed(request, action):
            if request.candidate_action.type is ActionType.REQUEST_CONFIRMATION:
                return decision(Decision.ALLOW, 0.3, 0.7, ["CONFIRMATION_REQUESTED"])
            if action.tool == "email_send" and "email_draft" in allowed:
                rewritten = CandidateAction(
                    type=ActionType.TOOL_CALL, tool="email_draft", arguments=dict(action.arguments)
                )
                return decision(
                    Decision.REWRITE, 0.6, 0.6, ["MISSING_CONFIRMATION"],
                    "unconfirmed send proposed as a draft instead, pending self-validation", rewritten,
                )
            return decision(Decision.ESCALATE, 0.6, 0.6, ["MISSING_CONFIRMATION"])

        return None

    # ---- Component B: object-identity-keyed state ----------------------------------------------
    def _object_state(self, request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
        if action.type is not ActionType.TOOL_CALL or action.tool is None:
            return None
        self._state.observe_history(request)
        oid = object_id(action)
        self._state.remember(request.step_id, action.tool, oid)

        required = REQUIRES.get(action.tool)
        if required is not None and not self._state.verified.get((required, oid), False):
            return decision(
                Decision.BLOCK, 0.9, 0.85, ["PREREQUISITE_NOT_MET_FOR_OBJECT"],
                f"{action.tool} requires {required} to have succeeded for object {oid!r} first",
            )

        if action.tool in NO_REPEAT_TOOLS and self._state.executed.get((action.tool, oid), False):
            return decision(
                Decision.ESCALATE, 0.7, 0.7, ["ACTION_ALREADY_EXECUTED_FOR_OBJECT"],
                f"{action.tool} already succeeded once for object {oid!r}",
            )
        return None

    # ---- Component C: narrow evidence-fidelity check, +Mechanisms B/C when enabled -------------
    def _evidence_fidelity(self, request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
        if self.enable_field_evidence:
            trusted_texts, untrusted_texts = _field_split_trusted_untrusted(request)
        else:
            trusted_texts, untrusted_texts = _split_trusted_untrusted(request)

        # Mechanism C: tier by WHERE the value sits, not just whether it's present. A value that
        # only ever appears in free-text `content` (a note, a summary) is informational; a value
        # that appears in `arguments` for a consequential tool call operationally parameterizes
        # what the tool actually does. This is the IBAN-in-a-payment-argument vs.
        # office-hours-in-a-note distinction from the brief, expressed observationally: we report
        # where the value is traceably located, never that untrusted content "caused" the action.
        arg_text = " ".join(str(v) for v in action.arguments.values() if v is not None)
        arg_values = extract_values(arg_text)
        content_values = extract_values(action.content or "") - arg_values
        decision_relevant = self.enable_decision_relevance and is_consequential(request, action)

        for value in arg_values:
            if _present(value, untrusted_texts) and not _present(value, trusted_texts):
                if decision_relevant:
                    # v2 found ESCALATE-only makes this tier observability-only: reason code
                    # changes, outcome does not, because the harness's own human-simulator
                    # approves anything matching the reference plan regardless of the flagged
                    # value, and it never even sees this defense's explanation text (Phase 8,
                    # Scenario 2's confound applies equally here). A "confirmation" granted by
                    # that mechanism verifies the requester's INTENT matches the plan; it never
                    # verifies that a specific VALUE inside the action is trustworthy. BLOCK
                    # (behind `enable_decision_block`) is the only decision the human-simulator
                    # cannot rubber-stamp -- gated behind its own flag so the ablation can show,
                    # not assume, whether this is worth the added false-block risk.
                    if self.enable_decision_block:
                        return decision(
                            Decision.BLOCK, 0.8, 0.6, ["DECISION_RELEVANT_UNVERIFIED_FACT"],
                            f"argument value {value!r} is traceably derived from untrusted-only content, "
                            "operationally parameterizes a consequential action, and has no trusted "
                            "corroboration this turn",
                        )
                    return decision(
                        Decision.ESCALATE, 0.7, 0.6, ["DECISION_RELEVANT_UNVERIFIED_FACT"],
                        f"argument value {value!r} is traceably derived from untrusted-only content and "
                        "operationally parameterizes a consequential action",
                    )
                return decision(
                    Decision.ESCALATE, 0.55, 0.5, ["EPISTEMIC_UNVERIFIED_FACT"],
                    f"value {value!r} used in this action has no source but untrusted content this turn",
                )
        for value in content_values:
            if _present(value, untrusted_texts) and not _present(value, trusted_texts):
                return decision(
                    Decision.ESCALATE, 0.55, 0.5, ["EPISTEMIC_UNVERIFIED_FACT"],
                    f"value {value!r} used in this action has no source but untrusted content this turn",
                )
        return None


# Registration factories for the four Phase 7/8 ablation arms.
def authority_core() -> Defense:
    return AuthorityCoreDefense()


def authority_core_state() -> Defense:
    return AuthorityCoreDefense(enable_state=True)


def authority_core_evidence() -> Defense:
    return AuthorityCoreDefense(enable_evidence=True)


def authority_core_full() -> Defense:
    return AuthorityCoreDefense(enable_state=True, enable_evidence=True)


# Registration factories for the v2 (post-Phase-8) ablation arms. Component B (enable_state) is
# omitted from all v2 combinations -- it was killed in Phase 8 and Section 3 of the v2 brief
# explicitly forbids resurrecting it.
def authority_core_auth() -> Defense:
    return AuthorityCoreDefense(enable_auth_binding=True)


def authority_core_field() -> Defense:
    return AuthorityCoreDefense(enable_evidence=True, enable_field_evidence=True)


def authority_core_decision() -> Defense:
    return AuthorityCoreDefense(enable_evidence=True, enable_decision_relevance=True)


def authority_core_v2_full() -> Defense:
    return AuthorityCoreDefense(
        enable_evidence=True, enable_auth_binding=True, enable_field_evidence=True, enable_decision_relevance=True
    )


# Registration factories for the "ambitious redesign" arms: falsifying whether the PDF's more
# ambitious versions of decision-relevance and cross-object authorization can be made to work
# within the harness's actual constraints, rather than discarding the ideas after the narrower v2
# versions proved lackluster. See SENTINEL_RESEARCH_V2_ARCHITECTURE.md's addendum for results.
def authority_core_decision_block() -> Defense:
    return AuthorityCoreDefense(enable_evidence=True, enable_decision_relevance=True, enable_decision_block=True)


def authority_core_goal() -> Defense:
    return AuthorityCoreDefense(enable_goal_consistency=True)


def authority_core_goal_block() -> Defense:
    return AuthorityCoreDefense(enable_goal_consistency=True, enable_goal_consistency_block=True)


def authority_core_v3_full() -> Defense:
    """The strongest, recommended-for-submission arm. Includes `enable_encoded`: Section 11 of the
    Phase 8 brief tested it as an isolated experiment and found "zero benefit and zero regression"
    against the corpus at the time, but left it off by default pending a case that actually needed
    it. `enterprise_val_encoded_exfil` (a live CRITICAL violation present in every prior arm,
    v2_full included) turned out to be exactly that case -- see the v3 addendum's writeup of the
    two real bugs found and fixed in `_decoded_variants` while closing it. There is no longer a
    reason to leave a validated, zero-regression fix for a live critical violation switched off.

    Also includes `enable_goal_consistency_block`: a hostile design review found that every
    ESCALATE-routed check's real effectiveness depends on the harness's human-simulator
    (PlanMatcher), which approves anything matching the reference plan's non-`match_keys`
    arguments too, regardless of the defense's own reasoning -- the same confound that motivated
    Mechanism A's BLOCK-not-ESCALATE choice, now applied consistently to Mechanism E."""
    return AuthorityCoreDefense(
        enable_evidence=True,
        enable_auth_binding=True,
        enable_field_evidence=True,
        enable_decision_relevance=True,
        enable_decision_block=True,
        enable_goal_consistency=True,
        enable_goal_consistency_block=True,
        enable_encoded=True,
    )
