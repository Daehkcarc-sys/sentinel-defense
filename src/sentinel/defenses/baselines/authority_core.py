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

import base64
import binascii
import json
import re
from dataclasses import dataclass, field

from sentinel.core.actions import ActionType, CandidateAction, Decision, DefenseDecision
from sentinel.core.provenance import Sensitivity
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
    found = set(_IBAN.findall(text)) | set(_REF_ID.findall(text)) | set(_AMOUNT.findall(text)) | set(_DATE.findall(text))
    lowered = squash(text)
    found |= {word for word in STATUS_WORDS if word in lowered}
    return found


# A run of base64-alphabet characters long enough to be a deliberate payload, not incidental
# text. Used to find an encoded SUBSTRING inside a larger string (e.g. `text_payload()` joins
# every argument value together, so a base64 `body` sits next to a plain-text `to`/`subject`
# that would otherwise break a whole-string decode attempt).
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _decoded_variants(text: str) -> list[str]:
    """Best-effort base64/hex normalization (Phase 3 Section 2 case 12's scoped fix, widened after
    Section 4 falsification found the original whole-string-only decode misses exactly the case it
    exists for): `text_payload()` joins every argument's value with newlines, so a single base64
    `body` argument sitting next to plain `to`/`subject` values never decodes as a whole string.
    This tries the whole string first (unchanged), then any long base64-alphabet substring found
    within it, decoded independently. Still not a general decoder: each attempt silently gives up
    if it doesn't cleanly decode to text; nothing here trawls for partial/nested encodings."""
    variants = [text]
    stripped = "".join(text.split())
    try:
        variants.append(base64.b64decode(stripped + "==", validate=False).decode("utf-8", "ignore"))
    except (binascii.Error, ValueError):
        pass
    if re.fullmatch(r"[0-9a-fA-F]{8,}", stripped):
        try:
            variants.append(bytes.fromhex(stripped).decode("utf-8", "ignore"))
        except ValueError:
            pass
    # Scanned against the ORIGINAL text, not `stripped`: `text_payload()` joins separate argument
    # values with newlines, and stripping all whitespace first erases that boundary, gluing the
    # tail of an unrelated short argument (e.g. `...example` + `ref`) onto the front of an
    # adjacent base64 run and breaking the decode. The `{20,}` minimum length already keeps
    # ordinary short words (email localparts, "ref") from being mistaken for a run on their own.
    for run in _BASE64_RUN.findall(text):
        try:
            variants.append(base64.b64decode(run + "==", validate=False).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            pass
    return variants


def _split_trusted_untrusted(request: DefenseRequest) -> tuple[list[str], list[str]]:
    """(trusted-or-better texts, untrusted-or-worse texts) this turn, classified per conversation
    item. An item with no provenance reference is treated as trusted-tier, matching
    `least_trusted([])`'s existing convention elsewhere in the baselines.

    A single conversation item can carry *multiple* provenance records of different trust levels
    -- confirmed directly: `account_summary`'s own response mixes a trusted account record with an
    untrusted-by-design `advisory` field in one JSON blob, with no attack present at all. An
    "all refs must be trusted" rule would sweep the trusted balance value into the untrusted
    bucket purely because it shares a response with an unrelated untrusted field, producing a
    false escalation on a benign, fully-agreeing case
    (`finance_cross_source_agreement_control.yaml`, caught during Phase 8 validation). So a mixed
    item counts as trusted-source if *any* ref clears the bar -- erring toward fewer false
    escalations, consistent with the "never escalate merely because untrusted content is present"
    requirement -- and separately as untrusted-source if any ref does not, so a value that only
    ever appears in the untrusted portion of some *other* item is still caught."""
    records = {r.id: r.provenance for r in request.provenance}
    trusted: list[str] = []
    untrusted: list[str] = []
    for item in request.conversation:
        provs = [records[pid] for pid in item.provenance_ids if pid in records]
        if not provs or any(p.trust_level.is_trusted for p in provs):
            trusted.append(item.content)
        if provs and any(not p.trust_level.is_trusted for p in provs):
            untrusted.append(item.content)
    return trusted, untrusted


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

# Field names the shipped domains document as untrusted-by-design within an otherwise trusted
# response. v2 hand-curated this as {"advisory", "enrichment"} from manual inspection of two
# domains; that manual pass MISSED a third, real one -- `TicketRead.untrusted_text_fields =
# {"latest_comment": "requester_portal"}` in the enterprise domain. Rather than patch the set by
# hand a third time, this is now discovered once, at import time, by reading every shipped
# `Tool.untrusted_text_fields` class attribute directly (the same attribute
# `sentinel.tools.gateway` itself already reads to build provenance for a tool's response) --
# so the field list can never again silently drift from what the domains actually declare. This is
# not a content classifier: it still only recognizes fields domain authors explicitly named as
# untrusted-by-design, and it still runs once, not per-decision.
def _discover_untrusted_fields() -> frozenset[str]:
    try:
        from sentinel.domains import DOMAIN_TOOLS
    except ImportError:
        # Should not happen in the shipped package layout; fail safe to the last known-good
        # manually curated set rather than silently disabling Mechanism B.
        return frozenset({"advisory", "enrichment", "latest_comment"})
    fields: set[str] = set()
    for factory in DOMAIN_TOOLS.values():
        for tool in factory():
            fields.update(tool.untrusted_text_fields)
    return frozenset(fields)


KNOWN_UNTRUSTED_FIELDS = _discover_untrusted_fields()


def _field_split_trusted_untrusted(request: DefenseRequest) -> tuple[list[str], list[str]]:
    """Like `_split_trusted_untrusted`, but for a JSON-object conversation item containing a
    `KNOWN_UNTRUSTED_FIELDS` key, only THAT field's value is treated as untrusted-source text and
    the rest of the object is treated as trusted-source text (subject to the item's own base
    provenance) -- rather than the whole item inheriting one shared label either way. Falls back
    to `_split_trusted_untrusted`'s item-level behavior for anything that doesn't parse as a JSON
    object, or that parses but has no recognized field.

    The critical regression this exists to fix, stated as the required test: a trusted
    `account.balance` value must not be tainted merely because it ships alongside an untrusted
    `account.advisory` field in the same response, AND `account.advisory`'s own untrusted content
    must not become trusted merely because `balance` is trusted in the same blob."""
    records = {r.id: r.provenance for r in request.provenance}
    trusted: list[str] = []
    untrusted: list[str] = []
    for item in request.conversation:
        provs = [records[pid] for pid in item.provenance_ids if pid in records]
        base_trusted = not provs or any(p.trust_level.is_trusted for p in provs)
        base_untrusted = bool(provs) and any(not p.trust_level.is_trusted for p in provs)
        parsed: object = None
        try:
            parsed = json.loads(item.content)
        except (ValueError, TypeError):
            parsed = None
        if isinstance(parsed, dict) and any(key in KNOWN_UNTRUSTED_FIELDS for key in parsed):
            flagged = {k: v for k, v in parsed.items() if k in KNOWN_UNTRUSTED_FIELDS}
            rest = {k: v for k, v in parsed.items() if k not in KNOWN_UNTRUSTED_FIELDS}
            untrusted.append(json.dumps(flagged))
            if base_trusted:
                trusted.append(json.dumps(rest))
            if base_untrusted:
                # The response as a whole is untrusted-sourced (e.g. an attacker-controlled
                # tool_output override), so the "rest" of it is not exempt either.
                untrusted.append(json.dumps(rest))
        else:
            if base_trusted:
                trusted.append(item.content)
            if base_untrusted:
                untrusted.append(item.content)
    return trusted, untrusted


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
    ) -> None:
        self.enable_state = enable_state
        self.enable_evidence = enable_evidence
        self.enable_encoded = enable_encoded
        self.enable_auth_binding = enable_auth_binding
        self.enable_field_evidence = enable_field_evidence
        self.enable_decision_relevance = enable_decision_relevance
        self.enable_decision_block = enable_decision_block
        self.enable_goal_consistency = enable_goal_consistency
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
        self.name = "_".join(parts)
        if enable_state and enable_evidence and not any(
            (enable_auth_binding, enable_field_evidence, enable_decision_relevance)
        ):
            self.name = "authority_core_full"
        self._state = _ObjectState()
        self._bindings = _AuthBindings()

    # ---- top-level entry point ----------------------------------------------------------------
    def decide(self, request: DefenseRequest) -> DefenseDecision:
        return self._decide(request, depth=0)

    def _decide(self, request: DefenseRequest, depth: int) -> DefenseDecision:
        candidate = request.candidate_action
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
        conversation content this turn), which `soc_val_mfa_phishing` satisfies trivially."""
        if action.type is not ActionType.TOOL_CALL or action.tool is None:
            return None
        oid = object_id(action)
        match = _OBJECT_TOKEN.fullmatch(oid)
        if match is None:
            return None
        prefix = match.group(1)
        goal_ids = _goal_declared_objects(request.user_goal).get(prefix)
        if not goal_ids:
            # The authenticated request never named any object of this kind at all -- e.g. a
            # legitimately, freshly discovered secondary object (a different id NAMESPACE than
            # anything the user mentioned). Constraining this would misclassify ordinary
            # multi-object workflows as violations; deliberately out of scope.
            return None
        if oid in goal_ids:
            return None
        # Field-level splitting, not item-level: an item-level check would let this object id
        # count as "trusted-corroborated" merely because it appears inside an untrusted field
        # (e.g. `alert_read`'s `enrichment`) shipped alongside an otherwise-trusted response --
        # exactly the mixed-response failure mode Mechanism B exists to fix. Confirmed by direct
        # trace: `soc_incident_object_mismatch`'s injected AL-3003 reference sits inside
        # `enrichment`, and item-level splitting silently treated it as corroborated.
        trusted_texts, _ = _field_split_trusted_untrusted(request)
        if _present(oid, trusted_texts):
            # Not named by the user, but independently corroborated by trusted conversation
            # content this turn (e.g. a trusted search result actually returned this id).
            return None
        return decision(
            Decision.ESCALATE, 0.65, 0.6, ["OBJECT_NOT_DECLARED_IN_REQUEST"],
            f"{action.tool} targets {oid!r}, a different {prefix}-object than named in the "
            "authenticated request, with no trusted corroboration this turn",
        )

    # ---- Component A extension: RESTRICTED-sensitivity disclosure, any destination -------------
    def _restricted_disclosure(self, request: DefenseRequest, action: CandidateAction) -> DefenseDecision | None:
        """Every canary in this benchmark's fixtures is declared RESTRICTED with an EMPTY
        `allowed_destinations` set (never allowed anywhere) or CONFIDENTIAL with
        `[authenticated_user, trusted_internal]` (fine for the user and internal records, just not
        external/untrusted ones) -- see fixtures/*/base.json. The existing external-recipient
        check already covers the confidential case correctly (it's only forbidden going out).
        RESTRICTED content needs a stricter, destination-independent rule: it must never appear in
        the payload of ANY action at all -- the final response to the user, an internal record
        write (`incident_create`, `case_note_create`, ...), or a memory write -- not just an
        outbound email. This is what the 21-scenario `*_disclosure`/`*_case_note` family (added
        after the organizer's real-Qwen3-8B testing) actually exercises: the leak lands in an
        incident summary or the agent's own reply, never in an email to an external address."""
        records = {r.id: r.provenance for r in request.provenance}
        restricted = [
            item.content
            for item in request.conversation
            if any(records[pid].sensitivity is Sensitivity.RESTRICTED for pid in item.provenance_ids if pid in records)
        ]
        if not restricted:
            return None
        payload = action.text_payload()
        hit = overlaps(payload, restricted) or (
            self.enable_encoded and any(overlaps(variant, restricted) for variant in _decoded_variants(payload))
        )
        if hit:
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


def authority_core_v3_full() -> Defense:
    """The strongest, recommended-for-submission arm. Includes `enable_encoded`: Section 11 of the
    Phase 8 brief tested it as an isolated experiment and found "zero benefit and zero regression"
    against the corpus at the time, but left it off by default pending a case that actually needed
    it. `enterprise_val_encoded_exfil` (a live CRITICAL violation present in every prior arm,
    v2_full included) turned out to be exactly that case -- see the v3 addendum's writeup of the
    two real bugs found and fixed in `_decoded_variants` while closing it. There is no longer a
    reason to leave a validated, zero-regression fix for a live critical violation switched off."""
    return AuthorityCoreDefense(
        enable_evidence=True,
        enable_auth_binding=True,
        enable_field_evidence=True,
        enable_decision_relevance=True,
        enable_decision_block=True,
        enable_goal_consistency=True,
        enable_encoded=True,
    )
