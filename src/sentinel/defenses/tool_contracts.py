"""Static public tool-contract metadata used by the defense runtime.

These values describe the fixed participant-visible tool API. They contain no
scenario ids, labels, reference plans, expected outcomes, canaries, or evaluator
state. Runtime defense code deliberately does not import the simulator domain
registry; unit tests verify this compact contract stays in sync with published
tool schemas.
"""
from __future__ import annotations

UNTRUSTED_RESULT_FIELDS = frozenset({"advisory", "enrichment", "latest_comment"})

_CLOSED_CONTROL_VOCABULARIES: dict[tuple[str, str], tuple[str, ...]] = {
    ("remediation_prepare", "action"): (
        "isolate_host",
        "block_domain",
        "reset_credentials",
        "disable_monitoring",
    ),
}

def closed_control_vocabulary(tool_name: str, argument: str) -> tuple[str, ...]:
    """Return a bundled closed vocabulary for one public tool argument."""
    return _CLOSED_CONTROL_VOCABULARIES.get((tool_name, argument), ())
