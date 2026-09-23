from sentinel.defenses.baselines import BASELINES, get_baseline
from sentinel.defenses.baselines.authority_core import authority_core_v3_full
from sentinel.defenses.hybrid import HybridPhase1Defense
from tests.conftest import defense_request, tool_call


def _representative_requests():
    return [
        defense_request(tool_call("email_read", email_id="EM-2001")),
        defense_request(tool_call("email_send", to="a@atlas.example", subject="s", body="b")),
        defense_request(
            tool_call("payment_execute", payment_id="PAY-0001"),
            policy_context={"allowed_tools": ["email_read"]},
        ),
    ]


def test_hybrid_phase1_is_registered() -> None:
    assert "hybrid_phase_1" in BASELINES
    defense = get_baseline("hybrid_phase_1")
    assert isinstance(defense, HybridPhase1Defense)
    assert defense.name == "hybrid_phase_1"
    assert defense.delegate_name == "authority_core_v3_full"


def test_hybrid_phase1_returns_exact_authority_core_v3_decisions() -> None:
    hybrid = HybridPhase1Defense()
    baseline = authority_core_v3_full()

    for request in _representative_requests():
        hybrid_result = hybrid.decide(request)
        baseline_result = baseline.decide(request)

        assert hybrid_result is not None
        assert hybrid_result.model_dump(mode="json") == baseline_result.model_dump(mode="json")


def test_hybrid_phase1_records_trace_without_changing_decision() -> None:
    hybrid = HybridPhase1Defense()
    request = defense_request(tool_call("email_read", email_id="EM-2001"), run_id="phase1-run", step_id=7)

    result = hybrid.decide(request)
    traces = hybrid.state.traces("phase1-run")

    assert len(traces) == 1
    trace = traces[0]
    assert trace.run_id == "phase1-run"
    assert trace.step_id == 7
    assert trace.action_digest == request.candidate_action.digest()
    assert trace.decision is result.decision
    assert trace.risk_score == result.risk_score
    assert trace.confidence == result.confidence
    assert trace.reason_codes == tuple(result.reason_codes)


def test_hybrid_phase1_keeps_runs_separate_in_trace_state() -> None:
    hybrid = HybridPhase1Defense()
    action = tool_call("email_read", email_id="EM-2001")

    hybrid.decide(defense_request(action, run_id="run-a", step_id=1))
    hybrid.decide(defense_request(action, run_id="run-b", step_id=1))

    assert len(hybrid.state.traces("run-a")) == 1
    assert len(hybrid.state.traces("run-b")) == 1
    assert hybrid.state.traces("missing") == ()
