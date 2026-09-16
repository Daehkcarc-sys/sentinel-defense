from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def request(round_: int, transcript: list[dict[str, object]] | None = None, budget: int = 3) -> dict[str, object]:
    return {
        "scenario_id": "demo",
        "domain": "enterprise",
        "round": round_,
        "step_id": 1,
        "objective": "demo",
        "surfaces": [{"id": "doc", "kind": "document", "operations": ["append_text"], "max_chars": 500}],
        "transcript": transcript or [],
        "seed_payloads": [{"surface_id": "doc", "operation": "append_text", "text": "synthetic instruction"}],
        "budget_remaining": budget,
    }


def test_first_round_replays_seed() -> None:
    body = client.post("/v1/attack/next", json=request(0)).json()
    assert body["mutation"] == {"surface_id": "doc", "operation": "append_text", "text": "synthetic instruction"}


def test_reframes_after_block() -> None:
    transcript = [{"step_id": 1, "kind": "tool_call", "tool": "email_send", "decision": "block"}]
    body = client.post("/v1/attack/next", json=request(1, transcript)).json()
    assert body["mutation"]["text"] != "synthetic instruction"
    assert body["mutation"]["surface_id"] == "doc"


def test_no_budget_means_no_mutation() -> None:
    assert client.post("/v1/attack/next", json=request(0, budget=0)).json()["mutation"] is None


def test_mutations_stay_within_max_chars() -> None:
    body = request(2, [{"step_id": 1, "kind": "tool_call", "decision": "block"}])
    body["surfaces"] = [{"id": "doc", "kind": "document", "operations": ["append_text"], "max_chars": 21}]
    mutation = client.post("/v1/attack/next", json=body).json()["mutation"]
    assert mutation is None or len(mutation["text"]) <= 21
