from pathlib import Path

from fastapi.testclient import TestClient

from sentinel.api.leaderboard_app import create_leaderboard_app, render_page
from sentinel.config import ScoringConfig
from sentinel.evaluator.scoring import compute_score
from sentinel.storage.leaderboard import LeaderboardStore, Status
from tests.unit.test_scoring import metrics

TOKEN = "test-admin-token"


def test_store_orders_by_eligibility_and_score(tmp_path: Path) -> None:
    store = LeaderboardStore(tmp_path / "lb.sqlite3")
    low = store.create("team-low", "v1", "public")
    high = store.create("team-high", "v1", "public")
    gated = store.create("team-gated", "v1", "public")
    queued = store.create("team-queued", "v1", "public")
    store.record_scores(low, metrics(asr=0.5), compute_score(metrics(asr=0.5), ScoringConfig()))
    store.record_scores(high, metrics(), compute_score(metrics(), ScoringConfig()))
    store.record_scores(gated, metrics(btu=0.1), compute_score(metrics(btu=0.1), ScoringConfig()))
    store.set_status(queued, Status.RUNNING)
    assert [e.name for e in store.list()] == ["team-high", "team-low", "team-gated", "team-queued"]
    assert store.list()[-1].status is Status.RUNNING


def test_api_requires_admin_for_writes_and_hides_details(tmp_path: Path) -> None:
    store = LeaderboardStore(tmp_path / "lb.sqlite3")
    client = TestClient(create_leaderboard_app(store, TOKEN))
    body = {"name": "team-a", "benchmark_version": "v1", "split": "private"}
    assert client.post("/api/submissions", json=body).status_code == 401
    assert client.post("/api/submissions", json=body, headers={"Authorization": "Bearer wrong"}).status_code == 401
    created = client.post("/api/submissions", json=body, headers={"Authorization": f"Bearer {TOKEN}"})
    assert created.status_code == 201
    sub_id = created.json()["id"]
    upload = {
        "metrics": metrics().model_dump(),
        "score": compute_score(metrics(), ScoringConfig()).model_dump(),
        "outcomes": [{"scenario_id": "hidden_case_42"}],
    }
    assert (
        client.post(
            f"/api/submissions/{sub_id}/result", json=upload, headers={"Authorization": f"Bearer {TOKEN}"}
        ).status_code
        == 200
    )
    listing = client.get("/api/submissions").json()
    assert listing[0]["status"] == "succeeded"
    assert "hidden_case_42" not in client.get("/api/submissions").text
    assert "hidden_case_42" not in client.get("/").text


def test_writes_disabled_without_token(tmp_path: Path) -> None:
    client = TestClient(create_leaderboard_app(LeaderboardStore(tmp_path / "lb.sqlite3"), None))
    body = {"name": "team-a", "benchmark_version": "v1", "split": "public"}
    assert client.post("/api/submissions", json=body, headers={"Authorization": "Bearer None"}).status_code == 401


def test_page_escapes_names(tmp_path: Path) -> None:
    store = LeaderboardStore(tmp_path / "lb.sqlite3")
    store.create("team-b", "v1<script>", "public")
    html = render_page(store)
    assert "<script>" not in html and "v1&lt;script&gt;" in html
