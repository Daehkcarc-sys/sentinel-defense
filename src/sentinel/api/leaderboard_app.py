"""Minimal leaderboard API and server-rendered page. Writes require an admin bearer token."""

from __future__ import annotations

import hmac
from html import escape
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from sentinel.evaluator.metrics import Metrics
from sentinel.evaluator.scoring import ScoreBreakdown
from sentinel.storage.leaderboard import LeaderboardError, LeaderboardStore, Status


class CreateSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    benchmark_version: str = Field(min_length=1, max_length=64)
    split: str = Field(pattern=r"^(public|validation|private|mixed)$")


class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Status
    error: str | None = Field(default=None, max_length=500)


class ResultUpload(BaseModel):
    """Aggregate results only. Extra fields such as per-scenario outcomes are ignored."""

    model_config = ConfigDict(extra="ignore")
    metrics: Metrics
    score: ScoreBreakdown


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.3f}"
    return "-" if value is None else escape(str(value))


def render_page(store: LeaderboardStore) -> str:
    rows = []
    for rank, entry in enumerate(store.list(), start=1):
        m = entry.metrics or {}
        rows.append(
            "<tr>"
            + "".join(
                f"<td>{cell}</td>"
                for cell in [
                    rank,
                    escape(entry.name),
                    escape(entry.status.value),
                    escape(entry.split),
                    _fmt(entry.official_score),
                    _fmt(entry.eligible),
                    _fmt(m.get("btu")),
                    _fmt(m.get("asr")),
                    _fmt(m.get("cvr")),
                    _fmt(m.get("fbr")),
                    _fmt(m.get("tui")),
                    _fmt(m.get("dfi")),
                    escape(entry.benchmark_version),
                    escape(entry.updated_at),
                ]
            )
            + "</tr>"
        )
    header = "".join(
        f"<th>{h}</th>"
        for h in [
            "#",
            "submission",
            "status",
            "split",
            "official",
            "eligible",
            "BTU",
            "ASR",
            "CVR",
            "FBR",
            "TUI",
            "DFI",
            "benchmark",
            "updated",
        ]
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>SENTINEL leaderboard</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem}table{border-collapse:collapse}"
        "td,th{border:1px solid #ccc;padding:.3rem .6rem;text-align:right}th{background:#eef}</style>"
        "</head><body><h1>SENTINEL leaderboard</h1>"
        "<p>Aggregate metrics only. Hidden per-scenario results are never shown.</p>"
        f"<table><thead><tr>{header}</tr></thead><tbody>{''.join(rows)}</tbody></table></body></html>"
    )


def create_leaderboard_app(store: LeaderboardStore, admin_token: str | None) -> FastAPI:
    app = FastAPI(title="SENTINEL leaderboard", docs_url=None, redoc_url=None)

    def require_admin(authorization: str | None = Header(default=None)) -> None:
        expected = f"Bearer {admin_token}" if admin_token else None
        if expected is None or authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="admin token required")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def page() -> str:
        return render_page(store)

    @app.get("/api/submissions")
    def list_submissions() -> list[dict[str, Any]]:
        return [entry.public_dict() for entry in store.list()]

    @app.post("/api/submissions", dependencies=[Depends(require_admin)], status_code=201)
    def create(body: CreateSubmission) -> dict[str, int]:
        try:
            return {"id": store.create(body.name, body.benchmark_version, body.split)}
        except LeaderboardError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/submissions/{submission_id}/status", dependencies=[Depends(require_admin)])
    def update_status(submission_id: int, body: StatusUpdate) -> dict[str, str]:
        try:
            store.set_status(submission_id, body.status, body.error)
        except LeaderboardError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"status": body.status.value}

    @app.post("/api/submissions/{submission_id}/result", dependencies=[Depends(require_admin)])
    def upload_result(submission_id: int, body: ResultUpload) -> dict[str, float]:
        try:
            store.record_scores(submission_id, body.metrics, body.score)
        except LeaderboardError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"official_score": body.score.official_score}

    return app
