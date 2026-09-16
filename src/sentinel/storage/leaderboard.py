"""SQLite-backed leaderboard. Stores aggregate metrics only, never per-scenario outcomes."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from sentinel.evaluator.metrics import Metrics
from sentinel.evaluator.scoring import ScoreBreakdown

NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    benchmark_version TEXT NOT NULL,
    split TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    official_score REAL,
    eligible INTEGER,
    metrics_json TEXT,
    score_json TEXT,
    error TEXT
);
"""


class Status(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class LeaderboardError(ValueError):
    pass


@dataclass(frozen=True)
class Entry:
    id: int
    name: str
    benchmark_version: str
    split: str
    status: Status
    created_at: str
    updated_at: str
    official_score: float | None
    eligible: bool | None
    metrics: dict[str, Any] | None
    score: dict[str, Any] | None
    error: str | None

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "benchmark_version": self.benchmark_version,
            "split": self.split,
            "status": self.status.value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "official_score": self.official_score,
            "eligible": self.eligible,
            "metrics": self.metrics,
            "score": self.score,
            "error": self.error,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class LeaderboardStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def create(self, name: str, benchmark_version: str, split: str) -> int:
        if not NAME_PATTERN.fullmatch(name):
            raise LeaderboardError("submission names use letters, digits, space, '_', '.', '-' (max 64)")
        now = _now()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO submissions (name, benchmark_version, split, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, benchmark_version, split, Status.QUEUED.value, now, now),
            )
            return int(cursor.lastrowid or 0)

    def set_status(self, submission_id: int, status: Status, error: str | None = None) -> None:
        with self._connect() as conn:
            updated = conn.execute(
                "UPDATE submissions SET status = ?, error = ?, updated_at = ? WHERE id = ?",
                (status.value, error, _now(), submission_id),
            ).rowcount
        if not updated:
            raise LeaderboardError(f"unknown submission {submission_id}")

    def record_scores(self, submission_id: int, metrics: Metrics, score: ScoreBreakdown) -> None:
        with self._connect() as conn:
            updated = conn.execute(
                "UPDATE submissions SET status = ?, official_score = ?, eligible = ?, metrics_json = ?, "
                "score_json = ?, error = NULL, updated_at = ? WHERE id = ?",
                (
                    Status.SUCCEEDED.value,
                    score.official_score,
                    int(score.eligible),
                    metrics.model_dump_json(),
                    score.model_dump_json(),
                    _now(),
                    submission_id,
                ),
            ).rowcount
        if not updated:
            raise LeaderboardError(f"unknown submission {submission_id}")

    def set_result(self, submission_id: int, report: Any) -> None:
        """Record an EvaluationReport. Only aggregate metrics and the score are persisted."""
        self.record_scores(submission_id, report.metrics, report.score)

    def list(self) -> list[Entry]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM submissions").fetchall()
        entries = [
            Entry(
                id=row["id"],
                name=row["name"],
                benchmark_version=row["benchmark_version"],
                split=row["split"],
                status=Status(row["status"]),
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                official_score=row["official_score"],
                eligible=None if row["eligible"] is None else bool(row["eligible"]),
                metrics=json.loads(row["metrics_json"]) if row["metrics_json"] else None,
                score=json.loads(row["score_json"]) if row["score_json"] else None,
                error=row["error"],
            )
            for row in rows
        ]
        return sorted(
            entries, key=lambda e: (e.status is not Status.SUCCEEDED, not e.eligible, -(e.official_score or 0.0), e.id)
        )
