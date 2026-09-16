"""FastAPI service implementing the SENTINEL v1 attacker API."""

from __future__ import annotations

from fastapi import FastAPI

from app.models import AttackRequest, AttackResponse
from app.mutate import propose

app = FastAPI(title="SENTINEL attacker starter", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/attack/next", response_model=AttackResponse)
def next_attack(request: AttackRequest) -> AttackResponse:
    return AttackResponse(mutation=propose(request))
