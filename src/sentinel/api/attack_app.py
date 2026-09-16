"""FastAPI app exposing a bounded attacker over the official HTTP contract."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable

from fastapi import FastAPI

from sentinel.api.schemas import API_VERSION, AttackRequest, AttackResponse
from sentinel.attackers.interface import Attacker

MAX_SESSIONS = 256


def create_attack_app(factory: Callable[[], Attacker]) -> FastAPI:
    app = FastAPI(title="SENTINEL attacker", version=API_VERSION, docs_url=None, redoc_url=None, openapi_url=None)
    sessions: OrderedDict[str, Attacker] = OrderedDict()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/attack/next", response_model=AttackResponse)
    def next_attack(request: AttackRequest) -> AttackResponse:
        key = request.scenario_id
        if request.round == 0 and key in sessions:
            sessions.pop(key).close()
        attacker = sessions.get(key)
        if attacker is None:
            attacker = factory()
            sessions[key] = attacker
            while len(sessions) > MAX_SESSIONS:
                _, oldest = sessions.popitem(last=False)
                oldest.close()
        return AttackResponse(mutation=attacker.next_mutation(request))

    return app
