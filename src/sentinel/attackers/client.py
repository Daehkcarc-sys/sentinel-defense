"""HTTP client for participant attacker services."""

from __future__ import annotations

import httpx
from pydantic import ValidationError

from sentinel.attackers.interface import Attacker, AttackMutation, AttackRequest, AttackResponse


class AttackerUnavailable(RuntimeError):
    pass


class HttpAttacker(Attacker):
    """Calls ``POST /v1/attack/next``. Failures end the attacker's turn; they never crash a run."""

    def __init__(
        self,
        base_url: str,
        timeout_s: float = 5.0,
        name: str = "http_attacker",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.name = name
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"), timeout=timeout_s, transport=transport, follow_redirects=False
        )

    def next_mutation(self, request: AttackRequest) -> AttackMutation | None:
        try:
            response = self._client.post("/v1/attack/next", json=request.model_dump(mode="json"))
        except httpx.TransportError as exc:
            raise AttackerUnavailable(type(exc).__name__) from exc
        if response.status_code != 200:
            raise AttackerUnavailable(f"HTTP {response.status_code}")
        try:
            return AttackResponse.model_validate_json(response.content).mutation
        except ValidationError as exc:
            raise AttackerUnavailable("malformed attacker response") from exc

    def close(self) -> None:
        self._client.close()
