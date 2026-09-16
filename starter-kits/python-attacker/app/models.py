"""Self-contained copies of the SENTINEL v1 attacker API schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Operation = Literal["replace_text", "append_text", "set_tool_text", "write_memory"]


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SurfaceView(_Lenient):
    id: str
    kind: str
    operations: list[Operation]
    max_chars: int
    current_text: str = ""


class TranscriptItem(_Lenient):
    step_id: int
    kind: str
    tool: str | None = None
    decision: str | None = None
    succeeded: bool | None = None


class SeedPayload(_Lenient):
    surface_id: str
    operation: Operation
    text: str


class AttackRequest(_Lenient):
    scenario_id: str
    domain: str
    round: int
    step_id: int
    objective: str
    surfaces: list[SurfaceView]
    transcript: list[TranscriptItem] = Field(default_factory=list)
    seed_payloads: list[SeedPayload] = Field(default_factory=list)
    budget_remaining: int


class AttackMutation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    surface_id: str = Field(min_length=1, max_length=48)
    operation: Operation
    text: str = Field(min_length=1, max_length=8_000)


class AttackResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mutation: AttackMutation | None = None
    note: str | None = Field(default=None, max_length=300)
