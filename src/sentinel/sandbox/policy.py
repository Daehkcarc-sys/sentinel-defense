"""Sandbox policy for participant containers, validated before any command is built."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

FORBIDDEN_MOUNT_SOURCES = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run",
    "/run",
    "/proc",
    "/sys",
    "/dev",
    "/etc",
    "/root",
    "/home",
)
IMAGE_PATTERN = r"^[a-z0-9][a-z0-9._/:@-]{0,254}$"


class SandboxPolicyError(ValueError):
    pass


def _is_forbidden_source(source: str) -> bool:
    path = PurePosixPath(source)
    if str(path) == "/" or "docker.sock" in source:
        return True
    return any(path == PurePosixPath(bad) or path.is_relative_to(bad) for bad in FORBIDDEN_MOUNT_SOURCES)


class Mount(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source: str = Field(min_length=1)
    target: str = Field(pattern=r"^/[A-Za-z0-9._/-]+$")
    read_only: bool = True

    @model_validator(mode="after")
    def _safe(self) -> Self:
        if not self.source.startswith("/"):
            raise ValueError("mount sources must be absolute paths")
        if ".." in PurePosixPath(self.source).parts or ".." in PurePosixPath(self.target).parts:
            raise ValueError("mount paths must not contain '..'")
        if _is_forbidden_source(self.source):
            raise ValueError(f"mount source {self.source!r} is not allowed (host sockets and system paths)")
        return self


class SandboxPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    image: str = Field(pattern=IMAGE_PATTERN)
    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$")
    official_mode: bool = True
    network: Literal["none"] | str = "none"
    memory: str = Field(default="2g", pattern=r"^[1-9]\d{0,5}[mg]$")
    cpus: float = Field(default=1.0, gt=0, le=64)
    pids_limit: int = Field(default=256, ge=16, le=4096)
    read_only_root: bool = True
    tmpfs_size: str = Field(default="256m", pattern=r"^[1-9]\d{0,5}[mg]$")
    user: str = Field(default="10001:10001", pattern=r"^\d{1,6}(:\d{1,6})?$")
    timeout_s: int = Field(default=900, ge=1, le=86_400)
    gpus: int = Field(default=0, ge=0, le=8)
    model_mount: Mount | None = None
    extra_mounts: list[Mount] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    publish_port: int | None = Field(default=None, ge=1024, le=65535)
    container_port: int = Field(default=8080, ge=1, le=65535)

    @model_validator(mode="after")
    def _official_constraints(self) -> Self:
        uid = self.user.split(":")[0]
        if uid == "0":
            raise ValueError("containers must not run as root (uid 0)")
        if self.network in ("host", "bridge") or self.network.startswith("container:"):
            raise ValueError(f"network {self.network!r} is not allowed; use 'none' or an internal network")
        if self.official_mode and self.network != "none" and not self.network.startswith("sentinel-internal"):
            raise ValueError("official mode requires network 'none' or a 'sentinel-internal*' network")
        if self.model_mount is not None and not self.model_mount.read_only:
            raise ValueError("model mounts must be read-only")
        if self.official_mode and any(not m.read_only for m in self.extra_mounts):
            raise ValueError("official mode allows only read-only extra mounts")
        for key in self.env:
            if not key.replace("_", "").isalnum() or not key[0].isalpha():
                raise ValueError(f"invalid environment variable name {key!r}")
        return self
