"""Sandbox runner abstraction. Docker is one implementation; a dry-run runner supports tests."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Protocol

from sentinel.sandbox.docker import build_run_command, build_stop_command
from sentinel.sandbox.policy import SandboxPolicy


@dataclass(frozen=True)
class SandboxHandle:
    name: str
    container_id: str


class SandboxRunner(Protocol):
    def start(self, policy: SandboxPolicy, command: list[str] | None = None) -> SandboxHandle: ...

    def stop(self, handle: SandboxHandle) -> None: ...


class SandboxUnavailable(RuntimeError):
    pass


class DockerSandboxRunner:
    def __init__(self, docker_binary: str = "docker", command_timeout_s: int = 120) -> None:
        self.docker_binary = docker_binary
        self.command_timeout_s = command_timeout_s

    def _run(self, args: list[str]) -> str:
        if shutil.which(self.docker_binary) is None:
            raise SandboxUnavailable("docker CLI not found")
        args = [self.docker_binary, *args[1:]]
        completed = subprocess.run(args, capture_output=True, text=True, timeout=self.command_timeout_s, check=False)
        if completed.returncode != 0:
            raise SandboxUnavailable(completed.stderr.strip()[:500] or "docker command failed")
        return completed.stdout.strip()

    def start(self, policy: SandboxPolicy, command: list[str] | None = None) -> SandboxHandle:
        container_id = self._run(build_run_command(policy, command))
        return SandboxHandle(name=policy.name, container_id=container_id)

    def stop(self, handle: SandboxHandle) -> None:
        self._run(build_stop_command(handle.name))


@dataclass
class DryRunSandboxRunner:
    """Records commands instead of executing them."""

    commands: list[list[str]] = field(default_factory=list)

    def start(self, policy: SandboxPolicy, command: list[str] | None = None) -> SandboxHandle:
        self.commands.append(build_run_command(policy, command))
        return SandboxHandle(name=policy.name, container_id=f"dry-run-{policy.name}")

    def stop(self, handle: SandboxHandle) -> None:
        self.commands.append(build_stop_command(handle.name))
