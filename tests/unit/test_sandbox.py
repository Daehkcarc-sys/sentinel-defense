import pytest
from pydantic import ValidationError

from sentinel.sandbox.docker import build_run_command
from sentinel.sandbox.policy import Mount, SandboxPolicy
from sentinel.sandbox.runner import DryRunSandboxRunner


def policy(**overrides: object) -> SandboxPolicy:
    data: dict[str, object] = {"image": "team-a/defense:1.0", "name": "team-a-defense"}
    data.update(overrides)
    return SandboxPolicy.model_validate(data)


def test_hardened_defaults() -> None:
    command = build_run_command(policy())
    joined = " ".join(command)
    for flag in (
        "--network none",
        "--memory 2g",
        "--memory-swap 2g",
        "--cpus 1",
        "--pids-limit 256",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--user 10001:10001",
        "--read-only",
    ):
        assert flag in joined
    assert "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m" in joined
    assert command[-1] == "team-a/defense:1.0"
    assert "--privileged" not in joined and "docker.sock" not in joined


def test_read_only_model_mount_and_internal_network() -> None:
    command = build_run_command(
        policy(
            network="sentinel-internal",
            publish_port=18080,
            model_mount={"source": "/srv/models/qwen", "target": "/models", "read_only": True},
        ),
        ["--port", "8080"],
    )
    joined = " ".join(command)
    assert "--volume /srv/models/qwen:/models:ro" in joined
    assert "--publish 127.0.0.1:18080:8080" in joined
    assert command[-2:] == ["--port", "8080"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"user": "0"},
        {"user": "0:0"},
        {"network": "host"},
        {"network": "bridge"},
        {"network": "my-public-net"},
        {"memory": "unlimited"},
        {"model_mount": {"source": "/srv/models", "target": "/models", "read_only": False}},
        {"extra_mounts": [{"source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}]},
        {"extra_mounts": [{"source": "/", "target": "/host"}]},
        {"extra_mounts": [{"source": "/srv/data", "target": "/data", "read_only": False}]},
        {"extra_mounts": [{"source": "relative/path", "target": "/data"}]},
        {"image": "UPPER/Case;rm -rf"},
    ],
)
def test_unsafe_policies_are_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        policy(**overrides)


def test_publish_requires_network() -> None:
    with pytest.raises(ValueError, match="internal network"):
        build_run_command(policy(publish_port=18080))


def test_mount_rejects_docker_socket_directly() -> None:
    with pytest.raises(ValidationError):
        Mount(source="/run/docker.sock", target="/sock")


def test_dry_run_runner_records_commands() -> None:
    runner = DryRunSandboxRunner()
    handle = runner.start(policy())
    runner.stop(handle)
    assert runner.commands[0][:2] == ["docker", "run"]
    assert runner.commands[1] == ["docker", "rm", "--force", "team-a-defense"]
