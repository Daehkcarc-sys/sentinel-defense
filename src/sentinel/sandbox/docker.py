"""Build hardened `docker run` command lines. Pure functions: no Docker daemon required."""

from __future__ import annotations

from sentinel.sandbox.policy import Mount, SandboxPolicy, SandboxPolicyError, _is_forbidden_source


def _mount_args(mount: Mount) -> list[str]:
    if _is_forbidden_source(mount.source):  # defense in depth: re-check at command build time
        raise SandboxPolicyError(f"refusing to mount {mount.source!r}")
    suffix = ":ro" if mount.read_only else ""
    return ["--volume", f"{mount.source}:{mount.target}{suffix}"]


def build_run_command(policy: SandboxPolicy, command: list[str] | None = None) -> list[str]:
    args = [
        "docker",
        "run",
        "--rm",
        "--detach",
        "--name",
        policy.name,
        "--network",
        policy.network,
        "--memory",
        policy.memory,
        "--memory-swap",
        policy.memory,
        "--cpus",
        f"{policy.cpus:g}",
        "--pids-limit",
        str(policy.pids_limit),
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--user",
        policy.user,
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,nodev,size={policy.tmpfs_size}",  # noqa: S108 - container-internal tmpfs
    ]
    if policy.read_only_root:
        args.append("--read-only")
    if policy.gpus:
        args += ["--gpus", str(policy.gpus)]
    if policy.model_mount is not None:
        args += _mount_args(policy.model_mount)
    for mount in policy.extra_mounts:
        args += _mount_args(mount)
    for key in sorted(policy.env):
        args += ["--env", f"{key}={policy.env[key]}"]
    if policy.publish_port is not None:
        if policy.network == "none":
            raise SandboxPolicyError("publish_port requires an internal network; 'none' has no ports")
        args += ["--publish", f"127.0.0.1:{policy.publish_port}:{policy.container_port}"]
    args.append(policy.image)
    args += command or []
    if any("docker.sock" in part for part in args):
        raise SandboxPolicyError("docker.sock must never be exposed to participant containers")
    return args


def build_stop_command(name: str) -> list[str]:
    return ["docker", "rm", "--force", name]


def build_image_command(context: str, tag: str) -> list[str]:
    return ["docker", "build", "--tag", tag, context]


def build_inspect_command(image: str) -> list[str]:
    return ["docker", "image", "inspect", image]
