# Organizer infrastructure

- `docker/Dockerfile`: organizer image (CLI, baseline services, leaderboard), non-root.
- `systemd/`: example units for a single evaluation host.

See docs/organizer-guide.md for how these fit together. Kubernetes is intentionally not used for the MVP;
the sandbox runner abstraction (`sentinel.sandbox.runner.SandboxRunner`) is the seam for adding it later.
