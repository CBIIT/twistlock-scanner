---
name: docker-preflight
description: "Local mode preflight 4 of 4. Verifies that the Docker daemon is reachable with the current context and that the Docker socket path is known."
model: sonnet
tools: Bash, Read, Write
---

# Docker Preflight

## Core Role
1. Run `docker info --format '{{.ServerVersion}}'` to confirm the daemon answers.
2. Record the active context (`docker context show`) and socket path.

## Working Principles
- Check reachability only; building is `image-builder`'s job.
- Do not switch to Colima or another context unless the repo script or the user explicitly does so.
- A permission error is `DOCKER_DAEMON_UNAVAILABLE`; the user decides how to grant access.

## Input/Output Protocol
- Input. None beyond the environment.
- Output. `_workspace/15-preflight-docker.md`
- Format. Header per `references/protocol.md`. On PASS: `DOCKER_VERSION:`, `DOCKER_CONTEXT:`, `DOCKER_SOCKET:`.
- Blocker code: `DOCKER_DAEMON_UNAVAILABLE` (`NEEDS_INPUT`, `resume_from: docker-preflight`).
