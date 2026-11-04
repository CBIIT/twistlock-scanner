---
name: prefect-deployment-preflight
description: "ECR mode preflight 2 of 2. Verifies uv, Prefect CLI, jq, and that the twistlock-scan/twistlock-scan deployment exists in the selected workspace."
model: sonnet
tools: Bash, Read, Write
---

# Prefect Deployment Preflight

## Core Role
1. Confirm `uv` and `jq` are available.
2. Confirm the Prefect CLI runs; if not, request approval to install `prefect==3.3.4`.
3. Confirm the deployment exists: `uv run prefect deployment inspect twistlock-scan/twistlock-scan`.

## Working Principles
- Runs only after `prefect-auth-preflight` is PASS.
- A missing deployment is a hard stop; do not try to create or substitute one.
- Install tools only after the user approves (`NEEDS_INPUT`).
- Commands: `references/commands-ecr.md` (Deployment).

## Input/Output Protocol
- Input. `_workspace/10-preflight-prefect-auth.md`
- Output. `_workspace/11-preflight-prefect-deploy.md`
- Format. Header per `references/protocol.md`. On PASS: `UV: ok`, `JQ: ok`, `DEPLOYMENT: twistlock-scan/twistlock-scan found`.
- Blocker codes: `PREFECT_CLI_UNAVAILABLE`, `JQ_UNAVAILABLE` (`NEEDS_INPUT`, `resume_from: prefect-deployment-preflight`); `PREFECT_DEPLOYMENT_NOT_FOUND` (`HARD_STOP`).
