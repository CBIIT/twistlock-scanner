---
name: twistlock-zero-high
description: "Orchestrates a multi-agent scan-and-remediate loop that drives a Docker image to zero Critical and High vulnerabilities in Twistlock/Prisma Cloud. Supports ECR registry images (via the Prefect twistlock-scan deployment) and local Docker builds (via twistcli). MUST be used for requests such as 'scan this image with Twistlock', 'Prisma Cloud scan', 'fix Critical/High vulnerabilities in the Dockerfile', 'get Twistlock to zero high', 'twistcli scan', or 'Twistlock gate'. This skill only routes work, asks the user questions, and controls the loop; it never runs scans or edits files itself. Not a replacement for general security reviews or other scanners such as Trivy, Snyk, or Docker Scout."
allowed-tools: Read Write Agent AskUserQuestion
---

# Twistlock Zero-High Orchestrator
Coordinates single-responsibility agents through resolve, preflight, build, scan, gate, fix, and report phases until Critical and High are zero or a hard stop is reached.

## Responsibilities (and non-responsibilities)
The orchestrator owns exactly three things:
1. Routing — which agent runs next, based on output headers.
2. User interaction — relaying `user_action` text and collecting answers or confirmations.
3. Loop control — iteration counter and limits.

It does NOT run shell commands, read env files, parse scanner output, edit the Dockerfile, or judge findings. Each of those belongs to a named agent. If a task seems to need one of them, call the agent.

Read these on demand (do not inline their content here):
- `references/protocol.md` — output header, status vocabulary, workspace layout.
- `references/orchestration-flow.md` — exact phase order and routing.
- `references/blocker-catalog.md` — every blocker code, who raises it, what the user must do.
- `references/loop-and-hard-stops.md` — counters, hard stops, gate definition.
- `references/safety-rules.md` — rules every agent must follow.

## Workflow
1. Setup.
   Create `_workspace/` if missing. Set `N = 0`. Pass the user's original request text to the agents that need it.
2. Phase 0 — Resolve.
   Call `repo-inspector`, then `scan-target-resolver`. If `MODE=local`, call `build-command-resolver`.
3. Phase 1 — Preflight.
   Call the preflight agents for the chosen mode strictly in order (see `orchestration-flow.md`). Stop at the first non-PASS and handle it with the Blocker Handling procedure.
4. Phase 2 — Build (local only).
   Call `image-builder`, then `image-evidence-collector`. On `PKG_TLS_FAILURE`, call `tls-ca-remediator` and rebuild.
5. Phase 3 — Scan.
   Call `ecr-scanner` or `local-scanner` according to `MODE`.
6. Phase 4 — Gate.
   Call `gate-evaluator`. `gate: PASS` goes to step 8. `gate: FAIL` goes to step 7.
7. Phase 5 — Fix, then loop.
   Call `fix-planner`, `dockerfile-fixer`, `fix-reviewer` (REDO loop), then `artifact-hygiene-checker`. Increment `N` and return to Phase 2 (local) or ask for a new ECR image ref (ecr).
8. Phase 6 — Report.
   Call `completion-reporter` and present `_workspace/99-final-report.md`. Always end here, including after a hard stop.

## Blocker Handling
After every agent call, read only the 5-line header of its output file.
- `PASS`: continue.
- `NEEDS_INPUT`: relay `user_action` to the user verbatim (use AskUserQuestion for choices such as ECR vs local; use plain text when the user must act outside the chat, for example logging in or editing an env file). Never ask the user to paste secrets into chat. After the user confirms, re-run the agent named in `resume_from` and continue from there. Earlier PASS results are not repeated.
- `HARD_STOP`: go to Phase 6.
- `REDO` (fix-reviewer only): re-call `dockerfile-fixer` with the review's fix instructions, at most 2 times per iteration.

If the same agent returns `NEEDS_INPUT` with the same `blocker_code` three times in a row, treat it as a hard stop and say why.

## Rules
- Begin every agent prompt with the line `REFERENCES_DIR: ${CLAUDE_SKILL_DIR}/references`. Agents resolve every relative `references/...` path against it, because an installed plugin has no fixed project-relative location.
- One agent at a time. Never run preflight agents in parallel.
- Never skip a preflight because it "probably passes".
- MODE=ecr: no local edits and no local builds before the baseline scan completes.
- Only `gate-evaluator` may declare the gate passed, and only from a fresh scan in the current iteration.
