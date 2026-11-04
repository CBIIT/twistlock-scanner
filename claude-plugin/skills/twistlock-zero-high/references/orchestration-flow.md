# Orchestration Flow

The orchestrator calls agents in this order. After each call it reads the header of the agent's output file (see protocol.md) and routes.

## Phase 0 — Resolve (always)
1. `repo-inspector` -> `00-repo-inspection.md`
2. `scan-target-resolver` -> `01-scan-target.md` (sets `MODE`, `IMAGE_REF`, `TWISTLOCK_ADDRESS`)
3. `build-command-resolver` -> `02-build-command.md` (only if `MODE=local`)

## Phase 1 — Preflight (sequential, stop at the first non-PASS)
Each check has one responsibility and depends on the previous one. Never skip ahead; never run two in parallel.

MODE=ecr:
1. `prefect-auth-preflight`
2. `prefect-deployment-preflight`

MODE=local:
1. `twistlock-credential-preflight`  (are credentials present?)
2. `twistlock-auth-preflight`        (does the console accept them?)
3. `twistcli-preflight`              (is a compatible binary available?)
4. `docker-preflight`                (is the daemon reachable?)

Routing on a non-PASS header:
- `NEEDS_INPUT`: relay `user_action` verbatim, wait for the user's confirmation, re-run the agent named in `resume_from`, then continue the chain from that point. Do not restart earlier passed checks.
- `HARD_STOP`: go to Phase 6.

## Phase 2 — Build (MODE=local only), iteration N
1. `image-builder` -> `iter-N/20-build.md`
   - `PKG_TLS_FAILURE`: call `tls-ca-remediator` -> `21-tls-remediation.md`, then re-run `image-builder` (max 2 remediation rounds per iteration).
2. `image-evidence-collector` -> `iter-N/22-evidence.md`

For MODE=ecr, skip Phase 2. No local build and no local edits happen before the baseline scan.

## Phase 3 — Scan, iteration N
- MODE=ecr: `ecr-scanner`
- MODE=local: `local-scanner`
Output: `iter-N/30-scan.md`

## Phase 4 — Gate
`gate-evaluator` -> `iter-N/40-gate.md` (body field `gate: PASS | FAIL`).
- `gate: PASS` -> Phase 6.
- `gate: FAIL` -> Phase 5.
- `HARD_STOP` (`FINDING_PERSISTS`) -> Phase 6.

## Phase 5 — Fix
1. `fix-planner` -> `50-fix-plan.md`
2. `dockerfile-fixer` -> `51-fix-applied.md`
3. `fix-reviewer` -> `52-fix-review.md`
   - `REDO`: re-call `dockerfile-fixer` with the review instructions (max 2 times, see loop-and-hard-stops.md).
   - `HARD_STOP`: Phase 6.
4. `artifact-hygiene-checker` -> `53-hygiene.md`
5. Next iteration:
   - MODE=local: N += 1, go to Phase 2.
   - MODE=ecr: raise `NEEDS_INPUT` with `NEW_ECR_IMAGE_REQUIRED`. After the user supplies a new ref (or chooses local), re-run `scan-target-resolver`, then N += 1 and go to Phase 3 (ecr) or Phase 1 (switching to local).

## Phase 6 — Report (always the last step)
`completion-reporter` -> `99-final-report.md`. Present its content to the user.
