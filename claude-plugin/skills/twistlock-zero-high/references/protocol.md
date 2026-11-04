# Agent Output Protocol

Every agent writes exactly one primary output file in `_workspace/` (path given in its own definition). The file MUST start with this header, followed by a free-form body.

```
status: PASS | NEEDS_INPUT | HARD_STOP | REDO
agent: <agent-name>
blocker_code: <CODE from blocker-catalog.md, or none>
user_action: <exact instruction for the user, or none>
resume_from: <agent to re-run after the user acts, or none>
```

## Status vocabulary
- `PASS` — the agent's single responsibility is fulfilled. Body holds the results.
- `NEEDS_INPUT` — the user can unblock this (answer a question, log in, add a credential). The orchestrator relays `user_action`, waits for confirmation, then re-runs `resume_from` only.
- `HARD_STOP` — no safe automated or quick user path. The orchestrator ends the run and calls `completion-reporter`.
- `REDO` — used only by `fix-reviewer`. Body contains fix instructions the fixer can apply directly.

## Rules
1. The orchestrator reads only the 5-line header of an output file to route. It opens the body only when it needs to pass facts to the next agent.
2. Agents never ask the user anything directly and never call other agents.
3. Bodies must never contain secret values. Record only whether a variable is set (`set` / `unset`) and where it was found (file name).
4. Facts handed between agents use `KEY: value` lines so they can be parsed (for example `MODE: ecr`).
5. A blocker code must exist in `blocker-catalog.md`. Add new codes there first.

## Workspace layout
```
_workspace/
  00-repo-inspection.md          repo-inspector
  01-scan-target.md              scan-target-resolver
  02-build-command.md            build-command-resolver        (local only)
  10-preflight-prefect-auth.md   prefect-auth-preflight        (ecr only)
  11-preflight-prefect-deploy.md prefect-deployment-preflight  (ecr only)
  12-preflight-tl-credentials.md twistlock-credential-preflight(local only)
  13-preflight-tl-auth.md        twistlock-auth-preflight      (local only)
  14-preflight-twistcli.md       twistcli-preflight            (local only)
  15-preflight-docker.md         docker-preflight              (local only)
  iter-<N>/
    20-build.md                  image-builder                 (local only)
    21-tls-remediation.md        tls-ca-remediator             (only if needed)
    22-evidence.md               image-evidence-collector      (local only)
    30-scan.md                   ecr-scanner | local-scanner
    40-gate.md                   gate-evaluator
    50-fix-plan.md               fix-planner
    51-fix-applied.md            dockerfile-fixer
    52-fix-review.md             fix-reviewer
    53-hygiene.md                artifact-hygiene-checker
  99-final-report.md             completion-reporter
.twistlock-runs/iter-<N>/        raw scanner artifacts (git-ignored)
```
