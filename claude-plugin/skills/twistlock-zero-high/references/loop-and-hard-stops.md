# Loop Policy and Hard Stops

This skill is intentionally stricter than a general security review. Do not stop after finding vulnerabilities. Continue build-scan-fix until the gate passes or a hard stop is reached.

## Gate
- Pass: Critical = 0 and High = 0 in a FRESH Twistlock scan of the selected image.
- Fail: any Critical or High finding (CVE or compliance).
- Dockerfile inspection alone never counts as success.

## Counters (owned by the orchestrator)
| Counter | Limit | On exceed |
|---|---|---|
| fix-reviewer REDO rounds per iteration | 2 | Proceed with the last fix and add a "manual review recommended" warning to the report. Never loop forever |
| tls-ca-remediator rounds per iteration | 2 | HARD_STOP with the last build error |
| Same Critical/High finding across iterations | 2 attempts | `gate-evaluator` raises `FINDING_PERSISTS` |

## Hard stops (route to completion-reporter)
- Twistlock credentials cannot authenticate and the user cannot fix them.
- Prefect credentials or workspace missing for MODE=ecr and the user cannot provide them.
- Deployment `twistlock-scan/twistlock-scan` unavailable in the selected workspace.
- `twistcli` requires permissions the account does not have (`TWISTLOCK_PERMISSION_DENIED`).
- The user provides neither an ECR image ref nor permission to build/use a local image.
- MODE=ecr and no new ECR image is available after a source fix.
- The required fixed version is unavailable from the distro/vendor channel.
- The next fix needs an unsupported major runtime upgrade.
- The build succeeds only by weakening transport security.
- The same Critical/High finding remains after two reasonable attempts.

## Verification-image exception
If a full rebuild is temporarily blocked but a previously built application artifact exists, a clearly marked final-stage-only verification image may be built to validate runtime hardening. The report MUST state this limitation. It is never described as a clean full source rebuild.
