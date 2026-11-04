# Gate Parsing and Fix Priority

Used by `gate-evaluator`, `fix-planner`, and `dockerfile-fixer`.

## Gate extraction
MODE=local: find the summary line in scanner stdout:
```text
Vulnerabilities found for image <image>: total - N, critical - C, high - H, medium - M, low - L
```
MODE=ecr: read `.twistlock-runs/iter-<N>/prefect-twistlock.stdout`, Prefect run links, and any report path the deployment printed.

Pass = `critical - 0, high - 0`. Fail = any Critical or High.

JSON output: some reports use `null` instead of `[]` when there are no vulnerabilities. Handle defensively:
```bash
jq -r '(.results[0].vulnerabilities // [])[] | select((.severity|ascii_downcase) == "critical" or (.severity|ascii_downcase) == "high")' \
  .twistlock-runs/iter-<N>/twistcli-results.json
```

Group Critical/High findings by package, installed version, and fixed version. Fix package groups, not individual CVEs, when they share a root cause.

Also inspect High/Critical compliance results. They are not CVEs but can fail the gate. Common Docker CIS High: "Image should be created with a non-root user". Minimal fix:
```dockerfile
COPY --from=builder --chown=10001:10001 /app/output /app/output
USER 10001
```

## Fix priority (smallest safe fix first)
1. Compatible base image patch/minor tag that already carries the fixed OS package.
2. Distro package update from the same distro channel.
3. Narrow dependency patch/minor update.

Do not switch distro families unless base-image candidates show the current family cannot reach the fixed package safely; a switch can introduce more Critical/High findings.

## ECR mode note
Local repo changes only affect future images. After a fix, a new ECR image must be built and pushed (or the user switches to local validation) before the next scan.

## Build-context hygiene
Keep scanner artifacts and secrets out of the Docker context. `.dockerignore` should contain:
```dockerignore
.env
.git/
.twistlock-runs/
target/
```
If the Dockerfile uses `COPY . .`, consider ignoring `Dockerfile` too when Dockerfile-only changes should not invalidate expensive dependency layers. Only do this when the Dockerfile is not needed inside the build context.
