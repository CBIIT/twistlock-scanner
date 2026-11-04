# ECR Mode Commands

Used by `prefect-auth-preflight`, `prefect-deployment-preflight`, and `ecr-scanner`. Values come from `defaults.md`.

## Auth (prefect-auth-preflight)
Check without printing values:
```bash
[ -n "${PREFECT_API_URL:-}" ] && echo "PREFECT_API_URL=set" || echo "PREFECT_API_URL=unset"
[ -n "${PREFECT_API_KEY:-}" ] && echo "PREFECT_API_KEY=set" || echo "PREFECT_API_KEY=unset"
uv run prefect cloud workspace ls    # exit 0 means an existing login works
```
Interactive login is performed by the USER, never by the agent:
```bash
export PREFECT_API_URL="<from defaults.md>"
uv run prefect cloud login
```
Non-interactive (only if `PREFECT_API_KEY` is already exported or provided by CI):
```bash
uv run prefect cloud login --key "$PREFECT_API_KEY" --workspace "<account>/<workspace>"
```
Set the workspace when the CLI needs the slug:
```bash
uv run prefect cloud workspace set --workspace "<account>/<workspace>"
```
Prefect credentials do not live in `backend/.env` by default; that is a repo-specific exception.

## Deployment (prefect-deployment-preflight)
```bash
command -v uv; command -v jq
uv run prefect deployment inspect twistlock-scan/twistlock-scan
```

## Scan (ecr-scanner)
```bash
mkdir -p .twistlock-runs/iter-<N>

IMAGE_REF="<ecr-image-ref>"
if [ -n "${TWISTLOCK_ADDRESS:-}" ]; then
  PARAMS=$(jq -n --arg image_ref "$IMAGE_REF" --arg twistlock_address "$TWISTLOCK_ADDRESS" \
    '{image_ref: $image_ref, twistlock_address: $twistlock_address}')
else
  PARAMS=$(jq -n --arg image_ref "$IMAGE_REF" '{image_ref: $image_ref}')
fi
printf '%s\n' "$PARAMS" > .twistlock-runs/iter-<N>/prefect-params.json

uv run prefect deployment run twistlock-scan/twistlock-scan \
  --params "$PARAMS" --watch --watch-interval 30 \
  > .twistlock-runs/iter-<N>/prefect-twistlock.stdout \
  2> .twistlock-runs/iter-<N>/prefect-twistlock.stderr
```
The watched Prefect run is the scan of record. Failure mapping:
- auth/workspace error -> `PREFECT_RUN_FAILED`
- deployment not found -> `PREFECT_DEPLOYMENT_NOT_FOUND`
- image access error -> `ECR_IMAGE_ACCESS_DENIED`
- Twistlock permission error -> `TWISTLOCK_PERMISSION_DENIED`
