# Local Mode Commands

Used by the local preflights, `build-command-resolver`, `image-builder`, `image-evidence-collector`, and `local-scanner`.

## Credential presence (twistlock-credential-preflight)
Accepted variables: `TWISTLOCK_TOKEN`, `TWISTLOCK_USERNAME`, `TWISTLOCK_PASSWORD`, `TWISTLOCK_ADDRESS` (optional).

Find candidate env files (names only):
```bash
for f in .env backend/.env deploy/.env scripts/.env; do [ -f "$f" ] && echo "$f"; done
```
Check variables in a subshell, never echoing values:
```bash
( set -a; . "<env-file>"; set +a
  for v in TWISTLOCK_TOKEN TWISTLOCK_USERNAME TWISTLOCK_PASSWORD TWISTLOCK_ADDRESS; do
    eval "[ -n \"\${$v:-}\" ]" && echo "$v=set" || echo "$v=unset"
  done )
```
Valid combinations: `TWISTLOCK_TOKEN`, or both `TWISTLOCK_USERNAME` and `TWISTLOCK_PASSWORD`.

Template shown to the user when credentials are missing (they fill real values on their own machine):
```dotenv
TWISTLOCK_USERNAME=<your Twistlock username>
TWISTLOCK_PASSWORD=<your Twistlock password>
TWISTLOCK_ADDRESS=https://twistlock.nci.nih.gov
```

## Credential validity (twistlock-auth-preflight)
Report only the HTTP status code. Never print the token.
```bash
( set -a; . "<env-file>"; set +a
  AUTH_JSON=$(python3 -c 'import json,os; print(json.dumps({"username":os.environ["TWISTLOCK_USERNAME"],"password":os.environ["TWISTLOCK_PASSWORD"]}))')
  curl -k -sS -o /dev/null -w '%{http_code}\n' -X POST "${TWISTLOCK_ADDRESS:-https://twistlock.nci.nih.gov}/api/v1/authenticate" \
    -H "Content-Type: application/json" -d "$AUTH_JSON" )
```
200 = accepted. Anything else, or a connection error, = `TWISTLOCK_AUTH_FAILED`. If only `TWISTLOCK_TOKEN` is set, skip this check and record `auth_method: token (not verified)`.

## twistcli location (twistcli-preflight)
Search order: repo-local `./twistcli`, user-provided path, known native path from `defaults.md`. Verify host compatibility with `uname -sm` and `file <binary>`. A Linux ELF on macOS is `TWISTCLI_INCOMPATIBLE_BINARY`.

## Docker reachability (docker-preflight)
```bash
docker info --format '{{.ServerVersion}}'
docker context show
```
Do not switch to Colima or another context unless the repo script or the user explicitly does so.

## Build (image-builder)
Prefer a repo script, for example `backend/build-local-image.sh <tag>`. Otherwise:
```bash
docker build -f <Dockerfile> -t <image> <context>
```
Use the same context the repo script uses.

## Evidence (image-evidence-collector)
```bash
docker run --rm --entrypoint sh <image> -c 'cat /etc/os-release; apk list --installed 2>/dev/null | grep -E "^(openssl|libssl3|libcrypto3)-" || true; dpkg-query -W openssl "libssl3*" 2>/dev/null || true'
```

## Scan (local-scanner)
Scan by image ID and pass the Docker socket explicitly:
```bash
mkdir -p .twistlock-runs/iter-<N>
( set -a; . "<env-file>"; set +a
  ADDR_VALUE="${TWISTLOCK_ADDRESS:-https://twistlock.nci.nih.gov}"
  IMG_ID=$(docker image inspect "<image>" --format "{{.Id}}")
  "<twistcli>" images scan \
    --address "$ADDR_VALUE" \
    --user "$TWISTLOCK_USERNAME" --password "$TWISTLOCK_PASSWORD" \
    --docker-address unix:///var/run/docker.sock \
    --details \
    --output-file .twistlock-runs/iter-<N>/twistcli-results.json \
    "$IMG_ID" \
    > .twistlock-runs/iter-<N>/twistcli.stdout \
    2> .twistlock-runs/iter-<N>/twistcli.stderr )
```
If only `TWISTLOCK_TOKEN` is set, replace `--user/--password` with `--user "$TWISTLOCK_USERNAME" --token "$TWISTLOCK_TOKEN"`. Tokens are never written to disk or echoed.

A `403 ... custom-compliance ... policyComplianceCustomRules` response means valid credentials but a missing account permission: `TWISTLOCK_PERMISSION_DENIED`.
