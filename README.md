# Scripts

## Reusable GitHub Actions workflow

The reusable workflow at `.github/workflows/reusable-twistlock-scan.yml` scans
one or more private ECR images from the CBIIT self-hosted runner. It retrieves
the Twistlock `username` and `password` from AWS Secrets Manager, prints a scan
summary and vulnerability table, and fails when any Critical or High finding
is present.

Store the Twistlock credential in Secrets Manager as JSON:

```json
{
  "username": "TWISTLOCK_ACCESS_KEY_ID",
  "password": "TWISTLOCK_SECRET_KEY"
}
```

The assumed AWS role must trust the calling GitHub repository through OIDC and
must be able to pull the requested ECR images and call
`secretsmanager:GetSecretValue` for the configured secret. Add `kms:Decrypt`
when the secret uses a customer-managed KMS key.

Caller example—the image list is the only workflow input:

```yaml
jobs:
  twistlock:
    permissions:
      contents: read
      id-token: write
    uses: CBIIT/twistlock-scanner/.github/workflows/reusable-twistlock-scan.yml@v1
    with:
      images: '["123456789012.dkr.ecr.us-east-1.amazonaws.com/service:tag"]'
      environment: build
```

The reusable workflow owns the fixed `us-east-1` region and `prod/twistlock`
secret ID. Set `environment` to the caller environment that already contains
`AWS_BUILD_ROLE_TO_ASSUME`. No Twistlock credential is stored in GitHub.

If `AWS_BUILD_ROLE_TO_ASSUME` is a repository or organization secret instead of
an environment secret, pass it with `secrets: inherit`.

Use a release tag or full commit SHA instead of a test branch for team usage.
If this repository is private, allow the intended organization repositories in
**Settings → Actions → General → Access**.

## `run_twistlock.sh`

### Token + image (recommended)

```bash
./run_twistlock.sh -token 'eyJ...' \
  -i '1236456789.dkr.ecr.us-east-1.amazonaws.com/my-repo:main.100' \
  -i '1236456789.dkr.ecr.us-east-1.amazonaws.com/other-repo:main.101'
./run_twistlock.sh --token 'eyJ...' --image '1236456789.dkr.ecr.us-east-1.amazonaws.com/my-repo:main.100'
# short flags (order among flags is free)
./run_twistlock.sh -i '1236456789.dkr.ecr.us-east-1.amazonaws.com/my-repo:main.100' -t 'eyJ...'
```

For safer usage, prefer a short-lived Twistlock token. You can also set `TWISTLOCK_TOKEN` and pass only `--image '...'`, repeat `-i/--image`, or pass multiple positional image refs.

### User + password (not recommended)

Username/password authentication is kept only as a fallback for older workflows. Avoid it when possible because it increases credential exposure risk; use token authentication instead.

```bash
export TWISTLOCK_USERNAME='...'
export TWISTLOCK_PASSWORD='...'

./run_twistlock.sh '1236456789.dkr.ecr.us-east-1.amazonaws.com/my-repo:main.100'
```

- **`1236456789.dkr.ecr.us-east-1.amazonaws.com`** — ECR registry host (your AWS account + region).
- **`my-repo`** — repository name.
- **`main.100`** — image tag.

- **Platform:** Tested on macOS only; Linux and Windows are not validated.
