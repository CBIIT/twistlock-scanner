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

Create a repository secret named `TWISTLOCK_SCANNER_AWS_ROLE_ARN` in each caller
repository. The value must be a dedicated, least-privilege Twistlock scan role
ARN. The ARN identifies the role; GitHub OIDC supplies short-lived AWS
credentials only while the job runs. GitHub does not allow a caller workflow to
pass an environment secret through `workflow_call`, so use a repository secret
unless an approved organization secret is available.

Caller example—the image list is the only scan-specific input. Set
`environment` only when the caller uses a non-default GitHub environment:

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
    secrets:
      TWISTLOCK_SCANNER_AWS_ROLE_ARN: ${{ secrets.TWISTLOCK_SCANNER_AWS_ROLE_ARN }}
```

The reusable workflow owns the fixed `us-east-1` region and `prod/twistlock`
secret ID. Set `environment` to the caller environment used by the AWS OIDC
trust policy. No Twistlock username or password is stored in GitHub.

Pass the role secret explicitly as shown above. Do not use `secrets: inherit`:
the reusable workflow needs only the Twistlock-specific role and does not use
the caller's general build role. A secret stored only in this central repository
is not passed to a remote reusable-workflow invocation; each caller must supply
the named secret.

The IAM role trust policy must restrict the GitHub OIDC `sub` claim to each
approved caller repository, branch, or environment. Avoid organization-wide
patterns such as `repo:CBIIT/*:*`. The role permission policy should contain
only the required ECR pull actions, `secretsmanager:GetSecretValue` for
`prod/twistlock`, and `kms:Decrypt` when the secret uses a customer-managed KMS
key. Do not share a general PowerUser role for scanning.

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
