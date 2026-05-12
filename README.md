# Scripts

## `twistlock_smoke.sh`

- Set credentials, then run with one image argument (same shape as `twistlock_scan`).

```bash
export TWISTLOCK_USERNAME='...'
export TWISTLOCK_PASSWORD='...'

./scripts/twistlock_smoke.sh '1236456789.dkr.ecr.us-east-1.amazonaws.com/my-repo:main.100'
```

- **`1236456789.dkr.ecr.us-east-1.amazonaws.com`** — ECR registry host (your AWS account + region).
- **`my-repo`** — repository name.
- **`main.100`** — image tag.
