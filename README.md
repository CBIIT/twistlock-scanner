# twistlock-scanner

Scan the Twistlock remotely.

## Scripts

### `twistlock_smoke.sh`

Set credentials, then run with one image argument (same shape as `twistlock_scan`).

```bash
export TWISTLOCK_USERNAME='Twistlock username'
export TWISTLOCK_PASSWORD='Twistlock password'

./scripts/twistlock_smoke.sh '12345677890.dkr.ecr.us-east-1.amazonaws.com/my-repo:main.100'
```

- `12345677890.dkr.ecr.us-east-1.amazonaws.com` — ECR registry host.
- `my-repo` — repository name.
- `main.100` — image tag.
