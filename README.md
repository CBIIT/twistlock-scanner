# Scripts

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