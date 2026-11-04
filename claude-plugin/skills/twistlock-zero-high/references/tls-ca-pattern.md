# VPN / TLS Interception: Build-Time Secret CA Pattern

Used by `tls-ca-remediator` and reviewed by `fix-reviewer`. Never use HTTP repositories or a permanent CA file in the final image.

## Dockerfile pattern
```dockerfile
# syntax=docker/dockerfile:1.6
FROM python:3.14-alpine

RUN --mount=type=secret,id=nci_ca,target=/usr/local/share/ca-certificates/nci-ca.crt \
    update-ca-certificates && \
    apk update && apk upgrade --no-cache && \
    apk add --no-cache 'openssl>=3.5.7'
RUN update-ca-certificates --fresh
```

## Build script pattern
```sh
#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
image_name="${1:-app:local}"
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
ca_cert="${NCI_CA_CERT:-$repo_dir/.twistlock-runs/nci-ca.pem}"

if [ -f "$ca_cert" ]; then
    docker build --secret "id=nci_ca,src=$ca_cert" -t "$image_name" -f "$script_dir/Dockerfile" "$script_dir"
else
    docker build -t "$image_name" -f "$script_dir/Dockerfile" "$script_dir"
fi
```

## Rules
- Create `.twistlock-runs/nci-ca.pem` only from a trusted local keychain or a user-provided CA. It is a local artifact, not application source.
- For Maven, DNF, APK, or other package managers with self-signed/intercepted certificate errors, diagnose the local trust/VPN context before changing dependencies.
- Never add insecure repository URLs or commit trust-store bypasses.
