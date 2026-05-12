#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${TWISTLOCK_USERNAME:-}" ]]; then
  echo "TWISTLOCK_USERNAME is required" >&2
  exit 1
fi

if [[ -z "${TWISTLOCK_PASSWORD:-}" ]]; then
  echo "TWISTLOCK_PASSWORD is required" >&2
  exit 1
fi

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <image>" >&2
  exit 1
fi

twistlock_scan "$1"
