#!/usr/bin/env bash
# Authenticate, POST on-demand registry scan, optional NCI scan/select, poll until compact registry has data.
#
#   Token authentication is recommended:
#   ./run_twistlock.sh -token 'JWT' -i 'registry/repo:tag' -i 'registry/other:tag'
#   ./run_twistlock.sh --token 'JWT' --image 'registry/repo:tag'
#   ./run_twistlock.sh -t 'JWT' 'registry/repo:tag' 'registry/other:tag'
#   export TWISTLOCK_TOKEN='...'   # optional; CLI token overrides env
#
#   Username/password is kept only as a fallback and is not recommended:
#   export TWISTLOCK_USERNAME='...' TWISTLOCK_PASSWORD='...'
#   ./run_twistlock.sh [--image|-i 'registry/repo:tag']...   # or positional image refs
#
# Env:
#   TWISTLOCK_IMAGE_REF — image if not set via --image/-i or positional refs
#   TWISTLOCK_TOKEN — Bearer (skips /authenticate); CLI --token overrides
#   TWISTLOCK_USERNAME, TWISTLOCK_PASSWORD — fallback only; token auth is recommended
#   TWISTLOCK_ADDRESS, TWISTLOCK_API_VERSION
#   TWISTLOCK_POLL_MAX (default 60), TWISTLOCK_POLL_INTERVAL (default 15) — seconds between polls
#   TWISTLOCK_VERBOSE=1 — print detailed API request/response progress
#   TWISTLOCK_SKIP_SCAN_SELECT=1 — skip POST /api/v1/registry/scan/select (otherwise sent with NCI defaults)
#   TWISTLOCK_SCAN_SELECT_COLLECTIONS, TWISTLOCK_SCAN_SELECT_PROJECT — override scan/select query
# After poll: GET compact=false, then print CVE table (embedded python, same parsing as twistlock_scan).
# IMAGE_REF: <registry-host>/<repo/path>:<tag>  (same rule as twistlock_scan._split_image_ref)

set -euo pipefail

_looks_like_jwt() {
  local s="${1:-}" j1 j2 j3 rest
  [[ "$s" == ey[Jj]* ]] || return 1
  IFS='.' read -r j1 j2 j3 rest <<< "$s"
  [[ -n "$j1" && -n "$j2" && -n "$j3" && -z "${rest:-}" ]] || return 1
  [[ "$j2" != */* ]] || return 1
  return 0
}

CLI_TOKEN=""
CLI_IMAGES=()
POS_IMAGES=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --token=* | -token=*)
      CLI_TOKEN="${1#--token=}"
      CLI_TOKEN="${CLI_TOKEN#-token=}"
      shift
      ;;
    --token | -token | -t)
      if [[ $# -lt 2 ]]; then
        echo "error: $1 requires a value" >&2
        exit 1
      fi
      CLI_TOKEN="$2"
      shift 2
      ;;
    --image=*)
      CLI_IMAGES+=("${1#--image=}")
      shift
      ;;
    --image | -i)
      if [[ $# -lt 2 ]]; then
        echo "error: $1 requires a value" >&2
        exit 1
      fi
      CLI_IMAGES+=("$2")
      shift 2
      ;;
    --help | -h)
      echo "usage: $0 [options] [IMAGE_REF ...]" >&2
      echo "  -token|--token|-t TOKEN  Bearer JWT (recommended; skips username/password login)" >&2
      echo "  --image|-i REF           container image registry/repo:tag; repeat for multiple images" >&2
      echo "  IMAGE_REF ...            optional positional images" >&2
      echo "  env: TWISTLOCK_TOKEN (recommended), TWISTLOCK_IMAGE_REF, TWISTLOCK_VERBOSE=1" >&2
      echo "       TWISTLOCK_USERNAME+PASSWORD are fallback only and not recommended" >&2
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        POS_IMAGES+=("$1")
        shift
      done
      break
      ;;
    -*)
      echo "error: unknown option: $1 (try --help)" >&2
      exit 1
      ;;
    *)
      POS_IMAGES+=("$1")
      shift
      ;;
  esac
done

IMAGE_REFS=()
if [[ ${#CLI_IMAGES[@]} -gt 0 ]]; then
  IMAGE_REFS+=("${CLI_IMAGES[@]}")
fi
if [[ ${#POS_IMAGES[@]} -gt 0 ]]; then
  IMAGE_REFS+=("${POS_IMAGES[@]}")
fi
if [[ ${#IMAGE_REFS[@]} -eq 0 && -n "${TWISTLOCK_IMAGE_REF:-}" ]]; then
  IMAGE_REFS=("$TWISTLOCK_IMAGE_REF")
fi

ADDRESS="${TWISTLOCK_ADDRESS:-https://twistlock.nci.nih.gov}"
ADDRESS="${ADDRESS%/}"
API_VERSION="${TWISTLOCK_API_VERSION:-v34.02}"
POLL_MAX="${TWISTLOCK_POLL_MAX:-60}"
POLL_INTERVAL="${TWISTLOCK_POLL_INTERVAL:-15}"
VERBOSE="${TWISTLOCK_VERBOSE:-0}"

TL_USER="${TWISTLOCK_USERNAME:-}"
TL_PASS="${TWISTLOCK_PASSWORD:-}"
TL_TOKEN="${CLI_TOKEN:-${TWISTLOCK_TOKEN:-}}"
TOKEN_FROM_CLI=0
[[ -n "${CLI_TOKEN:-}" ]] && TOKEN_FROM_CLI=1

USE_PREAUTH_TOKEN=0
if [[ -n "$TL_TOKEN" ]]; then
  USE_PREAUTH_TOKEN=1
elif [[ -z "$TL_USER" || -z "$TL_PASS" ]]; then
  echo "error: set -token/--token/-t or TWISTLOCK_TOKEN, or TWISTLOCK_USERNAME and TWISTLOCK_PASSWORD" >&2
  exit 1
fi

if [[ ${#IMAGE_REFS[@]} -eq 0 ]]; then
  echo "error: at least one image ref is required (registry/repo:tag)." >&2
  echo "  $0 -token 'JWT' -i 'registry/repo:tag' -i 'registry/other:tag'" >&2
  echo "  $0 --image 'registry/repo:tag'   # with TWISTLOCK_TOKEN or username/password in env" >&2
  echo "  $0 'registry/repo:tag' 'registry/other:tag'  # positional images" >&2
  exit 1
fi

validate_image_ref() {
  local image_ref="$1"
  if [[ -z "${image_ref// }" ]]; then
    echo "error: empty image ref is not allowed." >&2
    exit 1
  fi
  if [[ "$image_ref" == -* ]]; then
    echo "error: image ref looks like a flag (${image_ref}). Use --image '...'." >&2
    exit 1
  fi
  if [[ -n "${image_ref// }" ]] && _looks_like_jwt "$image_ref"; then
    echo "error: image value looks like a JWT. Use separate parameters, e.g.:" >&2
    echo "  $0 -token 'JWT' -i 'registry.example.com/repo:tag'" >&2
    exit 1
  fi
  if [[ "$image_ref" != */*:* ]]; then
    echo "error: image must be registry/repository:tag (with / and :)." >&2
    echo "  got: ${image_ref}" >&2
    exit 1
  fi
}

for IMAGE_REF in "${IMAGE_REFS[@]}"; do
  validate_image_ref "$IMAGE_REF"
done

if [[ "$USE_PREAUTH_TOKEN" == 1 ]]; then
  AUTH_BODY=""
else
  AUTH_BODY=$(TL_USER="$TL_USER" TL_PASS="$TL_PASS" python3 -c \
    'import json, os; print(json.dumps({"username": os.environ["TL_USER"], "password": os.environ["TL_PASS"]}))')
fi

json_token() {
  python3 -c 'import json,sys; d=json.load(sys.stdin); t=d.get("token"); print(t or "", end="")'
}

compact_ready() {
  # stdin: raw GET body; exit 0 if Twistlock returned a non-empty compact payload
  python3 -c '
import json, sys
t = sys.stdin.read().strip()
if not t or t == "null":
    raise SystemExit(1)
j = json.loads(t)
if j is None:
    raise SystemExit(1)
if isinstance(j, list) and len(j) == 0:
    raise SystemExit(1)
if isinstance(j, dict) and len(j) == 0:
    raise SystemExit(1)
raise SystemExit(0)
'
}

if [[ "$USE_PREAUTH_TOKEN" == 1 ]]; then
  TOKEN="$TL_TOKEN"
  if [[ "$TOKEN_FROM_CLI" == 1 ]]; then
    echo "==> auth: using Bearer from CLI token (skipping POST /api/v1/authenticate)"
  else
    echo "==> auth: using TWISTLOCK_TOKEN (skipping POST /api/v1/authenticate)"
  fi
  echo "    ok (token length ${#TOKEN})"
else
  echo "==> POST ${ADDRESS}/api/v1/authenticate"
  AUTH_JSON=$(curl -k -sS -X POST "${ADDRESS}/api/v1/authenticate" \
    -H "Content-Type: application/json" \
    -d "$AUTH_BODY") || true

  TOKEN=$(printf '%s' "$AUTH_JSON" | json_token)
  if [[ -z "$TOKEN" ]]; then
    echo "authenticate failed (no token). body:" >&2
    echo "$AUTH_JSON" >&2
    exit 1
  fi
  echo "    ok (token length ${#TOKEN})"
fi

REPORT_TMP_ROOT=$(mktemp -d)
trap 'rm -rf "${REPORT_TMP_ROOT}"' EXIT
REPORT_FILES=()
REPORT_TITLES=()
REPORT_STATUSES=()

scan_image() {
  local IMAGE_REF="$1"
  local REGISTRY REST REPO TAG SELECT_STATUS POLLS_USED REPORT_TMP REPORT_FILE

  REGISTRY="${IMAGE_REF%%/*}"
  REST="${IMAGE_REF#*/}"
  REPO="${REST%:*}"
  TAG="${REST##*:}"

if [[ "$VERBOSE" == "1" ]]; then
  echo "    GET registry compact (before scan)"
fi
REG_RAW=$(curl -k -sS -G "${ADDRESS}/api/${API_VERSION}/registry" \
  --data-urlencode "name=${IMAGE_REF}" \
  --data-urlencode "compact=true" \
  -H "Authorization: Bearer ${TOKEN}" \
  -w "\n%{http_code}")
REG_HTTP=$(printf '%s' "$REG_RAW" | tail -n1)
REG=$(printf '%s' "$REG_RAW" | sed '$d')
if [[ "$VERBOSE" == "1" ]]; then
  echo "      HTTP ${REG_HTTP} preview: $(printf '%s' "$REG" | head -c 80)"
fi

export REGISTRY REPO TAG
SCAN_BODY=$(python3 -c 'import json, os; print(json.dumps({"onDemandScan": True, "tag": {"registry": os.environ["REGISTRY"], "repo": os.environ["REPO"], "tag": os.environ["TAG"], "digest": ""}}))')

if [[ "$VERBOSE" == "1" ]]; then
  echo "    POST ${ADDRESS}/api/${API_VERSION}/registry/scan (on-demand)"
fi
SCAN_RAW=$(curl -k -sS --max-time 240 -X POST "${ADDRESS}/api/${API_VERSION}/registry/scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d "$SCAN_BODY" \
  -w "\n%{http_code}")
SCAN_HTTP=$(printf '%s' "$SCAN_RAW" | tail -n1)
SCAN_BODY_OUT=$(printf '%s' "$SCAN_RAW" | sed '$d')
echo "    scan: HTTP ${SCAN_HTTP}"
if [[ "$VERBOSE" == "1" && -n "$SCAN_BODY_OUT" ]]; then
  echo "    body: ${SCAN_BODY_OUT}"
fi
if [[ "$SCAN_HTTP" != 2* ]]; then
  if [[ -n "$SCAN_BODY_OUT" ]]; then
    echo "    scan error: ${SCAN_BODY_OUT}" >&2
  fi
  echo "error: registry/scan failed" >&2
  return 1
fi

SELECT_STATUS="skipped"
if [[ "${TWISTLOCK_SKIP_SCAN_SELECT:-0}" != "1" ]]; then
  COLLECTIONS="${TWISTLOCK_SCAN_SELECT_COLLECTIONS:-CRDC CCDI All Collection}"
  PROJECT="${TWISTLOCK_SCAN_SELECT_PROJECT:-Central Console}"
  SELECT_URL=$(
    ADDRESS="$ADDRESS" COLLECTIONS="$COLLECTIONS" PROJECT="$PROJECT" python3 -c '
import os, urllib.parse
q = urllib.parse.urlencode(
    {"collections": os.environ["COLLECTIONS"], "project": os.environ["PROJECT"]},
    quote_via=urllib.parse.quote_plus,
)
print(os.environ["ADDRESS"].rstrip("/") + "/api/v1/registry/scan/select?" + q)
'
  )
  SELECT_BODY=$(python3 -c 'import json, os; print(json.dumps([{"tag": {"registry": os.environ["REGISTRY"], "repo": "", "tag": ""}}]))')
  if [[ "$VERBOSE" == "1" ]]; then
    echo "    POST registry/scan/select (notify defenders; may run many minutes)"
  fi
  SEL_RAW=$(curl -k -sS --max-time 1800 -X POST "$SELECT_URL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "$SELECT_BODY" \
    -w "\n%{http_code}")
  SEL_HTTP=$(printf '%s' "$SEL_RAW" | tail -n1)
  SEL_OUT=$(printf '%s' "$SEL_RAW" | sed '$d')
  SELECT_STATUS="HTTP ${SEL_HTTP}"
  echo "    select: ${SELECT_STATUS}"
  if [[ "$VERBOSE" == "1" && -n "$SEL_OUT" ]]; then
    echo "    body (first 500 chars): $(printf '%.500s' "$SEL_OUT")"
  fi
else
  echo "    select: skipped"
fi

if [[ "$VERBOSE" == "1" ]]; then
  echo "    Poll GET registry compact (max ${POLL_MAX} tries, ${POLL_INTERVAL}s apart)"
fi
found=0
POLLS_USED=0
for ((i = 1; i <= POLL_MAX; i++)); do
  REG_RAW=$(curl -k -sS -G "${ADDRESS}/api/${API_VERSION}/registry" \
    --data-urlencode "name=${IMAGE_REF}" \
    --data-urlencode "compact=true" \
    -H "Authorization: Bearer ${TOKEN}" \
    -w "\n%{http_code}")
  REG_HTTP=$(printf '%s' "$REG_RAW" | tail -n1)
  REG=$(printf '%s' "$REG_RAW" | sed '$d')
  if printf '%s' "$REG" | compact_ready; then
    POLLS_USED="$i"
    if [[ "$VERBOSE" == "1" ]]; then
      echo "      poll #${i}: HTTP ${REG_HTTP} - compact payload ready"
    fi
    found=1
    break
  fi
  if [[ "$VERBOSE" == "1" ]]; then
    echo "      poll #${i}: HTTP ${REG_HTTP} - not ready yet; sleep ${POLL_INTERVAL}s"
  fi
  sleep "$POLL_INTERVAL"
done

if [[ "$found" != 1 ]]; then
  echo "error: timed out without compact registry row for ${IMAGE_REF}" >&2
  return 1
fi
echo "    poll: ready after ${POLLS_USED} attempt(s)"

REPORT_TMP=$(mktemp -d "${REPORT_TMP_ROOT}/image.XXXXXX")
REPORT_FILE="${REPORT_TMP}/report.txt"
printf '%s' "$REG" > "${REPORT_TMP}/compact.json"

if [[ "$VERBOSE" == "1" ]]; then
  echo "    GET registry detailed (compact=false) for CVE table" >&2
fi
DETAILED_HTTP=$(
  curl -k -sS --max-time 300 -G "${ADDRESS}/api/${API_VERSION}/registry" \
    --data-urlencode "name=${IMAGE_REF}" \
    --data-urlencode "compact=false" \
    -H "Authorization: Bearer ${TOKEN}" \
    -o "${REPORT_TMP}/detailed.json" \
    -w "%{http_code}"
) || true
if [[ "$DETAILED_HTTP" != 2* ]]; then
  echo "    warning: detailed GET HTTP ${DETAILED_HTTP}; CVE table uses compact JSON only" >&2
  cp "${REPORT_TMP}/compact.json" "${REPORT_TMP}/detailed.json"
else
  echo "    detail: HTTP ${DETAILED_HTTP}" >&2
fi

export TL_COMPACT="${REPORT_TMP}/compact.json" TL_DETAILED="${REPORT_TMP}/detailed.json" TL_MICRO="${REPO}"
python3 > "${REPORT_FILE}" <<'PY'
import json, os, re, time
from pathlib import Path

CVE_ID_PATTERN = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
_SEVERITY_SORT_KEY = {
    "critical": 0,
    "high": 1,
    "important": 1,
    "medium": 2,
    "moderate": 2,
    "low": 3,
    "informational": 4,
    "negligible": 5,
    "unknown": 9,
}


def _clip_cell(s, width):
    s = (s or "").replace("\n", " ").replace("\t", " ")
    return s if len(s) <= width else s[: width - 1] + "…"


def _format_vuln_timestamp(val):
    if val is None:
        return "—"
    if isinstance(val, (int, float)):
        ts = float(val) / 1000.0 if val > 1e12 else float(val)
        try:
            return time.strftime("%Y-%m-%d", time.gmtime(ts))
        except (OverflowError, OSError, ValueError):
            return str(int(val))[:16]
    if isinstance(val, str):
        v = val.strip()
        if len(v) >= 10 and v[4] == "-" and v[7] == "-":
            return v[:10]
        return _clip_cell(v, 32)
    return _clip_cell(str(val), 32)


def _cde_like_id_from_dict(d):
    for key in ("cdePublicId", "cdeId", "cde", "caDSRPublicId", "caDSR"):
        v = d.get(key)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def _severity_display(raw):
    if raw is None:
        return "—"
    s = str(raw).strip()
    if not s:
        return "—"
    low = s.lower()
    return low.capitalize() if low in _SEVERITY_SORT_KEY else s[:24]


def _parse_vuln_record(d):
    cve = None
    for key in ("cve", "cveId", "cveID"):
        v = d.get(key)
        if isinstance(v, str):
            m = CVE_ID_PATTERN.search(v)
            if m:
                cve = m.group(1).upper()
                break
    if not cve:
        return None
    sev_raw = d.get("severity") or d.get("risk") or d.get("cvssSeverity") or d.get("impact")
    date_raw = None
    for dk in ("discovered", "detected", "firstSeen", "modified", "time", "creationTime", "discoveredTime"):
        if dk in d and d[dk] is not None:
            date_raw = d[dk]
            break
    pkg = d.get("packageName") or d.get("package") or d.get("fullPackageName") or ""
    if isinstance(pkg, str):
        pkg_s = pkg.strip()
    else:
        pkg_s = str(pkg) if pkg else ""
    return {
        "cve": cve,
        "cde_id": _cde_like_id_from_dict(d),
        "severity": _severity_display(sev_raw),
        "severity_key": str(sev_raw).strip().lower() if sev_raw is not None else "unknown",
        "date": _format_vuln_timestamp(date_raw) if date_raw is not None else "—",
        "package": pkg_s,
    }


def _collect_vulnerability_rows(payload):
    rows = []
    seen_ids = set()

    def walk(o):
        if isinstance(o, dict):
            oid = id(o)
            if oid in seen_ids:
                return
            seen_ids.add(oid)
            parsed = _parse_vuln_record(o)
            if parsed:
                rows.append(parsed)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for item in o:
                walk(item)

    walk(payload)
    dedup = {}
    for r in rows:
        key = (r["cve"], r["package"], r.get("severity_key", ""), r["date"])
        dedup[key] = r
    out = list(dedup.values())

    def sort_key(r):
        sk = _SEVERITY_SORT_KEY.get(r.get("severity_key", ""), 9)
        return sk, r["cve"]

    out.sort(key=sort_key)
    return out


def emit_table_only(payload, microservice_name):
    rows = _collect_vulnerability_rows(payload)
    widths = (22, 18, 14, 10, 16, 28)
    headers = (
        "Microservice",
        "CVE identifier",
        "CDE ID",
        "Severity",
        "Date identified",
        "Package",
    )
    header_line = " | ".join(_clip_cell(h, w) for h, w in zip(headers, widths))
    print(header_line)
    print("-" * min(120, max(len(header_line), 80)))
    for rec in rows:
        line = " | ".join(
            _clip_cell(x, w)
            for x, w in zip(
                (
                    microservice_name,
                    rec["cve"],
                    rec["cde_id"] or "—",
                    rec["severity"],
                    rec["date"],
                    rec["package"] or "—",
                ),
                widths,
            )
        )
        print(line)


compact_raw = json.loads(Path(os.environ["TL_COMPACT"]).read_text(encoding="utf-8"))
detailed_text = Path(os.environ["TL_DETAILED"]).read_text(encoding="utf-8").strip()
if not detailed_text or detailed_text == "null":
    detailed_payload = compact_raw
else:
    try:
        detailed_payload = json.loads(detailed_text)
    except json.JSONDecodeError:
        detailed_payload = compact_raw

emit_table_only(detailed_payload, os.environ["TL_MICRO"])
PY

if [[ "$VERBOSE" == "1" ]]; then
  echo "    GET registry/progress repo=${REPO} tag=${TAG}" >&2
fi
PROG_RAW=$(curl -k -sS -G "${ADDRESS}/api/${API_VERSION}/registry/progress" \
  --data-urlencode "onDemand=true" \
  --data-urlencode "repo=${REPO}" \
  --data-urlencode "tag=${TAG}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -w "\n%{http_code}")
PROG_HTTP=$(printf '%s' "$PROG_RAW" | tail -n1)
PROG=$(printf '%s' "$PROG_RAW" | sed '$d')
if [[ "$VERBOSE" == "1" ]]; then
  echo "      HTTP ${PROG_HTTP}" >&2
  printf '%s\n' "$PROG" >&2
fi

REPORT_FILES+=("$REPORT_FILE")
REPORT_TITLES+=("${IMAGE_REF}")
REPORT_STATUSES+=("scan ${SCAN_HTTP}, select ${SELECT_STATUS}, detail ${DETAILED_HTTP}, progress ${PROG_HTTP}")
}

TOTAL_IMAGES=${#IMAGE_REFS[@]}
IMAGE_INDEX=0
FAILED_IMAGES=()
for IMAGE_REF in "${IMAGE_REFS[@]}"; do
  IMAGE_INDEX=$((IMAGE_INDEX + 1))
  echo "==> image ${IMAGE_INDEX}/${TOTAL_IMAGES}: ${IMAGE_REF}"
  if scan_image "$IMAGE_REF"; then
    echo "==> image ${IMAGE_INDEX}/${TOTAL_IMAGES}: completed"
  else
    echo "==> image ${IMAGE_INDEX}/${TOTAL_IMAGES}: failed" >&2
    FAILED_IMAGES+=("$IMAGE_REF")
  fi
done

if [[ ${#REPORT_FILES[@]} -gt 0 ]]; then
  echo
  echo "Vulnerability report"
  echo "===================="
  for ((i = 0; i < ${#REPORT_FILES[@]}; i++)); do
    echo
    echo "Image $((i + 1))/${#REPORT_FILES[@]}: ${REPORT_TITLES[$i]}"
    echo "Status: ${REPORT_STATUSES[$i]}"
    echo
    cat "${REPORT_FILES[$i]}"
  done
fi

if [[ ${#FAILED_IMAGES[@]} -gt 0 ]]; then
  echo >&2
  echo "error: ${#FAILED_IMAGES[@]} image(s) failed:" >&2
  for IMAGE_REF in "${FAILED_IMAGES[@]}"; do
    echo "  - ${IMAGE_REF}" >&2
  done
  exit 1
fi

echo "done." >&2
