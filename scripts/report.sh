#!/usr/bin/env bash

set -euo pipefail

STATE_FILE="${STATE_FILE:-state/serverless-lab-state.json}"
RESULTS_DB="${RESULTS_DB:-state/results.db}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_SCRIPT="${SCRIPT_DIR}/eval.sh"

info() {
  printf '[report] %s\n' "$1"
}

warn() {
  printf '[report][warn] %s\n' "$1" >&2
}

fail() {
  printf '[report][fail] %s\n' "$1" >&2
  exit 1
}

require_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    fail "State file not found at $STATE_FILE. Run init.sh first (or ensure STATE_FILE is set correctly)."
  fi
}

check_aws_cli_version() {
  local version major
  version="$(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)"
  major="${version%%.*}"
  if [[ -z "$version" ]]; then
    fail "Unable to determine AWS CLI version."
  fi
  if [[ "$major" != "3" ]]; then
    fail "AWS CLI v3 required. Detected $version."
  fi
  info "Detected AWS CLI version $version"
}

check_aws_credentials() {
  local missing=()
  for var in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; do
    if [[ -z "${!var:-}" ]]; then
      missing+=("$var")
    fi
  done
  if ((${#missing[@]} > 0)); then
    fail "Missing credential environment variables: ${missing[*]}"
  fi
  local session_account
  session_account="$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null)"
  if [[ -z "$session_account" ]]; then
    fail "Unable to validate credentials via AWS STS."
  fi
  export SESSION_ACCOUNT="$session_account"
  info "Session credentials validated for account $SESSION_ACCOUNT"
}

load_state() {
  while IFS='=' read -r key value; do
    export "$key"="$value"
  done < <(python3 - "$STATE_FILE" <<'PY'
import json
import os
import sys

state_path = sys.argv[1]
with open(state_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

for key, value in data.items():
    print(f"{key}={value}")
PY
)
}

record_result() {
  local status="$1"
  local flag_value="$2"
  mkdir -p "$(dirname "$RESULTS_DB")"
  if ! EVAL_STATUS="$status" EVAL_FLAG="$flag_value" python3 - "$RESULTS_DB" <<'PY'
import os
import sys
import sqlite3
import hashlib
import datetime

db_path = sys.argv[1]
status = os.environ.get("EVAL_STATUS")
flag_value = os.environ.get("EVAL_FLAG", "")
account_id = os.environ.get("AccountId", "")
region = os.environ.get("Region", "")
timestamp = datetime.datetime.utcnow().isoformat() + "Z"

def digest(value):
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

access_hash = digest(os.environ.get("AWS_ACCESS_KEY_ID", ""))
secret_hash = digest(os.environ.get("AWS_SECRET_ACCESS_KEY", ""))
token_hash = digest(os.environ.get("AWS_SESSION_TOKEN", ""))

conn = sqlite3.connect(db_path)
conn.execute("""
CREATE TABLE IF NOT EXISTS results (
  account_id TEXT,
  region TEXT,
  status TEXT,
  flag TEXT,
  evaluated_at TEXT,
  access_key_hash TEXT,
  secret_hash TEXT,
  token_hash TEXT
)
""")
conn.execute("""
INSERT INTO results (
  account_id,
  region,
  status,
  flag,
  evaluated_at,
  access_key_hash,
  secret_hash,
  token_hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", (
    account_id,
    region,
    status,
    flag_value,
    timestamp,
    access_hash,
    secret_hash,
    token_hash
))
conn.commit()
conn.close()
PY
  then
    warn "Failed to persist evaluation result to SQLite database"
  fi
}

run_evaluation() {
  local output
  if output="$("$EVAL_SCRIPT" "$@" 2>&1)"; then
    printf '%s\n' "$output"
    local flag_line
    flag_line="$(printf '%s\n' "$output" | grep -o 'FLAG{[^}]*}' | head -n 1 || true)"
    record_result "PASS" "${flag_line:-}"
    exit 0
  else
    local status=$?
    printf '%s\n' "$output" >&2
    record_result "FAIL" ""
    exit "$status"
  fi
}

main() {
  require_state
  check_aws_cli_version
  check_aws_credentials
  load_state

  if [[ "${SESSION_ACCOUNT:-}" != "${AccountId:-}" ]]; then
    warn "Credential account ($SESSION_ACCOUNT) does not match initialized account (${AccountId:-unknown})."
    record_result "ERROR" ""
    exit 1
  fi

  run_evaluation "$@"
}

main "$@"
