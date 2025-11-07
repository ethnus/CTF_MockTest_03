#!/usr/bin/env bash

set -euo pipefail
export AWS_PAGER=""

# Quick preflight to validate environment, identity, and state readiness

ok()  { printf '[doctor][ok] %s\n' "$1"; }
warn(){ printf '[doctor][warn] %s\n' "$1"; }
fail(){ printf '[doctor][fail] %s\n' "$1"; exit 1; }

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Required command missing: $1"
  fi
}

check_tools() {
  need_cmd aws
  need_cmd python3
  need_cmd zip
  ok "Tools present: aws, python3, zip"
  if command -v jq >/dev/null 2>&1; then
    ok "jq present (optional)"
  else
    warn "jq not found (optional, useful for ad-hoc inspection)"
  fi
}

check_aws_cli_version() {
  local version major
  version="$(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)"
  major="${version%%.*}"
  if [[ -z "$version" || -z "$major" ]]; then
    fail "Unable to determine AWS CLI version"
  fi
  if (( major < 2 )); then
    fail "AWS CLI v2 required; detected $version"
  fi
  ok "AWS CLI version: $version"
}

check_identity() {
  local ident arn acct user role
  if ! ident="$(aws sts get-caller-identity --output json 2>/dev/null)"; then
    fail "Unable to call STS. Configure credentials or start your Learner Lab session."
  fi
  arn="$(printf '%s' "$ident" | python3 -c 'import sys,json;print(json.load(sys.stdin)["Arn"])')"
  acct="$(printf '%s' "$ident" | python3 -c 'import sys,json;print(json.load(sys.stdin)["Account"])')"
  user="$(printf '%s' "$arn" | awk -F/ '{print $NF}')"
  role="$(printf '%s' "$arn" | awk -F/ '/assumed-role/{print $2}')"
  ok "STS identity: $arn"
  printf '[doctor][info] Account=%s User=%s Role=%s\n' "$acct" "$user" "${role:-}" || true
}

check_region() {
  local region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
  if [[ -z "$region" ]]; then
    warn "AWS_REGION not set; defaulting to us-east-1 is recommended for the lab"
  else
    ok "Region: $region"
  fi
}

check_repo_environment() {
  local root
  root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  if printf '%s' "$root" | grep -qiE 'GoogleDrive|CloudStorage/GoogleDrive'; then
    warn "Repo appears under Google Drive; .git may be read-only. Use scripts/git-commit-push.sh."
  fi
  if [[ -f "$root/.git/index.lock" ]]; then
    warn "Found stale Git lock: $root/.git/index.lock. Remove if no other git process is running."
  fi
}

check_state() {
  local state_file="${STATE_FILE:-state/serverless-lab-state.json}"
  if [[ -f "$state_file" ]]; then
    ok "State file present: $state_file"
    return
  fi
  local region acct bak
  region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
  acct="$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)"
  if [[ -n "$region" && -n "$acct" ]]; then
    bak="${HOME}/.lab-state/serverless-resiliency-lab/${acct}-${region}/serverless-lab-state.json"
    if [[ -f "$bak" ]]; then
      ok "Backup state available: $bak"
      return
    fi
  fi
  warn "No state found yet. After deployment, a backup will be written under ~/.lab-state/..."
}

main() {
  check_tools
  check_aws_cli_version
  check_identity
  check_region
  check_repo_environment
  check_state
  printf '\n[doctor] Environment looks good. Next steps:\n'
  printf '  - Deploy:   bash scripts/init.sh\n'
  printf '  - Evaluate: bash scripts/eval.sh\n'
  printf '  - Remediate with debug: bash scripts/remediate.sh --debug\n'
}

main "$@"

