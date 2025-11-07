#!/usr/bin/env bash

set -euo pipefail
export AWS_PAGER=""
EVAL_VERBOSE=${EVAL_VERBOSE:-0}

# Evaluation script for the Serverless Resiliency Lab.
# Validates learner fixes and emits a deterministic flag on complete success.

STATE_FILE="${STATE_FILE:-state/serverless-lab-state.json}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
PROJECT_NAME="serverless-resiliency-lab"
PROJECT_TAG_KEY="Project"
PROJECT_TAG_VALUE="ServerlessLab"
COST_TAG_KEY="CostCenter"
COST_TAG_VALUE="Training"

declare -a CONTROL_RESULTS=()
failures=0

info() {
  (( EVAL_VERBOSE )) && printf '[eval] %s\n' "$1"
}

fail() {
  (( EVAL_VERBOSE )) && printf '[eval][fail] %s\n' "$1"
}

# Diagnostic helpers (only active when --verbose)
diag_note() {
  (( EVAL_VERBOSE )) && printf '[eval][diag] %s\n' "$1"
}

diag_failure() {
  (( EVAL_VERBOSE )) || return 0
  local id="$1"
  case "$id" in
    1)
      diag_note "KMS policy details (expected principals may include both state and active roles):"
      diag_note " - Expected (state): arn:aws:iam::${AccountId}:role/${LabRoleName}"
      if [[ -n "${LAB_ROLE_NAME:-}" ]]; then
        diag_note " - Expected (active): arn:aws:iam::${AccountId}:role/${LAB_ROLE_NAME}"
      fi
      aws kms get-key-policy --key-id "$KmsKeyId" --policy-name default --region "$Region" --query Policy --output text 2>/dev/null || true
      ;;
    2)
      diag_note "S3 default encryption configuration:"
      aws s3api get-bucket-encryption --bucket "$S3BucketName" --region "$Region" 2>/dev/null || true
      ;;
    3)
      diag_note "S3 bucket tags:"
      aws s3api get-bucket-tagging --bucket "$S3BucketName" --region "$Region" 2>/dev/null || true
      ;;
    4)
      diag_note "DynamoDB SSE description:"
      aws dynamodb describe-table --table-name "$DynamoTableName" --region "$Region" --query 'Table.SSEDescription' 2>/dev/null || true
      ;;
    5)
      diag_note "DynamoDB PITR status:"
      aws dynamodb describe-continuous-backups --table-name "$DynamoTableName" --region "$Region" --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription' 2>/dev/null || true
      ;;
    6)
      diag_note "DynamoDB gateway endpoint count in VPC:"
      aws ec2 describe-vpc-endpoints --region "$Region" --filters "Name=vpc-id,Values=$VpcId" "Name=service-name,Values=com.amazonaws.${Region}.dynamodb" --query 'length(VpcEndpoints)' 2>/dev/null || true
      ;;
    7)
      diag_note "S3 gateway endpoint route associations:"
      aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$S3EndpointId" --region "$Region" --query 'VpcEndpoints[0].RouteTableIds' --output json 2>/dev/null || true
      ;;
    8)
      diag_note "Lambda env vars (expected DDB_TABLE_NAME=$DynamoTableName):"
      aws lambda get-function-configuration --function-name "$LambdaArn" --region "$Region" --query 'Environment.Variables' 2>/dev/null || true
      ;;
    9)
      diag_note "EventBridge rule state (should be ENABLED):"
      aws events describe-rule --name "$EventRuleName" --region "$Region" --query 'State' --output text 2>/dev/null || true
      ;;
    10)
      diag_note "API policy and endpointConfiguration.vpcEndpointIds:"
      aws apigateway get-rest-api --rest-api-id "$ApiId" --region "$Region" --query policy 2>/dev/null || true
      aws apigateway get-rest-api --rest-api-id "$ApiId" --region "$Region" --query 'endpointConfiguration.vpcEndpointIds' 2>/dev/null || true
      diag_note "Expected aws:SourceVpce: $ExecuteApiEndpointId"
      ;;
    *) ;;
  esac
}

usage() {
  cat <<'USAGE'
Usage: bash eval.sh [--verbose|-v] [--help|-h]

Runs the lab evaluation and prints a generic tabular scorecard with Task 1..N
and ACCEPTED/NOT ACCEPTED statuses. No check details are revealed.

Options:
  -v, --verbose  Instructor mode. Adds log lines and per-task numeric status.
  -h, --help     Show this help and exit.
USAGE
}

require_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    info "State file not found at $STATE_FILE. Checking backup..."
    local acct region bak
    region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
    acct="$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)"
    if [[ -n "$region" && -n "$acct" ]]; then
      bak="${HOME}/.lab-state/serverless-resiliency-lab/${acct}-${region}/serverless-lab-state.json"
      if [[ -f "$bak" ]]; then
        mkdir -p "$(dirname "$STATE_FILE")"
        cp "$bak" "$STATE_FILE"
        info "Recovered state from $bak"
      else
        fail "State file missing and no backup found. Run init.sh or rebuild-state.sh."
        exit 1
      fi
    else
      fail "Region/account unknown and state missing. Set AWS_REGION or run rebuild-state.sh."
      exit 1
    fi
  fi
}

check_aws_cli_version() {
  local version major
  version="$(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)"
  major="${version%%.*}"
  if [[ -z "$version" ]]; then
    fail "Unable to determine AWS CLI version."
    exit 1
  fi
  if ! [[ "$major" =~ ^[0-9]+$ ]]; then
    fail "Unrecognized AWS CLI version format: $version."
    exit 1
  fi
  if (( major < 2 )); then
    fail "AWS CLI v2 or later required. Detected $version."
    exit 1
  fi
  info "Detected AWS CLI version $version"
}

load_state() {
  python3 - <<'PY'
import json
import os
import sys

state_path = os.environ["STATE_FILE"]
with open(state_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

for key, value in data.items():
    print(f"{key}={value}")
PY
}

check_kms_policy() {
  local expected_principal="arn:aws:iam::${AccountId}:role/${LabRoleName}"
  local expected_active=""
  if [[ -n "${LAB_ROLE_NAME:-}" ]]; then
    expected_active="arn:aws:iam::${AccountId}:role/${LAB_ROLE_NAME}"
  fi
  local policy_json
  if ! policy_json="$(aws kms get-key-policy --key-id "$KmsKeyId" --policy-name default --region "$Region")"; then
    fail "Unable to read KMS key policy."
    return 1
  fi
  if printf '%s' "$policy_json" | python3 - "$expected_principal" "$expected_active" <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    wrapper = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)
policy_data = wrapper.get("Policy")
if policy_data is None:
    sys.exit(1)
if isinstance(policy_data, str):
    policy = json.loads(policy_data)
else:
    policy = policy_data

expected = [p for p in sys.argv[1:] if p]


def contains_principal(statement, principal_arn):
    principal_value = statement.get("Principal")
    if not principal_value:
        return False
    if isinstance(principal_value, str):
        return principal_value == principal_arn or principal_value == "*"
    if isinstance(principal_value, dict):
        aws = principal_value.get("AWS")
        if isinstance(aws, str):
            return aws == principal_arn or aws == "*"
        if isinstance(aws, list):
            return principal_arn in aws or "*" in aws
    return False


def has_encrypt_action(statement):
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    normalized = [action.lower() for action in actions]
    if "*" in normalized or "kms:*" in normalized:
        return True
    required = {
        "kms:encrypt",
        "kms:decrypt",
        "kms:generatedatakey",
        "kms:generatedatakeywithoutplaintext",
        "kms:reencrypt*",
        "kms:reencryptfrom",
        "kms:reencryptto",
    }
    return any(
        action in required or action.startswith("kms:reencrypt")
        for action in normalized
    )

def any_principal(stmt):
    for p in expected:
        if contains_principal(stmt, p):
            return True
    return False

found = any(
    stmt.get("Effect") == "Allow"
    and any_principal(stmt)
    and has_encrypt_action(stmt)
    for stmt in policy.get("Statement", [])
)

if not found:
    sys.exit(1)
PY
  then
    info "Encryption access controls verified"
    return 0
  else
    # Fallback: match principals and required actions in raw policy text
    local policy_text roles ok_principal ok_actions
    policy_text="$(aws kms get-key-policy --key-id "$KmsKeyId" --policy-name default --region "$Region" --query Policy --output text 2>/dev/null || true)"
    roles=("$expected_principal")
    [[ -n "$expected_active" ]] && roles+=("$expected_active")
    ok_principal=1
    ok_actions=1
    local r
    ok_principal=0
    for r in "${roles[@]}"; do
      if printf '%s' "$policy_text" | grep -Fq "$r"; then
        ok_principal=1
        break
      fi
    done
    if printf '%s' "$policy_text" | grep -Fq '"kms:Encrypt"' && printf '%s' "$policy_text" | grep -Fq '"kms:Decrypt"'; then
      ok_actions=1
    else
      ok_actions=0
    fi
    if (( ok_principal )) && (( ok_actions )); then
      info "Encryption access controls verified (fallback)"
      return 0
    fi
    fail "Encryption access controls still incomplete"
    return 1
  fi
}

check_s3_encryption() {
  local encryption
  local alias_arn="arn:aws:kms:${Region}:${AccountId}:alias/${PROJECT_NAME}"
  if ! encryption="$(aws s3api get-bucket-encryption --bucket "$S3BucketName" --region "$Region" 2>/dev/null)"; then
    return 1
  fi
  if printf '%s' "$encryption" | python3 - "$KmsKeyArn" "$KmsKeyId" "$alias_arn" <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)
rules = data.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
key_arn, key_id, alias_arn = sys.argv[1:4]


def matches(candidate):
    if not candidate:
        return False
    if candidate in {key_arn, key_id, alias_arn}:
        return True
    if candidate.endswith(key_id):
        return True
    return False


for rule in rules:
    apply = rule.get("ApplyServerSideEncryptionByDefault", {})
    key_id_value = apply.get("KMSMasterKeyID")
    if apply.get("SSEAlgorithm") == "aws:kms" and matches(key_id_value):
        sys.exit(0)
sys.exit(1)
PY
  then
    return 0
  else
    # Fallback via JMESPath
    local eff
    eff="$(aws s3api get-bucket-encryption --bucket "$S3BucketName" --region "$Region" \
      --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID' \
      --output text 2>/dev/null || true)"
    if [[ -z "$eff" || "$eff" == "None" ]]; then
      return 1
    fi
    if [[ "$eff" == "$KmsKeyArn" || "$eff" == "$KmsKeyId" || "$eff" == "arn:aws:kms:${Region}:${AccountId}:alias/${PROJECT_NAME}" || "$eff" == *"$KmsKeyId" ]]; then
      return 0
    fi
    return 1
  fi
}

check_s3_tags() {
  if ! tags_json="$(aws s3api get-bucket-tagging --bucket "$S3BucketName" --region "$Region" 2>/dev/null)"; then
    return 1
  fi
  if printf '%s' "$tags_json" | python3 - "$PROJECT_TAG_KEY" "$PROJECT_TAG_VALUE" "$COST_TAG_KEY" "$COST_TAG_VALUE" <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)
tagset = {tag["Key"]: tag["Value"] for tag in data.get("TagSet", [])}
proj_key, proj_value, cost_key, cost_value = sys.argv[1:5]

if tagset.get(proj_key) == proj_value and tagset.get(cost_key) == cost_value:
    sys.exit(0)
sys.exit(1)
PY
  then
    return 0
  else
    # Fallback via JMESPath
    local proj cost
    proj="$(aws s3api get-bucket-tagging --bucket "$S3BucketName" --region "$Region" \
      --query "TagSet[?Key=='${PROJECT_TAG_KEY}'].Value | [0]" --output text 2>/dev/null || true)"
    cost="$(aws s3api get-bucket-tagging --bucket "$S3BucketName" --region "$Region" \
      --query "TagSet[?Key=='${COST_TAG_KEY}'].Value | [0]" --output text 2>/dev/null || true)"
    if [[ "$proj" == "$PROJECT_TAG_VALUE" && "$cost" == "$COST_TAG_VALUE" ]]; then
      return 0
    fi
    return 1
  fi
}

check_dynamodb_sse() {
  local table_json
  table_json="$(aws dynamodb describe-table --table-name "$DynamoTableName" --region "$Region")"
  if printf '%s' "$table_json" | python3 - "$KmsKeyArn" <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    table = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)
expected_key = sys.argv[1]

sse = table["Table"].get("SSEDescription", {})
if sse.get("Status") != "ENABLED":
    sys.exit(1)
if sse.get("KMSMasterKeyArn") != expected_key:
    sys.exit(1)
sys.exit(0)
PY
  then
    return 0
  else
    # Fallback via query
    local status key
    status="$(aws dynamodb describe-table --table-name "$DynamoTableName" --region "$Region" --query 'Table.SSEDescription.Status' --output text 2>/dev/null || true)"
    key="$(aws dynamodb describe-table --table-name "$DynamoTableName" --region "$Region" --query 'Table.SSEDescription.KMSMasterKeyArn' --output text 2>/dev/null || true)"
    if [[ "$status" == "ENABLED" && "$key" == "$KmsKeyArn" ]]; then
      return 0
    fi
    return 1
  fi
}

check_dynamodb_pitr() {
  local summary_json
  summary_json="$(aws dynamodb describe-continuous-backups --table-name "$DynamoTableName" --region "$Region")"
  if printf '%s' "$summary_json" | python3 - <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)
status = data.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus")
sys.exit(0 if status == "ENABLED" else 1)
PY
  then
    return 0
  else
    local pitr
    pitr="$(aws dynamodb describe-continuous-backups --table-name "$DynamoTableName" --region "$Region" \
      --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus' \
      --output text 2>/dev/null || true)"
    [[ "$pitr" == "ENABLED" ]]
    return $?
  fi
}

check_dynamodb_endpoint() {
  local count
  count="$(aws ec2 describe-vpc-endpoints \
    --region "$Region" \
    --filters "Name=vpc-id,Values=$VpcId" "Name=service-name,Values=com.amazonaws.${Region}.dynamodb" \
    --query 'length(VpcEndpoints)')"
  if [[ "$count" -ge 1 ]]; then
    return 0
  else
    return 1
  fi
}

check_s3_endpoint_routes() {
  local routes_json
  routes_json="$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$S3EndpointId" --region "$Region" --query 'VpcEndpoints[0].RouteTableIds' --output json)"
  if printf '%s' "$routes_json" | python3 - <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)
if data and isinstance(data, list):
    sys.exit(0)
sys.exit(1)
PY
  then
    return 0
  else
    local cnt
    cnt="$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$S3EndpointId" --region "$Region" --query 'length(VpcEndpoints[0].RouteTableIds)' --output text 2>/dev/null || true)"
    if [[ "$cnt" =~ ^[0-9]+$ && "$cnt" -ge 1 ]]; then
      return 0
    fi
    return 1
  fi
}

check_lambda_env() {
  local config_json
  config_json="$(aws lambda get-function-configuration --function-name "$LambdaArn" --region "$Region")"
  if printf '%s' "$config_json" | python3 - "$DynamoTableName" <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    cfg = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)
target = sys.argv[1]
env = cfg.get("Environment", {}).get("Variables", {})
if env.get("DDB_TABLE_NAME") == target:
    sys.exit(0)
sys.exit(1)
PY
  then
    return 0
  else
    local ddb
    ddb="$(aws lambda get-function-configuration --function-name "$LambdaArn" --region "$Region" --query 'Environment.Variables.DDB_TABLE_NAME' --output text 2>/dev/null || true)"
    [[ "$ddb" == "$DynamoTableName" ]]
    return $?
  fi
}

check_event_rule() {
  local state
  state="$(aws events describe-rule --name "$EventRuleName" --region "$Region" --query 'State' --output text)"
  if [[ "$state" == "ENABLED" ]]; then
    return 0
  else
    return 1
  fi
}

check_api_policy() {
  local policy_json
  policy_json="$(aws apigateway get-rest-api --rest-api-id "$ApiId" --region "$Region" --query 'policy')"
  if POLICY_JSON="$policy_json" python3 - "$ExecuteApiEndpointId" <<'PY'
import json
import os
import sys

raw = os.environ.get("POLICY_JSON", "").strip()
if not raw:
    sys.exit(1)
try:
    policy_data = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)
if policy_data is None:
    sys.exit(1)
if isinstance(policy_data, str):
    if not policy_data:
        sys.exit(1)
    try:
        policy = json.loads(policy_data)
    except json.JSONDecodeError:
        sys.exit(1)
else:
    policy = policy_data

vpce = sys.argv[1]

def vpce_matches(cond, expected):
    if not isinstance(cond, dict):
        return False
    se = cond.get("StringEquals", {})
    if isinstance(se, dict):
        val = se.get("aws:SourceVpce")
        if isinstance(val, str) and val.strip() == expected:
            return True
        if isinstance(val, list) and expected in [str(x).strip() for x in val]:
            return True
    # Tolerate StringEqualsIfExists too
    se2 = cond.get("StringEqualsIfExists", {})
    if isinstance(se2, dict):
        val = se2.get("aws:SourceVpce")
        if isinstance(val, str) and val.strip() == expected:
            return True
        if isinstance(val, list) and expected in [str(x).strip() for x in val]:
            return True
    return False

for statement in policy.get("Statement", []):
    if statement.get("Effect") != "Allow":
        continue
    condition = statement.get("Condition", {})
    if vpce_matches(condition, vpce):
        sys.exit(0)

# Fallback: raw string contains expected VPCe
if vpce in raw:
    sys.exit(0)
sys.exit(1)
PY
  then
    return 0
  else
    # Shell-level fallback: simple substring match on the raw policy text
    local policy_text
    policy_text="$(aws apigateway get-rest-api --rest-api-id "$ApiId" --region "$Region" --query policy --output text 2>/dev/null || true)"
    if printf '%s' "$policy_text" | grep -Fq "$ExecuteApiEndpointId"; then
      return 0
    fi
    return 1
  fi
}

run_check() {
  local id="$1"
  local _unused_label="$2"
  local fn="$3"

  if "$fn"; then
    CONTROL_RESULTS+=("$id||ACCEPTED")
    (( EVAL_VERBOSE )) && printf '[eval] #%s: ACCEPTED\n' "$id"
  else
    CONTROL_RESULTS+=("$id||INCOMPLETE")
    (( EVAL_VERBOSE )) && printf '[eval] #%s: INCOMPLETE\n' "$id"
    diag_failure "$id"
    ((failures+=1))
  fi
}

print_scorecard() {
  local accepted=0 total=0 entry id status shown
  # Header
  printf '\n'
  printf '+----+-----------+---------------+\n'
  printf '| %-2s | %-9s | %-13s |\n' '#' 'Task' 'Status'
  printf '+----+-----------+---------------+\n'
  for entry in "${CONTROL_RESULTS[@]}"; do
    IFS='|' read -r id _ status <<<"$entry" || true
    (( total++ ))
    if [[ "$status" == "ACCEPTED" ]]; then
      shown="ACCEPTED"
      (( accepted++ ))
    else
      shown="NOT ACCEPTED"
    fi
    printf '| %-2s | %-9s | %-13s |\n' "$id" "Task $id" "$shown"
  done
  printf '+----+-----------+---------------+\n'
  printf 'Accepted: %d/%d\n' "$accepted" "$total"
}

main() {
  # Parse flags
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -v|--verbose)
        EVAL_VERBOSE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        # Ignore unknowns to stay forwards-compatible
        shift
        ;;
    esac
  done

  require_state
  check_aws_cli_version
  info "Loading deployment state from $STATE_FILE"

  while IFS='=' read -r key value; do
    export "$key"="$value"
  done < <(STATE_FILE="$STATE_FILE" load_state)

  info "Evaluating remediation status for account $AccountId in $Region"

  # Prefer the active assumed role if provided via LAB_ROLE_NAME for KMS checks.
  # Do not overwrite LabRoleName from state; KMS verification now accepts both.
  if [[ -n "${LAB_ROLE_NAME:-}" && "${LabRoleName:-}" != "$LAB_ROLE_NAME" ]]; then
    info "Using active role from LAB_ROLE_NAME for checks: $LAB_ROLE_NAME (state role remains $LabRoleName)"
  fi

  CONTROL_RESULTS=()
  failures=0

  run_check 1 "" check_kms_policy
  run_check 2 "" check_s3_encryption
  run_check 3 "" check_s3_tags
  run_check 4 "" check_dynamodb_sse
  run_check 5 "" check_dynamodb_pitr
  run_check 6 "" check_dynamodb_endpoint
  run_check 7 "" check_s3_endpoint_routes
  run_check 8 "" check_lambda_env
  run_check 9 "" check_event_rule
  run_check 10 "" check_api_policy

  print_scorecard

  if [[ "$failures" -eq 0 ]]; then
    local flag_input="${AccountId}:${Region}:${ApiId}"
    local flag
    flag="$(FLAG_INPUT="$flag_input" python3 - <<'PY'
import hashlib
import os

data = os.environ.get("FLAG_INPUT")
digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
print(digest[:32])
PY
)"
    info "All controls satisfied."
    printf 'FLAG{%s}\n' "$flag"
    exit 0
  else
    fail "Remediation incomplete. Continue investigating."
    exit 2
  fi
}

main "$@"
