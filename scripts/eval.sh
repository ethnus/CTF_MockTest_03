#!/usr/bin/env bash

set -euo pipefail

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
  printf '[eval] %s\n' "$1"
}

fail() {
  printf '[eval][fail] %s\n' "$1"
}

require_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    fail "State file not found at $STATE_FILE. Run init.sh first (or ensure STATE_FILE is set correctly)."
    exit 1
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
  local policy_json
  if ! policy_json="$(aws kms get-key-policy --key-id "$KmsKeyId" --policy-name default --region "$Region")"; then
    fail "Unable to read KMS key policy."
    return 1
  fi
  if printf '%s' "$policy_json" | python3 - "$expected_principal" <<'PY'
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

principal = sys.argv[1]


def contains_principal(statement, principal_arn):
    principal_value = statement.get("Principal")
    if not principal_value:
        return False
    if isinstance(principal_value, str):
        if principal_value == "*" or principal_value == principal_arn:
            return True
        return False
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


found = any(
    stmt.get("Effect") == "Allow"
    and contains_principal(stmt, principal)
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
    return 1
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
    return 1
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
  if printf '%s' "$policy_json" | python3 - "$ExecuteApiEndpointId" <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
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

for statement in policy.get("Statement", []):
    if statement.get("Effect") != "Allow":
        continue
    condition = statement.get("Condition", {}).get("StringEquals", {})
    if condition.get("aws:SourceVpce") == vpce:
        sys.exit(0)
sys.exit(1)
PY
  then
    return 0
  else
    return 1
  fi
}

run_check() {
  local id="$1"
  local label="$2"
  local fn="$3"

  if "$fn"; then
    CONTROL_RESULTS+=("$id|$label|ACCEPTED")
    info "[$id] $label -> ACCEPTED"
  else
    CONTROL_RESULTS+=("$id|$label|INCOMPLETE")
    info "[$id] $label -> INCOMPLETE"
    ((failures+=1))
  fi
}

print_scorecard() {
  printf '\n'
  printf '+----------------------------------------------------------------------------+\n'
  printf '| Control Scorecard                                                          |\n'
  printf '+----+--------------------------------------------------------------+--------+\n'
  printf '| %-2s | %-60s | %-6s |\n' '#' 'Control' 'Status'
  printf '+----+--------------------------------------------------------------+--------+\n'
  local entry
  for entry in "${CONTROL_RESULTS[@]}"; do
    IFS='|' read -r id label status <<<"$entry"
    printf '| %-2s | %-60s | %-6s |\n' "$id" "$label" "$status"
  done
  printf '+----+--------------------------------------------------------------+--------+\n'
}

main() {
  require_state
  check_aws_cli_version
  info "Loading deployment state from $STATE_FILE"

  while IFS='=' read -r key value; do
    export "$key"="$value"
  done < <(STATE_FILE="$STATE_FILE" load_state)

  info "Evaluating remediation status for account $AccountId in $Region"

  # Prefer the active assumed role if provided via LAB_ROLE_NAME for KMS checks
  if [[ -n "${LAB_ROLE_NAME:-}" && "${LabRoleName:-}" != "$LAB_ROLE_NAME" ]]; then
    info "Using active role from LAB_ROLE_NAME for checks: $LAB_ROLE_NAME (replacing $LabRoleName)"
    LabRoleName="$LAB_ROLE_NAME"
  fi

  CONTROL_RESULTS=()
  failures=0

  run_check 1 "KMS policy grants LabRole encrypt/decrypt" check_kms_policy
  run_check 2 "S3 bucket enforces default KMS encryption" check_s3_encryption
  run_check 3 "S3 bucket has required governance tags" check_s3_tags
  run_check 4 "DynamoDB table uses customer-managed KMS key" check_dynamodb_sse
  run_check 5 "DynamoDB point-in-time recovery enabled" check_dynamodb_pitr
  run_check 6 "DynamoDB Gateway endpoint attached to VPC" check_dynamodb_endpoint
  run_check 7 "S3 Gateway endpoint associated with route table" check_s3_endpoint_routes
  run_check 8 "Lambda environment configured with correct table name" check_lambda_env
  run_check 9 "EventBridge heartbeat rule enabled" check_event_rule
  run_check 10 "API Gateway policy targets correct VPC endpoint" check_api_policy

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
    info "All high-level controls satisfied. Share the flag below:"
    printf 'FLAG{%s}\n' "$flag"
    exit 0
  else
    fail "Remediation incomplete. Continue investigating."
    exit 2
  fi
}

main "$@"
