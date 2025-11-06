#!/usr/bin/env bash

set -euo pipefail

# Remediation script for the Serverless Resiliency Lab.
# Corrects all intentional faults silently so instructors can restore the baseline.

STATE_FILE="${STATE_FILE:-state/serverless-lab-state.json}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
PROJECT_TAG_KEY="Project"
PROJECT_TAG_VALUE="ServerlessLab"
COST_TAG_KEY="CostCenter"
COST_TAG_VALUE="Training"
PROJECT_NAME="serverless-resiliency-lab"

declare -a VERIFICATION_RESULTS=()

info() {
  printf '[remediate] %s\n' "$1"
}

warn() {
  printf '[remediate][warn] %s\n' "$1"
}

error() {
  printf '[remediate][error] %s\n' "$1" >&2
  exit 1
}

require_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    error "State file not found at $STATE_FILE. Run init.sh first."
  fi
}

check_aws_cli_version() {
  local version major
  version="$(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)"
  major="${version%%.*}"
  if [[ -z "$version" ]]; then
    printf '[remediate][error] Unable to determine AWS CLI version.\n' >&2
    exit 1
  fi
  if ! [[ "$major" =~ ^[0-9]+$ ]]; then
    printf '[remediate][error] Unrecognized AWS CLI version format: %s.\n' "$version" >&2
    exit 1
  fi
  if (( major < 2 )); then
    printf '[remediate][error] AWS CLI v2 or later required. Detected %s.\n' "$version" >&2
    exit 1
  fi
  info "Detected AWS CLI version $version"
}

load_state() {
  python3 - <<'PY'
import json
import os

state_path = os.environ["STATE_FILE"]
with open(state_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

for key, value in data.items():
    print(f"{key}={value}")
PY
}

ensure_kms_policy() {
  info "Ensuring KMS key policy allows Lab role usage"
  local policy_file
  policy_file="$(mktemp)"
  cat <<EOF >"$policy_file"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRootAccountAdministration",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${AccountId}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowLabRoleUsage",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${AccountId}:role/${LabRoleName}"
      },
      "Action": [
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:ReEncrypt*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

  aws kms put-key-policy \
    --key-id "$KmsKeyId" \
    --policy-name default \
    --policy file://"$policy_file" \
    --region "$Region" >/dev/null

  rm -f "$policy_file"
}

verify_kms_policy() {
  local expected_principal="arn:aws:iam::${AccountId}:role/${LabRoleName}"
  local policy_json
  if ! policy_json="$(aws kms get-key-policy --key-id "$KmsKeyId" --policy-name default --region "$Region")"; then
    warn "Unable to read KMS key policy for verification."
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
    try:
        policy = json.loads(policy_data)
    except json.JSONDecodeError:
        sys.exit(1)
else:
    policy = policy_data

principal = sys.argv[1]


def contains_principal(statement, principal_arn):
    principal_value = statement.get("Principal")
    if not principal_value:
        return False
    if isinstance(principal_value, str):
        return principal_value in (principal_arn, "*")
    if isinstance(principal_value, dict):
        aws = principal_value.get("AWS")
        if isinstance(aws, str):
            return aws in (principal_arn, "*")
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

sys.exit(0 if found else 1)
PY
  then
    return 0
  else
    return 1
  fi
}

ensure_s3_encryption() {
  info "Enforcing S3 bucket SSE-KMS with custom CMK"
  aws s3api put-bucket-encryption \
    --bucket "$S3BucketName" \
    --server-side-encryption-configuration "{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$KmsKeyArn\"}}]}" \
    --region "$Region" >/dev/null

  aws s3api put-bucket-tagging \
    --bucket "$S3BucketName" \
    --tagging "TagSet=[{Key=$PROJECT_TAG_KEY,Value=$PROJECT_TAG_VALUE},{Key=$COST_TAG_KEY,Value=$COST_TAG_VALUE}]" \
    --region "$Region" >/dev/null
}

verify_s3_encryption() {
  local alias_arn="arn:aws:kms:${Region}:${AccountId}:alias/${PROJECT_NAME}"
  local encryption
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

verify_s3_tags() {
  local tags_json
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

sys.exit(0 if tagset.get(proj_key) == proj_value and tagset.get(cost_key) == cost_value else 1)
PY
  then
    return 0
  else
    return 1
  fi
}

ensure_dynamodb_encryption() {
  info "Aligning DynamoDB table encryption and backups"
  local table_json action
  table_json="$(aws dynamodb describe-table --table-name "$DynamoTableName" --region "$Region")"
  action="$(printf '%s' "$table_json" | python3 - "$KmsKeyArn" <<'PY'
import json
import sys

raw = sys.stdin.read().strip()
if not raw:
    print("update")
    sys.exit(0)
try:
    table = json.loads(raw)
except json.JSONDecodeError:
    print("update")
    sys.exit(0)
desired = sys.argv[1]
sse = table.get("Table", {}).get("SSEDescription", {})
if sse.get("Status") == "ENABLED" and sse.get("KMSMasterKeyArn") == desired:
    print("skip")
else:
    print("update")
PY
)"

  if [[ "$action" == "update" ]]; then
    if ! update_output="$(aws dynamodb update-table \
      --table-name "$DynamoTableName" \
      --sse-specification "Enabled=true,SSEType=KMS,KMSMasterKeyId=$KmsKeyArn" \
      --region "$Region" 2>&1)"; then
      if grep -q "Table is already encrypted with given KMSMasterKeyId" <<<"$update_output"; then
        info "DynamoDB table already uses the expected CMK; skipping update-table call"
      else
        error "Failed to update DynamoDB table encryption: $update_output"
      fi
    fi
  else
    info "DynamoDB table already uses the expected CMK; skipping update-table call"
  fi

  aws dynamodb update-continuous-backups \
    --table-name "$DynamoTableName" \
    --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \
    --region "$Region" >/dev/null
}

ensure_dynamodb_endpoint() {
  info "Ensuring DynamoDB gateway endpoint exists"
  local existing
  existing="$(aws ec2 describe-vpc-endpoints \
    --filters "Name=vpc-id,Values=$VpcId" "Name=service-name,Values=com.amazonaws.${Region}.dynamodb" \
    --region "$Region" \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text 2>/dev/null || true)"
  if [[ "$existing" == "None" || -z "$existing" ]]; then
    aws ec2 create-vpc-endpoint \
      --vpc-id "$VpcId" \
      --service-name "com.amazonaws.${Region}.dynamodb" \
      --route-table-ids "$RouteTableId" \
      --vpc-endpoint-type Gateway \
      --region "$Region" >/dev/null
  else
    aws ec2 modify-vpc-endpoint \
      --vpc-endpoint-id "$existing" \
      --add-route-table-ids "$RouteTableId" \
      --region "$Region" >/dev/null
  fi
}

repair_s3_endpoint() {
  info "Re-attaching route table to S3 gateway endpoint"
  aws ec2 modify-vpc-endpoint \
    --vpc-endpoint-id "$S3EndpointId" \
    --add-route-table-ids "$RouteTableId" \
    --region "$Region" >/dev/null
}

repair_lambda_environment() {
  info "Updating Lambda environment variables"
  aws lambda update-function-configuration \
    --function-name "$LambdaArn" \
    --environment "Variables={DDB_TABLE_NAME=$DynamoTableName,S3_BUCKET_NAME=$S3BucketName,LOG_LEVEL=INFO}" \
    --region "$Region" >/dev/null
}

enable_eventbridge_rule() {
  info "Enabling EventBridge heartbeat rule"
  aws events enable-rule --name "$EventRuleName" --region "$Region" >/dev/null
}

repair_api_policy() {
  info "Aligning API Gateway resource policy with execute-api endpoint"
  local policy_file
  policy_file="$(mktemp)"
  cat <<EOF >"$policy_file"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:${Region}:${AccountId}:${ApiId}/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceVpce": "${ExecuteApiEndpointId}"
        }
      }
    }
  ]
}
EOF

  local policy_payload
  policy_payload="$(tr -d '\n' <"$policy_file" | sed 's/\"/\\\"/g')"

  aws apigateway update-rest-api \
    --rest-api-id "$ApiId" \
    --patch-operations "[{\"op\":\"replace\",\"path\":\"/policy\",\"value\":\"$policy_payload\"}]" \
    --region "$Region" >/dev/null

  rm -f "$policy_file"
}

verify_dynamodb_sse() {
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

verify_dynamodb_pitr() {
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

verify_dynamodb_endpoint() {
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

verify_s3_endpoint_routes() {
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

verify_lambda_env() {
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
sys.exit(0 if env.get("DDB_TABLE_NAME") == target else 1)
PY
  then
    return 0
  else
    return 1
  fi
}

verify_event_rule() {
  local state
  state="$(aws events describe-rule --name "$EventRuleName" --region "$Region" --query 'State' --output text)"
  if [[ "$state" == "ENABLED" ]]; then
    return 0
  else
    return 1
  fi
}

verify_api_policy() {
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

verify_step() {
  local label="$1"
  local fn="$2"
  info "Verifying $label"
  if "$fn"; then
    VERIFICATION_RESULTS+=("$label|OK")
    info "Verification passed: $label"
  else
    VERIFICATION_RESULTS+=("$label|FAILED")
    warn "Verification failed: $label"
  fi
}

print_verification_summary() {
  printf '\n[remediate] Verification Summary\n'
  printf '------------------------------------------------------------\n'
  printf '| %-55s | %-6s |\n' 'Control' 'Status'
  printf '------------------------------------------------------------\n'
  local entry
  for entry in "${VERIFICATION_RESULTS[@]}"; do
    IFS='|' read -r label status <<<"$entry"
    printf '| %-55s | %-6s |\n' "$label" "$status"
  done
  printf '------------------------------------------------------------\n'

  local has_fail=0
  for entry in "${VERIFICATION_RESULTS[@]}"; do
    IFS='|' read -r _ status <<<"$entry"
    if [[ "$status" == "FAILED" ]]; then
      has_fail=1
      break
    fi
  done

  if (( has_fail )); then
    printf '[remediate][error] Verification detected unresolved controls. Review the summary above.\n' >&2
    exit 1
  fi
}

main() {
  require_state
  check_aws_cli_version
  info "Using state file $STATE_FILE"

  while IFS='=' read -r key value; do
    export "$key"="$value"
  done < <(STATE_FILE="$STATE_FILE" load_state)

  ensure_kms_policy
  ensure_s3_encryption
  ensure_dynamodb_encryption
  ensure_dynamodb_endpoint
  repair_s3_endpoint
  repair_lambda_environment
  enable_eventbridge_rule
  repair_api_policy

  verify_step "KMS policy grants LabRole encrypt/decrypt" verify_kms_policy
  verify_step "S3 bucket default SSE-KMS configuration" verify_s3_encryption
  verify_step "S3 bucket governance tags present" verify_s3_tags
  verify_step "DynamoDB table uses customer-managed CMK" verify_dynamodb_sse
  verify_step "DynamoDB point-in-time recovery enabled" verify_dynamodb_pitr
  verify_step "DynamoDB Gateway endpoint attached to VPC" verify_dynamodb_endpoint
  verify_step "S3 Gateway endpoint associated with route table" verify_s3_endpoint_routes
  verify_step "Lambda environment configured with correct table name" verify_lambda_env
  verify_step "EventBridge heartbeat rule enabled" verify_event_rule
  verify_step "API Gateway policy targets execute-api endpoint" verify_api_policy

  print_verification_summary
  info "Remediation complete."
}

main "$@"
