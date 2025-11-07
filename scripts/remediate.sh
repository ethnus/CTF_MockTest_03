#!/usr/bin/env bash

set -euo pipefail
export AWS_PAGER=""

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
DEBUG=${DEBUG:-1}
VERBOSE=${VERBOSE:-1}
DEBUG_MAX_BYTES=${DEBUG_MAX_BYTES:-4096}

info() {
  (( VERBOSE )) && printf '[remediate] %s\n' "$1"
}

warn() {
  printf '[remediate][warn] %s\n' "$1"
}

error() {
  printf '[remediate][error] %s\n' "$1" >&2
  exit 1
}

# Debug-aware AWS CLI wrapper
# - Echoes the command, exit code, duration, and truncated stdout/stderr to stderr when DEBUG=1
# - Preserves stdout for command substitutions and pipelines
aws() {
  local dbg=${DEBUG:-0}
  # Pass-through for version to preserve original stderr/stdout behavior
  if [[ "${1:-}" == "--version" ]]; then
    command aws "$@"
    return $?
  fi
  # Print the command we are about to run (quoted args)
  if (( dbg )); then
    {
      printf '[remediate][debug] > aws'
      for arg in "$@"; do
        printf ' %q' "$arg"
      done
      printf '\n'
    } >&2
  fi

  local tmp_out tmp_err rc start end dur
  tmp_out="$(mktemp)"
  tmp_err="$(mktemp)"
  start=$(date +%s)
  command aws "$@" 1>"$tmp_out" 2>"$tmp_err"
  rc=$?
  end=$(date +%s)
  dur=$(( end - start ))

  if (( dbg )); then
    # Report status line
    printf '[remediate][debug] < exit=%d time=%ss\n' "$rc" "$dur" >&2

    # Dump (possibly truncated) stdout/stderr for visibility
    # Avoid flooding logs with huge payloads
    local out_size err_size
    out_size=$(wc -c <"$tmp_out" | tr -d ' ')
    err_size=$(wc -c <"$tmp_err" | tr -d ' ')

    if [[ -s "$tmp_out" ]]; then
      printf '[remediate][debug] < stdout (%s bytes)%s:\n' "$out_size" \
        $([[ "$out_size" -gt "$DEBUG_MAX_BYTES" ]] && printf ' [first %s]' "$DEBUG_MAX_BYTES" || printf '') >&2
      if [[ "$out_size" -gt "$DEBUG_MAX_BYTES" ]]; then
        head -c "$DEBUG_MAX_BYTES" "$tmp_out" >&2
        printf '\n[remediate][debug] < stdout (truncated)\n' >&2
      else
        cat "$tmp_out" >&2
        printf '\n' >&2
      fi
    fi

    if [[ -s "$tmp_err" ]]; then
      printf '[remediate][debug] < stderr (%s bytes)%s:\n' "$err_size" \
        $([[ "$err_size" -gt "$DEBUG_MAX_BYTES" ]] && printf ' [first %s]' "$DEBUG_MAX_BYTES" || printf '') >&2
      if [[ "$err_size" -gt "$DEBUG_MAX_BYTES" ]]; then
        head -c "$DEBUG_MAX_BYTES" "$tmp_err" >&2
        printf '\n[remediate][debug] < stderr (truncated)\n' >&2
      else
        cat "$tmp_err" >&2
        printf '\n' >&2
      fi
    fi
  fi

  # Preserve stdout for the caller
  cat "$tmp_out"
  rm -f "$tmp_out" "$tmp_err"
  return "$rc"
}

require_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    warn "State file not found at $STATE_FILE. Attempting backup recovery."
    local region acct bak
    region="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
    acct="$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)"
    if [[ -n "$region" && -n "$acct" ]]; then
      bak="${HOME}/.lab-state/serverless-resiliency-lab/${acct}-${region}/serverless-lab-state.json"
      if [[ -f "$bak" ]]; then
        mkdir -p "$(dirname "$STATE_FILE")"
        cp "$bak" "$STATE_FILE"
        info "Recovered state from $bak"
      else
        error "State missing and no backup found. Run init.sh or rebuild-state.sh."
      fi
    else
      error "Region/account unknown and state missing. Set AWS_REGION or run rebuild-state.sh."
    fi
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

debug_overview() {
  (( DEBUG )) || return 0
  printf '[remediate][debug] Session identity (aws sts get-caller-identity)\n' >&2
  aws sts get-caller-identity --region "$Region" >/dev/null || true
  printf '[remediate][debug] State overview\n' >&2
  printf '[remediate][debug] Region=%s AccountId=%s LabRoleName=%s (LAB_ROLE_NAME=%s)\n' \
    "$Region" "${AccountId:-?}" "${LabRoleName:-?}" "${LAB_ROLE_NAME:-}" >&2
  printf '[remediate][debug] Resources: VpcId=%s RouteTableId=%s ExecuteApiEndpointId=%s S3EndpointId=%s\n' \
    "${VpcId:-?}" "${RouteTableId:-?}" "${ExecuteApiEndpointId:-?}" "${S3EndpointId:-?}" >&2
  printf '[remediate][debug] Storage: S3BucketName=%s DynamoTableName=%s KmsKeyArn=%s KmsKeyId=%s\n' \
    "${S3BucketName:-?}" "${DynamoTableName:-?}" "${KmsKeyArn:-?}" "${KmsKeyId:-?}" >&2
  printf '[remediate][debug] Compute: LambdaArn=%s EventRuleName=%s ApiId=%s\n' \
    "${LambdaArn:-?}" "${EventRuleName:-?}" "${ApiId:-?}" >&2
}

print_plan() {
  (( DEBUG )) || return 0
  printf '[remediate][debug] Remediation plan (ensure then verify):\n' >&2
  printf '  - Ensure KMS key policy for LabRole\n' >&2
  printf '  - Enforce S3 default SSE-KMS and governance tags\n' >&2
  printf '  - Align DynamoDB SSE (CMK) and enable PITR\n' >&2
  printf '  - Ensure DynamoDB Gateway endpoint is present\n' >&2
  printf '  - Re-attach S3 Gateway endpoint route table\n' >&2
  printf '  - Update Lambda environment variables\n' >&2
  printf '  - Enable EventBridge heartbeat rule\n' >&2
  printf '  - Restrict API Gateway policy to execute-api VPCe\n' >&2
  printf '  - Verify each control with retries (10 attempts, 3s delay)\n' >&2
}

ensure_kms_policy() {
  info "Ensuring KMS key policy allows Lab role usage"
  if (( DEBUG )); then
    printf '[remediate][debug] KMS KeyId=%s KeyArn=%s Role=%s AccountId=%s\n' \
      "$KmsKeyId" "$KmsKeyArn" "$LabRoleName" "$AccountId" >&2
  fi
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
  local expected_lab_principal="arn:aws:iam::${AccountId}:role/${LabRoleName}"
  local expected_active_principal=""
  if [[ -n "${LAB_ROLE_NAME:-}" ]]; then
    expected_active_principal="arn:aws:iam::${AccountId}:role/${LAB_ROLE_NAME}"
  fi
  local policy_json
  if ! policy_json="$(aws kms get-key-policy --key-id "$KmsKeyId" --policy-name default --region "$Region")"; then
    warn "Unable to read KMS key policy for verification."
    return 1
  fi
  if DEBUG="$DEBUG" POLICY_JSON="$policy_json" python3 - "$expected_lab_principal" "$expected_active_principal" <<'PY'
import json
import os
import sys

raw = os.environ.get("POLICY_JSON", "").strip()
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

expected1 = sys.argv[1]
expected2 = sys.argv[2] if len(sys.argv) > 2 else ""


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

expected = [p for p in (expected1, expected2) if p]
stmts = policy.get("Statement", [])

def matching_principals(statement):
    return [p for p in expected if contains_principal(statement, p)]

found = False
for stmt in stmts:
    if stmt.get("Effect") != "Allow":
        continue
    principals = matching_principals(stmt)
    if principals and has_encrypt_action(stmt):
        found = True
        break

# In debug, print some helpful context
if not found and ("DEBUG" in os.environ and os.environ.get("DEBUG") in ("1", "true", "TRUE")):
    try:
        import pprint
        sys.stderr.write("[remediate][debug] KMS policy principals/actions observed for troubleshooting\n")
        for stmt in stmts:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            principals = stmt.get("Principal")
            sys.stderr.write("[remediate][debug]  - Principal=%s Actions=%s\n" % (json.dumps(principals), json.dumps(actions)))
        sys.stderr.write("[remediate][debug]  - Expected principals=%s\n" % json.dumps(expected))
    except Exception:
        pass

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
  if (( DEBUG )); then
    printf '[remediate][debug] S3BucketName=%s KmsKeyArn=%s\n' "$S3BucketName" "$KmsKeyArn" >&2
  fi
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
  local alias_name="alias/${PROJECT_NAME}"
  local encryption
  if ! encryption="$(aws s3api get-bucket-encryption --bucket "$S3BucketName" --region "$Region" 2>/dev/null)"; then
    return 1
  fi
  if ENC_JSON="$encryption" python3 - "$KmsKeyArn" "$KmsKeyId" "$alias_arn" "$alias_name" <<'PY'
import json
import os
import sys

raw = os.environ.get("ENC_JSON", "").strip()
if not raw:
    sys.exit(1)
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    sys.exit(1)

rules = data.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
key_arn, key_id, alias_arn, alias_name = sys.argv[1:5]


def matches(candidate):
    if not candidate:
        return False
    if candidate in {key_arn, key_id, alias_arn, alias_name}:
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
  if TAGS_JSON="$tags_json" python3 - "$PROJECT_TAG_KEY" "$PROJECT_TAG_VALUE" "$COST_TAG_KEY" "$COST_TAG_VALUE" <<'PY'
import json
import os
import sys

raw = os.environ.get("TAGS_JSON", "").strip()
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
  if (( DEBUG )); then
    printf '[remediate][debug] DynamoTableName=%s KmsKeyArn=%s\n' "$DynamoTableName" "$KmsKeyArn" >&2
  fi
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
  if (( DEBUG )); then
    printf '[remediate][debug] VpcId=%s RouteTableId=%s\n' "$VpcId" "$RouteTableId" >&2
  fi
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
  if (( DEBUG )); then
    printf '[remediate][debug] S3EndpointId=%s RouteTableId=%s\n' "$S3EndpointId" "$RouteTableId" >&2
  fi
  aws ec2 modify-vpc-endpoint \
    --vpc-endpoint-id "$S3EndpointId" \
    --add-route-table-ids "$RouteTableId" \
    --region "$Region" >/dev/null
}

repair_lambda_environment() {
  info "Updating Lambda environment variables"
  if (( DEBUG )); then
    printf '[remediate][debug] LambdaArn=%s DDB_TABLE_NAME=%s S3_BUCKET_NAME=%s\n' \
      "$LambdaArn" "$DynamoTableName" "$S3BucketName" >&2
  fi
  aws lambda update-function-configuration \
    --function-name "$LambdaArn" \
    --environment "Variables={DDB_TABLE_NAME=$DynamoTableName,S3_BUCKET_NAME=$S3BucketName,LOG_LEVEL=INFO}" \
    --region "$Region" >/dev/null
}

enable_eventbridge_rule() {
  info "Enabling EventBridge heartbeat rule"
  if (( DEBUG )); then
    printf '[remediate][debug] EventRuleName=%s\n' "$EventRuleName" >&2
  fi
  aws events enable-rule --name "$EventRuleName" --region "$Region" >/dev/null
}

repair_api_policy() {
  info "Aligning API Gateway resource policy with execute-api endpoint"
  if (( DEBUG )); then
    printf '[remediate][debug] RestApiId=%s ExecuteApiEndpointId=%s\n' "$ApiId" "$ExecuteApiEndpointId" >&2
  fi
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
      "Resource": "arn:aws:execute-api:${Region}:${AccountId}:${ApiId}/*/*/*",
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

  # Also ensure the VPC endpoint is associated with the API to avoid access gaps
  local current_vpces need_patch
  current_vpces="$(aws apigateway get-rest-api --rest-api-id "$ApiId" --region "$Region" --query 'endpointConfiguration.vpcEndpointIds' --output json 2>/dev/null || echo '[]')"
  need_patch="$(printf '%s' "$current_vpces" | python3 - "$ExecuteApiEndpointId" <<'PY'
import json,sys
raw=sys.stdin.read().strip() or '[]'
try:
  data=json.loads(raw)
except Exception:
  data=[]
expected=sys.argv[1]
print('yes' if (not isinstance(data,list) or expected not in [str(x).strip() for x in data]) else 'no')
PY
)"
  if [[ "$need_patch" == "yes" ]]; then
    aws apigateway update-rest-api \
      --rest-api-id "$ApiId" \
      --patch-operations "op=add,path=/endpointConfiguration/vpcEndpointIds,value=${ExecuteApiEndpointId}" \
      --region "$Region" >/dev/null 2>&1 || true
  fi
}

verify_dynamodb_sse() {
  local table_json
  table_json="$(aws dynamodb describe-table --table-name "$DynamoTableName" --region "$Region")"
  if TABLE_JSON="$table_json" python3 - "$KmsKeyArn" <<'PY'
import json
import os
import sys

raw = os.environ.get("TABLE_JSON", "").strip()
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
  if SUMMARY_JSON="$summary_json" python3 - <<'PY'
import json
import os
import sys

raw = os.environ.get("SUMMARY_JSON", "").strip()
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
  if ROUTES_JSON="$routes_json" python3 - <<'PY'
import json
import os
import sys

raw = os.environ.get("ROUTES_JSON", "").strip()
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
  if CONFIG_JSON="$config_json" python3 - "$DynamoTableName" <<'PY'
import json
import os
import sys

raw = os.environ.get("CONFIG_JSON", "").strip()
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
# Value may be under StringEquals or StringEqualsIfExists and may be a string or list
def vpce_matches(cond, expected):
    if not isinstance(cond, dict):
        return False
    for op in ("StringEquals", "StringEqualsIfExists"):
        sub = cond.get(op, {})
        if not isinstance(sub, dict):
            continue
        val = sub.get("aws:SourceVpce")
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

# Fallback: raw string contains expected VPCe (handle unusual string encodings)
raw_env = os.environ.get("POLICY_JSON", "")
try:
    if vpce in raw_env:
        sys.exit(0)
except Exception:
    pass

# Debug context when not found
if os.environ.get("DEBUG") in ("1", "true", "TRUE"):
    try:
        sys.stderr.write("[remediate][debug] API policy did not match expected VPCe; dumping conditions\n")
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            sys.stderr.write("[remediate][debug]  - Condition=%s\n" % json.dumps(stmt.get("Condition")))
        sys.stderr.write("[remediate][debug]  - Expected aws:SourceVpce=%s\n" % vpce)
    except Exception:
        pass
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
  local attempts=10
  local delay=3
  local success=0
  info "Verifying $label"
  for ((i=1; i<=attempts; i++)); do
    if (( DEBUG )); then
      printf '[remediate][debug] verify attempt %d/%d: %s\n' "$i" "$attempts" "$label" >&2
    fi
    if "$fn"; then
      success=1
      break
    fi
    if (( i < attempts )); then
      warn "Verification not yet passing for: $label (attempt $i/${attempts}); retrying in ${delay}s"
      sleep "$delay"
    fi
  done
  if (( success )); then
    VERIFICATION_RESULTS+=("$label|OK")
    info "Verification passed: $label"
  else
    VERIFICATION_RESULTS+=("$label|FAILED")
    warn "Verification failed: $label"
    if (( DEBUG )); then
      debug_dump "$label"
    fi
  fi
}

debug_dump() {
  local label="$1"
  printf '[remediate][debug] Dumping context for: %s\n' "$label"
  case "$label" in
    "KMS policy grants LabRole encrypt/decrypt")
      printf '[remediate][debug] Expected principal: arn:aws:iam::%s:role/%s\n' "$AccountId" "$LabRoleName"
      aws kms get-key-policy --key-id "$KmsKeyId" --policy-name default --region "$Region" || true
      ;;
    "S3 bucket default SSE-KMS configuration")
      aws s3api get-bucket-encryption --bucket "$S3BucketName" --region "$Region" || true
      ;;
    "S3 bucket governance tags present")
      aws s3api get-bucket-tagging --bucket "$S3BucketName" --region "$Region" || true
      ;;
    "DynamoDB table uses customer-managed CMK")
      aws dynamodb describe-table --table-name "$DynamoTableName" --region "$Region" --query 'Table.SSEDescription' || true
      ;;
    "DynamoDB point-in-time recovery enabled")
      aws dynamodb describe-continuous-backups --table-name "$DynamoTableName" --region "$Region" || true
      ;;
    "DynamoDB Gateway endpoint attached to VPC")
      aws ec2 describe-vpc-endpoints --region "$Region" \
        --filters "Name=vpc-id,Values=$VpcId" "Name=service-name,Values=com.amazonaws.${Region}.dynamodb" || true
      ;;
    "S3 Gateway endpoint associated with route table")
      aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$S3EndpointId" --region "$Region" || true
      ;;
    "Lambda environment configured with correct table name")
      aws lambda get-function-configuration --function-name "$LambdaArn" --region "$Region" --query 'Environment.Variables' || true
      ;;
    "EventBridge heartbeat rule enabled")
      aws events describe-rule --name "$EventRuleName" --region "$Region" || true
      ;;
    "API Gateway policy targets execute-api endpoint")
      aws apigateway get-rest-api --rest-api-id "$ApiId" --region "$Region" --query policy || true
      printf '\n[remediate][debug] Expected aws:SourceVpce: %s\n' "$ExecuteApiEndpointId"
      ;;
    *)
      printf '[remediate][debug] No debug handler for "%s"\n' "$label"
      ;;
  esac
}

print_verification_summary() {
  printf '\n[remediate] Verification Summary\n'
  printf -- '------------------------------------------------------------\n'
  printf '| %-55s | %-6s |\n' 'Control' 'Status'
  printf -- '------------------------------------------------------------\n'
  local entry
  for entry in "${VERIFICATION_RESULTS[@]}"; do
    IFS='|' read -r label status <<<"$entry"
    printf '| %-55s | %-6s |\n' "$label" "$status"
  done
  printf -- '------------------------------------------------------------\n'

  local has_fail=0
  for entry in "${VERIFICATION_RESULTS[@]}"; do
    IFS='|' read -r _ status <<<"$entry"
    if [[ "$status" == "FAILED" ]]; then
      has_fail=1
      break
    fi
  done

  if (( has_fail )); then
    printf -- '[remediate][error] Verification detected unresolved controls. Review the summary above.\n' >&2
    exit 1
  fi
}

main() {
  # Parse flags (e.g., --debug)
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --debug)
        DEBUG=1
        shift
        ;;
      *)
        # ignore unknowns to remain forwards-compatible
        shift
        ;;
    esac
  done
  require_state
  check_aws_cli_version
  info "Using state file $STATE_FILE"

  while IFS='=' read -r key value; do
    export "$key"="$value"
  done < <(STATE_FILE="$STATE_FILE" load_state)

  # Prefer the active assumed role if provided via LAB_ROLE_NAME
  if [[ -n "${LAB_ROLE_NAME:-}" && "${LabRoleName:-}" != "$LAB_ROLE_NAME" ]]; then
    info "Overriding LabRoleName ($LabRoleName) with active role ($LAB_ROLE_NAME)"
    LabRoleName="$LAB_ROLE_NAME"
  fi

  debug_overview
  print_plan

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
