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

info() {
  printf '[remediate] %s\n' "$1"
}

warn() {
  printf '[remediate][warn] %s\n' "$1"
}

require_state() {
  if [[ ! -f "$STATE_FILE" ]]; then
    printf '[remediate][error] State file not found at %s. Run init.sh first.\n' "$STATE_FILE" >&2
    exit 1
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
  if [[ "$major" != "3" ]]; then
    printf '[remediate][error] AWS CLI v3 required. Detected %s.\n' "$version" >&2
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
  local policy_json
  policy_json="$(aws kms get-key-policy --key-id "$KmsKeyId" --policy-name default --region "$Region")"
  updated_policy="$(printf '%s' "$policy_json" | python3 - "$AccountId" "$LabRoleName" <<'PY'
import json
import sys

policy = json.loads(sys.stdin.read())
account_id = sys.argv[1]
role_name = sys.argv[2]

principal_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

statement = {
    "Sid": "AllowLabRoleUsage",
    "Effect": "Allow",
    "Principal": {"AWS": principal_arn},
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

statements = policy.get("Statement", [])

def normalize_stmt(stmt):
    return stmt.get("Sid"), stmt.get("Principal"), sorted(
        stmt.get("Action", []) if isinstance(stmt.get("Action"), list) else [stmt.get("Action")]
    )

target_sid = statement["Sid"]
existing = None
for idx, stmt in enumerate(statements):
    if stmt.get("Sid") == target_sid:
        existing = idx
        break

if existing is not None:
    statements[existing] = statement
else:
    statements.append(statement)

policy["Statement"] = statements
print(json.dumps(policy))
PY
)"

  aws kms put-key-policy \
    --key-id "$KmsKeyId" \
    --policy-name default \
    --policy "$updated_policy" \
    --region "$Region" >/dev/null
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

ensure_dynamodb_encryption() {
  info "Aligning DynamoDB table encryption and backups"
  aws dynamodb update-table \
    --table-name "$DynamoTableName" \
    --sse-specification "Enabled=true,SSEType=KMS,KMSMasterKeyId=$KmsKeyArn" \
    --region "$Region" >/dev/null

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

main() {
  require_state
  check_aws_cli_version

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

  info "Remediation complete."
}

main "$@"
