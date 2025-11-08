#!/usr/bin/env bash

set -euo pipefail
export AWS_PAGER=""

# Regenerates state/serverless-lab-state.json by discovering lab resources in AWS.
# Useful when init.sh succeeded previously but the state file was deleted or lost.

STATE_FILE="${STATE_FILE:-state/serverless-lab-state.json}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
LAB_ROLE_NAME="${LAB_ROLE_NAME:-LabRole}"
PROJECT_NAME="serverless-resiliency-lab"
PROJECT_TAG_KEY="Project"
PROJECT_TAG_VALUE="ServerlessLab"

info() {
  printf '[rebuild-state] %s\n' "$1"
}

warn() {
  printf '[rebuild-state][warn] %s\n' "$1" >&2
}

error() {
  printf '[rebuild-state][error] %s\n' "$1" >&2
  exit 1
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    error "Required command '$1' not found in PATH."
  fi
}

check_prereqs() {
  require_command aws
  require_command python3
}

discover_resources() {
  info "Discovering resources for project $PROJECT_NAME in region $REGION"

  ACCOUNT_ID="$(aws sts get-caller-identity --query 'Account' --output text)"
  if [[ -z "$ACCOUNT_ID" ]]; then
    error "Unable to determine AWS account ID."
  fi

  KMS_KEY_ID="$(aws kms list-aliases \
    --region "$REGION" \
    --query "Aliases[?AliasName=='alias/${PROJECT_NAME}'].TargetKeyId" \
    --output text)"
  if [[ -z "$KMS_KEY_ID" || "$KMS_KEY_ID" == "None" ]]; then
    info "KMS alias alias/${PROJECT_NAME} not found; attempting fallback discovery."
    # Try to discover from DynamoDB SSE
    DYNAMO_TABLE_NAME_FALLBACK="${PROJECT_NAME}-telemetry"
    DDB_KMS_ARN="$(aws dynamodb describe-table \
      --table-name "$DYNAMO_TABLE_NAME_FALLBACK" \
      --region "$REGION" \
      --query 'Table.SSEDescription.KMSMasterKeyArn' \
      --output text 2>/dev/null || true)"
    if [[ -n "$DDB_KMS_ARN" && "$DDB_KMS_ARN" != "None" ]]; then
      KMS_KEY_ARN="$DDB_KMS_ARN"
      KMS_KEY_ID="$(aws kms describe-key --key-id "$KMS_KEY_ARN" --region "$REGION" --query 'KeyMetadata.KeyId' --output text)"
    else
      # Try to discover from S3 bucket default encryption
      S3_BUCKET_NAME_FALLBACK="${PROJECT_NAME}-bucket-${ACCOUNT_ID}-${REGION}"
      S3_KMS_ID="$(aws s3api get-bucket-encryption --bucket "$S3_BUCKET_NAME_FALLBACK" --region "$REGION" \
        --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID' \
        --output text 2>/dev/null || true)"
      if [[ -n "$S3_KMS_ID" && "$S3_KMS_ID" != "None" ]]; then
        # describe-key accepts key-id, ARN, alias, or alias ARN
        KMS_KEY_ID="$(aws kms describe-key --key-id "$S3_KMS_ID" --region "$REGION" --query 'KeyMetadata.KeyId' --output text)"
        KMS_KEY_ARN="$(aws kms describe-key --key-id "$S3_KMS_ID" --region "$REGION" --query 'KeyMetadata.Arn' --output text)"
      fi
    fi
    if [[ -z "${KMS_KEY_ID:-}" || "$KMS_KEY_ID" == "None" ]]; then
      # Last resort: search for a CMK tagged with Project=ServerlessLab
      CANDIDATES="$(aws kms list-keys --region "$REGION" --query 'Keys[].KeyId' --output text 2>/dev/null || true)"
      for kid in $CANDIDATES; do
        if aws kms list-resource-tags --key-id "$kid" --region "$REGION" \
          --query "Tags[?TagKey=='${PROJECT_TAG_KEY}' && TagValue=='${PROJECT_TAG_VALUE}'] | length(@)" \
          --output text 2>/dev/null | grep -q '^[1-9]'; then
          KMS_KEY_ID="$kid"
          KMS_KEY_ARN="$(aws kms describe-key --key-id "$kid" --region "$REGION" --query 'KeyMetadata.Arn' --output text 2>/dev/null || true)"
          break
        fi
      done
    fi
    if [[ -z "${KMS_KEY_ID:-}" || "$KMS_KEY_ID" == "None" ]]; then
      warn "KMS key not found. Continuing without KMS; teardown will skip key cleanup."
    else
      # Optionally re-create the expected alias to restore consistency
      aws kms create-alias --alias-name "alias/${PROJECT_NAME}" --target-key-id "$KMS_KEY_ID" --region "$REGION" >/dev/null 2>&1 || true
    fi
  else
    KMS_KEY_ARN="$(aws kms describe-key --key-id "$KMS_KEY_ID" --region "$REGION" --query 'KeyMetadata.Arn' --output text)"
  fi

  S3_BUCKET_NAME="${PROJECT_NAME}-bucket-${ACCOUNT_ID}-${REGION}"
  if ! aws s3api head-bucket --bucket "$S3_BUCKET_NAME" >/dev/null 2>&1; then
    warn "S3 bucket $S3_BUCKET_NAME not found."
    S3_BUCKET_NAME=""
  fi

  DYNAMO_TABLE_NAME="${PROJECT_NAME}-telemetry"
  if ! aws dynamodb describe-table --table-name "$DYNAMO_TABLE_NAME" --region "$REGION" >/dev/null 2>&1; then
    warn "DynamoDB table $DYNAMO_TABLE_NAME not found."
    DYNAMO_TABLE_NAME=""
  fi

  VPC_ID="$(aws ec2 describe-vpcs \
    --region "$REGION" \
    --filters "Name=tag:${PROJECT_TAG_KEY},Values=${PROJECT_TAG_VALUE}" \
    --query 'Vpcs[0].VpcId' \
    --output text)"
  if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
    warn "VPC for project tag ${PROJECT_TAG_KEY}=${PROJECT_TAG_VALUE} not found."
    VPC_ID=""
  fi

  SUBNET_ID=""
  ROUTE_TABLE_ID=""
  SECURITY_GROUP_ID=""
  S3_ENDPOINT_ID=""
  EXEC_API_ENDPOINT_ID=""
  if [[ -n "$VPC_ID" ]]; then
    SUBNET_ID="$(aws ec2 describe-subnets \
      --region "$REGION" \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=${PROJECT_NAME}-private-subnet-a" \
      --query 'Subnets[0].SubnetId' \
      --output text 2>/dev/null || true)"
    if [[ -z "$SUBNET_ID" || "$SUBNET_ID" == "None" ]]; then
      warn "Private subnet for the lab not found."
      SUBNET_ID=""
    fi

    ROUTE_TABLE_ID="$(aws ec2 describe-route-tables \
      --region "$REGION" \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=${PROJECT_NAME}-private-rt" \
      --query 'RouteTables[0].RouteTableId' \
      --output text 2>/dev/null || true)"
    if [[ -z "$ROUTE_TABLE_ID" || "$ROUTE_TABLE_ID" == "None" ]]; then
      warn "Route table ${PROJECT_NAME}-private-rt not found."
      ROUTE_TABLE_ID=""
    fi

    SECURITY_GROUP_ID="$(aws ec2 describe-security-groups \
      --region "$REGION" \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=${PROJECT_NAME}-lambda-sg" \
      --query 'SecurityGroups[0].GroupId' \
      --output text 2>/dev/null || true)"
    if [[ -z "$SECURITY_GROUP_ID" || "$SECURITY_GROUP_ID" == "None" ]]; then
      warn "Lambda security group ${PROJECT_NAME}-lambda-sg not found."
      SECURITY_GROUP_ID=""
    fi

    S3_ENDPOINT_ID="$(aws ec2 describe-vpc-endpoints \
      --region "$REGION" \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.${REGION}.s3" \
      --query 'VpcEndpoints[0].VpcEndpointId' \
      --output text 2>/dev/null || true)"
    if [[ -z "$S3_ENDPOINT_ID" || "$S3_ENDPOINT_ID" == "None" ]]; then
      warn "S3 gateway endpoint not found."
      S3_ENDPOINT_ID=""
    fi

    EXEC_API_ENDPOINT_ID="$(aws ec2 describe-vpc-endpoints \
      --region "$REGION" \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.${REGION}.execute-api" \
      --query 'VpcEndpoints[0].VpcEndpointId' \
      --output text 2>/dev/null || true)"
    if [[ -z "$EXEC_API_ENDPOINT_ID" || "$EXEC_API_ENDPOINT_ID" == "None" ]]; then
      warn "Execute-API interface endpoint not found."
      EXEC_API_ENDPOINT_ID=""
    fi
  fi

  LAMBDA_ARN="$(aws lambda get-function \
    --function-name "${PROJECT_NAME}-writer" \
    --region "$REGION" \
    --query 'Configuration.FunctionArn' \
    --output text 2>/dev/null || true)"
  if [[ -z "$LAMBDA_ARN" || "$LAMBDA_ARN" == "None" ]]; then
    warn "Lambda function ${PROJECT_NAME}-writer not found."
    LAMBDA_ARN=""
  fi

  API_ID="$(aws apigateway get-rest-apis \
    --region "$REGION" \
    --query "items[?name=='${PROJECT_NAME}-private-api'].id" \
    --output text 2>/dev/null || true)"
  if [[ -z "$API_ID" || "$API_ID" == "None" ]]; then
    warn "API Gateway REST API ${PROJECT_NAME}-private-api not found."
    API_ID=""
  fi

  API_STAGE="v1"
  DEPLOYMENT_ID=""
  if [[ -n "$API_ID" ]]; then
    DEPLOYMENT_ID="$(aws apigateway get-deployments \
      --rest-api-id "$API_ID" \
      --region "$REGION" \
      --query 'items[0].id' \
      --output text 2>/dev/null || true)"
    if [[ -z "$DEPLOYMENT_ID" || "$DEPLOYMENT_ID" == "None" ]]; then
      warn "Unable to determine deployment ID for API $API_ID."
      DEPLOYMENT_ID=""
    fi
  fi

  EVENT_RULE_NAME="${PROJECT_NAME}-ingest-heartbeat"
  if ! aws events describe-rule --name "$EVENT_RULE_NAME" --region "$REGION" >/dev/null 2>&1; then
    warn "EventBridge rule $EVENT_RULE_NAME not found."
    EVENT_RULE_NAME=""
  fi
}

write_state() {
  mkdir -p "$(dirname "$STATE_FILE")"
  cat >"$STATE_FILE" <<EOF
{
  "Region": "$REGION",
  "AccountId": "$ACCOUNT_ID",
  "KmsKeyId": "$KMS_KEY_ID",
  "KmsKeyArn": "$KMS_KEY_ARN",
  "S3BucketName": "$S3_BUCKET_NAME",
  "DynamoTableName": "$DYNAMO_TABLE_NAME",
  "VpcId": "$VPC_ID",
  "SubnetId": "$SUBNET_ID",
  "RouteTableId": "$ROUTE_TABLE_ID",
  "SecurityGroupId": "$SECURITY_GROUP_ID",
  "S3EndpointId": "$S3_ENDPOINT_ID",
  "ExecuteApiEndpointId": "$EXEC_API_ENDPOINT_ID",
  "LambdaArn": "$LAMBDA_ARN",
  "ApiId": "$API_ID",
  "ApiStage": "$API_STAGE",
  "EventRuleName": "$EVENT_RULE_NAME",
  "LabRoleName": "$LAB_ROLE_NAME",
  "DeploymentId": "$DEPLOYMENT_ID"
}
EOF
  info "State file rebuilt at $STATE_FILE"

  # Also persist a backup copy like init.sh for resilience
  local bak_dir
  bak_dir="${HOME}/.lab-state/serverless-resiliency-lab/${ACCOUNT_ID}-${REGION}"
  mkdir -p "$bak_dir"
  cp "$STATE_FILE" "$bak_dir/serverless-lab-state.json"
  info "Backup saved to $bak_dir/serverless-lab-state.json"
}

main() {
  check_prereqs

  if [[ -f "$STATE_FILE" ]]; then
    error "State file already exists at $STATE_FILE. Remove it before rebuilding."
  fi

  discover_resources
  write_state
}

main "$@"
