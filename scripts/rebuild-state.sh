#!/usr/bin/env bash

set -euo pipefail

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
    error "Could not locate KMS key alias alias/${PROJECT_NAME}."
  fi
  KMS_KEY_ARN="$(aws kms describe-key --key-id "$KMS_KEY_ID" --region "$REGION" --query 'KeyMetadata.Arn' --output text)"

  S3_BUCKET_NAME="${PROJECT_NAME}-bucket-${ACCOUNT_ID}-${REGION}"
  if ! aws s3api head-bucket --bucket "$S3_BUCKET_NAME" >/dev/null 2>&1; then
    error "Expected S3 bucket $S3_BUCKET_NAME not found."
  fi

  DYNAMO_TABLE_NAME="${PROJECT_NAME}-telemetry"
  if ! aws dynamodb describe-table --table-name "$DYNAMO_TABLE_NAME" --region "$REGION" >/dev/null 2>&1; then
    error "Expected DynamoDB table $DYNAMO_TABLE_NAME not found."
  fi

  VPC_ID="$(aws ec2 describe-vpcs \
    --region "$REGION" \
    --filters "Name=tag:${PROJECT_TAG_KEY},Values=${PROJECT_TAG_VALUE}" \
    --query 'Vpcs[0].VpcId' \
    --output text)"
  if [[ -z "$VPC_ID" || "$VPC_ID" == "None" ]]; then
    error "VPC tagged Name=${PROJECT_NAME}-vpc not found."
  fi

  SUBNET_ID="$(aws ec2 describe-subnets \
    --region "$REGION" \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=${PROJECT_NAME}-private-subnet-a" \
    --query 'Subnets[0].SubnetId' \
    --output text)"
  if [[ -z "$SUBNET_ID" || "$SUBNET_ID" == "None" ]]; then
    error "Private subnet for the lab not found."
  fi

  ROUTE_TABLE_ID="$(aws ec2 describe-route-tables \
    --region "$REGION" \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=${PROJECT_NAME}-private-rt" \
    --query 'RouteTables[0].RouteTableId' \
    --output text)"
  if [[ -z "$ROUTE_TABLE_ID" || "$ROUTE_TABLE_ID" == "None" ]]; then
    error "Route table ${PROJECT_NAME}-private-rt not found."
  fi

  SECURITY_GROUP_ID="$(aws ec2 describe-security-groups \
    --region "$REGION" \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=${PROJECT_NAME}-lambda-sg" \
    --query 'SecurityGroups[0].GroupId' \
    --output text)"
  if [[ -z "$SECURITY_GROUP_ID" || "$SECURITY_GROUP_ID" == "None" ]]; then
    error "Lambda security group ${PROJECT_NAME}-lambda-sg not found."
  fi

  S3_ENDPOINT_ID="$(aws ec2 describe-vpc-endpoints \
    --region "$REGION" \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.${REGION}.s3" \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text)"
  if [[ -z "$S3_ENDPOINT_ID" || "$S3_ENDPOINT_ID" == "None" ]]; then
    error "S3 gateway endpoint not found."
  fi

  EXEC_API_ENDPOINT_ID="$(aws ec2 describe-vpc-endpoints \
    --region "$REGION" \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=service-name,Values=com.amazonaws.${REGION}.execute-api" \
    --query 'VpcEndpoints[0].VpcEndpointId' \
    --output text)"
  if [[ -z "$EXEC_API_ENDPOINT_ID" || "$EXEC_API_ENDPOINT_ID" == "None" ]]; then
    error "Execute-API interface endpoint not found."
  fi

  LAMBDA_ARN="$(aws lambda get-function \
    --function-name "${PROJECT_NAME}-writer" \
    --region "$REGION" \
    --query 'Configuration.FunctionArn' \
    --output text)"
  if [[ -z "$LAMBDA_ARN" || "$LAMBDA_ARN" == "None" ]]; then
    error "Lambda function ${PROJECT_NAME}-writer not found."
  fi

  API_ID="$(aws apigateway get-rest-apis \
    --region "$REGION" \
    --query "items[?name=='${PROJECT_NAME}-private-api'].id" \
    --output text)"
  if [[ -z "$API_ID" || "$API_ID" == "None" ]]; then
    error "API Gateway REST API ${PROJECT_NAME}-private-api not found."
  fi

  API_STAGE="v1"
  DEPLOYMENT_ID="$(aws apigateway get-deployments \
    --rest-api-id "$API_ID" \
    --region "$REGION" \
    --query 'items[0].id' \
    --output text)"
  if [[ -z "$DEPLOYMENT_ID" || "$DEPLOYMENT_ID" == "None" ]]; then
    error "Unable to determine deployment ID for API $API_ID."
  fi

  EVENT_RULE_NAME="${PROJECT_NAME}-ingest-heartbeat"
  if ! aws events describe-rule --name "$EVENT_RULE_NAME" --region "$REGION" >/dev/null 2>&1; then
    error "EventBridge rule $EVENT_RULE_NAME not found."
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
