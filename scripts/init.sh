#!/usr/bin/env bash

set -euo pipefail
export AWS_PAGER=""
VERBOSE=${VERBOSE:-1}

# Bootstrap script for the Serverless Resiliency Lab.
# Deploys resources with intentional misconfigurations for troubleshooting practice.

STATE_FILE="${STATE_FILE:-state/serverless-lab-state.json}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
LAB_ROLE_NAME="${LAB_ROLE_NAME:-LabRole}"
PROJECT_NAME="serverless-resiliency-lab"
BUCKET_NAME="${PROJECT_NAME}-bucket"
TABLE_NAME="${PROJECT_NAME}-telemetry"
EVENT_RULE_NAME="${PROJECT_NAME}-ingest-heartbeat"
FUNCTION_NAME="${PROJECT_NAME}-writer"
API_NAME="${PROJECT_NAME}-private-api"
SG_NAME="${PROJECT_NAME}-lambda-sg"
VPC_NAME="${PROJECT_NAME}-vpc"
SUBNET_NAME="${PROJECT_NAME}-private-subnet-a"
ROUTE_TABLE_NAME="${PROJECT_NAME}-private-rt"
S3_ENDPOINT_NAME="${PROJECT_NAME}-s3-endpoint"
EXECUTE_API_ENDPOINT_NAME="${PROJECT_NAME}-executeapi-endpoint"
PROJECT_TAG_KEY="Project"
PROJECT_TAG_VALUE="ServerlessLab"
COST_TAG_KEY="CostCenter"
COST_TAG_VALUE="Training"

info() {
  (( VERBOSE )) && printf '[init] %s\n' "$1"
}

warn() {
  printf '[init][warn] %s\n' "$1" >&2
}

log_kv() {
  (( VERBOSE )) && printf '  - %s: %s\n' "$1" "$2"
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    warn "Required command '$1' is not available in PATH."
    exit 1
  fi
}

check_aws_cli_version() {
  local version major
  version="$(aws --version 2>&1 | awk '{print $1}' | cut -d/ -f2)"
  major="${version%%.*}"
  if [[ -z "$version" ]]; then
    warn "Unable to determine AWS CLI version."
    exit 1
  fi
  if ! [[ "$major" =~ ^[0-9]+$ ]]; then
    warn "Unrecognized AWS CLI version format: $version"
    exit 1
  fi
  if (( major < 2 )); then
    warn "AWS CLI v2 or later is required for this lab. Detected version $version."
    exit 1
  fi
  info "Detected AWS CLI version $version"
}

# Compute a consistent backup location for the state file so sessions can recover easily
state_backup_dir() {
  local account_id region
  account_id="$1"
  region="$2"
  printf '%s' "${HOME}/.lab-state/serverless-resiliency-lab/${account_id}-${region}"
}

preflight_conflicts() {
  # Detect partially-created resources from a prior run without state
  local account_id region bucket_name table_name api_name function_name conflicts=()
  account_id="$1"
  region="$2"
  bucket_name="$(printf "%s-%s-%s" "$BUCKET_NAME" "$account_id" "$region")"
  table_name="$TABLE_NAME"
  api_name="$API_NAME"
  function_name="$FUNCTION_NAME"

  if aws s3api head-bucket --bucket "$bucket_name" >/dev/null 2>&1; then
    conflicts+=("S3 bucket: $bucket_name")
  fi
  if aws dynamodb describe-table --table-name "$table_name" --region "$region" >/dev/null 2>&1; then
    conflicts+=("DynamoDB table: $table_name")
  fi
  if aws lambda get-function --function-name "$function_name" --region "$region" >/dev/null 2>&1; then
    conflicts+=("Lambda function: $function_name")
  fi
  if aws apigateway get-rest-apis --region "$region" --query "items[?name=='${api_name}'].id" --output text | grep -q .; then
    conflicts+=("API Gateway: $api_name")
  fi

  if ((${#conflicts[@]} > 0)); then
    warn "Found existing resources for this project with no state file:"
    local c
    for c in "${conflicts[@]}"; do
      warn " - $c"
    done
    warn "To proceed, either:"
    warn "  1) Rebuild state: bash scripts/rebuild-state.sh"
    warn "  2) Or tear down existing resources, then rerun: bash scripts/teardown.sh && bash scripts/init.sh"
    exit 1
  fi
}

main() {
  for cmd in aws zip; do
    require_command "$cmd"
  done

  check_aws_cli_version

  mkdir -p "$(dirname "$STATE_FILE")"

  if [[ -f "$STATE_FILE" ]]; then
    warn "Existing state file detected at $STATE_FILE. Remove it to redeploy from scratch."
    exit 1
  fi

  ACCOUNT_ID="$(aws sts get-caller-identity --query 'Account' --output text)"
  if [[ -z "$ACCOUNT_ID" ]]; then
    warn "Unable to determine AWS account. Check your AWS CLI configuration."
    exit 1
  fi

  info "Using AWS account $ACCOUNT_ID in region $REGION"

  if [[ "$REGION" != "us-east-1" && "$REGION" != "us-west-2" ]]; then
    warn "Region must be us-east-1 or us-west-2 for this lab."
    exit 1
  fi

  # Prevent duplicate deployments when state is missing but resources exist
  preflight_conflicts "$ACCOUNT_ID" "$REGION"

  local kms_key_id kms_key_arn bucket_name table_name vpc_id subnet_id route_table_id sg_id s3_endpoint_id api_vpce_id lambda_arn api_id api_root_id ingest_resource_id deployment_id

  info "Creating custom KMS key with restricted policy (intentional misconfiguration)"
  kms_key_id="$(aws kms create-key \
    --description "Serverless lab CMK (intentionally under-permissioned)" \
    --policy "$(kms_key_policy "$ACCOUNT_ID")" \
    --query 'KeyMetadata.KeyId' \
    --region "$REGION" \
    --output text)"

  kms_key_arn="$(aws kms describe-key --key-id "$kms_key_id" --region "$REGION" --query 'KeyMetadata.Arn' --output text)"
  log_kv "KMS KeyId" "$kms_key_id"
  log_kv "KMS KeyArn" "$kms_key_arn"

  info "Tagging KMS key"
  aws kms tag-resource \
    --key-id "$kms_key_id" \
    --tags "TagKey=$PROJECT_TAG_KEY,TagValue=$PROJECT_TAG_VALUE" \
    --region "$REGION" >/dev/null

  if ! aws kms list-aliases --region "$REGION" --query "Aliases[?AliasName=='alias/${PROJECT_NAME}'].AliasName" --output text | grep -q "alias/${PROJECT_NAME}"; then
    aws kms create-alias \
      --alias-name "alias/${PROJECT_NAME}" \
      --region "$REGION" \
      --target-key-id "$kms_key_id" >/dev/null
  fi

  info "Creating S3 bucket without required encryption or tags (intentional faults)"
  bucket_name="$(printf "%s-%s-%s" "$BUCKET_NAME" "$ACCOUNT_ID" "$REGION")"
  if [[ "$REGION" == "us-east-1" ]]; then
    aws s3api create-bucket --bucket "$bucket_name" --region "$REGION" >/dev/null
  else
    aws s3api create-bucket \
      --bucket "$bucket_name" \
      --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  fi

  info "Creating DynamoDB table with default encryption (intentional fault)"
  table_name="$TABLE_NAME"
  aws dynamodb create-table \
    --region "$REGION" \
    --table-name "$table_name" \
    --billing-mode PAY_PER_REQUEST \
    --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
    --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
    --sse-specification Enabled=true >/dev/null

  info "Creating VPC, subnet, and security group"
  vpc_id="$(aws ec2 create-vpc --cidr-block 10.20.0.0/24 --region "$REGION" --tag-specifications "ResourceType=vpc,Tags=[{Key=$PROJECT_TAG_KEY,Value=$PROJECT_TAG_VALUE}]" --query 'Vpc.VpcId' --output text)"
  aws ec2 modify-vpc-attribute --vpc-id "$vpc_id" --enable-dns-hostnames --region "$REGION" >/dev/null
  aws ec2 modify-vpc-attribute --vpc-id "$vpc_id" --enable-dns-support --region "$REGION" >/dev/null

  log_kv "VPC Id" "$vpc_id"
  subnet_id="$(aws ec2 create-subnet \
    --region "$REGION" \
    --vpc-id "$vpc_id" \
    --cidr-block 10.20.0.0/28 \
    --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=$SUBNET_NAME}]" \
    --query 'Subnet.SubnetId' \
    --output text)"

  log_kv "Subnet Id" "$subnet_id"
  route_table_id="$(aws ec2 create-route-table \
    --vpc-id "$vpc_id" \
    --region "$REGION" \
    --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=$ROUTE_TABLE_NAME}]" \
    --query 'RouteTable.RouteTableId' \
    --output text)"

  aws ec2 associate-route-table --route-table-id "$route_table_id" --subnet-id "$subnet_id" --region "$REGION" >/dev/null

  sg_id="$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "Lambda security group for serverless lab" \
    --vpc-id "$vpc_id" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=Name,Value=$SG_NAME}]" \
    --region "$REGION" \
    --query 'GroupId' \
    --output text)"

  if ! sg_authorize_output="$(aws ec2 authorize-security-group-egress \
    --group-id "$sg_id" \
    --ip-permissions '[{"IpProtocol":"-1","IpRanges":[{"CidrIp":"0.0.0.0/0"}]}]' \
    --region "$REGION" 2>&1)"; then
    if grep -q "InvalidPermission.Duplicate" <<<"$sg_authorize_output"; then
      warn "Security group $SG_NAME already has the expected egress rule; continuing."
    else
      warn "Failed to authorize security group egress: $sg_authorize_output"
      exit 1
    fi
  fi

  info "Provisioning S3 gateway endpoint with missing route table attachment (intentional fault)"
  s3_endpoint_id="$(aws ec2 create-vpc-endpoint \
    --region "$REGION" \
    --vpc-id "$vpc_id" \
    --service-name "com.amazonaws.${REGION}.s3" \
    --vpc-endpoint-type Gateway \
    --route-table-ids "$route_table_id" \
    --query 'VpcEndpoint.VpcEndpointId' \
    --output text)"

  aws ec2 modify-vpc-endpoint \
    --vpc-endpoint-id "$s3_endpoint_id" \
    --remove-route-table-ids "$route_table_id" \
    --region "$REGION" >/dev/null

  info "Provisioning interface endpoint for API Gateway invoke"
  api_vpce_id="$(aws ec2 create-vpc-endpoint \
    --region "$REGION" \
    --vpc-id "$vpc_id" \
    --service-name "com.amazonaws.${REGION}.execute-api" \
    --vpc-endpoint-type Interface \
    --subnet-ids "$subnet_id" \
    --security-group-ids "$sg_id" \
    --query 'VpcEndpoint.VpcEndpointId' \
    --output text)"

  info "Creating Lambda deployment package"
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT
  create_lambda_package "$tmp_dir"

  role_arn="arn:aws:iam::${ACCOUNT_ID}:role/${LAB_ROLE_NAME}"
  function_zip="${tmp_dir}/function.zip"
  lambda_handler="app.handler"

  info "Creating Lambda function with incorrect environment configuration (intentional fault)"
  if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" >/dev/null 2>&1; then
    warn "Lambda function $FUNCTION_NAME already exists; aborting to avoid clobbering."
    exit 1
  fi

  lambda_arn="$(aws lambda create-function \
    --function-name "$FUNCTION_NAME" \
    --runtime python3.11 \
    --handler "$lambda_handler" \
    --zip-file "fileb://${function_zip}" \
    --role "$role_arn" \
    --timeout 10 \
    --memory-size 256 \
    --vpc-config "SubnetIds=$subnet_id,SecurityGroupIds=$sg_id" \
    --environment "Variables={DDB_TABLE_NAME=${TABLE_NAME}y,S3_BUCKET_NAME=$bucket_name,LOG_LEVEL=INFO}" \
    --tags "$PROJECT_TAG_KEY=$PROJECT_TAG_VALUE" \
    --region "$REGION" \
    --query 'FunctionArn' \
    --output text)"

  info "Publishing EventBridge rule but leaving it disabled (intentional fault)"
  aws events put-rule \
    --name "$EVENT_RULE_NAME" \
    --schedule-expression "rate(10 minutes)" \
    --state DISABLED \
    --tags "Key=$PROJECT_TAG_KEY,Value=$PROJECT_TAG_VALUE" \
    --region "$REGION" >/dev/null

  aws events put-targets \
    --rule "$EVENT_RULE_NAME" \
    --targets "Id=lambda-target,Arn=$lambda_arn" \
    --region "$REGION" >/dev/null

  aws lambda add-permission \
    --function-name "$FUNCTION_NAME" \
    --statement-id "allow-events-${EVENT_RULE_NAME}" \
    --action "lambda:InvokeFunction" \
    --principal events.amazonaws.com \
    --source-arn "$(aws events describe-rule --name "$EVENT_RULE_NAME" --region "$REGION" --query 'Arn' --output text)" \
    --region "$REGION" >/dev/null

  info "Creating private REST API with restrictive policy (intentional fault)"
  api_id="$(aws apigateway create-rest-api \
    --name "$API_NAME" \
    --endpoint-configuration "types=PRIVATE" \
    --region "$REGION" \
    --tags "$PROJECT_TAG_KEY=$PROJECT_TAG_VALUE" \
    --query 'id' \
    --output text)"

  log_kv "API Id" "$api_id"
  api_root_id="$(aws apigateway get-resources --rest-api-id "$api_id" --region "$REGION" --query 'items[0].id' --output text)"

  log_kv "API Root Resource Id" "$api_root_id"
  ingest_resource_id="$(aws apigateway create-resource \
    --rest-api-id "$api_id" \
    --parent-id "$api_root_id" \
    --path-part "ingest" \
    --region "$REGION" \
    --query 'id' \
    --output text)"

  aws apigateway put-method \
    --rest-api-id "$api_id" \
    --resource-id "$ingest_resource_id" \
    --http-method POST \
    --authorization-type "NONE" \
    --region "$REGION" >/dev/null

  aws apigateway put-integration \
    --rest-api-id "$api_id" \
    --resource-id "$ingest_resource_id" \
    --http-method POST \
    --type AWS_PROXY \
    --integration-http-method POST \
    --uri "arn:aws:apigateway:${REGION}:lambda:path/2015-03-31/functions/${lambda_arn}/invocations" \
    --region "$REGION" >/dev/null

  aws lambda add-permission \
    --function-name "$FUNCTION_NAME" \
    --statement-id "allow-apigw-${api_id}" \
    --action "lambda:InvokeFunction" \
    --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:${REGION}:${ACCOUNT_ID}:${api_id}/*/POST/ingest" \
    --region "$REGION" >/dev/null

  apply_misconfigured_api_policy "$api_id" "$ACCOUNT_ID" "$REGION"

  deployment_id="$(aws apigateway create-deployment \
    --rest-api-id "$api_id" \
    --stage-name "v1" \
    --region "$REGION" \
    --query 'id' \
    --output text)"

  cat >"$STATE_FILE" <<EOF
{
  "Region": "$REGION",
  "AccountId": "$ACCOUNT_ID",
  "KmsKeyId": "$kms_key_id",
  "KmsKeyArn": "$kms_key_arn",
  "S3BucketName": "$bucket_name",
  "DynamoTableName": "$table_name",
  "VpcId": "$vpc_id",
  "SubnetId": "$subnet_id",
  "RouteTableId": "$route_table_id",
  "SecurityGroupId": "$sg_id",
  "S3EndpointId": "$s3_endpoint_id",
  "ExecuteApiEndpointId": "$api_vpce_id",
  "LambdaArn": "$lambda_arn",
  "ApiId": "$api_id",
  "ApiStage": "v1",
  "EventRuleName": "$EVENT_RULE_NAME",
  "LabRoleName": "$LAB_ROLE_NAME",
  "DeploymentId": "$deployment_id"
}
EOF

  # Persist a backup copy of state outside the repo to survive workspace changes
  backup_dir="$(state_backup_dir "$ACCOUNT_ID" "$REGION")"
  mkdir -p "$backup_dir"
  cp "$STATE_FILE" "$backup_dir/serverless-lab-state.json"

  info "Bootstrap complete. Intentional faults deployed. State captured at $STATE_FILE"
  info "Backup saved to $backup_dir/serverless-lab-state.json"
  info "Next: run eval.sh to view failing checks."

  if (( VERBOSE )); then
    printf '[init] Resource summary:\n'
    log_kv "Region" "$REGION"
    log_kv "Account" "$ACCOUNT_ID"
    log_kv "KMS KeyId" "$kms_key_id"
    log_kv "S3 Bucket" "$bucket_name"
    log_kv "DynamoDB Table" "$table_name"
    log_kv "VPC Id" "$vpc_id"
    log_kv "Subnet Id" "$subnet_id"
    log_kv "Route Table Id" "$route_table_id"
    log_kv "S3 GW Endpoint" "$s3_endpoint_id"
    log_kv "Execute-API IF Endpoint" "$api_vpce_id"
    log_kv "Lambda Arn" "$lambda_arn"
    log_kv "API Id" "$api_id"
    log_kv "Deployment Id" "$deployment_id"
  fi
}

kms_key_policy() {
  local account_id="$1"
  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRootAccountAdministration",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${account_id}:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
EOF
}

create_lambda_package() {
  local build_dir="$1"
  cat <<'PY' > "${build_dir}/app.py"
import json
import os
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

_session = boto3.session.Session()
_dynamodb = _session.resource("dynamodb")
_s3 = _session.client("s3")


def handler(event, context):
    response = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "source_event": event,
        "status": "processing"
    }
    table_name = os.environ.get("DDB_TABLE_NAME")
    bucket_name = os.environ.get("S3_BUCKET_NAME")

    if not table_name or not bucket_name:
        response["status"] = "error"
        response["reason"] = "Missing environment configuration"
        return {
            "statusCode": 500,
            "body": json.dumps(response)
        }

    item = {
        "pk": f"context#{context.aws_request_id}",
        "sk": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "event": event,
        "collected_at": int(time.time())
    }

    try:
        _dynamodb.Table(table_name).put_item(Item=item)
        response["status"] = "dynamodb_write_ok"
    except ClientError as exc:
        response["status"] = "dynamodb_write_failed"
        response["reason"] = exc.response["Error"]["Message"]

    try:
        _s3.put_object(
            Bucket=bucket_name,
            Key=f"events/{context.aws_request_id}.json",
            Body=json.dumps(response).encode("utf-8"),
            ContentType="application/json"
        )
        response["s3_status"] = "object_written"
    except ClientError as exc:
        response["s3_status"] = "object_failed"
        response["s3_reason"] = exc.response["Error"]["Message"]

    return {
        "statusCode": 200,
        "body": json.dumps(response)
    }
PY

  (cd "$build_dir" && zip -q "function.zip" "app.py")
}

apply_misconfigured_api_policy() {
  local api_id="$1"
  local account_id="$2"
  local region="$3"
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
      "Resource": "arn:aws:execute-api:${region}:${account_id}:${api_id}/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceVpce": "vpce-00000000000000000"
        }
      }
    }
  ]
}
EOF

  aws apigateway update-rest-api \
    --rest-api-id "$api_id" \
    --patch-operations "[{\"op\":\"replace\",\"path\":\"/policy\",\"value\":\"$(tr -d '\n' <"$policy_file" | sed 's/\"/\\\"/g')\"}]" \
    --region "$region" >/dev/null

  rm -f "$policy_file"
}

main "$@"
  log_kv "S3 Bucket" "$bucket_name"
  log_kv "DynamoDB Table" "$table_name"
  log_kv "Route Table Id" "$route_table_id"
  log_kv "Security Group Id" "$sg_id"
  log_kv "S3 Gateway Endpoint Id" "$s3_endpoint_id"
  log_kv "Execute-API Interface Endpoint Id" "$api_vpce_id"
  log_kv "Lambda Arn" "$lambda_arn"
  log_kv "Ingest Resource Id" "$ingest_resource_id"
  log_kv "Deployment Id" "$deployment_id"
