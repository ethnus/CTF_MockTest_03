#!/usr/bin/env bash

set -euo pipefail
export AWS_PAGER=""

# Teardown script for the Serverless Resiliency Lab.
# Uses the state file emitted by init.sh to delete lab resources.

STATE_FILE="${STATE_FILE:-state/serverless-lab-state.json}"
PROJECT_NAME="serverless-resiliency-lab"
KEEP_STATE=0
vpc_still_exists=0

usage() {
  cat <<'USAGE'
Usage: bash teardown.sh [--keep-state]

Deletes all lab resources recorded in the state file.

Options:
  --keep-state   Preserve the state file after teardown (default removes it).
USAGE
}

info() {
  printf '[teardown] %s\n' "$1"
}

warn() {
  printf '[teardown][warn] %s\n' "$1" >&2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    warn "Required command '$1' is not available in PATH."
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-state)
      KEEP_STATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      warn "Unrecognized option: $1"
      usage
      exit 1
      ;;
  esac
done

require_command aws
require_command python3

if [[ ! -f "$STATE_FILE" ]]; then
  warn "State file not found at $STATE_FILE. Attempting backup recovery."
  # Try to restore from backup location used by init.sh
  REGION_HINT="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
  ACCOUNT_HINT="$(aws sts get-caller-identity --query 'Account' --output text 2>/dev/null || true)"
  if [[ -n "$REGION_HINT" && -n "$ACCOUNT_HINT" ]]; then
    BAK_DIR="${HOME}/.lab-state/serverless-resiliency-lab/${ACCOUNT_HINT}-${REGION_HINT}"
    if [[ -f "$BAK_DIR/serverless-lab-state.json" ]]; then
      mkdir -p "$(dirname "$STATE_FILE")"
      cp "$BAK_DIR/serverless-lab-state.json" "$STATE_FILE"
      info "Recovered state from $BAK_DIR/serverless-lab-state.json"
    else
      warn "No backup state found at $BAK_DIR. Use: bash scripts/rebuild-state.sh"
      exit 1
    fi
  else
    warn "Region/account unknown. Set AWS_REGION and re-run or use: bash scripts/rebuild-state.sh"
    exit 1
  fi
fi

exports=""
if ! exports="$(STATE_FILE="$STATE_FILE" python3 - <<'PY'
import json
import os
import shlex
import sys

state_path = os.environ.get("STATE_FILE")
if not state_path:
    sys.exit(1)
with open(state_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

for key, value in data.items():
    print(f'export {key}={shlex.quote(str(value))}')
PY
)"; then
  warn "Failed to read or parse state from $STATE_FILE. Aborting."
  exit 1
fi
eval "$exports"

Region="${Region:-${AWS_REGION:-${AWS_DEFAULT_REGION:-}}}"

if [[ -z "${Region:-}" ]]; then
  warn "Region could not be determined from state or environment."
  exit 1
fi

export AWS_REGION="$Region"
export AWS_DEFAULT_REGION="$Region"

delete_eventbridge() {
  if [[ -z "${EventRuleName:-}" ]]; then
    return
  fi
  aws events remove-targets \
    --rule "$EventRuleName" \
    --ids lambda-target \
    --region "$Region" >/dev/null 2>&1 || warn "Failed to remove EventBridge targets (rule: $EventRuleName)"
  aws events delete-rule \
    --name "$EventRuleName" \
    --force \
    --region "$Region" >/dev/null 2>&1 || warn "Failed to delete EventBridge rule $EventRuleName"
}

delete_lambda() {
  if [[ -z "${LambdaArn:-}" ]]; then
    return
  fi
  local function_name
  function_name="${LambdaArn##*:function:}"
  aws lambda delete-function \
    --function-name "$function_name" \
    --region "$Region" >/dev/null 2>&1 || warn "Failed to delete Lambda function $function_name"
}

delete_api_gateway() {
  if [[ -z "${ApiId:-}" ]]; then
    return
  fi
  aws apigateway delete-rest-api \
    --rest-api-id "$ApiId" \
    --region "$Region" >/dev/null 2>&1 || warn "Failed to delete API Gateway REST API $ApiId"
}

delete_dynamodb_table() {
  if [[ -z "${DynamoTableName:-}" ]]; then
    return
  fi
  aws dynamodb delete-table \
    --table-name "$DynamoTableName" \
    --region "$Region" >/dev/null 2>&1 || warn "Failed to delete DynamoDB table $DynamoTableName"
}

empty_and_delete_bucket() {
  if [[ -z "${S3BucketName:-}" ]]; then
    return
  fi
  aws s3 rb "s3://${S3BucketName}" --force >/dev/null 2>&1 || warn "Failed to empty and delete S3 bucket ${S3BucketName}"
}

delete_vpc_endpoints() {
  local ids=()
  if [[ -n "${S3EndpointId:-}" ]]; then
    ids+=("$S3EndpointId")
  fi
  if [[ -n "${ExecuteApiEndpointId:-}" ]]; then
    ids+=("$ExecuteApiEndpointId")
  fi
  if [[ ${#ids[@]} -eq 0 ]]; then
    return
  fi
  aws ec2 delete-vpc-endpoints \
    --vpc-endpoint-ids "${ids[@]}" \
    --region "$Region" >/dev/null 2>&1 || warn "Failed to delete VPC endpoints: ${ids[*]}"
}

# Best-effort cleanup of residual ENIs that can block subnet/SG/VPC deletion
delete_residual_enis() {
  if [[ -z "${VpcId:-}" ]]; then
    return
  fi
  local enis eni attach
  enis="$(aws ec2 describe-network-interfaces \
    --filters Name=vpc-id,Values="$VpcId" \
    --region "$Region" \
    --query 'NetworkInterfaces[].NetworkInterfaceId' \
    --output text 2>/dev/null || true)"
  if [[ -z "$enis" || "$enis" == "None" ]]; then
    return
  fi
  for eni in $enis; do
    attach="$(aws ec2 describe-network-interfaces \
      --network-interface-ids "$eni" \
      --region "$Region" \
      --query 'NetworkInterfaces[0].Attachment.AttachmentId' \
      --output text 2>/dev/null || true)"
    if [[ -n "$attach" && "$attach" != "None" ]]; then
      aws ec2 detach-network-interface --attachment-id "$attach" --force --region "$Region" >/dev/null 2>&1 || true
      sleep 2
    fi
    aws ec2 delete-network-interface --network-interface-id "$eni" --region "$Region" >/dev/null 2>&1 || warn "Failed to delete ENI $eni"
  done
}

delete_networking() {
  # Residual ENIs (from Lambda VPC config or interface endpoints) can block delete
  delete_residual_enis
  if [[ -n "${RouteTableId:-}" ]]; then
    local assoc_id
    assoc_id="$(
      aws ec2 describe-route-tables \
        --route-table-ids "$RouteTableId" \
        --region "$Region" \
        --query 'RouteTables[0].Associations[?Main==`false`].RouteTableAssociationId' \
        --output text 2>/dev/null || true
    )"
    if [[ -n "$assoc_id" && "$assoc_id" != "None" ]]; then
      aws ec2 disassociate-route-table \
        --association-id "$assoc_id" \
        --region "$Region" >/dev/null 2>&1 || warn "Failed to disassociate route table $RouteTableId"
    fi
    aws ec2 delete-route-table \
      --route-table-id "$RouteTableId" \
      --region "$Region" >/dev/null 2>&1 || warn "Failed to delete route table $RouteTableId"
  fi

  if [[ -n "${SubnetId:-}" ]]; then
    aws ec2 delete-subnet \
      --subnet-id "$SubnetId" \
      --region "$Region" >/dev/null 2>&1 || warn "Failed to delete subnet $SubnetId"
  fi

  if [[ -n "${SecurityGroupId:-}" ]]; then
    aws ec2 delete-security-group \
      --group-id "$SecurityGroupId" \
      --region "$Region" >/dev/null 2>&1 || warn "Failed to delete security group $SecurityGroupId"
  fi

  if [[ -n "${VpcId:-}" ]]; then
    if ! aws ec2 delete-vpc --vpc-id "$VpcId" --region "$Region" >/dev/null 2>&1; then
      warn "Failed to delete VPC $VpcId"
      vpc_still_exists=1
    fi
  fi
}

cleanup_kms() {
  if [[ -n "${KmsKeyId:-}" ]]; then
    aws kms schedule-key-deletion \
      --key-id "$KmsKeyId" \
      --pending-window-in-days 7 \
      --region "$Region" >/dev/null 2>&1 || warn "Failed to schedule deletion for KMS key $KmsKeyId (may already be scheduled)"
  fi
  aws kms delete-alias \
    --alias-name "alias/${PROJECT_NAME}" \
    --region "$Region" >/dev/null 2>&1 || true
}

info "Starting teardown using state file $STATE_FILE"

delete_eventbridge
delete_api_gateway
delete_lambda
delete_dynamodb_table
empty_and_delete_bucket
delete_vpc_endpoints
delete_networking
cleanup_kms

# If VPC still exists, force retaining state for safe follow-up cleanup
if (( vpc_still_exists )); then
  KEEP_STATE=1
  warn "VPC still present; retaining state file for manual cleanup or retry."
fi

if [[ $KEEP_STATE -eq 0 ]]; then
  rm -f "$STATE_FILE"
  info "Removed state file $STATE_FILE"
else
  info "State file retained at $STATE_FILE"
fi

info "Teardown complete."
