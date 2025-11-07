#!/usr/bin/env bash
# User-facing evaluator (neutral) with table output
# Usage: PREFIX=ethnus-mocktest-01 REGION=us-east-1 bash eval.sh
set -uo pipefail
export AWS_PAGER=""

# --- Configuration ---
PREFIX="${PREFIX:-ethnus-mocktest-01}"
REGION="${REGION:-us-east-1}"

# --- Prerequisite check ---
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required. Install jq and rerun." >&2
  exit 2
fi

# --- AWS Configuration ---
aws configure set region "$REGION" >/dev/null 2>&1 || true
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "unknown")"
PARTITION="$(aws sts get-caller-identity --query Arn --output text 2>/dev/null | awk -F: '{print $2}')"
if [ "$ACCOUNT_ID" = "unknown" ]; then
  echo "Error: Unable to determine AWS Account ID. Please configure your AWS credentials." >&2
  exit 1
fi

# --- Table Formatting Utilities ---
rows=()
add_row(){ rows+=("$1|$2|$3|$4"); }
pad(){ local txt="$1" w="$2"; local len=${#txt}; if [ "$len" -ge "$w" ]; then echo -n "$txt"; else local fill=$((w-len)); printf "%s%*s" "$txt" $fill ""; fi; }
rule(){ printf "%s\n" "$(printf '%0.s-' $(seq 1 "$1"))"; }

# --- Infrastructure Validation ---
check_infrastructure() {
  local bucket_count ddb_table lambda_count
  bucket_count=$(aws s3api list-buckets --query "length(Buckets[?starts_with(Name, '${PREFIX}-') && contains(Name, 'data')])" --output text 2>/dev/null || echo "0")
  ddb_table=$(aws dynamodb describe-table --table-name "${PREFIX}-orders" --query "Table.TableName" --output text 2>/dev/null || echo "")
  lambda_count=$(aws lambda list-functions --query "length(Functions[?starts_with(FunctionName, '${PREFIX}-')])" --output text 2>/dev/null || echo "0")
  
  if [ "$bucket_count" = "0" ] || [ -z "$ddb_table" ] || [ "$lambda_count" -lt "2" ]; then
    echo ""
    echo "❌ ERROR: Infrastructure not found"
    echo "Please deploy the infrastructure first using: bash deploy.sh"
    echo "If deployment failed, try cleanup and redeploy: bash teardown.sh && bash deploy.sh"
    echo ""
    exit 1
  fi
}

# --- Resource Locators ---
s3_bucket_by_prefix() {
  aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' | grep -E "^${PREFIX}-${ACCOUNT_ID}-[0-9]+-data$" | head -n1 || true
}
vpc_by_cidr_and_tag() {
  local cidr="$1"
  aws ec2 describe-vpcs --filters "Name=tag:Challenge,Values=${PREFIX}" --query 'Vpcs[].[VpcId,CidrBlock]' --output text 2>/dev/null | awk -v C="$cidr" '$2==C{print $1; exit}'
}

# State management for ephemeral environments like AWS CloudShell
# This ensures Terraform state is persisted in the user's home directory,
# which survives CloudShell session restarts.
BAK_DIR="$HOME/.tfbak/CTF_MockTest_01"
STATE_FILE="terraform.tfstate"
STATE_LOCK_FILE=".terraform.lock.hcl"

# Function to restore state from backup
restore_state() {
  # Only restore if terraform has been initialized or if forced
  if [ -d "$BAK_DIR" ] && [ -f "$BAK_DIR/$STATE_FILE" ]; then
    echo "Restoring Terraform state from $BAK_DIR..."
    if [ -d ".terraform" ] || [ "$1" == "force" ]; then
        cp "$BAK_DIR/$STATE_FILE"* . 2>/dev/null
        if [ -f "$BAK_DIR/$STATE_LOCK_FILE" ]; then
            cp "$BAK_DIR/$STATE_LOCK_FILE" .
        fi
        echo "Restore complete."
    else
        echo "Skipping restore: .terraform directory not found. Run deploy first."
    fi
  fi
}

# Function to backup state
backup_state() {
  if [ -f "$STATE_FILE" ]; then
    echo "Backing up Terraform state to $BAK_DIR..."
    mkdir -p "$BAK_DIR"
    cp "$STATE_FILE"* "$BAK_DIR/" 2>/dev/null
    if [ -f "$STATE_LOCK_FILE" ]; then
        cp "$STATE_LOCK_FILE" "$BAK_DIR/"
    fi
    echo "Backup complete."
  fi
}

# Function to remove backup
remove_backup() {
  if [ -d "$BAK_DIR" ]; then
    echo "Removing Terraform state backup from $BAK_DIR..."
    rm -rf "$BAK_DIR"
    echo "Backup removed."
  fi
}

restore_state

# --- Main Execution ---
check_infrastructure

# --- Gather Resource Identifiers ---
BUCKET="$(s3_bucket_by_prefix)"
DDB_TABLE="${PREFIX}-orders"
WRITER="${PREFIX}-writer"
READER="${PREFIX}-reader"
TOPIC_ARN="$(aws sns list-topics --query "Topics[?contains(TopicArn, ':${PREFIX}-topic')].TopicArn|[0]" --output text 2>/dev/null || echo "None")"
VPC_A_ID="$(vpc_by_cidr_and_tag 10.10.0.0/16)"
RTA_MAIN="$(aws ec2 describe-route-tables --filters Name=vpc-id,Values="$VPC_A_ID" Name=association.main,Values=true --query 'RouteTables[0].RouteTableId' --output text 2>/dev/null || echo None)"
VPCE_JSON="$(aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values="$VPC_A_ID" --output json 2>/dev/null || echo '{}')"
VPCE_S3_ID="$(echo "$VPCE_JSON" | jq -r '.VpcEndpoints[]? | select(.ServiceName|endswith(".s3")) | .VpcEndpointId' | head -n1)"
VPCE_DDB_ID="$(echo "$VPCE_JSON" | jq -r '.VpcEndpoints[]? | select(.ServiceName|endswith(".dynamodb")) | .VpcEndpointId' | head -n1)"
VPCE_EXEC_ID="$(echo "$VPCE_JSON" | jq -r '.VpcEndpoints[]? | select(.ServiceName|endswith(".execute-api")) | .VpcEndpointId' | head -n1)"
API_ID="$(aws apigateway get-rest-apis --query "items[?name=='${PREFIX}-api'].id|[0]" --output text 2>/dev/null || echo None)"
API_JSON="{}"; API_RESOURCES_JSON="{}"; POLICY_JSON=""
if [ "$API_ID" != "None" ]; then
  API_JSON="$(aws apigateway get-rest-api --rest-api-id "$API_ID" --output json 2>/dev/null || echo '{}')"
  POLICY_JSON="$(echo "$API_JSON" | jq -c '(.policy // empty) | select(.!="") | fromjson' 2>/dev/null || echo "")"
  API_RESOURCES_JSON="$(aws apigateway get-resources --rest-api-id "$API_ID" --output json 2>/dev/null || echo '{}')"
fi

# --- Evaluation Header ---
echo "evaluation"
printf " account : %s\n" "$ACCOUNT_ID"
printf " region  : %s\n" "$REGION"
printf " prefix  : %s\n" "$PREFIX"
rule 91
printf "| %s | %s | %s | %s |\n" "$(pad "#" 2)" "$(pad "Check" 44)" "$(pad "Status" 12)" "$(pad "Note" 23)"
rule 91

# --- Challenge Evaluation ---
ACCEPTED=0; INCOMPLETE=0; i=1

# 1) Tags: object storage
ST="INCOMPLETE"; NOTE="tags"
if [ -n "${BUCKET:-}" ]; then
  if TAGS_JSON="$(aws s3api get-bucket-tagging --bucket "$BUCKET" --output json 2>/dev/null)"; then
    has_owner=$(echo "$TAGS_JSON" | jq -r '.TagSet[]? | select(.Key=="Owner" and .Value=="Ethnus") | length')
    has_chal=$(echo "$TAGS_JSON" | jq -r '.TagSet[]? | select(.Key=="Challenge" and .Value=="'"$PREFIX"'") | length')
    if [ "${has_owner:-0}" -gt 0 ] && [ "${has_chal:-0}" -gt 0 ]; then ST="ACCEPTED"; NOTE="ok"; fi
  fi
fi
add_row "$i" "Resource governance: storage" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 2) Tags: key-value database
ST="INCOMPLETE"; NOTE="table"
DDB_ARN="arn:${PARTITION:-aws}:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DDB_TABLE}"
if aws dynamodb describe-table --table-name "$DDB_TABLE" >/dev/null 2>&1; then
  NOTE="tags"
  if TJSON="$(aws dynamodb list-tags-of-resource --resource-arn "$DDB_ARN" --output json 2>/dev/null)"; then
    has_owner=$(echo "$TJSON" | jq -r '.Tags[]? | select(.Key=="Owner" and .Value=="Ethnus") | length')
    has_chal=$(echo "$TJSON" | jq -r '.Tags[]? | select(.Key=="Challenge" and .Value=="'"$PREFIX"'") | length')
    if [ "${has_owner:-0}" -gt 0 ] && [ "${has_chal:-0}" -gt 0 ]; then ST="ACCEPTED"; NOTE="ok"; fi
  fi
fi
add_row "$i" "Resource governance: database" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 3) Compute concurrency
ST="INCOMPLETE"; NOTE="function"
if aws lambda get-function --function-name "$WRITER" >/dev/null 2>&1; then
  RC="$(aws lambda get-function-concurrency --function-name "$WRITER" --query 'ReservedConcurrentExecutions' --output text 2>/dev/null || echo "UNSET")"
  if [ "$RC" = "0" ]; then NOTE="limit"; else ST="ACCEPTED"; NOTE="ok"; fi
fi
add_row "$i" "Performance optimization: compute" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 4) Compute configuration
ST="INCOMPLETE"; NOTE="function"
if aws lambda get-function --function-name "$WRITER" >/dev/null 2>&1; then
  WT="$(aws lambda get-function-configuration --function-name "$WRITER" --query 'Environment.Variables.DDB_TABLE' --output text 2>/dev/null || echo "")"
  if [ "$WT" = "${DDB_TABLE}" ]; then ST="ACCEPTED"; NOTE="ok"; else NOTE="env"; fi
fi
add_row "$i" "Application configuration: runtime" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 5) Notifications publish
ST="INCOMPLETE"; NOTE="publish"
if [ "$TOPIC_ARN" != "None" ]; then
  if aws sns publish --topic-arn "$TOPIC_ARN" --message '{"probe":"ok"}' >/dev/null 2>&1; then
    ST="ACCEPTED"; NOTE="ok"
  fi
fi
add_row "$i" "Communication services: publish" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 6) Private data endpoint policy
ST="INCOMPLETE"; NOTE="endpoint"
if [ -n "${VPCE_DDB_ID:-}" ]; then
  PJSON="$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$VPCE_DDB_ID" --query 'VpcEndpoints[0].PolicyDocument' --output text 2>/dev/null || echo '')"
  NOTE="policy"
  if [ -n "$PJSON" ] && echo "$PJSON" | jq -e '([.Statement[]? | select(.Effect=="Allow") | .Action] | flatten | map(tostring) | any(.=="dynamodb:PutItem" or .=="dynamodb:*"))' >/dev/null 2>&1; then
    ST="ACCEPTED"; NOTE="ok"
  fi
fi
add_row "$i" "Network security: data access" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 7) Network endpoints routing
ST="INCOMPLETE"; NOTE="routing"
okmain=0
if [ -n "${VPCE_S3_ID:-}" ] && [ "$RTA_MAIN" != "None" ] && [ -n "${VPCE_DDB_ID:-}" ]; then
  S3_RT_OK=$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$VPCE_S3_ID" --query "VpcEndpoints[0].RouteTableIds[?@=='$RTA_MAIN']" --output text)
  DDB_RT_OK=$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$VPCE_DDB_ID" --query "VpcEndpoints[0].RouteTableIds[?@=='$RTA_MAIN']" --output text)
  if [ -n "$S3_RT_OK" ] && [ -n "$DDB_RT_OK" ]; then okmain=1; fi
fi
[ $okmain -eq 1 ] && { ST="ACCEPTED"; NOTE="ok"; }
add_row "$i" "Network routing: service access" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 8) API integration
ST="INCOMPLETE"; NOTE="api"
if [ "$API_ID" != "None" ]; then
  RES_ORDERS_ID="$(echo "$API_RESOURCES_JSON" | jq -r '.items[]? | select(.path=="/orders") | .id' 2>/dev/null | head -n1)"
  NOTE="resource"
  if [ -n "$RES_ORDERS_ID" ]; then
    INTEG_URI="$(aws apigateway get-integration --rest-api-id "$API_ID" --resource-id "$RES_ORDERS_ID" --http-method GET --query 'uri' --output text 2>/dev/null || echo "")"
    READER_ARN="$(aws lambda get-function --function-name "$READER" --query 'Configuration.FunctionArn' --output text 2>/dev/null || echo "")"
    NOTE="integration"
    if [ -n "$INTEG_URI" ] && [ -n "$READER_ARN" ] && echo "$INTEG_URI" | grep -q "$READER_ARN"; then ST="ACCEPTED"; NOTE="ok"; fi
  fi
fi
add_row "$i" "API service: backend integration" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 9) API network restrictions
ST="INCOMPLETE"; NOTE="api"
if [ "$API_ID" != "None" ]; then
  NOTE="policy"
  TYPES="$(echo "$API_JSON" | jq -r '.endpointConfiguration.types[]?' 2>/dev/null)"
  priv_ok=0; match_ok=0
  echo "$TYPES" | grep -qx "PRIVATE" && priv_ok=1
  if [ -n "$VPCE_EXEC_ID" ] && [ -n "$POLICY_JSON" ]; then
    SRC="$(echo "$POLICY_JSON" | jq -r '.Statement[]? | .Condition?."StringEquals"?."aws:SourceVpce"? // empty' 2>/dev/null | head -n1)"
    [ "$SRC" = "$VPCE_EXEC_ID" ] && match_ok=1
  fi
  if [ $priv_ok -eq 1 ] && [ $match_ok -eq 1 ]; then ST="ACCEPTED"; NOTE="ok"; fi
fi
add_row "$i" "API security: access restrictions" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 10) Scheduled invocation
ST="INCOMPLETE"; NOTE="rule"
RULE="${PREFIX}-tick"
if aws events describe-rule --name "$RULE" >/dev/null 2>&1; then
  STT="$(aws events describe-rule --name "$RULE" --query 'State' --output text 2>/dev/null || echo "")"
  NOTE="state"
  if [ "$STT" = "ENABLED" ]; then ST="ACCEPTED"; NOTE="ok"; fi
fi
add_row "$i" "Process automation: scheduling" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 11) Compute integration test
ST="INCOMPLETE"; NOTE="function"
if aws lambda get-function --function-name "$WRITER" >/dev/null 2>&1; then
  OUT="$(aws lambda invoke --function-name "$WRITER" --payload '{}' --cli-binary-format raw-in-base64-out /dev/stdout 2>/dev/null || echo '{}')"
  NOTE="invoke"
  if echo "$OUT" | jq -e '.' >/dev/null 2>&1; then
    ddb_ok="$(echo "$OUT" | jq -r '.ddb_ok // empty')"
    s3_ok="$(echo "$OUT" | jq -r '.s3_ok // empty')"
    sns_ok="$(echo "$OUT" | jq -r '.sns_ok // empty')"
    NOTE="io"
    if [ "$ddb_ok" = "true" ] && [ "$s3_ok" = "true" ] && [ "$sns_ok" = "true" ]; then ST="ACCEPTED"; NOTE="ok"; fi
  fi
fi
add_row "$i" "System integration: end-to-end" "$ST" "$NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# 12) Final flag
ST="INCOMPLETE"; FLAG_NOTE=""
if [ "$API_ID" != "None" ]; then
  RES_ORDERS_ID="$(echo "$API_RESOURCES_JSON" | jq -r '.items[]? | select(.path=="/orders") | .id' 2>/dev/null | head -n1)"
  if [ -n "$RES_ORDERS_ID" ]; then
    TRES="$(aws apigateway test-invoke-method --rest-api-id "$API_ID" --resource-id "$RES_ORDERS_ID" --http-method GET --output json 2>/dev/null || echo '{}')"
    STATUS="$(echo "$TRES" | jq -r '.status // empty' 2>/dev/null || echo '')"
    BODY="$(echo "$TRES" | jq -r '.body // empty' 2>/dev/null || echo '')"
    if [ "$STATUS" = "200" ] && [[ "$BODY" =~ ^\{ ]]; then
        FLAG="$(echo "$BODY" | jq -r '.flag // empty' 2>/dev/null || echo '')"
        if [ -n "$FLAG" ]; then ST="ACCEPTED"; FLAG_NOTE="$FLAG"; fi
    fi
  fi
fi
add_row "$i" "Service delivery: final verification" "$ST" "$FLAG_NOTE"; [ "$ST" = "ACCEPTED" ] && ACCEPTED=$((ACCEPTED+1)) || INCOMPLETE=$((INCOMPLETE+1)); i=$((i+1))

# --- Print Results ---
for r in "${rows[@]}"; do
  IFS="|" read -r c1 c2 c3 c4 <<<"$r"
  printf "| %s | %s | %s | %s |\n" "$(pad "$c1" 2)" "$(pad "$c2" 44)" "$(pad "$c3" 12)" "$(pad "$c4" 23)"
done
rule 91
printf "ACCEPTED   : %s\n" "$ACCEPTED"
printf "INCOMPLETE : %s\n" "$INCOMPLETE"

exit "$INCOMPLETE"
