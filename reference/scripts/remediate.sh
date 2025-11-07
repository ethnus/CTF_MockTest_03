#!/usr/bin/env bash
# Remediation helper to bring resources to a passing state for eval.sh (trainer use)
# Usage: PREFIX=ethnus-mocktest-01 REGION=us-east-1 bash remediate.sh
set -Eeuo pipefail
export AWS_PAGER=""

PREFIX="${PREFIX:-ethnus-mocktest-01}"
REGION="${REGION:-us-east-1}"

aws configure set region "$REGION" >/dev/null
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
PARTITION="$(aws sts get-caller-identity --query Arn --output text | awk -F: '{print $2}')"
LABROLE_ARN="arn:${PARTITION}:iam::${ACCOUNT_ID}:role/LabRole"

echo "remediate"
echo " account: $ACCOUNT_ID"
echo " region : $REGION"
echo " prefix : $PREFIX"

# ---- discovery ----
BUCKET="$(aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' | grep -E "^${PREFIX}-${ACCOUNT_ID}-[0-9]+-data$" | head -n1 || true)"
DDB_TABLE="${PREFIX}-orders"
DDB_ARN="arn:${PARTITION}:dynamodb:${REGION}:${ACCOUNT_ID}:table/${DDB_TABLE}"
WRITER="${PREFIX}-writer"
READER="${PREFIX}-reader"
TOPIC_ARN="$(aws sns list-topics --query "Topics[?contains(TopicArn, ':${PREFIX}-topic')].TopicArn|[0]" --output text 2>/dev/null || echo "None")"

VPC_A_ID="$(aws ec2 describe-vpcs --filters "Name=tag:Challenge,Values=${PREFIX}" --query 'Vpcs[?CidrBlock==`10.10.0.0/16`].VpcId|[0]' --output text 2>/dev/null || echo None)"
RTA_MAIN="$(aws ec2 describe-route-tables --filters Name=vpc-id,Values="$VPC_A_ID" Name=association.main,Values=true --query 'RouteTables[0].RouteTableId' --output text 2>/dev/null || echo None)"
VPCE_JSON="$(aws ec2 describe-vpc-endpoints --filters Name=vpc-id,Values="$VPC_A_ID" --output json 2>/dev/null || echo '{}')"
VPCE_S3_ID="$(echo "$VPCE_JSON" | jq -r '.VpcEndpoints[]? | select(.ServiceName|endswith(".s3")) | .VpcEndpointId' | head -n1)"
VPCE_DDB_ID="$(echo "$VPCE_JSON" | jq -r '.VpcEndpoints[]? | select(.ServiceName|endswith(".dynamodb")) | .VpcEndpointId' | head -n1)"
VPCE_EXEC_ID="$(echo "$VPCE_JSON" | jq -r '.VpcEndpoints[]? | select(.ServiceName|endswith(".execute-api")) | .VpcEndpointId' | head -n1)"
VPCE_KMS_ID="$(echo "$VPCE_JSON" | jq -r '.VpcEndpoints[]? | select(.ServiceName|endswith(".kms")) | .VpcEndpointId' | head -n1)"
VPCE_SNS_ID="$(echo "$VPCE_JSON" | jq -r '.VpcEndpoints[]? | select(.ServiceName|endswith(".sns")) | .VpcEndpointId' | head -n1)"
API_ID="$(aws apigateway get-rest-apis --query "items[?name=='${PREFIX}-api'].id|[0]" --output text 2>/dev/null || echo None)"
ROOT_ID="$(aws apigateway get-resources --rest-api-id "$API_ID" --query 'items[?path==`/`].id' --output text 2>/dev/null || echo '')"
SUBNETS_A="$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC_A_ID" --query 'Subnets[].SubnetId' --output text 2>/dev/null || true)"
SUB_A1="$(echo "$SUBNETS_A" | awk '{print $1}')"
SUB_A2="$(echo "$SUBNETS_A" | awk '{print $2}')"
VPCE_SG_ID="$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC_A_ID" Name=group-name,Values="${PREFIX}-vpce-sg" --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo None)"
KEY_ID="$(aws kms list-aliases --query "Aliases[?AliasName=='alias/${PREFIX}-cmk'].TargetKeyId|[0]" --output text 2>/dev/null || echo None)"

echo " - bucket         : ${BUCKET:-None}"
echo " - ddb table      : ${DDB_TABLE}"
echo " - writer         : ${WRITER}"
echo " - reader         : ${READER}"
echo " - sns topic      : ${TOPIC_ARN}"
echo " - vpc a          : ${VPC_A_ID}"
echo " - rtb main (a)   : ${RTA_MAIN}"
echo " - vpce s3/ddb    : ${VPCE_S3_ID} / ${VPCE_DDB_ID}"
echo " - vpce exec      : ${VPCE_EXEC_ID}"
echo " - vpce kms/sns   : ${VPCE_KMS_ID:-None} / ${VPCE_SNS_ID:-None}"
echo " - subnets a      : ${SUB_A1:-None} ${SUB_A2:-None}"
echo " - vpce sg        : ${VPCE_SG_ID:-None}"
echo " - api id         : ${API_ID}"
echo " - api root id    : ${ROOT_ID}"

# ---- 1) tags ----
if [ -n "${BUCKET:-}" ]; then
  aws s3api put-bucket-tagging --bucket "$BUCKET" --tagging "TagSet=[{Key=Owner,Value=Ethnus},{Key=Challenge,Value=${PREFIX}}]" >/dev/null
  echo " bucket tags set"
fi
if aws dynamodb describe-table --table-name "$DDB_TABLE" >/dev/null 2>&1; then
  aws dynamodb tag-resource --resource-arn "$DDB_ARN" --tags Key=Owner,Value=Ethnus Key=Challenge,Value="$PREFIX" >/dev/null 2>&1 || true
  echo " ddb table tags set"
fi

# ---- 2) lambda writer config ----
if aws lambda get-function --function-name "$WRITER" >/dev/null 2>&1; then
  aws lambda delete-function-concurrency --function-name "$WRITER" >/dev/null 2>&1 || true
  CFG="$(aws lambda get-function-configuration --function-name "$WRITER" --output json)"
  BUCKET_ENV="$(echo "$CFG" | jq -r '.Environment.Variables.BUCKET')"
  TOPIC_ENV="$(echo "$CFG" | jq -r '.Environment.Variables.TOPIC_ARN')"
  aws lambda update-function-configuration --function-name "$WRITER" \
    --timeout 15 --memory-size 256 \
    --environment "Variables={DDB_TABLE=${DDB_TABLE},BUCKET=${BUCKET_ENV},TOPIC_ARN=${TOPIC_ENV}}" >/dev/null
  echo " writer env/timeout/memory updated"
fi

# ---- 3) sns allow publish ----
if [ "$TOPIC_ARN" != "None" ]; then
  cat > /tmp/sns-allow.json <<JSON
{"Version":"2012-10-17","Statement":[
  {"Sid":"AllowOwnerPublish","Effect":"Allow","Principal":{"AWS":"*"},"Action":"sns:Publish","Resource":"${TOPIC_ARN}",
   "Condition":{"StringEquals":{"AWS:SourceOwner":"${ACCOUNT_ID}"}}}
]}
JSON
  aws sns set-topic-attributes --topic-arn "$TOPIC_ARN" --attribute-name Policy --attribute-value file:///tmp/sns-allow.json >/dev/null
  echo " sns policy updated"
fi

# ---- 4) kms grant for LabRole ----
if [ "$KEY_ID" != "None" ]; then
  aws kms create-grant --key-id "$KEY_ID" --grantee-principal "$LABROLE_ARN" \
    --operations Encrypt Decrypt GenerateDataKey >/dev/null 2>&1 || true
  echo " kms grant created for LabRole"
fi

# ---- 5) ddb gw endpoint policy ----
if [ -n "${VPCE_DDB_ID:-}" ]; then
  cat > /tmp/ddb-ep-policy.json <<'JSON'
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Principal":"*","Action":["dynamodb:*"],"Resource":"*"}
]}
JSON
  aws ec2 modify-vpc-endpoint --vpc-endpoint-id "$VPCE_DDB_ID" --policy-document file:///tmp/ddb-ep-policy.json >/dev/null
  echo " ddb endpoint policy updated"
fi

# ---- 6) gw endpoints -> main RT ----
if [ "$RTA_MAIN" != "None" ]; then
  for EID in "$VPCE_S3_ID" "$VPCE_DDB_ID"; do
    [ -z "$EID" ] && continue
    CUR=$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$EID" --query 'VpcEndpoints[0].RouteTableIds' --output text | tr '\t' '\n')
    REMOVE=""
    for R in $CUR; do [ "$R" != "$RTA_MAIN" ] && REMOVE="$REMOVE $R"; done
    aws ec2 modify-vpc-endpoint --vpc-endpoint-id "$EID" --add-route-table-ids "$RTA_MAIN" >/dev/null 2>&1 || true
    if [ -n "$REMOVE" ]; then aws ec2 modify-vpc-endpoint --vpc-endpoint-id "$EID" --remove-route-table-ids $REMOVE >/dev/null 2>&1 || true; fi
  done
  echo " gateway endpoints associated with main RT"
fi

# ---- 7) Interface endpoints for KMS/SNS ----
if [ "$VPCE_SG_ID" = "None" ]; then
  VPCE_SG_ID="$(aws ec2 create-security-group --group-name "${PREFIX}-vpce-sg" --description "vpce" --vpc-id "$VPC_A_ID" --query GroupId --output text)"
  aws ec2 authorize-security-group-ingress --group-id "$VPCE_SG_ID" --protocol -1 --cidr "10.10.0.0/16" >/dev/null 2>&1 || true
  aws ec2 authorize-security-group-egress --group-id "$VPCE_SG_ID" --protocol -1 --cidr "0.0.0.0/0" >/dev/null 2>&1 || true
fi
if [ -z "${VPCE_KMS_ID:-}" ] || [ "$VPCE_KMS_ID" = "None" ]; then
  if [ -n "${SUB_A1:-}" ] && [ -n "${SUB_A2:-}" ]; then
    VPCE_KMS_ID="$(aws ec2 create-vpc-endpoint --vpc-id "$VPC_A_ID" --service-name "com.amazonaws.${REGION}.kms" \
        --vpc-endpoint-type Interface --subnet-ids "$SUB_A1" "$SUB_A2" --security-group-ids "$VPCE_SG_ID" \
        --query VpcEndpoint.VpcEndpointId --output text)"
    echo " kms interface endpoint created: $VPCE_KMS_ID"
  fi
fi
if [ -z "${VPCE_SNS_ID:-}" ] || [ "$VPCE_SNS_ID" = "None" ]; then
  if [ -n "${SUB_A1:-}" ] && [ -n "${SUB_A2:-}" ]; then
    VPCE_SNS_ID="$(aws ec2 create-vpc-endpoint --vpc-id "$VPC_A_ID" --service-name "com.amazonaws.${REGION}.sns" \
        --vpc-endpoint-type Interface --subnet-ids "$SUB_A1" "$SUB_A2" --security-group-ids "$VPCE_SG_ID" \
        --query VpcEndpoint.VpcEndpointId --output text)"
    echo " sns interface endpoint created: $VPCE_SNS_ID"
  fi
fi

# ---- 8) API: /orders, integration, policy, deploy ----
if [ "$API_ID" != "None" ] && [ -n "$ROOT_ID" ]; then
  RES_ORDERS_ID="$(aws apigateway get-resources --rest-api-id "$API_ID" --query 'items[?path==`/orders`].id|[0]' --output text 2>/dev/null || echo None)"
  if [ "$RES_ORDERS_ID" = "None" ] || [ -z "$RES_ORDERS_ID" ]; then
    RES_ORDERS_ID="$(aws apigateway create-resource --rest-api-id "$API_ID" --parent-id "$ROOT_ID" --path-part orders --query id --output text)"
  fi
  aws apigateway put-method --rest-api-id "$API_ID" --resource-id "$RES_ORDERS_ID" --http-method GET --authorization-type NONE >/dev/null 2>&1 || true
  LAMBDA_ARN="arn:${PARTITION}:lambda:${REGION}:${ACCOUNT_ID}:function:${READER}"
  INVOKE_URI="arn:${PARTITION}:apigateway:${REGION}:lambda:path/2015-03-31/functions/${LAMBDA_ARN}/invocations"
  aws apigateway put-integration --rest-api-id "$API_ID" --resource-id "$RES_ORDERS_ID" --http-method GET \
    --type AWS_PROXY --integration-http-method POST --uri "${INVOKE_URI}" >/dev/null
  aws lambda add-permission --function-name "${READER}" --statement-id "${PREFIX}-apigw-orders" \
    --action lambda:InvokeFunction --principal apigateway.amazonaws.com \
    --source-arn "arn:${PARTITION}:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/GET/orders" >/dev/null 2>&1 || true

  if [ -n "$VPCE_EXEC_ID" ]; then
    cat > /tmp/api-policy-doc.json <<JSON
{"Version":"2012-10-17","Statement":[{
  "Sid":"AllowFromSpecificVPCE",
  "Effect":"Allow",
  "Principal":"*",
  "Action":"execute-api:Invoke",
  "Resource":"arn:${PARTITION}:execute-api:${REGION}:${ACCOUNT_ID}:${API_ID}/*/*/*",
  "Condition":{"StringEquals":{"aws:SourceVpce":"${VPCE_EXEC_ID}"}}
}]}
JSON
    POLICY_STR="$(jq -c . /tmp/api-policy-doc.json)"
    aws apigateway update-rest-api --rest-api-id "$API_ID" \
      --patch-operations "op=replace,path=/policy,value='$POLICY_STR'" >/dev/null
  fi

  aws apigateway update-rest-api --rest-api-id "$API_ID" \
      --patch-operations "op=add,path=/endpointConfiguration/vpcEndpointIds,value=${VPCE_EXEC_ID}" >/dev/null 2>&1 || true
  
  # Create deployment and stage (modern approach)
  DEPLOYMENT_ID="$(aws apigateway create-deployment --rest-api-id "$API_ID" --query 'id' --output text)"
  aws apigateway create-stage --rest-api-id "$API_ID" --deployment-id "$DEPLOYMENT_ID" --stage-name prod >/dev/null 2>&1 || \
  aws apigateway update-stage --rest-api-id "$API_ID" --stage-name prod --patch-operations "op=replace,path=/deploymentId,value=${DEPLOYMENT_ID}" >/dev/null 2>&1 || true
  echo " api /orders configured and deployed"
fi

# ---- 9) S3 bucket policy: exempt LabRole from SSE header deny ----
if [ -n "${BUCKET:-}" ]; then
  cat > /tmp/bucket-policy.json <<JSON
{"Version":"2012-10-17","Statement":[
  {"Sid":"DenyUnEncryptedObjectUploadsExceptLabRole","Effect":"Deny","Principal":"*",
   "Action":["s3:PutObject"],"Resource":["arn:${PARTITION}:s3:::${BUCKET}/*"],
   "Condition":{
      "StringNotEquals":{"s3:x-amz-server-side-encryption":"aws:kms"},
      "ArnNotEquals":{"aws:PrincipalArn":"${LABROLE_ARN}"}
   }},
  {"Sid":"AllowSSLRequestsOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:${PARTITION}:s3:::${BUCKET}","arn:${PARTITION}:s3:::${BUCKET}/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}
]}
JSON
  aws s3api put-bucket-policy --bucket "$BUCKET" --policy file:///tmp/bucket-policy.json >/dev/null
  echo " bucket policy adjusted for LabRole"
fi

# ---- 10) Update Lambda code for deterministic success ----
# reader: returns {"flag": "<decrypted text>"}
cat > /tmp/reader.py <<'PY'
import os, json, base64, boto3, botocore
kms = boto3.client("kms")
def handler(event, context):
    ct_b64 = os.environ.get("FLAG_CIPHERTEXT_B64","")
    flag = ""
    try:
        if ct_b64:
            pt = kms.decrypt(CiphertextBlob=base64.b64decode(ct_b64))["Plaintext"]
            flag = pt.decode("utf-8")
    except botocore.exceptions.ClientError as e:
        return {"statusCode": 500, "body": json.dumps({"error": "kms", "detail": str(e)})}
    return {"statusCode": 200, "body": json.dumps({"flag": flag})}
PY
cd /tmp && zip -q reader.zip reader.py
aws lambda update-function-code --function-name "$READER" --zip-file fileb:///tmp/reader.zip >/dev/null || true

# writer: DDB PutItem, S3 PutObject with SSE header, SNS publish
cat > /tmp/writer.py <<'PY'
import os, json, uuid, boto3, time, botocore
ddb = boto3.client("dynamodb")
s3 = boto3.client("s3")
sns = boto3.client("sns")
def handler(event, context):
    ok = {"ddb_ok": False, "s3_ok": False, "sns_ok": False}
    table = os.environ.get("DDB_TABLE","")
    bucket = os.environ.get("BUCKET","")
    topic = os.environ.get("TOPIC_ARN","")
    pk = str(uuid.uuid4())
    try:
        if table:
            ddb.put_item(TableName=table, Item={"pk":{"S": pk}, "ts":{"N": str(int(time.time()))}})
            ok["ddb_ok"] = True
    except botocore.exceptions.ClientError:
        pass
    try:
        if bucket:
            s3.put_object(Bucket=bucket, Key=f"probe/{pk}.json", Body=json.dumps({"pk": pk}).encode("utf-8"), ServerSideEncryption="aws:kms")
            ok["s3_ok"] = True
    except botocore.exceptions.ClientError:
        pass
    try:
        if topic:
            sns.publish(TopicArn=topic, Message=json.dumps({"pk": pk}))
            ok["sns_ok"] = True
    except botocore.exceptions.ClientError:
        pass
    return ok
PY
cd /tmp && zip -q writer.zip writer.py
aws lambda update-function-code --function-name "$WRITER" --zip-file fileb:///tmp/writer.zip >/dev/null || true

# ---- 11) re-enable rule ----
RULE="${PREFIX}-tick"
aws events enable-rule --name "$RULE" >/dev/null 2>&1 || true
echo " event rule enabled"

echo "done"

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
