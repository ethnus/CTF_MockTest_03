import os, json, time, boto3
ddb = boto3.client("dynamodb")
s3  = boto3.client("s3")
sns = boto3.client("sns")

DDB_TABLE = os.environ.get("DDB_TABLE", "MISSING_TABLE")
BUCKET = os.environ["BUCKET"]
TOPIC_ARN = os.environ["TOPIC_ARN"]

def handler(event, context):
    out = {"ddb_ok": False, "s3_ok": False, "sns_ok": False}
    try:
        ddb.put_item(TableName=DDB_TABLE, Item={"pk": {"S": f"order#{int(time.time())}"}})
        out["ddb_ok"] = True
    except Exception as e:
        out["ddb_err"] = str(e)
    try:
        s3.put_object(Bucket=BUCKET, Key="probe.txt", Body=b"hello")
        out["s3_ok"] = True
    except Exception as e:
        out["s3_err"] = str(e)
    try:
        sns.publish(TopicArn=TOPIC_ARN, Message=json.dumps({"ts": int(time.time())}))
        out["sns_ok"] = True
    except Exception as e:
        out["sns_err"] = str(e)
    return out
