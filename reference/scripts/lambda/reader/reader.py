import os, base64, boto3
ddb = boto3.client("dynamodb")
kms = boto3.client("kms")

DDB_TABLE = os.environ["DDB_TABLE"]
CT_B64 = os.environ["FLAG_CIPHERTEXT_B64"]

def handler(event, context):
    ok = True
    try:
        ddb.describe_table(TableName=DDB_TABLE)
    except Exception:
        ok = False
    pt = kms.decrypt(CiphertextBlob=base64.b64decode(CT_B64))["Plaintext"].decode("utf-8")
    return {"table_ok": ok, "flag": pt}
