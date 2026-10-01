from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import boto3
import httpx

# 1. Read demo credentials
repo_root = Path(__file__).resolve().parent.parent.parent
candidates = [
    repo_root / ".demo-credentials.json",
    Path(".demo-credentials.json"),
    Path("../.demo-credentials.json"),
]
cred_path = None
for c in candidates:
    if c.exists():
        cred_path = c
        break

if not cred_path:
    print("ERROR: .demo-credentials.json not found", file=sys.stderr)
    sys.exit(1)

with open(cred_path, encoding="utf-8") as f:
    creds = json.load(f)

# Pick first admin
admin_user = None
for u in creds.get("users", []):
    role = u.get("role") or ""
    roles = u.get("roles") or []
    if (role == "admin" or "admin" in roles) and u.get("tenant_id") == "acme":
        admin_user = u
        break

if not admin_user:
    admin_user = creds["users"][0]

email = admin_user["email"]
password = admin_user["password"]
client_id = creds.get("client_id") or "7tphqalmdashifb1ee25oqca1n"
api_url = "https://w3jfxjxg34gptvv5gqqxrpevpm0zaxup.lambda-url.ap-south-1.on.aws"


print(f"[1/5] Authenticating as {email}...")
cognito = boto3.client("cognito-idp", region_name="ap-south-1")
auth_res = cognito.initiate_auth(
    ClientId=client_id,
    AuthFlow="USER_PASSWORD_AUTH",
    AuthParameters={"USERNAME": email, "PASSWORD": password},
)
id_token = auth_res["AuthenticationResult"]["IdToken"]
print("  --> Authentication successful, acquired ID token.")

# 2. Prepare real test file
test_content = (
    b"Acme Corporation Information Security Policy (Stage 8 Real File Ingestion Test).\n\n"
    b"All employees must complete mandatory data privacy and compliance training annually. "
    b"Confidential documents must be stored in approved tenant vaults with proper encryption. "
    b"Access control follows least-privilege principles based on user roles."
)

filename = "acme_security_policy.txt"
size_bytes = len(test_content)
print(f"[2/5] Creating document record via API for '{filename}' ({size_bytes} bytes)...")

headers = {
    "Authorization": f"Bearer {id_token}",
    "Content-Type": "application/json",
}
create_payload = {
    "filename": filename,
    "content_type": "text/plain",
    "size_bytes": size_bytes,
    "visibility": "tenant",
}

with httpx.Client(timeout=30.0) as client:
    resp = client.post(f"{api_url}/documents", headers=headers, json=create_payload)
    if resp.status_code != 200:
        print(f"ERROR: Failed to create document: {resp.status_code} {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    doc_id = data["doc_id"]
    upload_info = data["upload"]
    print(f"  --> Document created: doc_id={doc_id}")
    print(f"  --> S3 Presigned URL: {upload_info['url']}")

    # 3. Upload file to S3 via Presigned POST
    print("[3/5] Uploading file bytes to S3 presigned URL...")
    files = {"file": (filename, test_content, "text/plain")}
    post_resp = client.post(upload_info["url"], data=upload_info["fields"], files=files)
    if post_resp.status_code not in (200, 204):
        print(f"ERROR: S3 upload failed: {post_resp.status_code} {post_resp.text}", file=sys.stderr)
        sys.exit(1)
    print("  --> Upload to S3 completed successfully.")

    # 4. Poll GET /documents/{doc_id} for ingestion processing to complete
    print("[4/5] Waiting for Ingest Lambda to process document...")
    max_wait = 30
    start = time.monotonic()
    final_doc = None

    while time.monotonic() - start < max_wait:
        get_resp = client.get(f"{api_url}/documents/{doc_id}", headers=headers)
        if get_resp.status_code == 200:
            doc_record = get_resp.json()
            status = doc_record.get("status")
            print(f"  --> Document status: {status} (elapsed: {int(time.monotonic() - start)}s)")
            if status in ("READY", "FAILED", "QUARANTINED"):
                final_doc = doc_record
                break
        time.sleep(2)

    # 5. Output result
    print("[5/5] Ingestion verification:")
    if not final_doc:
        print("  --> Timed out waiting for document processing to finish", file=sys.stderr)
        sys.exit(1)

    print(f"  --> Final Status: {final_doc['status']}")
    print(f"  --> Chunk Count:  {final_doc.get('chunk_count', 0)}")
    print(f"  --> Document ID:  {final_doc['id']}")
    print(f"  --> Filename:     {final_doc['filename']}")

    if final_doc["status"] == "READY":
        print("\nSUCCESS: Real document upload and ingestion pipeline verified!")
    else:
        print(f"\nFAILURE: Ingestion did not complete as READY (status: {final_doc['status']})")
        sys.exit(1)
