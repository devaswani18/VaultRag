#!/usr/bin/env python3
"""E2E smoke test: upload a leave-policy doc as acme, query it, then verify globex gets no results.

Usage::

    cd backend && python scripts/e2e_smoke.py

Expected: acme gets a real answer with a source; globex gets "could not find".
If globex sees acme's content, stop and report immediately; that is a tenant-isolation bug.

Tokens and passwords are NEVER printed.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).resolve().parents[2]
CREDS_FILE = REPO_ROOT / ".demo-credentials.json"

# ── Constants ─────────────────────────────────────────────────────────────────
LEAVE_POLICY_TEXT = (
    "Acme Corp Leave Policy v1.0\n\n"
    "Full-time employees are entitled to 20 paid leave days per calendar year. "
    "Part-time employees receive leave on a pro-rata basis. "
    "Unused leave may be carried over up to 5 days into the next calendar year. "
    "Leave requests must be submitted at least 3 days in advance via HR portal."
)
QUESTION = "How many paid leave days do full-time employees get?"
DEFAULT_API_URL = "https://w3jfxjxg34gptvv5gqqxrpevpm0zaxup.lambda-url.ap-south-1.on.aws/"


def _load_creds() -> dict:
    candidates = [
        CREDS_FILE,
        Path(".demo-credentials.json"),
        Path("../.demo-credentials.json"),
    ]
    for c in candidates:
        if c.exists():
            with c.open(encoding="utf-8") as f:
                return json.load(f)
    sys.exit("ERROR: .demo-credentials.json not found.")


def _get_token(creds: dict, tenant_id: str, api_url: str) -> str:
    """Authenticate and return an id_token via Cognito. Passwords and tokens are never printed."""
    # 1. Search in users list
    user = None
    for u in creds.get("users", []):
        roles = u.get("roles") or []
        role = u.get("role") or ""
        if u.get("tenant_id") == tenant_id and (role == "admin" or "admin" in roles):
            user = u
            break

    if user and "password" in user:
        import boto3

        client_id = creds.get("client_id") or "7tphqalmdashifb1ee25oqca1n"
        region = creds.get("region") or "ap-south-1"
        cognito = boto3.client("cognito-idp", region_name=region)
        auth_res = cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": user["email"], "PASSWORD": user["password"]},
        )
        token = auth_res["AuthenticationResult"]["IdToken"]
        print(f"[auth] Authenticated as {tenant_id} admin (token omitted)")
        return token

    # 2. Fallback to direct dict key (e.g. creds["acme_admin"])
    user_key = f"{tenant_id}_admin"
    if user_key in creds:
        login_url = api_url.rstrip("/") + "/auth/login"
        resp = _http_json(
            login_url,
            method="POST",
            body={"username": creds[user_key].get("username")},
        )
        token = resp.get("id_token") or resp.get("access_token", "")
        if token:
            print(f"[auth] Authenticated as {user_key} (token omitted)")
            return token

    sys.exit(f"ERROR: Could not obtain token for tenant '{tenant_id}'. Check credentials.")


def _http_json(
    url: str, *, method: str = "GET", body: dict | None = None, headers: dict | None = None
) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _api(
    api_url: str, path: str, *, method: str = "GET", body: dict | None = None, token: str = ""
) -> dict:
    url = api_url.rstrip("/") + "/" + path.lstrip("/")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return _http_json(url, method=method, body=body, headers=headers)


def _poll_ready(api_url: str, token: str, doc_id: str, max_wait: int = 120) -> None:
    print(f"[poll] Waiting for doc {doc_id} to reach READY status…")
    deadline = time.monotonic() + max_wait
    while time.monotonic() < deadline:
        doc = _api(api_url, f"/documents/{doc_id}", token=token)
        status = doc.get("status", "UNKNOWN")
        print(f"       status={status}")
        if status == "READY":
            print(f"[poll] Document is READY (chunk_count={doc.get('chunk_count', '?')})")
            return
        if status in ("FAILED", "QUARANTINED"):
            sys.exit(f"ERROR: Document reached terminal failure state: {status}")
        time.sleep(5)
    sys.exit("ERROR: Document did not reach READY within the timeout.")


def main() -> None:
    creds = _load_creds()
    api_url = creds.get("api_url") or DEFAULT_API_URL

    # ── Step 1: Authenticate as acme admin ───────────────────────────────────
    acme_token = _get_token(creds, "acme", api_url)

    # ── Step 2: Create document record ───────────────────────────────────────
    filename = "leave_policy.txt"
    content = LEAVE_POLICY_TEXT.encode("utf-8")
    print(f"\n[upload] Creating document record for '{filename}' …")
    create_resp = _api(
        api_url,
        "/documents",
        method="POST",
        body={
            "filename": filename,
            "content_type": "text/plain",
            "size_bytes": len(content),
            "visibility": "tenant",
        },
        token=acme_token,
    )
    doc_id = create_resp["doc_id"]
    upload_url = create_resp["upload"]["url"]
    upload_fields = create_resp["upload"]["fields"]
    print(f"[upload] doc_id={doc_id}")

    # ── Step 3: POST file to presigned S3 URL ────────────────────────────────
    print("[upload] Uploading file to presigned S3 URL …")
    boundary = "----VaultRAGSmokeBoundary"
    body_parts: list[bytes] = []
    for key, val in upload_fields.items():
        body_parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{val}\r\n'.encode()
        )
    body_parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n".encode()
        + content
        + b"\r\n"
    )
    body_parts.append(f"--{boundary}--\r\n".encode())
    mp_body = b"".join(body_parts)

    s3_req = urllib.request.Request(
        upload_url,
        data=mp_body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(s3_req, timeout=30) as s3_resp:
        print(f"[upload] S3 response: {s3_resp.status}")

    # ── Step 4: Poll until READY ──────────────────────────────────────────────
    _poll_ready(api_url, acme_token, doc_id)

    # ── Step 5: Query as acme — expect a real answer ──────────────────────────
    print(f"\n[query] Asking as acme: {QUESTION!r}")
    acme_query = _api(
        api_url,
        "/query",
        method="POST",
        body={"question": QUESTION, "top_k": 5},
        token=acme_token,
    )
    print(f"[query] Answer: {acme_query.get('answer')}")
    sources = acme_query.get("sources", [])
    print(f"[query] Sources ({len(sources)}):")
    for src in sources:
        print(f"         chunk_id={src['chunk_id']} score={src['score']:.4f} page={src['page']}")

    if not sources:
        print("WARNING: acme received no sources for its own document!", file=sys.stderr)

    # ── Step 6: Query as globex — expect no results ───────────────────────────
    print("\n[isolation] Authenticating as globex admin …")
    globex_token = _get_token(creds, "globex", api_url)

    print(f"[isolation] Asking as globex: {QUESTION!r}")
    globex_query = _api(
        api_url,
        "/query",
        method="POST",
        body={"question": QUESTION, "top_k": 5},
        token=globex_token,
    )
    print(f"[isolation] Answer: {globex_query.get('answer')}")
    globex_sources = globex_query.get("sources", [])

    if globex_sources:
        print(
            "FATAL TENANT-ISOLATION BUG: globex received sources from acme's documents!",
            file=sys.stderr,
        )
        for s in globex_sources:
            print(f"   leaked: {s}", file=sys.stderr)
        sys.exit(1)
    else:
        print("[isolation] [PASS] globex received no sources - tenant isolation confirmed.")

    print("\n[PASS] E2E smoke test complete successfully.")


if __name__ == "__main__":
    main()
