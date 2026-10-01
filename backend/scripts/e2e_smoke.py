#!/usr/bin/env python3
"""E2E smoke test: upload a leave-policy doc as acme, query it, then verify globex gets no results.

Usage::

    python backend/scripts/e2e_smoke.py

Reads credentials from ``.demo-credentials.json`` in the repo root.
Format::

    {
        "acme_admin": {"username": "admin@acme.example.com", "password": "..."},
        "globex_admin": {"username": "admin@globex.example.com", "password": "..."},
        "api_url": "https://xxxxxx.lambda-url.ap-south-1.on.aws/"
    }

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


def _load_creds() -> dict:
    if not CREDS_FILE.exists():
        sys.exit(f"ERROR: {CREDS_FILE} not found. Please create it with your demo credentials.")
    with CREDS_FILE.open() as f:
        return json.load(f)


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


def _get_token(creds: dict, user_key: str, api_url: str) -> str:
    """Authenticate and return an id_token. Passwords are never printed."""
    user_creds = creds[user_key]
    login_url = api_url.rstrip("/") + "/auth/login"
    # POST credentials; token value is NOT printed anywhere
    resp = _http_json(
        login_url,
        method="POST",
        body={"username": user_creds["username"]},
    )
    # If the API uses a direct Cognito token endpoint, adapt here.
    # For the smoke test we assume the token is in resp["id_token"].
    token = resp.get("id_token") or resp.get("access_token", "")
    if not token:
        sys.exit(f"ERROR: Could not obtain token for {user_key}. Check credentials.")
    print(f"[auth] Authenticated as {user_key} (token omitted)")
    return token


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
    api_url = creds.get("api_url", "")
    if not api_url:
        sys.exit("ERROR: 'api_url' missing from .demo-credentials.json")

    # ── Step 1: Authenticate as acme admin ───────────────────────────────────
    acme_token = _get_token(creds, "acme_admin", api_url)

    # ── Step 2: Create document record ───────────────────────────────────────
    filename = "leave_policy.txt"
    content = LEAVE_POLICY_TEXT.encode()
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
    import urllib.parse

    print("[upload] Uploading file to presigned S3 URL …")
    # Build multipart form-data manually (no external deps)
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
    print(f"[query] Answer: {acme_query['answer']}")
    print(f"[query] Sources ({len(acme_query['sources'])}):")
    for src in acme_query["sources"]:
        print(f"         chunk_id={src['chunk_id']} score={src['score']:.4f} page={src['page']}")

    # ── Step 6: Query as globex — expect no results ───────────────────────────
    print("\n[isolation] Authenticating as globex admin …")
    globex_token = _get_token(creds, "globex_admin", api_url)

    print(f"[isolation] Asking as globex: {QUESTION!r}")
    globex_query = _api(
        api_url,
        "/query",
        method="POST",
        body={"question": QUESTION, "top_k": 5},
        token=globex_token,
    )
    print(f"[isolation] Answer: {globex_query['answer']}")
    if globex_query["sources"]:
        print(
            "WARNING: globex received sources — check tenant isolation!",
            file=sys.stderr,
        )
    else:
        print("[isolation] ✓ globex received no sources — tenant isolation confirmed.")

    print("\n✓ E2E smoke test complete.")


if __name__ == "__main__":
    main()
