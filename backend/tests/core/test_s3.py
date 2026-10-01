from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from vaultrag.clients.s3 import (
    build_object_key,
    create_presigned_post,
    delete_prefix,
    download_bytes,
    parse_object_key,
)
from vaultrag.errors import NotFound, ValidationFailed


def test_build_and_parse_object_key_round_trip() -> None:
    tenant_id = "tenant-01"
    doc_id = "doc-alpha-99"
    ext = "pdf"

    key = build_object_key(tenant_id, doc_id, ext)
    assert key == "uploads/tenant-01/doc-alpha-99/original.pdf"

    parsed_tenant, parsed_doc, parsed_ext = parse_object_key(key)
    assert parsed_tenant == tenant_id
    assert parsed_doc == doc_id
    assert parsed_ext == ext


@pytest.mark.parametrize(
    "bad_tenant, bad_doc, bad_ext",
    [
        ("../malicious", "doc-1", "pdf"),
        ("tenant-1", "../etc/passwd", "pdf"),
        ("tenant-1", "doc-1", "../sh"),
        ("%2e%2e", "doc-1", "pdf"),
        ("tenant-1", "%2e%2edoc", "pdf"),
        ("tenant-1", "doc-1", "%2e%2epdf"),
        ("tenant/sub", "doc-1", "pdf"),
        ("tenant-1", "doc/sub", "pdf"),
        ("tenant-1", "doc-1", "pdf/exe"),
        ("tenant\\win", "doc-1", "pdf"),
        ("tenant-1", "doc\\win", "pdf"),
        ("TENANT-1", "doc-1", "pdf"),  # Uppercase tenant
        ("tenant-1", "doc\x00null", "pdf"),
        ("tenant-1", "doc-1", "pdf\x00"),
        ("tenant-1", "doc-1", "toolongextension12345"),
        ("t", "doc-1", "pdf"),  # Too short tenant
        ("tenant-1", "doc\u2215trick", "pdf"),  # Unicode division slash trick
    ],
)
def test_build_object_key_rejections(bad_tenant: str, bad_doc: str, bad_ext: str) -> None:
    with pytest.raises(ValidationFailed):
        build_object_key(bad_tenant, bad_doc, bad_ext)


@pytest.mark.parametrize(
    "bad_key",
    [
        "uploads/../tenant/doc/original.pdf",
        "uploads/tenant/%2e%2e/original.pdf",
        "uploads/tenant/doc/original.pdf/../extra",
        "downloads/tenant/doc/original.pdf",
        "uploads/TENANT/doc/original.pdf",
        "uploads/tenant/doc/somethingelse.pdf",
        "uploads/tenant/doc/original",
        "uploads/tenant/doc/original.",
        "uploads/tenant/doc/original.pdf\x00",
        "uploads/tenant/doc/original.pdf;rm -rf",
    ],
)
def test_parse_object_key_rejections(bad_key: str) -> None:
    with pytest.raises(ValidationFailed):
        parse_object_key(bad_key)


@mock_aws
def test_create_presigned_post_content_length_range(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    monkeypatch.setenv("DOCS_BUCKET", "vaultrag-test-bucket")

    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(
        Bucket="vaultrag-test-bucket",
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )

    key = build_object_key("tenant-100", "doc-200", "pdf")
    max_bytes = 10 * 1024 * 1024  # 10 MB

    post_data = create_presigned_post(
        key=key,
        content_type="application/pdf",
        max_bytes=max_bytes,
        expires=300,
        bucket="vaultrag-test-bucket",
        s3_client=s3,
    )

    assert "url" in post_data
    assert "fields" in post_data
    assert post_data["fields"]["key"] == key
    assert post_data["fields"]["Content-Type"] == "application/pdf"

    # In moto / boto3 presigned post, policy is base64 JSON containing conditions
    import base64
    import json

    policy_json = json.loads(base64.b64decode(post_data["fields"]["policy"]).decode("utf-8"))
    conditions = policy_json.get("conditions", [])

    # Verify content-length-range condition exists with [1, max_bytes]
    has_range_cond = any(
        isinstance(c, list) and c[0] == "content-length-range" and c[1] == 1 and c[2] == max_bytes
        for c in conditions
    )
    assert has_range_cond, f"content-length-range condition missing in policy: {conditions}"


@mock_aws
def test_download_bytes_and_max_bytes_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    bucket = "vaultrag-test-bucket"

    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )

    key = build_object_key("tenant-100", "doc-200", "txt")
    payload = b"Hello, secure multi-tenant world!"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)

    # Normal download
    data = download_bytes(key, max_bytes=1024, bucket=bucket, s3_client=s3)
    assert data == payload

    # Exceeding max_bytes raises ValidationFailed
    with pytest.raises(ValidationFailed):
        download_bytes(key, max_bytes=5, bucket=bucket, s3_client=s3)

    # Missing file raises NotFound
    with pytest.raises(NotFound):
        download_bytes(
            build_object_key("tenant-100", "doc-404", "txt"),
            bucket=bucket,
            s3_client=s3,
        )


@mock_aws
def test_delete_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    bucket = "vaultrag-test-bucket"

    s3 = boto3.client("s3", region_name="ap-south-1")
    s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": "ap-south-1"},
    )

    tenant_id = "tenant-del"
    doc_id = "doc-del"

    # Put multiple files under uploads/tenant-del/doc-del/
    s3.put_object(Bucket=bucket, Key=f"uploads/{tenant_id}/{doc_id}/original.pdf", Body=b"1")
    s3.put_object(Bucket=bucket, Key=f"uploads/{tenant_id}/{doc_id}/extracted.txt", Body=b"2")
    s3.put_object(Bucket=bucket, Key=f"uploads/{tenant_id}/{doc_id}/metadata.json", Body=b"3")
    # Put another document under tenant-del
    s3.put_object(Bucket=bucket, Key=f"uploads/{tenant_id}/doc-other/original.pdf", Body=b"other")

    count = delete_prefix(tenant_id, doc_id, bucket=bucket, s3_client=s3)
    assert count == 3

    # Ensure other doc was not deleted
    other_obj = s3.get_object(Bucket=bucket, Key=f"uploads/{tenant_id}/doc-other/original.pdf")
    assert other_obj["Body"].read() == b"other"
