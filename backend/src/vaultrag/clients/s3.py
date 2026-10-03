from __future__ import annotations

import re
from typing import Any

import boto3
from botocore.exceptions import ClientError

from vaultrag.config import get_settings
from vaultrag.errors import NotFound, ValidationFailed

TENANT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
DOC_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
EXT_PATTERN = re.compile(r"^[a-zA-Z0-9]{1,10}$")
OBJECT_KEY_PATTERN = re.compile(
    r"^uploads/([a-z0-9][a-z0-9-]{1,30})/([a-zA-Z0-9_-]{1,64})/original\.([a-zA-Z0-9]{1,10})$"
)


def _validate_safe_id(val: str, pattern: re.Pattern[str], field_name: str) -> None:
    if not isinstance(val, str):
        raise ValidationFailed(f"{field_name} must be a string")
    # Disallow path traversal, urlencoded dots/slashes, and unicode tricks
    forbidden = ["..", "/", "\\", "%", "\x00", "\r", "\n"]
    if any(f in val.lower() for f in forbidden):
        raise ValidationFailed(f"Invalid characters in {field_name}: '{val}'")
    if not pattern.match(val):
        raise ValidationFailed(f"Invalid {field_name} format: '{val}'")


def build_object_key(tenant_id: str, doc_id: str, ext: str) -> str:
    """Build S3 object key for uploaded original document.

    Format: uploads/{tenant}/{doc}/original.{ext}
    Validates inputs strictly against regexes and path traversal.
    """
    _validate_safe_id(tenant_id, TENANT_ID_PATTERN, "tenant_id")
    _validate_safe_id(doc_id, DOC_ID_PATTERN, "doc_id")

    clean_ext = ext.lstrip(".") if isinstance(ext, str) else ""
    _validate_safe_id(clean_ext, EXT_PATTERN, "ext")

    return f"uploads/{tenant_id}/{doc_id}/original.{clean_ext}"


def parse_object_key(key: str) -> tuple[str, str, str]:
    """Parse S3 object key into (tenant_id, doc_id, ext).

    Raises ValidationFailed on any unexpected or invalid key format.
    """
    if not isinstance(key, str):
        raise ValidationFailed("Object key must be a string")

    # Reject path traversal tricks before regex
    if ".." in key or "%" in key or "\\" in key or "\x00" in key:
        raise ValidationFailed(f"Path traversal detected in object key: '{key}'")

    match = OBJECT_KEY_PATTERN.match(key)
    if not match:
        raise ValidationFailed(f"Invalid object key structure: '{key}'")

    tenant_id, doc_id, ext = match.group(1), match.group(2), match.group(3)
    return tenant_id, doc_id, ext


def get_s3_client(s3_client: Any = None) -> Any:
    """Return boto3 S3 client."""
    if s3_client is not None:
        return s3_client
    settings = get_settings()
    from botocore.config import Config

    config = Config(signature_version="s3v4", s3={"addressing_style": "virtual"})
    return boto3.client("s3", region_name=settings.aws_region, config=config)


def create_presigned_post(
    key: str,
    content_type: str,
    max_bytes: int,
    expires: int = 300,
    bucket: str | None = None,
    s3_client: Any = None,
) -> dict[str, Any]:
    """Generate S3 presigned post data with exact key, content-type and size constraints."""
    # Ensure key is valid before generating presigned post
    parse_object_key(key)

    settings = get_settings()
    target_bucket = bucket or settings.docs_bucket
    client = get_s3_client(s3_client)

    fields = {
        "key": key,
        "Content-Type": content_type,
    }
    conditions = [
        {"key": key},
        {"Content-Type": content_type},
        ["content-length-range", 1, max_bytes],
    ]

    return client.generate_presigned_post(
        Bucket=target_bucket,
        Key=key,
        Fields=fields,
        Conditions=conditions,
        ExpiresIn=expires,
    )


def download_bytes(
    key: str,
    max_bytes: int | None = None,
    bucket: str | None = None,
    s3_client: Any = None,
) -> bytes:
    """Download object bytes from S3. Validates key and enforces max_bytes."""
    parse_object_key(key)

    settings = get_settings()
    target_bucket = bucket or settings.docs_bucket
    client = get_s3_client(s3_client)

    try:
        response = client.get_object(Bucket=target_bucket, Key=key)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("NoSuchKey", "404"):
            raise NotFound(f"Object '{key}' not found in S3 bucket '{target_bucket}'") from e
        raise ValidationFailed(f"S3 download failed: {e}") from e

    content_length = response.get("ContentLength")
    if max_bytes is not None and content_length is not None and content_length > max_bytes:
        raise ValidationFailed(
            f"Object '{key}' size {content_length} bytes exceeds maximum allowed {max_bytes} bytes"
        )

    read_limit = (max_bytes + 1) if max_bytes is not None else None
    body_stream = response["Body"]
    if read_limit is not None:
        data = body_stream.read(read_limit)
        if len(data) > max_bytes:
            raise ValidationFailed(
                f"Object '{key}' stream exceeded maximum allowed {max_bytes} bytes"
            )
        return data

    return body_stream.read()


def delete_prefix(
    tenant_id: str,
    doc_id: str,
    bucket: str | None = None,
    s3_client: Any = None,
) -> int:
    """Delete all objects matching uploads/{tenant_id}/{doc_id}/ and return deleted count."""
    _validate_safe_id(tenant_id, TENANT_ID_PATTERN, "tenant_id")
    _validate_safe_id(doc_id, DOC_ID_PATTERN, "doc_id")

    settings = get_settings()
    target_bucket = bucket or settings.docs_bucket
    client = get_s3_client(s3_client)

    prefix = f"uploads/{tenant_id}/{doc_id}/"
    paginator = client.get_paginator("list_objects_v2")

    deleted_count = 0
    for page in paginator.paginate(Bucket=target_bucket, Prefix=prefix):
        contents = page.get("Contents", [])
        if not contents:
            continue
        delete_keys = [{"Key": obj["Key"]} for obj in contents]
        client.delete_objects(
            Bucket=target_bucket,
            Delete={"Objects": delete_keys, "Quiet": True},
        )
        deleted_count += len(delete_keys)

    return deleted_count


def delete_object(
    key: str,
    bucket: str | None = None,
    s3_client: Any = None,
) -> None:
    """Delete a single S3 object by key."""
    settings = get_settings()
    target_bucket = bucket or settings.docs_bucket
    client = get_s3_client(s3_client)
    client.delete_object(Bucket=target_bucket, Key=key)
