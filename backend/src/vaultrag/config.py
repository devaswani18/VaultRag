from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict

from vaultrag.errors import AppError

_SECRET_CACHE: dict[str, str] = {}


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    env: str = "dev"
    aws_region: str = "ap-south-1"
    tenants_table: str = "vaultrag-dev-tenants"
    documents_table: str = "vaultrag-dev-documents"
    audit_table: str = "vaultrag-dev-audit"
    usage_table: str = "vaultrag-dev-usage"
    gaps_table: str = "vaultrag-dev-gaps"
    conversations_table: str = "vaultrag-dev-conversations"
    docs_bucket: str = "vaultrag-docs-dev"
    qdrant_collection: str = "vaultrag_chunks"
    cache_collection: str = "vaultrag_cache"
    cache_similarity_threshold: float = 0.95
    embedding_model: str = "gemini-embedding-001"
    generation_model: str = "gemini-3.5-flash-lite"
    embedding_dim: int = 768
    max_upload_mb: int = 10
    top_k: int = 6
    gemini_max_rpm: int = 10
    cognito_user_pool_id: str = ""
    cognito_client_id: str = ""
    ssm_prefix: str = "/vaultrag/dev"
    local_mode: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()


def clear_secret_cache() -> None:
    """Clear in-process secret cache (used in testing)."""
    _SECRET_CACHE.clear()


def get_secret(name: str) -> str:
    """Retrieve secret by name.

    In local_mode: reads from environment variable VAULTRAG_SECRET_<NAME>.
    Otherwise: reads SSM parameter f"{ssm_prefix}/{name}" with decryption,
    cached in-process for the container lifetime.
    Secret values and contents are NEVER logged.
    """
    settings = get_settings()

    if settings.local_mode:
        normalized_name = name.upper().replace("-", "_")
        env_keys = [
            f"VAULTRAG_SECRET_{normalized_name}",
            f"VAULTRAG_SECRET_{name.upper()}",
            f"VAULTRAG_SECRET_{name}",
        ]
        for key in env_keys:
            val = os.environ.get(key)
            if val is not None:
                return val
        raise AppError(
            status=500,
            code="secret_not_found",
            message=f"Secret '{name}' not found in local environment",
        )

    # In-process cache check
    if name in _SECRET_CACHE:
        return _SECRET_CACHE[name]

    import boto3
    from botocore.exceptions import ClientError

    param_path = f"{settings.ssm_prefix.rstrip('/')}/{name.lstrip('/')}"
    try:
        ssm = boto3.client("ssm", region_name=settings.aws_region)
        response: dict[str, Any] = ssm.get_parameter(Name=param_path, WithDecryption=True)
        val = response["Parameter"]["Value"]
        _SECRET_CACHE[name] = val
        return val
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "SSMError")
        raise AppError(
            status=500,
            code="secret_fetch_error",
            message=f"Failed to fetch secret '{name}' from SSM ({error_code})",
        ) from None
