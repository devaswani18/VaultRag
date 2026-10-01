from __future__ import annotations

import pytest
from moto import mock_aws

from vaultrag.config import Settings, clear_secret_cache, get_secret, get_settings
from vaultrag.errors import AppError


def test_settings_defaults() -> None:
    settings = Settings()
    assert settings.env == "dev"
    assert settings.aws_region == "ap-south-1"
    assert settings.qdrant_collection == "vaultrag_chunks"
    assert settings.embedding_dim == 768
    assert settings.max_upload_mb == 10
    assert settings.top_k == 6
    assert settings.gemini_max_rpm == 10
    assert settings.ssm_prefix == "/vaultrag/dev"
    assert settings.local_mode is False


def test_get_settings_cached() -> None:
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_get_secret_local_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCAL_MODE", "true")
    monkeypatch.setenv("VAULTRAG_SECRET_QDRANT_API_KEY", "local-secret-123")
    get_settings.cache_clear()
    clear_secret_cache()

    try:
        val = get_secret("qdrant_api_key")
        assert val == "local-secret-123"

        val_hyphen = get_secret("qdrant-api-key")
        assert val_hyphen == "local-secret-123"
    finally:
        get_settings.cache_clear()
        clear_secret_cache()


def test_get_secret_local_mode_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCAL_MODE", "true")
    get_settings.cache_clear()
    clear_secret_cache()

    try:
        with pytest.raises(AppError) as exc_info:
            get_secret("nonexistent_secret")
        assert exc_info.value.code == "secret_not_found"
    finally:
        get_settings.cache_clear()
        clear_secret_cache()


@mock_aws
def test_get_secret_ssm_caching(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCAL_MODE", "false")
    monkeypatch.setenv("AWS_REGION", "ap-south-1")
    get_settings.cache_clear()
    clear_secret_cache()

    import boto3

    ssm = boto3.client("ssm", region_name="ap-south-1")
    ssm.put_parameter(
        Name="/vaultrag/dev/gemini_api_key",
        Value="gemini-live-mock-token",
        Type="SecureString",
    )

    try:
        val1 = get_secret("gemini_api_key")
        assert val1 == "gemini-live-mock-token"

        # Overwrite parameter in SSM; cached value should still return the first read
        ssm.put_parameter(
            Name="/vaultrag/dev/gemini_api_key",
            Value="updated-token",
            Type="SecureString",
            Overwrite=True,
        )
        val2 = get_secret("gemini_api_key")
        assert val2 == "gemini-live-mock-token"
    finally:
        get_settings.cache_clear()
        clear_secret_cache()
