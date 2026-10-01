from __future__ import annotations

import math
from unittest.mock import MagicMock, patch

import pytest
from google.genai import errors, types

from vaultrag.clients.gemini import (
    GenerationResult,
    RateLimiter,
    embed_texts,
    generate_json,
    l2_normalize,
    set_client,
    set_rate_limiter,
)
from vaultrag.errors import UpstreamError, ValidationFailed


@pytest.fixture(autouse=True)
def cleanup_gemini_client() -> None:
    set_client(None)
    set_rate_limiter(RateLimiter(max_rpm=1000))  # High RPM so unit tests don't sleep
    yield
    set_client(None)
    set_rate_limiter(None)


def test_l2_normalize() -> None:
    vec = [3.0, 4.0]
    normalized = l2_normalize(vec)
    assert pytest.approx(normalized[0]) == 0.6
    assert pytest.approx(normalized[1]) == 0.8
    assert pytest.approx(math.sqrt(sum(x * x for x in normalized))) == 1.0

    # Zero vector does not divide by zero
    assert l2_normalize([0.0, 0.0]) == [0.0, 0.0]


def test_embed_texts_batching() -> None:
    mock_client = MagicMock()
    set_client(mock_client)

    # 120 texts should produce 3 batches: 50, 50, 20
    texts = [f"Text line {i}" for i in range(120)]

    def fake_embed(model: str, contents: list[str], config: types.EmbedContentConfig) -> MagicMock:
        embeddings = [MagicMock(values=[0.1] * 768) for _ in contents]
        return MagicMock(embeddings=embeddings)

    mock_client.models.embed_content.side_effect = fake_embed

    results = embed_texts(texts, task_type="RETRIEVAL_DOCUMENT")

    assert len(results) == 120
    assert mock_client.models.embed_content.call_count == 3

    # Check batch sizes
    calls = mock_client.models.embed_content.call_args_list
    assert len(calls[0].kwargs["contents"]) == 50
    assert len(calls[1].kwargs["contents"]) == 50
    assert len(calls[2].kwargs["contents"]) == 20


def test_embed_texts_normalisation_when_dimension_reduced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EMBEDDING_DIM", "256")
    from vaultrag.config import get_settings

    get_settings.cache_clear()

    mock_client = MagicMock()
    set_client(mock_client)

    # Return unnormalized 256-dim vector
    unnormalized_vec = [2.0] * 256
    mock_client.models.embed_content.return_value = MagicMock(
        embeddings=[MagicMock(values=unnormalized_vec)]
    )

    try:
        results = embed_texts(["sample text"], task_type="RETRIEVAL_DOCUMENT")
        assert len(results) == 1
        res_vec = results[0]
        assert len(res_vec) == 256
        norm = math.sqrt(sum(x * x for x in res_vec))
        assert pytest.approx(norm) == 1.0
    finally:
        get_settings.cache_clear()


def test_embed_texts_invalid_task_type() -> None:
    with pytest.raises(ValidationFailed, match="Invalid task_type"):
        embed_texts(["hello"], task_type="INVALID_TASK")


@patch("time.sleep", return_value=None)
def test_retry_on_429_then_success(mock_sleep: MagicMock) -> None:
    mock_client = MagicMock()
    set_client(mock_client)

    # First attempt raises 429, second attempt succeeds
    err_429 = errors.APIError(code=429, response_json={"error": "RESOURCE_EXHAUSTED"})
    success_resp = MagicMock(embeddings=[MagicMock(values=[0.1] * 768)])
    mock_client.models.embed_content.side_effect = [err_429, success_resp]

    results = embed_texts(["retry test"])
    assert len(results) == 1
    assert mock_client.models.embed_content.call_count == 2
    assert mock_sleep.call_count == 1


@patch("time.sleep", return_value=None)
def test_failure_after_max_attempts_raises_upstream_error_no_prompt_leak(
    mock_sleep: MagicMock,
) -> None:
    mock_client = MagicMock()
    set_client(mock_client)

    super_secret_prompt = "TOP_SECRET_USER_QUERY_DO_NOT_LEAK"
    err_503 = errors.APIError(code=503, response_json={"error": "SERVICE_UNAVAILABLE"})
    mock_client.models.generate_content.side_effect = err_503

    with pytest.raises(UpstreamError) as exc_info:
        generate_json("System prompt", super_secret_prompt)

    # Verify safe message: NO prompt text in exception message
    error_message = str(exc_info.value)
    assert super_secret_prompt not in error_message
    assert "System prompt" not in error_message
    assert "Gemini service unavailable after 4 attempts" in error_message
    assert mock_client.models.generate_content.call_count == 4


def test_generate_json_success_and_metadata() -> None:
    mock_client = MagicMock()
    set_client(mock_client)

    mock_resp = MagicMock()
    mock_resp.text = '{"answer": "classified info"}'
    mock_resp.usage_metadata.prompt_token_count = 45
    mock_resp.usage_metadata.candidates_token_count = 18
    mock_client.models.generate_content.return_value = mock_resp

    result = generate_json("You are an assistant", "What is RAG?")

    assert isinstance(result, GenerationResult)
    assert isinstance(result, str)
    assert result == '{"answer": "classified info"}'
    assert result.input_tokens == 45
    assert result.output_tokens == 18
    assert result.text == '{"answer": "classified info"}'


def test_rate_limiter_delays() -> None:
    limiter = RateLimiter(max_rpm=2)

    # 1st call: immediate
    assert limiter.acquire() == 0.0

    # 2nd call: immediate
    assert limiter.acquire() == 0.0

    # 3rd call: must sleep because max_rpm=2 reached in the last 60s
    with patch("time.sleep") as mock_sleep:
        limiter.acquire()
        assert mock_sleep.call_count == 1
        sleep_arg = mock_sleep.call_args[0][0]
        assert sleep_arg > 0.0
