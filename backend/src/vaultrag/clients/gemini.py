from __future__ import annotations

import logging
import math
import random
import threading
import time
from typing import Any

from google import genai
from google.genai import types

from vaultrag.config import get_secret, get_settings
from vaultrag.errors import UpstreamError, ValidationFailed
from vaultrag.logging_utils import log_event

logger = logging.getLogger(__name__)

_GENAI_CLIENT: genai.Client | None = None
MAX_BATCH_SIZE = 50
MAX_ATTEMPTS = 4
BASE_BACKOFF_SECS = 0.5
MAX_BACKOFF_SECS = 5.0


class GenerationResult(str):
    """Result string with token usage metadata for telemetry and metering."""

    input_tokens: int
    output_tokens: int
    model: str

    def __new__(
        cls,
        text: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        model: str = "",
    ) -> GenerationResult:
        instance = super().__new__(cls, text)
        instance.input_tokens = input_tokens
        instance.output_tokens = output_tokens
        instance.model = model
        return instance

    @property
    def text(self) -> str:
        return str(self)


class RateLimiter:
    """Sliding-window in-process rate limiter honouring configured max RPM."""

    def __init__(self, max_rpm: int = 10) -> None:
        self.max_rpm = max_rpm
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Block until request can proceed. Returns time slept in seconds."""
        if self.max_rpm <= 0:
            return 0.0

        with self._lock:
            now = time.monotonic()
            # Retain only timestamps from the last 60 seconds
            self._timestamps = [t for t in self._timestamps if now - t < 60.0]

            slept = 0.0
            if len(self._timestamps) >= self.max_rpm:
                oldest = self._timestamps[0]
                wait_time = 60.0 - (now - oldest) + 0.05
                if wait_time > 0:
                    time.sleep(wait_time)
                    slept = wait_time
                    now = time.monotonic()
                    self._timestamps = [t for t in self._timestamps if now - t < 60.0]

            self._timestamps.append(time.monotonic())
            return slept


_RATE_LIMITER: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return in-process rate limiter configured with settings.gemini_max_rpm."""
    global _RATE_LIMITER
    if _RATE_LIMITER is None:
        settings = get_settings()
        _RATE_LIMITER = RateLimiter(max_rpm=settings.gemini_max_rpm)
    return _RATE_LIMITER


def set_rate_limiter(limiter: RateLimiter | None) -> None:
    """Override rate limiter instance (used in tests)."""
    global _RATE_LIMITER
    _RATE_LIMITER = limiter


def get_client() -> genai.Client:
    """Build and cache genai.Client from secrets."""
    global _GENAI_CLIENT
    if _GENAI_CLIENT is not None:
        return _GENAI_CLIENT

    api_key = get_secret("gemini_api_key")
    _GENAI_CLIENT = genai.Client(api_key=api_key)
    return _GENAI_CLIENT


def set_client(client: genai.Client | None) -> None:
    """Set or reset genai.Client instance (used in tests)."""
    global _GENAI_CLIENT
    _GENAI_CLIENT = client


def l2_normalize(vec: list[float]) -> list[float]:
    """L2-normalize float vector to unit length."""
    norm = math.sqrt(sum(x * x for x in vec))
    if norm == 0.0:
        return vec
    return [x / norm for x in vec]


def _is_retryable_error(exc: Exception) -> bool:
    """Check if exception represents a 429 rate limit or 5xx server error."""
    code = getattr(exc, "code", None) or getattr(exc, "status_code", None)
    if isinstance(code, int):
        return code == 429 or code >= 500

    msg = str(exc).lower()
    return any(
        err_hint in msg
        for err_hint in (
            "429",
            "resource_exhausted",
            "quota",
            "500",
            "502",
            "503",
            "504",
            "timeout",
            "timed out",
        )
    )


def _call_with_retry(operation: Any, op_name: str) -> Any:
    """Execute an SDK operation with exponential backoff + jitter on 429/5xx."""
    limiter = get_rate_limiter()

    for attempt in range(1, MAX_ATTEMPTS + 1):
        limiter.acquire()
        try:
            return operation()
        except Exception as e:
            if not _is_retryable_error(e) or attempt == MAX_ATTEMPTS:
                # SAFE error message: NEVER leak prompt text or document content
                logger.error(
                    "Gemini %s failed permanently on attempt %d/%d: %s",
                    op_name,
                    attempt,
                    MAX_ATTEMPTS,
                    type(e).__name__,
                )
                raise UpstreamError(
                    f"Gemini service unavailable after {attempt} attempts"
                ) from None

            backoff = min(BASE_BACKOFF_SECS * (2 ** (attempt - 1)), MAX_BACKOFF_SECS)
            jitter = random.uniform(0.0, 0.25 * backoff)  # noqa: S311
            sleep_time = backoff + jitter
            logger.warning(
                "Gemini %s returned retryable error on attempt %d/%d; retrying in %.2fs",
                op_name,
                attempt,
                MAX_ATTEMPTS,
                sleep_time,
            )
            time.sleep(sleep_time)


def embed_texts(
    texts: list[str],
    task_type: str = "RETRIEVAL_DOCUMENT",
) -> list[list[float]]:
    """Embed texts in batches up to 50 with task_type validation and dimensionality control."""
    allowed_tasks = {"RETRIEVAL_DOCUMENT", "RETRIEVAL_QUERY"}
    if task_type not in allowed_tasks:
        raise ValidationFailed(f"Invalid task_type '{task_type}'. Must be one of {allowed_tasks}")

    if not texts:
        return []

    settings = get_settings()
    client = get_client()
    model = settings.embedding_model
    output_dim = settings.embedding_dim

    results: list[list[float]] = []

    for i in range(0, len(texts), MAX_BATCH_SIZE):
        batch = texts[i : i + MAX_BATCH_SIZE]
        start_time = time.monotonic()

        config = types.EmbedContentConfig(
            task_type=task_type,
            output_dimensionality=output_dim,
        )

        def _do_embed(
            b: list[str] = batch,
            c: types.EmbedContentConfig = config,
        ) -> types.EmbedContentResponse:
            return client.models.embed_content(
                model=model,
                contents=b,
                config=c,
            )

        resp: types.EmbedContentResponse = _call_with_retry(_do_embed, "embed_texts")

        latency_ms = int((time.monotonic() - start_time) * 1000)
        log_event(
            "gemini_embed",
            model=model,
            batch_count=len(batch),
            total_chars=sum(len(t) for t in batch),
            latency_ms=latency_ms,
        )

        for emb in resp.embeddings or []:
            vec = list(emb.values or [])
            # L2-normalize vectors when dimensionality is reduced below native 768
            if output_dim < 768:
                vec = l2_normalize(vec)
            results.append(vec)

    return results


def generate_json(
    system_prompt: str,
    user_prompt: str,
) -> GenerationResult:
    """Generate structured JSON adhering to settings, returning text and token usage."""
    settings = get_settings()
    client = get_client()
    model = settings.generation_model

    config = types.GenerateContentConfig(
        system_instruction=system_prompt,
        temperature=0.2,
        response_mime_type="application/json",
        max_output_tokens=1024,
        http_options=types.HttpOptions(timeout=30000),
    )

    start_time = time.monotonic()

    def _do_generate() -> types.GenerateContentResponse:
        return client.models.generate_content(
            model=model,
            contents=user_prompt,
            config=config,
        )

    response: types.GenerateContentResponse = _call_with_retry(_do_generate, "generate_json")

    latency_ms = int((time.monotonic() - start_time) * 1000)
    result_text = response.text or ""

    input_tokens = 0
    output_tokens = 0
    if response.usage_metadata:
        input_tokens = response.usage_metadata.prompt_token_count or 0
        output_tokens = response.usage_metadata.candidates_token_count or 0

    log_event(
        "gemini_generate",
        model=model,
        system_len=len(system_prompt),
        user_len=len(user_prompt),
        output_len=len(result_text),
        latency_ms=latency_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )

    return GenerationResult(
        text=result_text,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        model=model,
    )
