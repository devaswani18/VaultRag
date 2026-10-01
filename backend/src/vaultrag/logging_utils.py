from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

# Context variables for request tracing
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
tenant_id_var: ContextVar[str | None] = ContextVar("tenant_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)

# Sensitive keys regex
SENSITIVE_KEY_PATTERN = re.compile(
    r"^(password|secret|token|api_key|authorization)$",
    re.IGNORECASE,
)

# Text redaction regex patterns
BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*")
AWS_KEY_PATTERN = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DIGITS_12_PLUS_PATTERN = re.compile(r"\b\d{12,}\b")
AADHAAR_SPACED_PATTERN = re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")
KEY_VALUE_SECRET_PATTERN = re.compile(
    r'(?i)(["\']?(?:password|secret|token|api_key|authorization)["\']?\s*[:=]\s*["\']?)(?!\[REDACTED\])[^\s,;\'"}]+(["\']?)'
)


def redact_text(text: str) -> str:
    """Mask sensitive patterns in raw text."""
    if not isinstance(text, str):
        return text

    # Redact Bearer tokens
    text = BEARER_TOKEN_PATTERN.sub("Bearer [REDACTED]", text)
    # Redact AWS keys
    text = AWS_KEY_PATTERN.sub("[REDACTED_AWS_KEY]", text)
    # Redact Emails
    text = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
    # Redact 12-digit spaced Aadhaar numbers
    text = AADHAAR_SPACED_PATTERN.sub("[REDACTED_NUMBER]", text)
    # Redact strings of 12+ digits
    text = DIGITS_12_PLUS_PATTERN.sub("[REDACTED_NUMBER]", text)
    # Redact key-value secrets
    text = KEY_VALUE_SECRET_PATTERN.sub(r"\g<1>[REDACTED]\g<2>", text)

    return text


def redact_data(data: Any) -> Any:
    """Recursively mask sensitive keys and patterns in nested data structures."""
    if isinstance(data, dict):
        redacted_dict: dict[str, Any] = {}
        for k, v in data.items():
            str_k = str(k)
            if SENSITIVE_KEY_PATTERN.match(str_k.replace("-", "_")):
                redacted_dict[str_k] = "[REDACTED]"
            else:
                redacted_dict[str_k] = redact_data(v)
        return redacted_dict
    elif isinstance(data, list):
        return [redact_data(item) for item in data]
    elif isinstance(data, str):
        return redact_text(data)
    return data


class RedactingFilter(logging.Filter):
    """Logging filter that ensures record messages and args are redacted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = redact_data(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(redact_data(a) for a in record.args)
        return True


class JSONFormatter(logging.Formatter):
    """Formatter producing single-line JSON log events with context and redaction."""

    def format(self, record: logging.LogRecord) -> str:
        # Determine context fields
        req_id = getattr(record, "request_id", None) or request_id_var.get()
        t_id = getattr(record, "tenant_id", None) or tenant_id_var.get()
        u_id = getattr(record, "user_id", None) or user_id_var.get()

        # Base payload
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "msg": redact_text(record.getMessage()),
            "request_id": req_id,
            "tenant_id": t_id,
            "user_id": u_id,
        }

        # Include custom extra fields if provided
        standard_attrs = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
            "request_id",
            "tenant_id",
            "user_id",
        }
        for attr, value in record.__dict__.items():
            if attr not in standard_attrs and not attr.startswith("_"):
                payload[attr] = redact_data(value)

        # Include exception info if present
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)

        json_str = json.dumps(payload, default=str)
        # Final pass redaction on raw JSON string to guarantee zero leak
        return redact_text(json_str)


def get_logger(name: str = "vaultrag") -> logging.Logger:
    """Configure and return the VaultRAG structured logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        logger.propagate = False
        handler = logging.StreamHandler(sys.stdout)
        handler.addFilter(RedactingFilter())
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    return logger


_LOGGER = get_logger()


def log_event(name: str, level: int = logging.INFO, **fields: Any) -> None:
    """Helper to log a structured event with contextual and redacted fields."""
    _LOGGER.log(level, name, extra=fields)
