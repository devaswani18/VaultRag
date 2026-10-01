from __future__ import annotations

import io
import json
import logging

from vaultrag.logging_utils import (
    JSONFormatter,
    RedactingFilter,
    log_event,
    request_id_var,
    tenant_id_var,
    user_id_var,
)


def _setup_capture_logger(name: str = "test_redact") -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    handler = logging.StreamHandler(stream)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    return logger, stream


def test_logging_redacts_token_email_and_aadhaar() -> None:
    logger, stream = _setup_capture_logger("test_privacy")

    token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5nV3i"
    email = "researcher.john@defense-agency.gov.in"
    aadhaar_num = "987654321098"
    aadhaar_spaced = "9876 5432 1098"
    aws_key = "AKIA1111222233334444"

    logger.info(
        "User action with token %s and email %s and id %s / %s and key %s",
        token,
        email,
        aadhaar_num,
        aadhaar_spaced,
        aws_key,
    )

    output = stream.getvalue()
    parsed = json.loads(output)

    # Prove raw values are NEVER in the log output
    assert token not in output
    assert email not in output
    assert aadhaar_num not in output
    assert aadhaar_spaced not in output
    assert aws_key not in output

    # Prove redaction placeholders are present
    assert "[REDACTED]" in parsed["msg"]
    assert "[REDACTED_EMAIL]" in parsed["msg"]
    assert "[REDACTED_NUMBER]" in parsed["msg"]
    assert "[REDACTED_AWS_KEY]" in parsed["msg"]


def test_logging_redacts_sensitive_keys_in_extra() -> None:
    logger, stream = _setup_capture_logger("test_keys")

    logger.info(
        "Login attempted",
        extra={
            "password": "SuperSecretPassword123!",
            "api_key": "my-dummy-api-key",  # gitleaks:allow
            "token": "tok_xyz789",
            "authorization": "Bearer internal-token",
            "safe_field": "public_data",
        },
    )

    output = stream.getvalue()
    parsed = json.loads(output)

    assert "SuperSecretPassword123!" not in output
    assert "my-dummy-api-key" not in output
    assert "tok_xyz789" not in output
    assert parsed["password"] == "[REDACTED]"
    assert parsed["api_key"] == "[REDACTED]"
    assert parsed["token"] == "[REDACTED]"
    assert parsed["safe_field"] == "public_data"


def test_logging_contextvars_and_log_event() -> None:
    token_req = request_id_var.set("req-test-999")
    token_tenant = tenant_id_var.set("tenant-dev-1")
    token_user = user_id_var.set("user-bob-42")

    try:
        from vaultrag.logging_utils import _LOGGER

        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.addFilter(RedactingFilter())
        handler.setFormatter(JSONFormatter())

        old_handlers = list(_LOGGER.handlers)
        _LOGGER.handlers.clear()
        _LOGGER.addHandler(handler)

        try:
            log_event(
                "document_uploaded",
                doc_id="doc-abc",
                email="secret.agent@vault.internal",
                aadhaar="555566667777",
            )
            output = stream.getvalue().strip()
            parsed = json.loads(output)

            assert parsed["request_id"] == "req-test-999"
            assert parsed["tenant_id"] == "tenant-dev-1"
            assert parsed["user_id"] == "user-bob-42"
            assert parsed["doc_id"] == "doc-abc"
            assert parsed["msg"] == "document_uploaded"
            assert "secret.agent@vault.internal" not in output
            assert "555566667777" not in output
            assert parsed["email"] == "[REDACTED_EMAIL]"
            assert parsed["aadhaar"] == "[REDACTED_NUMBER]"
        finally:
            _LOGGER.handlers = old_handlers
    finally:
        request_id_var.reset(token_req)
        tenant_id_var.reset(token_tenant)
        user_id_var.reset(token_user)
