from __future__ import annotations

from vaultrag.errors import (
    AppError,
    Conflict,
    Forbidden,
    NotFound,
    QuotaExceeded,
    Unauthorized,
    UpstreamError,
    ValidationFailed,
)


def test_errors_status_codes_and_payload() -> None:
    cases = [
        (Unauthorized(), 401, "unauthorized", "Authentication required"),
        (Forbidden(), 403, "forbidden", "Access denied"),
        (NotFound(), 404, "not_found", "Resource not found"),
        (ValidationFailed(), 422, "validation_failed", "Validation failed"),
        (QuotaExceeded(), 429, "quota_exceeded", "Quota exceeded"),
        (UpstreamError(), 502, "upstream_error", "Upstream service error"),
        (Conflict(), 409, "conflict", "Resource conflict"),
        (
            AppError(500, "internal_error", "Custom internal error"),
            500,
            "internal_error",
            "Custom internal error",
        ),
    ]

    for err, expected_status, expected_code, expected_msg in cases:
        assert err.status == expected_status
        assert err.code == expected_code
        assert err.message == expected_msg

        d = err.to_dict()
        assert d["error"]["code"] == expected_code
        assert d["error"]["message"] == expected_msg


def test_error_details() -> None:
    err = ValidationFailed("Field 'email' invalid", details={"field": "email"})
    assert err.details == {"field": "email"}
    d = err.to_dict()
    assert d["error"]["details"] == {"field": "email"}
