from __future__ import annotations

from typing import Any


class AppError(Exception):
    """Base application exception with HTTP status code and stable machine error code."""

    default_status: int = 500
    default_code: str = "internal_error"
    default_message: str = "An unexpected error occurred"

    def __init__(
        self,
        status_or_message: int | str | None = None,
        code: str | None = None,
        message: str | None = None,
        *,
        status: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        if isinstance(status_or_message, int):
            self.status = status_or_message
            self.code = code if code is not None else self.default_code
            self.message = message if message is not None else self.default_message
        elif isinstance(status_or_message, str):
            self.status = status if status is not None else self.default_status
            self.code = code if code is not None else self.default_code
            self.message = status_or_message
        else:
            self.status = status if status is not None else self.default_status
            self.code = code if code is not None else self.default_code
            self.message = message if message is not None else self.default_message

        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }
        if self.details:
            result["error"]["details"] = self.details
        return result

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(status={self.status}, "
            f"code={self.code!r}, message={self.message!r})"
        )


class Unauthorized(AppError):
    default_status = 401
    default_code = "unauthorized"
    default_message = "Authentication required"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            status=self.default_status,
            code=self.default_code,
            message=message or self.default_message,
            details=details,
        )


class Forbidden(AppError):
    default_status = 403
    default_code = "forbidden"
    default_message = "Access denied"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            status=self.default_status,
            code=self.default_code,
            message=message or self.default_message,
            details=details,
        )


class NotFound(AppError):
    default_status = 404
    default_code = "not_found"
    default_message = "Resource not found"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            status=self.default_status,
            code=self.default_code,
            message=message or self.default_message,
            details=details,
        )


class ValidationFailed(AppError):
    default_status = 422
    default_code = "validation_failed"
    default_message = "Validation failed"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            status=self.default_status,
            code=self.default_code,
            message=message or self.default_message,
            details=details,
        )


class QuotaExceeded(AppError):
    default_status = 429
    default_code = "quota_exceeded"
    default_message = "Quota exceeded"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            status=self.default_status,
            code=self.default_code,
            message=message or self.default_message,
            details=details,
        )


class UpstreamError(AppError):
    default_status = 502
    default_code = "upstream_error"
    default_message = "Upstream service error"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            status=self.default_status,
            code=self.default_code,
            message=message or self.default_message,
            details=details,
        )


class Conflict(AppError):
    default_status = 409
    default_code = "conflict"
    default_message = "Resource conflict"

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            status=self.default_status,
            code=self.default_code,
            message=message or self.default_message,
            details=details,
        )
