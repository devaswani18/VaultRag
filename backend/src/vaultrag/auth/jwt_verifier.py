from __future__ import annotations

import contextlib
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from vaultrag.config import get_settings
from vaultrag.context import Role
from vaultrag.errors import Unauthorized

logger = logging.getLogger(__name__)

TENANT_ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
MAX_TOKEN_BYTES = 8192
JWKS_CACHE_TTL_SECS = 3600.0  # 1 hour cache
JWKS_MIN_REFRESH_INTERVAL_SECS = 300.0  # At most once per 5 minutes on unknown kid

_JWKS_CACHE: dict[str, Any] = {}
_JWKS_CACHE_EXPIRY: float = 0.0
_JWKS_LAST_REFRESH: float = 0.0


@dataclass(frozen=True)
class Claims:
    """Parsed and verified JWT claims."""

    sub: str
    email: str
    tenant_id: str
    roles: frozenset[Role]
    token_use: str
    raw_claims: dict[str, Any]


def clear_jwks_cache() -> None:
    """Clear in-memory JWKS cache (used in tests)."""
    global _JWKS_CACHE, _JWKS_CACHE_EXPIRY, _JWKS_LAST_REFRESH
    _JWKS_CACHE = {}
    _JWKS_CACHE_EXPIRY = 0.0
    _JWKS_LAST_REFRESH = 0.0


def _fetch_jwks(jwks_url: str) -> dict[str, Any]:
    """Fetch JWKS keys from issuer URL."""
    try:
        resp = httpx.get(jwks_url, timeout=10.0)
        resp.raise_for_status()
        data = resp.json()
        keys = data.get("keys", [])
        return {k["kid"]: k for k in keys if "kid" in k}
    except Exception as e:
        logger.error("Failed to fetch JWKS from %s: %s", jwks_url, type(e).__name__)
        raise Unauthorized(
            "Unable to fetch public verification keys from identity provider"
        ) from None


def get_jwks(jwks_url: str, force_refresh: bool = False) -> dict[str, Any]:
    """Retrieve JWKS with in-memory caching and rate-limited refresh."""
    global _JWKS_CACHE, _JWKS_CACHE_EXPIRY, _JWKS_LAST_REFRESH
    now = time.monotonic()

    if force_refresh:
        # Rate limit refreshes to at most once per 5 minutes
        if now - _JWKS_LAST_REFRESH < JWKS_MIN_REFRESH_INTERVAL_SECS and _JWKS_CACHE:
            return _JWKS_CACHE
        keys_dict = _fetch_jwks(jwks_url)
        _JWKS_CACHE = keys_dict
        _JWKS_CACHE_EXPIRY = now + JWKS_CACHE_TTL_SECS
        _JWKS_LAST_REFRESH = now
        return _JWKS_CACHE

    if _JWKS_CACHE and now < _JWKS_CACHE_EXPIRY:
        return _JWKS_CACHE

    keys_dict = _fetch_jwks(jwks_url)
    _JWKS_CACHE = keys_dict
    _JWKS_CACHE_EXPIRY = now + JWKS_CACHE_TTL_SECS
    _JWKS_LAST_REFRESH = now
    return _JWKS_CACHE


def verify_id_token(
    token: str,
    expected_issuer: str | None = None,
    expected_client_id: str | None = None,
) -> Claims:
    """Verify Cognito ID token signature, expiration, claims, and tenant scoping.

    Steps:
      1. Reject tokens over 8 KB.
      2. Read header kid and alg; accept ONLY RS256.
      3. Fetch and cache JWKS from the issuer URL.
      4. Verify signature, exp, iat, iss, aud, and token_use == "id".
      5. Extract sub, email, custom:tenant_id, cognito:groups -> roles.
      6. Reject if tenant is missing/invalid or roles is empty.
    """
    if not isinstance(token, str):
        raise Unauthorized("Token must be a string")

    # 1. Reject tokens over 8 KB
    if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise Unauthorized("Token exceeds maximum allowed size of 8 KB")

    # 2. Inspect header: accept ONLY RS256
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception as e:
        raise Unauthorized(f"Malformed token header: {e}") from None

    alg = unverified_header.get("alg")
    if alg != "RS256":
        raise Unauthorized(f"Unsupported algorithm '{alg}'. Only RS256 is accepted")

    kid = unverified_header.get("kid")
    if not kid:
        raise Unauthorized("Token header missing 'kid'")

    # Determine expected issuer & audience
    settings = get_settings()
    issuer = (
        expected_issuer
        or f"https://cognito-idp.{settings.aws_region}.amazonaws.com/{settings.cognito_user_pool_id}"
    )
    client_id = expected_client_id or settings.cognito_client_id
    jwks_url = f"{issuer.rstrip('/')}/.well-known/jwks.json"

    # 3. Look up key in JWKS cache; refresh once if kid not found
    keys = get_jwks(jwks_url)
    if kid not in keys:
        keys = get_jwks(jwks_url, force_refresh=True)

    if kid not in keys:
        raise Unauthorized(f"Key with kid '{kid}' not found in identity provider JWKS")

    jwk_dict = keys[kid]
    try:
        public_key = RSAAlgorithm.from_jwk(jwk_dict)
    except Exception as e:
        raise Unauthorized(f"Invalid public key in JWKS: {e}") from None

    # 4. Verify signature and claims (leeway 10s for clock skew)
    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=issuer,
            audience=client_id,
            leeway=10,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
    except jwt.ExpiredSignatureError:
        raise Unauthorized("Token has expired") from None
    except jwt.InvalidAudienceError:
        raise Unauthorized("Invalid token audience") from None
    except jwt.InvalidIssuerError:
        raise Unauthorized("Invalid token issuer") from None
    except jwt.PyJWTError as e:
        raise Unauthorized(f"Token verification failed: {e}") from None

    # Verify token_use == "id"
    token_use = payload.get("token_use")
    if token_use != "id":  # noqa: S105
        raise Unauthorized(f"Invalid token_use '{token_use}'. Expected 'id' token")

    # 5. Extract sub, email, custom:tenant_id, cognito:groups
    sub = payload.get("sub")
    if not sub:
        raise Unauthorized("Missing 'sub' claim in token")

    email = payload.get("email", "")

    tenant_id = payload.get("custom:tenant_id")
    if not tenant_id or not isinstance(tenant_id, str) or not TENANT_ID_REGEX.match(tenant_id):
        raise Unauthorized(f"Missing or invalid 'custom:tenant_id' claim: '{tenant_id}'")

    raw_groups = payload.get("cognito:groups", [])
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]

    # Intersect with known Role values; ignore unknown groups
    matched_roles: set[Role] = set()
    for g in raw_groups:
        if isinstance(g, str):
            with contextlib.suppress(ValueError):
                matched_roles.add(Role(g.lower()))

    if not matched_roles:
        raise Unauthorized("User has no recognized role assignments")

    return Claims(
        sub=sub,
        email=email,
        tenant_id=tenant_id,
        roles=frozenset(matched_roles),
        token_use=token_use,
        raw_claims=payload,
    )
