from __future__ import annotations

import json
import time
from typing import Any

import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import Response
from jwt.algorithms import RSAAlgorithm

from vaultrag.auth.jwt_verifier import clear_jwks_cache, verify_id_token
from vaultrag.context import Role
from vaultrag.errors import Unauthorized

TEST_ISSUER = "https://cognito-idp.ap-south-1.amazonaws.com/ap-south-1_test123"
TEST_CLIENT_ID = "test-client-id-abc"
TEST_KID = "test-kid-1"


@pytest.fixture(scope="module")
def rsa_keys() -> tuple[rsa.RSAPrivateKey, dict[str, Any]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = TEST_KID
    jwk_dict["alg"] = "RS256"
    jwk_dict["use"] = "sig"
    return private_key, jwk_dict


@pytest.fixture(autouse=True)
def reset_jwks() -> None:
    clear_jwks_cache()
    yield
    clear_jwks_cache()


def make_token(
    private_key: rsa.RSAPrivateKey,
    *,
    sub: str = "usr-12345",
    email: str = "alice@acme.example.com",
    tenant_id: str | None = "acme-corp",
    groups: list[str] | None = None,
    token_use: str = "id",  # noqa: S107
    issuer: str = TEST_ISSUER,
    audience: str = TEST_CLIENT_ID,
    kid: str | None = TEST_KID,
    alg: str = "RS256",
    exp_delta: int = 3600,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": sub,
        "email": email,
        "token_use": token_use,
        "iss": issuer,
        "aud": audience,
        "iat": now - 10,
        "exp": now + exp_delta,
    }
    if tenant_id is not None:
        payload["custom:tenant_id"] = tenant_id
    if groups is not None:
        payload["cognito:groups"] = groups
    else:
        payload["cognito:groups"] = ["employee"]
    if extra_claims:
        payload.update(extra_claims)

    headers = {}
    if kid is not None:
        headers["kid"] = kid

    if alg == "none":
        return jwt.encode(payload, key="", algorithm="none", headers=headers)

    return jwt.encode(payload, key=private_key, algorithm=alg, headers=headers)


@respx.mock
def test_verify_valid_token(rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]]) -> None:
    priv, jwk = rsa_keys
    jwks_url = f"{TEST_ISSUER}/.well-known/jwks.json"
    respx.get(jwks_url).mock(return_value=Response(200, json={"keys": [jwk]}))

    token = make_token(priv, tenant_id="acme-corp", groups=["admin", "employee"])
    claims = verify_id_token(
        token,
        expected_issuer=TEST_ISSUER,
        expected_client_id=TEST_CLIENT_ID,
    )

    assert claims.sub == "usr-12345"
    assert claims.email == "alice@acme.example.com"
    assert claims.tenant_id == "acme-corp"
    assert Role.admin in claims.roles
    assert Role.employee in claims.roles
    assert claims.token_use == "id"


@respx.mock
def test_verify_expired_token(rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]]) -> None:
    priv, jwk = rsa_keys
    respx.get(f"{TEST_ISSUER}/.well-known/jwks.json").mock(
        return_value=Response(200, json={"keys": [jwk]})
    )

    # Expired 1 hour ago
    token = make_token(priv, exp_delta=-3600)
    with pytest.raises(Unauthorized, match="expired"):
        verify_id_token(token, expected_issuer=TEST_ISSUER, expected_client_id=TEST_CLIENT_ID)


@respx.mock
def test_verify_wrong_audience(rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]]) -> None:
    priv, jwk = rsa_keys
    respx.get(f"{TEST_ISSUER}/.well-known/jwks.json").mock(
        return_value=Response(200, json={"keys": [jwk]})
    )

    token = make_token(priv, audience="wrong-client-id")
    with pytest.raises(Unauthorized, match="Invalid token audience"):
        verify_id_token(token, expected_issuer=TEST_ISSUER, expected_client_id=TEST_CLIENT_ID)


@respx.mock
def test_verify_wrong_issuer(rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]]) -> None:
    priv, jwk = rsa_keys
    respx.get(f"{TEST_ISSUER}/.well-known/jwks.json").mock(
        return_value=Response(200, json={"keys": [jwk]})
    )

    token = make_token(priv, issuer="https://evil-issuer.com")
    with pytest.raises(Unauthorized, match="Invalid token issuer"):
        verify_id_token(token, expected_issuer=TEST_ISSUER, expected_client_id=TEST_CLIENT_ID)


@respx.mock
def test_verify_access_token_rejected(rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]]) -> None:
    priv, jwk = rsa_keys
    respx.get(f"{TEST_ISSUER}/.well-known/jwks.json").mock(
        return_value=Response(200, json={"keys": [jwk]})
    )

    token = make_token(priv, token_use="access")
    with pytest.raises(Unauthorized, match="Expected 'id' token"):
        verify_id_token(token, expected_issuer=TEST_ISSUER, expected_client_id=TEST_CLIENT_ID)


def test_verify_alg_none_rejected(rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]]) -> None:
    priv, _ = rsa_keys
    token = make_token(priv, alg="none")
    with pytest.raises(Unauthorized, match="Unsupported algorithm 'none'"):
        verify_id_token(token, expected_issuer=TEST_ISSUER, expected_client_id=TEST_CLIENT_ID)


def test_verify_hs256_with_public_key_rejected(
    rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]],
) -> None:
    # Attacker attempts algorithm confusion by signing with HS256
    token = jwt.encode(
        {"sub": "attacker", "custom:tenant_id": "acme", "token_use": "id"},
        key="mock-public-key-confusion-secret",
        algorithm="HS256",
        headers={"kid": TEST_KID},
    )

    with pytest.raises(Unauthorized, match="Unsupported algorithm 'HS256'"):
        verify_id_token(token, expected_issuer=TEST_ISSUER, expected_client_id=TEST_CLIENT_ID)


@respx.mock
def test_verify_unknown_kid(rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]]) -> None:
    priv, jwk = rsa_keys
    respx.get(f"{TEST_ISSUER}/.well-known/jwks.json").mock(
        return_value=Response(200, json={"keys": [jwk]})
    )

    token = make_token(priv, kid="unknown-kid-999")
    with pytest.raises(Unauthorized, match="Key with kid 'unknown-kid-999' not found"):
        verify_id_token(token, expected_issuer=TEST_ISSUER, expected_client_id=TEST_CLIENT_ID)


@respx.mock
def test_verify_missing_or_invalid_tenant(
    rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]],
) -> None:
    priv, jwk = rsa_keys
    respx.get(f"{TEST_ISSUER}/.well-known/jwks.json").mock(
        return_value=Response(200, json={"keys": [jwk]})
    )

    # Missing custom:tenant_id
    token_no_tenant = make_token(priv, tenant_id=None)
    with pytest.raises(Unauthorized, match="Missing or invalid 'custom:tenant_id'"):
        verify_id_token(
            token_no_tenant,
            expected_issuer=TEST_ISSUER,
            expected_client_id=TEST_CLIENT_ID,
        )

    # Bad tenant regex (e.g. uppercase / traversal)
    token_bad_tenant = make_token(priv, tenant_id="INVALID_TENANT")
    with pytest.raises(Unauthorized, match="Missing or invalid 'custom:tenant_id'"):
        verify_id_token(
            token_bad_tenant,
            expected_issuer=TEST_ISSUER,
            expected_client_id=TEST_CLIENT_ID,
        )


@respx.mock
def test_verify_unknown_groups_only_rejected(
    rsa_keys: tuple[rsa.RSAPrivateKey, dict[str, Any]],
) -> None:
    priv, jwk = rsa_keys
    respx.get(f"{TEST_ISSUER}/.well-known/jwks.json").mock(
        return_value=Response(200, json={"keys": [jwk]})
    )

    # Unknown groups that do not match Role enum
    token = make_token(priv, groups=["contractor", "guest", "temp"])
    with pytest.raises(Unauthorized, match="User has no recognized role assignments"):
        verify_id_token(token, expected_issuer=TEST_ISSUER, expected_client_id=TEST_CLIENT_ID)


def test_verify_oversized_token() -> None:
    # Token > 8 KB
    giant_string = "A" * 8500
    with pytest.raises(Unauthorized, match="exceeds maximum allowed size of 8 KB"):
        verify_id_token(giant_string)
