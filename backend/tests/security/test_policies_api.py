"""Tests for Admin Policies API (GET /admin/policies and PATCH /admin/policies)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from vaultrag.api.app import create_app
from vaultrag.auth.dependencies import clear_tenant_cache
from vaultrag.auth.jwt_verifier import Claims
from vaultrag.context import Role


@pytest.fixture(autouse=True)
def reset_cache() -> None:
    clear_tenant_cache()
    yield
    clear_tenant_cache()


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def _mock_claims(role: Role = Role.admin, tenant_id: str = "acme") -> Claims:
    return Claims(
        sub="usr-test-01",
        email=f"user@{tenant_id}.example.com",
        tenant_id=tenant_id,
        roles=frozenset([role]),
        token_use="id",
        raw_claims={
            "exp": 1800000000,
            "iat": 1700000000,
            "iss": "https://cognito-idp.ap-south-1.amazonaws.com/test",
            "aud": "test-client-id",
        },
    )


class TestPoliciesAuth:
    @patch("vaultrag.auth.dependencies.TenantRepo")
    @patch("vaultrag.auth.dependencies.verify_id_token")
    def test_non_admin_gets_403_on_get_and_patch(
        self,
        mock_verify: MagicMock,
        mock_repo_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_verify.return_value = _mock_claims(role=Role.employee)
        mock_repo = MagicMock()
        mock_repo.get.return_value = {"status": "active"}
        mock_repo_cls.return_value = mock_repo

        # GET /admin/policies
        resp_get = client.get(
            "/admin/policies",
            headers={"Authorization": "Bearer employee.token"},
        )
        assert resp_get.status_code == 403

        # PATCH /admin/policies
        resp_patch = client.patch(
            "/admin/policies",
            json={"pii_mode": "flag"},
            headers={"Authorization": "Bearer employee.token"},
        )
        assert resp_patch.status_code == 403


class TestPoliciesValidation:
    @patch("vaultrag.admin.policies.TenantRepo")
    @patch("vaultrag.auth.dependencies.TenantRepo")
    @patch("vaultrag.auth.dependencies.verify_id_token")
    def test_get_policies_returns_settings(
        self,
        mock_verify: MagicMock,
        mock_auth_repo_cls: MagicMock,
        mock_admin_repo_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_verify.return_value = _mock_claims(role=Role.admin)
        mock_auth_repo = MagicMock()
        mock_auth_repo.get.return_value = {"status": "active"}
        mock_auth_repo_cls.return_value = mock_auth_repo

        current_settings = {
            "pii_mode": "redact",
            "injection_policy": "quarantine_high",
            "min_retrieval_score": 0.35,
            "min_faithfulness": 0.6,
            "daily_query_quota": 200,
            "cache_enabled": True,
            "retain_original_files": True,
            "settings_version": 1,
        }
        mock_admin_repo = MagicMock()
        mock_admin_repo.get.return_value = {"settings": current_settings}
        mock_admin_repo_cls.return_value = mock_admin_repo

        resp = client.get(
            "/admin/policies",
            headers={"Authorization": "Bearer admin.token"},
        )
        assert resp.status_code == 200
        assert resp.json() == current_settings

    @patch("vaultrag.admin.policies.TenantRepo")
    @patch("vaultrag.auth.dependencies.TenantRepo")
    @patch("vaultrag.auth.dependencies.verify_id_token")
    def test_patch_rejects_unknown_keys(
        self,
        mock_verify: MagicMock,
        mock_auth_repo_cls: MagicMock,
        mock_admin_repo_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_verify.return_value = _mock_claims(role=Role.admin)
        mock_auth_repo = MagicMock()
        mock_auth_repo.get.return_value = {"status": "active"}
        mock_auth_repo_cls.return_value = mock_auth_repo

        resp = client.patch(
            "/admin/policies",
            json={"unknown_key": "some_value"},
            headers={"Authorization": "Bearer admin.token"},
        )
        assert resp.status_code == 422
        assert "Unknown settings key" in resp.text

    @pytest.mark.parametrize(
        ("invalid_payload", "error_substring"),
        [
            ({"pii_mode": "invalid_mode"}, "Invalid pii_mode"),
            ({"injection_policy": "invalid_inj"}, "Invalid injection_policy"),
            ({"min_retrieval_score": 1.5}, "min_retrieval_score must be between 0.0 and 1.0"),
            ({"min_retrieval_score": -0.1}, "min_retrieval_score must be between 0.0 and 1.0"),
            ({"min_faithfulness": 2.0}, "min_faithfulness must be between 0.0 and 1.0"),
            ({"daily_query_quota": 0}, "daily_query_quota must be an integer between 1 and 10000"),
            (
                {"daily_query_quota": 20000},
                "daily_query_quota must be an integer between 1 and 10000",
            ),
            ({"daily_query_quota": "fifty"}, "daily_query_quota must be an integer"),
            ({"cache_enabled": "not_a_bool"}, "cache_enabled must be a boolean"),
            ({"retain_original_files": "false"}, "retain_original_files must be a boolean"),
        ],
    )
    @patch("vaultrag.admin.policies.TenantRepo")
    @patch("vaultrag.auth.dependencies.TenantRepo")
    @patch("vaultrag.auth.dependencies.verify_id_token")
    def test_patch_field_validations(
        self,
        mock_verify: MagicMock,
        mock_auth_repo_cls: MagicMock,
        mock_admin_repo_cls: MagicMock,
        invalid_payload: dict,
        error_substring: str,
        client: TestClient,
    ) -> None:
        mock_verify.return_value = _mock_claims(role=Role.admin)
        mock_auth_repo = MagicMock()
        mock_auth_repo.get.return_value = {"status": "active"}
        mock_auth_repo_cls.return_value = mock_auth_repo

        resp = client.patch(
            "/admin/policies",
            json=invalid_payload,
            headers={"Authorization": "Bearer admin.token"},
        )
        assert resp.status_code == 422
        assert error_substring in resp.text

    @patch("vaultrag.admin.policies.TenantRepo")
    @patch("vaultrag.auth.dependencies.TenantRepo")
    @patch("vaultrag.auth.dependencies.verify_id_token")
    def test_patch_success_and_version_bump(
        self,
        mock_verify: MagicMock,
        mock_auth_repo_cls: MagicMock,
        mock_admin_repo_cls: MagicMock,
        client: TestClient,
    ) -> None:
        mock_verify.return_value = _mock_claims(role=Role.admin)
        mock_auth_repo = MagicMock()
        mock_auth_repo.get.return_value = {"status": "active"}
        mock_auth_repo_cls.return_value = mock_auth_repo

        mock_admin_repo = MagicMock()
        mock_admin_repo.update_settings.return_value = {
            "pii_mode": "block",
            "retain_original_files": False,
            "daily_query_quota": 500,
            "settings_version": 2,
        }
        mock_admin_repo_cls.return_value = mock_admin_repo

        resp = client.patch(
            "/admin/policies",
            json={"pii_mode": "block", "retain_original_files": False, "daily_query_quota": 500},
            headers={"Authorization": "Bearer admin.token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["pii_mode"] == "block"
        assert data["retain_original_files"] is False
        assert data["settings_version"] == 2
        mock_admin_repo.update_settings.assert_called_once_with(
            "acme",
            {"pii_mode": "block", "retain_original_files": False, "daily_query_quota": 500},
        )
