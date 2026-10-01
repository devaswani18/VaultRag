# ------------------------------------------------------------------------------
# Cognito User Pool & Authentication Resources
# ------------------------------------------------------------------------------
# Free Tier Note:
# AWS Cognito User Pools provides a generous free tier of 50,000 Monthly Active
# Users (MAUs) for users signing in directly with Cognito.
# Verify current pricing and tiers at: https://aws.amazon.com/cognito/pricing/
# ------------------------------------------------------------------------------

resource "aws_cognito_user_pool" "users" {
  name = "${local.name_prefix}-users"

  # Sign-in using email address
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # Strong password policy
  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  # Self sign-up enabled for user self-registration
  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  # Custom immutable attribute for tenant isolation
  schema {
    name                = "tenant_id"
    attribute_data_type = "String"
    mutable             = false
    required            = false

    string_attribute_constraints {
      min_length = "2"
      max_length = "31"
    }
  }

  # MFA configuration: OFF for dev to avoid SMS charges and complexity.
  # In production, MFA should be set to "ON" or "OPTIONAL" using software TOTP.
  mfa_configuration = "OFF"

  # Account recovery using verified email
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
}

# ------------------------------------------------------------------------------
# Public User Pool Client (No client secret for frontend / SPA use)
# ------------------------------------------------------------------------------
resource "aws_cognito_user_pool_client" "client" {
  name         = "${local.name_prefix}-client"
  user_pool_id = aws_cognito_user_pool.users.id

  # Public client (no client secret)
  generate_secret = false

  # Explicit authentication flows
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]

  prevent_user_existence_errors = "ENABLED"

  # Attribute permissions: write is limited to email.
  # read_attributes includes email and custom:tenant_id so custom:tenant_id
  # is present in the issued ID token claims.
  read_attributes = [
    "email",
    "custom:tenant_id",
  ]

  write_attributes = [
    "email",
    "custom:tenant_id",
  ]

  # Token validity: ID = 60m, Access = 60m, Refresh = 7d
  id_token_validity      = 60
  access_token_validity  = 60
  refresh_token_validity = 7

  token_validity_units {
    id_token      = "minutes"
    access_token  = "minutes"
    refresh_token = "days"
  }
}

# ------------------------------------------------------------------------------
# User Groups (Roles for RBAC)
# ------------------------------------------------------------------------------
resource "aws_cognito_user_group" "admin" {
  name         = "admin"
  user_pool_id = aws_cognito_user_pool.users.id
  description  = "Tenant Administrator with full tenant access"
}

resource "aws_cognito_user_group" "manager" {
  name         = "manager"
  user_pool_id = aws_cognito_user_pool.users.id
  description  = "Tenant Manager with document upload and audit inspection access"
}

resource "aws_cognito_user_group" "employee" {
  name         = "employee"
  user_pool_id = aws_cognito_user_pool.users.id
  description  = "Standard tenant employee with search and query access"
}

resource "aws_cognito_user_group" "intern" {
  name         = "intern"
  user_pool_id = aws_cognito_user_pool.users.id
  description  = "Intern with restricted query access"
}
