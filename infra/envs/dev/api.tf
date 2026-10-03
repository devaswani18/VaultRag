# ==============================================================================
# VaultRAG API: Lambda Function & Function URL (Zero-Cost / Least-Privilege)
# ==============================================================================

variable "lambda_zip_path" {
  description = "Path to the packaged Lambda ZIP distribution"
  type        = string
  default     = "../../../backend/dist/lambda.zip"
}

# ------------------------------------------------------------------------------
# 1. CloudWatch Log Group with 7-Day Retention
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "lambda_api" {
  name              = "/aws/lambda/${local.name_prefix}-api"
  retention_in_days = 7
}

# ------------------------------------------------------------------------------
# 2. IAM Role & Least-Privilege Policy
# ------------------------------------------------------------------------------
resource "aws_iam_role" "lambda_api" {
  name = "${local.name_prefix}-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_api" {
  name = "${local.name_prefix}-api-least-privilege"
  role = aws_iam_role.lambda_api.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # 1. CloudWatch Logs: strictly scoped to its own log group
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.lambda_api.arn}:*"
      },
      # 2. DynamoDB: GetItem, PutItem, UpdateItem, DeleteItem, Query, ConditionCheckItem
      # Strictly scoped to the five project tables (no Scan permission)
      {
        Sid    = "DynamoDBTableAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:ConditionCheckItem"
        ]
        Resource = [
          aws_dynamodb_table.tenants.arn,
          "${aws_dynamodb_table.tenants.arn}/*",
          aws_dynamodb_table.documents.arn,
          "${aws_dynamodb_table.documents.arn}/*",
          aws_dynamodb_table.audit.arn,
          "${aws_dynamodb_table.audit.arn}/*",
          aws_dynamodb_table.usage.arn,
          "${aws_dynamodb_table.usage.arn}/*",
          aws_dynamodb_table.gaps.arn,
          "${aws_dynamodb_table.gaps.arn}/*",
          aws_dynamodb_table.conversations.arn,
          "${aws_dynamodb_table.conversations.arn}/*"
        ]
      },
      # 3. S3 Documents Bucket: Object operations restricted under uploads/*
      {
        Sid    = "S3DocumentsObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.docs.arn}/uploads/*"
      },
      # 4. S3 Documents Bucket: Bucket listing with mandatory prefix condition uploads/*
      {
        Sid    = "S3DocumentsListAccess"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.docs.arn
        Condition = {
          StringLike = {
            "s3:prefix" = ["uploads/*"]
          }
        }
      },
      # 5. SSM Parameter Store: SecureString secrets under project prefix
      {
        Sid    = "SSMParameterAccess"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.project}/${var.env}/*"
      }
    ]
  })
}

# ------------------------------------------------------------------------------
# 3. S3 Deployment Object (Uploads Lambda package to artifacts bucket)
# ------------------------------------------------------------------------------
resource "aws_s3_object" "lambda_zip" {
  bucket = aws_s3_bucket.artifacts.id
  key    = "lambda/${filemd5(var.lambda_zip_path)}.zip"
  source = var.lambda_zip_path
  etag   = filemd5(var.lambda_zip_path)
}

# ------------------------------------------------------------------------------
# 4. Lambda Function (Python 3.12 / ARM64 / 512 MB / 30s timeout)
# ------------------------------------------------------------------------------
resource "aws_lambda_function" "api" {
  function_name                  = "${local.name_prefix}-api"
  role                           = aws_iam_role.lambda_api.arn
  runtime                        = "python3.12"
  architectures                  = ["arm64"]
  memory_size                    = 512
  timeout                        = 30
  handler                        = "vaultrag.api.handler.handler"
  s3_bucket                      = aws_s3_bucket.artifacts.id
  s3_key                         = aws_s3_object.lambda_zip.key
  source_code_hash               = filebase64sha256(var.lambda_zip_path)
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      ENV                  = var.env
      TENANTS_TABLE        = aws_dynamodb_table.tenants.name
      DOCUMENTS_TABLE      = aws_dynamodb_table.documents.name
      AUDIT_TABLE          = aws_dynamodb_table.audit.name
      USAGE_TABLE          = aws_dynamodb_table.usage.name
      GAPS_TABLE           = aws_dynamodb_table.gaps.name
      DOCS_BUCKET          = aws_s3_bucket.docs.id
      ARTIFACTS_BUCKET     = aws_s3_bucket.artifacts.id
      COGNITO_USER_POOL_ID = aws_cognito_user_pool.users.id
      COGNITO_CLIENT_ID    = aws_cognito_user_pool_client.client.id
      SSM_PARAM_PREFIX     = "/${var.project}/${var.env}"
      GEMINI_MODEL         = "gemini-3.5-flash-lite"
      EMBEDDING_MODEL      = "gemini-embedding-001"
      EMBEDDING_DIM        = "768"
      QDRANT_COLLECTION    = "vaultrag_chunks"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_api,
    aws_iam_role_policy.lambda_api
  ]
}

# ------------------------------------------------------------------------------
# 5. Lambda Function URL (Public Endpoint, In-App JWT Verification)
# ------------------------------------------------------------------------------
resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = local.all_allowed_origins
    allow_methods = ["GET", "POST", "PATCH", "DELETE"]
    allow_headers = ["authorization", "content-type", "x-request-id"]
    max_age       = 3600
  }
}

# ------------------------------------------------------------------------------
# 6. Public Invocation Permissions for Lambda Function URL (Dual-Permission Requirement)
# ------------------------------------------------------------------------------
# Statement 1: Grants public invocation of the Lambda Function URL.
resource "aws_lambda_permission" "public_function_url" {
  statement_id           = "FunctionURLAllowPublicAccess"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.api.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

# Statement 2: Grants invocation of the underlying Lambda function for Function URL requests.
# AWS enforces that new Function URLs require both lambda:InvokeFunctionUrl (auth type NONE)
# and lambda:InvokeFunction on the resource-based policy to authorize public incoming invocations.
resource "aws_lambda_permission" "public_function_invoke" {
  statement_id  = "FunctionURLAllowPublicInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "*"
}

# ------------------------------------------------------------------------------
# 7. Outputs
# ------------------------------------------------------------------------------
output "api_url" {
  description = "Public HTTPS endpoint for the VaultRAG API Lambda Function URL"
  value       = aws_lambda_function_url.api.function_url
}
