# ==============================================================================
# VaultRAG Ingestion: Lambda Function & S3 Event Trigger (Zero-Cost / Least-Privilege)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. CloudWatch Log Group with 7-Day Retention
# ------------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "lambda_ingest" {
  name              = "/aws/lambda/${local.name_prefix}-ingest"
  retention_in_days = 7
}

# ------------------------------------------------------------------------------
# 2. IAM Role & Least-Privilege Policy
# ------------------------------------------------------------------------------
resource "aws_iam_role" "lambda_ingest" {
  name = "${local.name_prefix}-ingest-role"

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

resource "aws_iam_role_policy" "lambda_ingest" {
  name = "${local.name_prefix}-ingest-least-privilege"
  role = aws_iam_role.lambda_ingest.id

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
        Resource = "${aws_cloudwatch_log_group.lambda_ingest.arn}:*"
      },
      # 2. DynamoDB: Scoped strictly to documents table only (no Scan permission)
      {
        Sid    = "DynamoDBDocumentsAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:ConditionCheckItem"
        ]
        Resource = [
          aws_dynamodb_table.documents.arn,
          "${aws_dynamodb_table.documents.arn}/*"
        ]
      },
      # 3. S3 Documents Bucket: GetObject and HeadObject restricted to uploads/*
      {
        Sid    = "S3DocumentsReadAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:HeadObject"
        ]
        Resource = "${aws_s3_bucket.docs.arn}/uploads/*"
      },
      # 4. SSM Parameter Store: SecureString secrets under project prefix
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
# 3. Lambda Function (Python 3.12 / ARM64 / 1024 MB / 300s timeout / Same ZIP)
# ------------------------------------------------------------------------------
# NOTE ON CONCURRENCY:
# Reserved concurrency is NOT set because new AWS accounts have low default service
# concurrency quotas (typically 10-50 total across all functions in the region).
# Setting reserved concurrency could exhaust the regional quota for other workloads.
resource "aws_lambda_function" "ingest" {
  function_name    = "${local.name_prefix}-ingest"
  role             = aws_iam_role.lambda_ingest.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  memory_size      = 1024
  timeout          = 300
  handler          = "vaultrag.ingest.handler.handler"
  s3_bucket        = aws_s3_bucket.artifacts.id
  s3_key           = aws_s3_object.lambda_zip.key
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  environment {
    variables = {
      ENV               = var.env
      DOCUMENTS_TABLE   = aws_dynamodb_table.documents.name
      DOCS_BUCKET       = aws_s3_bucket.docs.id
      SSM_PARAM_PREFIX  = "/${var.project}/${var.env}"
      GEMINI_MODEL      = "gemini-3.5-flash-lite"
      EMBEDDING_MODEL   = "gemini-embedding-001"
      EMBEDDING_DIM     = "768"
      QDRANT_COLLECTION = "vaultrag_chunks"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda_ingest,
    aws_iam_role_policy.lambda_ingest
  ]
}

# ------------------------------------------------------------------------------
# 4. Lambda Permission for S3 Invocations
# ------------------------------------------------------------------------------
resource "aws_lambda_permission" "s3_ingest" {
  statement_id   = "AllowS3BucketNotification"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.ingest.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.docs.arn
  source_account = data.aws_caller_identity.current.account_id
}

# ------------------------------------------------------------------------------
# 5. S3 Bucket Notification for uploads/
# ------------------------------------------------------------------------------
resource "aws_s3_bucket_notification" "docs_ingest" {
  bucket = aws_s3_bucket.docs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.ingest.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "uploads/"
  }

  depends_on = [aws_lambda_permission.s3_ingest]
}
