# ==============================================================================
# DynamoDB Storage Tables (Pay-Per-Request, Zero-Cost Base)
# ==============================================================================
# All tables use PAY_PER_REQUEST on-demand billing, default AWS-owned encryption,
# point-in-time recovery disabled to avoid storage cost, and deletion protection
# disabled for dev environment.

# 1. Tenants Table
# Documented Item Schema:
# - tenant_id (PK, S): Unique tenant identifier (UUID or slug)
# - name (S): Human-readable tenant name
# - status (S): ACTIVE | SUSPENDED
# - settings (M): Map containing:
#     - pii_mode (S): OFF | REDACT | BLOCK
#     - injection_policy (S): LOG | BLOCK
#     - min_retrieval_score (N): Similarity score threshold
#     - min_faithfulness (N): Faithfulness check threshold
#     - daily_query_quota (N): Daily query ceiling
#     - cache_enabled (BOOL): Semantic cache flag
# - created_at (S): ISO-8601 UTC timestamp
resource "aws_dynamodb_table" "tenants" {
  name                        = "${local.name_prefix}-tenants"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "tenant_id"
  deletion_protection_enabled = false

  attribute {
    name = "tenant_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = true
  }
}

# 2. Documents Table
# Documented Item Schema:
# - tenant_id (PK, S): Partition key for tenant isolation
# - doc_id (SK, S): Unique document UUID
# - filename (S): Original uploaded file name
# - content_type (S): MIME type (e.g., application/pdf, text/plain)
# - size_bytes (N): File payload size in bytes
# - status (S): PENDING_UPLOAD | PROCESSING | READY | QUARANTINED | FAILED | DELETED
# - visibility (S): TENANT | ROLE | USER
# - allowed_roles (L): List of permitted Cognito role strings
# - allowed_users (L): List of permitted user UUIDs
# - owner_user_id (S): Cognito sub of uploading user
# - s3_key (S): Object path in S3 documents bucket
# - chunk_count (N): Number of generated chunks indexed in Qdrant
# - pii_summary (M): Detected entity types and sanitization record
# - injection_summary (M): Heuristic/LLM prompt injection analysis
# - error (S): Pipeline failure explanation if status is FAILED
# - created_at (S): ISO-8601 UTC timestamp
# - updated_at (S): ISO-8601 UTC timestamp
resource "aws_dynamodb_table" "documents" {
  name                        = "${local.name_prefix}-documents"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "tenant_id"
  range_key                   = "doc_id"
  deletion_protection_enabled = false

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "doc_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = true
  }
}

# 3. Audit Table (Append-only Cryptographic Hashchain Log)
# Item Schema:
# - tenant_id (PK, S): Partition key
# - seq (SK, N): Monotonically increasing sequence number per tenant
# - action (S): INGEST | RETRIEVE | GENERATE | ERASURE | POLICY_CHANGE
# - actor_user_id (S): Cognito user sub
# - actor_role (S): User role at time of action
# - payload_hash (S): SHA-256 of request payload
# - prev_hash (S): Hash of sequence item (seq - 1)
# - entry_hash (S): SHA-256(prev_hash + seq + action + payload_hash + timestamp)
# - timestamp (S): ISO-8601 UTC timestamp
resource "aws_dynamodb_table" "audit" {
  name                        = "${local.name_prefix}-audit"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "tenant_id"
  range_key                   = "seq"
  deletion_protection_enabled = false

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "seq"
    type = "N"
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = true
  }
}

# 4. Usage Table (Daily Query Quotas & Rate Tracking)
# Item Schema:
# - tenant_id (PK, S): Partition key
# - day (SK, S): Format "YYYY-MM-DD"
# - query_count (N): Total queries served on day
# - token_count (N): Total Gemini tokens consumed
# - expires_at (N): Epoch timestamp for automatic DynamoDB TTL expiration
resource "aws_dynamodb_table" "usage" {
  name                        = "${local.name_prefix}-usage"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "tenant_id"
  range_key                   = "day"
  deletion_protection_enabled = false

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "day"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = true
  }
}

# 5. Gaps Table (Knowledge Gap Detection & Feedback Loop)
# Item Schema:
# - tenant_id (PK, S): Partition key
# - ts_id (SK, S): Timestamp + query identifier
# - query_text (S): User query that yielded sub-threshold retrieval
# - top_score (N): Highest chunk similarity score found
# - expires_at (N): Epoch timestamp for TTL expiration
resource "aws_dynamodb_table" "gaps" {
  name                        = "${local.name_prefix}-gaps"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "tenant_id"
  range_key                   = "ts_id"
  deletion_protection_enabled = false

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "ts_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = true
  }
}

# 6. Conversations Table (Privacy-Preserving User Conversation History)
# Item Schema:
# - pk (PK, S): Format "<tenant_id>#<user_id>" (strictly derived from authenticated context)
# - sk (SK, S): Format "C#<conversation_id>" (conversation metadata) or "M#<conversation_id>#<seq>" (message)
# - expires_at (N): Epoch timestamp for automatic DynamoDB TTL expiration
resource "aws_dynamodb_table" "conversations" {
  name                        = "${local.name_prefix}-conversations"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = false

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled = true
  }
}

# ==============================================================================
# S3 Documents Bucket (Raw Document Ingestion & Storage)
# ==============================================================================
# Versioning is intentionally NOT enabled on the documents bucket.
# Under the zero-cost architecture and GDPR right-to-erasure requirements,
# non-versioned storage ensures that when a document deletion or tenant erasure
# is executed, files are permanently deleted immediately without accumulating
# billable noncurrent versions or delete-marker overhead.

resource "aws_s3_bucket" "docs" {
  bucket        = "${var.project}-docs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "docs" {
  bucket = aws_s3_bucket.docs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "docs" {
  bucket = aws_s3_bucket.docs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "docs_enforce_tls" {
  bucket = aws_s3_bucket.docs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.docs.arn,
          "${aws_s3_bucket.docs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_cors_configuration" "docs" {
  bucket = aws_s3_bucket.docs.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["POST", "GET", "HEAD"]
    allowed_origins = local.all_allowed_origins
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "docs" {
  bucket = aws_s3_bucket.docs.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "expire-temporary-uploads"
    status = "Enabled"

    filter {
      prefix = "tmp/"
    }

    expiration {
      days = 1
    }
  }
}

# ==============================================================================
# S3 Artifacts Bucket (Lambda Deployment Packages & Artifacts)
# ==============================================================================
# Stores zipped Lambda function packages. Lifecycled to 30 days to avoid
# historical build accumulation.

resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project}-artifacts-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts_enforce_tls" {
  bucket = aws_s3_bucket.artifacts.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLSRequestsOnly"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-build-artifacts"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }
  }
}
