output "tenants_table_name" {
  description = "Name of the DynamoDB tenants table"
  value       = aws_dynamodb_table.tenants.name
}

output "documents_table_name" {
  description = "Name of the DynamoDB documents table"
  value       = aws_dynamodb_table.documents.name
}

output "audit_table_name" {
  description = "Name of the DynamoDB audit table"
  value       = aws_dynamodb_table.audit.name
}

output "usage_table_name" {
  description = "Name of the DynamoDB usage table"
  value       = aws_dynamodb_table.usage.name
}

output "gaps_table_name" {
  description = "Name of the DynamoDB gaps table"
  value       = aws_dynamodb_table.gaps.name
}

output "docs_bucket_name" {
  description = "Name of the S3 documents bucket"
  value       = aws_s3_bucket.docs.id
}

output "artifacts_bucket_name" {
  description = "Name of the S3 artifacts bucket"
  value       = aws_s3_bucket.artifacts.id
}

output "table_arns" {
  description = "Map of all DynamoDB table ARNs"
  value = {
    tenants   = aws_dynamodb_table.tenants.arn
    documents = aws_dynamodb_table.documents.arn
    audit     = aws_dynamodb_table.audit.arn
    usage     = aws_dynamodb_table.usage.arn
    gaps      = aws_dynamodb_table.gaps.arn
  }
}

output "user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.users.id
}

output "client_id" {
  description = "Cognito User Pool Client ID"
  value       = aws_cognito_user_pool_client.client.id
}

output "cognito_issuer_url" {
  description = "Cognito OIDC Issuer URL"
  value       = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.users.id}"
}

output "cognito_jwks_url" {
  description = "Cognito JWKS public keys endpoint URL"
  value       = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.users.id}/.well-known/jwks.json"
}

output "web_url" {
  description = "Public HTTPS CloudFront URL for the VaultRAG frontend"
  value       = "https://${aws_cloudfront_distribution.web.domain_name}"
}

output "distribution_id" {
  description = "CloudFront distribution ID for frontend static site"
  value       = aws_cloudfront_distribution.web.id
}

output "site_bucket_name" {
  description = "Name of the private S3 bucket hosting frontend static assets"
  value       = aws_s3_bucket.web.id
}
