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
