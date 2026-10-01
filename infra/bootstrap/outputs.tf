output "state_bucket" {
  description = "Name of the S3 bucket created for Terraform remote state"
  value       = aws_s3_bucket.state.id
}

output "plan_role_arn" {
  description = "ARN of the IAM role assumed by GitHub Actions for terraform plan"
  value       = aws_iam_role.gha_plan.arn
}

output "apply_role_arn" {
  description = "ARN of the IAM role assumed by GitHub Actions for terraform apply"
  value       = aws_iam_role.gha_apply.arn
}

output "account_id" {
  description = "AWS account ID where bootstrap resources are provisioned"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS region used for bootstrap resources"
  value       = var.aws_region
}
