variable "aws_region" {
  description = "AWS region for provisioning dev resources"
  type        = string
  default     = "ap-south-1"
}

variable "env" {
  description = "Target deployment environment name"
  type        = string
  default     = "dev"
}

variable "project" {
  description = "Project name identifier"
  type        = string
  default     = "vaultrag"
}

variable "allowed_origins" {
  description = "Allowed CORS origins for the documents S3 bucket"
  type        = list(string)
  default     = ["http://localhost:5173"]
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency for Lambda functions to protect free tier. Null preserves unreserved pool for accounts with <100 concurrency limit."
  type        = number
  default     = null
}
