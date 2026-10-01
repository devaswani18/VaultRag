variable "aws_region" {
  description = "AWS region for provisioning bootstrap resources"
  type        = string
  default     = "ap-south-1"
}

variable "github_repo" {
  description = "Target GitHub repository in owner/repo format for OIDC trust"
  type        = string
  default     = "devaswani18/VaultRag"
}

variable "alert_email" {
  description = "Email address to receive AWS Budget cost alerts"
  type        = string
}

variable "project" {
  description = "Project name identifier used for prefixing resource names"
  type        = string
  default     = "vaultrag"
}
