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
