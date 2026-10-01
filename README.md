# VaultRAG

VaultRAG is a cloud-native, multi-tenant RAG (Retrieval-Augmented Generation) platform engineered with a strict security Trust Layer to enforce tenant isolation, PII sanitization, prompt injection defense, and cryptographic auditability under a zero-cost architecture constraint.

> **Status:** Under construction

## Features
- Strict tenant boundary isolation at ingestion, indexing, and retrieval.
- Multi-tier Trust Layer: PII scrubbing, injection detection, and audit hashchains.
- Zero-cost serverless deployment on AWS Lambda (arm64) and free-tier cloud services.

## Architecture
- **Backend:** FastAPI + Mangum on AWS Lambda arm64 (Python 3.12).
- **Authentication:** Amazon Cognito User Pools with tenant and role claims.
- **Storage & Vector:** DynamoDB (on-demand), S3, Qdrant Cloud Free Tier.
- **AI Engine:** Google Gemini API (free tier) for embeddings and generation.
- **Frontend:** React + Vite + TypeScript.
- **IaC:** Terraform with GitHub Actions OIDC.

## Quick Start
Refer to backend and frontend documentation for local development setup.

## Security
- Tenant-scoped vector queries and strict ACL verification.
- Zero credentials or PII in logs; SSM SecureString for secrets.
- Gitleaks secrets scanning in pre-commit and CI.

## Deployment
Automated via Terraform and GitHub Actions OIDC workflows.
