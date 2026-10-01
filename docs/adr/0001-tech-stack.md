# ADR 0001: Technology Stack Selection

## Status
Accepted

## Context
VaultRAG is a multi-tenant Retrieval-Augmented Generation (RAG) platform with a zero-trust security architecture. A hard constraint governing the system design is **ZERO COST**: all components must operate strictly within persistent free tiers without incurring operational infrastructure expenses (e.g., no NAT Gateways, no paid RDS/OpenSearch, no paid external APIs). At the same time, the system requires high performance, tenant-isolated vector retrieval, cryptographic audit trails, robust authentication, and enterprise-grade code maintainability.

## Decision
We select the following core technologies, each adhering to the zero-cost and high-security requirements:

1. **Python 3.12**: Delivers modern performance enhancements, strict static typing support, and long-term runtime compatibility on AWS Lambda.
2. **FastAPI + Mangum**: Provides high-performance, asynchronous REST API routing and OpenAPI generation, adapted seamlessly for AWS Lambda execution.
3. **AWS Lambda (arm64)**: Offers cost-effective, high-throughput serverless compute within AWS Free Tier (1M free requests/month) using Graviton processors.
4. **Amazon Cognito User Pool**: Provides fully managed, zero-cost user authentication (50,000 MAUs free) with custom claims (`custom:tenant_id`) and group-based RBAC.
5. **Amazon DynamoDB (On-Demand)**: Delivers fast, serverless NoSQL storage for document metadata, audit logs, and ACLs with 25 GB always-free storage.
6. **Amazon S3 (Private)**: Supplies highly durable, private object storage for raw uploaded documents and transient chunks within standard free allocation.
7. **Qdrant Cloud (Free Tier)**: Provides a managed vector database cluster with payload indexing and native tenant-filtering capabilities at zero cost.
8. **Google Gemini API (Free Tier)**: Provides state-of-the-art embedding generation (`text-embedding-004`) and LLM reasoning (`gemini-1.5-flash` or newer) with zero API fees under rate limits.
9. **AWS Systems Manager (SSM) Parameter Store (SecureString)**: Stores sensitive secrets and credentials encrypted with KMS at zero cost, avoiding paid Secrets Manager fees.
10. **Terraform**: Enables reproducible, declarative Infrastructure-as-Code across all cloud resources without vendor lock-in.
11. **GitHub Actions with OIDC**: Automates CI/CD and secure cloud deployments using short-lived IAM credentials without static long-lived AWS keys.
12. **React + Vite + TypeScript**: Powers a fast, typed, responsive single-page frontend application easily hostable on free static hosting.

## Consequences
- **Positive:** System operational expenditure is $0.00 while maintaining production-grade security, tenant isolation, and auditability.
- **Constraints & Trade-offs:** Architectures that require NAT Gateways or dedicated VPC endpoints are avoided; outbound traffic from Lambda relies on direct internet access or dual-stack IPv6 to avoid NAT charges. Rate limits on external free tiers (e.g., Gemini API, Qdrant Cloud Free Tier) must be respected through exponential backoff and caching.
