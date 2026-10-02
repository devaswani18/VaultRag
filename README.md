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

## Quality & Evaluation Harness

VaultRAG includes a hermetic evaluation harness (`eval/run_eval.py`) and a 40-item golden benchmark dataset (`eval/golden_set.yaml`) evaluated against a synthetic multi-tenant corporate knowledge base (`eval/corpus/`).

The benchmark runs in two modes:
- **Mock Mode (CI Gate):** Uses hermetic local simulation (moto for AWS DynamoDB/S3/SSM, in-memory Qdrant, deterministic embeddings) to enforce security and isolation hard gates on every commit.
- **Live Mode (Nightly / Dispatch):** Runs against Google Gemini API with rate-limit backoff, evaluating end-to-end generation quality, faithfulness, and answer accuracy.

### Hard Security Gates (Zero-Tolerance)
All builds strictly fail closed (`exit 1`) if any leak is detected in answers, sources, or stored chunks:

| Gate | Target | Observed Leaks | Status | Description |
| :--- | :--- | :--- | :--- | :--- |
| **ACL Boundaries** | `acl_leaks == 0` | **0** | **PASS** | Strict role-based filter isolation prevents unauthorized roles from retrieving restricted documents. |
| **Cross-Tenant Isolation** | `cross_tenant_leaks == 0` | **0** | **PASS** | Complete cryptographic and vector partition prevents queries from seeing another tenant's data. |
| **Zero Raw PII** | `pii_leaks == 0` | **0** | **PASS** | Ingestion hooks and query guards ensure raw sensitive identifiers (PAN, credit cards, phones) are never indexed or output. |
| **Role-Scoped Cache** | `cache_leaks == 0` | **0** | **PASS** | Scope key hashing (`sha256(tenant_id\|roles)`) prevents lower-privileged callers from hitting cached manager answers. |
| **Prompt Injection Resistance** | `injection_followed == 0` | **0** | **PASS** | Malicious injection payloads inside retrieved documents are flagged and neutralized; instructions are never obeyed. |

### Retrieval & Accuracy Metrics (Benchmark Summary)

| Metric | Target | Observed (Mock Mode) |
| :--- | :--- | :--- |
| **Retrieval Hit@k Rate** | >= 80.0% | **90.5%** |
| **Correct Abstain Rate** | >= 85.0% | **82.5%** |
| **Mean Query Latency** | <= 5000 ms | **46.5 ms** |
| **Security Leak Violations** | 0 | **0 (Zero Leaks)** |

## Deployment
Automated via Terraform and GitHub Actions OIDC workflows.
