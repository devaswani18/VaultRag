# VaultRAG Compliance & Privacy Architecture Mapping

> **Disclaimer**: This document describes technical capabilities engineered to assist organizations with security and data governance requirements. VaultRAG **supports** technical safeguards and data minimization practices; this document does not certify, attest, or warrant legal compliance under any regulatory statute.

---

## Digital Personal Data Protection (DPDP) Act, 2023 (India)

The Digital Personal Data Protection Act, 2023 introduces strict obligations for Data Fiduciaries regarding the collection, processing, retention, and protection of personal data. The table below outlines how VaultRAG's architectural features **support** these principles:

| Principle & Section | Regulatory Focus | How VaultRAG Architecture Supports the Principle |
|---|---|---|
| **Data Minimisation** (Sec. 6) | Personal data processed should be limited to what is necessary for the specified purpose. | - **PII Guard Redaction**: The ingestion pipeline automatically identifies and replaces sensitive Indian identifiers (Aadhaar with Verhoeff verification, PAN with holder-type validation, and mobile numbers) with generic tokens (e.g. `[AADHAAR_REDACTED]`), preventing indexing into the vector store.<br>- **Pre-Query Redaction**: Questions asked by users are sanitized before embedding or sending to LLMs.<br>- **Original File Purging**: The tenant setting `retain_original_files: false` supports deleting raw source documents from S3 once embeddings are generated. |
| **Purpose Limitation** (Sec. 5, 7) | Personal data must be processed solely for the specific, lawful purpose for which consent was provided. | - **Tenant Boundary Enforcement**: Strict tenant isolation prevents personal data of one company from being retrieved or processed for another.<br>- **Role-Based Access Control**: Ensures personal records are accessible only to authorized roles within the tenant organization. |
| **Reasonable Security Safeguards** (Sec. 8(5)) | Data Fiduciaries must implement reasonable security safeguards to prevent personal data breaches. | - **Defense-in-Depth Trust Layer**: Multi-tier scanning on ingestion, vector search, question prompt, and LLM output.<br>- **Zero-Log Sensitive Data Policy**: Scanners record span coordinates and entity counts but strictly omit matched sensitive substrings from memory objects, logs, and telemetry. |
| **Storage Limitation** (Sec. 8(7)) | Personal data should be erased when the specified purpose is satisfied. | - **Configurable Retention**: Through the Admin Policies API (`PATCH /admin/policies`), administrators can toggle `retain_original_files: false` to ensure original copies do not linger in long-term object storage. |
