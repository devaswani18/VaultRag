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
| **Storage Limitation** (Sec. 8(7)) | Personal data should be erased when the specified purpose is satisfied. | - **Configurable Retention**: Through the Admin Policies API (`PATCH /admin/policies`), administrators can toggle `retain_original_files: false` to ensure original copies do not linger in long-term object storage.<br>- **User Conversation History TTL**: Conversation history is retained strictly for a tenant-configured duration (`chat_history_days`, default 7, max 30 days) and automatically purged via DynamoDB TTL. When set to 0, no conversation data is stored. Users can also trigger immediate deletion. |

---

## Right to Erasure & Verifiable Deletion (DPDP Sec. 12(3) / GDPR Art. 17)

VaultRAG implements an idempotent, verified erasure pipeline (`DELETE /documents/{doc_id}` and `DELETE /admin/users/{user_id}/documents`) returning a cryptographically signed **Certificate of Erasure** (`POST /admin/certificates/verify`).

### Technical Deletion Controls
1. **Multi-Tier Purging**:
   - **Vector Store (Qdrant)**: Deletes all points matching `tenant_id` and `doc_id`, followed by a post-check asserting zero points remaining.
   - **Object Store (S3)**: Deletes all raw documents and artifacts under `uploads/{tenant_id}/{doc_id}/`, followed by a prefix listing check asserting zero files remaining.
   - **Semantic Cache**: Evicts all cached retrieval/generation entries referencing the erased document.
   - **Metadata Minimization (DynamoDB)**: Replaces the full document record with a minimal tombstone containing solely `{tenant_id, doc_id, status: DELETED, deleted_at, deleted_by, certificate_sha256}`. Filenames, content types, sizes, and access control lists are permanently removed.
2. **Cryptographic Certificate**: Produces an HMAC-SHA256 signature over the canonical JSON certificate payload using the AWS SSM secret `cert_hmac_secret`.
3. **Audit Immutability**: Logs `erasure` lifecycle events in the append-only cryptographic hash chain.

### What the Certificate of Erasure Does NOT Cover

To maintain transparency with auditors and data fiduciaries, the cryptographic Certificate of Erasure covers only active application storage and specifically **does NOT cover**:
1. **Backups & Disaster Recovery Snapshots**: AWS DynamoDB Point-in-Time Recovery (PITR) snapshots and S3 lifecycle retention archives. In compliance with AWS security boundaries, backup snapshots are immutable and cannot be selectively rewritten; they age out according to backup lifecycle retention windows.
2. **CloudWatch Logs**: Application access logs and execution logs. By design, CloudWatch logs contain request IDs, tenant IDs, timestamps, and cryptographic hashes, but *never contain document body text, queries, or raw PII*.
3. **Third-Party Model Provider Retention**: Transient request logs or diagnostic retention maintained by Google Cloud Vertex AI / Gemini API according to Google's Enterprise Terms of Service and data governance policies.
4. **User-Side Artifacts**: Any local copies, browser caches, downloaded files, or exported CSV summaries created or retained by end users prior to invoking deletion.
5. **Private Conversation History (Stale Answer Limitation)**: Historical assistant responses previously stored in end-users' private conversation histories are not retroactively rewritten when a document is erased. Storing raw snippets is prohibited, and automatic TTL expiration (`chat_history_days`, default 7 days) and user-initiated "Clear history" actions ensure these records expire swiftly.
