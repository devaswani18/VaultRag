# VaultRAG Threat Model

This document outlines the threat modeling, security architecture, and defensive controls implemented across VaultRAG.

---

## Sensitive Data Leakage

### 1. Threat Description
Multi-tenant RAG systems ingest internal enterprise documents that frequently contain Personally Identifiable Information (PII) and secret credentials, including:
- National identifiers (e.g., Aadhaar, PAN)
- Payment card data (Credit/Debit card PANs)
- Contact information (Indian mobile numbers, email addresses)
- Financial routing numbers (IFSC)
- Cloud and application credentials (AWS access keys, API tokens, passwords, private keys, JWTs)

Without controls, sensitive data can leak across multiple attack surfaces:
1. **Third-Party Model Leakage**: Raw PII sent directly to external LLM providers (e.g. Google Gemini) in prompt contexts.
2. **Vector Index Exposure**: Sensitive values stored as plain text in vector search chunk payloads.
3. **Cross-Tenant or Cross-Role Inference**: Unauthorized colleagues retrieving sensitive data via natural-language queries.
4. **Log Pollution**: Plaintext credentials or identifiers written to cloud log aggregators (CloudWatch).

---

### 2. Mitigations & Defensive Architecture

VaultRAG enforces a strict, defense-in-depth Trust Layer using the `pii_guard` module:

| Surface | Defensive Control | Enforcement Point |
|---|---|---|
| **Ingestion Pipeline** | `PIIHook` runs as the **first** hook in the document processing pipeline. Text is normalized using Unicode NFKC. Spans are replaced with deterministic redacted tokens (e.g. `[AADHAAR_REDACTED]`, `[CREDIT_CARD_REDACTED]`). | [`backend/src/vaultrag/ingest/hooks/pii_hook.py`](file:///backend/src/vaultrag/ingest/hooks/pii_hook.py) |
| **Vector Storage** | Only sanitized chunk text is embedded and indexed into Qdrant. Chunk payloads track boolean flags (`pii_found`) and categorized type lists (`pii_types`), but **never** the raw matched values. | [`backend/src/vaultrag/ingest/handler.py`](file:///backend/src/vaultrag/ingest/handler.py) |
| **Object Storage Retention** | Configurable tenant policy `retain_original_files`. When set to `false`, the original raw S3 document is purged immediately after successful vector indexing. | [`backend/src/vaultrag/ingest/handler.py`](file:///backend/src/vaultrag/ingest/handler.py) |
| **Query Input** | Incoming questions are scanned before vector retrieval or LLM execution. In `redact` mode, identifiers are masked before embedding; in `block` mode, requests are rejected with HTTP 422. | [`backend/src/vaultrag/api/routers/query.py`](file:///backend/src/vaultrag/api/routers/query.py) |
| **Answer Generation** | LLM responses are scanned prior to returning to the user. In `redact` mode, any model-hallucinated or reflected PII is masked. Non-off modes mark `pii_in_answer: true` for the cryptographic audit trail. | [`backend/src/vaultrag/api/routers/query.py`](file:///backend/src/vaultrag/api/routers/query.py) |
| **Zero-Log Guarantee** | The `Finding` dataclass does not store the matched string. Logging utilities log only aggregate type counts (e.g. `{"AADHAAR": 1}`), preventing secrets from entering log streams. | [`backend/src/vaultrag/security/pii_guard.py`](file:///backend/src/vaultrag/security/pii_guard.py) |
