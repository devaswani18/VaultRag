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

---

## Broken Access Control / IDOR

### 1. Threat Description
In a multi-tenant retrieval-augmented generation platform, unauthorized data access can occur across both tenant boundaries and internal role boundaries:
1. **Cross-Tenant Vector Bleed**: A user in Tenant B crafting semantic queries that retrieve chunks belonging to Tenant A if vector database searches lack tenant partitioning.
2. **Insecure Direct Object Reference (IDOR)**: An attacker guessing or enumerating predictable document IDs (`doc_...`) to access metadata or content belonging to other tenants or privileged users.
3. **Privilege Escalation via Document Probing**: An attacker receiving HTTP 403 Forbidden responses to determine whether confidential documents (e.g. `doc_merger_q4`) exist, enabling targeted corporate reconnaissance.
4. **Desynchronized Retrieval Payloads**: Document permission changes updated in the primary database but not propagated to chunk payloads in the vector engine, allowing continued unauthorized retrieval.
5. **Unauthorized ACL Mutation**: Non-owner or non-admin callers modifying document visibility flags to grant themselves or peers access to restricted knowledge.

---

### 2. Mitigations & Defensive Architecture

VaultRAG enforces document-level access control with defense-in-depth across the application and vector layers:

| Attack Vector | Defensive Control | Enforcement Point |
|---|---|---|
| **Cross-Tenant & Cross-Role Retrieval** | All vector retrieval paths mandatory route through `build_filter(ctx)`. Searches enforce `tenant_id == ctx.tenant_id` and evaluate `(visibility == 'tenant' OR allowed_roles INTERSECTS ctx.roles OR allowed_users CONTAINS ctx.user_id OR owner_user_id == ctx.user_id)`. Non-admin callers cannot bypass document visibility constraints. | [`backend/src/vaultrag/security/acl.py`](file:///backend/src/vaultrag/security/acl.py), [`backend/src/vaultrag/rag/retrieve.py`](file:///backend/src/vaultrag/rag/retrieve.py) |
| **Fail-Closed Vector Filter** | If any error occurs while generating retrieval filters (e.g., malformed claims or unexpected input), the filter fails closed by querying `tenant_id == '__none__'` and logging an error event. An unscoped filter is never returned. | [`backend/src/vaultrag/security/acl.py`](file:///backend/src/vaultrag/security/acl.py) |
| **IDOR & Existence Leaks** | `GET /documents/{doc_id}` applies `can_view(ctx, doc)`. Inaccessible documents return **HTTP 404 (Not Found)** rather than 403 (Forbidden) to prevent document discovery and enumeration. `GET /documents` similarly filters out unauthorized records. | [`backend/src/vaultrag/api/routers/documents.py`](file:///backend/src/vaultrag/api/routers/documents.py) |
| **Atomic Multi-Engine ACL Sync** | `PATCH /documents/{doc_id}/acl` verifies caller is document owner or tenant admin. It updates DynamoDB conditionally, updates chunk payloads in Qdrant using `set_payload_by_filter(filter={tenant_id, doc_id})`, and atomically increments tenant `kb_version` via DynamoDB `ADD` to invalidate downstream caches. | [`backend/src/vaultrag/api/routers/documents.py`](file:///backend/src/vaultrag/api/routers/documents.py) |
| **Strict Schema Enforcement** | `PATCH /documents/{doc_id}/acl` rejects unknown body fields (`extra="forbid"`), validates visibility options (`tenant`, `roles`, `private`), and requires non-empty `allowed_roles` from the system `Role` enum when visibility is set to `roles`. | [`backend/src/vaultrag/api/routers/documents.py`](file:///backend/src/vaultrag/api/routers/documents.py) |
| **Rule Parity Assurance** | Property tests verify that pure-Python `can_view` and Qdrant `build_filter` produce identical chunk visibility decisions across all tenant, role, and user permutations in an in-memory vector database. | [`backend/tests/acl/test_acl_parity.py`](file:///backend/tests/acl/test_acl_parity.py) |
