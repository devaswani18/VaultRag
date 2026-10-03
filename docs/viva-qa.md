# VaultRAG Engineering Viva & Technical Q&A

This document contains architectural defenses, viva questions, and technical explanations of VaultRAG's security controls and the **Assurance Center**.

---

## Stage 23: Assurance Center & Continuous Security Verification

### Question 1: Why use synthetic canaries with an identical fixed unit vector $V$ instead of real document embeddings?

**Answer:**
In a standard vector search, whether a chunk is retrieved depends on two distinct factors:
1. **Geometric Proximity**: The cosine similarity between the query embedding and the chunk embedding ($\cos(\theta) \ge \text{threshold}$).
2. **Boolean Access Filters**: The Qdrant payload filters enforcing `tenant_id`, `visibility`, `allowed_roles`, and `allowed_users`.

If we used real document text and model embeddings, semantic variation could cause chunks to be omitted simply because their similarity score was $0.72$ instead of $0.85$. This would conflate semantic relevance with security authorization.

By synthesizing a deterministic fixed unit vector:
$$V = \left[ \frac{1}{\sqrt{D}}, \frac{1}{\sqrt{D}}, \dots, \frac{1}{\sqrt{D}} \right] \in \mathbb{R}^D, \quad \|V\|_2 = 1.0$$
where $D = 768$ (matching `settings.embedding_dim`), every single canary vector is identical, and every query uses vector $V$. The dot product and cosine similarity between any query and any canary is mathematically **$1.0$**.

Consequently, vector distance is eliminated as an independent variable: **retrieval outcomes depend 100% on the Boolean ACL filter logic in Qdrant**. Any unexpected retrieval or exclusion is an unequivocal security authorization defect.

---

### Question 2: Why must the 30-cell expected matrix be hardcoded as a literal constant rather than derived dynamically from helper functions like `can_view()`?

**Answer:**
Deriving the expected test outcomes dynamically from runtime helper functions like `can_view(ctx, doc)` or `build_filter(ctx)` introduces a **circular testing anti-pattern**:
- If an engineer introduces a bug in role evaluation (e.g. accidentally allowing employees to access manager documents), `can_view()` would also evaluate to `True` for employees.
- If the test derived its expected matrix dynamically from `can_view()`, the test would re-evaluate the expected cell to `True`, compare `True == True`, and pass green! The test would silently ratify the vulnerability.

To prevent this, the 30-cell matrix in [`backend/src/vaultrag/assurance/canaries.py`](file:///backend/src/vaultrag/assurance/canaries.py) is explicitly written as a **literal constant**:
```python
EXPECTED_MATRIX = {
    "C1": {"A-admin": True, "A-manager": True, "A-employee": True, "A-intern": True, "B-admin": False},
    "C2": {"A-admin": True, "A-manager": True, "A-employee": False, "A-intern": False, "B-admin": False},
    ...
}
```
This immutable specification serves as an absolute ground truth representing the platform security contract. Live vector retrieval from Qdrant is compared directly against this constant. Any discrepancy is immediately flagged as a `LEAK` (unauthorized access) or `MISSING` (unintended denial).

---

### Question 3: How does the Assurance Center ensure tenant data safety and prevent canary pollution in production?

**Answer:**
The Assurance Center is engineered to run safely directly in production environments without risking cross-tenant pollution or data leakage:
1. **Reserved Synthetic Namespaces**:
   All test canaries use synthetic tenant IDs:
   - Primary: `st-<run_id>-a`
   - Foreign: `st-<run_id>-b`
   The prefix `st-` is permanently reserved across the codebase. Both `verify_id_token` in [`backend/src/vaultrag/auth/jwt_verifier.py`](file:///backend/src/vaultrag/auth/jwt_verifier.py) and `TenantRepo.put` in [`backend/src/vaultrag/clients/dynamo.py`](file:///backend/src/vaultrag/clients/dynamo.py) strictly reject any tenant ID starting with `st-` with `ValidationFailed`. No real user or tenant can ever assume a synthetic identity.
2. **Compound Isolation Filters**:
   Canary points are tagged with `selftest_run_id = run_id`. Retrieval queries compose the principal's ACL filter with a mandatory `selftest_run_id == run_id` condition. Canaries from concurrent or prior runs can never be retrieved.
3. **Hard Ephemeral Teardown Guarantee**:
   Cleanup runs inside a `finally` block in [`backend/src/vaultrag/assurance/runner.py`](file:///backend/src/vaultrag/assurance/runner.py). Even if a check throws an unhandled exception or times out, `delete_by_filter` purges all vectors for `st-<run_id>-a` and `st-<run_id>-b`.
4. **Verification Check E2**:
   Check `E2` executes after cleanup, querying Qdrant to verify that exactly 0 points remain with the synthetic tenant IDs and run ID.
5. **Real Tenant Non-Interference**:
   Because real customer points lack `selftest_run_id` and have different `tenant_id`s, they are completely invisible to the self-test queries and immune to the cleanup filters.

---

### Question 4: Why are zero calls made to Google Gemini or external LLMs during an assurance run?

**Answer:**
Zero calls are made to Google Gemini or external foundation model endpoints during an assurance run for three fundamental architectural reasons:
1. **Cost and Quota Preservation**:
   Executing 30 access queries plus 19 security checks via an LLM on every self-test would rapidly deplete API rate limits (e.g. 10 RPM on Gemini free-tier) and generate unnecessary cloud costs.
2. **Low Latency (< 10 seconds)**:
   In-process vector search in Qdrant and local security evaluation complete in under **3 to 5 seconds**. Invoking an external LLM for 30 queries would introduce network latency and generation overhead of 30–60+ seconds.
3. **Deterministic Evaluation**:
   The Assurance Center verifies **system security mechanics**:
   - Vector database access control filters (`assert_tenant_scoped`, `build_filter`)
   - Sensitive data detection (`pii_guard.apply_policy`)
   - Prompt injection heuristics (`injection_guard.scan_text`)
   - Cryptographic hash chain validity (`audit.hashchain.verify_records`)
   - Certificate signatures (`erasure.sign_payload`)
   - Database configuration posture (`clients.qdrant.ensure_collection`)

   All of these subsystems are deterministic. Involving an LLM would introduce stochastic variability without adding any security validation value.

---

### Question 5: How does fault injection simulation work without compromising tenant isolation?

**Answer:**
Administrators can run simulated tests via the UI or API (`POST /admin/assurance/run` with `simulate_bug: "drop_role_condition"` or `"ignore_private"`):
1. **Isolated Module Boundary**:
   The fault injection builders are contained strictly within [`backend/src/vaultrag/assurance/fault_injection.py`](file:///backend/src/vaultrag/assurance/fault_injection.py). Unit tests enforce via static AST analysis that `fault_injection` is **never imported** anywhere in `vaultrag/api/` or `vaultrag/rag/`.
2. **Immutable Tenant Scoping**:
   Both simulated builders (`build_filter_drop_role_condition` and `build_filter_ignore_private`) retain the mandatory top-level `tenant_id == ctx.tenant_id` clause. `assert_tenant_scoped` is called on every generated filter. As a result, cross-tenant isolation (Check `I1` and `I2`) **always passes**, even when role or private filters are deliberately bypassed!
3. **State Protection**:
   Simulated runs return `simulated: true` and the name of the injected fault. The endpoint [`backend/src/vaultrag/admin/assurance.py`](file:///backend/src/vaultrag/admin/assurance.py) explicitly skips updating `last_assurance` in DynamoDB for simulated runs. Only authentic, unsimulated runs can update the tenant's stored security attestation.
4. **Audit Trail Accountability**:
   Simulated runs emit an `assurance_run_simulated` audit record, distinguishing test runs from real production audits in the hash chain.

---

### Question 6: How does cryptographic report signing provide non-repudiation and auditability?

**Answer:**
Every completed Assurance Report is cryptographically bound and signed before being returned or persisted:
1. **Canonical JSON Normalization**:
   To prevent whitespace or key-ordering ambiguity, the report payload is serialized using strict canonical JSON formatting (sorted dictionary keys, compact `,` and `:` separators, UTF-8 encoding).
2. **SHA-256 Digest**:
   The canonical representation is hashed to compute `report_sha256 = SHA256(canonical_json)`.
3. **HMAC-SHA256 Signature**:
   The payload is signed using HMAC-SHA256 with the tenant's secret (`cert_hmac_secret` from AWS Systems Manager Parameter Store).
4. **Tamper Evident**:
   If an adversary or rogue tenant attempts to modify any value (e.g. changing a `leak` cell to `allowed`, increasing `passed` count, or altering the timestamp), recomputing the HMAC signature during verification fails immediately.
5. **Independent Auditor Verification**:
   The `POST /admin/assurance/verify` endpoint allows external compliance auditors to upload an exported report. The endpoint verifies:
   - That `report.tenant_id == ctx.tenant_id` (preventing tenant spoofing).
   - That `verify_signed_payload(report, secret)` returns `True` using constant-time comparison (`hmac.compare_digest`), preventing timing side-channel attacks.
