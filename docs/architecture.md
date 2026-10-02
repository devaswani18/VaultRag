# VaultRAG Architecture

This document describes the architectural design, security controls, and verification guarantees of the VaultRAG platform.

---

## Answer Trust & Retrieval Gating

VaultRAG enforces end-to-end factual grounding and hallucination prevention on the question-answering path through a multi-stage Trust Layer:

### 1. Retrieval Gating
Before invoking generative foundation models, the retrieval layer queries vector chunks partitioned by tenant ID and document-level ACLs.
- If no candidate chunks are returned, or if the maximum chunk similarity score is strictly below the tenant's `min_retrieval_score` threshold, the request is immediately abstained without calling the LLM.
- **Abstain Response**: `{"answer": "I could not find this in the documents you can access.", "trust": {"score": 0.0, "grounded": false, "abstained": true, "partial": false, "reasons": ["below_min_retrieval_score"]}}`.
- This eliminates unnecessary inference costs and prevents hallucinated responses to out-of-domain questions.

### 2. Threshold Calibration Methodology
The `min_retrieval_score` threshold is calibrated empirically via `scripts/calibrate_thresholds.py` using `eval/golden_set.yaml`.
- **Dataset**: Balanced benchmark of in-document questions (verifiably present in `eval/corpus/`) and out-of-document questions (unanswerable general domain prompts).
- **Optimization Criterion**: Grid search evaluating candidate thresholds across similarity distributions to maximize balanced classification accuracy (true answerable retention vs. true unanswerable abstention).
- **Default Value**: Calibrated at `0.35` (empirically yielding >= 90% balanced accuracy on standard enterprise corpora).

### 3. Structured Generation & XML Sandboxing
When the retrieval gate passes, the generative prompt isolates retrieved context:
- Retrieved chunks are wrapped in `<retrieved_document id="CHUNK_ID">` tags with opening and closing delimiter sequences escaped to prevent context breakouts.
- A per-request random canary string (`CANARY: vr-<hex>`) is injected with the rule that it must never appear in the output.
- The model is constrained to output JSON conforming to `{"segments": [{"text": "...", "citations": ["chunk_id", ...]}]}`.

### 4. Factual Faithfulness Engine
Post-generation, `vaultrag.rag.faithfulness.check` inspects each individual statement:
- **Rule (a) - Citation Presence**: Every segment must specify at least one citation.
- **Rule (b) - Citation Validity**: Every cited chunk ID must exist within the retrieved chunk set. Fabricated citation IDs incur a penalty (-0.2 from total score).
- **Rule (c) - Lexical Support**: Non-stopword content tokens must achieve at least 50% overlap with the text of the cited chunks.
- **Rule (d) - Numeric & Date Consistency**: All numbers and date expressions in the segment must appear verbatim in at least one cited chunk.
- **Score Calculation**: `supported_segments / total_segments - 0.2 * len(invalid_citations)` (bounded in `[0.0, 1.0]`).
- **Borderline LLM Judge**: Optional fallback (`llm_judge_enabled`, default `false`) for borderline scores in `[0.4, min_faithfulness)`.

### 5. Partial Answer Fallback
If the faithfulness score falls below `min_faithfulness`:
- Unsupported segments are pruned.
- If zero supported segments remain, the system abstains with reason `"insufficient_support"`.
- If one or more supported segments remain, the partial answer is returned with `trust.partial = true` and an explicit disclaimer appended to the answer.

---

## Semantic Caching & Why Naive Semantic Caching is a Data-Leak Bug

VaultRAG implements an ACL-aware, role-scoped semantic query cache (`vaultrag.rag.semantic_cache`).

### Why Naive Semantic Caching is a Critical Vulnerability

In naive implementations, semantic query caches store `(question_embedding, answer)` pairs globally or at the tenant root. When a user asks a similar question (cosine similarity >= threshold), the cache returns the stored answer. In multi-tenant, role-based enterprise systems, this creates severe security and data-leak vulnerabilities:

1. **Cross-Tenant Data Exposure**: If query vectors are matched across tenant boundaries, Tenant B can extract proprietary intellectual property or PII from Tenant A simply by submitting semantically similar inquiries.
2. **Cross-Role Privilege Escalation**:
   - *Attack Scenario*: An Executive or HR Admin asks: *"What was the executive severance package for Q3?"* The system retrieves confidential HR documents and generates an accurate answer.
   - Five minutes later, an Intern asks: *"Tell me about the executive severance payouts."*
   - Under a naive cache, vector similarity triggers a cache hit. The intern receives the confidential answer, completely bypassing document ACLs and role-based permissions.
3. **User-Level Private Document Leaks**: Documents marked with `visibility: private` or restricted to specific `allowed_users` belong exclusively to their respective owners. Because semantic cache entries are role-scoped, caching an answer synthesized from a private document would leak that document's contents to any peer holding the same organizational role.
4. **Stale Information & Broken Revocation**: When a document is deleted (e.g. GDPR/DPDP Right to Erasure) or its ACL is restricted, a naive cache continues serving the cached response until the TTL expires, violating compliance mandates and data governance rules.

### VaultRAG Semantic Cache Controls

To prevent these data leaks while still saving LLM inference latency and costs, VaultRAG enforces five defense-in-depth rules:

1. **Deterministic Scope Keys**:
   Cache lookups and writes are partitioned not only by `tenant_id`, but by a cryptographic `scope_key`:
   $$\text{scope\_key} = \text{SHA256}(\text{tenant\_id} \parallel \text{"|"} \parallel \text{sorted\_role\_names})$$
   An employee with role `intern` will never hit a cache entry populated by role `admin`, even for verbatim identical questions.
2. **Strict Exclusion of Private & User-Restricted Chunks**:
   When storing an answer, the cache inspects every retrieved chunk contributing to the answer. If **any** chunk has `visibility == "private"` or non-empty `allowed_users`, the answer is **never written to the semantic cache**.
3. **Knowledge Base Version Invalidation (`kb_version`)**:
   Tenant records maintain an atomic integer `kb_version`. Any document upload, deletion, ACL mutation, or policy change increments `kb_version`. Cache lookups enforce `cached.kb_version == current.kb_version`; any bump invalidates all prior cache entries for that tenant immediately.
4. **Verifiable Erasure Integration (`delete_for_doc`)**:
   During Stage 16 verifiable erasure (`erase_document`), the orchestrator invokes `delete_for_doc(tenant_id, doc_id)`, purging every cached vector referencing the erased document before issuing the Certificate of Erasure.
5. **No Storage of Unanswered or Partial Queries**:
   Queries that abstain or return partial answers are never cached, preventing negative results from suppressing newly added knowledge.
