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

---

## Cost Model & Cloud Resource Economics

VaultRAG is engineered with a strict **zero-cost idle base**, running entirely within the AWS Free Tier and developer-friendly third-party quotas during initial deployment, testing, and small-team operations.

> **Important**: AWS pricing, allowances, and Free Tier terms evolve over time. Readers and deployers should always verify the latest current terms at the [AWS Free Tier Pricing Page](https://aws.amazon.com/free/) before deployment.

### Service-by-Service Breakdown

| AWS Service | Provisioned Configuration | Free-Tier Allowance / Cost Note | Idle Monthly Cost |
| :--- | :--- | :--- | :--- |
| **AWS Lambda** | 2 Functions (`api` @ 512 MB, `ingest` @ 1024 MB), ARM64 architecture | **1,000,000 free requests/month** and **3,200,000 seconds of compute time** (up to 400,000 GB-seconds) every month. Zero cold cost when idle. | **$0.00** |
| **Amazon S3** | 4 Buckets (`docs`, `artifacts`, `web`, `tfstate`), SSE-S3 AES-256 | **5 GB Standard Storage**, 20,000 GET requests, and 2,000 PUT requests/month under the 12-month free tier. Object lifecycle rules purge old builds after 30 days and temp uploads after 1 day. | **$0.00** |
| **Amazon DynamoDB** | 5 Tables (`tenants`, `documents`, `audit`, `usage`, `gaps`) in `PAY_PER_REQUEST` on-demand mode | **25 GB of storage** free indefinitely. On-demand billing charges strictly per read/write request unit ($0.00 when idle). | **$0.00** |
| **Amazon CloudFront** | 1 Distribution (OAC, PriceClass_100, custom ResponseHeadersPolicy) | **1 TB Data Transfer Out** per month and **10,000,000 HTTP/HTTPS requests** free indefinitely. | **$0.00** |
| **Amazon Cognito** | 1 User Pool + 1 App Client (Email/password SRP authentication) | **50,000 Monthly Active Users (MAUs)** free indefinitely without advanced security features. | **$0.00** |
| **Amazon CloudWatch** | 2 Log Groups (`/aws/lambda/vaultrag-dev-*`), 7-day retention limit | **5 GB log ingestion** and **5 GB archive storage** free per month. 7-day TTL guarantees dev logs stay well below quota. | **$0.00** |
| **AWS Systems Manager (SSM)** | Standard SecureString parameters (`/vaultrag/dev/*`) | Standard parameter store storage and throughput are **free of charge**. | **$0.00** |
| **AWS Budgets** | 1 Zero-Cost Budget with SNS email notifications | First 2 action-enabled budgets are free; standard budget monitoring is **$0.00**. | **$0.00** |

### Deliberately Excluded Paid Infrastructure

To prevent unexpected monthly bills, the following traditional enterprise cloud components are intentionally **excluded** from the architecture:

1. **No NAT Gateways**: Replaced by direct TLS egress from public Lambda runtimes. Avoids ~$32.40/month per availability zone plus data-transfer fees.
2. **No Elastic Load Balancers (ALB/NLB)**: Replaced by Lambda Function URLs with CORS and CloudFront CDN integration. Avoids ~$16.20/month base cost.
3. **No Managed Relational Database (RDS/Aurora)**: Replaced by serverless DynamoDB on-demand tables and Qdrant Cloud Free Tier (1 GB cluster). Avoids ~$15–$50+/month.
4. **No AWS WAF**: Replaced by native CloudFront Response Headers Policies (HSTS, CSP, X-Frame-Options) combined with application-layer tenant query quotas and token rate limits. Avoids ~$5.00/month per WebACL and $1.00/month per managed rule.

---

## Assurance Center: Continuous Live Security Self-Testing

The **Assurance Center** is VaultRAG's flagship automated security verification system. Rather than relying solely on static unit tests or CI pipelines, the Assurance Center provides live, in-situ cryptographic verification of multi-tenant isolation, role boundaries, sensitive data protection, injection defense, and audit integrity directly against running infrastructure.

### 1. Verification Architecture & Fixed Vector Canaries

During an assurance run (`run_assurance`), the runner creates a unique execution context:
1. **Synthetic Isolation Namespaces**: Creates two synthetic tenant IDs:
   - Primary: `st-<run_id>-a`
   - Foreign: `st-<run_id>-b`
   Both tenant IDs begin with `st-`, a prefix strictly reserved by authentication verifiers and rejected for any real tenant or Cognito token.
2. **Fixed Unit Vector $V$**:
   A deterministic unit vector with dimension $D = 768$ (matching `settings.embedding_dim`) is synthesized:
   $$V = \left[ \frac{1}{\sqrt{D}}, \frac{1}{\sqrt{D}}, \dots, \frac{1}{\sqrt{D}} \right], \quad \|V\|_2 = 1.0$$
   Every canary vector is assigned vector $V$, and every search query uses vector $V$. This guarantees cosine similarity of $1.0$ across all canaries, ensuring that retrieval outcomes depend **strictly on access control filter logic** rather than vector distance or embedding semantics.
3. **Zero Gemini Invocation**: The self-test suite executes entirely without calling LLM endpoints or external foundation model APIs, completing in < 10 seconds with zero API inference cost.

---

### 2. Canary Descriptors (C1–C6)

Six canary points are planted in Qdrant with `selftest_run_id = <run_id>`:

| Canary | Descriptor Name | Tenant | Visibility | Allowed Roles | Allowed Users | Owner |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **C1** | Tenant-wide Public | `st-*-a` | `tenant` | None | None | `u-admin` |
| **C2** | Manager Role Restricted | `st-*-a` | `roles` | `["manager"]` | None | `u-admin` |
| **C3** | Admin-Private Document | `st-*-a` | `private` | None | None | `u-admin` |
| **C4** | User-Granted to Intern | `st-*-a` | `roles` | `["manager"]` | `["u-intern"]` | `u-admin` |
| **C5** | Intern-Private Document | `st-*-a` | `private` | None | None | `u-intern` |
| **C6** | Foreign-Tenant Document | `st-*-b` | `tenant` | None | None | `u-b-admin` |

---

### 3. The 30-Cell Expected Access Matrix

Five synthetic principals query Qdrant using vector $V$ with their respective ACL filters. The results are compared against an **immutable, literal constant matrix**:

| Canary Vector Tier | A-admin | A-manager | A-employee | A-intern | B-admin |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **C1** (Tenant-wide Public) | Allowed | Allowed | Allowed | Allowed | **Blocked** |
| **C2** (Manager Role Restricted) | Allowed | Allowed | **Blocked** | **Blocked** | **Blocked** |
| **C3** (Admin-Private Document) | Allowed | **Blocked** | **Blocked** | **Blocked** | **Blocked** |
| **C4** (User-Granted to Intern) | Allowed | Allowed | **Blocked** | Allowed | **Blocked** |
| **C5** (Intern-Private Document) | Allowed | **Blocked** | **Blocked** | Allowed | **Blocked** |
| **C6** (Foreign-Tenant Document) | **Blocked** | **Blocked** | **Blocked** | **Blocked** | Allowed |

> [!IMPORTANT]
> **Ground Truth Design Principle:**
> This matrix is hard-coded as a literal constant in [`backend/src/vaultrag/assurance/canaries.py`](file:///backend/src/vaultrag/assurance/canaries.py) and is **never** derived dynamically from `can_view()`, `build_filter()`, or any runtime helper. A logical bug in authorization logic cannot redefine the ground truth. Any discrepancy produces a `LEAK` (unauthorized access) or `MISSING` (unintended denial) state.

---

### 4. The 19 Security Checks Across 7 Categories

| ID | Category | Check Description |
| :--- | :--- | :--- |
| **I1** | Isolation | Tenant A principals never retrieve foreign canary C6 under any circumstance. |
| **I2** | Isolation | Tenant B principals never retrieve Tenant A canaries C1–C5. |
| **I3** | Isolation | `assert_tenant_scoped` strictly rejects query filters lacking tenant conditions. |
| **I4** | Isolation | `build_filter` fails closed upon malformed context (querying `tenant_id == '__none__'`). |
| **A1** | Access Control | Role-restricted canary C2 is accessible to manager and blocked for general employee. |
| **A2** | Access Control | Private canaries C3 and C5 are blocked for unauthorized peers. |
| **A3** | Access Control | Explicit user grant in C4 allows intern retrieval while blocking general employee. |
| **A4** | Access Control | All 30 live vector retrieval cells match the literal ground-truth matrix 100%. |
| **D1** | Data Protection | PII guard redacts synthetic Aadhaar (Verhoeff-valid), PAN, and Credit Card numbers. |
| **D2** | Data Protection | Zero-log filter redacts bearer tokens and email addresses from application logs. |
| **J1** | Injection Defense | Direct prompt injection override samples are scored `high` risk ($\ge 40$). |
| **J2** | Injection Defense | Benign policy look-alike sentences resist false positives and score `low` risk ($< 20$). |
| **J3** | Injection Defense | Roleplay delimiter breakouts (`<|im_start|>system`) are intercepted and quarantined. |
| **U1** | Audit Integrity | Verifies the calling tenant's cryptographic hash chain is valid and unbroken. |
| **U2** | Audit Integrity | Synthesizes a tampered record and verifies `verify_records` detects the break immediately. |
| **E1** | Cryptography | Verifies HMAC-SHA256 signature generation and constant-time verification. |
| **E2** | Cryptography | Verifies that zero residual canary points remain in Qdrant after suite cleanup. |
| **C1** | Configuration Posture | Inspects Qdrant collection to ensure payload index on `tenant_id` and `selftest_run_id` exists. |
| **C2** | Configuration Posture | Verifies that tenant active defense policies (`pii_mode`, `injection_policy`) are active. |

---

### 5. Ephemeral Teardown & Cryptographic Report Signing

1. **Guaranteed Cleanup in `finally`**:
   The canary cleanup logic executes inside a `finally` block in [`backend/src/vaultrag/assurance/runner.py`](file:///backend/src/vaultrag/assurance/runner.py). Even if a check crashes or times out, all canary points for `st-<run_id>-a` and `st-<run_id>-b` are purged via `delete_by_filter`. Check `E2` then counts the remaining points to guarantee zero leakage.
2. **Cryptographic Report Signing**:
   Every report is canonically serialized, hashed via SHA-256 (`report_sha256`), and signed using HMAC-SHA256 with the SSM secret `cert_hmac_secret`. Reports can be exported as JSON and verified independently by third-party auditors using `POST /admin/assurance/verify`.
3. **Controlled Simulation**:
   Administrators can run simulated runs (`drop_role_condition`, `ignore_private`) to demonstrate leak detection in the Trust Center UI. Simulated runs are marked `simulated: true`, never overwrite `last_assurance` in DynamoDB, and emit distinct audit events (`assurance_run_simulated`).
