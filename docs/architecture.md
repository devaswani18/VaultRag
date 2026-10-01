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
