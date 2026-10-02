# VaultRAG Operational Runbook & Observability Guide

This runbook provides incident response workflows, monitoring procedures, and CloudWatch Logs Insights queries for operating VaultRAG in production.

All observability is designed around **zero new paid services**, utilizing native AWS CloudWatch Logs Insights (covered by the AWS Free Tier up to 5 GB ingestion and queries on existing log groups).

---

## Log Group Architecture

VaultRAG emits single-line structured JSON logs with automatic PII masking to two primary CloudWatch log groups:

1. `/aws/lambda/vaultrag-dev-api` — Handles all FastAPI HTTP requests, query generation, document management, and admin endpoints.
2. `/aws/lambda/vaultrag-dev-ingest` — Handles asynchronous document parsing, chunking, sanitization, embedding, and vector upsert.

Both log groups are configured with `retention_in_days = 7` to strictly prevent storage cost accumulation.

---

## Standard JSON Log Schema

Every structured log event emitted by `vaultrag.logging_utils` contains:

```json
{
  "ts": "2026-10-02T19:30:00.000000+00:00",
  "level": "INFO | WARNING | ERROR",
  "msg": "event_identifier_or_message",
  "request_id": "c7a8b9e0-1234-5678-9abc-def012345678",
  "tenant_id": "acme",
  "user_id": "usr_abc123",
  "path": "/query",
  "method": "POST",
  "status_code": 200,
  "duration_ms": 342.5,
  "tokens_used": 156,
  "cache_hit": false,
  "injection_detected": false
}
```

---

## CloudWatch Logs Insights Operational Queries

Navigate to **AWS CloudWatch > Logs Insights** in the AWS Console and select `/aws/lambda/vaultrag-dev-api` and/or `/aws/lambda/vaultrag-dev-ingest`.

### 1. Errors by `request_id` & Failure Trace Correlation

Isolate unhandled server errors (HTTP 500), unhandled exceptions, and traceback logs grouped by unique `request_id`:

```sql
fields @timestamp, request_id, tenant_id, user_id, path, method, status_code, msg, error_type, exc_info
| filter level = "ERROR" or status_code >= 500 or ispresent(exc_info)
| sort @timestamp desc
| limit 100
```

To drill into the full lifecycle of a specific failed request:

```sql
fields @timestamp, level, msg, path, status_code, duration_ms, exc_info
| filter request_id = "PASTE_REQUEST_ID_HERE"
| sort @timestamp asc
```

---

### 2. Latency Percentiles from Access Logs

Analyze endpoint latency distributions ($p50$, $p90$, $p95$, $p99$) across routes to detect API bottlenecks or slow Gemini LLM calls:

```sql
fields @timestamp, path, method, duration_ms
| filter ispresent(duration_ms) and ispresent(path)
| stats count(*) as request_count,
        avg(duration_ms) as avg_latency_ms,
        pct(duration_ms, 50) as p50_ms,
        pct(duration_ms, 90) as p90_ms,
        pct(duration_ms, 95) as p95_ms,
        pct(duration_ms, 99) as p99_ms
        by path, method
| sort request_count desc
```

To analyze compute runtime from native AWS Lambda execution reports:

```sql
filter @type = "REPORT"
| stats count(*) as total_invocations,
        avg(@duration) as avg_duration_ms,
        pct(@duration, 50) as p50_duration_ms,
        pct(@duration, 95) as p95_duration_ms,
        pct(@duration, 99) as p99_duration_ms,
        max(@maxMemoryUsed / 1000000) as max_memory_mb
        by bin(1h)
```

---

### 3. Tenant Quota Exceeded Events

Identify tenants that have hit their configured `daily_query_quota` ceiling and are receiving HTTP 429 Too Many Requests:

```sql
fields @timestamp, tenant_id, user_id, path, status_code, msg, daily_quota, current_usage
| filter status_code = 429 or msg = "quota_exceeded" or error_type = "QuotaExceeded"
| stats count(*) as quota_rejections by tenant_id, bin(1h)
| sort quota_rejections desc
```

---

### 4. Prompt Injection Attempt Detection & Risk Analytics

Audit documents and user prompts flagged for prompt injection payloads (e.g. `SYSTEM OVERRIDE`, jailbreaks, canary extraction attempts):

```sql
fields @timestamp, tenant_id, user_id, doc_id, injection_detected, risk_reasons, msg
| filter injection_detected = true or msg like /(?i)injection/ or ispresent(injection_summary)
| stats count(*) as total_flags,
        count_distinct(user_id) as suspicious_users,
        count_distinct(doc_id) as flagged_docs
        by tenant_id
| sort total_flags desc
```

To inspect specific flagged injection triggers:

```sql
fields @timestamp, tenant_id, user_id, doc_id, risk_reasons, msg
| filter injection_detected = true
| sort @timestamp desc
| limit 50
```

---

### 5. Semantic Cache Efficiency & Hit Rates

Track cache hit ratios to measure latency savings and verify scope-key partitioning:

```sql
fields @timestamp, tenant_id, cache_hit
| filter ispresent(cache_hit)
| stats count(*) as total_queries,
        sum(cache_hit == true) as cache_hits,
        (sum(cache_hit == true) * 100.0 / count(*)) as hit_rate_pct
        by tenant_id, bin(1d)
| sort @timestamp desc
```

---

### 6. Audit Chain Integrity Anomalies

Monitor for any cryptographic hashchain verification failures or sequential break events:

```sql
fields @timestamp, tenant_id, seq, broken_at, verification_status, msg
| filter verification_status = "broken" or msg like /(?i)hash_mismatch/ or msg like /(?i)broken_chain/
| sort @timestamp desc
```

---

## Incident Response Triage Checklist

### Alert 1: Elevated API Latency (> 3000 ms)
1. Run Query #2 (Latency Percentiles by Path).
2. If `/query` latency is elevated, check whether external Gemini API calls or Qdrant vector retrieval times are spiking.
3. Check Lambda execution memory consumption (`maxMemoryUsed`). If approaching 512 MB, increase memory allocation in `infra/envs/dev/api.tf`.

### Alert 2: Spiking 403 Forbidden Errors
1. Run Query #1 filtered by `status_code = 403`.
2. Determine if errors originate from:
   - Expired Cognito JWT tokens (`TokenExpiredError`): User re-login required.
   - Non-admin accessing `/admin` endpoints: Expected access-denied behavior.
   - Document ACL denials (`Forbidden`): User attempting to access documents outside their role.

### Alert 3: Quarantined Document Spikes
1. Navigate to the Admin Trust Center > **Quarantine Tab**.
2. Review the risk triggers (Prompt Injection Heuristic vs Disallowed PII types).
3. If legitimate internal documents are being quarantined, adjust policy thresholds in the **Policies Tab** or calibrate sensitivity in `eval/thresholds.yaml`.
