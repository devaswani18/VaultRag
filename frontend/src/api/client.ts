/**
 * VaultRAG API Client
 * Typed client for interacting with the backend API.
 * Never logs tokens, passwords, or document text.
 */

export interface MeResponse {
  tenant_id: string
  user_id: string
  email: string
  roles: string[]
  request_id?: string
}

export type DocumentStatus =
  | 'PENDING_UPLOAD'
  | 'PROCESSING'
  | 'READY'
  | 'QUARANTINED'
  | 'FAILED'
  | 'DELETING'
  | 'DELETE_FAILED'
  | 'DELETED'

export type DocumentVisibility = 'tenant' | 'roles' | 'private'

export interface DocumentRecord {
  id: string
  doc_id?: string
  filename: string
  status: DocumentStatus
  size_bytes: number
  created_at: string
  chunk_count?: number
  content_type?: string
  visibility?: DocumentVisibility
  allowed_roles?: string[]
  allowed_users?: string[]
  owner_user_id?: string
  pii_summary?: Record<string, number>
  injection_summary?: Record<string, number>
  quarantine_report?: Array<{
    chunk_index: number
    page: number | null
    risk: string
    reasons: string[]
  }>
}

export interface CreateDocumentRequest {
  filename: string
  content_type: string
  size_bytes: number
  visibility?: DocumentVisibility
  allowed_roles?: string[]
  allowed_users?: string[]
}

export interface PresignedPost {
  url: string
  fields: Record<string, string>
}

export interface CreateDocumentResponse {
  doc_id: string
  upload: PresignedPost
  expires_in: number
}

export interface QuerySource {
  doc_id: string
  filename: string
  chunk_id: string
  page: number | null
  score: number
  snippet: string
}

export interface QueryTrust {
  score: number
  grounded: boolean
  abstained: boolean
  partial: boolean
  reasons: string[]
}

export interface QueryResponse {
  answer: string
  trust?: QueryTrust
  sources: QuerySource[]
  scope?: { scoped: boolean; n_docs: number }
  request_id?: string
  pii_in_answer?: boolean
  injection_attempt?: boolean
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public requestId?: string,
    public details?: any
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export type TokenGetter = () => string | null | Promise<string | null>

let globalTokenGetter: TokenGetter = () => null
let onUnauthorizedHandler: (() => void) | null = null

export function setTokenGetter(getter: TokenGetter): void {
  globalTokenGetter = getter
}

export function setUnauthorizedHandler(handler: () => void): void {
  onUnauthorizedHandler = handler
}

const DEFAULT_TIMEOUT_MS = 30000

export function getApiBaseUrl(): string {
  const url = import.meta.env.VITE_API_URL || ''
  return url.replace(/\/+$/, '')
}

/**
 * Perform a typed HTTP request to the VaultRAG backend API.
 */
export async function apiRequest<T>(
  path: string,
  options: {
    method?: string
    body?: any
    headers?: Record<string, string>
    timeoutMs?: number
  } = {}
): Promise<T> {
  const baseUrl = getApiBaseUrl()
  const url = `${baseUrl}/${path.replace(/^\/+/, '')}`
  const method = options.method || 'GET'
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS

  const requestId =
    typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : `req-${Date.now()}`

  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Request-Id': requestId,
    ...options.headers,
  }

  const token = await globalTokenGetter()
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  if (options.body !== undefined && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    const response = await fetch(url, {
      method,
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    })

    clearTimeout(timer)

    if (response.status === 401) {
      if (onUnauthorizedHandler) {
        onUnauthorizedHandler()
      }
    }

    if (!response.ok) {
      let code = `HTTP_${response.status}`
      let message = response.statusText || 'An API error occurred'
      let details: any = null
      let respRequestId: string | undefined = response.headers.get('x-request-id') || requestId

      try {
        const errJson = await response.json()
        if (errJson && typeof errJson === 'object') {
          if (errJson.detail) {
            if (typeof errJson.detail === 'object') {
              code = errJson.detail.code || code
              message = errJson.detail.message || message
              respRequestId = errJson.detail.request_id || respRequestId
              details = errJson.detail
            } else if (typeof errJson.detail === 'string') {
              message = errJson.detail
            }
          } else if (errJson.message) {
            message = errJson.message
          }
        }
      } catch {
        // Response wasn't valid JSON, fallback to standard status message
      }

      throw new ApiError(response.status, code, message, respRequestId, details)
    }

    if (response.status === 204) {
      return {} as T
    }

    return (await response.json()) as T
  } catch (err: any) {
    clearTimeout(timer)
    if (err instanceof ApiError) {
      throw err
    }
    if (err?.name === 'AbortError') {
      throw new ApiError(408, 'REQUEST_TIMEOUT', `Request timed out after ${timeoutMs}ms`, requestId)
    }
    throw new ApiError(0, 'NETWORK_ERROR', err?.message || 'Network request failed', requestId)
  }
}

/**
 * API methods matching the backend spec.
 */
export async function me(): Promise<MeResponse> {
  return apiRequest<MeResponse>('/me')
}

export async function listDocuments(): Promise<DocumentRecord[]> {
  return apiRequest<DocumentRecord[]>('/documents')
}

export async function getDocument(id: string): Promise<DocumentRecord> {
  return apiRequest<DocumentRecord>(`/documents/${encodeURIComponent(id)}`)
}

export async function createDocument(meta: CreateDocumentRequest): Promise<CreateDocumentResponse> {
  return apiRequest<CreateDocumentResponse>('/documents', {
    method: 'POST',
    body: meta,
  })
}

export interface ErasureCertificate {
  version: number
  tenant_id: string
  doc_id: string
  requested_by: string
  ts: string
  deleted: {
    vectors: number
    files: number
    cache_entries: number
  }
  post_check: {
    remaining_vectors: number
    remaining_files: number
  }
  audit_seq: number
  signature: string
}

export async function deleteDocument(id: string): Promise<ErasureCertificate> {
  return apiRequest<ErasureCertificate>(`/documents/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  })
}

export async function query(
  question: string,
  topK: number = 6,
  docIds?: string[]
): Promise<QueryResponse> {
  const body: Record<string, any> = { question, top_k: topK }
  if (docIds && docIds.length > 0) {
    body.doc_ids = docIds
  }
  return apiRequest<QueryResponse>('/query', {
    method: 'POST',
    body,
  })
}

/**
 * Upload a document directly to S3 via presigned POST policy with progress tracking.
 */
export function uploadToPresigned(
  post: PresignedPost,
  file: File,
  onProgress?: (percent: number) => void
): Promise<void> {
  return new Promise((resolve, reject) => {
    const formData = new FormData()

    // S3 expects policy fields first, then file
    for (const [key, value] of Object.entries(post.fields)) {
      formData.append(key, value)
    }
    formData.append('file', file)

    const xhr = new XMLHttpRequest()
    xhr.open('POST', post.url)

    if (xhr.upload && onProgress) {
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) {
          const percent = Math.round((event.loaded / event.total) * 100)
          onProgress(percent)
        }
      }
    }

    xhr.onload = () => {
      // S3 presigned POST returns 200, 201, or 204 on success
      if (xhr.status >= 200 && xhr.status < 300) {
        if (onProgress) onProgress(100)
        resolve()
      } else {
        reject(
          new ApiError(
            xhr.status,
            'S3_UPLOAD_FAILED',
            `S3 upload failed with status ${xhr.status}`
          )
        )
      }
    }

    xhr.onerror = () => {
      reject(new ApiError(0, 'S3_NETWORK_ERROR', 'Network error during S3 upload'))
    }

    xhr.ontimeout = () => {
      reject(new ApiError(408, 'S3_TIMEOUT', 'S3 upload timed out'))
    }

    xhr.timeout = 120000 // 2 minutes for upload
    xhr.send(formData)
  })
}

// ============================================================================
// Trust Center & Administration API Methods
// ============================================================================

export interface OverviewSummary {
  tenant_id: string
  queries_today: number
  daily_query_quota: number
  abstain_rate: number
  avg_trust_score: number
  cache_hit_rate: number
  quarantined_documents_count: number
  pii_findings_by_type: Record<string, number>
  audit_chain_status: {
    valid: boolean
    checked: number
    broken_at_seq: number | null
    timestamp: string
  }
}

export interface AuditRecord {
  seq: number
  ts: string
  actor: string
  action: string
  resource_id?: string
  outcome: string
  hash: string
  prev_hash: string
  details?: Record<string, any>
}

export interface AuditListResponse {
  items: AuditRecord[]
  next_cursor: string | null
}

export interface AuditVerifyResponse {
  valid: boolean
  checked: number
  broken_at_seq: number | null
}

export interface AuditAnchorResponse {
  tenant_id: string
  latest_seq: number
  hash: string
  signature: string
  exported_at: string
}

export interface KnowledgeGapCluster {
  representative_preview: string
  count: number
  first_seen: string
  last_seen: string
  reasons: string[]
}

export interface TenantPolicies {
  pii_mode: 'off' | 'flag' | 'redact' | 'block'
  injection_policy: 'off' | 'flag_only' | 'quarantine_high'
  min_retrieval_score: number
  min_faithfulness: number
  daily_query_quota: number
  cache_enabled: boolean
  retain_original_files: boolean
  llm_judge_enabled: boolean
  settings_version?: number
}

export interface QuarantinedDocument {
  doc_id: string
  filename: string
  status: string
  created_at: string
  chunk_count: number
  error?: string | null
  injection_summary?: Record<string, number>
  quarantine_report?: Array<{
    chunk_index: number
    page: number | null
    risk: string
    reasons: string[]
  }>
}

export interface UsageDayRecord {
  tenant_id: string
  day: string
  queries: number
  cache_hits: number
  cache_misses: number
  chunks?: number
  est_tokens?: number
}

export interface UsageResponse {
  tenant_id: string
  days: number
  usage: UsageDayRecord[]
}

export interface PatchDocumentAclRequest {
  visibility: DocumentVisibility
  allowed_roles?: string[]
  allowed_users?: string[]
}

export interface CertificateVerifyResult {
  valid: boolean
  reason?: string | null
}

export async function getAdminOverview(): Promise<OverviewSummary> {
  return apiRequest<OverviewSummary>('/admin/overview')
}

export async function getAuditLogs(
  limit: number = 50,
  cursor?: string | null,
  action?: string,
  actor?: string
): Promise<AuditListResponse> {
  const params = new URLSearchParams()
  params.set('limit', String(limit))
  if (cursor) params.set('cursor', cursor)
  if (action) params.set('action', action)
  if (actor) params.set('actor', actor)

  return apiRequest<AuditListResponse>(`/admin/audit?${params.toString()}`)
}

export async function verifyAuditChain(): Promise<AuditVerifyResponse> {
  return apiRequest<AuditVerifyResponse>('/admin/audit/verify')
}

export async function getAuditAnchor(): Promise<AuditAnchorResponse> {
  return apiRequest<AuditAnchorResponse>('/admin/audit/anchor')
}

export async function exportAuditCsv(): Promise<string> {
  const baseUrl = getApiBaseUrl()
  const token = await globalTokenGetter()
  const res = await fetch(`${baseUrl}/admin/audit/export`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  })
  if (!res.ok) {
    throw new ApiError(res.status, 'EXPORT_FAILED', 'Failed to export audit CSV')
  }
  return res.text()
}

export async function getKnowledgeGaps(days: number = 30): Promise<KnowledgeGapCluster[]> {
  return apiRequest<KnowledgeGapCluster[]>(`/admin/gaps?days=${days}`)
}

export async function getPolicies(): Promise<TenantPolicies> {
  return apiRequest<TenantPolicies>('/admin/policies')
}

export async function updatePolicies(
  patch: Partial<TenantPolicies>
): Promise<TenantPolicies> {
  return apiRequest<TenantPolicies>('/admin/policies', {
    method: 'PATCH',
    body: patch,
  })
}

export async function getQuarantine(): Promise<QuarantinedDocument[]> {
  return apiRequest<QuarantinedDocument[]>('/admin/quarantine')
}

export async function getUsage(days: number = 30): Promise<UsageResponse> {
  return apiRequest<UsageResponse>(`/admin/usage?days=${days}`)
}

export async function verifyCertificate(
  cert: any
): Promise<CertificateVerifyResult> {
  return apiRequest<CertificateVerifyResult>('/admin/certificates/verify', {
    method: 'POST',
    body: cert,
  })
}

export async function patchDocumentAcl(
  docId: string,
  acl: PatchDocumentAclRequest
): Promise<DocumentRecord> {
  return apiRequest<DocumentRecord>(`/documents/${encodeURIComponent(docId)}/acl`, {
    method: 'PATCH',
    body: acl,
  })
}
