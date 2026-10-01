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

export type DocumentVisibility = 'tenant' | 'roles' | 'private'

export interface DocumentRecord {
  id: string
  filename: string
  status: DocumentStatus
  size_bytes: number
  created_at: string
  chunk_count?: number
  content_type?: string
  visibility?: DocumentVisibility
  allowed_roles?: string[]
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

export async function query(question: string, topK: number = 6): Promise<QueryResponse> {
  return apiRequest<QueryResponse>('/query', {
    method: 'POST',
    body: { question, top_k: topK },
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
