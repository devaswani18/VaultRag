import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  DocumentRecord,
  DocumentVisibility,
  ErasureCertificate,
  createDocument,
  deleteDocument,
  listDocuments,
  uploadToPresigned,
} from '../api/client'
import {
  Upload,
  FileText,
  CheckCircle2,
  Clock,
  AlertTriangle,
  XCircle,
  ShieldAlert,
  Trash2,
  Download,
  ShieldCheck,
  MessageSquare,
} from 'lucide-react'

const ALLOWED_EXTENSIONS = ['pdf', 'docx', 'txt', 'md']
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024 // 10 MB limit
const AVAILABLE_ROLES = ['admin', 'manager', 'employee', 'intern']
const FINAL_STATUSES = new Set(['READY', 'FAILED', 'QUARANTINED'])

const CONTENT_TYPE_MAP: Record<string, string> = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  txt: 'text/plain',
  md: 'text/markdown',
}

export const DocumentsPage: React.FC = () => {
  const navigate = useNavigate()
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [isLoadingDocs, setIsLoadingDocs] = useState<boolean>(true)
  const [fetchError, setFetchError] = useState<string | null>(null)

  // Upload Form State
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [visibility, setVisibility] = useState<DocumentVisibility>('tenant')
  const [selectedRoles, setSelectedRoles] = useState<string[]>([])
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploadProgress, setUploadProgress] = useState<number | null>(null)
  const [isUploading, setIsUploading] = useState<boolean>(false)

  // Deletion & Certificate State
  const [deletingDoc, setDeletingDoc] = useState<DocumentRecord | null>(null)
  const [isDeleting, setIsDeleting] = useState<boolean>(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [activeCertificate, setActiveCertificate] = useState<ErasureCertificate | null>(null)

  const fileInputRef = useRef<HTMLInputElement>(null)
  const isMountedRef = useRef<boolean>(true)

  // Load documents
  const loadDocuments = useCallback(async () => {
    try {
      const docs = await listDocuments()
      if (isMountedRef.current) {
        setDocuments(docs)
        setFetchError(null)
      }
      return docs
    } catch (err: any) {
      if (isMountedRef.current) {
        setFetchError(err?.message || 'Failed to load documents')
      }
      return []
    } finally {
      if (isMountedRef.current) {
        setIsLoadingDocs(false)
      }
    }
  }, [])

  // Initial load
  useEffect(() => {
    isMountedRef.current = true
    loadDocuments()
    return () => {
      isMountedRef.current = false
    }
  }, [loadDocuments])

  // Polling every 3s for non-final statuses; stops on unmount or when all final
  useEffect(() => {
    const hasNonFinal = documents.some((d) => !FINAL_STATUSES.has(d.status))
    if (!hasNonFinal) {
      return
    }

    const intervalId = setInterval(async () => {
      if (!isMountedRef.current) return
      try {
        const updated = await listDocuments()
        if (isMountedRef.current) {
          setDocuments(updated)
        }
      } catch {
        // Silently tolerate transient polling errors
      }
    }, 3000)

    // Stop polling on unmount or when dependencies change
    return () => {
      clearInterval(intervalId)
    }
  }, [documents])

  const validateFile = (file: File): string | null => {
    const parts = file.name.split('.')
    if (parts.length < 2) {
      return 'File must have a valid extension (.pdf, .docx, .txt, or .md)'
    }
    const ext = parts[parts.length - 1].toLowerCase()
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return `Invalid file type '.${ext}'. Allowed types: ${ALLOWED_EXTENSIONS.map((e) => `.${e}`).join(', ')}`
    }
    if (file.size <= 0) {
      return 'File is empty'
    }
    if (file.size > MAX_UPLOAD_BYTES) {
      return `File exceeds maximum allowed size of 10 MB (selected: ${(file.size / (1024 * 1024)).toFixed(1)} MB)`
    }
    return null
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUploadError(null)
    const file = e.target.files?.[0]
    if (!file) {
      setSelectedFile(null)
      return
    }

    const error = validateFile(file)
    if (error) {
      setUploadError(error)
      setSelectedFile(null)
      if (fileInputRef.current) fileInputRef.current.value = ''
      return
    }

    setSelectedFile(file)
  }

  const handleRoleToggle = (role: string) => {
    setSelectedRoles((prev) =>
      prev.includes(role) ? prev.filter((r) => r !== role) : [...prev, role]
    )
  }

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setUploadError(null)

    if (!selectedFile) {
      setUploadError('Please choose a file to upload')
      return
    }

    const validationError = validateFile(selectedFile)
    if (validationError) {
      setUploadError(validationError)
      return
    }

    if (visibility === 'roles' && selectedRoles.length === 0) {
      setUploadError('Please select at least one role when visibility is set to "roles"')
      return
    }

    const parts = selectedFile.name.split('.')
    const ext = parts[parts.length - 1].toLowerCase()
    const contentType = CONTENT_TYPE_MAP[ext] || 'application/octet-stream'

    setIsUploading(true)
    setUploadProgress(0)

    try {
      // 1. Create document record via API to obtain S3 presigned post
      const createResp = await createDocument({
        filename: selectedFile.name,
        content_type: contentType,
        size_bytes: selectedFile.size,
        visibility,
        allowed_roles: visibility === 'roles' ? selectedRoles : undefined,
      })

      // 2. Upload file directly to S3 via presigned post
      await uploadToPresigned(createResp.upload, selectedFile, (percent) => {
        if (isMountedRef.current) {
          setUploadProgress(percent)
        }
      })

      // 3. Reset form and reload documents table
      if (isMountedRef.current) {
        setSelectedFile(null)
        setUploadProgress(null)
        setSelectedRoles([])
        if (fileInputRef.current) fileInputRef.current.value = ''
      }
      await loadDocuments()
    } catch (err: any) {
      if (isMountedRef.current) {
        setUploadError(err?.message || 'Failed to complete upload')
      }
    } finally {
      if (isMountedRef.current) {
        setIsUploading(false)
      }
    }
  }

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case 'PENDING_UPLOAD':
        return (
          <span className="status-badge PENDING_UPLOAD" data-testid="status-pending">
            <Clock size={12} />
            PENDING_UPLOAD
          </span>
        )
      case 'PROCESSING':
        return (
          <span className="status-badge PROCESSING" data-testid="status-processing">
            <span className="spinner spinner-dark" style={{ width: 10, height: 10, borderWidth: 1 }} />
            PROCESSING
          </span>
        )
      case 'READY':
        return (
          <span className="status-badge READY" data-testid="status-ready">
            <CheckCircle2 size={12} />
            READY
          </span>
        )
      case 'QUARANTINED':
        return (
          <span className="status-badge QUARANTINED" data-testid="status-quarantined">
            <ShieldAlert size={12} />
            QUARANTINED
          </span>
        )
      case 'FAILED':
        return (
          <span className="status-badge FAILED" data-testid="status-failed">
            <XCircle size={12} />
            FAILED
          </span>
        )
      default:
        return <span className="status-badge">{status}</span>
    }
  }

  const handleDownloadCertificate = (cert: ErasureCertificate) => {
    const blob = new Blob([JSON.stringify(cert, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `certificate-${cert.doc_id}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleConfirmDelete = async () => {
    if (!deletingDoc) return
    setIsDeleting(true)
    setDeleteError(null)
    try {
      const cert = await deleteDocument(deletingDoc.id)
      setActiveCertificate(cert)
      setDeletingDoc(null)
      await loadDocuments()
    } catch (err: any) {
      setDeleteError(err?.message || 'Failed to erase document')
    } finally {
      setIsDeleting(false)
    }
  }

  return (
    <div className="documents-page">
      <div className="page-title-row">
        <h1>Tenant Documents</h1>
        <button
          onClick={loadDocuments}
          disabled={isLoadingDocs}
          className="btn-logout"
          data-testid="btn-refresh-docs"
        >
          {isLoadingDocs ? 'Refreshing...' : 'Refresh List'}
        </button>
      </div>

      {fetchError && (
        <div className="error-banner" data-testid="fetch-error-banner">
          {fetchError}
        </div>
      )}

      {/* Upload Form Card */}
      <section className="upload-card">
        <h2>Upload Document</h2>

        {uploadError && (
          <div className="error-banner" data-testid="upload-error-banner" role="alert">
            <AlertTriangle size={16} style={{ display: 'inline', marginRight: 6 }} />
            {uploadError}
          </div>
        )}

        <form onSubmit={handleUploadSubmit} noValidate>
          <div className="upload-form-grid">
            {/* File Dropzone / Picker */}
            <div
              className="file-dropzone"
              onClick={() => fileInputRef.current?.click()}
              data-testid="file-dropzone"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".pdf,.docx,.txt,.md"
                onChange={handleFileChange}
                disabled={isUploading}
                data-testid="file-input"
              />
              <div className="dropzone-label">
                <Upload size={24} color="var(--accent-primary-hover)" />
                <span>
                  {selectedFile ? 'Change selected file' : 'Click or drop document to upload'}
                </span>
                <span className="dropzone-hint">
                  PDF, DOCX, TXT, or MD (max 10 MB)
                </span>
              </div>
              {selectedFile && (
                <div className="selected-file-badge" data-testid="selected-file-name">
                  <FileText size={14} />
                  <span>{selectedFile.name}</span>
                  <span style={{ color: 'var(--text-muted)' }}>
                    ({(selectedFile.size / 1024).toFixed(1)} KB)
                  </span>
                </div>
              )}
            </div>

            {/* Visibility & Role Access Configuration */}
            <div className="visibility-options">
              <div className="form-group">
                <label htmlFor="select-visibility">Access Visibility</label>
                <select
                  id="select-visibility"
                  className="form-input"
                  value={visibility}
                  onChange={(e) => setVisibility(e.target.value as DocumentVisibility)}
                  disabled={isUploading}
                  data-testid="select-visibility"
                >
                  <option value="tenant">Tenant-Wide (all members)</option>
                  <option value="roles">Role-Restricted</option>
                  <option value="private">Private (owner only)</option>
                </select>
              </div>

              {visibility === 'roles' && (
                <div className="form-group" data-testid="roles-selector-group">
                  <label>Allowed Roles (select at least one)</label>
                  <div className="roles-checkbox-grid">
                    {AVAILABLE_ROLES.map((role) => (
                      <label key={role} className="checkbox-chip">
                        <input
                          type="checkbox"
                          checked={selectedRoles.includes(role)}
                          onChange={() => handleRoleToggle(role)}
                          disabled={isUploading}
                          data-testid={`checkbox-role-${role}`}
                        />
                        <span>{role}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Progress bar */}
          {uploadProgress !== null && (
            <div className="progress-container" data-testid="upload-progress-container">
              <div className="progress-bar-bg">
                <div
                  className="progress-bar-fill"
                  style={{ width: `${uploadProgress}%` }}
                  data-testid="upload-progress-bar"
                />
              </div>
              <div className="progress-text">{uploadProgress}% uploaded</div>
            </div>
          )}

          <div style={{ marginTop: '1rem', display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              className="btn-primary"
              style={{ width: 'auto', minWidth: 160 }}
              disabled={isUploading || !selectedFile}
              data-testid="btn-upload-submit"
            >
              {isUploading ? (
                <>
                  <span className="spinner" />
                  <span>Uploading...</span>
                </>
              ) : (
                <>
                  <Upload size={16} />
                  <span>Start Upload</span>
                </>
              )}
            </button>
          </div>
        </form>
      </section>

      {/* Documents Table */}
      <section className="table-card">
        <table className="documents-table" data-testid="documents-table">
          <thead>
            <tr>
              <th>Filename</th>
              <th>Status</th>
              <th>Size</th>
              <th>Chunks</th>
              <th>Created At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {documents.length === 0 ? (
              <tr>
                <td colSpan={6} className="empty-state" data-testid="empty-docs-message">
                  {isLoadingDocs ? 'Loading documents...' : 'No documents ingested yet.'}
                </td>
              </tr>
            ) : (
              documents.map((doc) => (
                <tr key={doc.id} data-testid={`doc-row-${doc.id}`}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <FileText size={16} color="var(--text-secondary)" />
                      <span style={{ fontWeight: 500 }}>{doc.filename}</span>
                    </div>
                  </td>
                  <td>{renderStatusBadge(doc.status)}</td>
                  <td>{(((doc.size_bytes ?? (doc as any).size) || 0) / 1024).toFixed(1)} KB</td>
                  <td>{doc.chunk_count !== undefined ? doc.chunk_count : '—'}</td>
                  <td style={{ color: 'var(--text-muted)' }}>
                    {new Date(doc.created_at).toLocaleString()}
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      {doc.status === 'READY' && (
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{
                            padding: '0.35rem 0.65rem',
                            fontSize: '0.8rem',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.35rem',
                          }}
                          onClick={() =>
                            navigate('/chat', {
                              state: {
                                preselectedDoc: {
                                  id: doc.id || (doc as any).doc_id,
                                  filename: doc.filename,
                                },
                              },
                            })
                          }
                          data-testid={`btn-ask-doc-${doc.id || (doc as any).doc_id}`}
                          title="Ask about this document"
                        >
                          <MessageSquare size={14} />
                          <span>Ask about this document</span>
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn-danger-outline"
                        style={{
                          padding: '0.35rem 0.65rem',
                          fontSize: '0.8rem',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.35rem',
                        }}
                        onClick={() => setDeletingDoc(doc)}
                        data-testid={`btn-delete-${doc.id}`}
                        title="Verifiably erase document"
                      >
                        <Trash2 size={14} />
                        <span>Erase</span>
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </section>

      {/* Confirmation Dialog Modal */}
      {deletingDoc && (
        <div className="modal-backdrop" data-testid="delete-confirm-modal">
          <div className="modal-card" style={{ maxWidth: 480 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem', color: 'var(--danger)' }}>
              <AlertTriangle size={24} />
              <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 600 }}>Confirm Verifiable Erasure</h3>
            </div>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '1rem' }}>
              Are you sure you want to permanently erase <strong>{deletingDoc.filename}</strong>?
            </p>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: '1.5rem' }}>
              This will irreversibly purge all vectors from Qdrant, source files from S3, semantic cache entries, and replace document metadata with an immutable tombstone. A signed cryptographic Certificate of Erasure will be generated.
            </p>
            {deleteError && (
              <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="delete-error-message">
                <AlertTriangle size={16} />
                <span>{deleteError}</span>
              </div>
            )}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => { setDeletingDoc(null); setDeleteError(null); }}
                disabled={isDeleting}
                data-testid="btn-cancel-delete"
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn-danger"
                onClick={handleConfirmDelete}
                disabled={isDeleting}
                data-testid="btn-confirm-delete"
              >
                {isDeleting ? (
                  <>
                    <span className="spinner" />
                    <span>Erasing...</span>
                  </>
                ) : (
                  <>
                    <Trash2 size={16} />
                    <span>Erase Document</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Certificate of Erasure Modal */}
      {activeCertificate && (
        <div className="modal-backdrop" data-testid="certificate-modal">
          <div className="modal-card" style={{ maxWidth: 540 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem', color: 'var(--success)' }}>
              <ShieldCheck size={28} />
              <div>
                <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 600 }}>Certificate of Erasure</h3>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Cryptographically verified & signed</span>
              </div>
            </div>

            <div style={{ background: 'var(--bg-secondary)', padding: '1rem', borderRadius: 8, fontSize: '0.85rem', fontFamily: 'monospace', marginBottom: '1.25rem' }}>
              <div><strong>Doc ID:</strong> {activeCertificate.doc_id}</div>
              <div><strong>Tenant:</strong> {activeCertificate.tenant_id}</div>
              <div><strong>Requested By:</strong> {activeCertificate.requested_by}</div>
              <div><strong>Vectors Erased:</strong> {activeCertificate.deleted?.vectors ?? 0}</div>
              <div><strong>Files Erased:</strong> {activeCertificate.deleted?.files ?? 0}</div>
              <div><strong>Audit Sequence:</strong> #{activeCertificate.audit_seq}</div>
              <div style={{ wordBreak: 'break-all', marginTop: '0.5rem', color: 'var(--text-muted)' }}>
                <strong>Signature:</strong> {activeCertificate.signature}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setActiveCertificate(null)}
                data-testid="btn-close-certificate"
              >
                Close
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={() => handleDownloadCertificate(activeCertificate)}
                data-testid="btn-download-certificate"
              >
                <Download size={16} />
                <span>Download Certificate</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
