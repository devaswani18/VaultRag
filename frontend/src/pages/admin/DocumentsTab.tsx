import React, { useCallback, useEffect, useState } from 'react'
import {
  DocumentRecord,
  ErasureCertificate,
  deleteDocument,
  listDocuments,
} from '../../api/client'
import { AclModal } from './AclModal'
import {
  FileText,
  Trash2,
  Download,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  Clock,
  XCircle,
  FileWarning,
  Key,
} from 'lucide-react'

export const DocumentsTab: React.FC = () => {
  const [documents, setDocuments] = useState<DocumentRecord[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  // Modal states
  const [aclDoc, setAclDoc] = useState<DocumentRecord | null>(null)
  const [deletingDoc, setDeletingDoc] = useState<DocumentRecord | null>(null)
  const [isDeleting, setIsDeleting] = useState<boolean>(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const [activeCertificate, setActiveCertificate] = useState<ErasureCertificate | null>(null)

  const fetchDocs = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const docs = await listDocuments()
      setDocuments(docs)
    } catch (err: any) {
      setError(err?.message || 'Failed to load documents')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchDocs()
  }, [fetchDocs])

  const handleConfirmDelete = async () => {
    if (!deletingDoc) return
    const docId = deletingDoc.doc_id || deletingDoc.id
    try {
      setIsDeleting(true)
      setDeleteError(null)
      const cert = await deleteDocument(docId)
      setActiveCertificate(cert)
      setDeletingDoc(null)
      await fetchDocs()
    } catch (err: any) {
      setDeleteError(err?.message || 'Failed to erase document')
    } finally {
      setIsDeleting(false)
    }
  }

  const handleDownloadCertificate = (cert: ErasureCertificate) => {
    const jsonStr = JSON.stringify(cert, null, 2)
    const blob = new Blob([jsonStr], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `erasure-certificate-${cert.doc_id}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleAclSaved = (updatedDoc: DocumentRecord) => {
    const updatedId = updatedDoc.doc_id || updatedDoc.id
    setDocuments((prev) =>
      prev.map((d) => ((d.doc_id || d.id) === updatedId ? { ...d, ...updatedDoc } : d))
    )
  }

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case 'READY':
        return (
          <span className="badge badge-success" data-testid="status-ready">
            <CheckCircle2 size={12} />
            <span>READY</span>
          </span>
        )
      case 'PROCESSING':
      case 'PENDING_UPLOAD':
        return (
          <span className="badge badge-info" data-testid="status-processing">
            <Clock size={12} />
            <span>{status}</span>
          </span>
        )
      case 'QUARANTINED':
        return (
          <span className="badge badge-danger" data-testid="status-quarantined">
            <FileWarning size={12} />
            <span>QUARANTINED</span>
          </span>
        )
      case 'DELETING':
        return (
          <span className="badge badge-warning" data-testid="status-deleting">
            <Clock size={12} />
            <span>DELETING</span>
          </span>
        )
      default:
        return (
          <span className="badge badge-danger" data-testid="status-failed">
            <XCircle size={12} />
            <span>{status}</span>
          </span>
        )
    }
  }

  const renderVisibilityChips = (doc: DocumentRecord) => {
    const vis = doc.visibility || 'tenant'
    if (vis === 'tenant') {
      return (
        <span className="chip chip-tenant" data-testid={`chip-visibility-${doc.id}`}>
          Tenant
        </span>
      )
    }
    if (vis === 'private') {
      return (
        <span className="chip chip-private" data-testid={`chip-visibility-${doc.id}`}>
          Private
        </span>
      )
    }
    const roles = doc.allowed_roles || []
    return (
      <div className="chips-row" data-testid={`chips-roles-${doc.id}`}>
        {roles.length === 0 ? (
          <span className="chip chip-role">roles</span>
        ) : (
          roles.map((r) => (
            <span key={r} className="chip chip-role">
              {r}
            </span>
          ))
        )}
      </div>
    )
  }

  const renderPiiBadge = (doc: DocumentRecord) => {
    const summary = doc.pii_summary || {}
    const types = Object.keys(summary)
    if (types.length === 0) {
      return <span className="badge badge-neutral" data-testid={`pii-badge-clean-${doc.id}`}>No PII</span>
    }
    return (
      <span
        className="badge badge-pii"
        title={types.map((t) => `${t}: ${summary[t]}`).join(', ')}
        data-testid={`pii-badge-types-${doc.id}`}
      >
        PII: {types.join(', ')}
      </span>
    )
  }

  const renderInjectionBadge = (doc: DocumentRecord) => {
    const summary = doc.injection_summary || {}
    const quarRep = doc.quarantine_report || []
    const hasHigh = (summary.high ?? 0) > 0 || quarRep.some((q) => q.risk === 'high')
    const hasMed = (summary.medium ?? 0) > 0 || quarRep.some((q) => q.risk === 'medium')

    if (hasHigh) {
      return <span className="badge badge-danger" data-testid={`injection-badge-${doc.id}`}>High Risk</span>
    }
    if (hasMed) {
      return <span className="badge badge-warning" data-testid={`injection-badge-${doc.id}`}>Medium Risk</span>
    }
    return <span className="badge badge-success" data-testid={`injection-badge-${doc.id}`}>Clean</span>
  }

  if (loading) {
    return (
      <div className="tab-loading-state" data-testid="docs-loading">
        <div className="spinner" />
        <p>Loading documents inventory...</p>
      </div>
    )
  }

  return (
    <div className="documents-tab" data-testid="documents-tab">
      {error && (
        <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="docs-error-message">
          <AlertTriangle size={16} />
          <span>{error}</span>
        </div>
      )}

      <div className="table-responsive">
        <table className="data-table" data-testid="admin-docs-table">
          <thead>
            <tr>
              <th>Document</th>
              <th>Status</th>
              <th>Visibility / Roles</th>
              <th>PII Findings</th>
              <th>Injection Risk</th>
              <th>Size</th>
              <th>Created</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {documents.length === 0 ? (
              <tr>
                <td colSpan={8} className="empty-state" data-testid="empty-docs-message">
                  No documents found in this tenant vault.
                </td>
              </tr>
            ) : (
              documents.map((doc) => {
                const docId = doc.doc_id || doc.id
                return (
                  <tr key={docId} data-testid={`doc-row-${docId}`}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <FileText size={16} color="var(--text-secondary)" />
                        <div>
                          <div style={{ fontWeight: 500 }}>{doc.filename}</div>
                          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                            {docId}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>{renderStatusBadge(doc.status)}</td>
                    <td>{renderVisibilityChips(doc)}</td>
                    <td>{renderPiiBadge(doc)}</td>
                    <td>{renderInjectionBadge(doc)}</td>
                    <td>{((doc.size_bytes || 0) / 1024).toFixed(1)} KB</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                      {doc.created_at ? new Date(doc.created_at).toLocaleDateString() : '—'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                          onClick={() => setAclDoc(doc)}
                          data-testid={`btn-acl-${docId}`}
                          title="Change access visibility and roles"
                        >
                          <Key size={13} />
                          <span>Change access</span>
                        </button>
                        <button
                          type="button"
                          className="btn-danger-outline"
                          style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
                          onClick={() => setDeletingDoc(doc)}
                          data-testid={`btn-delete-${docId}`}
                          title="Verifiably erase document"
                        >
                          <Trash2 size={13} />
                          <span>Delete</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* ACL Dialog Modal */}
      {aclDoc && (
        <AclModal
          doc={aclDoc}
          onClose={() => setAclDoc(null)}
          onSaved={handleAclSaved}
        />
      )}

      {/* Delete Confirmation Modal */}
      {deletingDoc && (
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget && !isDeleting) setDeletingDoc(null)
          }}
          data-testid="delete-confirm-modal"
        >
          <div
            className="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="delete-confirm-title"
            style={{ maxWidth: 480 }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem', color: 'var(--danger)' }}>
              <AlertTriangle size={24} />
              <h3 id="delete-confirm-title" style={{ margin: 0, fontSize: '1.2rem', fontWeight: 600 }}>
                Confirm Verifiable Erasure
              </h3>
            </div>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '1rem' }}>
              Are you sure you want to permanently erase <strong>{deletingDoc.filename}</strong>?
            </p>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: '1.5rem' }}>
              This will irreversibly purge all vectors from Qdrant, source files from S3, semantic cache entries, and record an immutable tombstone. A signed cryptographic Certificate of Erasure will be generated.
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
                    <span>Confirm Erasure</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Certificate Modal */}
      {activeCertificate && (
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setActiveCertificate(null)
          }}
          data-testid="certificate-modal"
        >
          <div
            className="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="cert-modal-title"
            style={{ maxWidth: 540 }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem', color: 'var(--success)' }}>
              <ShieldCheck size={28} />
              <div>
                <h3 id="cert-modal-title" style={{ margin: 0, fontSize: '1.25rem', fontWeight: 600 }}>
                  Certificate of Erasure
                </h3>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Cryptographically verified & signed
                </span>
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
