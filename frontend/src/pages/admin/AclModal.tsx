import React, { useEffect, useRef, useState } from 'react'
import { DocumentRecord, DocumentVisibility, patchDocumentAcl } from '../../api/client'
import { Shield, Users, User, X, AlertTriangle, Check } from 'lucide-react'

const AVAILABLE_ROLES = ['admin', 'manager', 'employee', 'intern']

interface AclModalProps {
  doc: DocumentRecord
  onClose: () => void
  onSaved: (updatedDoc: DocumentRecord) => void
}

export const AclModal: React.FC<AclModalProps> = ({ doc, onClose, onSaved }) => {
  const [visibility, setVisibility] = useState<DocumentVisibility>(doc.visibility || 'tenant')
  const [selectedRoles, setSelectedRoles] = useState<string[]>(doc.allowed_roles || [])
  const [usersInput, setUsersInput] = useState<string>(
    (doc.allowed_users || []).join(', ')
  )
  const [saving, setSaving] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)

  const modalRef = useRef<HTMLDivElement>(null)
  const visibilitySelectRef = useRef<HTMLSelectElement>(null)

  // Focus trap / keyboard accessibility
  useEffect(() => {
    visibilitySelectRef.current?.focus()

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const handleRoleToggle = (role: string) => {
    if (selectedRoles.includes(role)) {
      setSelectedRoles(selectedRoles.filter((r) => r !== role))
    } else {
      setSelectedRoles([...selectedRoles, role])
    }
  }

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (visibility === 'roles' && selectedRoles.length === 0) {
      setError('Please select at least one permitted role when visibility is set to Roles.')
      return
    }

    const cleanedUsers = usersInput
      .split(',')
      .map((u) => u.trim())
      .filter(Boolean)

    try {
      setSaving(true)
      const docId = doc.doc_id || doc.id
      const updated = await patchDocumentAcl(docId, {
        visibility,
        allowed_roles: visibility === 'roles' ? selectedRoles : [],
        allowed_users: cleanedUsers,
      })
      onSaved(updated)
      onClose()
    } catch (err: any) {
      setError(err?.message || 'Failed to update document access controls')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
      data-testid="acl-modal"
    >
      <div
        className="modal-card"
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="acl-modal-title"
        style={{ maxWidth: 520 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Shield size={20} color="var(--accent-primary)" />
            <h2 id="acl-modal-title" style={{ margin: 0, fontSize: '1.15rem', fontWeight: 600 }}>
              Change Document Access
            </h2>
          </div>
          <button
            type="button"
            className="btn-icon"
            onClick={onClose}
            aria-label="Close modal"
            data-testid="btn-close-acl-modal"
          >
            <X size={18} />
          </button>
        </div>

        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
          Configuring access policies for document: <strong style={{ color: 'var(--text-primary)' }}>{doc.filename}</strong>
        </p>

        {error && (
          <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="acl-error-message">
            <AlertTriangle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSave}>
          {/* Visibility Selector */}
          <div className="form-group" style={{ marginBottom: '1.25rem' }}>
            <label htmlFor="acl-visibility-select" className="form-label">
              Document Visibility
            </label>
            <select
              id="acl-visibility-select"
              ref={visibilitySelectRef}
              className="form-input"
              value={visibility}
              onChange={(e) => setVisibility(e.target.value as DocumentVisibility)}
              data-testid="acl-visibility-select"
            >
              <option value="tenant">Tenant (All authenticated users in this tenant)</option>
              <option value="roles">Role-restricted (Only users with specific roles)</option>
              <option value="private">Private (Only owner and explicit users)</option>
            </select>
            <span className="form-help-text">
              Defines the top-level ACL tier enforced at chunk retrieval time.
            </span>
          </div>

          {/* Role Checkboxes */}
          {visibility === 'roles' && (
            <div className="form-group" style={{ marginBottom: '1.25rem' }} data-testid="roles-selector-container">
              <label className="form-label">
                <Users size={14} style={{ display: 'inline', marginRight: 4 }} />
                Allowed Roles <span style={{ color: 'var(--danger)' }}>*</span>
              </label>
              <div className="roles-checkbox-grid">
                {AVAILABLE_ROLES.map((role) => (
                  <label key={role} className="checkbox-pill-label">
                    <input
                      type="checkbox"
                      checked={selectedRoles.includes(role)}
                      onChange={() => handleRoleToggle(role)}
                      data-testid={`checkbox-role-${role}`}
                    />
                    <span>{role}</span>
                  </label>
                ))}
              </div>
              <span className="form-help-text">
                Users holding ANY of the selected roles will be granted retrieval access.
              </span>
            </div>
          )}

          {/* Allowed Users input */}
          <div className="form-group" style={{ marginBottom: '1.5rem' }}>
            <label htmlFor="acl-users-input" className="form-label">
              <User size={14} style={{ display: 'inline', marginRight: 4 }} />
              Allowed User IDs (Optional)
            </label>
            <input
              id="acl-users-input"
              type="text"
              className="form-input"
              placeholder="e.g. user-abc, user-xyz"
              value={usersInput}
              onChange={(e) => setUsersInput(e.target.value)}
              data-testid="acl-users-input"
            />
            <span className="form-help-text">
              Comma-separated list of Cognito user sub IDs granted direct document access.
            </span>
          </div>

          {/* Modal Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
            <button
              type="button"
              className="btn-secondary"
              onClick={onClose}
              disabled={saving}
              data-testid="btn-cancel-acl"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={saving}
              data-testid="btn-save-acl"
            >
              {saving ? (
                <>
                  <span className="spinner" />
                  <span>Saving ACL...</span>
                </>
              ) : (
                <>
                  <Check size={16} />
                  <span>Save Access Controls</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
