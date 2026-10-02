import React, { useCallback, useEffect, useState } from 'react'
import { QuarantinedDocument, getQuarantine } from '../../api/client'
import { FileWarning, AlertCircle, ShieldCheck, Tag } from 'lucide-react'

export const QuarantineTab: React.FC = () => {
  const [items, setItems] = useState<QuarantinedDocument[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  const fetchQuarantine = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await getQuarantine()
      setItems(data)
    } catch (err: any) {
      setError(err?.message || 'Failed to load quarantined items')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchQuarantine()
  }, [fetchQuarantine])

  return (
    <div className="quarantine-tab" data-testid="quarantine-tab">
      <div style={{ marginBottom: '1.25rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Quarantine & Threat Isolation</h2>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Documents and vector chunks blocked by security scanners. Text content is strictly withheld to prevent payload execution.
        </p>
      </div>

      {error && (
        <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="quarantine-error-message">
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="tab-loading-state" data-testid="quarantine-loading">
          <div className="spinner" />
          <p>Scanning security quarantine registry...</p>
        </div>
      ) : items.length === 0 ? (
        <div className="empty-substate" data-testid="empty-quarantine-message">
          <ShieldCheck size={28} color="var(--success)" />
          <p style={{ margin: '0.5rem 0 0', fontWeight: 500 }}>No quarantined documents</p>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            All ingested content successfully cleared prompt injection checks.
          </span>
        </div>
      ) : (
        <div className="quarantine-cards-grid" data-testid="quarantine-cards-grid">
          {items.map((item) => {
            const reports = item.quarantine_report || []
            const injection = item.injection_summary || {}

            return (
              <div key={item.doc_id} className="quarantine-card" data-testid={`quarantine-card-${item.doc_id}`}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.6rem' }}>
                    <FileWarning size={20} color="var(--danger)" style={{ marginTop: 2, flexShrink: 0 }} />
                    <div>
                      <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>{item.filename}</h3>
                      <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-muted)', marginTop: 2 }}>
                        {item.doc_id}
                      </div>
                    </div>
                  </div>

                  <span className="badge badge-danger" data-testid="quarantine-badge">
                    QUARANTINED
                  </span>
                </div>

                {item.error && (
                  <div style={{ background: 'rgba(239, 68, 68, 0.1)', padding: '0.5rem 0.75rem', borderRadius: 6, fontSize: '0.82rem', color: 'var(--danger)', marginBottom: '0.75rem' }}>
                    <strong>Reason:</strong> {item.error}
                  </div>
                )}

                {/* Risk Reasons List (strictly no document text) */}
                <div style={{ marginBottom: '0.75rem' }}>
                  <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                    Detected Threat Triggers (Metadata only):
                  </div>

                  {reports.length === 0 ? (
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Whole document isolated by security policy drop ratio threshold.
                    </span>
                  ) : (
                    <div className="threat-reasons-list">
                      {reports.map((rep, rIdx) => (
                        <div key={rIdx} className="threat-reason-item" data-testid="threat-reason-item">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                            <span className="badge badge-danger" style={{ fontSize: '0.7rem' }}>
                              Chunk #{rep.chunk_index} {rep.page ? `(Page ${rep.page})` : ''} - {rep.risk.toUpperCase()}
                            </span>
                          </div>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginTop: '0.3rem' }}>
                            {(rep.reasons || []).map((reason, reasonIdx) => (
                              <span key={reasonIdx} className="badge badge-neutral" style={{ fontSize: '0.72rem' }}>
                                <Tag size={10} style={{ display: 'inline', marginRight: 3 }} />
                                {reason}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '0.6rem', borderTop: '1px solid var(--border-color)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  <span>Created: {item.created_at ? new Date(item.created_at).toLocaleDateString() : '—'}</span>
                  <span>Injection detections: High({injection.high ?? 0}), Med({injection.medium ?? 0})</span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
