import React, { useCallback, useEffect, useState } from 'react'
import { KnowledgeGapCluster, getKnowledgeGaps } from '../../api/client'
import { HelpCircle, AlertCircle, Calendar, Hash, Tag, Layers } from 'lucide-react'

export const KnowledgeGapsTab: React.FC = () => {
  const [clusters, setClusters] = useState<KnowledgeGapCluster[]>([])
  const [days, setDays] = useState<number>(30)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  const fetchGaps = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await getKnowledgeGaps(days)
      setClusters(data)
    } catch (err: any) {
      setError(err?.message || 'Failed to load knowledge gaps')
    } finally {
      setLoading(false)
    }
  }, [days])

  useEffect(() => {
    fetchGaps()
  }, [fetchGaps])

  return (
    <div className="knowledge-gaps-tab" data-testid="knowledge-gaps-tab">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Unanswered Queries & Gaps</h2>
          <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Deterministically clustered abstentions and low-faithfulness questions highlighting documentation deficiencies.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <label htmlFor="select-gap-days" style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Window:
          </label>
          <select
            id="select-gap-days"
            className="form-input"
            style={{ width: 'auto', padding: '0.35rem 0.6rem' }}
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            data-testid="select-gap-days"
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>
        </div>
      </div>

      {error && (
        <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="gaps-error-message">
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="tab-loading-state" data-testid="gaps-loading">
          <div className="spinner" />
          <p>Clustering unanswered questions...</p>
        </div>
      ) : clusters.length === 0 ? (
        <div className="empty-substate" data-testid="empty-gaps-message">
          <Layers size={24} color="var(--text-muted)" />
          <p style={{ margin: '0.5rem 0 0', fontWeight: 500 }}>No knowledge gaps detected</p>
          <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            All queries within the last {days} days achieved grounded faithfulness.
          </span>
        </div>
      ) : (
        <div className="clusters-list" data-testid="clusters-list">
          {clusters.map((c, idx) => (
            <div key={idx} className="cluster-card" data-testid={`cluster-card-${idx}`}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', marginBottom: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                  <HelpCircle size={18} color="var(--warning)" style={{ flexShrink: 0, marginTop: 2 }} />
                  <div>
                    <h3 style={{ margin: 0, fontSize: '0.98rem', fontWeight: 600 }} data-testid="cluster-representative">
                      {c.representative_preview}
                    </h3>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.35rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      <Calendar size={12} />
                      <span>
                        First seen: {c.first_seen ? new Date(c.first_seen).toLocaleDateString() : '—'} | Last seen: {c.last_seen ? new Date(c.last_seen).toLocaleDateString() : '—'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="cluster-count-badge" data-testid={`cluster-count-${idx}`}>
                  <Hash size={12} />
                  <span>{c.count} queries</span>
                </div>
              </div>

              {c.reasons && c.reasons.length > 0 && (
                <div className="cluster-reasons" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.5rem' }}>
                  <Tag size={12} color="var(--text-muted)" />
                  {c.reasons.map((r) => (
                    <span key={r} className="badge badge-neutral" style={{ fontSize: '0.72rem' }}>
                      {r}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
