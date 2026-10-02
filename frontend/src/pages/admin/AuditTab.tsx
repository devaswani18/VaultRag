import React, { useCallback, useEffect, useState } from 'react'
import {
  AuditAnchorResponse,
  AuditRecord,
  AuditVerifyResponse,
  exportAuditCsv,
  getAuditAnchor,
  getAuditLogs,
  verifyAuditChain,
} from '../../api/client'
import {
  ShieldCheck,
  ShieldAlert,
  FileSpreadsheet,
  Filter,
  RefreshCw,
  AlertCircle,
  ChevronRight,
  Anchor,
} from 'lucide-react'

export const AuditTab: React.FC = () => {
  const [records, setRecords] = useState<AuditRecord[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  // Filters & Pagination
  const [actionFilter, setActionFilter] = useState<string>('')
  const [actorFilter, setActorFilter] = useState<string>('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [cursorHistory, setCursorHistory] = useState<(string | null)[]>([])
  const [currentCursor, setCurrentCursor] = useState<string | null>(null)

  // Actions state
  const [verification, setVerification] = useState<AuditVerifyResponse | null>(null)
  const [isVerifying, setIsVerifying] = useState<boolean>(false)
  const [isExporting, setIsExporting] = useState<boolean>(false)
  const [isDownloadingAnchor, setIsDownloadingAnchor] = useState<boolean>(false)

  const loadAuditLogs = useCallback(
    async (cursor: string | null = null) => {
      try {
        setLoading(true)
        setError(null)
        const res = await getAuditLogs(
          30,
          cursor,
          actionFilter.trim() || undefined,
          actorFilter.trim() || undefined
        )
        setRecords(res.items)
        setNextCursor(res.next_cursor)
        setCurrentCursor(cursor)
      } catch (err: any) {
        setError(err?.message || 'Failed to load audit logs')
      } finally {
        setLoading(false)
      }
    },
    [actionFilter, actorFilter]
  )

  useEffect(() => {
    loadAuditLogs(null)
    setCursorHistory([])
  }, [loadAuditLogs])

  const handleNextPage = () => {
    if (!nextCursor) return
    setCursorHistory((prev) => [...prev, currentCursor])
    loadAuditLogs(nextCursor)
  }

  const handlePrevPage = () => {
    if (cursorHistory.length === 0) return
    const prevCursor = cursorHistory[cursorHistory.length - 1]
    setCursorHistory((prev) => prev.slice(0, -1))
    loadAuditLogs(prevCursor)
  }

  const handleVerifyIntegrity = async () => {
    try {
      setIsVerifying(true)
      setError(null)
      const res = await verifyAuditChain()
      setVerification(res)
    } catch (err: any) {
      setError(err?.message || 'Verification failed')
    } finally {
      setIsVerifying(false)
    }
  }

  const handleExportCsv = async () => {
    try {
      setIsExporting(true)
      const csvData = await exportAuditCsv()
      const blob = new Blob([csvData], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit-trail-${Date.now()}.csv`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err: any) {
      setError(err?.message || 'Failed to export CSV')
    } finally {
      setIsExporting(false)
    }
  }

  const handleDownloadAnchor = async () => {
    try {
      setIsDownloadingAnchor(true)
      const anchor: AuditAnchorResponse = await getAuditAnchor()
      const jsonStr = JSON.stringify(anchor, null, 2)
      const blob = new Blob([jsonStr], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `signed-anchor-seq-${anchor.latest_seq}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err: any) {
      setError(err?.message || 'Failed to download signed anchor')
    } finally {
      setIsDownloadingAnchor(false)
    }
  }

  return (
    <div className="audit-tab" data-testid="audit-tab">
      {/* Top Controls: Actions & Status */}
      <div className="audit-header-actions" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn-primary"
            onClick={handleVerifyIntegrity}
            disabled={isVerifying}
            data-testid="btn-verify-integrity"
          >
            <RefreshCw size={14} className={isVerifying ? 'spin' : ''} />
            <span>{isVerifying ? 'Verifying...' : 'Verify integrity'}</span>
          </button>

          <button
            type="button"
            className="btn-secondary"
            onClick={handleExportCsv}
            disabled={isExporting}
            data-testid="btn-export-csv"
          >
            <FileSpreadsheet size={14} />
            <span>{isExporting ? 'Exporting...' : 'Export CSV'}</span>
          </button>

          <button
            type="button"
            className="btn-secondary"
            onClick={handleDownloadAnchor}
            disabled={isDownloadingAnchor}
            data-testid="btn-download-anchor"
          >
            <Anchor size={14} />
            <span>{isDownloadingAnchor ? 'Signing...' : 'Download signed anchor'}</span>
          </button>
        </div>

        {/* Verification Outcome Badge */}
        {verification && (
          <div
            className={`verify-outcome-badge ${verification.valid ? 'outcome-intact' : 'outcome-broken'}`}
            data-testid={verification.valid ? 'audit-verify-intact' : 'audit-verify-broken'}
          >
            {verification.valid ? (
              <>
                <ShieldCheck size={18} />
                <span>chain intact {verification.checked} records</span>
              </>
            ) : (
              <>
                <ShieldAlert size={18} />
                <span>broken at seq {verification.broken_at_seq ?? 'unknown'}</span>
              </>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="audit-error-message">
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* Filter Bar */}
      <div className="filter-bar" style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flex: '1 1 200px' }}>
          <Filter size={14} color="var(--text-secondary)" />
          <input
            type="text"
            className="form-input"
            placeholder="Filter by action (e.g. query, erasure)..."
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            data-testid="input-action-filter"
          />
        </div>

        <div style={{ flex: '1 1 200px' }}>
          <input
            type="text"
            className="form-input"
            placeholder="Filter by actor (e.g. user-admin)..."
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            data-testid="input-actor-filter"
          />
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="table-responsive">
        <table className="data-table" data-testid="audit-table">
          <thead>
            <tr>
              <th style={{ width: '70px' }}>Seq</th>
              <th style={{ width: '160px' }}>Timestamp</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Outcome</th>
              <th>Hash</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8} className="empty-state" data-testid="audit-loading">
                  <div className="spinner" style={{ margin: '0 auto 0.5rem' }} />
                  Loading audit hashchain records...
                </td>
              </tr>
            ) : records.length === 0 ? (
              <tr>
                <td colSpan={8} className="empty-state" data-testid="empty-audit-message">
                  No audit records match the selected filters.
                </td>
              </tr>
            ) : (
              records.map((r) => (
                <tr key={r.seq} data-testid={`audit-row-${r.seq}`}>
                  <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>#{r.seq}</td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {r.ts ? new Date(r.ts).toLocaleString() : '—'}
                  </td>
                  <td>
                    <span style={{ fontSize: '0.85rem', fontFamily: 'monospace' }}>{r.actor}</span>
                  </td>
                  <td>
                    <span className="badge badge-info" style={{ fontFamily: 'monospace' }}>
                      {r.action}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.8rem', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                    {r.resource_id || '—'}
                  </td>
                  <td>
                    <span
                      className={`badge ${r.outcome === 'ok' ? 'badge-success' : 'badge-danger'}`}
                      style={{ fontSize: '0.72rem' }}
                    >
                      {r.outcome}
                    </span>
                  </td>
                  <td>
                    <span
                      style={{ fontSize: '0.72rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}
                      title={r.hash}
                    >
                      {r.hash ? `${r.hash.slice(0, 10)}...` : '—'}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.78rem', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {r.details ? JSON.stringify(r.details) : '—'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '0.75rem', marginTop: '1rem' }}>
        <button
          type="button"
          className="btn-secondary"
          onClick={handlePrevPage}
          disabled={cursorHistory.length === 0 || loading}
          data-testid="btn-prev-audit-page"
        >
          Previous
        </button>
        <button
          type="button"
          className="btn-secondary"
          onClick={handleNextPage}
          disabled={!nextCursor || loading}
          data-testid="btn-next-audit-page"
        >
          <span>Next</span>
          <ChevronRight size={14} />
        </button>
      </div>
    </div>
  )
}
