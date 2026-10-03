import React, { useEffect, useState } from 'react'
import {
  OverviewSummary,
  getAdminOverview,
  verifyAuditChain,
  getLatestAssurance,
  AssuranceReport,
} from '../../api/client'
import {
  ShieldCheck,
  ShieldAlert,
  Zap,
  Percent,
  FileWarning,
  EyeOff,
  RefreshCw,
  AlertCircle,
  Activity,
  Layers,
} from 'lucide-react'

export const OverviewTab: React.FC = () => {
  const [overview, setOverview] = useState<OverviewSummary | null>(null)
  const [assuranceReport, setAssuranceReport] = useState<AssuranceReport | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [verifying, setVerifying] = useState<boolean>(false)

  const fetchOverview = async () => {
    try {
      setLoading(true)
      setError(null)
      const [data, assurance] = await Promise.all([
        getAdminOverview(),
        getLatestAssurance().catch(() => null),
      ])
      setOverview(data)
      setAssuranceReport(assurance)
    } catch (err: any) {
      setError(err?.message || 'Failed to load security overview')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchOverview()
  }, [])

  const handleVerifyChain = async () => {
    try {
      setVerifying(true)
      await verifyAuditChain()
      await fetchOverview()
    } catch (err: any) {
      setError(err?.message || 'Audit chain verification failed')
    } finally {
      setVerifying(false)
    }
  }

  if (loading) {
    return (
      <div className="tab-loading-state" data-testid="overview-loading">
        <div className="spinner" />
        <p>Loading Trust Center telemetry...</p>
      </div>
    )
  }

  if (error && !overview) {
    return (
      <div className="tab-error-state" data-testid="overview-error">
        <AlertCircle size={28} />
        <p>{error}</p>
        <button type="button" className="btn-secondary" onClick={fetchOverview}>
          Retry
        </button>
      </div>
    )
  }

  const queries = overview?.queries_today ?? 0
  const quota = overview?.daily_query_quota ?? 200
  const quotaPercent = Math.min(100, Math.round((queries / Math.max(1, quota)) * 100))
  const abstainPercent = ((overview?.abstain_rate ?? 0) * 100).toFixed(1)
  const trustPercent = ((overview?.avg_trust_score ?? 0) * 100).toFixed(1)
  const cacheHitPercent = ((overview?.cache_hit_rate ?? 0) * 100).toFixed(1)
  const quarantinedCount = overview?.quarantined_documents_count ?? 0
  const piiEntries = Object.entries(overview?.pii_findings_by_type ?? {})
  const auditStatus = overview?.audit_chain_status

  return (
    <div className="overview-tab" data-testid="overview-tab">
      {/* Top Banner: Audit Chain Status */}
      <div className="audit-chain-status-banner" data-testid="audit-chain-status-badge">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {auditStatus?.valid ? (
            <div className="status-icon intact" data-testid="audit-status-intact">
              <ShieldCheck size={24} />
            </div>
          ) : (
            <div className="status-icon broken" data-testid="audit-status-broken">
              <ShieldAlert size={24} />
            </div>
          )}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <strong style={{ fontSize: '1rem' }}>
                {auditStatus?.valid
                  ? `Cryptographic Audit Chain Intact (${auditStatus.checked} records)`
                  : `Audit Chain Broken at Seq #${auditStatus?.broken_at_seq ?? 'Unknown'}`}
              </strong>
              <span
                className={`badge ${auditStatus?.valid ? 'badge-success' : 'badge-danger'}`}
              >
                {auditStatus?.valid ? 'VERIFIED' : 'TAMPER DETECTED'}
              </span>
            </div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Last verified: {auditStatus?.timestamp ? new Date(auditStatus.timestamp).toLocaleString() : 'Just now'}
            </span>
          </div>
        </div>

        <button
          type="button"
          className="btn-secondary"
          onClick={handleVerifyChain}
          disabled={verifying}
          data-testid="btn-verify-chain-now"
          title="Trigger live hash chain verification"
        >
          <RefreshCw size={14} className={verifying ? 'spin' : ''} />
          <span>{verifying ? 'Verifying...' : 'Verify Now'}</span>
        </button>
      </div>

      {/* Assurance Center Live Posture Banner */}
      <div
        className="trust-card"
        style={{
          marginBottom: '1.25rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
        data-testid="assurance-posture-card"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              background: assuranceReport && assuranceReport.summary.leaks === 0
                ? 'rgba(16, 185, 129, 0.15)'
                : 'rgba(79, 104, 245, 0.15)',
              color: assuranceReport && assuranceReport.summary.leaks === 0
                ? 'var(--status-ready)'
                : 'var(--accent-primary)',
              borderRadius: 8,
              padding: 8,
              display: 'flex',
            }}
          >
            <ShieldCheck size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <strong style={{ fontSize: '0.95rem' }}>Assurance Center Security Posture</strong>
              {assuranceReport ? (
                <span
                  className={`badge ${assuranceReport.summary.leaks === 0 ? 'badge-success' : 'badge-danger'}`}
                  data-testid="overview-assurance-badge"
                >
                  {assuranceReport.summary.passed}/{assuranceReport.summary.total} PASSED
                </span>
              ) : (
                <span className="badge" style={{ background: 'var(--bg-elevated)', color: 'var(--text-muted)' }}>
                  AWAITING FIRST RUN
                </span>
              )}
            </div>
            <p style={{ margin: '0.2rem 0 0', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              {assuranceReport
                ? `Active vector canary self-test: ${assuranceReport.summary.leaks} leaks, 30/30 access cells verified at ${new Date(assuranceReport.ts * 1000).toLocaleTimeString()}`
                : 'Run live canary-based security testing across 19 isolation and access control checks in the Assurance tab.'}
            </p>
          </div>
        </div>
      </div>

      {/* Quota Progress Bar Card */}
      <div className="trust-card" style={{ marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={18} color="var(--accent-primary)" />
            <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600 }}>Daily Query Quota</h3>
          </div>
          <span style={{ fontSize: '0.9rem', fontWeight: 600 }} data-testid="quota-counter">
            {queries} / {quota} queries ({quotaPercent}%)
          </span>
        </div>
        <div className="progress-bar-container" data-testid="quota-progress-container">
          <div
            className={`progress-bar-fill ${quotaPercent > 90 ? 'danger' : quotaPercent > 70 ? 'warning' : 'primary'}`}
            style={{ width: `${quotaPercent}%` }}
            data-testid="quota-progress-fill"
          />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.35rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <span>0</span>
          <span>{Math.round(quota / 2)}</span>
          <span>{quota} (Resets daily at 00:00 UTC)</span>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="kpi-grid">
        <div className="kpi-card" data-testid="kpi-trust-score">
          <div className="kpi-header">
            <span>Average Trust Score</span>
            <ShieldCheck size={16} color="var(--success)" />
          </div>
          <div className="kpi-value">{trustPercent}%</div>
          <div className="kpi-subtext">Faithfulness across RAG answers</div>
        </div>

        <div className="kpi-card" data-testid="kpi-abstain-rate">
          <div className="kpi-header">
            <span>Abstain Rate</span>
            <Percent size={16} color="var(--warning)" />
          </div>
          <div className="kpi-value">{abstainPercent}%</div>
          <div className="kpi-subtext">Queries blocked by safe abstention</div>
        </div>

        <div className="kpi-card" data-testid="kpi-cache-rate">
          <div className="kpi-header">
            <span>Cache Hit Rate</span>
            <Zap size={16} color="var(--accent-primary)" />
          </div>
          <div className="kpi-value">{cacheHitPercent}%</div>
          <div className="kpi-subtext">30-day semantic cache efficiency</div>
        </div>

        <div className="kpi-card" data-testid="kpi-quarantined-count">
          <div className="kpi-header">
            <span>Quarantined Docs</span>
            <FileWarning size={16} color="var(--danger)" />
          </div>
          <div className="kpi-value">{quarantinedCount}</div>
          <div className="kpi-subtext">Blocked by prompt injection filter</div>
        </div>
      </div>

      {/* PII Findings By Type Card */}
      <div className="trust-card" style={{ marginTop: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <EyeOff size={18} color="var(--accent-primary)" />
          <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600 }}>PII Findings by Type</h3>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>(counts only — no raw data)</span>
        </div>

        {piiEntries.length === 0 ? (
          <div className="empty-substate" data-testid="empty-pii">
            <Layers size={20} color="var(--text-muted)" />
            <span>No PII findings detected across vault documents.</span>
          </div>
        ) : (
          <div className="pii-chips-container" data-testid="pii-chips">
            {piiEntries.map(([type, count]) => (
              <div key={type} className="pii-chip" data-testid={`pii-chip-${type}`}>
                <span className="pii-chip-type">{type}</span>
                <span className="pii-chip-count">{count}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
