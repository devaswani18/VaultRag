import React, { useEffect, useState } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  RefreshCw,
  Download,
  Lock,
  CheckCircle2,
  XCircle,
  FileCheck,
  AlertCircle,
  ChevronDown,
  ChevronRight,
} from 'lucide-react'
import {
  AssuranceReport,
  runAssurance,
  getLatestAssurance,
  verifyAssuranceReport,
  MatrixCell,
  CheckResult,
} from '../../api/client'

const CANARY_INFO: Record<string, { name: string; desc: string; tenant: string }> = {
  C1: {
    name: 'Tenant-wide Public',
    desc: 'Tenant A public doc. Accessible to all Tenant A principals.',
    tenant: 'st-*-a',
  },
  C2: {
    name: 'Manager Role Restricted',
    desc: 'Tenant A doc restricted to manager role. Accessible to A-admin and A-manager.',
    tenant: 'st-*-a',
  },
  C3: {
    name: 'Admin-Private Document',
    desc: 'Tenant A private doc owned by admin. Only accessible to A-admin.',
    tenant: 'st-*-a',
  },
  C4: {
    name: 'User-Granted to Intern',
    desc: 'Tenant A doc with allowed_users=["u-intern"] and role manager. Accessible to A-admin, A-manager, A-intern.',
    tenant: 'st-*-a',
  },
  C5: {
    name: 'Intern-Private Document',
    desc: 'Tenant A private doc owned by intern. Accessible to A-admin and A-intern.',
    tenant: 'st-*-a',
  },
  C6: {
    name: 'Foreign-Tenant Document',
    desc: 'Tenant B doc. STRICTLY BLOCKED for all Tenant A principals; accessible only to B-admin.',
    tenant: 'st-*-b',
  },
}

const PRINCIPALS = [
  { key: 'A-admin', label: 'A-admin', sub: 'Tenant A Admin' },
  { key: 'A-manager', label: 'A-manager', sub: 'Tenant A Manager' },
  { key: 'A-employee', label: 'A-employee', sub: 'Tenant A Employee' },
  { key: 'A-intern', label: 'A-intern', sub: 'Tenant A Intern' },
  { key: 'B-admin', label: 'B-admin', sub: 'Tenant B Admin' },
]

const PIPELINE_STEPS = [
  'Planting synthetic canaries (C1–C6)',
  'Evaluating 30 principal-canary vector retrieval queries',
  'Verifying Tenant Isolation (I1–I4)',
  'Verifying Access Control Matrix (A1–A4)',
  'Testing Sensitive Data Redaction (D1–D2)',
  'Probing Prompt Injection Defense (J1–J3)',
  'Validating Cryptographic Audit Chain (U1–U2)',
  'Checking Certificate Signing & Erasure Teardown (E1–E2)',
  'Inspecting Payload Indexes & Defense Configuration (C1–C2)',
]

export const AssuranceTab: React.FC = () => {
  const [report, setReport] = useState<AssuranceReport | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [running, setRunning] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [selectedBug, setSelectedBug] = useState<string>('none')
  const [activeStep, setActiveStep] = useState<number>(0)
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({
    'Isolation': true,
    'Access Control': true,
  })

  // Verification Drawer State
  const [showVerifyModal, setShowVerifyModal] = useState<boolean>(false)
  const [verifyInputJson, setVerifyInputJson] = useState<string>('')
  const [verifyResult, setVerifyResult] = useState<{ valid: boolean; reason: string | null } | null>(
    null
  )
  const [verifying, setVerifying] = useState<boolean>(false)

  const fetchLatest = async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await getLatestAssurance()
      setReport(data)
    } catch (err: any) {
      if (err?.status === 404) {
        setReport(null)
      } else {
        setError(err?.message || 'Failed to load assurance telemetry')
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchLatest()
  }, [])

  const handleRunTest = async () => {
    try {
      setRunning(true)
      setError(null)
      setActiveStep(0)

      // Step simulation timer for visual feedback
      const stepInterval = setInterval(() => {
        setActiveStep((prev) => {
          if (prev < PIPELINE_STEPS.length - 1) return prev + 1
          return prev
        })
      }, 400)

      const bugArg = selectedBug === 'none' ? null : selectedBug
      const res = await runAssurance(bugArg)

      clearInterval(stepInterval)
      setActiveStep(PIPELINE_STEPS.length)
      setReport(res)
    } catch (err: any) {
      setError(err?.message || 'Security self-test execution failed')
    } finally {
      setRunning(false)
    }
  }

  const handleDownloadReport = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vaultrag-assurance-report-${report.run_id}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleVerifyReport = async () => {
    if (!verifyInputJson.trim()) return
    try {
      setVerifying(true)
      setVerifyResult(null)
      const parsed = JSON.parse(verifyInputJson)
      const res = await verifyAssuranceReport(parsed)
      setVerifyResult(res)
    } catch (err: any) {
      setVerifyResult({
        valid: false,
        reason: err?.message || 'Invalid JSON format or network error',
      })
    } finally {
      setVerifying(false)
    }
  }

  const toggleGroup = (group: string) => {
    setExpandedGroups((prev) => ({ ...prev, [group]: !prev[group] }))
  }

  const getCellFor = (canary: string, principal: string): MatrixCell | undefined => {
    return report?.matrix?.find((m) => m.canary === canary && m.principal === principal)
  }

  // Group checks by category
  const groupedChecks: Record<string, CheckResult[]> = {}
  if (report?.checks) {
    for (const c of report.checks) {
      if (!groupedChecks[c.group]) groupedChecks[c.group] = []
      groupedChecks[c.group].push(c)
    }
  }

  const allPassed = report ? report.summary.passed === report.summary.total && report.summary.leaks === 0 : false

  return (
    <div className="assurance-tab" data-testid="assurance-tab">
      {/* Top Header Card */}
      <div className="trust-card" style={{ marginBottom: '1.25rem' }}>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: '1rem',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <div
                style={{
                  background: allPassed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                  color: allPassed ? 'var(--status-ready)' : 'var(--status-failed)',
                  borderRadius: 8,
                  padding: 8,
                  display: 'flex',
                }}
              >
                {allPassed ? <ShieldCheck size={28} /> : <ShieldAlert size={28} />}
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700 }}>
                    Assurance Center
                  </h2>
                  {report && (
                    <span
                      className={`badge ${allPassed ? 'badge-success' : 'badge-danger'}`}
                      data-testid="assurance-status-badge"
                    >
                      {allPassed
                        ? `${report.summary.passed}/${report.summary.total} CHECKS PASSED`
                        : `${report.summary.leaks} LEAKS DETECTED (${report.summary.passed}/${report.summary.total} PASSED)`}
                    </span>
                  )}
                </div>
                <p style={{ margin: '0.35rem 0 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  Continuous active security testing: live canary isolation, role boundaries, injection defense, and cryptographic chain proofs
                </p>
              </div>
            </div>

            {report && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '1.25rem',
                  marginTop: '0.75rem',
                  fontSize: '0.8rem',
                  color: 'var(--text-muted)',
                }}
              >
                <span>
                  Run ID: <code style={{ color: 'var(--text-primary)' }}>{report.run_id}</code>
                </span>
                <span>
                  Timestamp: {new Date(report.ts * 1000).toLocaleString()}
                </span>
                {report.signature && (
                  <span title={report.signature}>
                    HMAC-SHA256: <code style={{ color: 'var(--status-ready)' }}>{report.signature.slice(0, 12)}...</code>
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Action Buttons & Simulation Mode */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <label htmlFor="sim-select" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Fault Injection Mode:
              </label>
              <select
                id="sim-select"
                value={selectedBug}
                onChange={(e) => setSelectedBug(e.target.value)}
                disabled={running}
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-primary)',
                  borderRadius: 6,
                  padding: '6px 10px',
                  fontSize: '0.85rem',
                }}
                data-testid="select-simulate-bug"
              >
                <option value="none">None (Real Security Run)</option>
                <option value="drop_role_condition">Simulate: Missing Role Filter</option>
                <option value="ignore_private">Simulate: Private Scope Bypass</option>
              </select>
            </div>

            <button
              type="button"
              className="btn-primary"
              onClick={handleRunTest}
              disabled={running}
              style={{ marginTop: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
              data-testid="btn-run-assurance"
            >
              {running ? <RefreshCw size={15} className="spin" /> : <Play size={15} />}
              <span>{running ? 'Testing Vault...' : 'Run Security Self-Test'}</span>
            </button>

            {report && (
              <button
                type="button"
                className="btn-secondary"
                onClick={handleDownloadReport}
                style={{ marginTop: 'auto', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                data-testid="btn-download-report"
                title="Download signed JSON report"
              >
                <Download size={14} />
                <span>Download Report</span>
              </button>
            )}

            <button
              type="button"
              className="btn-secondary"
              onClick={() => setShowVerifyModal(true)}
              style={{ marginTop: 'auto', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              data-testid="btn-open-verify-modal"
            >
              <FileCheck size={14} />
              <span>Verify a Report</span>
            </button>
          </div>
        </div>

        {/* Warning Banner if Simulation Mode Active */}
        {report?.simulated && (
          <div
            style={{
              marginTop: '1rem',
              padding: '0.75rem 1rem',
              borderRadius: 8,
              background: 'rgba(245, 158, 11, 0.12)',
              border: '1px solid rgba(245, 158, 11, 0.4)',
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
            }}
            data-testid="simulation-banner"
          >
            <AlertTriangle size={20} color="var(--status-pending)" />
            <div>
              <strong style={{ color: 'var(--status-pending)', fontSize: '0.9rem' }}>
                SIMULATION MODE ACTIVE: Injected Fault &ldquo;{report.simulated_bug}&rdquo;
              </strong>
              <p style={{ margin: '0.2rem 0 0', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                This run demonstrates live fault injection. Expected leaks are visualized below. Notice cross-tenant isolation (Check I1) remains strictly enforced.
              </p>
            </div>
          </div>
        )}

        {/* Stepper Progress Bar (Active during run) */}
        {running && (
          <div style={{ marginTop: '1.25rem' }} data-testid="assurance-stepper">
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.4rem', fontSize: '0.8rem' }}>
              <span style={{ color: 'var(--accent-primary)', fontWeight: 600 }}>
                Step {Math.min(activeStep + 1, PIPELINE_STEPS.length)} of {PIPELINE_STEPS.length}: {PIPELINE_STEPS[activeStep] || 'Finalizing Attestation'}
              </span>
              <span style={{ color: 'var(--text-muted)' }}>
                {Math.round(((activeStep + 1) / PIPELINE_STEPS.length) * 100)}%
              </span>
            </div>
            <div className="progress-bar-container">
              <div
                className="progress-bar-fill primary"
                style={{
                  width: `${Math.min(100, Math.round(((activeStep + 1) / PIPELINE_STEPS.length) * 100))}%`,
                  transition: 'width 0.3s ease',
                }}
              />
            </div>
          </div>
        )}

        {error && (
          <div style={{ marginTop: '1rem', color: 'var(--status-failed)', fontSize: '0.85rem' }}>
            <AlertCircle size={16} style={{ display: 'inline', verticalAlign: 'middle', marginRight: 6 }} />
            {error}
          </div>
        )}
      </div>

      {loading && !report && (
        <div className="tab-loading-state" data-testid="assurance-loading">
          <div className="spinner" />
          <p>Loading security self-test attestation...</p>
        </div>
      )}

      {/* Access Matrix Grid Card */}
      {report && (
        <div className="trust-card" style={{ marginBottom: '1.25rem' }} data-testid="access-matrix-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Lock size={16} color="var(--accent-primary)" />
                Continuous Access Control & Isolation Matrix
              </h3>
              <p style={{ margin: '0.25rem 0 0', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Evaluated in real-time by planting 6 canary unit vectors in Qdrant and querying across 5 synthetic identities.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.75rem' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--status-ready)' }}>
                <CheckCircle2 size={13} /> Allowed
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--text-muted)' }}>
                <Lock size={13} /> Blocked
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--status-failed)', fontWeight: 700 }}>
                <AlertTriangle size={13} /> LEAK
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--status-pending)', fontWeight: 700 }}>
                <AlertCircle size={13} /> MISSING
              </span>
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table
              style={{
                width: '100%',
                borderCollapse: 'collapse',
                textAlign: 'left',
                fontSize: '0.85rem',
              }}
              data-testid="access-matrix-table"
            >
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', background: 'var(--bg-secondary)' }}>
                  <th style={{ padding: '10px 14px', width: '220px' }}>Canary Vector Tier</th>
                  {PRINCIPALS.map((p) => (
                    <th key={p.key} style={{ padding: '10px 14px', textAlign: 'center' }}>
                      <div style={{ fontWeight: 600 }}>{p.label}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{p.sub}</div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.entries(CANARY_INFO).map(([cKey, cInfo]) => (
                  <tr
                    key={cKey}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      transition: 'background 0.15s ease',
                    }}
                  >
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        <code style={{ color: 'var(--accent-primary)', marginRight: 6 }}>{cKey}</code>
                        {cInfo.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 2 }}>
                        {cInfo.desc}
                      </div>
                    </td>
                    {PRINCIPALS.map((p) => {
                      const cell = getCellFor(cKey, p.key)
                      const state = cell?.state || 'blocked'

                      let bg = 'transparent'
                      let color = 'var(--text-muted)'
                      let icon = <Lock size={14} />
                      let text = 'Blocked'

                      if (state === 'allowed') {
                        bg = 'rgba(16, 185, 129, 0.08)'
                        color = 'var(--status-ready)'
                        icon = <CheckCircle2 size={14} />
                        text = 'Allowed'
                      } else if (state === 'leak') {
                        bg = 'rgba(239, 68, 68, 0.2)'
                        color = 'var(--status-failed)'
                        icon = <AlertTriangle size={15} />
                        text = 'LEAK'
                      } else if (state === 'missing') {
                        bg = 'rgba(245, 158, 11, 0.18)'
                        color = 'var(--status-pending)'
                        icon = <AlertCircle size={15} />
                        text = 'MISSING'
                      }

                      const tooltip = `${cKey} accessed by ${p.key}: Expected ${cell?.expected_allowed ? 'Allowed' : 'Blocked'}, Actual ${cell?.actually_allowed ? 'Allowed' : 'Blocked'} (${state.toUpperCase()})`

                      return (
                        <td
                          key={p.key}
                          style={{
                            padding: '10px 14px',
                            textAlign: 'center',
                            background: bg,
                            borderLeft: '1px solid var(--border-subtle)',
                          }}
                          title={tooltip}
                          data-testid={`cell-${cKey}-${p.key}`}
                        >
                          <div
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.35rem',
                              color,
                              fontWeight: state === 'leak' || state === 'missing' ? 700 : 500,
                            }}
                          >
                            {icon}
                            <span>{text}</span>
                          </div>
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Security Checks List Card */}
      {report && (
        <div className="trust-card" data-testid="security-checks-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>
              Live Security & Isolation Checks ({report.summary.passed}/{report.summary.total} Passed)
            </h3>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                const allKeys = Object.keys(groupedChecks)
                const nextState: Record<string, boolean> = {}
                const areAnyCollapsed = allKeys.some((k) => !expandedGroups[k])
                for (const k of allKeys) nextState[k] = areAnyCollapsed
                setExpandedGroups(nextState)
              }}
              style={{ fontSize: '0.75rem', padding: '4px 8px' }}
            >
              Toggle All
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {Object.entries(groupedChecks).map(([groupName, checkList]) => {
              const isExpanded = expandedGroups[groupName] ?? true
              const groupPassedCount = checkList.filter((c) => c.passed).length
              const allGroupPassed = groupPassedCount === checkList.length

              return (
                <div
                  key={groupName}
                  style={{
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 8,
                    overflow: 'hidden',
                  }}
                  data-testid={`check-group-${groupName.replace(/\s+/g, '-').toLowerCase()}`}
                >
                  <div
                    onClick={() => toggleGroup(groupName)}
                    style={{
                      padding: '10px 14px',
                      background: 'var(--bg-secondary)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      cursor: 'pointer',
                      userSelect: 'none',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600, fontSize: '0.9rem' }}>
                      {isExpanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      <span>{groupName}</span>
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        ({groupPassedCount}/{checkList.length} passed)
                      </span>
                    </div>
                    <span
                      className={`badge ${allGroupPassed ? 'badge-success' : 'badge-danger'}`}
                      style={{ fontSize: '0.75rem' }}
                    >
                      {allGroupPassed ? 'PASS' : 'FAIL'}
                    </span>
                  </div>

                  {isExpanded && (
                    <div style={{ padding: '8px 14px', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                      {checkList.map((c) => (
                        <div
                          key={c.id}
                          style={{
                            padding: '8px 10px',
                            borderRadius: 6,
                            background: c.passed ? 'var(--bg-surface)' : 'rgba(239, 68, 68, 0.08)',
                            borderLeft: `3px solid ${c.passed ? 'var(--status-ready)' : 'var(--status-failed)'}`,
                            fontSize: '0.82rem',
                          }}
                          data-testid={`check-item-${c.id}`}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
                              <span style={{ color: 'var(--accent-primary)', fontFamily: 'var(--font-mono)' }}>
                                {c.id}
                              </span>
                              <span>{c.name}</span>
                              <span
                                style={{
                                  fontSize: '0.7rem',
                                  padding: '1px 5px',
                                  borderRadius: 4,
                                  background: c.severity === 'high' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(100, 113, 150, 0.2)',
                                  color: c.severity === 'high' ? 'var(--status-failed)' : 'var(--text-secondary)',
                                  textTransform: 'uppercase',
                                }}
                              >
                                {c.severity}
                              </span>
                            </div>
                            <span
                              style={{
                                color: c.passed ? 'var(--status-ready)' : 'var(--status-failed)',
                                fontWeight: 700,
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.3rem',
                              }}
                            >
                              {c.passed ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                              {c.passed ? 'PASSED' : 'FAILED'}
                            </span>
                          </div>

                          <div style={{ marginTop: '0.35rem', color: 'var(--text-secondary)' }}>
                            {c.detail}
                          </div>

                          <div
                            style={{
                              marginTop: '0.35rem',
                              fontSize: '0.75rem',
                              color: 'var(--text-muted)',
                              display: 'flex',
                              gap: '1rem',
                            }}
                          >
                            <span>
                              <strong>Expected:</strong> {c.expected}
                            </span>
                            <span>
                              <strong>Observed:</strong> {c.actual}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Verify External Report Modal / Drawer */}
      {showVerifyModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            backdropFilter: 'blur(4px)',
          }}
          data-testid="verify-report-modal"
        >
          <div
            className="trust-card"
            style={{
              width: '90%',
              maxWidth: '650px',
              maxHeight: '90vh',
              overflowY: 'auto',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-strong)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FileCheck size={18} color="var(--accent-primary)" />
                Cryptographic Assurance Report Verifier
              </h3>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  setShowVerifyModal(false)
                  setVerifyResult(null)
                }}
                style={{ padding: '2px 8px' }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
              Paste any exported Assurance Report JSON below to cryptographically verify its HMAC-SHA256 signature and tenant scoping.
            </p>

            <textarea
              rows={8}
              value={verifyInputJson}
              onChange={(e) => setVerifyInputJson(e.target.value)}
              placeholder="Paste signed report JSON here..."
              style={{
                width: '100%',
                background: 'var(--bg-primary)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.78rem',
                borderRadius: 6,
                padding: 10,
                resize: 'vertical',
              }}
              data-testid="textarea-verify-json"
            />

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.75rem' }}>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  setShowVerifyModal(false)
                  setVerifyResult(null)
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={handleVerifyReport}
                disabled={verifying || !verifyInputJson.trim()}
                data-testid="btn-submit-verify-report"
              >
                {verifying ? 'Verifying...' : 'Verify Cryptographic Signature'}
              </button>
            </div>

            {verifyResult && (
              <div
                style={{
                  marginTop: '1rem',
                  padding: '10px 14px',
                  borderRadius: 6,
                  background: verifyResult.valid ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                  border: `1px solid ${verifyResult.valid ? 'var(--status-ready)' : 'var(--status-failed)'}`,
                }}
                data-testid="verify-report-result"
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
                  {verifyResult.valid ? (
                    <CheckCircle2 size={18} color="var(--status-ready)" />
                  ) : (
                    <XCircle size={18} color="var(--status-failed)" />
                  )}
                  <span style={{ color: verifyResult.valid ? 'var(--status-ready)' : 'var(--status-failed)' }}>
                    {verifyResult.valid
                      ? 'CRYPTOGRAPHIC SIGNATURE VALID — Report is Authentic and Scoped to Tenant'
                      : 'VERIFICATION FAILED'}
                  </span>
                </div>
                {verifyResult.reason && (
                  <p style={{ margin: '0.35rem 0 0', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {verifyResult.reason}
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
