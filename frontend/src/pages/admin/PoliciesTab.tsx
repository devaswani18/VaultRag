import React, { useEffect, useState } from 'react'
import { TenantPolicies, getPolicies, updatePolicies } from '../../api/client'
import {
  Sliders,
  ShieldCheck,
  AlertTriangle,
  Check,
  FileCheck2,
} from 'lucide-react'

export const PoliciesTab: React.FC = () => {
  const [initialPolicies, setInitialPolicies] = useState<TenantPolicies | null>(null)
  const [policies, setPolicies] = useState<TenantPolicies>({
    pii_mode: 'redact',
    injection_policy: 'quarantine_high',
    min_retrieval_score: 0.35,
    min_faithfulness: 0.6,
    daily_query_quota: 200,
    cache_enabled: true,
    retain_original_files: true,
    llm_judge_enabled: false,
    chat_history_days: 7,
  })

  const [loading, setLoading] = useState<boolean>(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [serverError, setServerError] = useState<string | null>(null)
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({})
  const [successMessage, setSuccessMessage] = useState<string | null>(null)

  // Confirmation modal state
  const [showConfirmModal, setShowConfirmModal] = useState<boolean>(false)
  const [isSaving, setIsSaving] = useState<boolean>(false)

  const fetchCurrentPolicies = async () => {
    try {
      setLoading(true)
      setFetchError(null)
      const data = await getPolicies()
      setInitialPolicies(data)
      setPolicies(data)
    } catch (err: any) {
      setFetchError(err?.message || 'Failed to load security policies')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCurrentPolicies()
  }, [])

  // Keyboard accessibility for confirm modal
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showConfirmModal) {
        setShowConfirmModal(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [showConfirmModal])

  const validateForm = (): boolean => {
    const errors: Record<string, string> = {}

    if (
      isNaN(policies.min_retrieval_score) ||
      policies.min_retrieval_score < 0 ||
      policies.min_retrieval_score > 1
    ) {
      errors.min_retrieval_score = 'Must be a number between 0.00 and 1.00'
    }

    if (
      isNaN(policies.min_faithfulness) ||
      policies.min_faithfulness < 0 ||
      policies.min_faithfulness > 1
    ) {
      errors.min_faithfulness = 'Must be a number between 0.00 and 1.00'
    }

    if (
      isNaN(policies.daily_query_quota) ||
      !Number.isInteger(Number(policies.daily_query_quota)) ||
      policies.daily_query_quota < 1 ||
      policies.daily_query_quota > 10000
    ) {
      errors.daily_query_quota = 'Must be an integer between 1 and 10,000'
    }

    if (
      policies.chat_history_days !== undefined &&
      (isNaN(policies.chat_history_days) ||
        !Number.isInteger(Number(policies.chat_history_days)) ||
        policies.chat_history_days < 0 ||
        policies.chat_history_days > 30)
    ) {
      errors.chat_history_days = 'Must be an integer between 0 and 30 days'
    }

    setClientErrors(errors)
    return Object.keys(errors).length === 0
  }

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setServerError(null)
    setSuccessMessage(null)

    if (validateForm()) {
      setShowConfirmModal(true)
    }
  }

  const handleConfirmSave = async () => {
    try {
      setIsSaving(true)
      setServerError(null)

      const patchPayload: Partial<TenantPolicies> = {
        pii_mode: policies.pii_mode,
        injection_policy: policies.injection_policy,
        min_retrieval_score: Number(policies.min_retrieval_score),
        min_faithfulness: Number(policies.min_faithfulness),
        daily_query_quota: Number(policies.daily_query_quota),
        cache_enabled: Boolean(policies.cache_enabled),
        retain_original_files: Boolean(policies.retain_original_files),
        llm_judge_enabled: Boolean(policies.llm_judge_enabled),
        chat_history_days: Number(policies.chat_history_days ?? 7),
      }

      const updated = await updatePolicies(patchPayload)
      setInitialPolicies(updated)
      setPolicies(updated)
      setShowConfirmModal(false)
      setSuccessMessage('Tenant security policies updated and cryptographically audited!')
    } catch (err: any) {
      setServerError(err?.message || 'Server rejected policy update')
      setShowConfirmModal(false)
    } finally {
      setIsSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="tab-loading-state" data-testid="policies-loading">
        <div className="spinner" />
        <p>Loading tenant security configuration...</p>
      </div>
    )
  }

  if (fetchError && !initialPolicies) {
    return (
      <div className="tab-error-state" data-testid="policies-fetch-error">
        <AlertTriangle size={24} />
        <p>{fetchError}</p>
        <button type="button" className="btn-secondary" onClick={fetchCurrentPolicies}>
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="policies-tab" data-testid="policies-tab">
      <div style={{ marginBottom: '1.25rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>Security & Operational Policies</h2>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Fine-tune guardrails, PII redaction, prompt injection thresholds, and quota caps.
        </p>
      </div>

      {serverError && (
        <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="policies-server-error">
          <AlertTriangle size={16} />
          <span>{serverError}</span>
        </div>
      )}

      {successMessage && (
        <div className="success-alert" style={{ marginBottom: '1rem' }} data-testid="policies-success-banner">
          <FileCheck2 size={16} />
          <span>{successMessage}</span>
        </div>
      )}

      <form onSubmit={handleFormSubmit} noValidate data-testid="policies-form">
        <div className="form-grid-2col">
          {/* 1. pii_mode */}
          <div className="form-group">
            <label htmlFor="field-pii-mode" className="form-label">
              PII Mode
            </label>
            <select
              id="field-pii-mode"
              className="form-input"
              value={policies.pii_mode}
              onChange={(e) =>
                setPolicies({ ...policies, pii_mode: e.target.value as TenantPolicies['pii_mode'] })
              }
              data-testid="input-pii-mode"
            >
              <option value="redact">Redact (Mask detected PII tokens before generation)</option>
              <option value="flag">Flag Only (Retain tokens but log telemetry)</option>
              <option value="block">Block (Abstain if question or context contains PII)</option>
              <option value="off">Off (Disable PII inspection)</option>
            </select>
            <span className="form-help-text">
              Determines how Personally Identifiable Information is processed and scrubbed across queries.
            </span>
          </div>

          {/* 2. injection_policy */}
          <div className="form-group">
            <label htmlFor="field-injection-policy" className="form-label">
              Prompt Injection Policy
            </label>
            <select
              id="field-injection-policy"
              className="form-input"
              value={policies.injection_policy}
              onChange={(e) =>
                setPolicies({
                  ...policies,
                  injection_policy: e.target.value as TenantPolicies['injection_policy'],
                })
              }
              data-testid="input-injection-policy"
            >
              <option value="quarantine_high">Quarantine High (Isolate risky documents automatically)</option>
              <option value="flag_only">Flag Only (Ingest but report risk in quarantine dashboard)</option>
              <option value="off">Off (Do not scan chunks for injection patterns)</option>
            </select>
            <span className="form-help-text">
              Defines the enforcement tier when prompt injection heuristics trigger during document ingestion.
            </span>
          </div>

          {/* 3. min_retrieval_score */}
          <div className="form-group">
            <label htmlFor="field-min-retrieval-score" className="form-label">
              Min Retrieval Score (0.00 – 1.00)
            </label>
            <input
              id="field-min-retrieval-score"
              type="number"
              step="0.01"
              min="0"
              max="1"
              className={`form-input ${clientErrors.min_retrieval_score ? 'input-error' : ''}`}
              value={policies.min_retrieval_score}
              onChange={(e) =>
                setPolicies({ ...policies, min_retrieval_score: parseFloat(e.target.value) })
              }
              data-testid="input-min-retrieval-score"
            />
            {clientErrors.min_retrieval_score && (
              <span className="error-text" data-testid="error-min-retrieval-score">
                {clientErrors.min_retrieval_score}
              </span>
            )}
            <span className="form-help-text">
              Minimum cosine similarity threshold required for vector chunks to be included in generative context.
            </span>
          </div>

          {/* 4. min_faithfulness */}
          <div className="form-group">
            <label htmlFor="field-min-faithfulness" className="form-label">
              Min Faithfulness Threshold (0.00 – 1.00)
            </label>
            <input
              id="field-min-faithfulness"
              type="number"
              step="0.01"
              min="0"
              max="1"
              className={`form-input ${clientErrors.min_faithfulness ? 'input-error' : ''}`}
              value={policies.min_faithfulness}
              onChange={(e) =>
                setPolicies({ ...policies, min_faithfulness: parseFloat(e.target.value) })
              }
              data-testid="input-min-faithfulness"
            />
            {clientErrors.min_faithfulness && (
              <span className="error-text" data-testid="error-min-faithfulness">
                {clientErrors.min_faithfulness}
              </span>
            )}
            <span className="form-help-text">
              Threshold below which the model safely abstains or drops unsupported claims.
            </span>
          </div>

          {/* 5. daily_query_quota */}
          <div className="form-group">
            <label htmlFor="field-daily-quota" className="form-label">
              Daily Query Quota (1 – 10,000)
            </label>
            <input
              id="field-daily-quota"
              type="number"
              step="1"
              min="1"
              max="10000"
              className={`form-input ${clientErrors.daily_query_quota ? 'input-error' : ''}`}
              value={policies.daily_query_quota}
              onChange={(e) =>
                setPolicies({ ...policies, daily_query_quota: parseInt(e.target.value, 10) })
              }
              data-testid="input-daily-quota"
            />
            {clientErrors.daily_query_quota && (
              <span className="error-text" data-testid="error-daily-quota">
                {clientErrors.daily_query_quota}
              </span>
            )}
            <span className="form-help-text">
              Maximum number of queries permitted per calendar day (UTC) before rate limits engage.
            </span>
          </div>

          {/* 6. chat_history_days */}
          <div className="form-group">
            <label htmlFor="field-chat-history-days" className="form-label">
              Conversation History Retention (0 – 30 Days)
            </label>
            <input
              id="field-chat-history-days"
              type="number"
              step="1"
              min="0"
              max="30"
              className={`form-input ${clientErrors.chat_history_days ? 'input-error' : ''}`}
              value={policies.chat_history_days ?? 7}
              onChange={(e) =>
                setPolicies({ ...policies, chat_history_days: parseInt(e.target.value, 10) })
              }
              data-testid="input-chat-history-days"
            />
            {clientErrors.chat_history_days && (
              <span className="error-text" data-testid="error-chat-history-days">
                {clientErrors.chat_history_days}
              </span>
            )}
            <span className="form-help-text">
              Number of days to store user conversation history before automatic TTL expiration (0 disables history).
            </span>
          </div>
        </div>

        {/* Toggles Grid */}
        <div className="toggles-grid" style={{ marginTop: '1rem', marginBottom: '1.5rem' }}>
          {/* 6. cache_enabled */}
          <div className="toggle-card">
            <label className="toggle-label" htmlFor="toggle-cache-enabled">
              <input
                id="toggle-cache-enabled"
                type="checkbox"
                checked={policies.cache_enabled}
                onChange={(e) => setPolicies({ ...policies, cache_enabled: e.target.checked })}
                data-testid="toggle-cache-enabled"
              />
              <span className="toggle-title">Enable Semantic Answer Cache</span>
            </label>
            <span className="form-help-text">
              Accelerate response time and economize quota for recurring natural-language questions.
            </span>
          </div>

          {/* 7. retain_original_files */}
          <div className="toggle-card">
            <label className="toggle-label" htmlFor="toggle-retain-files">
              <input
                id="toggle-retain-files"
                type="checkbox"
                checked={policies.retain_original_files}
                onChange={(e) =>
                  setPolicies({ ...policies, retain_original_files: e.target.checked })
                }
                data-testid="toggle-retain-files"
              />
              <span className="toggle-title">Retain Original Files in S3</span>
            </label>
            <span className="form-help-text">
              Preserve raw uploaded source files in encrypted tenant storage after vectorization.
            </span>
          </div>

          {/* 8. llm_judge_enabled */}
          <div className="toggle-card">
            <label className="toggle-label" htmlFor="toggle-llm-judge">
              <input
                id="toggle-llm-judge"
                type="checkbox"
                checked={policies.llm_judge_enabled}
                onChange={(e) => setPolicies({ ...policies, llm_judge_enabled: e.target.checked })}
                data-testid="toggle-llm-judge"
              />
              <span className="toggle-title">Enable Secondary LLM Judge</span>
            </label>
            <span className="form-help-text">
              Employ secondary LLM evaluation for ambiguous claims and deep faithfulness verification.
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={fetchCurrentPolicies}
            disabled={isSaving}
            data-testid="btn-reset-policies"
          >
            Reset Form
          </button>
          <button
            type="submit"
            className="btn-primary"
            disabled={isSaving}
            data-testid="btn-save-policies"
          >
            <Sliders size={16} />
            <span>Review & Save Policies</span>
          </button>
        </div>
      </form>

      {/* Confirmation Dialog Modal */}
      {showConfirmModal && (
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget && !isSaving) setShowConfirmModal(false)
          }}
          data-testid="policies-confirm-modal"
        >
          <div
            className="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-policy-title"
            style={{ maxWidth: 480 }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '1rem', color: 'var(--accent-primary)' }}>
              <ShieldCheck size={24} />
              <h3 id="confirm-policy-title" style={{ margin: 0, fontSize: '1.15rem', fontWeight: 600 }}>
                Confirm Policy Changes
              </h3>
            </div>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              Are you sure you want to update the tenant operational policies? This action will immediately alter guardrail behavior and record an immutable event in the audit hashchain.
            </p>

            <div style={{ background: 'var(--bg-secondary)', padding: '0.85rem', borderRadius: 8, fontSize: '0.82rem', marginBottom: '1.25rem' }}>
              <div><strong>PII Mode:</strong> {policies.pii_mode}</div>
              <div><strong>Injection Policy:</strong> {policies.injection_policy}</div>
              <div><strong>Min Faithfulness:</strong> {policies.min_faithfulness}</div>
              <div><strong>Daily Quota:</strong> {policies.daily_query_quota} queries</div>
              <div><strong>Chat History Retention:</strong> {policies.chat_history_days ?? 7} days</div>
              <div><strong>LLM Judge:</strong> {policies.llm_judge_enabled ? 'Enabled' : 'Disabled'}</div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setShowConfirmModal(false)}
                disabled={isSaving}
                data-testid="btn-cancel-confirm-policies"
              >
                Back to Form
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={handleConfirmSave}
                disabled={isSaving}
                data-testid="btn-confirm-save-policies"
              >
                {isSaving ? (
                  <>
                    <span className="spinner" />
                    <span>Applying...</span>
                  </>
                ) : (
                  <>
                    <Check size={16} />
                    <span>Confirm & Apply</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
