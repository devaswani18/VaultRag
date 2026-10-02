import React, { useState } from 'react'
import { CertificateVerifyResult, verifyCertificate } from '../../api/client'
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, FileCode2 } from 'lucide-react'

export const CertificateVerifyBox: React.FC = () => {
  const [jsonInput, setJsonInput] = useState<string>('')
  const [result, setResult] = useState<CertificateVerifyResult | null>(null)
  const [verifying, setVerifying] = useState<boolean>(false)
  const [parseError, setParseError] = useState<string | null>(null)

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    setParseError(null)
    setResult(null)

    const trimmed = jsonInput.trim()
    if (!trimmed) {
      setParseError('Please paste a certificate JSON string')
      return
    }

    let parsed: any
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      setParseError('Invalid JSON format. Please paste valid certificate JSON.')
      return
    }

    try {
      setVerifying(true)
      const res = await verifyCertificate(parsed)
      setResult(res)
    } catch (err: any) {
      setResult({
        valid: false,
        reason: err?.message || 'Verification endpoint call failed',
      })
    } finally {
      setVerifying(false)
    }
  }

  const handleClear = () => {
    setJsonInput('')
    setResult(null)
    setParseError(null)
  }

  return (
    <div className="certificate-verify-box trust-card" data-testid="certificate-verify-box">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.75rem' }}>
        <FileCode2 size={20} color="var(--accent-primary)" />
        <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600 }}>Verify Erasure Certificate</h3>
      </div>
      <p style={{ margin: '0 0 1rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
        Paste the signed JSON Certificate of Erasure generated during document deletion to verify its cryptographic HMAC signature and tenant authenticity.
      </p>

      <form onSubmit={handleVerify}>
        <div className="form-group" style={{ marginBottom: '1rem' }}>
          <textarea
            className="form-input"
            rows={5}
            placeholder='{"version": 1, "tenant_id": "...", "signature": "..."}'
            value={jsonInput}
            onChange={(e) => {
              setJsonInput(e.target.value)
              if (result || parseError) {
                setResult(null)
                setParseError(null)
              }
            }}
            data-testid="textarea-certificate-json"
            style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}
          />
        </div>

        {parseError && (
          <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="cert-parse-error">
            <XCircle size={16} />
            <span>{parseError}</span>
          </div>
        )}

        {/* Verification Result Display */}
        {result && (
          <div
            className={`cert-result-banner ${result.valid ? 'valid' : 'invalid'}`}
            style={{
              padding: '0.75rem 1rem',
              borderRadius: 6,
              marginBottom: '1rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.6rem',
              fontSize: '0.88rem',
              background: result.valid ? 'rgba(34, 197, 94, 0.12)' : 'rgba(239, 68, 68, 0.12)',
              border: `1px solid ${result.valid ? 'var(--success)' : 'var(--danger)'}`,
              color: result.valid ? 'var(--success)' : 'var(--danger)',
            }}
            data-testid={result.valid ? 'cert-result-valid' : 'cert-result-invalid'}
          >
            {result.valid ? (
              <>
                <ShieldCheck size={20} />
                <div>
                  <strong>Valid Certificate:</strong> Cryptographic HMAC-SHA256 signature is authentic and verified for this tenant.
                </div>
              </>
            ) : (
              <>
                <ShieldAlert size={20} />
                <div>
                  <strong>Invalid Certificate:</strong> {result.reason || 'Signature mismatch or invalid tenant.'}
                </div>
              </>
            )}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
          {jsonInput && (
            <button
              type="button"
              className="btn-secondary"
              onClick={handleClear}
              disabled={verifying}
              data-testid="btn-clear-cert"
            >
              Clear
            </button>
          )}
          <button
            type="submit"
            className="btn-primary"
            disabled={verifying || !jsonInput.trim()}
            data-testid="btn-verify-cert"
          >
            {verifying ? (
              <>
                <span className="spinner" />
                <span>Verifying Signature...</span>
              </>
            ) : (
              <>
                <CheckCircle2 size={16} />
                <span>Verify Certificate</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  )
}
