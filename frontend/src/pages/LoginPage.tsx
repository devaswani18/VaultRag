import React, { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { Shield, Lock, UserPlus, CheckCircle2, KeyRound } from 'lucide-react'

export const LoginPage: React.FC = () => {
  const { user, login, signUp, confirmSignUp } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const [mode, setMode] = useState<'signin' | 'signup' | 'confirm'>('signin')

  // Sign In / Sign Up form fields
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [tenantId, setTenantId] = useState('acme')
  const [confirmationCode, setConfirmationCode] = useState('')

  // Error & Status states
  const [emailError, setEmailError] = useState<string | null>(null)
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)

  // Redirect if already authenticated
  if (user) {
    const from = (location.state as any)?.from?.pathname || '/chat'
    return <Navigate to={from} replace />
  }

  const validate = (): boolean => {
    let valid = true
    setEmailError(null)
    setPasswordError(null)
    setAuthError(null)

    const trimmedEmail = email.trim()
    if (!trimmedEmail) {
      setEmailError('Email is required')
      valid = false
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      setEmailError('Please enter a valid email address')
      valid = false
    }

    if (mode !== 'confirm') {
      if (!password) {
        setPasswordError('Password is required')
        valid = false
      } else if (mode === 'signup' && password.length < 12) {
        setPasswordError('Sign-up password must be at least 12 characters (include upper, lower, number, symbol)')
        valid = false
      } else if (password.length < 6) {
        setPasswordError('Password must be at least 6 characters')
        valid = false
      }
    }

    return valid
  }

  const handleSignInSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!validate()) return

    setIsSubmitting(true)
    setAuthError(null)

    try {
      await login(email.trim(), password)
      const from = (location.state as any)?.from?.pathname || '/chat'
      navigate(from, { replace: true })
    } catch (err: any) {
      const msg = err?.message || 'Authentication failed. Please check your credentials.'
      setAuthError(msg)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleSignUpSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!validate()) return

    setIsSubmitting(true)
    setAuthError(null)
    setSuccessMsg(null)

    try {
      const res = await signUp(email.trim(), password, tenantId.trim().toLowerCase())
      if (res.userConfirmed) {
        setSuccessMsg('Account created successfully! You can now sign in.')
        setMode('signin')
      } else {
        setSuccessMsg('Confirmation code sent to your email. Please enter it below.')
        setMode('confirm')
      }
    } catch (err: any) {
      setAuthError(err?.message || 'Registration failed. Check password complexity.')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleConfirmSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!confirmationCode.trim()) {
      setAuthError('Please enter the confirmation code sent to your email')
      return
    }

    setIsSubmitting(true)
    setAuthError(null)

    try {
      await confirmSignUp(email.trim(), confirmationCode.trim())
      setSuccessMsg('Email confirmed! You can now sign in with your password.')
      setMode('signin')
    } catch (err: any) {
      setAuthError(err?.message || 'Failed to confirm account. Check the verification code.')
    } finally {
      setIsSubmitting(false)
    }
  }

  const fillDemoAccount = (demoEmail: string) => {
    setEmail(demoEmail)
    setPassword('VaultRag@2026!')
    setEmailError(null)
    setPasswordError(null)
    setAuthError(null)
  }

  return (
    <div className="login-page-wrapper">
      <div className="login-card">
        <div className="login-header">
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <div className="brand-icon" style={{ width: 42, height: 42 }}>
              <Shield size={24} />
            </div>
          </div>
          <h1>{mode === 'signup' ? 'Create Vault Account' : mode === 'confirm' ? 'Confirm Account' : 'VaultRAG Login'}</h1>
          <p>
            {mode === 'signup'
              ? 'Self-register an account in a tenant vault'
              : mode === 'confirm'
              ? 'Enter the confirmation code sent to your email'
              : 'Sign in to access your tenant knowledge vault'}
          </p>
        </div>

        {/* Tab switcher */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem' }}>
          <button
            type="button"
            className={`btn-logout ${mode === 'signin' ? 'active' : ''}`}
            style={{
              flex: 1,
              backgroundColor: mode === 'signin' ? 'var(--bg-surface)' : 'transparent',
              borderColor: mode === 'signin' ? 'var(--border-focus)' : 'var(--border-subtle)',
              color: mode === 'signin' ? '#fff' : 'var(--text-secondary)',
              fontWeight: 600,
            }}
            onClick={() => {
              setMode('signin')
              setAuthError(null)
              setSuccessMsg(null)
            }}
            data-testid="tab-signin"
          >
            Sign In
          </button>
          <button
            type="button"
            className={`btn-logout ${mode === 'signup' ? 'active' : ''}`}
            style={{
              flex: 1,
              backgroundColor: mode === 'signup' ? 'var(--bg-surface)' : 'transparent',
              borderColor: mode === 'signup' ? 'var(--border-focus)' : 'var(--border-subtle)',
              color: mode === 'signup' ? '#fff' : 'var(--text-secondary)',
              fontWeight: 600,
            }}
            onClick={() => {
              setMode('signup')
              setAuthError(null)
              setSuccessMsg(null)
            }}
            data-testid="tab-signup"
          >
            Sign Up
          </button>
        </div>

        {authError && (
          <div className="error-banner" role="alert" data-testid="login-error-banner">
            {authError}
          </div>
        )}

        {successMsg && (
          <div
            className="error-banner"
            style={{
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              borderColor: 'rgba(16, 185, 129, 0.4)',
              color: '#6ee7b7',
            }}
            data-testid="success-banner"
          >
            <CheckCircle2 size={16} style={{ display: 'inline', marginRight: 6 }} />
            {successMsg}
          </div>
        )}

        {/* Quick Demo Accounts Helper (Sign In only) */}
        {mode === 'signin' && (
          <div
            style={{
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.65rem 0.85rem',
              marginBottom: '1.25rem',
              fontSize: '0.8rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-secondary)', marginBottom: '0.4rem', fontWeight: 600 }}>
              <KeyRound size={13} color="var(--accent-primary-hover)" />
              <span>Quick Demo Accounts (shared password: VaultRag@2026!):</span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
              <button
                type="button"
                className="role-badge"
                style={{ cursor: 'pointer', background: 'var(--bg-elevated)' }}
                onClick={() => fillDemoAccount('admin@acme.example.com')}
                data-testid="fill-acme-admin"
              >
                Acme Admin
              </button>
              <button
                type="button"
                className="role-badge"
                style={{ cursor: 'pointer', background: 'var(--bg-elevated)' }}
                onClick={() => fillDemoAccount('employee@acme.example.com')}
                data-testid="fill-acme-employee"
              >
                Acme Employee
              </button>
              <button
                type="button"
                className="role-badge"
                style={{ cursor: 'pointer', background: 'var(--bg-elevated)' }}
                onClick={() => fillDemoAccount('admin@globex.example.com')}
                data-testid="fill-globex-admin"
              >
                Globex Admin
              </button>
            </div>
          </div>
        )}

        {/* Form: Sign In */}
        {mode === 'signin' && (
          <form onSubmit={handleSignInSubmit} noValidate>
            <div className="form-group">
              <label htmlFor="login-email">Email Address</label>
              <input
                id="login-email"
                type="email"
                className="form-input"
                placeholder="name@example.com"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value)
                  if (emailError) setEmailError(null)
                }}
                disabled={isSubmitting}
                autoComplete="email"
                data-testid="input-email"
              />
              {emailError && (
                <p className="field-error" data-testid="error-email">
                  {emailError}
                </p>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="login-password">Password</label>
              <input
                id="login-password"
                type="password"
                className="form-input"
                placeholder="Enter password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value)
                  if (passwordError) setPasswordError(null)
                }}
                disabled={isSubmitting}
                autoComplete="current-password"
                data-testid="input-password"
              />
              {passwordError && (
                <p className="field-error" data-testid="error-password">
                  {passwordError}
                </p>
              )}
            </div>

            <button
              type="submit"
              className="btn-primary"
              disabled={isSubmitting}
              data-testid="btn-login-submit"
            >
              {isSubmitting ? (
                <>
                  <span className="spinner" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <Lock size={16} />
                  <span>Sign In</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* Form: Sign Up */}
        {mode === 'signup' && (
          <form onSubmit={handleSignUpSubmit} noValidate>
            <div className="form-group">
              <label htmlFor="signup-email">Email Address</label>
              <input
                id="signup-email"
                type="email"
                className="form-input"
                placeholder="name@company.com"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value)
                  if (emailError) setEmailError(null)
                }}
                disabled={isSubmitting}
                autoComplete="email"
                data-testid="input-signup-email"
              />
              {emailError && <p className="field-error">{emailError}</p>}
            </div>

            <div className="form-group">
              <label htmlFor="signup-tenant">Tenant ID</label>
              <input
                id="signup-tenant"
                type="text"
                className="form-input"
                placeholder="e.g. acme or globex"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                disabled={isSubmitting}
                data-testid="input-signup-tenant"
              />
            </div>

            <div className="form-group">
              <label htmlFor="signup-password">Password</label>
              <input
                id="signup-password"
                type="password"
                className="form-input"
                placeholder="Min 12 chars: uppercase, digit, symbol"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value)
                  if (passwordError) setPasswordError(null)
                }}
                disabled={isSubmitting}
                autoComplete="new-password"
                data-testid="input-signup-password"
              />
              {passwordError && <p className="field-error">{passwordError}</p>}
            </div>

            <button
              type="submit"
              className="btn-primary"
              disabled={isSubmitting}
              data-testid="btn-signup-submit"
            >
              {isSubmitting ? (
                <>
                  <span className="spinner" />
                  <span>Creating Account...</span>
                </>
              ) : (
                <>
                  <UserPlus size={16} />
                  <span>Sign Up</span>
                </>
              )}
            </button>
          </form>
        )}

        {/* Form: Confirm Account */}
        {mode === 'confirm' && (
          <form onSubmit={handleConfirmSubmit} noValidate>
            <div className="form-group">
              <label htmlFor="confirm-code">Confirmation Code</label>
              <input
                id="confirm-code"
                type="text"
                className="form-input"
                placeholder="6-digit code"
                value={confirmationCode}
                onChange={(e) => setConfirmationCode(e.target.value)}
                disabled={isSubmitting}
                data-testid="input-confirm-code"
              />
            </div>

            <button
              type="submit"
              className="btn-primary"
              disabled={isSubmitting}
              data-testid="btn-confirm-submit"
            >
              {isSubmitting ? (
                <>
                  <span className="spinner" />
                  <span>Confirming...</span>
                </>
              ) : (
                <>
                  <CheckCircle2 size={16} />
                  <span>Confirm & Sign In</span>
                </>
              )}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
