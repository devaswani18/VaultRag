import React, { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { Shield, Lock } from 'lucide-react'

export const LoginPage: React.FC = () => {
  const { user, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [emailError, setEmailError] = useState<string | null>(null)
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)
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

    if (!password) {
      setPasswordError('Password is required')
      valid = false
    } else if (password.length < 6) {
      setPasswordError('Password must be at least 6 characters')
      valid = false
    }

    return valid
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!validate()) return

    setIsSubmitting(true)
    setAuthError(null)

    try {
      await login(email.trim(), password)
      const from = (location.state as any)?.from?.pathname || '/chat'
      navigate(from, { replace: true })
    } catch (err: any) {
      // Safe error display: Never log or reflect back passwords
      const msg = err?.message || 'Authentication failed. Please check your credentials.'
      setAuthError(msg)
    } finally {
      setIsSubmitting(false)
    }
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
          <h1>VaultRAG Login</h1>
          <p>Sign in to access your tenant knowledge vault</p>
        </div>

        {authError && (
          <div className="error-banner" role="alert" data-testid="login-error-banner">
            {authError}
          </div>
        )}

        <form onSubmit={handleSubmit} noValidate>
          <div className="form-group">
            <label htmlFor="login-email">Email Address</label>
            <div style={{ position: 'relative' }}>
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
            </div>
            {emailError && (
              <p className="field-error" data-testid="error-email">
                {emailError}
              </p>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="login-password">Password</label>
            <div style={{ position: 'relative' }}>
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
            </div>
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
      </div>
    </div>
  )
}
