import React from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './useAuth'

export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, idToken, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="auth-loading-screen" data-testid="auth-loading">
        <div className="spinner" />
        <p>Authenticating session...</p>
      </div>
    )
  }

  if (!user || !idToken) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return <>{children}</>
}
