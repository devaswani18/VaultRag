import React from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './useAuth'
import { Forbidden403 } from '../pages/Forbidden403'

export const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, idToken, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="auth-loading-screen" data-testid="admin-auth-loading">
        <div className="spinner" />
        <p>Verifying administrative privileges...</p>
      </div>
    )
  }

  if (!user || !idToken) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  const isAdmin = Array.isArray(user.roles) && user.roles.includes('admin')
  if (!isAdmin) {
    return <Forbidden403 />
  }

  return <>{children}</>
}
