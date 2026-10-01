import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { AuthContext } from '../context'
import { ProtectedRoute } from '../ProtectedRoute'
import { AuthContextType } from '../types'

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    sessionStorage.clear()
    localStorage.clear()
  })

  it('redirects unauthenticated user to /login', () => {
    const mockAuthContext: AuthContextType = {
      user: null,
      idToken: null,
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getIdToken: () => null,
    }

    render(
      <AuthContext.Provider value={mockAuthContext}>
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/login" element={<div>Login Page Mock</div>} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <div>Secret Vault Content</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    )

    expect(screen.queryByText('Secret Vault Content')).not.toBeInTheDocument()
    expect(screen.getByText('Login Page Mock')).toBeInTheDocument()
  })

  it('renders protected child component for authenticated user', () => {
    const mockAuthContext: AuthContextType = {
      user: {
        email: 'admin@acme.com',
        tenant_id: 'acme',
        roles: ['admin'],
        role: 'admin',
        sub: 'usr-123',
      },
      idToken: 'valid-in-memory-token',
      isLoading: false,
      login: vi.fn(),
      logout: vi.fn(),
      getIdToken: () => 'valid-in-memory-token',
    }

    render(
      <AuthContext.Provider value={mockAuthContext}>
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/login" element={<div>Login Page Mock</div>} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <div>Secret Vault Content</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    )

    expect(screen.getByText('Secret Vault Content')).toBeInTheDocument()
    expect(screen.queryByText('Login Page Mock')).not.toBeInTheDocument()
  })

  it('verifies tokens are never stored in localStorage', () => {
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('id_token')).toBeNull()
    expect(localStorage.getItem('refresh_token')).toBeNull()
    expect(localStorage.length).toBe(0)
  })
})
