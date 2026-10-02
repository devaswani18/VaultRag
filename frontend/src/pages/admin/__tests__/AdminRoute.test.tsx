import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AdminRoute } from '../../../auth/AdminRoute'
import * as useAuthHook from '../../../auth/useAuth'

vi.mock('../../../auth/useAuth', () => ({
  useAuth: vi.fn(),
}))

describe('AdminRoute Component Guard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders children when user holds admin role', () => {
    vi.mocked(useAuthHook.useAuth).mockReturnValue({
      user: {
        email: 'admin@acme.com',
        tenant_id: 'acme',
        roles: ['admin', 'employee'],
        role: 'admin',
        sub: 'usr-1',
      },
      idToken: 'mock-token',
      isLoading: false,
      login: vi.fn(),
      signUp: vi.fn(),
      confirmSignUp: vi.fn(),
      logout: vi.fn(),
      getIdToken: () => 'mock-token',
    })

    render(
      <MemoryRouter initialEntries={['/admin']}>
        <AdminRoute>
          <div data-testid="admin-secret-content">Secret Admin Dashboard</div>
        </AdminRoute>
      </MemoryRouter>
    )

    expect(screen.getByTestId('admin-secret-content')).toHaveTextContent('Secret Admin Dashboard')
    expect(screen.queryByTestId('forbidden-403')).not.toBeInTheDocument()
  })

  it('renders 403 Forbidden page when user does not hold admin role', () => {
    vi.mocked(useAuthHook.useAuth).mockReturnValue({
      user: {
        email: 'employee@acme.com',
        tenant_id: 'acme',
        roles: ['employee'],
        role: 'employee',
        sub: 'usr-2',
      },
      idToken: 'mock-token',
      isLoading: false,
      login: vi.fn(),
      signUp: vi.fn(),
      confirmSignUp: vi.fn(),
      logout: vi.fn(),
      getIdToken: () => 'mock-token',
    })

    render(
      <MemoryRouter initialEntries={['/admin']}>
        <AdminRoute>
          <div data-testid="admin-secret-content">Secret Admin Dashboard</div>
        </AdminRoute>
      </MemoryRouter>
    )

    expect(screen.getByTestId('forbidden-403')).toBeInTheDocument()
    expect(screen.getByText('403 — Forbidden')).toBeInTheDocument()
    expect(screen.getByTestId('btn-forbidden-back')).toBeInTheDocument()
    expect(screen.queryByTestId('admin-secret-content')).not.toBeInTheDocument()
  })

  it('renders loading state when session is authenticating', () => {
    vi.mocked(useAuthHook.useAuth).mockReturnValue({
      user: null,
      idToken: null,
      isLoading: true,
      login: vi.fn(),
      signUp: vi.fn(),
      confirmSignUp: vi.fn(),
      logout: vi.fn(),
      getIdToken: () => null,
    })

    render(
      <MemoryRouter initialEntries={['/admin']}>
        <AdminRoute>
          <div>Secret Admin Dashboard</div>
        </AdminRoute>
      </MemoryRouter>
    )

    expect(screen.getByTestId('admin-auth-loading')).toBeInTheDocument()
  })
})
