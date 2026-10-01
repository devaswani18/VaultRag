import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthContext } from '../../auth'
import { LoginPage } from '../LoginPage'
import { AuthContextType } from '../../auth/types'

describe('LoginPage Form Validation', () => {
  let mockLogin: any

  beforeEach(() => {
    mockLogin = vi.fn()
  })

  const renderLoginPage = (contextOverrides: Partial<AuthContextType> = {}) => {
    const mockContext: AuthContextType = {
      user: null,
      idToken: null,
      isLoading: false,
      login: mockLogin,
      logout: vi.fn(),
      getIdToken: () => null,
      ...contextOverrides,
    }

    return render(
      <AuthContext.Provider value={mockContext}>
        <MemoryRouter>
          <LoginPage />
        </MemoryRouter>
      </AuthContext.Provider>
    )
  }

  it('renders login fields and submit button', () => {
    renderLoginPage()
    expect(screen.getByTestId('input-email')).toBeInTheDocument()
    expect(screen.getByTestId('input-password')).toBeInTheDocument()
    expect(screen.getByTestId('btn-login-submit')).toBeInTheDocument()
  })

  it('shows validation error when email is empty', async () => {
    renderLoginPage()
    fireEvent.click(screen.getByTestId('btn-login-submit'))

    expect(await screen.findByTestId('error-email')).toHaveTextContent('Email is required')
    expect(mockLogin).not.toHaveBeenCalled()
  })

  it('shows validation error when email format is invalid', async () => {
    renderLoginPage()
    fireEvent.change(screen.getByTestId('input-email'), { target: { value: 'not-an-email' } })
    fireEvent.change(screen.getByTestId('input-password'), { target: { value: 'validPassword123' } })
    fireEvent.click(screen.getByTestId('btn-login-submit'))

    expect(await screen.findByTestId('error-email')).toHaveTextContent('Please enter a valid email address')
    expect(mockLogin).not.toHaveBeenCalled()
  })

  it('shows validation error when password is empty or too short', async () => {
    renderLoginPage()
    fireEvent.change(screen.getByTestId('input-email'), { target: { value: 'admin@acme.com' } })
    fireEvent.change(screen.getByTestId('input-password'), { target: { value: '123' } })
    fireEvent.click(screen.getByTestId('btn-login-submit'))

    expect(await screen.findByTestId('error-password')).toHaveTextContent('Password must be at least 6 characters')
    expect(mockLogin).not.toHaveBeenCalled()
  })

  it('submits successfully when form is valid', async () => {
    mockLogin.mockResolvedValueOnce(undefined)
    renderLoginPage()

    fireEvent.change(screen.getByTestId('input-email'), { target: { value: 'admin@acme.com' } })
    fireEvent.change(screen.getByTestId('input-password'), { target: { value: 'SecurePass123' } })
    fireEvent.click(screen.getByTestId('btn-login-submit'))

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('admin@acme.com', 'SecurePass123')
    })
  })

  it('displays error banner when authentication fails', async () => {
    mockLogin.mockRejectedValueOnce(new Error('Incorrect username or password.'))
    renderLoginPage()

    fireEvent.change(screen.getByTestId('input-email'), { target: { value: 'admin@acme.com' } })
    fireEvent.change(screen.getByTestId('input-password'), { target: { value: 'WrongPassword' } })
    fireEvent.click(screen.getByTestId('btn-login-submit'))

    const errorBanner = await screen.findByTestId('login-error-banner')
    expect(errorBanner).toHaveTextContent('Incorrect username or password.')
  })
})
