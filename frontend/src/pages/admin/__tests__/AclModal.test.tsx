import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AclModal } from '../AclModal'
import * as apiClient from '../../../api/client'

vi.mock('../../../api/client', () => ({
  patchDocumentAcl: vi.fn(),
}))

describe('AclModal Component', () => {
  const mockDoc: apiClient.DocumentRecord = {
    id: 'doc-123',
    doc_id: 'doc-123',
    filename: 'quarterly_report.pdf',
    status: 'READY',
    size_bytes: 4096,
    created_at: '2026-10-01T12:00:00Z',
    visibility: 'tenant',
    allowed_roles: [],
    allowed_users: [],
  }

  const onCloseMock = vi.fn()
  const onSavedMock = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders modal with document filename and initial visibility', () => {
    render(<AclModal doc={mockDoc} onClose={onCloseMock} onSaved={onSavedMock} />)

    expect(screen.getByText('Change Document Access')).toBeInTheDocument()
    expect(screen.getByText('quarterly_report.pdf')).toBeInTheDocument()
    expect(screen.getByTestId('acl-visibility-select')).toHaveValue('tenant')
    expect(screen.queryByTestId('roles-selector-container')).not.toBeInTheDocument()
  })

  it('displays roles checkboxes when visibility is changed to roles', () => {
    render(<AclModal doc={mockDoc} onClose={onCloseMock} onSaved={onSavedMock} />)

    fireEvent.change(screen.getByTestId('acl-visibility-select'), {
      target: { value: 'roles' },
    })

    expect(screen.getByTestId('roles-selector-container')).toBeInTheDocument()
    expect(screen.getByTestId('checkbox-role-admin')).toBeInTheDocument()
    expect(screen.getByTestId('checkbox-role-manager')).toBeInTheDocument()
  })

  it('validates that roles visibility requires at least one selected role', async () => {
    render(<AclModal doc={mockDoc} onClose={onCloseMock} onSaved={onSavedMock} />)

    fireEvent.change(screen.getByTestId('acl-visibility-select'), {
      target: { value: 'roles' },
    })

    fireEvent.click(screen.getByTestId('btn-save-acl'))

    expect(await screen.findByTestId('acl-error-message')).toHaveTextContent(
      'Please select at least one permitted role'
    )
    expect(apiClient.patchDocumentAcl).not.toHaveBeenCalled()
  })

  it('submits valid ACL patch and invokes callbacks', async () => {
    vi.mocked(apiClient.patchDocumentAcl).mockResolvedValue({
      ...mockDoc,
      visibility: 'roles',
      allowed_roles: ['manager', 'admin'],
      allowed_users: ['user-456'],
    })

    render(<AclModal doc={mockDoc} onClose={onCloseMock} onSaved={onSavedMock} />)

    fireEvent.change(screen.getByTestId('acl-visibility-select'), {
      target: { value: 'roles' },
    })
    fireEvent.click(screen.getByTestId('checkbox-role-manager'))
    fireEvent.click(screen.getByTestId('checkbox-role-admin'))

    fireEvent.change(screen.getByTestId('acl-users-input'), {
      target: { value: 'user-456, ' },
    })

    fireEvent.click(screen.getByTestId('btn-save-acl'))

    await waitFor(() => {
      expect(apiClient.patchDocumentAcl).toHaveBeenCalledWith('doc-123', {
        visibility: 'roles',
        allowed_roles: ['manager', 'admin'],
        allowed_users: ['user-456'],
      })
    })

    expect(onSavedMock).toHaveBeenCalled()
    expect(onCloseMock).toHaveBeenCalled()
  })

  it('closes dialog on Escape key press', () => {
    render(<AclModal doc={mockDoc} onClose={onCloseMock} onSaved={onSavedMock} />)

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onCloseMock).toHaveBeenCalledTimes(1)
  })
})
