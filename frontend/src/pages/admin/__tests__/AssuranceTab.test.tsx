import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AssuranceTab } from '../AssuranceTab'
import * as apiClient from '../../../api/client'

vi.mock('../../../api/client', () => ({
  runAssurance: vi.fn(),
  getLatestAssurance: vi.fn(),
  verifyAssuranceReport: vi.fn(),
}))

const mockReport: apiClient.AssuranceReport = {
  run_id: 'selftest-test123456',
  tenant_id: 'tenant-test',
  ts: 1727900000,
  version: 1,
  simulated: false,
  simulated_bug: null,
  summary: {
    passed: 19,
    total: 19,
    leaks: 0,
    missing: 0,
  },
  matrix: [
    {
      canary: 'C1',
      principal: 'A-admin',
      expected_allowed: true,
      actually_allowed: true,
      state: 'allowed',
    },
    {
      canary: 'C1',
      principal: 'B-admin',
      expected_allowed: false,
      actually_allowed: false,
      state: 'blocked',
    },
    {
      canary: 'C2',
      principal: 'A-admin',
      expected_allowed: true,
      actually_allowed: true,
      state: 'allowed',
    },
    {
      canary: 'C2',
      principal: 'A-employee',
      expected_allowed: false,
      actually_allowed: false,
      state: 'blocked',
    },
    {
      canary: 'C6',
      principal: 'A-admin',
      expected_allowed: false,
      actually_allowed: false,
      state: 'blocked',
    },
    {
      canary: 'C6',
      principal: 'B-admin',
      expected_allowed: true,
      actually_allowed: true,
      state: 'allowed',
    },
  ],
  checks: [
    {
      id: 'I1',
      group: 'Isolation',
      name: 'Tenant Isolation',
      severity: 'high',
      passed: true,
      expected: 'No cross-tenant leaks',
      actual: '0 leaks',
      detail: 'Tenant isolation verified.',
    },
    {
      id: 'A1',
      group: 'Access Control',
      name: 'Role Boundaries',
      severity: 'high',
      passed: true,
      expected: 'Manager role enforced',
      actual: 'Enforced',
      detail: 'Access control verified.',
    },
  ],
  signature: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  report_sha256: 'fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321',
}

describe('AssuranceTab Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.getLatestAssurance).mockResolvedValue(mockReport)
  })

  it('renders header card and 19/19 checks passed badge', async () => {
    render(<AssuranceTab />)

    expect(await screen.findByText('Assurance Center')).toBeInTheDocument()
    expect(screen.getByTestId('assurance-status-badge')).toHaveTextContent('19/19 CHECKS PASSED')
    expect(screen.getByText('selftest-test123456')).toBeInTheDocument()
  })

  it('renders Access Control Matrix with canary rows and principal columns', async () => {
    render(<AssuranceTab />)

    expect(await screen.findByTestId('access-matrix-card')).toBeInTheDocument()
    expect(screen.getByText('Tenant-wide Public')).toBeInTheDocument()
    expect(screen.getByText('Foreign-Tenant Document')).toBeInTheDocument()
    expect(screen.getByTestId('cell-C1-A-admin')).toHaveTextContent('Allowed')
    expect(screen.getByTestId('cell-C1-B-admin')).toHaveTextContent('Blocked')
  })

  it('renders grouped security checks list', async () => {
    render(<AssuranceTab />)

    expect(await screen.findByTestId('security-checks-card')).toBeInTheDocument()
    expect(screen.getByTestId('check-item-I1')).toBeInTheDocument()
    expect(screen.getByText('Tenant Isolation')).toBeInTheDocument()
    expect(screen.getByText('Role Boundaries')).toBeInTheDocument()
  })

  it('triggers Run Security Self-Test button with selected fault injection', async () => {
    const simReport: apiClient.AssuranceReport = {
      ...mockReport,
      simulated: true,
      simulated_bug: 'drop_role_condition',
      summary: {
        passed: 18,
        total: 19,
        leaks: 3,
        missing: 0,
      },
      matrix: [
        ...mockReport.matrix,
        {
          canary: 'C2',
          principal: 'A-employee',
          expected_allowed: false,
          actually_allowed: true,
          state: 'leak',
        },
      ],
    }

    vi.mocked(apiClient.runAssurance).mockResolvedValue(simReport)

    render(<AssuranceTab />)
    await screen.findByText('Assurance Center')

    // Select fault injection mode
    const select = screen.getByTestId('select-simulate-bug')
    fireEvent.change(select, { target: { value: 'drop_role_condition' } })

    // Click run
    const runBtn = screen.getByTestId('btn-run-assurance')
    fireEvent.click(runBtn)

    await waitFor(() => {
      expect(apiClient.runAssurance).toHaveBeenCalledWith('drop_role_condition')
    })

    // Verify simulation banner is shown
    expect(await screen.findByTestId('simulation-banner')).toBeInTheDocument()
    expect(screen.getByText(/SIMULATION MODE ACTIVE/)).toBeInTheDocument()
  })

  it('opens report verifier modal and handles valid and invalid signatures', async () => {
    render(<AssuranceTab />)
    await screen.findByText('Assurance Center')

    // Open modal
    const openBtn = screen.getByTestId('btn-open-verify-modal')
    fireEvent.click(openBtn)

    expect(screen.getByTestId('verify-report-modal')).toBeInTheDocument()

    // Test verification success
    vi.mocked(apiClient.verifyAssuranceReport).mockResolvedValue({
      valid: true,
      reason: null,
    })

    const textarea = screen.getByTestId('textarea-verify-json')
    fireEvent.change(textarea, { target: { value: JSON.stringify(mockReport) } })

    const submitBtn = screen.getByTestId('btn-submit-verify-report')
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(apiClient.verifyAssuranceReport).toHaveBeenCalled()
    })

    expect(
      await screen.findByText(/CRYPTOGRAPHIC SIGNATURE VALID/)
    ).toBeInTheDocument()

    // Test verification failure
    vi.mocked(apiClient.verifyAssuranceReport).mockResolvedValue({
      valid: false,
      reason: 'Cryptographic signature mismatch',
    })

    fireEvent.click(submitBtn)
    expect(await screen.findByText('VERIFICATION FAILED')).toBeInTheDocument()
    expect(screen.getByText('Cryptographic signature mismatch')).toBeInTheDocument()
  })
})
