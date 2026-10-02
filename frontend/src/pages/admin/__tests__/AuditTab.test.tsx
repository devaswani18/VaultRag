import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AuditTab } from '../AuditTab'
import * as apiClient from '../../../api/client'

vi.mock('../../../api/client', () => ({
  getAuditLogs: vi.fn(),
  verifyAuditChain: vi.fn(),
  exportAuditCsv: vi.fn(),
  getAuditAnchor: vi.fn(),
}))

describe('AuditTab Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({
      items: [
        {
          seq: 1,
          ts: '2026-10-01T12:00:00Z',
          actor: 'user-admin',
          action: 'document_create',
          resource_id: 'doc-1',
          outcome: 'ok',
          hash: 'abc1234567890',
          prev_hash: '0000000000000',
        },
        {
          seq: 2,
          ts: '2026-10-01T12:05:00Z',
          actor: 'user-emp',
          action: 'query',
          resource_id: 'q-1',
          outcome: 'ok',
          hash: 'def1234567890',
          prev_hash: 'abc1234567890',
        },
      ],
      next_cursor: null,
    })
  })

  it('renders audit logs table with records', async () => {
    render(<AuditTab />)

    expect(await screen.findByText('#1')).toBeInTheDocument()
    expect(screen.getByText('#2')).toBeInTheDocument()
    expect(screen.getByText('document_create')).toBeInTheDocument()
    expect(screen.getByText('query')).toBeInTheDocument()
  })

  it('displays green "chain intact N records" badge when integrity check succeeds', async () => {
    vi.mocked(apiClient.verifyAuditChain).mockResolvedValue({
      valid: true,
      checked: 42,
      broken_at_seq: null,
    })

    render(<AuditTab />)
    await screen.findByText('#1')

    const verifyBtn = screen.getByTestId('btn-verify-integrity')
    fireEvent.click(verifyBtn)

    const outcomeBadge = await screen.findByTestId('audit-verify-intact')
    expect(outcomeBadge).toHaveTextContent('chain intact 42 records')
    expect(outcomeBadge).toHaveClass('outcome-intact')
  })

  it('displays red "broken at seq X" badge when integrity check fails', async () => {
    vi.mocked(apiClient.verifyAuditChain).mockResolvedValue({
      valid: false,
      checked: 15,
      broken_at_seq: 7,
    })

    render(<AuditTab />)
    await screen.findByText('#1')

    const verifyBtn = screen.getByTestId('btn-verify-integrity')
    fireEvent.click(verifyBtn)

    const brokenBadge = await screen.findByTestId('audit-verify-broken')
    expect(brokenBadge).toHaveTextContent('broken at seq 7')
    expect(brokenBadge).toHaveClass('outcome-broken')
  })

  it('triggers CSV export and signed anchor downloads', async () => {
    vi.mocked(apiClient.exportAuditCsv).mockResolvedValue('seq,ts,actor,action\n1,2026-10-01,user,create')
    vi.mocked(apiClient.getAuditAnchor).mockResolvedValue({
      tenant_id: 'acme',
      latest_seq: 25,
      hash: '9f8e7d',
      signature: 'hmac-sig-123',
      exported_at: '2026-10-01T12:00:00Z',
    })

    // Mock window.URL.createObjectURL and revokeObjectURL
    window.URL.createObjectURL = vi.fn().mockReturnValue('blob:mock-url')
    window.URL.revokeObjectURL = vi.fn()

    render(<AuditTab />)
    await screen.findByText('#1')

    // Click Export CSV
    fireEvent.click(screen.getByTestId('btn-export-csv'))
    await waitFor(() => {
      expect(apiClient.exportAuditCsv).toHaveBeenCalled()
    })

    // Click Download Signed Anchor
    fireEvent.click(screen.getByTestId('btn-download-anchor'))
    await waitFor(() => {
      expect(apiClient.getAuditAnchor).toHaveBeenCalled()
    })
  })
})
