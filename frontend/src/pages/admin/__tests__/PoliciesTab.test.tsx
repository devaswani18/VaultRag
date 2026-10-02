import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { PoliciesTab } from '../PoliciesTab'
import * as apiClient from '../../../api/client'

vi.mock('../../../api/client', () => ({
  getPolicies: vi.fn(),
  updatePolicies: vi.fn(),
}))

describe('PoliciesTab Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.getPolicies).mockResolvedValue({
      pii_mode: 'redact',
      injection_policy: 'quarantine_high',
      min_retrieval_score: 0.35,
      min_faithfulness: 0.6,
      daily_query_quota: 200,
      cache_enabled: true,
      retain_original_files: true,
      llm_judge_enabled: false,
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders form with policy fields and help text', async () => {
    render(<PoliciesTab />)

    expect(await screen.findByTestId('input-pii-mode')).toBeInTheDocument()
    expect(screen.getByTestId('input-injection-policy')).toBeInTheDocument()
    expect(screen.getByTestId('input-min-retrieval-score')).toHaveValue(0.35)
    expect(screen.getByTestId('input-min-faithfulness')).toHaveValue(0.6)
    expect(screen.getByTestId('input-daily-quota')).toHaveValue(200)
    expect(screen.getByTestId('toggle-cache-enabled')).toBeChecked()
    expect(screen.getByTestId('toggle-retain-files')).toBeChecked()
    expect(screen.getByTestId('toggle-llm-judge')).not.toBeChecked()

    // One line of help text under fields
    expect(
      screen.getByText(/Determines how Personally Identifiable Information is processed/i)
    ).toBeInTheDocument()
  })

  it('validates out-of-range inputs before showing confirmation modal', async () => {
    render(<PoliciesTab />)
    await screen.findByTestId('input-min-retrieval-score')

    const scoreInput = screen.getByTestId('input-min-retrieval-score')
    fireEvent.change(scoreInput, { target: { value: '1.5' } })

    const quotaInput = screen.getByTestId('input-daily-quota')
    fireEvent.change(quotaInput, { target: { value: '-5' } })

    const saveBtn = screen.getByTestId('btn-save-policies')
    fireEvent.click(saveBtn)

    expect(await screen.findByTestId('error-min-retrieval-score')).toHaveTextContent(
      'Must be a number between 0.00 and 1.00'
    )
    expect(screen.getByTestId('error-daily-quota')).toHaveTextContent(
      'Must be an integer between 1 and 10,000'
    )

    // Confirmation modal should NOT open on validation errors
    expect(screen.queryByTestId('policies-confirm-modal')).not.toBeInTheDocument()
    expect(apiClient.updatePolicies).not.toHaveBeenCalled()
  })

  it('shows confirmation modal before saving and applies updates', async () => {
    vi.mocked(apiClient.updatePolicies).mockResolvedValue({
      pii_mode: 'block',
      injection_policy: 'quarantine_high',
      min_retrieval_score: 0.45,
      min_faithfulness: 0.7,
      daily_query_quota: 500,
      cache_enabled: true,
      retain_original_files: true,
      llm_judge_enabled: true,
    })

    render(<PoliciesTab />)
    await screen.findByTestId('input-pii-mode')

    // Change pii_mode and llm_judge_enabled
    fireEvent.change(screen.getByTestId('input-pii-mode'), { target: { value: 'block' } })
    fireEvent.click(screen.getByTestId('toggle-llm-judge'))

    // Click Review & Save
    fireEvent.click(screen.getByTestId('btn-save-policies'))

    // Confirmation modal is visible
    expect(await screen.findByTestId('policies-confirm-modal')).toBeInTheDocument()
    expect(screen.getByText('Confirm Policy Changes')).toBeInTheDocument()

    // Click Confirm & Apply
    fireEvent.click(screen.getByTestId('btn-confirm-save-policies'))

    await waitFor(() => {
      expect(apiClient.updatePolicies).toHaveBeenCalledWith(
        expect.objectContaining({
          pii_mode: 'block',
          llm_judge_enabled: true,
        })
      )
    })

    expect(await screen.findByTestId('policies-success-banner')).toBeInTheDocument()
  })

  it('displays server validation error if API rejects patch', async () => {
    vi.mocked(apiClient.updatePolicies).mockRejectedValue(
      new Error('daily_query_quota must be an integer between 1 and 10000')
    )

    render(<PoliciesTab />)
    await screen.findByTestId('input-daily-quota')

    fireEvent.click(screen.getByTestId('btn-save-policies'))
    expect(await screen.findByTestId('policies-confirm-modal')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('btn-confirm-save-policies'))

    expect(await screen.findByTestId('policies-server-error')).toHaveTextContent(
      'daily_query_quota must be an integer between 1 and 10000'
    )
  })
})
