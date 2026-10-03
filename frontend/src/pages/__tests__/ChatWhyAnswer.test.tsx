import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ChatPage } from '../ChatPage'
import * as apiClient from '../../api/client'

vi.mock('../../api/client', () => ({
  query: vi.fn(),
}))

describe('ChatPage "Why this answer?" Panel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders "Why this answer?" panel with trust breakdown, sources, and policy notes', async () => {
    vi.mocked(apiClient.query).mockResolvedValue({
      answer: 'The annual leave allowance is 25 days with rollover support.',
      trust: {
        score: 0.92,
        grounded: true,
        abstained: false,
        partial: false,
        reasons: [],
      },
      sources: [
        {
          doc_id: 'doc-hr-1',
          filename: 'hr_leave_policy.md',
          chunk_id: 'chk-1',
          page: 3,
          score: 0.885,
          snippet: 'Employees accrue 25 days of paid annual vacation each calendar year.',
        },
      ],
      pii_in_answer: true,
      injection_attempt: false,
    })

    render(
      <MemoryRouter>
        <ChatPage />
      </MemoryRouter>
    )

    const textarea = screen.getByTestId('input-chat-question')
    fireEvent.change(textarea, { target: { value: 'What is the leave policy?' } })

    const sendBtn = screen.getByTestId('btn-chat-send')
    fireEvent.click(sendBtn)

    // Wait for response to appear
    expect(await screen.findByText(/The annual leave allowance is 25 days/i)).toBeInTheDocument()

    // "Why this answer?" panel should be rendered
    const whyPanel = screen.getByTestId('why-this-answer-panel')
    expect(whyPanel).toBeInTheDocument()
    expect(screen.getByTestId('why-this-answer-trigger')).toHaveTextContent('Why this answer?')
    expect(screen.getByText('Trust: 92%')).toBeInTheDocument()

    // Policy notes include PII note because pii_in_answer is true
    expect(screen.getByTestId('why-note-pii')).toHaveTextContent(
      'Sensitive data (PII) findings detected and redacted in accordance with tenant privacy policy'
    )

    // Source item is listed with filename and score inside whyPanel
    expect(within(whyPanel).getByTestId('why-source-item')).toBeInTheDocument()
    expect(within(whyPanel).getByText(/hr_leave_policy.md \(Page 3\)/i)).toBeInTheDocument()
    expect(within(whyPanel).getByText('Score: 0.885')).toBeInTheDocument()
    expect(
      within(whyPanel).getByText(/"Employees accrue 25 days of paid annual vacation each calendar year."/i)
    ).toBeInTheDocument()
  })
})
