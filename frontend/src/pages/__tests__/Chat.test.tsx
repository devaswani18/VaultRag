import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ChatPage } from '../ChatPage'
import * as apiClient from '../../api/client'

vi.mock('../../api/client', () => ({
  query: vi.fn(),
}))

describe('ChatPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders chat interface with welcome message and input bar', () => {
    render(<ChatPage />)

    expect(screen.getByText(/Ask any question about your tenant documents/i)).toBeInTheDocument()
    expect(screen.getByTestId('input-chat-question')).toBeInTheDocument()
    expect(screen.getByTestId('btn-chat-send')).toBeInTheDocument()
  })

  it('submits question and renders answer along with sources list', async () => {
    vi.mocked(apiClient.query).mockResolvedValueOnce({
      answer: 'Full-time employees receive 20 days paid leave.',
      sources: [
        {
          doc_id: 'doc-123',
          filename: 'leave_policy.txt',
          chunk_id: 'chunk-abc-1',
          page: 1,
          score: 0.892,
          snippet: 'Employees are entitled to 20 paid leave days per calendar year.',
        },
      ],
      request_id: 'req-chat-001',
      trust: {
        score: 0.92,
        grounded: true,
        abstained: false,
        partial: false,
        reasons: [],
      },
    })

    render(<ChatPage />)

    const textarea = screen.getByTestId('input-chat-question')
    const sendButton = screen.getByTestId('btn-chat-send')

    fireEvent.change(textarea, { target: { value: 'How many leave days?' } })
    fireEvent.click(sendButton)

    // User question displayed
    expect(screen.getByText('How many leave days?')).toBeInTheDocument()

    // Assistant answer displayed
    expect(
      await screen.findByText('Full-time employees receive 20 days paid leave.')
    ).toBeInTheDocument()

    // Green trust badge displayed for score >= 0.8
    const badge = screen.getByTestId('trust-badge')
    expect(badge).toBeInTheDocument()
    expect(badge).toHaveAttribute('data-color', 'green')
    expect(badge).toHaveTextContent(/High Trust/i)

    // Source chips displayed
    expect(screen.getByTestId('source-chips')).toBeInTheDocument()
    expect(screen.getByTestId('source-chip')).toHaveTextContent('leave_policy.txt (p. 1)')

    // Sources detail list displayed
    expect(screen.getByTestId('sources-container')).toBeInTheDocument()
    expect(screen.getByTestId('source-filename')).toHaveTextContent('leave_policy.txt (p. 1)')
    expect(screen.getByTestId('source-score')).toHaveTextContent('Score: 0.892')
    expect(screen.getByTestId('source-snippet')).toHaveTextContent(
      'Employees are entitled to 20 paid leave days per calendar year.'
    )
  })

  it('renders amber trust badge for moderate score (0.6 - 0.8) and partial note', async () => {
    vi.mocked(apiClient.query).mockResolvedValueOnce({
      answer: 'Partial answer from source.',
      sources: [
        {
          doc_id: 'doc-456',
          filename: 'guide.pdf',
          chunk_id: 'c-1',
          page: 3,
          score: 0.72,
          snippet: 'Some guide text.',
        },
      ],
      request_id: 'req-chat-002',
      trust: {
        score: 0.70,
        grounded: false,
        abstained: false,
        partial: true,
        reasons: ['partial_support'],
      },
    })

    render(<ChatPage />)

    const textarea = screen.getByTestId('input-chat-question')
    fireEvent.change(textarea, { target: { value: 'Partial question' } })
    fireEvent.click(screen.getByTestId('btn-chat-send'))

    expect(await screen.findByText('Partial answer from source.')).toBeInTheDocument()

    // Amber badge for 0.70
    const badge = screen.getByTestId('trust-badge')
    expect(badge).toHaveAttribute('data-color', 'amber')
    expect(badge).toHaveTextContent(/Moderate Trust/i)

    // Partial note banner displayed
    expect(screen.getByTestId('partial-note-banner')).toBeInTheDocument()
    expect(screen.getByTestId('partial-note-banner')).toHaveTextContent(/unverified statements were removed/i)
  })

  it('renders red trust badge and abstain style when abstained or score < 0.6', async () => {
    vi.mocked(apiClient.query).mockResolvedValueOnce({
      answer: 'I could not find this in the documents you can access.',
      sources: [],
      request_id: 'req-chat-003',
      trust: {
        score: 0.0,
        grounded: false,
        abstained: true,
        partial: false,
        reasons: ['below_min_retrieval_score'],
      },
    })

    render(<ChatPage />)

    const textarea = screen.getByTestId('input-chat-question')
    fireEvent.change(textarea, { target: { value: 'Out of domain question' } })
    fireEvent.click(screen.getByTestId('btn-chat-send'))

    expect(
      await screen.findByText('I could not find this in the documents you can access.')
    ).toBeInTheDocument()

    // Red badge for abstained
    const badge = screen.getByTestId('trust-badge')
    expect(badge).toHaveAttribute('data-color', 'red')
    expect(badge).toHaveTextContent(/Abstained/i)

    // Abstain message style applied
    expect(screen.getByTestId('message-abstained')).toBeInTheDocument()
  })

  it('handles query failure and displays error banner', async () => {
    vi.mocked(apiClient.query).mockRejectedValueOnce(
      new Error('Upstream LLM rate limit exceeded')
    )

    render(<ChatPage />)

    const textarea = screen.getByTestId('input-chat-question')
    fireEvent.change(textarea, { target: { value: 'Trigger error question' } })
    fireEvent.click(screen.getByTestId('btn-chat-send'))

    const banner = await screen.findByTestId('chat-error-banner')
    expect(banner).toHaveTextContent('Upstream LLM rate limit exceeded')
  })
})
