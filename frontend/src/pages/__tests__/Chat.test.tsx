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

    // Sources displayed
    expect(screen.getByTestId('sources-container')).toBeInTheDocument()
    expect(screen.getByTestId('source-filename')).toHaveTextContent('leave_policy.txt (p. 1)')
    expect(screen.getByTestId('source-score')).toHaveTextContent('Score: 0.892')
    expect(screen.getByTestId('source-snippet')).toHaveTextContent(
      'Employees are entitled to 20 paid leave days per calendar year.'
    )
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
