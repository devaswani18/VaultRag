import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ChatPage } from '../ChatPage'
import * as apiClient from '../../api/client'

vi.mock('../../api/client', () => ({
  query: vi.fn(),
  listDocuments: vi.fn(),
}))

const renderChatPage = (initialEntries: any[] = ['/chat']) => {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <ChatPage />
    </MemoryRouter>
  )
}

describe('ChatPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(apiClient.listDocuments).mockResolvedValue([
      {
        id: 'doc-ready-1',
        filename: 'leave_policy.txt',
        status: 'READY',
        size_bytes: 1024,
        chunk_count: 3,
        created_at: '2026-10-01T00:00:00Z',
      },
      {
        id: 'doc-ready-2',
        filename: 'handbook.pdf',
        status: 'READY',
        size_bytes: 2048,
        chunk_count: 5,
        created_at: '2026-10-01T00:00:00Z',
      },
      {
        id: 'doc-proc-3',
        filename: 'notes.txt',
        status: 'PROCESSING',
        size_bytes: 512,
        chunk_count: 0,
        created_at: '2026-10-01T00:00:00Z',
      },
    ])
  })

  it('renders chat interface with welcome message, search in selector, and input bar', () => {
    renderChatPage()

    expect(screen.getByText(/Ask any question about your tenant documents/i)).toBeInTheDocument()
    expect(screen.getByTestId('select-search-in')).toBeInTheDocument()
    expect(screen.getByTestId('input-chat-question')).toBeInTheDocument()
    expect(screen.getByTestId('btn-chat-send')).toBeInTheDocument()
  })

  it('submits question and renders answer along with sources list and scope note', async () => {
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
      scope: {
        scoped: false,
        n_docs: 0,
      },
    })

    renderChatPage()

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

    // Scope note displayed in plain text in answer area
    const scopeNote = screen.getByTestId('message-scope-text')
    expect(scopeNote).toBeInTheDocument()
    expect(scopeNote).toHaveTextContent('Answered from: leave_policy.txt')

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

    renderChatPage()

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

    renderChatPage()

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

    renderChatPage()

    const textarea = screen.getByTestId('input-chat-question')
    fireEvent.change(textarea, { target: { value: 'Trigger error question' } })
    fireEvent.click(screen.getByTestId('btn-chat-send'))

    const banner = await screen.findByTestId('chat-error-banner')
    expect(banner).toHaveTextContent('Upstream LLM rate limit exceeded')
  })

  it('supports selecting documents via Search in dropdown and multi-select modal', async () => {
    renderChatPage()

    // Select "Selected documents"
    const select = screen.getByTestId('select-search-in')
    fireEvent.change(select, { target: { value: 'selected' } })

    // Modal opens and fetches documents
    expect(await screen.findByTestId('doc-scope-modal')).toBeInTheDocument()
    expect(apiClient.listDocuments).toHaveBeenCalled()

    // READY documents are listed, PROCESSING is omitted
    expect(screen.getByText('leave_policy.txt')).toBeInTheDocument()
    expect(screen.getByText('handbook.pdf')).toBeInTheDocument()
    expect(screen.queryByText('notes.txt')).not.toBeInTheDocument()

    // Select leave_policy.txt
    const checkbox1 = screen.getByTestId('checkbox-doc-doc-ready-1')
    fireEvent.click(checkbox1)

    // Filter documents by filename
    const searchInput = screen.getByTestId('input-doc-search')
    fireEvent.change(searchInput, { target: { value: 'handbook' } })
    expect(screen.queryByText('leave_policy.txt')).not.toBeInTheDocument()
    expect(screen.getByText('handbook.pdf')).toBeInTheDocument()

    // Select handbook.pdf
    const checkbox2 = screen.getByTestId('checkbox-doc-doc-ready-2')
    fireEvent.click(checkbox2)

    // Close modal
    fireEvent.click(screen.getByTestId('btn-modal-done'))
    expect(screen.queryByTestId('doc-scope-modal')).not.toBeInTheDocument()

    // Scope chip shows count
    const chip = screen.getByTestId('scope-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('Searching 2 documents')
  })

  it('clears document scope when clear button on chip is clicked', async () => {
    renderChatPage()

    // Open modal and select a document
    fireEvent.change(screen.getByTestId('select-search-in'), { target: { value: 'selected' } })
    expect(await screen.findByTestId('doc-scope-modal')).toBeInTheDocument()

    fireEvent.click(screen.getByTestId('checkbox-doc-doc-ready-1'))
    fireEvent.click(screen.getByTestId('btn-modal-done'))

    // Verify chip appears
    expect(screen.getByTestId('scope-chip')).toHaveTextContent('Searching 1 document')

    // Click clear button on chip
    fireEvent.click(screen.getByTestId('btn-clear-scope'))

    // Chip disappears, select reverts to "all"
    expect(screen.queryByTestId('scope-chip')).not.toBeInTheDocument()
    const select = screen.getByTestId('select-search-in') as HTMLSelectElement
    expect(select.value).toBe('all')
  })

  it('preselects document from navigation state and sends doc_ids on query', async () => {
    vi.mocked(apiClient.query).mockResolvedValueOnce({
      answer: 'Scoped answer from document.',
      sources: [
        {
          doc_id: 'doc-pre',
          filename: 'special_report.pdf',
          chunk_id: 'chk-1',
          page: 1,
          score: 0.95,
          snippet: 'Specific report content.',
        },
      ],
      request_id: 'req-chat-004',
      trust: {
        score: 0.95,
        grounded: true,
        abstained: false,
        partial: false,
        reasons: [],
      },
      scope: {
        scoped: true,
        n_docs: 1,
      },
    })

    // Render with preselected document in location state
    renderChatPage([
      {
        pathname: '/chat',
        state: {
          preselectedDoc: { id: 'doc-pre', filename: 'special_report.pdf' },
        },
      },
    ])

    // Scope chip should immediately appear
    await waitFor(() => {
      expect(screen.getByTestId('scope-chip')).toBeInTheDocument()
    })
    expect(screen.getByTestId('scope-chip')).toHaveTextContent('Searching 1 document')

    // Submit question
    const textarea = screen.getByTestId('input-chat-question')
    fireEvent.change(textarea, { target: { value: 'What is in the special report?' } })
    fireEvent.click(screen.getByTestId('btn-chat-send'))

    // Ensure apiClient.query was called with question, topK (5), and docIds: ['doc-pre']
    await waitFor(() => {
      expect(apiClient.query).toHaveBeenCalledWith('What is in the special report?', 5, ['doc-pre'])
    })

    // Scope note displayed in answer
    expect(await screen.findByTestId('message-scope-text')).toHaveTextContent('Answered from: special_report.pdf')
  })
})
