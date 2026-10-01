import React, { useRef, useState } from 'react'
import { QuerySource, QueryTrust, query } from '../api/client'
import {
  Send,
  FileText,
  Bot,
  User as UserIcon,
  AlertCircle,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
} from 'lucide-react'

interface ChatMessage {
  id: string
  sender: 'user' | 'assistant'
  text: string
  sources?: QuerySource[]
  trust?: QueryTrust
}

export const ChatPage: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'msg-welcome',
      sender: 'assistant',
      text: 'Hello! Ask any question about your tenant documents, and I will answer with citations grounded in your vault.',
    },
  ])
  const [question, setQuestion] = useState('')
  const [topK, setTopK] = useState(5)
  const [isLoading, setIsLoading] = useState(false)
  const [queryError, setQueryError] = useState<string | null>(null)

  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = question.trim()
    if (!trimmed || isLoading) return

    setQueryError(null)

    // Add user message
    const userMsgId = `usr-${Date.now()}`
    const newMessages: ChatMessage[] = [
      ...messages,
      { id: userMsgId, sender: 'user', text: trimmed },
    ]
    setMessages(newMessages)
    setQuestion('')
    setIsLoading(true)

    try {
      const resp = await query(trimmed, topK)
      const assistantMsgId = `asst-${Date.now()}`
      setMessages([
        ...newMessages,
        {
          id: assistantMsgId,
          sender: 'assistant',
          text: resp.answer,
          sources: resp.sources,
          trust: resp.trust,
        },
      ])
    } catch (err: any) {
      setQueryError(err?.message || 'Failed to retrieve answer from knowledge vault')
    } finally {
      setIsLoading(false)
      setTimeout(() => textareaRef.current?.focus(), 50)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const renderTrustBadge = (trust?: QueryTrust) => {
    if (!trust) return null

    let colorClass = 'trust-badge-green'
    let label = `High Trust (${(trust.score * 100).toFixed(0)}%)`
    let Icon = ShieldCheck

    if (trust.abstained || trust.score < 0.6) {
      colorClass = 'trust-badge-red'
      label = trust.abstained ? 'Abstained' : `Low Trust (${(trust.score * 100).toFixed(0)}%)`
      Icon = ShieldAlert
    } else if (trust.score < 0.8) {
      colorClass = 'trust-badge-amber'
      label = `Moderate Trust (${(trust.score * 100).toFixed(0)}%)`
      Icon = AlertTriangle
    }

    return (
      <span
        className={`trust-badge ${colorClass}`}
        data-testid="trust-badge"
        data-color={
          trust.abstained || trust.score < 0.6 ? 'red' : trust.score < 0.8 ? 'amber' : 'green'
        }
      >
        <Icon size={12} />
        <span>{label}</span>
      </span>
    )
  }

  return (
    <div className="chat-layout">
      <div className="page-title-row" style={{ marginBottom: '1rem' }}>
        <div>
          <h1>Knowledge Vault Query</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>
            Multi-tenant RAG with grounded answer generation, faithfulness scoring and Trust Layer
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <label
            htmlFor="select-top-k"
            style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}
          >
            Max Chunks (Top-K):
          </label>
          <select
            id="select-top-k"
            className="form-input"
            style={{ width: 'auto', padding: '0.35rem 0.6rem' }}
            value={topK}
            onChange={(e) => setTopK(Number(e.target.value))}
            disabled={isLoading}
            data-testid="select-topk"
          >
            {[1, 3, 5, 8, 10].map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
        </div>
      </div>

      {queryError && (
        <div className="error-banner" data-testid="chat-error-banner" role="alert">
          <AlertCircle size={16} style={{ display: 'inline', marginRight: 6 }} />
          {queryError}
        </div>
      )}

      {/* Messages Scroll Area */}
      <div className="chat-history" data-testid="chat-history">
        {messages.map((msg) => {
          const isAbstained = Boolean(msg.trust?.abstained)
          const isPartial = Boolean(msg.trust?.partial)

          return (
            <div
              key={msg.id}
              className={`chat-message ${msg.sender}`}
              data-testid={`chat-message-${msg.sender}`}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '0.5rem',
                  marginBottom: '0.25rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  {msg.sender === 'assistant' ? (
                    <>
                      <Bot size={14} color="var(--accent-primary-hover)" />
                      <span
                        style={{
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          color: 'var(--accent-primary-hover)',
                        }}
                      >
                        VaultRAG Assistant
                      </span>
                    </>
                  ) : (
                    <>
                      <UserIcon size={14} color="var(--text-secondary)" />
                      <span
                        style={{
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          color: 'var(--text-secondary)',
                        }}
                      >
                        You
                      </span>
                    </>
                  )}
                </div>

                {/* Trust Badge for assistant messages */}
                {msg.sender === 'assistant' && renderTrustBadge(msg.trust)}
              </div>

              {/* Plain text rendering ONLY */}
              <div
                className={`message-bubble ${isAbstained ? 'message-abstained' : ''}`}
                data-testid={isAbstained ? 'message-abstained' : 'message-bubble'}
                style={{ whiteSpace: 'pre-wrap' }}
              >
                {msg.text}
              </div>

              {/* Visible Note when Partial */}
              {isPartial && (
                <div className="partial-note-banner" data-testid="partial-note-banner">
                  <AlertTriangle size={14} style={{ display: 'inline', marginRight: 4 }} />
                  <span>
                    Note: Some unverified statements were removed from this response.
                  </span>
                </div>
              )}

              {/* Source chips row */}
              {msg.sources && msg.sources.length > 0 && (
                <div className="source-chips" data-testid="source-chips">
                  {msg.sources.map((src, i) => (
                    <span
                      key={`chip-${src.chunk_id}-${i}`}
                      className="source-chip"
                      data-testid="source-chip"
                    >
                      <FileText size={11} style={{ display: 'inline', marginRight: 4 }} />
                      {src.filename}
                      {src.page !== null && ` (p. ${src.page})`}
                    </span>
                  ))}
                </div>
              )}

              {/* Citations / Sources list details */}
              {msg.sources && msg.sources.length > 0 && (
                <div className="sources-container" data-testid="sources-container">
                  <div className="sources-title">Supporting Citations ({msg.sources.length}):</div>
                  <ul className="sources-list" data-testid="sources-list">
                    {msg.sources.map((src, idx) => (
                      <li
                        key={`${src.chunk_id}-${idx}`}
                        className="source-item"
                        data-testid="source-item"
                      >
                        <div className="source-item-header">
                          <span className="source-filename" data-testid="source-filename">
                            <FileText size={12} style={{ display: 'inline', marginRight: 4 }} />
                            {src.filename}
                            {src.page !== null && ` (p. ${src.page})`}
                          </span>
                          <span className="source-score" data-testid="source-score">
                            Score: {src.score.toFixed(3)}
                          </span>
                        </div>
                        {src.snippet && (
                          <div className="source-snippet" data-testid="source-snippet">
                            &ldquo;{src.snippet}&rdquo;
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )
        })}

        {isLoading && (
          <div className="chat-message assistant" data-testid="chat-loading-indicator">
            <div
              className="message-bubble"
              style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            >
              <span className="spinner spinner-dark" />
              <span style={{ color: 'var(--text-secondary)' }}>
                Searching vault and generating grounded answer...
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Input bar */}
      <form onSubmit={handleSubmit} className="chat-input-bar">
        <textarea
          ref={textareaRef}
          className="chat-input-textarea"
          placeholder="Ask a question about your documents... (Press Enter to send)"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          rows={1}
          maxLength={1000}
          data-testid="input-chat-question"
        />
        <button
          type="submit"
          className="btn-send"
          disabled={isLoading || !question.trim()}
          data-testid="btn-chat-send"
        >
          {isLoading ? (
            <span className="spinner" />
          ) : (
            <>
              <Send size={16} />
              <span>Send</span>
            </>
          )}
        </button>
      </form>
    </div>
  )
}
