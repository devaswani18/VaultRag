import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { DocumentRecord, QuerySource, QueryTrust, listDocuments, query } from '../api/client'
import {
  Send,
  FileText,
  Bot,
  User as UserIcon,
  AlertCircle,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  X,
  Search,
} from 'lucide-react'

interface ChatMessage {
  id: string
  sender: 'user' | 'assistant'
  text: string
  sources?: QuerySource[]
  trust?: QueryTrust
  scope?: { scoped: boolean; n_docs: number }
  scopeFilenames?: string[]
  pii_in_answer?: boolean
  injection_attempt?: boolean
}

export const ChatPage: React.FC = () => {
  const location = useLocation()
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

  // Document scope state
  const [selectedDocIds, setSelectedDocIds] = useState<string[]>([])
  const [docNameMap, setDocNameMap] = useState<Record<string, string>>({})
  const [readyDocs, setReadyDocs] = useState<DocumentRecord[]>([])
  const [isDocModalOpen, setIsDocModalOpen] = useState(false)
  const [docSearchQuery, setDocSearchQuery] = useState('')
  const [isLoadingDocs, setIsLoadingDocs] = useState(false)

  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Handle preselected document navigation from Documents page
  useEffect(() => {
    const state = location.state as { preselectedDoc?: { id: string; filename: string } } | null
    if (state?.preselectedDoc) {
      const doc = state.preselectedDoc
      setSelectedDocIds([doc.id])
      setDocNameMap((prev) => ({ ...prev, [doc.id]: doc.filename }))
    }
  }, [location.state])

  const loadReadyDocs = useCallback(async () => {
    setIsLoadingDocs(true)
    try {
      const docs = await listDocuments()
      const ready = docs.filter((d) => d.status === 'READY')
      setReadyDocs(ready)
      const map: Record<string, string> = {}
      for (const d of ready) {
        const id = d.id || (d as any).doc_id
        if (id) {
          map[id] = d.filename
        }
      }
      setDocNameMap((prev) => ({ ...map, ...prev }))
    } catch {
      // ignore
    } finally {
      setIsLoadingDocs(false)
    }
  }, [])

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

    const scopedFilenames =
      selectedDocIds.length > 0
        ? selectedDocIds.map((id) => docNameMap[id] || id)
        : undefined

    try {
      const resp = await query(
        trimmed,
        topK,
        selectedDocIds.length > 0 ? selectedDocIds : undefined
      )
      const assistantMsgId = `asst-${Date.now()}`
      setMessages([
        ...newMessages,
        {
          id: assistantMsgId,
          sender: 'assistant',
          text: resp.answer,
          sources: resp.sources,
          trust: resp.trust,
          scope: resp.scope,
          scopeFilenames: scopedFilenames,
          pii_in_answer: resp.pii_in_answer,
          injection_attempt: resp.injection_attempt,
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

              {/* Answered from scope plain text display */}
              {msg.sender === 'assistant' && (msg.sources || msg.trust) && (
                <div
                  className="message-scope-answered-from"
                  data-testid="message-scope-text"
                  style={{
                    fontSize: '0.8rem',
                    color: 'var(--text-secondary)',
                    marginTop: '0.35rem',
                    marginBottom: '0.35rem',
                  }}
                >
                  Answered from:{' '}
                  {msg.sources && msg.sources.length > 0
                    ? Array.from(new Set(msg.sources.map((s) => s.filename))).join(', ')
                    : msg.scopeFilenames && msg.scopeFilenames.length > 0
                    ? msg.scopeFilenames.join(', ')
                    : 'All documents I can access'}
                </div>
              )}

              {/* Visible Note when Partial */}
              {isPartial && (
                <div className="partial-note-banner" data-testid="partial-note-banner">
                  <AlertTriangle size={14} style={{ display: 'inline', marginRight: 4 }} />
                  <span>
                    Note: Some unverified statements were removed from this response.
                  </span>
                </div>
              )}

              {/* "Why this answer?" Panel */}
              {msg.sender === 'assistant' && (msg.sources || msg.trust) && (
                <details className="why-this-answer-panel" data-testid="why-this-answer-panel">
                  <summary className="why-this-answer-trigger" data-testid="why-this-answer-trigger">
                    <HelpCircle size={13} />
                    <span>Why this answer?</span>
                    {msg.trust && (
                      <span className="why-trust-score-pill">
                        Trust: {(msg.trust.score * 100).toFixed(0)}%
                      </span>
                    )}
                  </summary>

                  <div className="why-this-answer-content" data-testid="why-this-answer-content">
                    {/* Policy Notes */}
                    <div className="why-policy-notes" data-testid="why-policy-notes">
                      <div className="why-section-label">Policy & Trust Breakdown:</div>
                      <ul className="why-notes-list">
                        <li>
                          <strong>Faithfulness score:</strong> {(Number(msg.trust?.score || 0) * 100).toFixed(0)}%
                          {msg.trust?.grounded ? ' (Fully grounded in source documents)' : ' (Under strict verification)'}
                        </li>
                        {msg.pii_in_answer && (
                          <li className="why-note-warning" data-testid="why-note-pii">
                            Sensitive data (PII) findings detected and redacted in accordance with tenant privacy policy.
                          </li>
                        )}
                        {msg.trust?.partial && (
                          <li className="why-note-warning" data-testid="why-note-partial">
                            Some unverified statements were removed to preserve ground truth.
                          </li>
                        )}
                        {msg.trust?.abstained && (
                          <li className="why-note-danger" data-testid="why-note-abstained">
                            Model safely abstained due to insufficient context or faithfulness below threshold.
                          </li>
                        )}
                        {msg.injection_attempt && (
                          <li className="why-note-danger" data-testid="why-note-injection">
                            Security scan detected and neutralized a potential prompt injection attempt.
                          </li>
                        )}
                      </ul>
                    </div>

                    {/* Sources with Trust Score */}
                    {msg.sources && msg.sources.length > 0 && (
                      <div className="why-sources-section">
                        <div className="why-section-label">Sources Used ({msg.sources.length}):</div>
                        <div className="why-sources-list">
                          {msg.sources.map((src, sIdx) => (
                            <div key={`${src.chunk_id}-${sIdx}`} className="why-source-card" data-testid="why-source-item">
                              <div className="why-source-header">
                                <span className="why-source-filename">
                                  <FileText size={12} style={{ display: 'inline', marginRight: 4 }} />
                                  {src.filename} {src.page !== null ? `(Page ${src.page})` : ''}
                                </span>
                                <span className="why-source-score">
                                  Score: {src.score.toFixed(3)}
                                </span>
                              </div>
                              <div className="why-source-snippet">
                                "{src.snippet}"
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </details>
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

      {/* Document Scope Control Bar */}
      <div
        className="chat-scope-bar"
        data-testid="chat-scope-bar"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '0.75rem',
          padding: '0.45rem 0.75rem',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-sm)',
          marginBottom: '0.5rem',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <label
            htmlFor="search-in-select"
            style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontWeight: 500 }}
          >
            Search in:
          </label>
          <select
            id="search-in-select"
            className="form-input"
            style={{ width: 'auto', padding: '0.25rem 0.6rem', fontSize: '0.82rem' }}
            value={selectedDocIds.length > 0 ? 'selected' : 'all'}
            onChange={(e) => {
              if (e.target.value === 'selected') {
                loadReadyDocs()
                setIsDocModalOpen(true)
              } else {
                setSelectedDocIds([])
              }
            }}
            data-testid="select-search-in"
          >
            <option value="all">All documents I can access</option>
            <option value="selected">Selected documents</option>
          </select>
        </div>

        {selectedDocIds.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span
              className="scope-chip"
              data-testid="scope-chip"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.35rem',
                padding: '0.2rem 0.55rem',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--bg-surface-hover)',
                border: '1px solid var(--border-strong)',
                fontSize: '0.8rem',
                color: 'var(--text-primary)',
              }}
            >
              <span>{`Searching ${selectedDocIds.length} document${selectedDocIds.length > 1 ? 's' : ''}`}</span>
              <button
                type="button"
                onClick={() => setSelectedDocIds([])}
                data-testid="btn-clear-scope"
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  padding: 0,
                  display: 'flex',
                  alignItems: 'center',
                  color: 'var(--text-secondary)',
                }}
                title="Clear document scope"
                aria-label="Clear document scope"
              >
                <X size={13} />
              </button>
            </span>
            <button
              type="button"
              className="btn-secondary"
              style={{ padding: '0.2rem 0.5rem', fontSize: '0.78rem' }}
              onClick={() => {
                loadReadyDocs()
                setIsDocModalOpen(true)
              }}
              data-testid="btn-edit-scope"
            >
              Change
            </button>
          </div>
        )}
      </div>

      {/* Document Selection Modal */}
      {isDocModalOpen && (
        <div
          className="modal-backdrop"
          data-testid="doc-scope-modal"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
        >
          <div
            className="modal-card"
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--radius-md)',
              padding: '1.25rem',
              width: '90%',
              maxWidth: 480,
              maxHeight: '80vh',
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: '1rem',
              }}
            >
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 600 }}>
                Select Documents to Scope Search
              </h3>
              <button
                type="button"
                onClick={() => setIsDocModalOpen(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-secondary)',
                  cursor: 'pointer',
                }}
                data-testid="btn-close-scope-modal"
              >
                <X size={18} />
              </button>
            </div>

            {/* Filter Search Box */}
            <div style={{ position: 'relative', marginBottom: '0.75rem' }}>
              <input
                type="text"
                className="form-input"
                style={{ width: '100%', paddingLeft: '2rem' }}
                placeholder="Search documents by filename..."
                value={docSearchQuery}
                onChange={(e) => setDocSearchQuery(e.target.value)}
                data-testid="input-doc-search"
              />
              <Search
                size={14}
                style={{
                  position: 'absolute',
                  left: '0.7rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-muted)',
                }}
              />
            </div>

            {/* Document list */}
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '0.5rem',
                maxHeight: '300px',
              }}
              data-testid="doc-select-list"
            >
              {isLoadingDocs ? (
                <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Loading documents...
                </div>
              ) : readyDocs.filter((d) =>
                  d.filename.toLowerCase().includes(docSearchQuery.toLowerCase())
                ).length === 0 ? (
                <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No matching READY documents found.
                </div>
              ) : (
                readyDocs
                  .filter((d) =>
                    d.filename.toLowerCase().includes(docSearchQuery.toLowerCase())
                  )
                  .map((doc) => {
                    const id = doc.id || (doc as any).doc_id
                    const isChecked = selectedDocIds.includes(id)
                    return (
                      <label
                        key={id}
                        data-testid={`doc-select-item-${id}`}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.6rem',
                          padding: '0.4rem 0.5rem',
                          borderRadius: 'var(--radius-sm)',
                          cursor: 'pointer',
                          background: isChecked ? 'var(--bg-surface-hover)' : 'transparent',
                        }}
                      >
                        <input
                          type="checkbox"
                          checked={isChecked}
                          data-testid={`checkbox-doc-${id}`}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedDocIds((prev) => [...prev, id])
                              setDocNameMap((prev) => ({ ...prev, [id]: doc.filename }))
                            } else {
                              setSelectedDocIds((prev) => prev.filter((i) => i !== id))
                            }
                          }}
                        />
                        <span
                          style={{
                            fontSize: '0.86rem',
                            color: 'var(--text-primary)',
                            wordBreak: 'break-all',
                          }}
                        >
                          {doc.filename}
                        </span>
                      </label>
                    )
                  })
              )}
            </div>

            {/* Modal Footer */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginTop: '1rem',
                paddingTop: '0.75rem',
                borderTop: '1px solid var(--border-subtle)',
              }}
            >
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                {selectedDocIds.length} selected
              </span>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {selectedDocIds.length > 0 && (
                  <button
                    type="button"
                    className="btn-secondary"
                    style={{ fontSize: '0.8rem', padding: '0.3rem 0.6rem' }}
                    onClick={() => setSelectedDocIds([])}
                    data-testid="btn-modal-clear-all"
                  >
                    Clear All
                  </button>
                )}
                <button
                  type="button"
                  className="btn-primary"
                  style={{ fontSize: '0.8rem', padding: '0.3rem 0.75rem' }}
                  onClick={() => setIsDocModalOpen(false)}
                  data-testid="btn-modal-done"
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

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
