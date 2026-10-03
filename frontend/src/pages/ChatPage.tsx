import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  ConversationSummary,
  DocumentRecord,
  QuerySource,
  QueryTrust,
  clearAllConversations,
  deleteConversation,
  getConversation,
  getPolicies,
  listConversations,
  listDocuments,
  query,
} from '../api/client'
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
  Plus,
  Trash2,
  Clock,
  Info,
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
  const navigate = useNavigate()
  const { conversationId } = useParams<{ conversationId?: string }>()

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

  // Conversation history state
  const [conversations, setConversations] = useState<ConversationSummary[]>([])
  const [chatHistoryDays, setChatHistoryDays] = useState<number>(7)
  const [isLoadingHistory, setIsLoadingHistory] = useState<boolean>(false)
  const [showClearConfirm, setShowClearConfirm] = useState<boolean>(false)
  const [currentConversationId, setCurrentConversationId] = useState<string | undefined>(
    conversationId
  )

  // Document scope state
  const [selectedDocIds, setSelectedDocIds] = useState<string[]>([])
  const [docNameMap, setDocNameMap] = useState<Record<string, string>>({})
  const [readyDocs, setReadyDocs] = useState<DocumentRecord[]>([])
  const [isDocModalOpen, setIsDocModalOpen] = useState(false)
  const [docSearchQuery, setDocSearchQuery] = useState('')
  const [isLoadingDocs, setIsLoadingDocs] = useState(false)

  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Load tenant policy to check chat_history_days
  useEffect(() => {
    let mounted = true
    getPolicies()
      .then((pol) => {
        if (mounted && pol && pol.chat_history_days !== undefined) {
          setChatHistoryDays(pol.chat_history_days)
        }
      })
      .catch(() => {
        // Fall back to default 7
      })
    return () => {
      mounted = false
    }
  }, [])

  // Load conversations list if history is enabled
  const loadConversations = useCallback(async () => {
    if (chatHistoryDays <= 0) return
    setIsLoadingHistory(true)
    try {
      const resp = await listConversations(50)
      setConversations(resp.conversations || [])
    } catch {
      // ignore
    } finally {
      setIsLoadingHistory(false)
    }
  }, [chatHistoryDays])

  useEffect(() => {
    if (chatHistoryDays > 0) {
      loadConversations()
    }
  }, [chatHistoryDays, loadConversations])

  // Load messages when conversationId changes or on page refresh
  useEffect(() => {
    setCurrentConversationId(conversationId)
    if (!conversationId) {
      setMessages([
        {
          id: 'msg-welcome',
          sender: 'assistant',
          text: 'Hello! Ask any question about your tenant documents, and I will answer with citations grounded in your vault.',
        },
      ])
      return
    }

    let isMounted = true
    setIsLoading(true)
    getConversation(conversationId)
      .then((detail) => {
        if (!isMounted) return
        if (detail.messages && detail.messages.length > 0) {
          const loaded: ChatMessage[] = detail.messages.map((m) => ({
            id: `msg-${m.seq}`,
            sender: m.role,
            text: m.text,
            trust: m.trust,
            sources: m.sources,
          }))
          setMessages(loaded)
        } else {
          setMessages([
            {
              id: 'msg-welcome',
              sender: 'assistant',
              text: 'Conversation history loaded.',
            },
          ])
        }
      })
      .catch((err) => {
        if (!isMounted) return
        setQueryError(err?.message || 'Failed to load conversation')
      })
      .finally(() => {
        if (isMounted) setIsLoading(false)
      })

    return () => {
      isMounted = false
    }
  }, [conversationId])

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
        selectedDocIds.length > 0 ? selectedDocIds : undefined,
        currentConversationId
      )

      if (resp.conversation_id && resp.conversation_id !== currentConversationId) {
        setCurrentConversationId(resp.conversation_id)
        navigate(`/chat/${resp.conversation_id}`, { replace: true })
        loadConversations()
      }

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

  const handleNewChat = () => {
    setCurrentConversationId(undefined)
    navigate('/chat')
    setMessages([
      {
        id: 'msg-welcome',
        sender: 'assistant',
        text: 'Hello! Ask any question about your tenant documents, and I will answer with citations grounded in your vault.',
      },
    ])
  }

  const handleDeleteOne = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    try {
      await deleteConversation(id)
      setConversations((prev) => prev.filter((c) => c.conversation_id !== id))
      if (currentConversationId === id) {
        handleNewChat()
      }
    } catch (err: any) {
      setQueryError(err?.message || 'Failed to delete conversation')
    }
  }

  const handleClearAll = async () => {
    try {
      await clearAllConversations()
      setConversations([])
      setShowClearConfirm(false)
      handleNewChat()
    } catch (err: any) {
      setQueryError(err?.message || 'Failed to clear conversations')
    }
  }

  const formatRelativeDate = (isoStr: string) => {
    try {
      const date = new Date(isoStr)
      const now = new Date()
      const diffMs = now.getTime() - date.getTime()
      const diffMins = Math.floor(diffMs / 60000)
      if (diffMins < 1) return 'Just now'
      if (diffMins < 60) return `${diffMins}m ago`
      const diffHours = Math.floor(diffMins / 60)
      if (diffHours < 24) return `${diffHours}h ago`
      const diffDays = Math.floor(diffHours / 24)
      if (diffDays === 1) return 'Yesterday'
      if (diffDays < 7) return `${diffDays}d ago`
      return date.toLocaleDateString()
    } catch {
      return ''
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
    <div className="chat-page-container">
      {/* Sidebar: only rendered when chat_history_days > 0 */}
      {chatHistoryDays > 0 && (
        <aside className="chat-sidebar" data-testid="chat-sidebar">
          <div className="chat-sidebar-header">
            <div className="chat-sidebar-title-row">
              <span className="chat-sidebar-title">Conversations</span>
              <button
                type="button"
                className="btn-primary"
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.78rem' }}
                onClick={handleNewChat}
                data-testid="btn-new-chat"
              >
                <Plus size={13} style={{ marginRight: 3 }} />
                New chat
              </button>
            </div>
          </div>

          <div className="chat-sidebar-list" data-testid="chat-sidebar-list">
            {isLoadingHistory && conversations.length === 0 ? (
              <div style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                Loading conversations...
              </div>
            ) : conversations.length === 0 ? (
              <div style={{ padding: '1.25rem 0.5rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                No prior conversations
              </div>
            ) : (
              conversations.map((conv) => {
                const isActive = conv.conversation_id === currentConversationId
                return (
                  <div
                    key={conv.conversation_id}
                    className={`chat-sidebar-item ${isActive ? 'active' : ''}`}
                    onClick={() => navigate(`/chat/${conv.conversation_id}`)}
                    data-testid={`conversation-item-${conv.conversation_id}`}
                  >
                    <div className="chat-sidebar-item-content">
                      <span className="chat-sidebar-item-title" title={conv.title}>
                        {conv.title || 'Conversation'}
                      </span>
                      <span className="chat-sidebar-item-date">
                        {formatRelativeDate(conv.updated_at || conv.created_at)}
                      </span>
                    </div>
                    <button
                      type="button"
                      className="chat-sidebar-item-delete"
                      onClick={(e) => handleDeleteOne(e, conv.conversation_id)}
                      data-testid={`btn-delete-conv-${conv.conversation_id}`}
                      title="Delete conversation"
                      aria-label="Delete conversation"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                )
              })
            )}
          </div>

          <div className="chat-sidebar-footer">
            {conversations.length > 0 && (
              <button
                type="button"
                className="btn-secondary"
                style={{ width: '100%', fontSize: '0.78rem', padding: '0.3rem 0.6rem', color: 'var(--status-failed)' }}
                onClick={() => setShowClearConfirm(true)}
                data-testid="btn-clear-all-history"
              >
                Clear all history
              </button>
            )}
          </div>
        </aside>
      )}

      {/* Main Chat Area */}
      <div className="chat-layout" style={{ flex: 1, minWidth: 0 }}>
        <div className="page-title-row" style={{ marginBottom: '0.75rem' }}>
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

        {/* History retention notice: strictly when history is enabled */}
        {chatHistoryDays > 0 && (
          <div className="chat-history-note" data-testid="chat-history-note">
            <Info size={13} />
            <span>{`History is kept for ${chatHistoryDays} days and is visible only to you.`}</span>
          </div>
        )}

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

        {/* Clear All History Confirmation Modal */}
        {showClearConfirm && (
          <div
            className="modal-backdrop"
            data-testid="clear-history-modal"
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
                maxWidth: 420,
              }}
            >
              <h3 style={{ margin: '0 0 0.5rem', fontSize: '1rem', fontWeight: 600 }}>
                Clear Conversation History?
              </h3>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1.25rem' }}>
                This will permanently delete all your conversation history and messages across all sessions. This action cannot be undone.
              </p>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '0.82rem', padding: '0.35rem 0.75rem' }}
                  onClick={() => setShowClearConfirm(false)}
                  data-testid="btn-cancel-clear-history"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  style={{ fontSize: '0.82rem', padding: '0.35rem 0.75rem', backgroundColor: 'var(--status-failed)' }}
                  onClick={handleClearAll}
                  data-testid="btn-confirm-clear-history"
                >
                  Clear All
                </button>
              </div>
            </div>
          </div>
        )}

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
    </div>
  )
}
