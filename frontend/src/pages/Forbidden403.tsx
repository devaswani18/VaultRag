import React from 'react'
import { Link } from 'react-router-dom'
import { ShieldAlert, ArrowLeft } from 'lucide-react'

export const Forbidden403: React.FC = () => {
  return (
    <div className="forbidden-page" data-testid="forbidden-403">
      <div className="forbidden-card">
        <div className="forbidden-icon-wrapper">
          <ShieldAlert size={48} className="forbidden-icon" />
        </div>
        <h1 className="forbidden-title">403 — Forbidden</h1>
        <p className="forbidden-text">
          Access to the VaultRAG Admin Trust Center is restricted strictly to administrators.
          Your current roles do not have permission to view or manage tenant security policies.
        </p>
        <div className="forbidden-actions">
          <Link to="/chat" className="btn-primary" data-testid="btn-forbidden-back">
            <ArrowLeft size={16} />
            <span>Return to Knowledge Query</span>
          </Link>
        </div>
      </div>
    </div>
  )
}
