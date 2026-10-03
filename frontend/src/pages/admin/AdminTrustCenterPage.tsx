import React, { useState } from 'react'
import {
  ShieldCheck,
  LayoutDashboard,
  Files,
  ScrollText,
  HelpCircle,
  Sliders,
  FileWarning,
  BarChart3,
  FileCode2,
  LucideIcon,
} from 'lucide-react'
import { OverviewTab } from './OverviewTab'
import { DocumentsTab } from './DocumentsTab'
import { AuditTab } from './AuditTab'
import { KnowledgeGapsTab } from './KnowledgeGapsTab'
import { PoliciesTab } from './PoliciesTab'
import { QuarantineTab } from './QuarantineTab'
import { UsageTab } from './UsageTab'
import { AssuranceTab } from './AssuranceTab'
import { CertificateVerifyBox } from './CertificateVerifyBox'

type TabKey =
  | 'overview'
  | 'assurance'
  | 'documents'
  | 'audit'
  | 'gaps'
  | 'policies'
  | 'quarantine'
  | 'usage'

interface TabDef {
  key: TabKey
  label: string
  icon: LucideIcon
}

const TABS: TabDef[] = [
  { key: 'overview', label: 'Overview', icon: LayoutDashboard },
  { key: 'assurance', label: 'Assurance', icon: ShieldCheck },
  { key: 'documents', label: 'Documents', icon: Files },
  { key: 'audit', label: 'Audit', icon: ScrollText },
  { key: 'gaps', label: 'Knowledge Gaps', icon: HelpCircle },
  { key: 'policies', label: 'Policies', icon: Sliders },
  { key: 'quarantine', label: 'Quarantine', icon: FileWarning },
  { key: 'usage', label: 'Usage', icon: BarChart3 },
]

export const AdminTrustCenterPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('overview')
  const [showCertBox, setShowCertBox] = useState<boolean>(false)

  return (
    <div className="admin-trust-center-page" data-testid="admin-trust-center">
      {/* Page Header */}
      <div className="trust-center-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <div className="brand-icon" style={{ background: 'var(--accent-primary)', color: '#fff', borderRadius: 8, padding: 6, display: 'flex' }}>
              <ShieldCheck size={22} />
            </div>
            <h1 style={{ margin: 0, fontSize: '1.45rem', fontWeight: 700 }}>
              Trust Center & Governance
            </h1>
          </div>
          <p style={{ margin: '0.35rem 0 0', fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
            Cryptographic auditability, tenant security policies, document ACL controls, and verification
          </p>
        </div>

        <div>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => setShowCertBox(!showCertBox)}
            data-testid="btn-toggle-cert-box"
          >
            <FileCode2 size={15} />
            <span>{showCertBox ? 'Hide Certificate Verifier' : 'Verify Certificate'}</span>
          </button>
        </div>
      </div>

      {/* Certificate Verification Drawer/Card */}
      {showCertBox && (
        <div style={{ marginBottom: '1.5rem' }}>
          <CertificateVerifyBox />
        </div>
      )}

      {/* Tabs Navigation */}
      <div className="trust-tabs-nav" role="tablist" aria-label="Trust Center Sections">
        {TABS.map((tab) => {
          const Icon = tab.icon
          const isActive = activeTab === tab.key
          return (
            <button
              key={tab.key}
              role="tab"
              aria-selected={isActive}
              aria-controls={`panel-${tab.key}`}
              id={`tab-${tab.key}`}
              className={`trust-tab-button ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.key)}
              data-testid={`tab-${tab.key}`}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          )
        })}
      </div>

      {/* Tab Panels */}
      <div
        className="trust-tab-content"
        role="tabpanel"
        id={`panel-${activeTab}`}
        aria-labelledby={`tab-${activeTab}`}
        style={{ marginTop: '1.25rem' }}
      >
        {activeTab === 'overview' && <OverviewTab />}
        {activeTab === 'assurance' && <AssuranceTab />}
        {activeTab === 'documents' && <DocumentsTab />}
        {activeTab === 'audit' && <AuditTab />}
        {activeTab === 'gaps' && <KnowledgeGapsTab />}
        {activeTab === 'policies' && <PoliciesTab />}
        {activeTab === 'quarantine' && <QuarantineTab />}
        {activeTab === 'usage' && <UsageTab />}
      </div>
    </div>
  )
}
