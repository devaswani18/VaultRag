import React from 'react'
import { Link, NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth'
import { Shield, MessageSquare, Files, LogOut } from 'lucide-react'

export const Layout: React.FC = () => {
  const { user, logout } = useAuth()

  return (
    <div className="app-container">
      <header className="app-header">
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <Link to="/chat" className="header-brand">
            <div className="brand-icon">
              <Shield size={16} />
            </div>
            <span>VaultRAG</span>
          </Link>

          <nav className="nav-links">
            <NavLink
              to="/chat"
              className={({ isActive }) =>
                `nav-link ${isActive ? 'active' : ''}`
              }
            >
              <MessageSquare size={16} />
              <span>Query & Chat</span>
            </NavLink>
            <NavLink
              to="/documents"
              className={({ isActive }) =>
                `nav-link ${isActive ? 'active' : ''}`
              }
            >
              <Files size={16} />
              <span>Documents</span>
            </NavLink>
            {user?.roles?.includes('admin') && (
              <NavLink
                to="/admin"
                className={({ isActive }) =>
                  `nav-link ${isActive ? 'active' : ''}`
                }
                data-testid="nav-link-admin"
              >
                <Shield size={16} />
                <span>Trust Center</span>
              </NavLink>
            )}
          </nav>
        </div>

        {user && (
          <div className="header-user-meta">
            <div className="meta-pill" title="Current tenant">
              <span>TENANT:</span>
              <strong data-testid="user-tenant">{user.tenant_id}</strong>
            </div>

            <span className="user-email-text" data-testid="user-email">
              {user.email}
            </span>

            <div className="roles-badge-container">
              {user.roles.map((r) => (
                <span key={r} className="role-badge" data-testid={`role-${r}`}>
                  {r}
                </span>
              ))}
            </div>

            <button
              onClick={logout}
              className="btn-logout"
              title="Sign out of your session"
              data-testid="btn-logout"
            >
              <LogOut size={14} style={{ display: 'inline', marginRight: '4px' }} />
              Logout
            </button>
          </div>
        )}
      </header>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  )
}
