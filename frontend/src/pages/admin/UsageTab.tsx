import React, { useCallback, useEffect, useState } from 'react'
import { UsageDayRecord, getUsage } from '../../api/client'
import { Activity, Zap, TrendingUp, AlertCircle, BarChart3, Database } from 'lucide-react'

export const UsageTab: React.FC = () => {
  const [usage, setUsage] = useState<UsageDayRecord[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [hoveredDay, setHoveredDay] = useState<UsageDayRecord | null>(null)

  const fetchUsage = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await getUsage(30)
      // Sort chronologically ascending for the chart
      const sorted = [...(data.usage || [])].sort((a, b) => a.day.localeCompare(b.day))
      setUsage(sorted)
    } catch (err: any) {
      setError(err?.message || 'Failed to load usage history')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchUsage()
  }, [fetchUsage])

  // Calculations for summary & chart scaling
  const totalQueries = usage.reduce((sum, d) => sum + (d.queries || 0), 0)
  const totalHits = usage.reduce((sum, d) => sum + (d.cache_hits || 0), 0)
  const totalMisses = usage.reduce((sum, d) => sum + (d.cache_misses || 0), 0)
  const totalLookups = totalHits + totalMisses
  const hitRate = totalLookups > 0 ? ((totalHits / totalLookups) * 100).toFixed(1) : '0.0'
  const totalTokens = usage.reduce((sum, d) => sum + (d.est_tokens || 0), 0)

  const maxVal = Math.max(1, ...usage.map((d) => Math.max(d.queries || 0, d.cache_hits || 0)))

  // SVG Chart dimensions
  const chartHeight = 220
  const chartPaddingTop = 20
  const chartPaddingBottom = 30
  const usableHeight = chartHeight - chartPaddingTop - chartPaddingBottom

  return (
    <div className="usage-tab" data-testid="usage-tab">
      <div style={{ marginBottom: '1.25rem' }}>
        <h2 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>30-Day Query & Cache Telemetry</h2>
        <p style={{ margin: '0.25rem 0 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Historical query volume, semantic cache utilization, and estimated token metering over the last 30 days.
        </p>
      </div>

      {error && (
        <div className="error-alert" style={{ marginBottom: '1rem' }} data-testid="usage-error-message">
          <AlertCircle size={16} />
          <span>{error}</span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="kpi-grid" style={{ marginBottom: '1.5rem' }}>
        <div className="kpi-card" data-testid="kpi-total-queries">
          <div className="kpi-header">
            <span>30-Day Total Queries</span>
            <Activity size={16} color="var(--accent-primary)" />
          </div>
          <div className="kpi-value">{totalQueries.toLocaleString()}</div>
          <div className="kpi-subtext">Cumulative RAG inquiries</div>
        </div>

        <div className="kpi-card" data-testid="kpi-total-cache-hits">
          <div className="kpi-header">
            <span>Semantic Cache Hits</span>
            <Zap size={16} color="var(--success)" />
          </div>
          <div className="kpi-value">{totalHits.toLocaleString()}</div>
          <div className="kpi-subtext">{hitRate}% cache efficiency</div>
        </div>

        <div className="kpi-card" data-testid="kpi-cache-hit-rate">
          <div className="kpi-header">
            <span>Cache Hit Rate</span>
            <TrendingUp size={16} color="var(--warning)" />
          </div>
          <div className="kpi-value">{hitRate}%</div>
          <div className="kpi-subtext">Zero-latency responses</div>
        </div>

        <div className="kpi-card" data-testid="kpi-est-tokens">
          <div className="kpi-header">
            <span>Estimated Tokens</span>
            <Database size={16} color="var(--accent-primary-hover)" />
          </div>
          <div className="kpi-value">{totalTokens > 1000 ? `${(totalTokens / 1000).toFixed(1)}k` : totalTokens}</div>
          <div className="kpi-subtext">Estimated model tokens</div>
        </div>
      </div>

      {/* Pure SVG Bar Chart Container */}
      <div className="trust-card" data-testid="usage-chart-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <BarChart3 size={18} color="var(--accent-primary)" />
            <h3 style={{ margin: 0, fontSize: '0.95rem', fontWeight: 600 }}>Daily Queries & Cache Hits</h3>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.8rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--accent-primary)', display: 'inline-block' }} />
              <span>Queries</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--success)', display: 'inline-block' }} />
              <span>Cache Hits</span>
            </div>
          </div>
        </div>

        {loading ? (
          <div className="tab-loading-state" data-testid="usage-loading">
            <div className="spinner" />
            <p>Plotting usage bars...</p>
          </div>
        ) : usage.length === 0 ? (
          <div className="empty-substate" data-testid="empty-usage-message">
            <span>No query usage records available for this tenant.</span>
          </div>
        ) : (
          <div className="svg-chart-wrapper" style={{ position: 'relative', overflowX: 'auto' }}>
            <svg
              viewBox={`0 0 ${Math.max(640, usage.length * 28)} ${chartHeight}`}
              preserveAspectRatio="none"
              style={{ width: '100%', minWidth: 640, height: 220 }}
              data-testid="usage-svg-chart"
            >
              {/* Horizontal guide lines */}
              {[0, 0.25, 0.5, 0.75, 1].map((ratio, i) => {
                const y = chartPaddingTop + usableHeight * (1 - ratio)
                const val = Math.round(maxVal * ratio)
                return (
                  <g key={i}>
                    <line
                      x1="40"
                      y1={y}
                      x2={Math.max(640, usage.length * 28)}
                      y2={y}
                      stroke="var(--border-color)"
                      strokeDasharray="3,3"
                      strokeWidth="1"
                    />
                    <text
                      x="35"
                      y={y + 3}
                      textAnchor="end"
                      fill="var(--text-muted)"
                      fontSize="9"
                      fontFamily="monospace"
                    >
                      {val}
                    </text>
                  </g>
                )
              })}

              {/* Day Bars */}
              {usage.map((d, index) => {
                const totalBarWidth = 18
                const groupX = 50 + index * 26
                const qHeight = ((d.queries || 0) / maxVal) * usableHeight
                const hHeight = ((d.cache_hits || 0) / maxVal) * usableHeight

                const qY = chartHeight - chartPaddingBottom - qHeight
                const hY = chartHeight - chartPaddingBottom - hHeight

                const isHovered = hoveredDay?.day === d.day

                return (
                  <g
                    key={d.day}
                    onMouseEnter={() => setHoveredDay(d)}
                    onMouseLeave={() => setHoveredDay(null)}
                    style={{ cursor: 'pointer' }}
                    data-testid={`bar-day-${d.day}`}
                  >
                    {/* Background highlight on hover */}
                    {isHovered && (
                      <rect
                        x={groupX - 3}
                        y={chartPaddingTop}
                        width={totalBarWidth + 6}
                        height={usableHeight}
                        fill="rgba(99, 102, 241, 0.1)"
                        rx="4"
                      />
                    )}

                    {/* Queries bar */}
                    <rect
                      x={groupX}
                      y={qY}
                      width={8}
                      height={Math.max(2, qHeight)}
                      fill={isHovered ? 'var(--accent-primary-hover)' : 'var(--accent-primary)'}
                      rx="2"
                    />

                    {/* Cache hits bar */}
                    <rect
                      x={groupX + 9}
                      y={hY}
                      width={8}
                      height={Math.max(2, hHeight)}
                      fill="var(--success)"
                      rx="2"
                    />

                    {/* X-axis date label (every 3rd or 4th day) */}
                    {(index % 4 === 0 || index === usage.length - 1) && (
                      <text
                        x={groupX + 8}
                        y={chartHeight - 8}
                        textAnchor="middle"
                        fill="var(--text-muted)"
                        fontSize="8.5"
                        fontFamily="monospace"
                      >
                        {d.day.slice(5)}
                      </text>
                    )}
                  </g>
                )
              })}
            </svg>

            {/* Hover Tooltip */}
            {hoveredDay && (
              <div
                className="chart-tooltip"
                data-testid="chart-tooltip"
                style={{
                  position: 'absolute',
                  top: 10,
                  right: 15,
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 6,
                  padding: '0.5rem 0.75rem',
                  fontSize: '0.8rem',
                  boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
                  pointerEvents: 'none',
                }}
              >
                <div><strong>Date:</strong> {hoveredDay.day}</div>
                <div>Queries: {hoveredDay.queries}</div>
                <div>Cache Hits: {hoveredDay.cache_hits}</div>
                <div>Hit Rate: {hoveredDay.queries ? `${((hoveredDay.cache_hits / hoveredDay.queries) * 100).toFixed(0)}%` : '0%'}</div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
