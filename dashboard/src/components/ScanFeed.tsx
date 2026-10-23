'use client';

import { useState } from 'react';
import type { ScanRecord } from '@/app/page';

interface ScanFeedProps {
  scans: ScanRecord[];
  onGenerateReport?: (scanId: string) => void;
  onLaunchSandbox?: (url: string, threatLevel: string) => void;
}

const LEVEL_COLOR: Record<string, string> = {
  LOW: 'var(--low)', MEDIUM: 'var(--medium)', HIGH: 'var(--high)', CRITICAL: 'var(--critical)',
};
const ACTION_ICON: Record<string, string> = {
  ALLOW: '✓', WARN: '⚠', CONTROLLED: '🔬', ISOLATE: '🛡',
};

export default function ScanFeed({ scans, onGenerateReport, onLaunchSandbox }: ScanFeedProps) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>('ALL');

  const filtered = filter === 'ALL' ? scans : scans.filter(s => s.threat_level === filter);

  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: '1px solid var(--border)',
      borderRadius: '12px',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '16px 20px',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>⊞</span> Scan History
          <span style={{ fontSize: '11px', fontWeight: 400, color: 'var(--text-muted)', background: 'var(--bg-tertiary)', padding: '2px 8px', borderRadius: '20px', border: '1px solid var(--border)' }}>
            {scans.length} scans
          </span>
        </div>
        {/* Filter pills */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '3px 10px',
                borderRadius: '20px',
                border: `1px solid ${filter === f ? LEVEL_COLOR[f] ?? 'var(--accent-blue)' : 'var(--border)'}`,
                background: filter === f ? `${LEVEL_COLOR[f] ?? 'var(--accent-blue)'}15` : 'transparent',
                color: filter === f ? (LEVEL_COLOR[f] ?? 'var(--accent-blue)') : 'var(--text-muted)',
                fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                transition: 'all .15s',
              }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Table header */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '120px 1fr 90px 80px 90px 100px',
        padding: '8px 20px',
        background: 'var(--bg-tertiary)',
        borderBottom: '1px solid var(--border)',
        fontSize: '10px', fontWeight: 700, color: 'var(--text-muted)',
        textTransform: 'uppercase', letterSpacing: '0.5px',
      }}>
        <span>Time</span>
        <span>URL</span>
        <span>Score</span>
        <span>Level</span>
        <span>Action</span>
        <span>Confidence</span>
      </div>

      {/* Rows */}
      <div style={{ maxHeight: '380px', overflowY: 'auto' }}>
        {filtered.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
            No scans yet — use the Live Scanner or browse with the extension
          </div>
        ) : filtered.map((scan) => (
          <div key={scan.scan_id}>
            <div
              onClick={() => setExpanded(expanded === scan.scan_id ? null : scan.scan_id)}
              style={{
                display: 'grid',
                gridTemplateColumns: '120px 1fr 90px 80px 90px 100px',
                padding: '11px 20px',
                borderBottom: '1px solid var(--border)',
                cursor: 'pointer',
                transition: 'background .15s',
                background: expanded === scan.scan_id ? 'rgba(88,166,255,.04)' : 'transparent',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.02)')}
              onMouseLeave={e => (e.currentTarget.style.background = expanded === scan.scan_id ? 'rgba(88,166,255,.04)' : 'transparent')}
            >
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                {new Date(scan.scan_timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: '12px', fontFamily: 'JetBrains Mono, monospace' }}>
                {scan.url}
              </span>
              <span style={{ fontSize: '13px', fontWeight: 700, color: LEVEL_COLOR[scan.threat_level] }}>
                {Math.round(scan.risk_score)}
              </span>
              <span style={{
                fontSize: '10px', fontWeight: 700,
                padding: '2px 8px', borderRadius: '20px',
                background: `${LEVEL_COLOR[scan.threat_level]}15`,
                color: LEVEL_COLOR[scan.threat_level],
                display: 'inline-flex', alignItems: 'center',
                width: 'fit-content',
              }}>
                {scan.threat_level}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                {ACTION_ICON[scan.adaptive_action]} {scan.adaptive_action}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                {Math.round(scan.confidence * 100)}%
              </span>
            </div>

            {/* Expanded row */}
            {expanded === scan.scan_id && (
              <div style={{
                padding: '16px 20px',
                background: 'rgba(88,166,255,.03)',
                borderBottom: '1px solid var(--border)',
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '16px',
              }}>
                {/* Score breakdown */}
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
                    Score Breakdown
                  </div>
                  {Object.entries(scan.indicators?.score_breakdown ?? {}).map(([key, val]) => (
                    <div key={key} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-secondary)', padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                      <span>{key.replace(/_/g, ' ')}</span>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-primary)' }}>{(val as number).toFixed(2)}</span>
                    </div>
                  ))}
                </div>
                {/* Reasons + features */}
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '10px' }}>
                    Detection Reasons
                  </div>
                  {(scan.indicators?.reasons ?? []).length === 0 ? (
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>No indicators — site appears clean.</div>
                  ) : (scan.indicators?.reasons ?? []).map((r, i) => (
                    <div key={i} style={{ fontSize: '11px', color: 'var(--text-secondary)', padding: '4px 0', display: 'flex', gap: '6px', borderBottom: '1px solid var(--border)' }}>
                      <span style={{ color: LEVEL_COLOR[scan.threat_level], flexShrink: 0 }}>›</span> {r}
                    </div>
                  ))}
                  <div style={{ marginTop: '12px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                    {onGenerateReport && (
                      <button
                        onClick={(e) => { e.stopPropagation(); onGenerateReport(scan.scan_id); }}
                        style={{
                          padding: '5px 12px', borderRadius: '6px', border: '1px solid var(--accent-blue)',
                          background: 'rgba(88, 166, 255, 0.15)', color: 'var(--accent-blue)',
                          fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                        }}
                      >
                        🤖 Generate AI Report
                      </button>
                    )}
                    {onLaunchSandbox && scan.threat_level !== 'LOW' && (
                      <button
                        onClick={(e) => { e.stopPropagation(); onLaunchSandbox(scan.url, scan.threat_level); }}
                        style={{
                          padding: '5px 12px', borderRadius: '6px', border: '1px solid var(--critical)',
                          background: 'rgba(239, 68, 68, 0.15)', color: 'var(--critical)',
                          fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                        }}
                      >
                        🚀 Isolate in Sandbox
                      </button>
                    )}
                  </div>
                  <div style={{ marginTop: '10px', fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                    Scan ID: {scan.scan_id}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
