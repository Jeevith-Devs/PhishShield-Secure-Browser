'use client';

import { useState, useEffect } from 'react';

interface FeedEntry {
  url: string;
  threat_type: string;
  reporter: string;
  reported_at: string;
  tags: string[];
}

interface RecentFeedProps {
  apiBase: string;
}

const REPORTER_COLOR: Record<string, string> = {
  URLhaus: '#f97316',
  AbuseIPDB: '#f59e0b',
  VirusTotal: '#22c55e',
};

export default function RecentFeed({ apiBase }: RecentFeedProps) {
  const [entries, setEntries] = useState<FeedEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await fetch(`${apiBase}/intel/feeds/recent?limit=10`);
        if (res.ok) setEntries(await res.json());
      } catch {
        // fail silently — feed stubs shown as empty
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [apiBase]);

  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: '1px solid var(--border)',
      borderRadius: '12px',
      overflow: 'hidden',
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '16px 20px',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span>◇</span> Live Threat Intelligence Feed
        </div>
        <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '4px', background: 'rgba(245,158,11,.1)', border: '1px solid var(--medium)', color: 'var(--medium)' }}>
          Stub — Sprint 3 live feeds
        </span>
      </div>

      <div>
        {loading ? (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>Loading feed…</div>
        ) : entries.length === 0 ? (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>No recent feed entries.</div>
        ) : entries.map((entry, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'flex-start', gap: '14px',
            padding: '14px 20px',
            borderBottom: i < entries.length - 1 ? '1px solid var(--border)' : 'none',
            transition: 'background .15s',
          }}>
            {/* Threat type badge */}
            <div style={{
              flexShrink: 0,
              padding: '3px 10px',
              borderRadius: '4px',
              background: 'rgba(239,68,68,.1)',
              border: '1px solid var(--critical)',
              color: 'var(--critical)',
              fontSize: '10px', fontWeight: 700, textTransform: 'uppercase',
            }}>
              {entry.threat_type}
            </div>

            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: '12px', color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: '6px' }}>
                {entry.url}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <span style={{
                  fontSize: '10px', fontWeight: 600,
                  color: REPORTER_COLOR[entry.reporter] ?? 'var(--accent-blue)',
                }}>
                  {entry.reporter}
                </span>
                {entry.tags.map((tag) => (
                  <span key={tag} style={{
                    fontSize: '10px', padding: '1px 7px',
                    borderRadius: '3px',
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-muted)',
                  }}>
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace', flexShrink: 0 }}>
              {new Date(entry.reported_at).toLocaleDateString()}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
