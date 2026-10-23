'use client';

import { useState, useRef, useCallback } from 'react';
import type { ScanRecord } from '@/app/page';

interface LiveScannerProps {
  apiBase: string;
  onNewScan: (scan: ScanRecord) => void;
}

const LEVEL_COLOR: Record<string, string> = {
  LOW: 'var(--low)',
  MEDIUM: 'var(--medium)',
  HIGH: 'var(--high)',
  CRITICAL: 'var(--critical)',
};
const LEVEL_BG: Record<string, string> = {
  LOW: 'rgba(34,197,94,.08)',
  MEDIUM: 'rgba(245,158,11,.08)',
  HIGH: 'rgba(249,115,22,.08)',
  CRITICAL: 'rgba(239,68,68,.10)',
};

export default function LiveScanner({ apiBase, onNewScan }: LiveScannerProps) {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const runScan = useCallback(async (targetUrl: string) => {
    if (!targetUrl.trim()) return;
    setScanning(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`${apiBase}/scan/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl.trim(), client_type: 'dashboard' }),
      });
      if (!res.ok) throw new Error(`API error ${res.status}`);
      const data: ScanRecord = await res.json();
      setResult(data);
      onNewScan(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Scan failed. Is the backend running?');
    } finally {
      setScanning(false);
    }
  }, [apiBase, onNewScan]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    runScan(url);
  };

  const sampleUrls = [
    'https://google.com',
    'http://paypal-secure-login.xyz/verify',
    'http://192.168.1.1/wallet/signin',
    'http://apple-id-verify.top/account',
  ];

  const level = result?.threat_level ?? 'LOW';

  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: '1px solid var(--border)',
      borderRadius: '12px',
      padding: '20px',
      display: 'flex',
      flexDirection: 'column',
      gap: '16px',
    }}>
      <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span>⬡</span> Live URL Scanner
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
        <input
          ref={inputRef}
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="Enter a URL to scan…"
          style={{
            width: '100%',
            background: 'var(--bg-primary)',
            border: '1px solid var(--border-bright)',
            borderRadius: '8px',
            padding: '10px 14px',
            color: 'var(--text-primary)',
            fontSize: '12px',
            fontFamily: 'JetBrains Mono, monospace',
            outline: 'none',
            transition: 'border-color .2s',
          }}
        />
        <button
          type="submit"
          disabled={scanning || !url.trim()}
          style={{
            width: '100%',
            padding: '10px',
            borderRadius: '8px',
            border: 'none',
            background: scanning ? 'var(--bg-tertiary)' : 'linear-gradient(135deg, #58a6ff, #7c3aed)',
            color: scanning ? 'var(--text-muted)' : 'white',
            fontSize: '13px',
            fontWeight: 700,
            cursor: scanning ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
          }}
        >
          {scanning ? (
            <>
              <span style={{ display: 'inline-block', width: '14px', height: '14px', border: '2px solid #444', borderTopColor: '#58a6ff', borderRadius: '50%', animation: 'spin 0.7s linear infinite' }} />
              Scanning…
            </>
          ) : '🔍 Analyze URL'}
        </button>
      </form>

      {/* Sample URLs */}
      <div>
        <div style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px' }}>
          Quick Test URLs
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {sampleUrls.map((s) => (
            <button
              key={s}
              onClick={() => { setUrl(s); runScan(s); }}
              style={{
                background: 'transparent',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '5px 10px',
                color: 'var(--accent-blue)',
                fontSize: '10px',
                fontFamily: 'JetBrains Mono, monospace',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all .15s',
                wordBreak: 'break-all',
              }}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          background: 'rgba(239,68,68,.08)', border: '1px solid var(--critical)',
          borderRadius: '8px', padding: '12px',
          fontSize: '12px', color: 'var(--critical)',
        }}>
          ⚠ {error}
        </div>
      )}

      {/* Result */}
      {result && (
        <div style={{
          background: LEVEL_BG[level],
          border: `1px solid ${LEVEL_COLOR[level]}`,
          borderRadius: '10px',
          padding: '16px',
          animation: 'fadeUp 0.3s ease',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
            <div>
              <div style={{ fontSize: '28px', fontWeight: 800, color: LEVEL_COLOR[level], lineHeight: 1 }}>
                {Math.round(result.risk_score)}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>Risk Score</div>
            </div>
            <div style={{
              padding: '4px 12px',
              borderRadius: '20px',
              background: `${LEVEL_COLOR[level]}20`,
              color: LEVEL_COLOR[level],
              fontSize: '11px',
              fontWeight: 700,
            }}>
              {level}
            </div>
          </div>

          {/* Score bar */}
          <div style={{ height: '4px', background: 'var(--border)', borderRadius: '2px', marginBottom: '12px', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${result.risk_score}%`,
              background: LEVEL_COLOR[level],
              borderRadius: '2px',
              transition: 'width 0.8s ease',
            }} />
          </div>

          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px', fontWeight: 600 }}>
            Action: <span style={{ color: LEVEL_COLOR[level] }}>{result.adaptive_action}</span>
            <span style={{ color: 'var(--text-muted)', marginLeft: '8px' }}>· {Math.round(result.confidence * 100)}% confidence</span>
          </div>

          {result.indicators?.reasons?.length > 0 && (
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '10px' }}>
              {result.indicators.reasons.slice(0, 3).map((r, i) => (
                <div key={i} style={{ fontSize: '11px', color: 'var(--text-secondary)', padding: '3px 0', display: 'flex', gap: '6px' }}>
                  <span style={{ color: LEVEL_COLOR[level], flexShrink: 0 }}>›</span> {r}
                </div>
              ))}
            </div>
          )}

          <div style={{ marginTop: '10px', fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
            ID: {result.scan_id?.slice(0, 16)}…
          </div>
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } } @keyframes fadeUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }`}</style>
    </div>
  );
}
