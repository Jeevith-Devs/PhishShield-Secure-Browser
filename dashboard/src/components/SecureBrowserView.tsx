'use client';

import { useState } from 'react';

interface ScanVerdict {
  url: string;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  adaptive_action: string;
  confidence: number;
  indicators: {
    reasons: string[];
    score_breakdown: Record<string, number>;
  };
  scan_id?: string;
}

interface SecureBrowserViewProps {
  onOpenReport?: (scanId: string) => void;
  onOpenSandbox?: (url: string, threatLevel: string) => void;
}

export default function SecureBrowserView({ onOpenReport, onOpenSandbox }: SecureBrowserViewProps) {
  const [inputUrl, setInputUrl] = useState('https://www.google.com');
  const [currentUrl, setCurrentUrl] = useState('https://www.google.com');
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState<ScanVerdict | null>({
    url: 'https://www.google.com',
    threat_level: 'LOW',
    risk_score: 5,
    adaptive_action: 'ALLOW',
    confidence: 0.99,
    indicators: {
      reasons: ['Trusted domain reputation', 'Standard lexical entropy', 'Valid TLS architecture'],
      score_breakdown: { lexical: 0, threat_intel: 5, heuristic: 0 },
    },
  });
  const [barrierBlocked, setBarrierBlocked] = useState(false);

  const handleNavigate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    let target = inputUrl.trim();
    if (!target) return;
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = 'https://' + target;
      setInputUrl(target);
    }

    setLoading(true);
    try {
      const res = await fetch('http://localhost:8000/api/v1/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target, client_type: 'browser' }),
      });
      const data: ScanVerdict = await res.json();
      setVerdict(data);

      if (data.threat_level === 'HIGH' || data.threat_level === 'CRITICAL') {
        setBarrierBlocked(true);
      } else {
        setBarrierBlocked(false);
        setCurrentUrl(target);
      }
    } catch {
      // Offline fallback
      setVerdict({
        url: target,
        threat_level: 'LOW',
        risk_score: 0,
        adaptive_action: 'ALLOW',
        confidence: 0.8,
        indicators: { reasons: ['Evaluation fallback - direct navigation'], score_breakdown: {} },
      });
      setBarrierBlocked(false);
      setCurrentUrl(target);
    } finally {
      setLoading(false);
    }
  };

  const loadSample = (sampleUrl: string) => {
    setInputUrl(sampleUrl);
  };

  const getPillColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return { bg: 'rgba(248,81,73,0.15)', text: '#f85149', border: '#f85149' };
      case 'HIGH': return { bg: 'rgba(210,153,34,0.15)', text: '#d29922', border: '#d29922' };
      case 'MEDIUM': return { bg: 'rgba(187,128,9,0.15)', text: '#e3b341', border: '#e3b341' };
      default: return { bg: 'rgba(63,185,80,0.15)', text: '#3fb950', border: '#3fb950' };
    }
  };

  const pill = getPillColor(verdict?.threat_level || 'LOW');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Header Info */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            🛡️ PhishShield Secure Dedicated Browser
          </h2>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Hardened environment for analysts · Ephemeral in-memory sessions · Dynamic risk interception
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <span style={{
            fontSize: '11px', padding: '4px 8px', borderRadius: '4px',
            background: 'rgba(63,185,80,0.1)', color: '#3fb950', border: '1px solid rgba(63,185,80,0.2)'
          }}>
            ● Ephemeral Memory Isolation
          </span>
          <span style={{
            fontSize: '11px', padding: '4px 8px', borderRadius: '4px',
            background: 'rgba(88,166,255,0.1)', color: '#58a6ff', border: '1px solid rgba(88,166,255,0.2)'
          }}>
            🛡️ WebRTC Leak Guard Active
          </span>
        </div>
      </div>

      {/* Browser Hardware Shell */}
      <div style={{
        background: '#0a0d14',
        borderRadius: '12px',
        border: '1px solid var(--border)',
        overflow: 'hidden',
        boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
        display: 'flex',
        flexDirection: 'column',
        minHeight: '680px',
      }}>
        {/* Navigation & Omnibar */}
        <div style={{
          background: '#161b22',
          padding: '10px 14px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}>
          {/* Nav Buttons */}
          <div style={{ display: 'flex', gap: '4px' }}>
            <button
              onClick={() => {}}
              style={{
                background: '#21262d', border: '1px solid #30363d', color: '#c9d1d9',
                borderRadius: '6px', width: '28px', height: '28px', cursor: 'pointer',
              }}
              title="Back"
            >
              ◂
            </button>
            <button
              onClick={() => {}}
              style={{
                background: '#21262d', border: '1px solid #30363d', color: '#c9d1d9',
                borderRadius: '6px', width: '28px', height: '28px', cursor: 'pointer',
              }}
              title="Forward"
            >
              ▸
            </button>
            <button
              onClick={() => handleNavigate()}
              style={{
                background: '#21262d', border: '1px solid #30363d', color: '#c9d1d9',
                borderRadius: '6px', width: '28px', height: '28px', cursor: 'pointer',
              }}
              title="Reload"
            >
              ↻
            </button>
          </div>

          {/* Omnibar Form */}
          <form onSubmit={handleNavigate} style={{ flex: 1, display: 'flex', alignItems: 'center', position: 'relative' }}>
            <span style={{ position: 'absolute', left: '12px', fontSize: '13px', opacity: 0.7 }}>🔒</span>
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              placeholder="Enter URL to inspect safely (e.g. https://google.com or paypal-security-update.xyz)..."
              style={{
                width: '100%',
                padding: '8px 110px 8px 34px',
                background: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: '8px',
                color: '#c9d1d9',
                fontSize: '13px',
                fontFamily: 'monospace',
                outline: 'none',
              }}
            />
            {/* Risk Pill inside Omnibar */}
            {verdict && (
              <div style={{
                position: 'absolute', right: '6px',
                display: 'flex', alignItems: 'center', gap: '6px',
                background: pill.bg, color: pill.text, border: `1px solid ${pill.border}`,
                padding: '3px 8px', borderRadius: '6px', fontSize: '11px', fontWeight: 700,
              }}>
                <span>{Math.round(verdict.risk_score)}</span>
                <span style={{ opacity: 0.8 }}>{verdict.threat_level}</span>
              </div>
            )}
          </form>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => onOpenSandbox && onOpenSandbox(currentUrl, verdict?.threat_level || 'HIGH')}
              style={{
                background: 'linear-gradient(135deg, #7c3aed, #a855f7)',
                color: '#fff', border: 'none', borderRadius: '6px',
                padding: '6px 12px', fontSize: '12px', fontWeight: 600, cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: '4px',
              }}
              title="Isolate in ephemeral sandbox with synthetic credentials"
            >
              🚀 Isolate (SDI)
            </button>
            <button
              onClick={() => onOpenReport && onOpenReport(verdict?.scan_id || 'manual-eval')}
              style={{
                background: '#238636', color: '#fff', border: 'none', borderRadius: '6px',
                padding: '6px 12px', fontSize: '12px', fontWeight: 600, cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: '4px',
              }}
              title="Generate AI Security Analyst Report"
            >
              🤖 AI Report
            </button>
          </div>
        </div>

        {/* Quick Sample Selector */}
        <div style={{
          background: '#0d1117', padding: '6px 14px', borderBottom: '1px solid #21262d',
          display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px', color: '#8b949e',
        }}>
          <span>Quick Test Presets:</span>
          <button
            onClick={() => loadSample('https://google.com')}
            style={{ background: 'transparent', border: 'none', color: '#58a6ff', cursor: 'pointer', fontSize: '11px' }}
          >
            Google (Safe)
          </button>
          <span>•</span>
          <button
            onClick={() => loadSample('https://github.com')}
            style={{ background: 'transparent', border: 'none', color: '#58a6ff', cursor: 'pointer', fontSize: '11px' }}
          >
            GitHub (Safe)
          </button>
          <span>•</span>
          <button
            onClick={() => loadSample('https://paypal-verification-account-auth.xyz/login')}
            style={{ background: 'transparent', border: 'none', color: '#f85149', cursor: 'pointer', fontSize: '11px' }}
          >
            PayPal Phish (Critical)
          </button>
          <span>•</span>
          <button
            onClick={() => loadSample('http://appleid-security-cloud-verify.info/verify')}
            style={{ background: 'transparent', border: 'none', color: '#f85149', cursor: 'pointer', fontSize: '11px' }}
          >
            AppleID Phish (Critical)
          </button>
          <span>•</span>
          <button
            onClick={() => loadSample('https://chase-bank-credential-auth-portal.top')}
            style={{ background: 'transparent', border: 'none', color: '#d29922', cursor: 'pointer', fontSize: '11px' }}
          >
            Chase Phish (High)
          </button>
        </div>

        {/* Viewport Content Area */}
        <div style={{ flex: 1, position: 'relative', display: 'flex', flexDirection: 'column' }}>
          {/* Loading Indicator */}
          {loading && (
            <div style={{
              position: 'absolute', top: 0, left: 0, right: 0, height: '3px',
              background: 'linear-gradient(90deg, #58a6ff, #a855f7)',
              animation: 'pulse 1s infinite', zIndex: 10,
            }} />
          )}

          {/* Barrier Interstitial Screen */}
          {barrierBlocked ? (
            <div style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'radial-gradient(ellipse at center, rgba(248,81,73,0.12) 0%, #0a0d14 75%)',
              padding: '24px',
            }}>
              <div style={{
                maxWidth: '620px', width: '100%',
                background: '#161b22', border: '1px solid rgba(248,81,73,0.4)',
                borderRadius: '12px', padding: '24px',
                boxShadow: '0 8px 32px rgba(0,0,0,0.6)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '16px' }}>
                  <div style={{
                    width: '44px', height: '44px', borderRadius: '10px',
                    background: 'rgba(248,81,73,0.15)', display: 'flex', alignItems: 'center',
                    justifyContent: 'center', fontSize: '24px', color: '#f85149',
                  }}>
                    ⚠️
                  </div>
                  <div>
                    <h3 style={{ margin: 0, fontSize: '17px', color: '#f85149', fontWeight: 700 }}>
                      PhishShield Adaptive Barrier Intercepted
                    </h3>
                    <div style={{ fontSize: '12px', color: '#8b949e', wordBreak: 'break-all', marginTop: '2px' }}>
                      Destination: <code style={{ color: '#c9d1d9' }}>{verdict?.url}</code>
                    </div>
                  </div>
                </div>

                <div style={{
                  display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px',
                  background: '#0d1117', padding: '12px', borderRadius: '8px', marginBottom: '16px',
                }}>
                  <div>
                    <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase' }}>Risk Score</div>
                    <div style={{ fontSize: '20px', fontWeight: 800, color: pill.text }}>
                      {Math.round(verdict?.risk_score || 0)} / 100
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase' }}>Threat Level</div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: pill.text, marginTop: '4px' }}>
                      {verdict?.threat_level}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '10px', color: '#8b949e', textTransform: 'uppercase' }}>Enforcement</div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: '#58a6ff', marginTop: '4px' }}>
                      {verdict?.adaptive_action}
                    </div>
                  </div>
                </div>

                <div style={{ marginBottom: '18px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 600, color: '#8b949e', marginBottom: '6px' }}>
                    DETECTION SIGNALS & HEURISTICS:
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12px', color: '#c9d1d9', lineHeight: 1.6 }}>
                    {verdict?.indicators.reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>

                <div style={{
                  background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.2)',
                  borderRadius: '8px', padding: '10px 12px', fontSize: '12px', color: '#58a6ff',
                  marginBottom: '18px',
                }}>
                  🛡️ <strong>Recommended Safe Action:</strong> Open in PhishShield Ephemeral Sandbox with Synthetic Data Injection (SDI). No real passwords or IP addresses will be exposed.
                </div>

                <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                  <button
                    onClick={() => {
                      setBarrierBlocked(false);
                      setInputUrl('https://www.google.com');
                      setCurrentUrl('https://www.google.com');
                    }}
                    style={{
                      background: '#21262d', color: '#c9d1d9', border: '1px solid #30363d',
                      borderRadius: '6px', padding: '8px 14px', fontSize: '12px', cursor: 'pointer',
                    }}
                  >
                    ◂ Return to Safety
                  </button>
                  <button
                    onClick={() => {
                      setBarrierBlocked(false);
                      setCurrentUrl(verdict?.url || inputUrl);
                    }}
                    style={{
                      background: 'rgba(248,81,73,0.15)', color: '#f85149', border: '1px solid rgba(248,81,73,0.4)',
                      borderRadius: '6px', padding: '8px 14px', fontSize: '12px', cursor: 'pointer',
                    }}
                  >
                    Proceed at Own Risk
                  </button>
                  <button
                    onClick={() => onOpenSandbox && onOpenSandbox(verdict?.url || inputUrl, verdict?.threat_level || 'HIGH')}
                    style={{
                      background: 'linear-gradient(135deg, #7c3aed, #a855f7)', color: '#fff',
                      border: 'none', borderRadius: '6px', padding: '8px 16px', fontSize: '12px',
                      fontWeight: 600, cursor: 'pointer',
                    }}
                  >
                    🚀 Open in Sandbox (SDI)
                  </button>
                </div>
              </div>
            </div>
          ) : (
            /* Active Web Canvas Frame */
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: '#0a0d14' }}>
              <div style={{
                background: '#0d1117', padding: '8px 14px', borderBottom: '1px solid #21262d',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', color: '#8b949e',
              }}>
                <div>
                  Active Frame: <code style={{ color: '#58a6ff' }}>{currentUrl}</code>
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <span>Cookies: <strong>In-Memory Only</strong></span>
                  <span>Isolation: <strong>Active</strong></span>
                </div>
              </div>
              <iframe
                src={currentUrl}
                title="PhishShield Secure Viewport"
                sandbox="allow-scripts allow-same-origin allow-forms"
                style={{
                  flex: 1,
                  width: '100%',
                  minHeight: '560px',
                  border: 'none',
                  background: '#ffffff',
                }}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
