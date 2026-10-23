'use client';

import { useState, useEffect, useCallback } from 'react';

interface SyntheticIdentity {
  card_number: string;
  card_expiry: string;
  card_cvv: string;
  cardholder_name: string;
  email: string;
  password: string;
  note: string;
}

interface TelemetryEvent {
  event_id: string;
  event_type: string;
  timestamp: string;
  data: Record<string, any>;
}

interface SandboxSessionItem {
  session_id: string;
  url: string;
  status: string;
  threat_level: string;
  synthetic_data?: SyntheticIdentity;
  launched_at: string;
  container_id?: string;
  redirect_chain?: string[];
  forms_detected?: number;
  exfiltration_events?: number;
}

interface SandboxViewProps {
  apiBase: string;
}

export default function SandboxView({ apiBase }: SandboxViewProps) {
  const [sessions, setSessions] = useState<SandboxSessionItem[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedTelemetry, setSelectedTelemetry] = useState<TelemetryEvent[]>([]);
  const [loadingTelemetry, setLoadingTelemetry] = useState(false);
  
  const [targetUrl, setTargetUrl] = useState('http://paypal-verification.security-portal.xyz/login');
  const [threatLevel, setThreatLevel] = useState<'HIGH' | 'CRITICAL'>('HIGH');
  const [injectSynthetic, setInjectSynthetic] = useState(true);
  const [launching, setLaunching] = useState(false);

  const fetchSessions = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/sandbox/sessions`);
      if (res.ok) {
        const data = await res.json();
        setSessions(data.sessions || []);
        if (data.sessions?.length > 0 && !selectedSessionId) {
          setSelectedSessionId(data.sessions[0].session_id);
        }
      }
    } catch {
      // offline fallback
    }
  }, [apiBase, selectedSessionId]);

  const fetchTelemetry = useCallback(async (sessionId: string) => {
    setLoadingTelemetry(true);
    try {
      const res = await fetch(`${apiBase}/sandbox/sessions/${sessionId}/telemetry`);
      if (res.ok) {
        const data = await res.json();
        setSelectedTelemetry(data.events || []);
      }
    } catch {
      setSelectedTelemetry([]);
    } finally {
      setLoadingTelemetry(false);
    }
  }, [apiBase]);

  useEffect(() => {
    fetchSessions();
    const interval = setInterval(fetchSessions, 10000);
    return () => clearInterval(interval);
  }, [fetchSessions]);

  useEffect(() => {
    if (selectedSessionId) {
      fetchTelemetry(selectedSessionId);
    }
  }, [selectedSessionId, fetchTelemetry]);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl) return;
    setLaunching(true);
    try {
      const res = await fetch(`${apiBase}/sandbox/launch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: targetUrl,
          threat_level: threatLevel,
          inject_synthetic_data: injectSynthetic,
        }),
      });
      if (res.ok) {
        const newSession = await res.json();
        await fetchSessions();
        setSelectedSessionId(newSession.session_id);
      }
    } finally {
      setLaunching(false);
    }
  };

  const handleTerminate = async (sessionId: string) => {
    try {
      const res = await fetch(`${apiBase}/sandbox/sessions/${sessionId}/terminate`, {
        method: 'POST',
      });
      if (res.ok) {
        await fetchSessions();
        if (selectedSessionId === sessionId) {
          fetchTelemetry(sessionId);
        }
      }
    } catch {
      // ignore
    }
  };

  const selectedSession = sessions.find(s => s.session_id === selectedSessionId);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header card with Launch controls */}
      <div style={{
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        borderRadius: '14px', padding: '24px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Ephemeral Playwright Sandboxing & Synthetic Data Injection (SDI)
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '4px 0 0' }}>
              Safely isolate high-risk destinations with automated honeypot credentials and zero real-user data leakage.
            </p>
          </div>
          <span style={{
            fontSize: '11px', padding: '4px 10px', borderRadius: '6px',
            background: 'rgba(56, 189, 248, 0.15)', color: 'var(--accent-blue)',
            border: '1px solid rgba(56, 189, 248, 0.3)', fontWeight: 600,
          }}>
            ISO/IEC 7812 Luhn Compliant
          </span>
        </div>

        <form onSubmit={handleLaunch} style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="Enter suspicious URL to isolate…"
            style={{
              flex: 1, minWidth: '320px', padding: '10px 14px',
              background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
              borderRadius: '8px', color: 'var(--text-primary)', fontSize: '13px',
            }}
          />
          <select
            value={threatLevel}
            onChange={(e) => setThreatLevel(e.target.value as any)}
            style={{
              padding: '10px 14px', background: 'var(--bg-tertiary)',
              border: '1px solid var(--border)', borderRadius: '8px',
              color: 'var(--text-primary)', fontSize: '13px',
            }}
          >
            <option value="HIGH">HIGH Threat</option>
            <option value="CRITICAL">CRITICAL Threat</option>
          </select>

          <label style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            fontSize: '13px', color: 'var(--text-primary)', cursor: 'pointer',
          }}>
            <input
              type="checkbox"
              checked={injectSynthetic}
              onChange={(e) => setInjectSynthetic(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            Inject Synthetic Honeypot (SDI)
          </label>

          <button
            type="submit"
            disabled={launching}
            style={{
              padding: '10px 20px', borderRadius: '8px', border: 'none',
              background: 'linear-gradient(135deg, #7c3aed, #2563eb)',
              color: 'white', fontWeight: 600, fontSize: '13px', cursor: 'pointer',
              opacity: launching ? 0.7 : 1,
            }}
          >
            {launching ? 'Launching Container…' : '🚀 Launch Sandbox'}
          </button>
        </form>
      </div>

      {/* Main Grid: Sessions List (Left) + Detail & Telemetry (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: '420px 1fr', gap: '20px' }}>
        {/* Sessions List */}
        <div style={{
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: '14px', overflow: 'hidden', display: 'flex', flexDirection: 'column',
          maxHeight: '680px',
        }}>
          <div style={{
            padding: '14px 18px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Active & Recent Sessions ({sessions.length})
            </span>
            <button
              onClick={fetchSessions}
              style={{
                background: 'transparent', border: 'none', color: 'var(--accent-blue)',
                cursor: 'pointer', fontSize: '12px',
              }}
            >
              ↺ Refresh
            </button>
          </div>

          <div style={{ overflow: 'auto', flex: 1 }}>
            {sessions.length === 0 ? (
              <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                No active sandbox sessions. Launch one above!
              </div>
            ) : (
              sessions.map((s) => {
                const isSelected = s.session_id === selectedSessionId;
                const isTerm = s.status === 'terminated';
                return (
                  <div
                    key={s.session_id}
                    onClick={() => setSelectedSessionId(s.session_id)}
                    style={{
                      padding: '14px 18px', borderBottom: '1px solid var(--border)',
                      cursor: 'pointer',
                      background: isSelected ? 'rgba(88, 166, 255, 0.08)' : 'transparent',
                      borderLeft: isSelected ? '3px solid var(--accent-blue)' : '3px solid transparent',
                      transition: 'all 0.15s',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                      <span style={{
                        fontSize: '11px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px',
                        background: s.threat_level === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(249,115,22,0.2)',
                        color: s.threat_level === 'CRITICAL' ? 'var(--critical)' : 'var(--high)',
                      }}>
                        {s.threat_level}
                      </span>
                      <span style={{
                        fontSize: '11px', padding: '2px 6px', borderRadius: '4px',
                        background: isTerm ? 'var(--bg-tertiary)' : 'rgba(34,197,94,0.15)',
                        color: isTerm ? 'var(--text-muted)' : 'var(--low)',
                      }}>
                        ● {s.status.toUpperCase()}
                      </span>
                    </div>

                    <div style={{
                      fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)',
                      whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginBottom: '4px',
                    }}>
                      {s.url}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)' }}>
                      <span>ID: {s.session_id.slice(0, 8)}…</span>
                      <span>{new Date(s.launched_at).toLocaleTimeString()}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Session Detail & Behavioral Waterfall */}
        <div style={{
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: '14px', overflow: 'hidden', display: 'flex', flexDirection: 'column',
          maxHeight: '680px',
        }}>
          {selectedSession ? (
            <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
              {/* Session Top Bar */}
              <div style={{
                padding: '16px 20px', borderBottom: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                background: 'rgba(255,255,255,0.02)',
              }}>
                <div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Session: {selectedSession.container_id || selectedSession.session_id}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                    Isolated Target: <span style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{selectedSession.url}</span>
                  </div>
                </div>

                {selectedSession.status === 'active' && (
                  <button
                    onClick={() => handleTerminate(selectedSession.session_id)}
                    style={{
                      padding: '6px 14px', borderRadius: '6px', border: '1px solid var(--critical)',
                      background: 'rgba(239, 68, 68, 0.1)', color: 'var(--critical)',
                      fontSize: '12px', fontWeight: 600, cursor: 'pointer',
                    }}
                  >
                    ⏹ Terminate Container
                  </button>
                )}
              </div>

              <div style={{ flex: 1, overflow: 'auto', padding: '20px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
                {/* Synthetic Honeypot Identity Card */}
                {selectedSession.synthetic_data && (
                  <div style={{
                    border: '1px solid rgba(124, 58, 237, 0.4)', borderRadius: '12px',
                    background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.08), rgba(37, 99, 235, 0.08))',
                    padding: '16px',
                  }}>
                    <div style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      marginBottom: '12px',
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span>💳</span>
                        <span style={{ fontSize: '13px', fontWeight: 700, color: '#c084fc' }}>
                          Synthetic Honeypot Identity Injected (SDI)
                        </span>
                      </div>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                        ISO/IEC 7812 Checksum Validated
                      </span>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', fontSize: '12px' }}>
                      <div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>CARD NUMBER</div>
                        <div style={{ color: 'var(--text-primary)', fontFamily: 'monospace', fontWeight: 600 }}>
                          {selectedSession.synthetic_data.card_number}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>EXPIRY / CVV</div>
                        <div style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                          {selectedSession.synthetic_data.card_expiry} · {selectedSession.synthetic_data.card_cvv}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>CARDHOLDER</div>
                        <div style={{ color: 'var(--text-primary)' }}>
                          {selectedSession.synthetic_data.cardholder_name}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>CANARY EMAIL</div>
                        <div style={{ color: 'var(--accent-blue)', fontFamily: 'monospace', fontSize: '11px' }}>
                          {selectedSession.synthetic_data.email}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>CANARY PASSWORD</div>
                        <div style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                          {selectedSession.synthetic_data.password}
                        </div>
                      </div>
                      <div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>EXFILTRATION STATUS</div>
                        <div style={{ color: 'var(--low)', fontWeight: 600 }}>
                          🛡️ Trapped (0 Real Assets Leaked)
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Behavioral Waterfall */}
                <div>
                  <div style={{
                    fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)',
                    marginBottom: '12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  }}>
                    <span>Behavioral Telemetry Waterfall ({selectedTelemetry.length} events)</span>
                    {loadingTelemetry && <span style={{ fontSize: '11px', color: 'var(--accent-blue)' }}>Loading…</span>}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {selectedTelemetry.length === 0 ? (
                      <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                        No events recorded yet.
                      </div>
                    ) : (
                      selectedTelemetry.map((evt, i) => {
                        const badgeColor =
                          evt.event_type === 'redirect' ? 'var(--medium)' :
                          evt.event_type === 'exfiltration_alert' ? 'var(--critical)' :
                          evt.event_type === 'form_submit' ? '#c084fc' : 'var(--accent-blue)';

                        return (
                          <div key={i} style={{
                            padding: '10px 14px', borderRadius: '8px', background: 'var(--bg-tertiary)',
                            border: '1px solid var(--border)', fontSize: '12px',
                          }}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span style={{
                                  fontSize: '10px', padding: '1px 6px', borderRadius: '4px',
                                  background: `${badgeColor}20`, border: `1px solid ${badgeColor}`, color: badgeColor,
                                  fontWeight: 700, textTransform: 'uppercase',
                                }}>
                                  {evt.event_type}
                                </span>
                                <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                                  {evt.data?.target_url || evt.data?.target || evt.data?.action || evt.event_type}
                                </span>
                              </div>
                              <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                                {new Date(evt.timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                            <pre style={{
                              margin: 0, padding: '6px 8px', borderRadius: '4px',
                              background: 'var(--bg-primary)', fontSize: '10px', color: 'var(--text-secondary)',
                              fontFamily: 'monospace', overflow: 'auto',
                            }}>
                              {JSON.stringify(evt.data, null, 2)}
                            </pre>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
              Select a session on the left to view behavioral telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
