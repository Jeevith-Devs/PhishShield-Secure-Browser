'use client';

import { useState } from 'react';

export interface AnalystReportData {
  report_id: string;
  generated_at: string;
  target_url: string;
  scan_id: string;
  risk_score: number;
  threat_level: string;
  adaptive_action: string;
  executive_summary: string;
  observed: Array<{
    category: string;
    description: string;
    evidence_source: string;
    timestamp: string;
  }>;
  inferred: Array<{
    hypothesis: string;
    supporting_facts: string[];
    confidence: string;
  }>;
  unknown: Array<{
    what_is_unknown: string;
    why_unknown: string;
  }>;
  recommended_actions: string[];
  iocs: {
    domains?: string[];
    ips?: string[];
    hashes?: string[];
  };
}

interface ModalProps {
  report: AnalystReportData | null;
  loading?: boolean;
  onClose: () => void;
}

export default function AnalystReportModal({ report, loading, onClose }: ModalProps) {
  const [activeTab, setActiveTab] = useState<'triad' | 'iocs' | 'actions' | 'raw'>('triad');
  const [copied, setCopied] = useState(false);

  if (!report && !loading) return null;

  const handleCopyJson = () => {
    if (report) {
      navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const threatColor =
    report?.threat_level === 'CRITICAL' ? 'var(--critical)' :
    report?.threat_level === 'HIGH' ? 'var(--high)' :
    report?.threat_level === 'MEDIUM' ? 'var(--medium)' : 'var(--low)';

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(5, 7, 10, 0.85)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '24px',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '920px',
        maxHeight: '90vh',
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderRadius: '16px',
        display: 'flex',
        flexDirection: 'column',
        boxShadow: '0 24px 64px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05)',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{
          padding: '20px 24px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(255,255,255,0.02)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '36px', height: '36px', borderRadius: '10px',
              background: 'linear-gradient(135deg, #7c3aed, #58a6ff)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '18px',
            }}>
              🤖
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                  AI Security Analyst Investigation Report
                </h2>
                {report && (
                  <span style={{
                    padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700,
                    background: `${threatColor}20`, border: `1px solid ${threatColor}`, color: threatColor,
                  }}>
                    {report.threat_level} · SCORE {Math.round(report.risk_score)}
                  </span>
                )}
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                Zero-Hallucination Triad: OBSERVED · INFERRED · UNKNOWN
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {report && (
              <button
                onClick={handleCopyJson}
                style={{
                  background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
                  color: 'var(--text-secondary)', padding: '6px 12px', borderRadius: '6px',
                  fontSize: '12px', cursor: 'pointer', transition: 'all 0.2s',
                }}
              >
                {copied ? '✓ Copied JSON' : 'Export JSON'}
              </button>
            )}
            <button
              onClick={onClose}
              aria-label="Close"
              style={{
                background: 'var(--bg-tertiary)', border: '1px solid var(--border)', color: 'var(--text-secondary)',
                fontSize: '12px', fontWeight: 600, cursor: 'pointer', padding: '6px 12px', borderRadius: '6px',
                display: 'flex', alignItems: 'center', gap: '4px',
              }}
            >
              Close ✕
            </button>
          </div>
        </div>

        {/* Content Body */}
        {loading ? (
          <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            <div style={{ fontSize: '28px', marginBottom: '12px', animation: 'spin 1.5s linear infinite' }}>⚙️</div>
            <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>Generating Evidence-Grounded Report…</div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Synthesizing lexical features, network telemetry, and infrastructure graph links
            </div>
          </div>
        ) : report ? (
          <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>
            {/* Executive Summary banner */}
            <div style={{
              padding: '16px 24px',
              background: 'rgba(88, 166, 255, 0.05)',
              borderBottom: '1px solid var(--border)',
              fontSize: '13px',
              lineHeight: 1.5,
              color: 'var(--text-primary)',
            }}>
              <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--accent-blue)', textTransform: 'uppercase', marginBottom: '4px' }}>
                Executive Summary
              </div>
              {report.executive_summary}
            </div>

            {/* Sub-nav tabs */}
            <div style={{
              display: 'flex', gap: '6px', padding: '10px 24px', borderBottom: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
            }}>
              {[
                { id: 'triad', label: 'Evidence Triad (Observed / Inferred / Unknown)' },
                { id: 'actions', label: `Actions (${report.recommended_actions.length})` },
                { id: 'iocs', label: 'Indicators of Compromise (IOCs)' },
                { id: 'raw', label: 'Raw Evidence Payload' },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  style={{
                    padding: '6px 14px', borderRadius: '6px', fontSize: '12px', border: 'none',
                    background: activeTab === tab.id ? 'rgba(88,166,255,0.15)' : 'transparent',
                    color: activeTab === tab.id ? 'var(--accent-blue)' : 'var(--text-secondary)',
                    fontWeight: activeTab === tab.id ? 600 : 400, cursor: 'pointer',
                  }}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Tab Panels */}
            <div style={{ flex: 1, overflow: 'auto', padding: '24px' }}>
              {activeTab === 'triad' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  {/* OBSERVED */}
                  <div style={{
                    border: '1px solid rgba(34, 197, 94, 0.3)', borderRadius: '12px',
                    background: 'rgba(34, 197, 94, 0.03)', overflow: 'hidden',
                  }}>
                    <div style={{
                      padding: '10px 16px', background: 'rgba(34, 197, 94, 0.1)',
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      borderBottom: '1px solid rgba(34, 197, 94, 0.2)',
                    }}>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--low)' }}>
                        ✓ OBSERVED (Verified Ground Truth Log Facts)
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{report.observed.length} entries</span>
                    </div>
                    <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {report.observed.map((obs, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '10px', fontSize: '12px' }}>
                          <span style={{
                            fontSize: '10px', padding: '2px 6px', borderRadius: '4px',
                            background: 'var(--bg-tertiary)', color: 'var(--text-secondary)', textTransform: 'uppercase',
                          }}>
                            {obs.category}
                          </span>
                          <span style={{ flex: 1, color: 'var(--text-primary)' }}>{obs.description}</span>
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                            src: {obs.evidence_source}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* INFERRED */}
                  <div style={{
                    border: '1px solid rgba(245, 158, 11, 0.3)', borderRadius: '12px',
                    background: 'rgba(245, 158, 11, 0.03)', overflow: 'hidden',
                  }}>
                    <div style={{
                      padding: '10px 16px', background: 'rgba(245, 158, 11, 0.1)',
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      borderBottom: '1px solid rgba(245, 158, 11, 0.2)',
                    }}>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--medium)' }}>
                        ▲ INFERRED (Deductive Reasoning & Hypotheses)
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{report.inferred.length} conclusions</span>
                    </div>
                    <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      {report.inferred.map((inf, i) => (
                        <div key={i} style={{ fontSize: '12px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{inf.hypothesis}</span>
                            <span style={{
                              fontSize: '10px', padding: '1px 6px', borderRadius: '4px',
                              background: 'rgba(245, 158, 11, 0.2)', color: 'var(--medium)',
                            }}>
                              {inf.confidence} Confidence
                            </span>
                          </div>
                          <ul style={{ margin: '4px 0 0 16px', padding: 0, color: 'var(--text-secondary)', fontSize: '11px' }}>
                            {inf.supporting_facts.map((f, j) => <li key={j}>{f}</li>)}
                          </ul>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* UNKNOWN */}
                  <div style={{
                    border: '1px solid rgba(139, 148, 158, 0.3)', borderRadius: '12px',
                    background: 'rgba(139, 148, 158, 0.03)', overflow: 'hidden',
                  }}>
                    <div style={{
                      padding: '10px 16px', background: 'rgba(139, 148, 158, 0.1)',
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      borderBottom: '1px solid rgba(139, 148, 158, 0.2)',
                    }}>
                      <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)' }}>
                        ? UNKNOWN (Data Gaps & Inaccessible Information)
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{report.unknown.length} gaps</span>
                    </div>
                    <div style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {report.unknown.map((gap, i) => (
                        <div key={i} style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                          <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{gap.what_is_unknown}: </span>
                          <span>{gap.why_unknown}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'actions' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
                    Recommended automated containment actions based on risk level <strong>{report.threat_level}</strong>:
                  </div>
                  {report.recommended_actions.map((act, i) => (
                    <div key={i} style={{
                      padding: '12px 16px', borderRadius: '8px', background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '12px',
                      fontSize: '13px', color: 'var(--text-primary)',
                    }}>
                      <span style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>#{i + 1}</span>
                      <span>{act}</span>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'iocs' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                      DOMAINS & HOSTNAMES
                    </div>
                    {(report.iocs.domains || []).map((d, i) => (
                      <div key={i} style={{
                        padding: '8px 12px', borderRadius: '6px', background: 'var(--bg-tertiary)',
                        border: '1px solid var(--border)', fontSize: '12px', fontFamily: 'monospace',
                        color: 'var(--text-primary)', marginBottom: '4px',
                      }}>
                        {d}
                      </div>
                    ))}
                  </div>

                  <div>
                    <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '8px' }}>
                      TARGET URL
                    </div>
                    <div style={{
                      padding: '8px 12px', borderRadius: '6px', background: 'var(--bg-tertiary)',
                      border: '1px solid var(--border)', fontSize: '12px', fontFamily: 'monospace',
                      color: 'var(--critical)',
                    }}>
                      {report.target_url}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'raw' && (
                <pre style={{
                  padding: '16px', borderRadius: '8px', background: 'var(--bg-primary)',
                  border: '1px solid var(--border)', fontSize: '11px', fontFamily: 'monospace',
                  color: 'var(--text-secondary)', overflow: 'auto', maxHeight: '450px',
                }}>
                  {JSON.stringify(report, null, 2)}
                </pre>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
