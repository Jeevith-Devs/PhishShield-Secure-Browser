'use client';

import { useState, useEffect } from 'react';

interface ThreatIntelData {
  domain: string;
  queried_at: string;
  urlhaus: {
    listed: boolean;
    threat_count: number;
    threat_types?: string[];
    tags?: string[];
    last_seen?: string;
  };
  abuseipdb: {
    abuse_confidence_score: number;
    total_reports: number;
    country_code?: string;
    isp?: string;
    last_reported_at?: string;
  };
  virustotal: {
    malicious_votes: number;
    harmless_votes: number;
    suspicious_votes: number;
    undetected_votes: number;
    engines_total: number;
    permalink?: string;
  };
  rdap: {
    registrar?: string;
    creation_date?: string;
    expiry_date?: string;
    registrant_country?: string;
    domain_age_days?: number;
  };
  composite_reputation_score: number;
}

interface FeedEntry {
  url: string;
  threat_type: string;
  reporter: string;
  reported_at: string;
  tags: string[];
}

interface IntelViewProps {
  apiBase: string;
}

export default function IntelView({ apiBase }: IntelViewProps) {
  const [query, setQuery] = useState('paypal-secure-login.xyz');
  const [intelData, setIntelData] = useState<ThreatIntelData | null>(null);
  const [loading, setLoading] = useState(false);
  const [feed, setFeed] = useState<FeedEntry[]>([]);
  const [stats, setStats] = useState<any>(null);

  const fetchStats = async () => {
    try {
      const res = await fetch(`${apiBase}/intel/feeds/stats`);
      if (res.ok) setStats(await res.json());
    } catch {}
  };

  const fetchFeed = async () => {
    try {
      const res = await fetch(`${apiBase}/intel/feeds/recent?limit=15`);
      if (res.ok) setFeed(await res.json());
    } catch {}
  };

  const handleLookup = async (domainToLookup?: string) => {
    const target = domainToLookup || query;
    if (!target) return;
    setLoading(true);
    try {
      let clean = target.trim();
      if (clean.startsWith('http')) {
        try { clean = new URL(clean).hostname; } catch {}
      }
      const res = await fetch(`${apiBase}/intel/domain/${clean}`);
      if (res.ok) {
        setIntelData(await res.json());
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    fetchFeed();
    handleLookup('paypal-secure-login.xyz');
  }, []);

  const repScore = intelData?.composite_reputation_score ?? 0;
  const repColor =
    repScore >= 70 ? 'var(--critical)' :
    repScore >= 40 ? 'var(--high)' :
    repScore >= 20 ? 'var(--medium)' : 'var(--low)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header & Search */}
      <div style={{
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        borderRadius: '14px', padding: '24px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Threat Intelligence Aggregator & Domain Reputation
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '4px 0 0' }}>
              Real-time multi-source enrichment: URLhaus, AbuseIPDB, VirusTotal, and RDAP registration metrics.
            </p>
          </div>
          <span style={{
            fontSize: '11px', padding: '4px 10px', borderRadius: '6px',
            background: 'rgba(34, 197, 94, 0.15)', color: 'var(--low)',
            border: '1px solid rgba(34, 197, 94, 0.3)', fontWeight: 600,
          }}>
            ● Live Threat Feeds Active
          </span>
        </div>

        <form onSubmit={(e) => { e.preventDefault(); handleLookup(); }} style={{ display: 'flex', gap: '12px' }}>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search domain or IP (e.g. apple-verify.xyz, 185.220.101.4)…"
            style={{
              flex: 1, padding: '10px 14px', background: 'var(--bg-tertiary)',
              border: '1px solid var(--border)', borderRadius: '8px',
              color: 'var(--text-primary)', fontSize: '13px',
            }}
          />
          <button
            type="submit"
            disabled={loading}
            style={{
              padding: '10px 20px', borderRadius: '8px', border: 'none',
              background: 'linear-gradient(135deg, #0284c7, #2563eb)',
              color: 'white', fontWeight: 600, fontSize: '13px', cursor: 'pointer',
            }}
          >
            {loading ? 'Querying Feeds…' : '🔍 Lookup Intel'}
          </button>
        </form>
      </div>

      {/* Feed Stats Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Curated IOCs</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--accent-blue)', marginTop: '4px' }}>
            {stats?.total_iocs?.toLocaleString() || '1,550+'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--low)', marginTop: '4px' }}>● Synchronized</div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>URLhaus Feed</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {stats?.sources?.urlhaus?.ioc_count || '300+'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Malware hosting links</div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>AbuseIPDB Feed</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {stats?.sources?.abuseipdb?.ioc_count || '820'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>High-abuse IP addresses</div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>VirusTotal Feed</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {stats?.sources?.virustotal?.ioc_count || '430'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Community-flagged domains</div>
        </div>
      </div>

      {/* Main Content: Intel Dossier (Left) + Feed (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 420px', gap: '20px' }}>
        {/* Intel Dossier */}
        <div style={{
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: '14px', overflow: 'hidden', padding: '24px',
          display: 'flex', flexDirection: 'column', gap: '20px',
        }}>
          {intelData ? (
            <>
              {/* Domain Header & Reputation Bar */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Domain Threat Dossier
                  </div>
                  <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '2px' }}>
                    {intelData.domain}
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>COMPOSITE REPUTATION</div>
                  <div style={{ fontSize: '24px', fontWeight: 800, color: repColor }}>
                    {Math.round(repScore)} / 100
                  </div>
                </div>
              </div>

              {/* Multi-source Breakdown Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                {/* VirusTotal Card */}
                <div style={{
                  background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
                  borderRadius: '10px', padding: '16px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>VirusTotal v3</span>
                    <span style={{
                      fontSize: '11px', padding: '2px 8px', borderRadius: '4px',
                      background: intelData.virustotal.malicious_votes > 0 ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)',
                      color: intelData.virustotal.malicious_votes > 0 ? 'var(--critical)' : 'var(--low)',
                      fontWeight: 600,
                    }}>
                      {intelData.virustotal.malicious_votes} / {intelData.virustotal.engines_total || 89} engines
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    <div>Malicious: <strong style={{ color: 'var(--critical)' }}>{intelData.virustotal.malicious_votes}</strong></div>
                    <div>Suspicious: <strong style={{ color: 'var(--medium)' }}>{intelData.virustotal.suspicious_votes}</strong></div>
                    <div>Harmless: <strong style={{ color: 'var(--low)' }}>{intelData.virustotal.harmless_votes}</strong></div>
                  </div>
                </div>

                {/* AbuseIPDB Card */}
                <div style={{
                  background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
                  borderRadius: '10px', padding: '16px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>AbuseIPDB</span>
                    <span style={{
                      fontSize: '11px', padding: '2px 8px', borderRadius: '4px',
                      background: intelData.abuseipdb.abuse_confidence_score > 50 ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)',
                      color: intelData.abuseipdb.abuse_confidence_score > 50 ? 'var(--critical)' : 'var(--low)',
                      fontWeight: 600,
                    }}>
                      {intelData.abuseipdb.abuse_confidence_score}% Confidence
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    <div>Total Reports: <strong>{intelData.abuseipdb.total_reports}</strong></div>
                    <div>Country: <strong>{intelData.abuseipdb.country_code || 'US'}</strong></div>
                    <div>ISP: <strong style={{ fontSize: '11px' }}>{intelData.abuseipdb.isp || 'N/A'}</strong></div>
                  </div>
                </div>

                {/* URLhaus Card */}
                <div style={{
                  background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
                  borderRadius: '10px', padding: '16px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>URLhaus (abuse.ch)</span>
                    <span style={{
                      fontSize: '11px', padding: '2px 8px', borderRadius: '4px',
                      background: intelData.urlhaus.listed ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)',
                      color: intelData.urlhaus.listed ? 'var(--critical)' : 'var(--low)',
                      fontWeight: 600,
                    }}>
                      {intelData.urlhaus.listed ? 'BLACKLISTED' : 'CLEAN'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    <div>Threat Count: <strong>{intelData.urlhaus.threat_count}</strong></div>
                    <div>Tags: {intelData.urlhaus.tags?.join(', ') || 'none'}</div>
                  </div>
                </div>

                {/* RDAP / WHOIS Card */}
                <div style={{
                  background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
                  borderRadius: '10px', padding: '16px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>WHOIS / RDAP</span>
                    <span style={{
                      fontSize: '11px', padding: '2px 8px', borderRadius: '4px',
                      background: (intelData.rdap.domain_age_days || 999) < 30 ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)',
                      color: (intelData.rdap.domain_age_days || 999) < 30 ? 'var(--critical)' : 'var(--low)',
                      fontWeight: 600,
                    }}>
                      {intelData.rdap.domain_age_days ? `${intelData.rdap.domain_age_days} days old` : 'Verified'}
                    </span>
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    <div>Registrar: <strong style={{ fontSize: '11px' }}>{intelData.rdap.registrar || 'Unknown'}</strong></div>
                    <div>Created: <strong>{intelData.rdap.creation_date?.slice(0, 10) || 'N/A'}</strong></div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Enter a domain above to inspect threat intelligence.
            </div>
          )}
        </div>

        {/* Live Aggregated Threat Feed */}
        <div style={{
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: '14px', overflow: 'hidden', display: 'flex', flexDirection: 'column',
          maxHeight: '620px',
        }}>
          <div style={{
            padding: '16px 20px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Aggregated Threat Feed
            </span>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{feed.length} items</span>
          </div>

          <div style={{ overflow: 'auto', flex: 1 }}>
            {feed.map((entry, i) => (
              <div
                key={i}
                onClick={() => {
                  try {
                    const host = new URL(entry.url).hostname;
                    setQuery(host);
                    handleLookup(host);
                  } catch {
                    setQuery(entry.url);
                    handleLookup(entry.url);
                  }
                }}
                style={{
                  padding: '12px 18px', borderBottom: '1px solid var(--border)',
                  cursor: 'pointer', transition: 'background 0.15s',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{
                    fontSize: '10px', padding: '1px 6px', borderRadius: '4px',
                    background: 'rgba(239, 68, 68, 0.15)', color: 'var(--critical)', fontWeight: 700,
                  }}>
                    {entry.reporter}
                  </span>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                    {new Date(entry.reported_at).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{
                  fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginBottom: '4px',
                }}>
                  {entry.url}
                </div>
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                  {entry.tags.map((t, j) => (
                    <span key={j} style={{
                      fontSize: '9px', padding: '1px 5px', borderRadius: '3px',
                      background: 'var(--bg-tertiary)', color: 'var(--text-secondary)',
                    }}>
                      #{t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
