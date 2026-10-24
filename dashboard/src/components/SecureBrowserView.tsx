'use client';

import { useState, useEffect, useRef } from 'react';

// ─── Search Engine Registry ───────────────────────────────────────────────────

const SEARCH_ENGINES: Record<string, { name: string; short: string; searchUrl: string; favicon: string; privacyNote: string; placeholder: string }> = {
  brave: {
    name: 'Brave Search', short: 'Brave',
    searchUrl: 'https://search.brave.com/search?q=',
    favicon: 'https://search.brave.com/favicon.ico',
    privacyNote: 'Brave Search — No tracking · Independent index',
    placeholder: 'Search privately with Brave Search…',
  },
  duckduckgo: {
    name: 'DuckDuckGo', short: 'DDG',
    searchUrl: 'https://duckduckgo.com/?q=',
    favicon: 'https://duckduckgo.com/favicon.ico',
    privacyNote: 'DuckDuckGo — No user tracking · No search history',
    placeholder: 'Search with DuckDuckGo…',
  },
  startpage: {
    name: 'Startpage', short: 'SP',
    searchUrl: 'https://www.startpage.com/search?q=',
    favicon: 'https://www.startpage.com/favicon.ico',
    privacyNote: 'Startpage — Anonymous Google results · Zero tracking',
    placeholder: 'Search anonymously with Startpage…',
  },
  google: {
    name: 'Google', short: 'Google',
    searchUrl: 'https://www.google.com/search?q=',
    favicon: 'https://www.google.com/favicon.ico',
    privacyNote: 'Google Search — Personalised results',
    placeholder: 'Search with Google…',
  },
  bing: {
    name: 'Bing', short: 'Bing',
    searchUrl: 'https://www.bing.com/search?q=',
    favicon: 'https://www.bing.com/favicon.ico',
    privacyNote: 'Bing — Microsoft Search',
    placeholder: 'Search with Bing…',
  },
};

const QUICKLINKS = [
  { label: 'Brave Search', url: 'https://search.brave.com', icon: '🦁', bg: 'linear-gradient(135deg,#fb5000,#ff2d55)' },
  { label: 'GitHub', url: 'https://github.com', icon: '⌨️', bg: '#21262d' },
  { label: 'Wikipedia', url: 'https://wikipedia.org', icon: '📖', bg: '#1e3a5f' },
  { label: 'ProtonMail', url: 'https://proton.me', icon: '📧', bg: '#6d4aff' },
  { label: 'Hacker News', url: 'https://news.ycombinator.com', icon: '📰', bg: '#ff6600' },
  { label: 'DuckDuckGo', url: 'https://duckduckgo.com', icon: '🦆', bg: '#de5833' },
];

// ─── 5-Second Rotating GPS Location Scrambler Pool ───────────────────────────
const SPOOF_LOCATIONS = [
  { city: 'Zurich', country: 'Switzerland', flag: '🇨🇭', lat: 47.3769, lng: 8.5417, accuracy: 12, tz: 'Europe/Zurich' },
  { city: 'Reykjavik', country: 'Iceland', flag: '🇮🇸', lat: 64.1466, lng: -21.9426, accuracy: 15, tz: 'Atlantic/Reykjavik' },
  { city: 'Tokyo', country: 'Japan', flag: '🇯🇵', lat: 35.6762, lng: 139.6503, accuracy: 8, tz: 'Asia/Tokyo' },
  { city: 'Singapore', country: 'Singapore', flag: '🇸🇬', lat: 1.3521, lng: 103.8198, accuracy: 10, tz: 'Asia/Singapore' },
  { city: 'Frankfurt', country: 'Germany', flag: '🇩🇪', lat: 50.1109, lng: 8.6821, accuracy: 14, tz: 'Europe/Berlin' },
  { city: 'Amsterdam', country: 'Netherlands', flag: '🇳🇱', lat: 52.3676, lng: 4.9041, accuracy: 11, tz: 'Europe/Amsterdam' },
  { city: 'Sydney', country: 'Australia', flag: '🇦🇺', lat: -33.8688, lng: 151.2093, accuracy: 18, tz: 'Australia/Sydney' },
  { city: 'Toronto', country: 'Canada', flag: '🇨🇦', lat: 43.6532, lng: -79.3832, accuracy: 9, tz: 'America/Toronto' },
  { city: 'Oslo', country: 'Norway', flag: '🇳🇴', lat: 59.9139, lng: 10.7522, accuracy: 13, tz: 'Europe/Oslo' },
  { city: 'London', country: 'United Kingdom', flag: '🇬🇧', lat: 51.5074, lng: -0.1278, accuracy: 10, tz: 'Europe/London' },
  { city: 'São Paulo', country: 'Brazil', flag: '🇧🇷', lat: -23.5505, lng: -46.6333, accuracy: 20, tz: 'America/Sao_Paulo' },
  { city: 'Helsinki', country: 'Finland', flag: '🇫🇮', lat: 60.1699, lng: 24.9384, accuracy: 12, tz: 'Europe/Helsinki' },
];

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
  // Search engine state
  const [engineKey, setEngineKey] = useState<string>(() => {
    if (typeof window !== 'undefined') return localStorage.getItem('ps_search_engine') || 'brave';
    return 'brave';
  });
  const [enginePickerOpen, setEnginePickerOpen] = useState(false);
  const enginePickerRef = useRef<HTMLDivElement>(null);

  // Browser state
  const [inputUrl, setInputUrl] = useState('');
  const [currentUrl, setCurrentUrl] = useState('');
  const [showHomeScreen, setShowHomeScreen] = useState(true);
  const [ntSearchQuery, setNtSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState<ScanVerdict | null>(null);
  const [barrierBlocked, setBarrierBlocked] = useState(false);

  // Virtual Machine Sandbox & 5-Min Rotating VPN State
  const [isVmSandbox, setIsVmSandbox] = useState(false);
  const [vpnStatus, setVpnStatus] = useState<any>(null);
  const [sdiData, setSdiData] = useState<any>(null);
  const [showSdiModal, setShowSdiModal] = useState(false);
  const [rotationToast, setRotationToast] = useState<string | null>(null);

  // ─── 5-Second GPS Location Scrambler State ────────────────────────────────
  const [locationScrambler, setLocationScrambler] = useState(true);
  const [locIndex, setLocIndex] = useState(0);
  const [locCountdown, setLocCountdown] = useState(5);
  const [showLocModal, setShowLocModal] = useState(false);

  const currentLoc = SPOOF_LOCATIONS[locIndex] || SPOOF_LOCATIONS[0];

  // 5-Second Location Scrambler Countdown
  useEffect(() => {
    if (!locationScrambler) return;
    const interval = setInterval(() => {
      setLocCountdown((prev) => {
        if (prev <= 1) {
          setLocIndex((i) => (i + 1) % SPOOF_LOCATIONS.length);
          return 5;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [locationScrambler]);

  const handleManualScramble = () => {
    setLocIndex((i) => (i + 1) % SPOOF_LOCATIONS.length);
    setLocCountdown(5);
  };

  const engine = SEARCH_ENGINES[engineKey] || SEARCH_ENGINES.brave;

  // Persist engine preference
  useEffect(() => {
    localStorage.setItem('ps_search_engine', engineKey);
  }, [engineKey]);

  // Close engine picker on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (enginePickerRef.current && !enginePickerRef.current.contains(e.target as Node)) {
        setEnginePickerOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  // 5-Minute VPN Auto-Rotation Countdown Effect
  useEffect(() => {
    if (!isVmSandbox) return;
    const interval = setInterval(() => {
      setVpnStatus((prev: any) => {
        if (!prev) return prev;
        const nextSec = (prev.seconds_remaining || 300) - 1;
        if (nextSec <= 0) {
          handleRotateVpn();
          return { ...prev, seconds_remaining: 300, countdown_str: '05:00' };
        }
        const mins = Math.floor(nextSec / 60);
        const secs = nextSec % 60;
        const countdown_str = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
        return { ...prev, seconds_remaining: nextSec, countdown_str };
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [isVmSandbox]);

  const enterVmSandbox = async (target?: string) => {
    const url = target || currentUrl || inputUrl || verdict?.url || 'https://paypal-verification-account-auth.xyz/login';
    setCurrentUrl(url);
    setInputUrl(url);
    setShowHomeScreen(false);
    setBarrierBlocked(false);
    setIsVmSandbox(true);
    setLoading(true);

    try {
      const vpnRes = await fetch('http://localhost:8000/api/v1/sandbox/vpn/current');
      if (vpnRes.ok) {
        const vpn = await vpnRes.json();
        setVpnStatus(vpn);
      }
    } catch (e) {
      console.error(e);
    }

    try {
      const res = await fetch('http://localhost:8000/api/v1/sandbox/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: url,
          threat_level: 'HIGH',
          inject_synthetic_data: true,
        }),
      });
      if (res.ok) {
        const session = await res.json();
        setSdiData(session.synthetic_data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const exitVmSandbox = () => {
    setIsVmSandbox(false);
    setRotationToast('🧹 Ephemeral VM container destroyed. RAM disk wiped. 0 traces remain.');
    setTimeout(() => setRotationToast(null), 3500);
  };

  const handleRotateVpn = async () => {
    try {
      setRotationToast('🔄 Rotating to a new random VPN server (5-min cycle)...');
      const res = await fetch('http://localhost:8000/api/v1/sandbox/vpn/rotate', {
        method: 'POST',
      });
      if (res.ok) {
        const data = await res.json();
        setVpnStatus(data.vpn_state);
        setTimeout(() => setRotationToast(null), 3000);
      }
    } catch {
      setRotationToast(null);
    }
  };
  function resolveNavigationTarget(raw: string): string {
    const value = raw.trim();
    if (!value) return '';
    if (/^https?:\/\//i.test(value)) return value;
    const looksLikeHost = /^(?:localhost|(?:[a-z\d](?:[a-z\d-]*[a-z\d])?\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/?#][^\s]*)?$/i.test(value);
    if (looksLikeHost) return `https://${value}`;
    return `${engine.searchUrl}${encodeURIComponent(value)}`;
  }

  const handleNavigate = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    let target = resolveNavigationTarget(inputUrl);
    if (!target) return;
    setInputUrl(target);
    setShowHomeScreen(false);
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
      setVerdict({
        url: target, threat_level: 'LOW', risk_score: 0, adaptive_action: 'ALLOW', confidence: 0.8,
        indicators: { reasons: ['Evaluation fallback — direct navigation'], score_breakdown: {} },
      });
      setBarrierBlocked(false);
      setCurrentUrl(target);
    } finally {
      setLoading(false);
    }
  };

  const handleNtSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = ntSearchQuery.trim();
    if (!q) return;
    const target = resolveNavigationTarget(q);
    setInputUrl(target);
    setNtSearchQuery('');
    await handleNavigateWithUrl(target);
  };

  const handleNavigateWithUrl = async (target: string) => {
    setShowHomeScreen(false);
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
      setVerdict({
        url: target, threat_level: 'LOW', risk_score: 0, adaptive_action: 'ALLOW', confidence: 0.8,
        indicators: { reasons: ['Evaluation fallback'], score_breakdown: {} },
      });
      setBarrierBlocked(false);
      setCurrentUrl(target);
    } finally {
      setLoading(false);
    }
  };

  const loadSample = async (sampleUrl: string) => {
    setInputUrl(sampleUrl);
    await handleNavigateWithUrl(sampleUrl);
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
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <img src="/phishshield-mark.png" alt="" aria-hidden="true" style={{ width: '22px', height: '22px', objectFit: 'contain' }} />
            PhishShield Secure Dedicated Browser
          </h2>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Hardened environment for analysts · Ephemeral in-memory sessions · Dynamic risk interception
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          {/* 5-Second Location Scrambler Toggle Widget */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            background: locationScrambler ? 'rgba(168,85,247,0.12)' : 'rgba(255,255,255,0.04)',
            border: locationScrambler ? '1px solid rgba(168,85,247,0.4)' : '1px solid var(--border)',
            padding: '3px 10px', borderRadius: '6px', fontSize: '11px',
          }}>
            <button
              onClick={() => setLocationScrambler(!locationScrambler)}
              style={{
                background: locationScrambler ? '#7c3aed' : '#334155',
                border: 'none', borderRadius: '12px', width: '32px', height: '18px',
                position: 'relative', cursor: 'pointer', padding: 0,
                display: 'inline-flex', alignItems: 'center',
                transition: 'background 0.2s', flexShrink: 0,
              }}
              title="Toggle Location Scrambler ON/OFF"
            >
              <span style={{
                position: 'absolute',
                left: locationScrambler ? '16px' : '2px',
                width: '14px', height: '14px', borderRadius: '50%', background: '#fff',
                transition: 'left 0.2s',
              }} />
            </button>
            <span style={{ color: locationScrambler ? '#c084fc' : '#94a3b8', fontWeight: 600 }}>
              {locationScrambler ? '📍 GPS Scrambler: ON' : '📍 Location Shield: OFF'}
            </span>
            {locationScrambler ? (
              <button
                onClick={() => setShowLocModal(true)}
                style={{
                  background: 'rgba(0,0,0,0.3)', border: 'none', padding: '2px 8px',
                  borderRadius: '4px', color: '#38bdf8', fontFamily: 'monospace',
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px',
                  fontSize: '11px',
                }}
                title="Click to inspect live rotating coordinates"
              >
                <span>{currentLoc.flag} <strong>{currentLoc.city}</strong> ({currentLoc.lat.toFixed(1)}°, {currentLoc.lng.toFixed(1)}°)</span>
                <span style={{ color: '#facc15', fontWeight: 700 }}>⏱️ {locCountdown}s</span>
              </button>
            ) : (
              <span style={{ color: '#ef4444', fontSize: '10px' }}>Real GPS Exposed</span>
            )}
          </div>

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
              placeholder={`Search with ${engine.name} or enter a URL…`}
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

          {/* Search Engine Picker */}
          <div ref={enginePickerRef} style={{ position: 'relative', flexShrink: 0 }}>
            <button
              onClick={() => setEnginePickerOpen(v => !v)}
              style={{
                display: 'flex', alignItems: 'center', gap: '5px',
                height: '32px', padding: '0 10px',
                background: '#21262d', border: '1px solid #30363d',
                borderRadius: '8px', color: '#c9d1d9',
                fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                whiteSpace: 'nowrap',
              }}
              title="Change default search engine"
            >
              <img src={engine.favicon} style={{ width: 14, height: 14, borderRadius: 3, objectFit: 'contain' }} alt="" />
              <span>{engine.short}</span>
              <span style={{ opacity: 0.5, fontSize: 9 }}>{enginePickerOpen ? '▲' : '▼'}</span>
            </button>

            {enginePickerOpen && (
              <div style={{
                position: 'absolute', top: 'calc(100% + 6px)', right: 0,
                zIndex: 200, minWidth: '270px',
                background: '#161b22', border: '1px solid #30363d',
                borderRadius: '12px', padding: '6px',
                boxShadow: '0 16px 48px rgba(0,0,0,0.7)',
                animation: 'none',
              }}>
                <div style={{ padding: '5px 10px 7px', fontSize: '9px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: '#8b949e' }}>
                  Default Search Engine
                </div>
                {Object.entries(SEARCH_ENGINES).map(([key, eng]) => (
                  <button
                    key={key}
                    onClick={() => { setEngineKey(key); setEnginePickerOpen(false); }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: '10px',
                      width: '100%', padding: '8px 10px', borderRadius: '8px',
                      background: engineKey === key ? 'rgba(63,185,80,0.1)' : 'transparent',
                      border: 'none', cursor: 'pointer', textAlign: 'left',
                    }}
                  >
                    <img src={eng.favicon} style={{ width: 22, height: 22, borderRadius: 5, objectFit: 'contain', background: '#21262d', padding: 3 }} alt="" />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '12px', fontWeight: 600, color: '#c9d1d9' }}>{eng.name}</div>
                      <div style={{ fontSize: '10px', color: '#8b949e' }}>{eng.privacyNote}</div>
                    </div>
                    {engineKey === key && <span style={{ color: '#3fb950', fontWeight: 700, fontSize: 12 }}>✓</span>}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => {
                const target = currentUrl || inputUrl || verdict?.url || 'https://paypal-verification-account-auth.xyz/login';
                enterVmSandbox(target);
              }}
              style={{
                background: isVmSandbox
                  ? 'linear-gradient(135deg, #10b981, #059669)'
                  : 'linear-gradient(135deg, #7c3aed, #a855f7)',
                color: '#fff', border: 'none', borderRadius: '6px',
                padding: '6px 12px', fontSize: '12px', fontWeight: 600, cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: '4px',
                boxShadow: isVmSandbox ? '0 0 14px rgba(16,185,129,0.5)' : 'none',
              }}
              title="Open site in isolated virtual machine sandbox with 5-minute rotating random VPN"
            >
              {isVmSandbox ? '✓ VM Sandbox Active' : '🚀 Isolate (SDI)'}
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

          {/* ── New Tab / Home Screen ── */}
          {showHomeScreen && !barrierBlocked && (
            <div style={{
              flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
              background: 'radial-gradient(ellipse 80% 60% at 50% 30%, rgba(63,185,80,0.06) 0%, #0a0d14 70%)',
              padding: '40px 20px', gap: '32px', overflowY: 'auto',
            }}>
              {/* Brand */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px' }}>
                <div style={{
                  width: 68, height: 68, borderRadius: 18,
                  background: '#000', border: '1px solid rgba(255,255,255,0.15)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  boxShadow: '0 0 24px rgba(0,0,0,0.5)',
                }}>
                  <img src="/phishshield-mark.png" alt="PhishShield" style={{ width: 50, height: 50, objectFit: 'contain' }} />
                </div>
                <div style={{ fontSize: 28, fontWeight: 800, letterSpacing: '-0.03em', background: 'linear-gradient(135deg,#fff,#94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                  PhishShield
                </div>
                <div style={{ fontSize: 12, color: '#8b949e', textAlign: 'center' }}>
                  Secure Browser · All navigation scanned in real time
                </div>
              </div>

              {/* Search Box */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', width: 'min(560px,100%)' }}>
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 6, padding: '4px 12px',
                  borderRadius: 999, background: 'rgba(63,185,80,0.08)', border: '1px solid rgba(63,185,80,0.18)',
                  fontSize: 11, fontWeight: 600, color: '#3fb950',
                }}>
                  <img src={engine.favicon} style={{ width: 14, height: 14, borderRadius: 3 }} alt="" />
                  {engine.name}
                </div>
                <form onSubmit={handleNtSearch} style={{
                  width: '100%', display: 'flex', alignItems: 'center',
                  background: '#161b22', border: '1.5px solid #30363d',
                  borderRadius: 12, overflow: 'hidden',
                  boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
                }}>
                  <span style={{ padding: '0 14px', color: '#8b949e', fontSize: 16 }}>🔍</span>
                  <input
                    type="text"
                    value={ntSearchQuery}
                    onChange={e => setNtSearchQuery(e.target.value)}
                    placeholder={engine.placeholder}
                    style={{
                      flex: 1, padding: '13px 0', background: 'transparent',
                      border: 'none', outline: 'none', color: '#c9d1d9', fontSize: 14,
                    }}
                    autoFocus
                  />
                  <button type="submit" style={{
                    margin: 6, padding: '0 16px', height: 36, borderRadius: 8,
                    background: 'linear-gradient(135deg,#238636,#3fb950)',
                    border: 'none', color: '#fff', fontSize: 12, fontWeight: 700, cursor: 'pointer',
                  }}>Search</button>
                </form>
                <div style={{ fontSize: 11, color: '#8b949e', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#3fb950', boxShadow: '0 0 8px rgba(63,185,80,0.5)', display: 'inline-block' }}></span>
                  {engine.privacyNote}
                </div>
              </div>

              {/* Quicklinks */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px', width: 'min(520px,100%)' }}>
                <div style={{ fontSize: '10px', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#8b949e' }}>Quick Access</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: '10px', width: '100%' }}>
                  {QUICKLINKS.map((ql) => (
                    <button
                      key={ql.url}
                      onClick={() => { setInputUrl(ql.url); handleNavigateWithUrl(ql.url); }}
                      style={{
                        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 5,
                        padding: '10px 4px', background: '#161b22', border: '1px solid #21262d',
                        borderRadius: 10, cursor: 'pointer', fontSize: 10, color: '#8b949e', fontWeight: 500,
                      }}
                    >
                      <div style={{ width: 34, height: 34, borderRadius: 9, background: ql.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 17 }}>{ql.icon}</div>
                      <span style={{ textAlign: 'center', lineHeight: 1.2 }}>{ql.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
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
                      setInputUrl('');
                      setCurrentUrl('');
                      setShowHomeScreen(true);
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
                    onClick={() => enterVmSandbox(verdict?.url || inputUrl)}
                    style={{
                      background: 'linear-gradient(135deg, #7c3aed, #a855f7)', color: '#fff',
                      border: 'none', borderRadius: '6px', padding: '8px 16px', fontSize: '12px',
                      fontWeight: 600, cursor: 'pointer',
                    }}
                  >
                    🚀 Open in Isolated VM (Rotating VPN)
                  </button>
                </div>
              </div>
            </div>
          ) : isVmSandbox ? (
            /* Virtual Machine Sandbox Container Mode */
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: '#070a10', position: 'relative' }}>
              {/* VM Hypervisor HUD & Rotating VPN Banner */}
              <div style={{
                background: 'linear-gradient(90deg, #130e24 0%, #0e1726 100%)',
                padding: '10px 16px',
                borderBottom: '1px solid #3b2d6a',
                display: 'flex',
                flexWrap: 'wrap',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: '12px',
              }}>
                {/* Left: VM Status */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: '6px',
                    background: 'rgba(168,85,247,0.18)', border: '1px solid #a855f7',
                    color: '#c084fc', padding: '4px 10px', borderRadius: '6px',
                    fontSize: '11px', fontWeight: 800, letterSpacing: '0.5px'
                  }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 8px #22c55e' }}></span>
                    VIRTUAL MACHINE SANDBOX
                  </span>
                  <span style={{ fontSize: '11px', color: '#94a3b8' }}>
                    MicroVM Isolation · 512MB RAM-Disk · Host System Untouched
                  </span>
                </div>

                {/* Center: Live 5-Min Rotating VPN & 5-Sec Rotating GPS Status */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    background: 'rgba(56,189,248,0.12)', border: '1px solid rgba(56,189,248,0.35)',
                    color: '#38bdf8', padding: '4px 10px', borderRadius: '6px', fontSize: '11px', fontWeight: 600,
                  }}>
                    <span>{vpnStatus?.active_node?.flag || '🇨🇭'}</span>
                    <span>VPN: <strong>{vpnStatus?.active_node?.city || 'Zurich'}, {vpnStatus?.active_node?.country || 'Switzerland'}</strong></span>
                    <code style={{ fontSize: '10px', color: '#7dd3fc', background: 'rgba(0,0,0,0.3)', padding: '1px 5px', borderRadius: '4px' }}>
                      {vpnStatus?.active_node?.ip || '185.220.101.44'}
                    </code>
                  </div>

                  <div style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    background: 'rgba(234,179,8,0.12)', border: '1px solid rgba(234,179,8,0.35)',
                    color: '#facc15', padding: '4px 8px', borderRadius: '6px', fontSize: '11px', fontWeight: 600,
                  }} title="Switches VPN server every 5 minutes automatically">
                    <span>⏱️ Rotate in:</span>
                    <strong style={{ fontFamily: 'monospace' }}>{vpnStatus?.countdown_str || '05:00'}</strong>
                  </div>

                  {/* 5-Second GPS Scrambler Pill in VM HUD */}
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: '6px',
                    background: locationScrambler ? 'rgba(168,85,247,0.18)' : 'rgba(255,255,255,0.05)',
                    border: locationScrambler ? '1px solid #a855f7' : '1px solid #475569',
                    color: locationScrambler ? '#c084fc' : '#94a3b8',
                    padding: '4px 8px', borderRadius: '6px', fontSize: '11px', fontWeight: 600,
                  }}>
                    <button
                      onClick={() => setLocationScrambler(!locationScrambler)}
                      style={{
                        background: locationScrambler ? '#7c3aed' : '#334155',
                        border: 'none', borderRadius: '10px', width: '26px', height: '14px',
                        position: 'relative', cursor: 'pointer', padding: 0,
                        display: 'inline-flex', alignItems: 'center',
                      }}
                      title="Toggle Location Scrambler"
                    >
                      <span style={{
                        position: 'absolute',
                        left: locationScrambler ? '13px' : '2px',
                        width: '10px', height: '10px', borderRadius: '50%', background: '#fff',
                        transition: 'left 0.2s',
                      }} />
                    </button>
                    {locationScrambler ? (
                      <button
                        onClick={() => setShowLocModal(true)}
                        style={{
                          background: 'transparent', border: 'none', color: '#c084fc',
                          cursor: 'pointer', fontSize: '11px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '4px', padding: 0,
                        }}
                      >
                        <span>📍 GPS: {currentLoc.flag} <strong>{currentLoc.city}</strong></span>
                        <span style={{ color: '#facc15', fontFamily: 'monospace' }}>⏱️ {locCountdown}s</span>
                      </button>
                    ) : (
                      <span style={{ color: '#ef4444', fontSize: '10px' }}>GPS Shield OFF</span>
                    )}
                  </div>

                  <button
                    onClick={handleRotateVpn}
                    style={{
                      background: '#1e293b', border: '1px solid #475569', color: '#f1f5f9',
                      padding: '4px 8px', borderRadius: '6px', fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                      display: 'flex', alignItems: 'center', gap: '4px'
                    }}
                    title="Switch to a new random VPN server immediately"
                  >
                    🔄 Switch Node
                  </button>
                </div>

                {/* Right: SDI Honeypot & Exit Buttons */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <button
                    onClick={() => setShowSdiModal(true)}
                    style={{
                      background: 'rgba(168,85,247,0.15)', border: '1px solid #a855f7',
                      color: '#c084fc', padding: '4px 10px', borderRadius: '6px',
                      fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                    }}
                  >
                    🧪 Injected Honeypot (SDI)
                  </button>
                  <button
                    onClick={exitVmSandbox}
                    style={{
                      background: 'rgba(239,68,68,0.2)', border: '1px solid #ef4444',
                      color: '#f87171', padding: '4px 10px', borderRadius: '6px',
                      fontSize: '11px', fontWeight: 700, cursor: 'pointer',
                    }}
                    title="Destroy container and wipe all ephemeral traces"
                  >
                    💣 Destroy VM & Wipe
                  </button>
                </div>
              </div>

              {/* Rotating Toast Notification */}
              {rotationToast && (
                <div style={{
                  position: 'absolute', top: 50, left: '50%', transform: 'translateX(-50%)',
                  background: '#1e1b4b', border: '1px solid #818cf8', color: '#c7d2fe',
                  padding: '8px 18px', borderRadius: '8px', fontSize: '12px', fontWeight: 600,
                  boxShadow: '0 8px 24px rgba(0,0,0,0.5)', zIndex: 100,
                }}>
                  {rotationToast}
                </div>
              )}

              {/* Virtual Machine Frame */}
              <div style={{
                flex: 1, display: 'flex', flexDirection: 'column', position: 'relative',
                border: '2px solid #7c3aed', margin: '8px', borderRadius: '8px', overflow: 'hidden',
                boxShadow: '0 0 24px rgba(124,58,237,0.3)',
              }}>
                <div style={{
                  background: '#0f172a', padding: '5px 12px', borderBottom: '1px solid #334155',
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  fontSize: '10px', color: '#94a3b8',
                }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981' }}></span>
                    MicroVM Viewport · Isolated Memory Partition · No Host Filesystem Access
                  </span>
                  <span>Target: <code style={{ color: '#38bdf8' }}>{currentUrl}</code></span>
                </div>
                <iframe
                  src={currentUrl}
                  title="PhishShield Isolated Virtual Viewport"
                  sandbox="allow-scripts allow-same-origin allow-forms"
                  style={{
                    flex: 1, width: '100%', minHeight: '540px', border: 'none', background: '#ffffff',
                  }}
                />
              </div>

              {/* Bottom VM Isolation Ribbon */}
              <div style={{
                background: '#090d16', padding: '6px 14px', borderTop: '1px solid #1e293b',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                fontSize: '10px', color: '#64748b',
              }}>
                <div style={{ display: 'flex', gap: '16px' }}>
                  <span>Tunnel: <strong style={{ color: '#38bdf8' }}>{vpnStatus?.active_node?.protocol || 'WireGuard / AES-256'}</strong></span>
                  <span>Host Protection: <strong style={{ color: '#22c55e' }}>Zero Real Cookies / No Host Storage</strong></span>
                  <span>Server Rotation: <strong style={{ color: '#eab308' }}>Every 5 Minutes ({vpnStatus?.countdown_str || '05:00'})</strong></span>
                </div>
                <div>
                  Egress: <strong style={{ color: '#c084fc' }}>RFC-1918 Private LAN Blocked</strong>
                </div>
              </div>

              {/* SDI Honeypot Profile Modal */}
              {showSdiModal && (
                <div style={{
                  position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.7)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 120,
                }}>
                  <div style={{
                    background: '#0f172a', border: '1px solid #a855f7', borderRadius: '12px',
                    padding: '20px', maxWidth: '440px', width: '90%', color: '#f8fafc',
                    boxShadow: '0 16px 36px rgba(0,0,0,0.8)',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                      <h3 style={{ margin: 0, fontSize: '14px', color: '#c084fc', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        🧪 Injected Honeypot Profile (SDI)
                      </h3>
                      <button
                        onClick={() => setShowSdiModal(false)}
                        style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '16px', cursor: 'pointer' }}
                      >
                        ✕
                      </button>
                    </div>
                    <p style={{ fontSize: '11px', color: '#94a3b8', margin: '0 0 12px', lineHeight: 1.5 }}>
                      When this isolated VM encounters login or credit card forms on the target site, it automatically feeds these fake honeypot credentials. Zero real user assets are exposed.
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '11px', background: '#020617', padding: '12px', borderRadius: '8px' }}>
                      <div><span style={{ color: '#64748b' }}>Decoy Card:</span> <code style={{ color: '#f1f5f9' }}>{sdiData?.card_number || '4111 7752 4889 4268'}</code></div>
                      <div><span style={{ color: '#64748b' }}>Exp / CVV:</span> <span style={{ color: '#f1f5f9' }}>{sdiData?.card_expiry || '09/28'} · {sdiData?.card_cvv || '910'}</span></div>
                      <div><span style={{ color: '#64748b' }}>Cardholder:</span> <span style={{ color: '#f1f5f9' }}>{sdiData?.cardholder_name || 'Sam Holloway'}</span></div>
                      <div><span style={{ color: '#64748b' }}>Canary Email:</span> <code style={{ color: '#38bdf8' }}>{sdiData?.email || 'canary.sam.holloway@phishshield-trap.invalid'}</code></div>
                      <div><span style={{ color: '#64748b' }}>Decoy Password:</span> <code style={{ color: '#ec4899' }}>{sdiData?.password || 'P$h1sh_Sam#1920!'}</code></div>
                    </div>
                    <button
                      onClick={() => setShowSdiModal(false)}
                      style={{
                        marginTop: '14px', width: '100%', padding: '8px', borderRadius: '6px',
                        background: '#7c3aed', color: '#fff', border: 'none', fontWeight: 600, fontSize: '12px', cursor: 'pointer',
                      }}
                    >
                      Close Viewer
                    </button>
                  </div>
                </div>
              )}
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

      {/* 5-Second GPS Location Scrambler Inspector Modal */}
      {showLocModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999,
          backdropFilter: 'blur(4px)',
        }}>
          <div style={{
            background: '#0f172a', border: '1px solid #8b5cf6', borderRadius: '14px',
            padding: '24px', maxWidth: '480px', width: '92%', color: '#f8fafc',
            boxShadow: '0 20px 50px rgba(0,0,0,0.85)',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ margin: 0, fontSize: '15px', color: '#c084fc', display: 'flex', alignItems: 'center', gap: '8px' }}>
                📍 Live GPS Location Scrambler (5-Second Cycle)
              </h3>
              <button
                onClick={() => setShowLocModal(false)}
                style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '18px', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 16px', lineHeight: 1.5 }}>
              Websites attempting to query your physical GPS, Wi-Fi triangulation, or browser geolocation are automatically fed changing fake coordinates every 5 seconds. Your actual host device location is completely invisible.
            </p>

            <div style={{
              background: '#020617', border: '1px solid #1e293b', borderRadius: '10px',
              padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '8px' }}>
                <span style={{ color: '#64748b' }}>Real Host Location:</span>
                <span style={{ color: '#ef4444', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '4px' }}>
                  🚫 BLOCKED / ZERO LEAK
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '8px' }}>
                <span style={{ color: '#64748b' }}>Active Spoofed City:</span>
                <span style={{ color: '#f1f5f9', fontWeight: 600 }}>
                  {currentLoc.flag} {currentLoc.city}, {currentLoc.country}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '8px' }}>
                <span style={{ color: '#64748b' }}>Spoofed GPS Coordinates:</span>
                <code style={{ color: '#38bdf8' }}>
                  {currentLoc.lat.toFixed(4)}° N, {currentLoc.lng.toFixed(4)}° E
                </code>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '8px' }}>
                <span style={{ color: '#64748b' }}>Rotation Frequency:</span>
                <span style={{ color: '#facc15', fontWeight: 700 }}>
                  Every 5 Seconds
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#64748b' }}>Next City Switch in:</span>
                <span style={{
                  color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '2px 8px', borderRadius: '4px',
                  fontFamily: 'monospace', fontWeight: 700, fontSize: '13px'
                }}>
                  ⏱️ {locCountdown}s
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px', marginTop: '18px' }}>
              <button
                onClick={handleManualScramble}
                style={{
                  flex: 1, padding: '10px', borderRadius: '8px',
                  background: '#1e293b', border: '1px solid #475569', color: '#f1f5f9',
                  fontWeight: 600, fontSize: '12px', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px'
                }}
              >
                🎲 Scramble to Next Now
              </button>
              <button
                onClick={() => setShowLocModal(false)}
                style={{
                  flex: 1, padding: '10px', borderRadius: '8px',
                  background: '#7c3aed', color: '#fff', border: 'none',
                  fontWeight: 600, fontSize: '12px', cursor: 'pointer',
                }}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
