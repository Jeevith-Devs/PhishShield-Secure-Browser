'use client';

import { useState, useEffect, useCallback } from 'react';
import Sidebar from '@/components/Sidebar';
import StatCard from '@/components/StatCard';
import ScanFeed from '@/components/ScanFeed';
import LiveScanner from '@/components/LiveScanner';
import ThreatChart from '@/components/ThreatChart';
import RecentFeed from '@/components/RecentFeed';
import SandboxView from '@/components/SandboxView';
import IntelView from '@/components/IntelView';
import GraphView from '@/components/GraphView';
import SecureBrowserView from '@/components/SecureBrowserView';
import AnalystReportModal, { AnalystReportData } from '@/components/AnalystReportModal';

export interface ScanRecord {
  scan_id: string;
  url: string;
  risk_score: number;
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  adaptive_action: string;
  confidence: number;
  indicators: {
    model_used?: string;
    reasons: string[];
    score_breakdown: Record<string, number>;
    features_summary: Record<string, unknown>;
  };
  scan_timestamp: string;
  client_type: string;
}

export interface Stats {
  total_scans: number;
  threat_level_breakdown: Record<string, number>;
  average_risk_score: number;
}

const API = 'http://localhost:8000/api/v1';

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [apiStatus, setApiStatus] = useState<'checking' | 'online' | 'offline'>('checking');
  const [activeSection, setActiveSection] = useState('overview');

  // AI Analyst Modal State
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [currentReport, setCurrentReport] = useState<AnalystReportData | null>(null);
  const [reportLoading, setReportLoading] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [histRes, statsRes, healthRes] = await Promise.all([
        fetch(`${API}/scan/history?limit=50`),
        fetch(`${API}/scan/stats`),
        fetch('http://localhost:8000/health'),
      ]);
      if (healthRes.ok) setApiStatus('online'); else setApiStatus('offline');
      if (histRes.ok) { const d = await histRes.json(); setScans(d.scans || []); }
      if (statsRes.ok) { const d = await statsRes.json(); setStats(d); }
    } catch {
      setApiStatus('offline');
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const handleGenerateReport = async (scanId: string) => {
    setReportModalOpen(true);
    setReportLoading(true);
    try {
      const res = await fetch(`${API}/analyst/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: scanId,
          include_sandbox_telemetry: true,
          include_graph_data: true,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setCurrentReport(data);
      }
    } catch {
      // error handled inside modal
    } finally {
      setReportLoading(false);
    }
  };

  const handleLaunchSandbox = (url: string, threatLevel: string) => {
    setActiveSection('sandbox');
  };

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      <Sidebar active={activeSection} onNavigate={setActiveSection} />
      
      <main style={{ flex: 1, padding: '28px', overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
        {/* Page Top Header */}
        <div style={{ marginBottom: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <h1 style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              {activeSection === 'overview' && 'Security Operations Center'}
              {activeSection === 'scanner' && 'Real-Time Deep Lexical & ML Scanner'}
              {activeSection === 'history' && 'Threat Intelligence Audit Log'}
              {activeSection === 'sandbox' && 'Sandbox Isolation & Synthetic Injection'}
              {activeSection === 'intel' && 'Threat Intelligence Aggregation Feeds'}
              {activeSection === 'graph' && 'Infrastructure Threat Graph & Clusters'}
            </h1>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%',
                background: apiStatus === 'online' ? 'var(--low)' : apiStatus === 'offline' ? 'var(--critical)' : 'var(--medium)',
                boxShadow: apiStatus === 'online' ? '0 0 8px var(--low)' : '0 0 8px var(--critical)',
              }} />
              <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                API {apiStatus === 'checking' ? 'Connecting…' : apiStatus === 'online' ? 'Online' : 'Offline'}
              </span>
              <button
                onClick={fetchData}
                style={{
                  background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
                  color: 'var(--text-secondary)', padding: '5px 12px',
                  borderRadius: '6px', cursor: 'pointer', fontSize: '12px',
                  transition: 'all 0.2s',
                }}
              >
                ↺ Refresh
              </button>
            </div>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: 0 }}>
            PhishShield Enterprise Defense · DETECT. ADAPT. ISOLATE. EXPLAIN.
          </p>
        </div>

        {/* Section View Routing */}
        {activeSection === 'overview' && (
          <>
            {/* Stat Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
              <StatCard
                label="Total Scans"
                value={stats?.total_scans ?? 0}
                icon="🔍"
                color="var(--accent-blue)"
              />
              <StatCard
                label="Critical Threats"
                value={stats?.threat_level_breakdown?.CRITICAL ?? 0}
                icon="🛑"
                color="var(--critical)"
                highlight
              />
              <StatCard
                label="High Risk"
                value={stats?.threat_level_breakdown?.HIGH ?? 0}
                icon="🚨"
                color="var(--high)"
              />
              <StatCard
                label="Avg Risk Score"
                value={stats ? `${stats.average_risk_score.toFixed(1)}` : '—'}
                icon="📊"
                color="var(--medium)"
              />
            </div>

            {/* Main grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '20px', marginBottom: '20px' }}>
              <ThreatChart scans={scans} stats={stats} />
              <LiveScanner apiBase={API} onNewScan={(s) => setScans(prev => [s, ...prev.slice(0, 49)])} />
            </div>

            {/* Scan feed with AI report trigger */}
            <ScanFeed
              scans={scans}
              onGenerateReport={handleGenerateReport}
              onLaunchSandbox={handleLaunchSandbox}
            />

            {/* Threat intel feed */}
            <div style={{ marginTop: '20px' }}>
              <RecentFeed apiBase={API} />
            </div>
          </>
        )}

        {activeSection === 'browser' && (
          <SecureBrowserView
            onOpenReport={handleGenerateReport}
            onOpenSandbox={handleLaunchSandbox}
          />
        )}

        {activeSection === 'scanner' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ maxWidth: '800px', width: '100%' }}>
              <LiveScanner apiBase={API} onNewScan={(s) => setScans(prev => [s, ...prev.slice(0, 49)])} />
            </div>
            <ScanFeed
              scans={scans}
              onGenerateReport={handleGenerateReport}
              onLaunchSandbox={handleLaunchSandbox}
            />
          </div>
        )}

        {activeSection === 'history' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <ScanFeed
              scans={scans}
              onGenerateReport={handleGenerateReport}
              onLaunchSandbox={handleLaunchSandbox}
            />
          </div>
        )}

        {activeSection === 'sandbox' && (
          <SandboxView apiBase={API} />
        )}

        {activeSection === 'intel' && (
          <IntelView apiBase={API} />
        )}

        {activeSection === 'graph' && (
          <GraphView apiBase={API} />
        )}

        {/* Global AI Security Analyst Modal */}
        {reportModalOpen && (
          <AnalystReportModal
            report={currentReport}
            loading={reportLoading}
            onClose={() => {
              setReportModalOpen(false);
              setCurrentReport(null);
            }}
          />
        )}
      </main>
    </div>
  );
}
