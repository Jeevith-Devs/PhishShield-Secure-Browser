'use client';

import type { ScanRecord, Stats } from '@/app/page';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface ThreatChartProps {
  scans: ScanRecord[];
  stats: Stats | null;
}

const COLORS = {
  LOW:      '#22c55e',
  MEDIUM:   '#f59e0b',
  HIGH:     '#f97316',
  CRITICAL: '#ef4444',
};

export default function ThreatChart({ scans, stats }: ThreatChartProps) {
  const breakdown = stats?.threat_level_breakdown ?? { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  const pieData = Object.entries(breakdown)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }));

  // Build score histogram from last 20 scans
  const recentScans = scans.slice(0, 20).reverse().map((s, i) => ({
    idx: i + 1,
    score: Math.round(s.risk_score),
    level: s.threat_level,
  }));

  const CustomTooltipBar = ({ active, payload }: { active?: boolean; payload?: Array<{payload: typeof recentScans[0], value: number}> }) => {
    if (active && payload && payload.length) {
      const d = payload[0].payload;
      return (
        <div style={{
          background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
          borderRadius: '8px', padding: '10px 14px', fontSize: '12px',
        }}>
          <div style={{ color: COLORS[d.level as keyof typeof COLORS], fontWeight: 700 }}>{d.level}</div>
          <div style={{ color: 'var(--text-secondary)' }}>Score: {d.score}</div>
        </div>
      );
    }
    return null;
  };

  const CustomTooltipPie = ({ active, payload }: { active?: boolean; payload?: Array<{name: string, value: number}> }) => {
    if (active && payload && payload.length) {
      return (
        <div style={{
          background: 'var(--bg-tertiary)', border: '1px solid var(--border)',
          borderRadius: '8px', padding: '10px 14px', fontSize: '12px',
        }}>
          <div style={{ color: COLORS[payload[0].name as keyof typeof COLORS], fontWeight: 700 }}>{payload[0].name}</div>
          <div style={{ color: 'var(--text-secondary)' }}>{payload[0].value} scans</div>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: '1px solid var(--border)',
      borderRadius: '12px',
      padding: '20px',
    }}>
      <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span>📊</span> Threat Distribution &amp; Risk Timeline
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 200px', gap: '24px', alignItems: 'center' }}>
        {/* Bar chart */}
        <div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px' }}>
            Risk Score Timeline (Last 20 Scans)
          </div>
          {recentScans.length === 0 ? (
            <div style={{ height: '140px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
              No scans yet — run a URL analysis
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={140}>
              <BarChart data={recentScans} margin={{ top: 0, right: 0, left: -30, bottom: 0 }}>
                <XAxis dataKey="idx" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltipBar />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                <Bar dataKey="score" radius={[3, 3, 0, 0]} maxBarSize={24}>
                  {recentScans.map((entry, index) => (
                    <Cell key={index} fill={COLORS[entry.level as keyof typeof COLORS]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Pie chart */}
        <div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '12px' }}>
            Threat Breakdown
          </div>
          {pieData.length === 0 ? (
            <div style={{ height: '120px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
              No data
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={120}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={32} outerRadius={52} paddingAngle={3} dataKey="value">
                    {pieData.map((entry, index) => (
                      <Cell key={index} fill={COLORS[entry.name as keyof typeof COLORS]} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltipPie />} />
                </PieChart>
              </ResponsiveContainer>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '8px' }}>
                {pieData.map(({ name, value }) => (
                  <div key={name} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: 'var(--text-secondary)' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: COLORS[name as keyof typeof COLORS], flexShrink: 0 }} />
                    {name} ({value})
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
