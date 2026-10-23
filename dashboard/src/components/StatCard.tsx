'use client';

interface StatCardProps {
  label: string;
  value: number | string;
  icon: string;
  color: string;
  highlight?: boolean;
}

export default function StatCard({ label, value, icon, color, highlight }: StatCardProps) {
  return (
    <div style={{
      background: 'var(--bg-secondary)',
      border: `1px solid ${highlight ? color : 'var(--border)'}`,
      borderRadius: '12px',
      padding: '18px 20px',
      position: 'relative',
      overflow: 'hidden',
      transition: 'all 0.2s',
      boxShadow: highlight ? `0 0 16px ${color}25` : 'none',
    }}>
      {/* Background glow */}
      {highlight && (
        <div style={{
          position: 'absolute', top: '-20px', right: '-20px',
          width: '80px', height: '80px',
          borderRadius: '50%',
          background: color,
          opacity: 0.06,
          pointerEvents: 'none',
        }} />
      )}

      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '12px' }}>
        <div style={{
          fontSize: '20px',
          width: '38px', height: '38px',
          background: `${color}18`,
          borderRadius: '10px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          {icon}
        </div>
      </div>

      <div style={{ fontSize: '28px', fontWeight: 800, color: color, lineHeight: 1, marginBottom: '4px' }}>
        {value}
      </div>
      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 500 }}>
        {label}
      </div>
    </div>
  );
}
