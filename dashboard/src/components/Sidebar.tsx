'use client';

interface SidebarProps {
  active: string;
  onNavigate: (section: string) => void;
}

const NAV_ITEMS = [
  { id: 'overview', icon: '◈', label: 'Overview' },
  { id: 'browser', icon: '🛡️', label: 'Secure Browser' },
  { id: 'scanner', icon: '⬡', label: 'Live Scanner' },
  { id: 'history', icon: '⊞', label: 'Scan History' },
  { id: 'sandbox', icon: '⬡', label: 'Sandbox Sessions' },
  { id: 'intel', icon: '◇', label: 'Threat Intel' },
  { id: 'graph', icon: '⬡', label: 'Infrastructure Graph' },
];

export default function Sidebar({ active, onNavigate }: SidebarProps) {
  return (
    <aside style={{
      width: '220px',
      minHeight: '100vh',
      background: 'var(--bg-secondary)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      padding: '0',
      position: 'sticky',
      top: 0,
      alignSelf: 'flex-start',
      height: '100vh',
    }}>
      {/* Logo */}
      <div style={{
        padding: '20px 18px 16px',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
          <div style={{
            width: '32px', height: '32px',
            background: 'linear-gradient(135deg, #58a6ff, #7c3aed)',
            borderRadius: '8px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '14px', fontWeight: 800, color: 'white',
            flexShrink: 0,
          }}>
            PS
          </div>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.2 }}>
              PhishShield
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>SOC Dashboard</div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, padding: '12px 10px' }}>
        <div style={{ fontSize: '10px', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.8px', padding: '6px 8px', marginBottom: '4px', textTransform: 'uppercase' }}>
          Navigation
        </div>
        {NAV_ITEMS.map((item) => {
          const isActive = active === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              style={{
                width: '100%', textAlign: 'left',
                display: 'flex', alignItems: 'center', gap: '10px',
                padding: '9px 10px',
                borderRadius: '8px',
                border: 'none',
                background: isActive ? 'rgba(88,166,255,0.1)' : 'transparent',
                color: isActive ? 'var(--accent-blue)' : 'var(--text-secondary)',
                fontSize: '13px', fontWeight: isActive ? 600 : 400,
                cursor: 'pointer',
                transition: 'all 0.15s',
                marginBottom: '2px',
                borderLeft: isActive ? '2px solid var(--accent-blue)' : '2px solid transparent',
              }}
            >
              <span style={{ fontSize: '14px' }}>{item.icon}</span>
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* Footer status */}
      <div style={{
        padding: '14px 18px',
        borderTop: '1px solid var(--border)',
        fontSize: '10px',
        color: 'var(--text-muted)',
      }}>
        <div style={{ marginBottom: '4px', fontWeight: 600, color: 'var(--text-secondary)' }}>PhishShield v1.0.0</div>
        <div>Sprint 2 · MVP Release</div>
        <div style={{ marginTop: '4px', opacity: 0.7 }}>DETECT. ADAPT. ISOLATE.</div>
      </div>
    </aside>
  );
}
