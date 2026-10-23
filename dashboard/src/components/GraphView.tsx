'use client';

import { useState, useEffect, useCallback } from 'react';

interface GraphNode {
  id: string;
  label: string;
  type: string;
  properties: Record<string, any>;
}

interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  confidence: 'CONFIRMED' | 'INFERRED';
  properties?: Record<string, any>;
}

interface CampaignCluster {
  cluster_id: string;
  name: string;
  tactic: string;
  target_industry: string;
  risk_score: number;
  first_seen: string;
  url_count: number;
  domains: string[];
  active: boolean;
}

interface GraphViewProps {
  apiBase: string;
}

export default function GraphView({ apiBase }: GraphViewProps) {
  const [queryDomain, setQueryDomain] = useState('chase-bank-verify.xyz');
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignCluster[]>([]);
  const [overview, setOverview] = useState<any>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchOverview = async () => {
    try {
      const res = await fetch(`${apiBase}/graph/overview`);
      if (res.ok) setOverview(await res.json());
    } catch {}
  };

  const fetchCampaigns = async () => {
    try {
      const res = await fetch(`${apiBase}/graph/campaigns`);
      if (res.ok) {
        const d = await res.json();
        setCampaigns(d.campaigns || []);
      }
    } catch {}
  };

  const loadDomainGraph = useCallback(async (domain: string) => {
    if (!domain) return;
    setLoading(true);
    try {
      const res = await fetch(`${apiBase}/graph/domain/${domain}`);
      if (res.ok) {
        const d = await res.json();
        setNodes(d.nodes || []);
        setEdges(d.edges || []);
        if (d.nodes?.length > 0) {
          setSelectedNode(d.nodes[0]);
        }
      }
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  useEffect(() => {
    fetchOverview();
    fetchCampaigns();
    loadDomainGraph('chase-bank-verify.xyz');
  }, [loadDomainGraph]);

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'Campaign': return '#ef4444';
      case 'Domain': return '#38bdf8';
      case 'IP': return '#f59e0b';
      case 'ASN': return '#a855f7';
      case 'Certificate': return '#10b981';
      case 'URL': return '#06b6d4';
      default: return '#94a3b8';
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'Campaign': return '🎯';
      case 'Domain': return '🏢';
      case 'IP': return '💻';
      case 'ASN': return '🌐';
      case 'Certificate': return '🔒';
      case 'URL': return '🔗';
      default: return '◈';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Header card with overview stats */}
      <div style={{
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        borderRadius: '14px', padding: '24px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Neo4j Infrastructure Threat Graph & Campaign Clustering
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '4px 0 0' }}>
              Map threat actor infrastructure: correlate URLs, hosting IPs, bulletproof ASNs, and SSL thumbprints.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <span style={{
              fontSize: '11px', padding: '4px 10px', borderRadius: '6px',
              background: 'rgba(34, 197, 94, 0.15)', color: 'var(--low)',
              border: '1px solid rgba(34, 197, 94, 0.3)', fontWeight: 600,
            }}>
              Solid: CONFIRMED DNS
            </span>
            <span style={{
              fontSize: '11px', padding: '4px 10px', borderRadius: '6px',
              background: 'rgba(239, 68, 68, 0.15)', color: 'var(--critical)',
              border: '1px solid rgba(239, 68, 68, 0.3)', fontWeight: 600,
            }}>
              Dashed: INFERRED Campaign
            </span>
          </div>
        </div>

        {/* Search */}
        <form onSubmit={(e) => { e.preventDefault(); loadDomainGraph(queryDomain); }} style={{ display: 'flex', gap: '12px' }}>
          <input
            type="text"
            value={queryDomain}
            onChange={(e) => setQueryDomain(e.target.value)}
            placeholder="Explore domain infrastructure (e.g. chase-bank-verify.xyz, crypto-login.top)…"
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
              background: 'linear-gradient(135deg, #7c3aed, #0284c7)',
              color: 'white', fontWeight: 600, fontSize: '13px', cursor: 'pointer',
            }}
          >
            {loading ? 'Mapping Graph…' : '🕸️ Explore Infrastructure'}
          </button>
        </form>
      </div>

      {/* Stats overview row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Sub-Graph Nodes</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--accent-blue)', marginTop: '4px' }}>
            {nodes.length}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>Reachable entities</div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Sub-Graph Edges</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
            {edges.length}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>Infrastructure links</div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Identified Campaigns</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--critical)', marginTop: '4px' }}>
            {campaigns.length}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--critical)', marginTop: '4px' }}>● Active Clusters</div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '12px', padding: '16px' }}>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Graph Database</div>
          <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--medium)', marginTop: '4px' }}>
            {overview?.total_nodes || '50+'}
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>Global Neo4j store</div>
        </div>
      </div>

      {/* Main Grid: Visual Graph Canvas (Left) + Node & Campaign Inspector (Right) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '20px' }}>
        {/* Interactive Visual Graph Canvas */}
        <div style={{
          background: 'var(--bg-secondary)', border: '1px solid var(--border)',
          borderRadius: '14px', overflow: 'hidden', minHeight: '520px',
          display: 'flex', flexDirection: 'column', position: 'relative',
        }}>
          <div style={{
            padding: '14px 18px', borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            background: 'rgba(255,255,255,0.02)',
          }}>
            <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Interactive Infrastructure Topology · {queryDomain}
            </span>
            <div style={{ display: 'flex', gap: '12px', fontSize: '11px', color: 'var(--text-muted)' }}>
              <span>Click any node to inspect</span>
            </div>
          </div>

          {/* Graph Visualization Arena */}
          <div style={{
            flex: 1, padding: '24px', display: 'flex', flexWrap: 'wrap',
            alignContent: 'center', justifyContent: 'center', gap: '20px',
            position: 'relative', background: 'radial-gradient(circle at center, rgba(56, 189, 248, 0.03) 0%, transparent 70%)',
          }}>
            {nodes.map((node) => {
              const isSelected = selectedNode?.id === node.id;
              const color = getNodeColor(node.type);
              const icon = getNodeIcon(node.type);

              return (
                <div
                  key={node.id}
                  onClick={() => setSelectedNode(node)}
                  style={{
                    padding: '12px 18px',
                    borderRadius: '12px',
                    background: isSelected ? 'rgba(255,255,255,0.08)' : 'var(--bg-tertiary)',
                    border: isSelected ? `2px solid ${color}` : `1px solid ${color}40`,
                    boxShadow: isSelected ? `0 0 20px ${color}40` : 'none',
                    cursor: 'pointer',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: '6px',
                    minWidth: '130px',
                    maxWidth: '220px',
                    transition: 'all 0.2s',
                  }}
                >
                  <div style={{
                    width: '36px', height: '36px', borderRadius: '50%',
                    background: `${color}20`, border: `1px solid ${color}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '16px',
                  }}>
                    {icon}
                  </div>
                  <span style={{
                    fontSize: '10px', fontWeight: 700, color: color,
                    textTransform: 'uppercase', letterSpacing: '0.5px',
                  }}>
                    {node.type}
                  </span>
                  <span style={{
                    fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)',
                    textAlign: 'center', wordBreak: 'break-all',
                  }}>
                    {node.label}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Relationships Ribbon */}
          <div style={{
            padding: '12px 18px', borderTop: '1px solid var(--border)',
            background: 'var(--bg-primary)', display: 'flex', gap: '10px',
            overflowX: 'auto', fontSize: '11px',
          }}>
            {edges.map((e, i) => (
              <span key={i} style={{
                padding: '3px 8px', borderRadius: '4px',
                background: e.confidence === 'CONFIRMED' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                border: e.confidence === 'CONFIRMED' ? '1px solid rgba(34, 197, 94, 0.3)' : '1px dashed rgba(239, 68, 68, 0.4)',
                color: e.confidence === 'CONFIRMED' ? 'var(--low)' : 'var(--critical)',
                whiteSpace: 'nowrap',
              }}>
                {e.source.split(':')[0]} ➔ {e.relationship} ➔ {e.target.split(':')[0]} ({e.confidence})
              </span>
            ))}
          </div>
        </div>

        {/* Right Panel: Selected Node Inspector & Campaign Clusters */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Node Inspector */}
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: '14px', padding: '20px',
          }}>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '8px' }}>
              Entity Inspector
            </div>
            {selectedNode ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <div style={{
                    width: '32px', height: '32px', borderRadius: '8px',
                    background: `${getNodeColor(selectedNode.type)}20`,
                    border: `1px solid ${getNodeColor(selectedNode.type)}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: '16px',
                  }}>
                    {getNodeIcon(selectedNode.type)}
                  </div>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {selectedNode.label}
                    </div>
                    <div style={{ fontSize: '11px', color: getNodeColor(selectedNode.type), fontWeight: 600 }}>
                      {selectedNode.type} Node
                    </div>
                  </div>
                </div>

                <div style={{
                  padding: '12px', borderRadius: '8px', background: 'var(--bg-tertiary)',
                  fontSize: '11px', fontFamily: 'monospace', color: 'var(--text-secondary)',
                  maxHeight: '180px', overflow: 'auto',
                }}>
                  {JSON.stringify(selectedNode.properties, null, 2)}
                </div>
              </div>
            ) : (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Click a node on the left to inspect its infrastructure attributes.
              </div>
            )}
          </div>

          {/* Campaign Clusters */}
          <div style={{
            background: 'var(--bg-secondary)', border: '1px solid var(--border)',
            borderRadius: '14px', padding: '20px', flex: 1,
            display: 'flex', flexDirection: 'column',
          }}>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '12px' }}>
              Identified Adversarial Campaigns
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', overflow: 'auto' }}>
              {campaigns.map((camp, i) => (
                <div key={i} style={{
                  padding: '12px', borderRadius: '10px', background: 'var(--bg-tertiary)',
                  border: '1px solid var(--border)', fontSize: '12px',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <span style={{ fontWeight: 700, color: 'var(--critical)' }}>{camp.name}</span>
                    <span style={{
                      fontSize: '10px', padding: '1px 5px', borderRadius: '3px',
                      background: 'rgba(239, 68, 68, 0.2)', color: 'var(--critical)', fontWeight: 600,
                    }}>
                      Score {Math.round(camp.risk_score)}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    Tactic: {camp.tactic} · Target: {camp.target_industry}
                  </div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                    Domains: {camp.domains.slice(0, 3).join(', ')}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
