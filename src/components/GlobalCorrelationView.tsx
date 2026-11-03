import React, { useState, useEffect } from 'react';
import { 
  Network, 
  AlertTriangle, 
  ShieldAlert, 
  Layers, 
  HelpCircle,
  Loader2,
  RefreshCw
} from 'lucide-react';
import { GraphNode, GraphEdge } from '../types/forensics';
import { GraphView } from './workspace/GraphView';

export const GlobalCorrelationView: React.FC = () => {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [totalEmails, setTotalEmails] = useState(0);
  const [caveat, setCaveat] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  const fetchCorrelation = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/graph/session');
      const data = await res.json();
      setNodes(data.graph?.nodes || []);
      setEdges(data.graph?.edges || []);
      setTotalEmails(data.totalEmailsInSession || 0);
      setCaveat(data.caveat || '');
    } catch (err) {
      console.error('Failed to fetch session correlation:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCorrelation();
  }, []);

  const sharedEdges = edges.filter(e => e.relationshipType === 'SHARES_INFRASTRUCTURE_WITH');

  return (
    <div className="max-w-7xl mx-auto py-6 px-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            <span>Multi-Email Infrastructure Threat Correlation</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Detects shared sending candidate IPs, sender domains, and mail relays across all emails analyzed in this session.
          </p>
        </div>

        <button
          onClick={fetchCorrelation}
          disabled={isLoading}
          className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors flex items-center gap-1.5 self-start"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Correlation</span>
        </button>
      </div>

      {/* Mandatory Campaign Attribution Caveat Card */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <div className="font-semibold text-slate-200">
            Attribution Integrity Notice (Section 12 Compliance)
          </div>
          <p className="text-slate-400 leading-relaxed">
            Infrastructure sharing (e.g. common candidate IP address or mail server) represents exploratory clustering rather than confirmed adversary attribution. Legitimate cloud hosting providers (AWS, Microsoft 365, Google Cloud), email security gateways, and shared CDNs routinely service multiple unrelated tenants.
          </p>
        </div>
      </div>

      {/* Shared Infrastructure Highlights */}
      {sharedEdges.length > 0 && (
        <div className="p-4 bg-rose-950/20 border border-rose-900/50 rounded space-y-2">
          <div className="flex items-center gap-2 text-rose-400 font-semibold text-xs">
            <ShieldAlert className="w-4 h-4" />
            <span>Shared Infrastructure Intersections Detected ({sharedEdges.length})</span>
          </div>
          <div className="space-y-1.5">
            {sharedEdges.map((edge, idx) => (
              <div key={idx} className="p-2.5 bg-slate-950 rounded border border-rose-900/40 text-xs font-mono text-slate-300">
                <span className="text-rose-300 font-bold">[{edge.relationshipType}]</span>{' '}
                <span>{edge.sourceNode} &harr; {edge.targetNode}</span>
                <div className="text-slate-400 font-sans text-[11px] mt-0.5">
                  {edge.supportingObservation}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Interactive Global Graph */}
      {isLoading ? (
        <div className="h-96 flex items-center justify-center border border-slate-800 rounded bg-slate-950">
          <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
        </div>
      ) : totalEmails < 2 ? (
        <div className="p-12 border border-dashed border-slate-800 rounded text-center bg-slate-900/30 space-y-3">
          <Layers className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-sm font-semibold text-slate-200">
            Multi-Email Correlation Requires 2+ Analyses
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            You currently have {totalEmails} email in the session. Ingest another message or load an additional synthetic fixture from the Dashboard to correlate shared candidate IPs and domains.
          </p>
        </div>
      ) : (
        <GraphView
          nodes={nodes}
          edges={edges}
          title={`Session-Wide Infrastructure Graph (${totalEmails} emails)`}
          isGlobal={true}
        />
      )}
    </div>
  );
};
