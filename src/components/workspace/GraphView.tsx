import React, { useState, useMemo } from 'react';
import { 
  Network, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  Info, 
  Layers,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { GraphNode, GraphEdge } from '../../types/forensics';

interface GraphViewProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  title?: string;
  isGlobal?: boolean;
}

export const GraphView: React.FC<GraphViewProps> = ({
  nodes,
  edges,
  title = 'Email Infrastructure Relationship Graph',
  isGlobal = false
}) => {
  const [zoom, setZoom] = useState(1);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);

  // Layout node positions in a clean radial or layered distribution
  const layout = useMemo(() => {
    const width = 800;
    const height = 500;
    const centerX = width / 2;
    const centerY = height / 2;

    const positions = new Map<string, { x: number; y: number }>();

    if (nodes.length === 0) return { positions, width, height };

    // Group nodes by type
    const rootNodes = nodes.filter(n => n.type === 'email');
    const senderNodes = nodes.filter(n => n.type === 'sender_address' || n.type === 'sender_domain');
    const ipNodes = nodes.filter(n => n.type === 'candidate_source_ip' || n.type === 'mail_server');
    const urlNodes = nodes.filter(n => n.type === 'url' || n.type === 'related_domain');
    const otherNodes = nodes.filter(n => 
      n.type !== 'email' && 
      n.type !== 'sender_address' && 
      n.type !== 'sender_domain' && 
      n.type !== 'candidate_source_ip' && 
      n.type !== 'mail_server' && 
      n.type !== 'url' && 
      n.type !== 'related_domain'
    );

    // Root node(s) in center
    rootNodes.forEach((node, i) => {
      const offsetX = rootNodes.length > 1 ? (i - (rootNodes.length - 1) / 2) * 160 : 0;
      positions.set(node.id, { x: centerX + offsetX, y: centerY });
    });

    // Sender nodes positioned top-left / top
    senderNodes.forEach((node, i) => {
      const angle = (Math.PI * 0.75) + (i / Math.max(1, senderNodes.length)) * (Math.PI * 0.5);
      const radius = 180;
      positions.set(node.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY - Math.sin(angle) * radius
      });
    });

    // IP and server nodes positioned right
    ipNodes.forEach((node, i) => {
      const angle = -(Math.PI * 0.3) + (i / Math.max(1, ipNodes.length)) * (Math.PI * 0.6);
      const radius = 220;
      positions.set(node.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius
      });
    });

    // URL nodes positioned bottom-left
    urlNodes.forEach((node, i) => {
      const angle = (Math.PI * 1.1) + (i / Math.max(1, urlNodes.length)) * (Math.PI * 0.5);
      const radius = 200;
      positions.set(node.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY - Math.sin(angle) * radius
      });
    });

    // Any remaining nodes in circle
    otherNodes.forEach((node, i) => {
      const angle = (i / Math.max(1, otherNodes.length)) * (2 * Math.PI);
      const radius = 240;
      positions.set(node.id, {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius
      });
    });

    return { positions, width, height };
  }, [nodes]);

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'email':
        return '#38bdf8'; // Sky blue
      case 'sender_address':
      case 'sender_domain':
        return '#a78bfa'; // Purple
      case 'candidate_source_ip':
        return '#f87171'; // Red / Coral
      case 'mail_server':
        return '#fbbf24'; // Amber
      case 'url':
      case 'related_domain':
        return '#34d399'; // Emerald
      default:
        return '#94a3b8'; // Slate
    }
  };

  const getEdgeStyle = (edge: GraphEdge) => {
    if (edge.relationshipType === 'SHARES_INFRASTRUCTURE_WITH') {
      return { stroke: '#f43f5e', strokeDasharray: '4 4', strokeWidth: 2.5 };
    }
    if (edge.confidence === 'hypothesized') {
      return { stroke: '#94a3b8', strokeDasharray: '3 3', strokeWidth: 1.5 };
    }
    if (edge.confidence === 'derived') {
      return { stroke: '#38bdf8', strokeDasharray: 'none', strokeWidth: 1.8 };
    }
    return { stroke: '#64748b', strokeDasharray: 'none', strokeWidth: 1.5 };
  };

  return (
    <div className="space-y-4">
      {/* Controls & Legend Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-900 border border-slate-800 rounded">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold text-slate-200">{title}</span>
          <span className="text-xs font-mono text-slate-400">
            ({nodes.length} nodes · {edges.length} edges)
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setZoom(prev => Math.min(2, prev + 0.2))}
            className="p-1.5 text-slate-400 hover:text-slate-100 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoom(prev => Math.max(0.5, prev - 0.2))}
            className="p-1.5 text-slate-400 hover:text-slate-100 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => { setZoom(1); setSelectedNode(null); setSelectedEdge(null); }}
            className="p-1.5 text-slate-400 hover:text-slate-100 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
            title="Reset View"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Canvas Viewport */}
      <div className="relative border border-slate-800 rounded bg-slate-950 overflow-hidden h-[500px]">
        {nodes.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500 italic">
            No graph relationships available.
          </div>
        ) : (
          <svg
            className="w-full h-full cursor-grab active:cursor-grabbing"
            viewBox={`0 0 ${layout.width} ${layout.height}`}
          >
            <g transform={`scale(${zoom}) translate(${(layout.width * (1 - zoom)) / 2}, ${(layout.height * (1 - zoom)) / 2})`}>
              {/* Render Edges */}
              {edges.map((edge) => {
                const src = layout.positions.get(edge.sourceNode);
                const tgt = layout.positions.get(edge.targetNode);
                if (!src || !tgt) return null;

                const style = getEdgeStyle(edge);
                const isSelected = selectedEdge?.id === edge.id;

                return (
                  <g key={edge.id} className="cursor-pointer" onClick={() => { setSelectedEdge(edge); setSelectedNode(null); }}>
                    <line
                      x1={src.x}
                      y1={src.y}
                      x2={tgt.x}
                      y2={tgt.y}
                      stroke={isSelected ? '#38bdf8' : style.stroke}
                      strokeWidth={isSelected ? style.strokeWidth + 1.5 : style.strokeWidth}
                      strokeDasharray={style.strokeDasharray}
                      className="transition-colors hover:stroke-cyan-300"
                    />
                    {/* Edge Label on hover / mid point */}
                    <text
                      x={(src.x + tgt.x) / 2}
                      y={(src.y + tgt.y) / 2 - 4}
                      fill="#64748b"
                      fontSize="9"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="pointer-events-none select-none"
                    >
                      {edge.relationshipType}
                    </text>
                  </g>
                );
              })}

              {/* Render Nodes */}
              {nodes.map((node) => {
                const pos = layout.positions.get(node.id);
                if (!pos) return null;

                const color = getNodeColor(node.type);
                const isSelected = selectedNode?.id === node.id;
                const radius = node.type === 'email' ? 14 : 10;

                return (
                  <g
                    key={node.id}
                    className="cursor-pointer"
                    onClick={() => { setSelectedNode(node); setSelectedEdge(null); }}
                  >
                    {/* Focus Ring */}
                    {isSelected && (
                      <circle
                        cx={pos.x}
                        cy={pos.y}
                        r={radius + 5}
                        fill="none"
                        stroke="#38bdf8"
                        strokeWidth="2"
                        className="animate-pulse"
                      />
                    )}

                    {/* Node Circle */}
                    <circle
                      cx={pos.x}
                      cy={pos.y}
                      r={radius}
                      fill={color}
                      stroke="#0f172a"
                      strokeWidth="2"
                      className="hover:scale-110 transition-transform"
                    />

                    {/* Node Label */}
                    <text
                      x={pos.x}
                      y={pos.y + radius + 12}
                      fill="#e2e8f0"
                      fontSize="10"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="pointer-events-none select-none"
                    >
                      {node.label}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>
        )}

        {/* Legend Overlay */}
        <div className="absolute bottom-3 left-3 bg-slate-900/90 border border-slate-800 p-2.5 rounded text-[10px] space-y-1 font-mono backdrop-blur-sm pointer-events-none">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
            <span className="text-slate-300">Email Root</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400" />
            <span className="text-slate-300">Sender Entity</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-400" />
            <span className="text-slate-300">Candidate IP</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-400" />
            <span className="text-slate-300">Mail Server</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
            <span className="text-slate-300">Extracted URL</span>
          </div>
        </div>
      </div>

      {/* Node / Edge Details Inspector Panel */}
      {selectedNode && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <div className="font-semibold text-slate-200 flex items-center gap-2">
              <Info className="w-4 h-4 text-cyan-400" />
              <span>Node Inspector: {selectedNode.label}</span>
            </div>
            <span className="font-mono text-cyan-400 uppercase text-[11px]">
              {selectedNode.type}
            </span>
          </div>
          <div className="text-slate-400 font-mono">ID: {selectedNode.id}</div>
          {selectedNode.evidenceReferences && (
            <div className="text-slate-300">
              <span className="text-slate-500">Supporting Evidence:</span>{' '}
              {selectedNode.evidenceReferences.join(', ')}
            </div>
          )}
        </div>
      )}

      {selectedEdge && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <div className="font-semibold text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>Relationship Edge Inspector: {selectedEdge.relationshipType}</span>
            </div>
            <span className="font-mono text-purple-400 uppercase text-[11px]">
              Confidence: {selectedEdge.confidence}
            </span>
          </div>
          <div className="text-slate-400 font-mono">
            {selectedEdge.sourceNode} &rarr; {selectedEdge.targetNode}
          </div>
          {selectedEdge.supportingObservation && (
            <p className="text-slate-300 leading-relaxed">
              {selectedEdge.supportingObservation}
            </p>
          )}
        </div>
      )}
    </div>
  );
};
