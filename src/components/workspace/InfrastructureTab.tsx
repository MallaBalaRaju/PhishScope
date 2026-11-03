import React from 'react';
import { 
  Server, 
  Globe, 
  ShieldAlert, 
  Clock, 
  Layers, 
  AlertCircle,
  Database,
  ExternalLink
} from 'lucide-react';
import { EmailAnalysis, InfrastructureObservation } from '../../types/forensics';

interface InfrastructureTabProps {
  analysis: EmailAnalysis;
}

export const InfrastructureTab: React.FC<InfrastructureTabProps> = ({ analysis }) => {
  const { infrastructureFindings, forensicFindings } = analysis;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'available':
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-800 bg-emerald-950/60 text-emerald-300">
            Available
          </span>
        );
      case 'internal_ip_skipped':
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-blue-800 bg-blue-950/60 text-blue-300">
            Internal RFC 1918 Skipped
          </span>
        );
      case 'provider_unconfigured':
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-400">
            Provider Unconfigured
          </span>
        );
      default:
        return (
          <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-amber-800 bg-amber-950/60 text-amber-300">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Safeguards Notice */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <div className="font-semibold text-slate-200">
            Infrastructure Attribution &amp; Geolocation Constraints
          </div>
          <p className="text-slate-400 leading-relaxed">
            Forensic principle: IP address geolocation identifies the data center or hosting provider boundary where the mail relay resides. It does <strong className="text-slate-200">not</strong> identify the physical location of the human adversary. Attackers routinely route phishing through commercial cloud platforms, VPNs, bulletproof relays, and compromised proxy nodes.
          </p>
        </div>
      </div>

      {/* Observations List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
            <Database className="w-4 h-4 text-cyan-400" />
            <span>Infrastructure Intelligence &amp; DNS Records ({infrastructureFindings.length})</span>
          </h3>
          <span className="text-xs font-mono text-slate-400">
            Zero Leaked Content · Safe Resolvers
          </span>
        </div>

        {infrastructureFindings.length === 0 ? (
          <div className="text-xs text-slate-400 italic p-4 bg-slate-950 rounded border border-slate-800">
            No infrastructure queries were recorded for this analysis.
          </div>
        ) : (
          <div className="space-y-3">
            {infrastructureFindings.map((obs: InfrastructureObservation, idx: number) => (
              <div key={idx} className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-mono">
                    <span className="text-xs font-bold text-cyan-300">
                      {obs.entityType.toUpperCase()}: {obs.entity}
                    </span>
                    <span className="text-xs text-slate-500">·</span>
                    <span className="text-xs text-slate-400 font-sans">
                      Provider: {obs.provider}
                    </span>
                  </div>
                  {getStatusBadge(obs.status)}
                </div>

                <div className="p-3 bg-slate-950 rounded border border-slate-850 font-mono text-xs text-slate-300 overflow-x-auto">
                  <pre className="text-[11px] leading-relaxed">
                    {JSON.stringify(obs.observation, null, 2)}
                  </pre>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-1 text-[11px] text-slate-400">
                  <div>
                    <span className="text-slate-500">Source:</span> {obs.sourceReference}
                  </div>
                  <div>
                    <span className="text-slate-500">Limitations:</span> {obs.reliabilityLimitations}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
