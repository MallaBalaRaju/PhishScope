import React, { useState } from 'react';
import { 
  ArrowDown, 
  AlertTriangle, 
  ShieldCheck, 
  Globe, 
  Lock, 
  Terminal,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { EmailAnalysis, ReceivedHop } from '../../types/forensics';

interface HeaderForensicsTabProps {
  analysis: EmailAnalysis;
}

export const HeaderForensicsTab: React.FC<HeaderForensicsTabProps> = ({ analysis }) => {
  const { forensicFindings, envelope, rawHeaders } = analysis;
  const [showRawHeaders, setShowRawHeaders] = useState(false);

  const getIpTypeBadge = (type: string) => {
    switch (type) {
      case 'public':
        return (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-emerald-800 bg-emerald-950/40 text-emerald-300">
            Public IP
          </span>
        );
      case 'private':
        return (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-blue-800 bg-blue-950/40 text-blue-300">
            RFC 1918 Private
          </span>
        );
      case 'loopback':
        return (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-purple-800 bg-purple-950/40 text-purple-300">
            Loopback
          </span>
        );
      default:
        return (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-700 bg-slate-800 text-slate-400">
            {type}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Candidate Sending IPs Table */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Candidate Sending IP Addresses &amp; Origin Attribution
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {forensicFindings.candidateSourceIps.length} candidate(s) identified
          </span>
        </div>

        <p className="text-xs text-slate-400">
          Identified by walking the chronological SMTP Received chain. Internal LAN addresses reflect client submission, while the first public relay marks the internet routing boundary.
        </p>

        {forensicFindings.candidateSourceIps.length === 0 ? (
          <div className="text-xs text-slate-400 italic p-3 bg-slate-950 rounded border border-slate-800">
            No IP addresses were extractable from the provided headers.
          </div>
        ) : (
          <div className="border border-slate-800 rounded overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <tr>
                  <th className="py-2 px-3">IP Address</th>
                  <th className="py-2 px-3">Classification</th>
                  <th className="py-2 px-3">Confidence</th>
                  <th className="py-2 px-3">Forensic Justification</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 bg-slate-900/40">
                {forensicFindings.candidateSourceIps.map((candidate, idx) => (
                  <tr key={idx} className="font-mono">
                    <td className="py-2.5 px-3 font-bold text-slate-100">
                      {candidate.ip}
                    </td>
                    <td className="py-2.5 px-3">
                      {getIpTypeBadge(candidate.ipType)}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {candidate.confidence}
                    </td>
                    <td className="py-2.5 px-3 font-sans text-slate-300">
                      {candidate.justification}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Identity Mismatches & Anomaly Warnings */}
      {forensicFindings.identityMismatches.length > 0 && (
        <div className="p-4 bg-rose-950/20 border border-rose-900/50 rounded space-y-3">
          <div className="flex items-center gap-2 text-rose-400 font-semibold text-xs">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>Identity Inconsistencies &amp; Spoofing Indicators ({forensicFindings.identityMismatches.length})</span>
          </div>

          <div className="space-y-2">
            {forensicFindings.identityMismatches.map((mismatch, idx) => (
              <div key={idx} className="p-3 bg-slate-950/80 rounded border border-rose-900/40 text-xs space-y-1">
                <div className="font-mono text-rose-300 font-semibold">
                  [{mismatch.findingType}] {mismatch.value}
                </div>
                <p className="text-slate-300 leading-relaxed font-sans">
                  {mismatch.explanation}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Chronological Received-Chain Timeline */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Chronological SMTP Mail Relay Progression
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Earliest Submission &rarr; Final MX Delivery
          </span>
        </div>

        {forensicFindings.receivedHops.length === 0 ? (
          <div className="text-xs text-slate-400 italic p-3 bg-slate-950 rounded border border-slate-800">
            No Received headers found. Complete mail path reconstruction is unavailable for this input.
          </div>
        ) : (
          <div className="space-y-3">
            {forensicFindings.receivedHops.map((hop: ReceivedHop, idx: number) => (
              <div key={idx} className="relative">
                <div className="p-3.5 bg-slate-950 rounded border border-slate-800 text-xs space-y-2 font-mono">
                  <div className="flex items-center justify-between font-sans">
                    <div className="flex items-center gap-2 font-mono font-bold text-cyan-300">
                      <span>Hop #{hop.hopIndex}</span>
                      {hop.ipType && getIpTypeBadge(hop.ipType)}
                    </div>
                    <div className="text-slate-400 text-xs flex items-center gap-1 font-mono">
                      <Clock className="w-3 h-3" />
                      <span>{hop.timestamp || 'No timestamp'}</span>
                      {typeof hop.timeDeltaSeconds === 'number' && (
                        <span className={`ml-2 font-bold ${
                          hop.timeDeltaSeconds < 0 ? 'text-rose-400' : 'text-slate-400'
                        }`}>
                          ({hop.timeDeltaSeconds >= 0 ? `+${hop.timeDeltaSeconds}s` : `${hop.timeDeltaSeconds}s anomaly`})
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-300">
                    <div>
                      <span className="text-slate-400">From / Submitting:</span>{' '}
                      <span className="text-slate-100">{hop.reportingServer || 'Unspecified'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">By / Receiving MTA:</span>{' '}
                      <span className="text-slate-100">{hop.byServer || 'Unspecified'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">IP Observed:</span>{' '}
                      <span className="text-cyan-300 font-bold">{hop.ipAddress || 'None'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400">Protocol:</span>{' '}
                      <span className="text-slate-300">{hop.protocol || 'SMTP'}</span>
                    </div>
                  </div>

                  {hop.suspiciousSignals.length > 0 && (
                    <div className="pt-2 border-t border-slate-800 space-y-1">
                      {hop.suspiciousSignals.map((sig, sIdx) => (
                        <div key={sIdx} className="text-rose-400 text-[11px] font-sans flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                          <span>{sig}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  <details className="pt-1">
                    <summary className="text-[11px] text-slate-400 hover:text-slate-300 cursor-pointer font-sans">
                      Show Raw Received Header Line
                    </summary>
                    <pre className="mt-1.5 p-2 bg-slate-900 rounded text-[10px] text-slate-400 overflow-x-auto whitespace-pre-wrap leading-tight">
                      {hop.rawHeader}
                    </pre>
                  </details>
                </div>

                {idx < forensicFindings.receivedHops.length - 1 && (
                  <div className="flex justify-center my-1 text-slate-600">
                    <ArrowDown className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Raw Parsed Headers Inspector Toggle */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3">
        <button
          onClick={() => setShowRawHeaders(!showRawHeaders)}
          className="w-full flex items-center justify-between text-xs font-semibold text-slate-200 hover:text-white transition-colors"
        >
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>Complete RFC 5322 Raw Header Dump ({Object.keys(rawHeaders).length} headers)</span>
          </div>
          {showRawHeaders ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        {showRawHeaders && (
          <div className="p-3 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-slate-300 max-h-96 overflow-y-auto space-y-2">
            {Object.entries(rawHeaders).map(([key, val], idx) => (
              <div key={idx} className="border-b border-slate-900 pb-1.5">
                <span className="text-cyan-400 font-bold uppercase">{key}:</span>{' '}
                <span className="text-slate-300 break-all">
                  {Array.isArray(val) ? val.join('\n') : String(val)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
