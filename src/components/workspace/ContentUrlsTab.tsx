import React from 'react';
import { 
  Link2, 
  Paperclip, 
  AlertTriangle, 
  ShieldAlert, 
  Globe, 
  ExternalLink,
  FileCheck,
  AlertOctagon
} from 'lucide-react';
import { EmailAnalysis } from '../../types/forensics';

interface ContentUrlsTabProps {
  analysis: EmailAnalysis;
}

export const ContentUrlsTab: React.FC<ContentUrlsTabProps> = ({ analysis }) => {
  const { contentFindings } = analysis;
  const { urls, attachments, suspiciousIndicators } = contentFindings;

  return (
    <div className="space-y-6">
      {/* Extracted URLs Section */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Link2 className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Extracted Hyperlinks &amp; Domain Targets ({urls.length})
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Defanged for Safe Analyst Review
          </span>
        </div>

        <p className="text-xs text-slate-400">
          URLs are extracted safely from HTML anchors and plain text bodies without resolving or executing client scripts. All destination targets are defanged (<code className="font-mono text-cyan-300">hxxp://</code> and <code className="font-mono text-cyan-300">[.]</code>) to prevent accidental execution.
        </p>

        {urls.length === 0 ? (
          <div className="text-xs text-slate-400 italic p-3 bg-slate-950 rounded border border-slate-800">
            No hyperlinks were detected in the message text or HTML.
          </div>
        ) : (
          <div className="border border-slate-800 rounded overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <tr>
                  <th className="py-2.5 px-3">Defanged URL Target</th>
                  <th className="py-2.5 px-3">Domain</th>
                  <th className="py-2.5 px-3">Visual Anchor Text</th>
                  <th className="py-2.5 px-3">Threat Flags</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 bg-slate-900/40">
                {urls.map((u, idx) => (
                  <tr key={idx} className={u.isMismatch ? 'bg-rose-950/20' : ''}>
                    <td className="py-2.5 px-3 font-mono text-slate-200 max-w-sm truncate" title={u.defangedUrl}>
                      {u.defangedUrl}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-cyan-300">
                      {u.domain}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate font-sans">
                      {u.displayText ? (
                        <span className={u.isMismatch ? 'text-rose-300 font-semibold underline' : ''}>
                          {u.displayText}
                        </span>
                      ) : (
                        <span className="text-slate-500 italic">None (Plain URL)</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3">
                      {u.suspiciousFlags.length === 0 ? (
                        <span className="text-emerald-400 font-mono text-[11px]">Nominal</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {u.isMismatch && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-rose-800 bg-rose-950 text-rose-300 font-bold">
                              Anchor Divergence
                            </span>
                          )}
                          {u.isIpBased && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-rose-800 bg-rose-950 text-rose-300">
                              Direct IP Host
                            </span>
                          )}
                          {u.isPunycode && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-amber-800 bg-amber-950 text-amber-300">
                              Punycode IDN
                            </span>
                          )}
                          {u.isShortener && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-amber-800 bg-amber-950 text-amber-300">
                              URL Shortener
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Attachments Metadata & Hash Section */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Paperclip className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              MIME Attachments &amp; Cryptographic Checksums ({attachments.length})
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Never Executed · Zero Disk Retention
          </span>
        </div>

        {attachments.length === 0 ? (
          <div className="text-xs text-slate-400 italic p-3 bg-slate-950 rounded border border-slate-800">
            No MIME attachments present in this message.
          </div>
        ) : (
          <div className="border border-slate-800 rounded overflow-hidden">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <tr>
                  <th className="py-2.5 px-3">Filename</th>
                  <th className="py-2.5 px-3">Content Type</th>
                  <th className="py-2.5 px-3 text-right">Size</th>
                  <th className="py-2.5 px-3">SHA-256 Checksum</th>
                  <th className="py-2.5 px-3">Risk Assessment</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80 bg-slate-900/40">
                {attachments.map((att, idx) => (
                  <tr key={idx} className={att.isSuspiciousExtension ? 'bg-rose-950/20' : ''}>
                    <td className="py-2.5 px-3 font-mono font-medium text-slate-200">
                      {att.filename}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-400">
                      {att.contentType}
                    </td>
                    <td className="py-2.5 px-3 text-right font-mono tabular-nums text-slate-300">
                      {(att.size / 1024).toFixed(1)} KB
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-cyan-400 max-w-xs truncate" title={att.checksumSha256}>
                      {att.checksumSha256}
                    </td>
                    <td className="py-2.5 px-3">
                      {att.isSuspiciousExtension ? (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-rose-800 bg-rose-950 text-rose-300 font-bold">
                          Dangerous Executable / Script
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono text-emerald-400">
                          Standard Format
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Social Engineering & Language Heuristics */}
      {suspiciousIndicators.length > 0 && (
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <AlertOctagon className="w-4 h-4 text-amber-400" />
            <span>Social Engineering &amp; Coercion Cues ({suspiciousIndicators.length})</span>
          </div>

          <div className="space-y-2">
            {suspiciousIndicators.map((ind, idx) => (
              <div key={idx} className="p-3 bg-slate-950 rounded border border-slate-800 text-xs space-y-1">
                <div className="font-mono text-amber-300 font-semibold">
                  [{ind.findingType}] {ind.value}
                </div>
                <p className="text-slate-300 font-sans">
                  {ind.explanation}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
