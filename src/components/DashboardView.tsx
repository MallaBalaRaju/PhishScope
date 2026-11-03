import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  HelpCircle, 
  Server, 
  ArrowRight,
  UploadCloud,
  FileCode,
  Network
} from 'lucide-react';
import { SessionMetrics } from '../types/forensics';

interface DashboardViewProps {
  metrics: SessionMetrics;
  analyses: Array<{
    analysisId: string;
    createdAt: string;
    inputType: string;
    sourceFilename?: string;
    subject: string;
    sender: string;
    assessment: string;
    score: number;
    confidence: string;
    candidateIpsCount: number;
    urlsCount: number;
  }>;
  onSelectAnalysis: (id: string) => void;
  onNavigate: (tab: string) => void;
  onLoadSample: (fixtureId: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  metrics,
  analyses,
  onSelectAnalysis,
  onNavigate,
  onLoadSample
}) => {
  const getAssessmentBadge = (label: string) => {
    switch (label) {
      case 'likely_phishing':
        return (
          <span className="text-rose-400 font-medium text-xs">
            Likely Phishing
          </span>
        );
      case 'potentially_suspicious':
        return (
          <span className="text-amber-400 font-medium text-xs">
            Potentially Suspicious
          </span>
        );
      case 'likely_legitimate':
        return (
          <span className="text-emerald-400 font-medium text-xs">
            Likely Legitimate
          </span>
        );
      case 'insufficient_evidence':
        return (
          <span className="text-slate-400 font-medium text-xs">
            Insufficient Evidence
          </span>
        );
      default:
        return (
          <span className="text-slate-300 font-medium text-xs">
            Inconclusive
          </span>
        );
    }
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto py-6 px-6">
      {/* Title & Scope Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">
            Analyst Security Operations Console
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time session triage, email header forensics, SPF/DKIM verification, and infrastructure intelligence.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded border border-slate-800">
          <span className="w-2 h-2 rounded-full bg-cyan-400" />
          <span>Storage: In-Memory Session (RFC Compliant)</span>
        </div>
      </div>

      {/* Primary Metrics Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded">
          <div className="text-xs text-slate-400 font-medium">Session Analyzed</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-slate-100 mt-1">
            {metrics.totalAnalyzed}
          </div>
          <div className="text-xs text-slate-400 mt-1">Total in session</div>
        </div>

        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded">
          <div className="text-xs text-rose-400 font-medium flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Likely Phishing</span>
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-rose-300 mt-1">
            {metrics.phishingCount}
          </div>
          <div className="text-xs text-slate-400 mt-1">High-risk indicators</div>
        </div>

        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded">
          <div className="text-xs text-amber-400 font-medium flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Suspicious</span>
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-amber-300 mt-1">
            {metrics.suspiciousCount}
          </div>
          <div className="text-xs text-slate-400 mt-1">Anomalous routing/urls</div>
        </div>

        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded">
          <div className="text-xs text-emerald-400 font-medium flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Legitimate</span>
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-emerald-300 mt-1">
            {metrics.legitimateCount}
          </div>
          <div className="text-xs text-slate-400 mt-1">Auth &amp; headers passed</div>
        </div>

        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded">
          <div className="text-xs text-slate-400 font-medium flex items-center gap-1.5">
            <HelpCircle className="w-3.5 h-3.5" />
            <span>Inconclusive</span>
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-slate-300 mt-1">
            {metrics.inconclusiveCount}
          </div>
          <div className="text-xs text-slate-400 mt-1">Partial or missing data</div>
        </div>

        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded">
          <div className="text-xs text-purple-400 font-medium flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5" />
            <span>Auth Warnings</span>
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-purple-300 mt-1">
            {metrics.authenticationWarningsCount}
          </div>
          <div className="text-xs text-slate-400 mt-1">SPF/DKIM/DMARC flags</div>
        </div>
      </div>

      {/* Main Content Area */}
      {analyses.length === 0 ? (
        /* Empty State */
        <div className="p-10 border border-dashed border-slate-800 rounded text-center bg-slate-900/30 space-y-6">
          <div className="w-12 h-12 mx-auto rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400">
            <UploadCloud className="w-6 h-6 text-cyan-400" />
          </div>

          <div className="max-w-md mx-auto space-y-2">
            <h3 className="text-lg font-semibold text-slate-100">
              No Emails Analyzed in Current Session
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Upload a raw RFC 5322 <span className="font-mono text-slate-300">.eml</span> file, paste email headers, or load one of the standardized forensic test fixtures below to inspect live routing and threat intelligence.
            </p>
          </div>

          <div className="flex flex-wrap justify-center gap-3 pt-2">
            <button
              onClick={() => onNavigate('ingestion')}
              className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
            >
              Upload or Paste Email
            </button>
            <button
              onClick={() => onLoadSample('fixture-02-credential-phish')}
              className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors"
            >
              Load Sample: Banking Credential Phish
            </button>
            <button
              onClick={() => onLoadSample('fixture-01-legitimate')}
              className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors"
            >
              Load Sample: Legitimate Digest
            </button>
          </div>
        </div>
      ) : (
        /* Recent Session Analyses Table */
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-slate-100">
              Recent Session Analyses
            </h2>
            <button
              onClick={() => onNavigate('correlation')}
              className="text-xs font-medium text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
            >
              <Network className="w-3.5 h-3.5" />
              <span>Inspect Infrastructure Correlation Graph</span>
              <ArrowRight className="w-3 h-3 ml-0.5" />
            </button>
          </div>

          <div className="border border-slate-800 rounded overflow-hidden bg-slate-900/40">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <tr>
                  <th className="py-2.5 px-4">Subject</th>
                  <th className="py-2.5 px-4">Sender Address</th>
                  <th className="py-2.5 px-4">Assessment</th>
                  <th className="py-2.5 px-4 text-right">Risk Score</th>
                  <th className="py-2.5 px-4 text-center">Candidate IPs</th>
                  <th className="py-2.5 px-4 text-center">URLs</th>
                  <th className="py-2.5 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {analyses.map((a) => (
                  <tr
                    key={a.analysisId}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectAnalysis(a.analysisId)}
                  >
                    <td className="py-3 px-4 text-slate-200 font-medium max-w-xs truncate">
                      {a.subject}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 max-w-xs truncate">
                      {a.sender}
                    </td>
                    <td className="py-3 px-4">
                      {getAssessmentBadge(a.assessment)}
                    </td>
                    <td className="py-3 px-4 text-right font-mono tabular-nums">
                      <span className={
                        a.score >= 65 ? 'text-rose-400 font-bold' :
                        a.score >= 35 ? 'text-amber-400 font-semibold' : 'text-emerald-400'
                      }>
                        {a.score}/100
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center font-mono tabular-nums text-slate-400">
                      {a.candidateIpsCount}
                    </td>
                    <td className="py-3 px-4 text-center font-mono tabular-nums text-slate-400">
                      {a.urlsCount}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAnalysis(a.analysisId);
                        }}
                        className="px-2.5 py-1 text-xs text-cyan-400 hover:text-cyan-300 font-medium hover:bg-cyan-950/40 rounded transition-colors"
                      >
                        Open Workspace &rarr;
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Synthetic Test Fixtures Quick-Launch Strip */}
      <div className="border border-slate-800/80 rounded p-4 bg-slate-900/30 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Standardized Synthetic Forensic Test Fixtures
            </h3>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Lab Environment Fixtures
          </span>
        </div>

        <p className="text-xs text-slate-400">
          Load verified synthetic test cases to test parser fidelity, spoofing detection, negative transit time algorithms, and infrastructure clustering.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 pt-1">
          <button
            onClick={() => onLoadSample('fixture-02-credential-phish')}
            className="text-left p-2.5 rounded bg-slate-900 border border-slate-800 hover:border-rose-800/60 transition-colors group"
          >
            <div className="text-xs font-medium text-slate-200 group-hover:text-rose-300">
              Banking Credential Phish
            </div>
            <div className="text-xs text-slate-400 mt-0.5 line-clamp-1">
              SPF fail, direct IP link, anchor text mismatch.
            </div>
          </button>

          <button
            onClick={() => onLoadSample('fixture-03-routing-anomaly')}
            className="text-left p-2.5 rounded bg-slate-900 border border-slate-800 hover:border-amber-800/60 transition-colors group"
          >
            <div className="text-xs font-medium text-slate-200 group-hover:text-amber-300">
              Forged Routing Chain
            </div>
            <div className="text-xs text-slate-400 mt-0.5 line-clamp-1">
              Negative transit time, clock reversal, relay hopping.
            </div>
          </button>

          <button
            onClick={() => onLoadSample('fixture-04-punycode-homoglyph')}
            className="text-left p-2.5 rounded bg-slate-900 border border-slate-800 hover:border-cyan-800/60 transition-colors group"
          >
            <div className="text-xs font-medium text-slate-200 group-hover:text-cyan-300">
              Punycode IDN Homoglyph
            </div>
            <div className="text-xs text-slate-400 mt-0.5 line-clamp-1">
              xn--pple-43d.com Cyrillic lookalike domain spoofing.
            </div>
          </button>
        </div>
      </div>
    </div>
  );
};
