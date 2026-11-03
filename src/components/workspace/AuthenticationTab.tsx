import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  HelpCircle, 
  Key, 
  Lock, 
  Info,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import { EmailAnalysis } from '../../types/forensics';

interface AuthenticationTabProps {
  analysis: EmailAnalysis;
}

export const AuthenticationTab: React.FC<AuthenticationTabProps> = ({ analysis }) => {
  const { authenticationFindings, envelope } = analysis;
  const { spf, dkim, dmarc, provenance, limitations } = authenticationFindings;

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pass':
        return (
          <span className="flex items-center gap-1.5 text-xs font-mono font-bold text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>PASS</span>
          </span>
        );
      case 'fail':
        return (
          <span className="flex items-center gap-1.5 text-xs font-mono font-bold text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800">
            <XCircle className="w-3.5 h-3.5" />
            <span>FAIL</span>
          </span>
        );
      case 'softfail':
        return (
          <span className="flex items-center gap-1.5 text-xs font-mono font-bold text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>SOFTFAIL</span>
          </span>
        );
      case 'missing':
        return (
          <span className="flex items-center gap-1.5 text-xs font-mono font-medium text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
            <HelpCircle className="w-3.5 h-3.5" />
            <span>MISSING</span>
          </span>
        );
      case 'not_independently_verified':
        return (
          <span className="flex items-center gap-1.5 text-xs font-mono font-medium text-blue-400 bg-blue-950/60 px-2 py-0.5 rounded border border-blue-800">
            <Info className="w-3.5 h-3.5" />
            <span>SIGNATURE PRESENT (UNVERIFIED)</span>
          </span>
        );
      default:
        return (
          <span className="text-xs font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded">
            {status.toUpperCase()}
          </span>
        );
    }
  };

  const getAlignmentBadge = (alignment: string) => {
    switch (alignment) {
      case 'strict':
      case 'aligned':
        return <span className="text-emerald-400 font-mono text-xs font-semibold">Aligned (Strict)</span>;
      case 'relaxed':
        return <span className="text-emerald-300 font-mono text-xs">Aligned (Relaxed)</span>;
      case 'misaligned':
        return <span className="text-rose-400 font-mono text-xs font-semibold">Misaligned</span>;
      default:
        return <span className="text-slate-400 font-mono text-xs">Inapplicable / N/A</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Provenance Notice Banner */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded flex items-start gap-3">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <div className="font-semibold text-slate-200">
            Authentication Provenance Status: <span className="text-cyan-300 font-mono uppercase">{provenance.replace(/_/g, ' ')}</span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            Forensic distinction: Results shown here reflect evaluations recorded by the receiving Mail Transfer Agent in <code className="text-slate-300 font-mono">Authentication-Results</code> and <code className="text-slate-300 font-mono">Received-SPF</code> headers. Text headers are verified as they exist within the ingested message; cryptographic signature verification and live DNS re-validation require active authoritative network checks.
          </p>
        </div>
      </div>

      {/* Triad Grid: SPF, DKIM, DMARC */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* 1. SPF Card */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
              SPF (RFC 7208)
            </span>
            {getStatusBadge(spf.result)}
          </div>

          <div className="space-y-2 text-xs font-mono pt-1">
            <div>
              <span className="text-slate-400">Evaluated Domain:</span>{' '}
              <span className="text-slate-100">{spf.domain || 'None declared'}</span>
            </div>
            <div>
              <span className="text-slate-400">Sending IP:</span>{' '}
              <span className="text-cyan-300">{spf.ip || 'Unspecified in header'}</span>
            </div>
            <div>
              <span className="text-slate-400">Identifier Alignment:</span>{' '}
              {getAlignmentBadge(spf.alignmentWithFrom)}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 text-xs text-slate-300 font-sans leading-relaxed">
            {spf.note}
          </div>

          {spf.rawSnippet && (
            <details className="pt-1">
              <summary className="text-[11px] text-slate-400 hover:text-slate-300 cursor-pointer font-sans">
                Show Header Snippet
              </summary>
              <pre className="mt-1 p-2 bg-slate-950 rounded text-[10px] text-slate-400 overflow-x-auto whitespace-pre-wrap font-mono">
                {spf.rawSnippet}
              </pre>
            </details>
          )}
        </div>

        {/* 2. DKIM Card */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
              DKIM (RFC 6376)
            </span>
            {getStatusBadge(dkim.result)}
          </div>

          <div className="space-y-2 text-xs font-mono pt-1">
            <div>
              <span className="text-slate-400">Signing Domain (d=):</span>{' '}
              <span className="text-slate-100">{dkim.domain || 'None declared'}</span>
            </div>
            <div>
              <span className="text-slate-400">Selector (s=):</span>{' '}
              <span className="text-cyan-300">{dkim.selector || 'None declared'}</span>
            </div>
            <div>
              <span className="text-slate-400">Identifier Alignment:</span>{' '}
              {getAlignmentBadge(dkim.alignmentWithFrom)}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 text-xs text-slate-300 font-sans leading-relaxed">
            {dkim.note}
          </div>

          {dkim.headerSnippet && (
            <details className="pt-1">
              <summary className="text-[11px] text-slate-400 hover:text-slate-300 cursor-pointer font-sans">
                Show Header Snippet
              </summary>
              <pre className="mt-1 p-2 bg-slate-950 rounded text-[10px] text-slate-400 overflow-x-auto whitespace-pre-wrap font-mono">
                {dkim.headerSnippet}
              </pre>
            </details>
          )}
        </div>

        {/* 3. DMARC Card */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
              DMARC (RFC 7489)
            </span>
            {getStatusBadge(dmarc.result)}
          </div>

          <div className="space-y-2 text-xs font-mono pt-1">
            <div>
              <span className="text-slate-400">Published Policy (p=):</span>{' '}
              <span className="text-slate-100 uppercase">{dmarc.policy || 'None specified'}</span>
            </div>
            <div>
              <span className="text-slate-400">From Domain (Header):</span>{' '}
              <span className="text-cyan-300">{envelope.from?.domain || 'Missing'}</span>
            </div>
            <div>
              <span className="text-slate-400">Policy Alignment:</span>{' '}
              {getAlignmentBadge(dmarc.alignmentWithFrom)}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 text-xs text-slate-300 font-sans leading-relaxed">
            {dmarc.note}
          </div>
        </div>
      </div>

      {/* Technical Limitations and Verification Disclaimers */}
      <div className="p-4 bg-slate-950 border border-slate-800 rounded space-y-2 text-xs text-slate-400">
        <div className="font-semibold text-slate-300">
          Standard RFC Authentication Constraints
        </div>
        <ul className="list-disc list-inside space-y-1 pl-1 text-slate-400">
          <li>
            <strong>SPF limitation:</strong> SPF only validates the envelope Return-Path domain, not the visible From header. Attackers often pass SPF by registering a throwaway domain for Return-Path while forging the visible From display.
          </li>
          <li>
            <strong>DKIM limitation:</strong> A valid DKIM signature proves message integrity from the signing domain, but does not prevent spoofing if the signing domain does not match the From address (DMARC alignment failure).
          </li>
          <li>
            <strong>DMARC role:</strong> DMARC bridges SPF and DKIM by enforcing that either SPF or DKIM must pass with identifier alignment matching the visible RFC 5322 From domain.
          </li>
        </ul>
      </div>
    </div>
  );
};
