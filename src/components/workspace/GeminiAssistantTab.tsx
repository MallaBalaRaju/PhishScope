import React, { useState } from 'react';
import { 
  Sparkles, 
  ShieldAlert, 
  HelpCircle, 
  CheckCircle2, 
  ListOrdered, 
  Compass, 
  Loader2,
  AlertCircle,
  FileCheck
} from 'lucide-react';
import { EmailAnalysis } from '../../types/forensics';

interface GeminiAssistantTabProps {
  analysis: EmailAnalysis;
  onUpdateAnalysis: (updated: EmailAnalysis) => void;
}

export const GeminiAssistantTab: React.FC<GeminiAssistantTabProps> = ({
  analysis,
  onUpdateAnalysis
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const aiResult = analysis.aiAssistantResult;

  const handleInvokeAssistant = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/analyses/${analysis.analysisId}/assistant`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.error || 'Failed to execute Gemini assistant.');
      }
      const data = await res.json();
      onUpdateAnalysis({
        ...analysis,
        aiAssistantResult: data
      });
    } catch (err: any) {
      setError(err.message || 'Error communicating with assistant.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Scope and Grounding Header */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Gemini Evidence-Grounded Investigation Assistant
            </h3>
          </div>
          <p className="text-xs text-slate-400">
            Powered server-side by <span className="font-mono text-cyan-300">gemini-3.8-flash</span>. Operates strictly on structured forensic findings (no raw bodies or sensitive tokens transmitted).
          </p>
        </div>

        <button
          onClick={handleInvokeAssistant}
          disabled={isLoading}
          className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 shadow-sm font-sans"
        >
          {isLoading ? (
            <>
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>Synthesizing Findings...</span>
            </>
          ) : (
            <>
              <Sparkles className="w-3.5 h-3.5" />
              <span>{aiResult ? 'Re-Run AI Investigation' : 'Run AI Investigation'}</span>
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-950/40 border border-rose-900/60 rounded text-xs text-rose-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Main AI Output Display */}
      {!aiResult && !isLoading && (
        <div className="p-8 border border-dashed border-slate-800 rounded text-center bg-slate-900/30 space-y-3">
          <Sparkles className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-xs font-medium text-slate-300">
            Assistant Briefing Not Yet Generated
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Click "Run AI Investigation" above to prompt Gemini 3.8 Flash to synthesize observed facts, derived conclusions, conflicting evidence, and actionable triage steps.
          </p>
        </div>
      )}

      {aiResult && (
        <div className="space-y-6">
          {/* Executive Summary */}
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded space-y-2">
            <div className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-2">
              <FileCheck className="w-4 h-4" />
              <span>Executive Briefing Summary</span>
            </div>
            <p className="text-xs text-slate-200 leading-relaxed font-sans">
              {aiResult.executiveSummary}
            </p>
            <div className="text-[10px] font-mono text-slate-400 pt-1">
              Generated: {aiResult.generatedAt} · Model: {aiResult.modelUsed}
            </div>
          </div>

          {/* 5-Pillar Structured Forensic Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* 1. Directly Observed Facts */}
            <div className="p-4 bg-slate-900/50 border border-slate-800 rounded space-y-2.5">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>1. Directly Observed Technical Facts</span>
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {aiResult.observedFacts.map((fact, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-emerald-400 font-mono text-[10px] mt-0.5">&bull;</span>
                    <span className="leading-relaxed">{fact}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* 2. Derived Technical Findings */}
            <div className="p-4 bg-slate-900/50 border border-slate-800 rounded space-y-2.5">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>2. Derived Forensic Findings</span>
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {aiResult.derivedFindings.map((finding, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-amber-400 font-mono text-[10px] mt-0.5">&bull;</span>
                    <span className="leading-relaxed">{finding}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* 3. Unknown & Missing Information */}
            <div className="p-4 bg-slate-900/50 border border-slate-800 rounded space-y-2.5">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <HelpCircle className="w-4 h-4 text-slate-400" />
                <span>3. Missing or Unverified Information</span>
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {aiResult.unknownInformation.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-slate-400 font-mono text-[10px] mt-0.5">&bull;</span>
                    <span className="leading-relaxed">{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* 4. Recommended Analyst Actions */}
            <div className="p-4 bg-slate-900/50 border border-slate-800 rounded space-y-2.5">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <Compass className="w-4 h-4 text-cyan-400" />
                <span>4. Recommended Further Investigative Checks</span>
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {aiResult.recommendedFurtherChecks.map((check, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-cyan-400 font-mono text-[10px] mt-0.5">&bull;</span>
                    <span className="leading-relaxed">{check}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* 5. Expert AI Interpretation */}
          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-2">
            <div className="text-xs font-semibold text-slate-200">
              5. Comprehensive Threat Interpretation
            </div>
            <p className="text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">
              {aiResult.aiInterpretation}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
