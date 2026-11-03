import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  HelpCircle, 
  CheckCircle2, 
  XCircle, 
  AlertCircle,
  FileText,
  Clock,
  Cpu
} from 'lucide-react';
import { EmailAnalysis } from '../../types/forensics';

interface OverviewTabProps {
  analysis: EmailAnalysis;
  onNavigateTab: (tab: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  analysis,
  onNavigateTab
}) => {
  const { overallAssessment, mlResult, envelope, limitations } = analysis;

  const getScoreColor = (score: number) => {
    if (score >= 65) return 'text-rose-400 border-rose-800/80 bg-rose-950/30';
    if (score >= 35) return 'text-amber-400 border-amber-800/80 bg-amber-950/30';
    return 'text-emerald-400 border-emerald-800/80 bg-emerald-950/30';
  };

  return (
    <div className="space-y-6">
      {/* Top Threat Assessment Banner */}
      <div className={`p-5 rounded border ${getScoreColor(overallAssessment.score)} flex flex-col md:flex-row md:items-center justify-between gap-4`}>
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase tracking-wider font-semibold opacity-90">
              Primary Threat Assessment
            </span>
            <span className="text-xs opacity-60">·</span>
            <span className="text-xs font-mono capitalize">
              Confidence: {overallAssessment.confidenceLevel}
            </span>
          </div>
          <div className="text-xl font-bold tracking-tight">
            {overallAssessment.label === 'likely_phishing' && 'Likely Phishing Email'}
            {overallAssessment.label === 'potentially_suspicious' && 'Potentially Suspicious Email'}
            {overallAssessment.label === 'likely_legitimate' && 'Likely Legitimate Email'}
            {overallAssessment.label === 'inconclusive' && 'Inconclusive Analysis'}
            {overallAssessment.label === 'insufficient_evidence' && 'Insufficient Forensic Evidence'}
          </div>
          <p className="text-xs opacity-90 max-w-2xl leading-relaxed">
            {overallAssessment.summary}
          </p>
        </div>

        <div className="text-right shrink-0">
          <div className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Evidence Risk Score
          </div>
          <div className="text-4xl font-extrabold font-mono tabular-nums">
            {overallAssessment.score}
            <span className="text-lg font-normal text-slate-500">/100</span>
          </div>
        </div>
      </div>

      {/* Key Metadata Strip */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="p-3 bg-slate-900 border border-slate-800 rounded">
          <div className="text-xs text-slate-400">Sender Address (From)</div>
          <div className="text-xs font-mono text-slate-200 mt-1 truncate" title={envelope.from?.address}>
            {envelope.from?.address || 'Missing'}
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded">
          <div className="text-xs text-slate-400">Return-Path (Envelope)</div>
          <div className="text-xs font-mono text-slate-200 mt-1 truncate" title={envelope.returnPath}>
            {envelope.returnPath || 'Missing'}
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded">
          <div className="text-xs text-slate-400">Received Transit Hops</div>
          <div className="text-xs font-mono text-slate-200 mt-1">
            {analysis.forensicFindings.receivedHops.length} hops recorded
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded">
          <div className="text-xs text-slate-400">Candidate Sending IPs</div>
          <div className="text-xs font-mono text-slate-200 mt-1">
            {analysis.forensicFindings.candidateSourceIps.length > 0 
              ? analysis.forensicFindings.candidateSourceIps[0].ip 
              : 'None identified'}
          </div>
        </div>
      </div>

      {/* Primary Risk vs Mitigating Factors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Risk Factors */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
          <div className="flex items-center gap-2 text-rose-400 font-medium text-xs">
            <XCircle className="w-4 h-4" />
            <span>Observed Threat Indicators ({overallAssessment.primaryRiskFactors.length})</span>
          </div>
          {overallAssessment.primaryRiskFactors.length === 0 ? (
            <div className="text-xs text-slate-400 italic">
              No critical threat indicators detected.
            </div>
          ) : (
            <ul className="space-y-2 text-xs text-slate-300">
              {overallAssessment.primaryRiskFactors.map((factor, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-rose-400 font-mono text-[10px] mt-0.5">&bull;</span>
                  <span className="leading-relaxed">{factor}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Mitigating Factors */}
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
          <div className="flex items-center gap-2 text-emerald-400 font-medium text-xs">
            <CheckCircle2 className="w-4 h-4" />
            <span>Mitigating &amp; Corroborating Signals ({overallAssessment.mitigatingFactors.length})</span>
          </div>
          {overallAssessment.mitigatingFactors.length === 0 ? (
            <div className="text-xs text-slate-400 italic">
              No significant mitigating factors observed.
            </div>
          ) : (
            <ul className="space-y-2 text-xs text-slate-300">
              {overallAssessment.mitigatingFactors.map((factor, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-emerald-400 font-mono text-[10px] mt-0.5">&bull;</span>
                  <span className="leading-relaxed">{factor}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Machine Learning Status Panel (Mandatory Architectural Decision 3.1 & Model Registry) */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>Machine Learning Classification &amp; Adapter Provenance</span>
          </div>
          <div className="flex items-center gap-2">
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              mlResult.isExperimentallyValidated
                ? 'text-emerald-400 border-emerald-800 bg-emerald-950/40'
                : 'text-amber-400 border-amber-800 bg-amber-950/40'
            }`}>
              {mlResult.isExperimentallyValidated ? 'Validated Benchmark' : 'Unvalidated Research Adapter'}
            </span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
              mlResult.mlConfigured 
                ? 'text-cyan-400 border-cyan-800 bg-cyan-950/40' 
                : 'text-slate-400 border-slate-700 bg-slate-800'
            }`}>
              {mlResult.mlConfigured ? 'Model Active' : 'ML Unconfigured'}
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          {mlResult.rationale}
        </p>

        {mlResult.mlConfigured ? (
          <div className="pt-2 border-t border-slate-800 space-y-2 text-xs font-mono">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] text-slate-300">
              <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
                <span className="text-[10px] text-slate-500 block">Model</span>
                <span className="font-semibold text-slate-200">{mlResult.modelName}</span>
                <span className="text-[10px] text-slate-400 block">v{mlResult.modelVersion}</span>
              </div>
              <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
                <span className="text-[10px] text-slate-500 block">Prediction</span>
                <span className="font-semibold text-cyan-400 uppercase">{mlResult.predictedClass || 'inconclusive'}</span>
                <span className="text-[10px] text-slate-400 block">{mlResult.featureAvailability?.length ?? 0} features evaluated</span>
              </div>
              <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
                <span className="text-[10px] text-slate-500 block">Score &amp; Interpretation</span>
                <span className="font-semibold text-slate-200">
                  {mlResult.decisionScore !== undefined ? mlResult.decisionScore.toFixed(3) : 'N/A'}
                </span>
                <span className="text-[10px] text-slate-400 block truncate" title={mlResult.scoreInterpretation}>
                  {mlResult.scoreInterpretation === 'svm_hyperplane_margin' ? 'SVM Margin (Distance)' : mlResult.scoreInterpretation || 'Raw Score'}
                </span>
              </div>
              <div className="p-2 bg-slate-950 rounded border border-slate-800/80">
                <span className="text-[10px] text-slate-500 block">Calibration</span>
                <span className={`font-semibold ${mlResult.isCalibrated ? 'text-emerald-400' : 'text-amber-400'}`}>
                  {mlResult.isCalibrated ? 'Calibrated' : 'Uncalibrated'}
                </span>
                <span className="text-[10px] text-slate-400 block truncate">
                  {mlResult.calibrationMethod || 'None'}
                </span>
              </div>
            </div>

            {/* Version & Provenance Lock Ribbon */}
            <div className="p-2 bg-slate-950/70 rounded border border-slate-800/60 flex flex-wrap items-center justify-between gap-y-1 text-[10px] text-slate-400">
              <div className="flex items-center gap-3">
                <span>Snapshot: <strong className="text-slate-300">{mlResult.configurationSnapshotId || 'snapshot-locked'}</strong></span>
                <span>Preproc: <strong className="text-slate-300">v{mlResult.preprocessingVersion}</strong></span>
                <span>Schema: <strong className="text-slate-300">v{mlResult.featureSchemaVersion || '1.0.0'}</strong></span>
              </div>
              <div>
                Timestamp: <span className="text-slate-400">{new Date(mlResult.predictionTimestamp).toLocaleTimeString()}</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="pt-2 border-t border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
            <span>Active Model: <strong>{mlResult.modelName}</strong> (v{mlResult.modelVersion})</span>
            <span className="text-slate-500">Snapshot: {mlResult.configurationSnapshotId || 'baseline'}</span>
          </div>
        )}
      </div>

      {/* Step-by-Step Evidence Reasoning Chain */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span>Step-by-Step Evidence Fusion Reasoning Chain</span>
        </div>
        <div className="space-y-1.5 font-mono text-xs text-slate-400 bg-slate-950 p-3 rounded border border-slate-800 overflow-x-auto">
          {overallAssessment.reasoningChain.map((step, idx) => (
            <div key={idx} className={step.startsWith('---') ? 'text-cyan-400 font-semibold pt-1' : 'text-slate-300 pl-2'}>
              {step}
            </div>
          ))}
        </div>
      </div>

      {/* Methodology Limitations */}
      <div className="p-4 bg-slate-950 border border-slate-800/80 rounded space-y-2 text-xs text-slate-400">
        <div className="font-semibold text-slate-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-amber-400" />
          <span>Investigation Limitations &amp; Caveats</span>
        </div>
        <ul className="list-disc list-inside space-y-1 pl-1 text-slate-400">
          {limitations.map((lim, idx) => (
            <li key={idx}>{lim}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};
