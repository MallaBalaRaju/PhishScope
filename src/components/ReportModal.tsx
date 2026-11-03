import React from 'react';
import { 
  X, 
  Printer, 
  Download, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle,
  FileCheck
} from 'lucide-react';
import { EmailAnalysis } from '../types/forensics';

interface ReportModalProps {
  analysis: EmailAnalysis;
  onClose: () => void;
}

export const ReportModal: React.FC<ReportModalProps> = ({ analysis, onClose }) => {
  const { overallAssessment, envelope, forensicFindings, authenticationFindings, mlResult, limitations } = analysis;

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-950 border border-slate-800 rounded-lg max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header Modal Bar */}
        <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-slate-900/80">
          <div className="flex items-center gap-2">
            <FileCheck className="w-5 h-5 text-cyan-400" />
            <span className="text-sm font-semibold text-slate-100">
              Cybersecurity Email Forensic Investigation Report
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="px-3 py-1.5 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors flex items-center gap-1.5"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white rounded transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Printable Report Content */}
        <div className="p-8 space-y-6 overflow-y-auto text-slate-200 text-xs font-sans print:bg-white print:text-black">
          {/* Document Header */}
          <div className="border-b border-slate-800 pb-4 flex justify-between items-start">
            <div>
              <div className="text-xl font-bold tracking-tight text-slate-100 print:text-black">
                PhishScope Forensic Threat Report
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1">
                Forensic Traceability &amp; Infrastructure-Aware Phishing Analysis
              </div>
            </div>
            <div className="text-right font-mono text-[11px] text-slate-400">
              <div>Report ID: {analysis.analysisId}</div>
              <div>Generated: {new Date().toISOString()}</div>
              <div>Input Type: {analysis.inputType}</div>
            </div>
          </div>

          {/* Assessment Summary Box */}
          <div className="p-4 bg-slate-900 rounded border border-slate-800 print:border-gray-400 space-y-2">
            <div className="flex items-center justify-between font-mono">
              <span className="font-bold text-sm uppercase tracking-wide text-cyan-400 print:text-black">
                Assessment: {overallAssessment.label.replace(/_/g, ' ')}
              </span>
              <span className="text-base font-bold tabular-nums">
                Risk Score: {overallAssessment.score}/100 ({overallAssessment.confidenceLevel.toUpperCase()} Confidence)
              </span>
            </div>
            <p className="text-slate-300 print:text-gray-800 leading-relaxed font-sans">
              {overallAssessment.summary}
            </p>
          </div>

          {/* Envelope Metadata */}
          <div className="space-y-2">
            <h4 className="font-mono text-xs font-bold uppercase text-slate-400 print:text-black border-b border-slate-800 pb-1">
              1. RFC 5322 Envelope Metadata
            </h4>
            <div className="grid grid-cols-2 gap-2 font-mono">
              <div><strong>From:</strong> {envelope.from?.address || 'None'}</div>
              <div><strong>Return-Path:</strong> {envelope.returnPath || 'None'}</div>
              <div><strong>Reply-To:</strong> {envelope.replyTo?.address || 'None'}</div>
              <div><strong>Date:</strong> {envelope.date || 'None'}</div>
              <div className="col-span-2"><strong>Subject:</strong> {envelope.subject || 'None'}</div>
              <div className="col-span-2"><strong>Message-ID:</strong> {envelope.messageId || 'None'}</div>
            </div>
          </div>

          {/* Authentication Triad */}
          <div className="space-y-2">
            <h4 className="font-mono text-xs font-bold uppercase text-slate-400 print:text-black border-b border-slate-800 pb-1">
              2. Authentication Forensics (RFC 8601 / RFC 7208 / RFC 6376 / RFC 7489)
            </h4>
            <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
              <div className="p-2 bg-slate-900 rounded border border-slate-800">
                <div className="font-bold">SPF: {authenticationFindings.spf.result.toUpperCase()}</div>
                <div>Domain: {authenticationFindings.spf.domain || 'N/A'}</div>
                <div>Alignment: {authenticationFindings.spf.alignmentWithFrom}</div>
              </div>
              <div className="p-2 bg-slate-900 rounded border border-slate-800">
                <div className="font-bold">DKIM: {authenticationFindings.dkim.result.toUpperCase()}</div>
                <div>Domain: {authenticationFindings.dkim.domain || 'N/A'}</div>
                <div>Alignment: {authenticationFindings.dkim.alignmentWithFrom}</div>
              </div>
              <div className="p-2 bg-slate-900 rounded border border-slate-800">
                <div className="font-bold">DMARC: {authenticationFindings.dmarc.result.toUpperCase()}</div>
                <div>Policy: {authenticationFindings.dmarc.policy || 'none'}</div>
                <div>Alignment: {authenticationFindings.dmarc.alignmentWithFrom}</div>
              </div>
            </div>
            <div className="text-[11px] text-slate-400 italic">
              Provenance Status: {authenticationFindings.provenance}
            </div>
          </div>

          {/* Candidate Routing Chain */}
          <div className="space-y-2">
            <h4 className="font-mono text-xs font-bold uppercase text-slate-400 print:text-black border-b border-slate-800 pb-1">
              3. SMTP Received Chain &amp; Candidate Sending IPs
            </h4>
            <div className="space-y-1 font-mono text-[11px]">
              {forensicFindings.candidateSourceIps.map((c, idx) => (
                <div key={idx} className="p-1.5 bg-slate-900 rounded border border-slate-800 flex justify-between">
                  <span>Candidate IP: <strong>{c.ip}</strong> ({c.ipType})</span>
                  <span>{c.confidence}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Indicators & Anomalies */}
          <div className="space-y-2">
            <h4 className="font-mono text-xs font-bold uppercase text-slate-400 print:text-black border-b border-slate-800 pb-1">
              4. Key Forensic Indicators &amp; Detected Anomalies
            </h4>
            <ul className="list-disc list-inside space-y-1 text-slate-300">
              {overallAssessment.primaryRiskFactors.map((f, idx) => (
                <li key={idx}>{f}</li>
              ))}
            </ul>
          </div>

          {/* Machine Learning Status & Provenance */}
          <div className="space-y-2">
            <h4 className="font-mono text-xs font-bold uppercase text-slate-400 print:text-black border-b border-slate-800 pb-1">
              5. Machine Learning Evaluation &amp; Adapter Provenance
            </h4>
            <div className="p-3 bg-slate-900 rounded border border-slate-800 text-[11px] font-mono space-y-2">
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                <div><strong>Model:</strong> {mlResult.modelName} (v{mlResult.modelVersion})</div>
                <div><strong>Configured:</strong> {mlResult.mlConfigured ? 'Yes' : 'No'}</div>
                <div><strong>Validation:</strong> {mlResult.isExperimentallyValidated ? 'Validated' : 'Unvalidated Research Adapter'}</div>
                <div><strong>Snapshot ID:</strong> {mlResult.configurationSnapshotId || 'snapshot-initial'}</div>
                <div><strong>Feature Schema:</strong> v{mlResult.featureSchemaVersion || '1.0.0'}</div>
                <div><strong>Preprocessing:</strong> v{mlResult.preprocessingVersion}</div>
                <div><strong>Decision Score:</strong> {mlResult.decisionScore !== undefined ? mlResult.decisionScore.toFixed(3) : 'N/A'}</div>
                <div><strong>Score Interpretation:</strong> {mlResult.scoreInterpretation || 'raw_score'}</div>
                <div><strong>Calibration:</strong> {mlResult.isCalibrated ? `Calibrated (${mlResult.calibrationMethod})` : 'Uncalibrated'}</div>
              </div>
              {mlResult.rationale && (
                <div className="pt-2 border-t border-slate-800 text-slate-400 font-sans text-xs">
                  <strong>Rationale:</strong> {mlResult.rationale}
                </div>
              )}
            </div>
          </div>

          {/* Analyst Notes */}
          {analysis.analystNotes && (
            <div className="p-3 bg-slate-900 rounded border border-slate-800 space-y-1">
              <div className="font-mono font-bold text-xs uppercase text-slate-300">
                Analyst Notes
              </div>
              <p className="text-slate-300 font-sans whitespace-pre-wrap">
                {analysis.analystNotes}
              </p>
            </div>
          )}

          {/* Investigation Limitations */}
          <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500 space-y-1">
            <div className="font-bold uppercase">Methodology Limitations:</div>
            {limitations.map((lim, idx) => (
              <div key={idx}>&bull; {lim}</div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
