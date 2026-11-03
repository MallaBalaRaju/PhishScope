import React, { useState } from 'react';
import { 
  X, 
  FileJson, 
  FileText, 
  FileSpreadsheet, 
  Download, 
  Loader2, 
  CheckCircle2, 
  AlertCircle,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Eye,
  Info
} from 'lucide-react';
import { EmailAnalysis } from '../types/forensics';
import { ExportFormat, ExportOptions, executeExportInvestigation } from '../export';

interface ExportModalProps {
  analysis: EmailAnalysis | null;
  isOpen: boolean;
  onClose: () => void;
}

export const ExportModal: React.FC<ExportModalProps> = ({
  analysis,
  isOpen,
  onClose
}) => {
  const [selectedFormat, setSelectedFormat] = useState<ExportFormat>('json');
  const [includeSensitive, setIncludeSensitive] = useState<boolean>(false);
  const [includeChecksum, setIncludeChecksum] = useState<boolean>(true);
  const [analystName, setAnalystName] = useState<string>('');
  const [isExporting, setIsExporting] = useState<boolean>(false);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleExport = async () => {
    if (!analysis) {
      setErrorMessage('No investigation is currently selected. Please load or select an investigation first.');
      return;
    }

    setIsExporting(true);
    setErrorMessage(null);
    setExportSuccess(null);

    try {
      const options: ExportOptions = {
        includeSensitiveRawData: includeSensitive,
        includeSha256Checksum: includeChecksum,
        analystName: analystName.trim() || undefined
      };

      const result = await executeExportInvestigation(analysis, selectedFormat, options, true);
      setExportSuccess(`Successfully generated and downloaded: ${result.filename} (${(result.bytesCount / 1024).toFixed(1)} KB)`);
    } catch (err: any) {
      console.error('Export generation error:', err);
      setErrorMessage(`Export failed: ${err.message || 'Unknown generation error'}`);
    } finally {
      setIsExporting(false);
    }
  };

  const formatCards = [
    {
      id: 'json' as ExportFormat,
      name: 'JSON Export (.json)',
      badge: 'Machine-Readable',
      icon: FileJson,
      color: 'text-amber-400',
      bgColor: 'bg-amber-950/20',
      borderColor: 'border-amber-500/30',
      description: 'Complete structured JSON conforming to Schema 1.0.0. Ideal for SIEM ingestion, automated case handoff, or programmatic forensic pipelines.'
    },
    {
      id: 'pdf' as ExportFormat,
      name: 'Forensic PDF Report (.pdf)',
      badge: 'Executive & Legal',
      icon: FileText,
      color: 'text-rose-400',
      bgColor: 'bg-rose-950/20',
      borderColor: 'border-rose-500/30',
      description: 'Publication-quality 14-section cybersecurity investigation report with repeating table headers, page numbers, and provenance annotations.'
    },
    {
      id: 'xlsx' as ExportFormat,
      name: 'Excel Evidence Workbook (.xlsx)',
      badge: 'Multi-Sheet Forensic',
      icon: FileSpreadsheet,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-950/20',
      borderColor: 'border-emerald-500/30',
      description: 'Structured 12-sheet workbook with frozen header rows, autofilters, text-preserved hashes/IPs, and formula injection protection.'
    }
  ];

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-950 border border-slate-800 rounded-xl max-w-2xl w-full flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/90">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-cyan-950/60 border border-cyan-800/40 rounded-lg text-cyan-400">
              <Download className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <span>Export Forensic Investigation</span>
              </h2>
              <p className="text-xs text-slate-400">
                Generate and download canonical forensic evidence reports
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 text-slate-200">
          {/* Target Investigation Banner */}
          {analysis ? (
            <div className="p-3.5 bg-slate-900/60 border border-slate-800 rounded-lg flex items-center justify-between">
              <div className="space-y-0.5">
                <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                  Target Investigation
                </div>
                <div className="text-xs font-semibold text-slate-200 truncate max-w-md">
                  {analysis.envelope.subject || 'Untitled Investigation'}
                </div>
                <div className="text-[11px] font-mono text-slate-400 flex items-center gap-2">
                  <span>ID: {analysis.analysisId.slice(0, 12)}</span>
                  <span>·</span>
                  <span>From: {analysis.envelope.from?.address || 'Unknown'}</span>
                </div>
              </div>

              <div className="text-right">
                <span className={`inline-block px-2 py-0.5 text-[10px] font-mono font-bold uppercase rounded border ${
                  analysis.overallAssessment.score >= 65 
                    ? 'text-rose-400 bg-rose-950/40 border-rose-800/60'
                    : analysis.overallAssessment.score >= 35
                    ? 'text-amber-400 bg-amber-950/40 border-amber-800/60'
                    : 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60'
                }`}>
                  Risk {analysis.overallAssessment.score}/100
                </span>
              </div>
            </div>
          ) : (
            <div className="p-4 bg-rose-950/20 border border-rose-800/40 rounded-lg flex items-center gap-3 text-rose-300 text-xs">
              <AlertCircle className="w-5 h-5 shrink-0" />
              <span>No active investigation is selected. Please select an investigation in the dashboard to enable export.</span>
            </div>
          )}

          {/* Format Selection Cards */}
          <div className="space-y-2.5">
            <label className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold block">
              Select Export Format
            </label>

            <div className="grid grid-cols-1 gap-2.5">
              {formatCards.map(format => {
                const Icon = format.icon;
                const isSelected = selectedFormat === format.id;

                return (
                  <button
                    key={format.id}
                    type="button"
                    onClick={() => {
                      setSelectedFormat(format.id);
                      setExportSuccess(null);
                    }}
                    className={`w-full text-left p-3.5 rounded-xl border transition-all flex items-start gap-3.5 ${
                      isSelected 
                        ? 'bg-slate-900 border-cyan-500 shadow-md shadow-cyan-950/20 ring-1 ring-cyan-500/50'
                        : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/70'
                    }`}
                  >
                    <div className={`p-2 rounded-lg border shrink-0 ${format.bgColor} ${format.borderColor} ${format.color}`}>
                      <Icon className="w-5 h-5" />
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="text-xs font-bold text-slate-100">
                          {format.name}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {format.badge}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        {format.description}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Options & Privacy Safeguards */}
          <div className="space-y-3 pt-2 border-t border-slate-800">
            <label className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold block">
              Forensic &amp; Privacy Controls
            </label>

            {/* Analyst Name Optional Field */}
            <div className="flex flex-col gap-1 text-xs">
              <span className="text-slate-400">Analyst / Case Examiner Name (Optional):</span>
              <input
                type="text"
                value={analystName}
                onChange={e => setAnalystName(e.target.value)}
                placeholder="e.g. SOC Analyst #418"
                className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Checkbox: Sensitive Data Inclusion */}
            <div className="p-3 bg-slate-900/40 border border-slate-800 rounded-lg space-y-1.5">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeSensitive}
                  onChange={e => setIncludeSensitive(e.target.checked)}
                  className="mt-0.5 rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0"
                />
                <div className="space-y-0.5">
                  <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                    <span>Include sensitive raw email text snippet &amp; raw headers</span>
                    {includeSensitive ? (
                      <Eye className="w-3.5 h-3.5 text-amber-400" />
                    ) : (
                      <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 leading-normal">
                    By default, exports are sanitized to forensic indicators, defanged URLs, and routing hops without embedding the original email body text. Enabling this option embeds the full body snippet.
                  </p>
                </div>
              </label>
            </div>

            {/* Checkbox: SHA-256 Checksum */}
            <label className="flex items-center gap-2.5 cursor-pointer text-xs text-slate-300">
              <input
                type="checkbox"
                checked={includeChecksum}
                onChange={e => setIncludeChecksum(e.target.checked)}
                className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0"
              />
              <span className="flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                <span>Calculate &amp; embed canonical SHA-256 integrity checksum</span>
              </span>
            </label>
          </div>

          {/* Feedback Banners */}
          {exportSuccess && (
            <div className="p-3 bg-emerald-950/30 border border-emerald-800/50 rounded-lg flex items-center gap-2 text-xs text-emerald-300 animate-in fade-in">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
              <span className="truncate">{exportSuccess}</span>
            </div>
          )}

          {errorMessage && (
            <div className="p-3 bg-rose-950/30 border border-rose-800/50 rounded-lg flex items-center gap-2 text-xs text-rose-300 animate-in fade-in">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{errorMessage}</span>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <div className="text-[11px] font-mono text-slate-500">
            Filename: PhishScope_Investigation_...
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={onClose}
              disabled={isExporting}
              className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleExport}
              disabled={!analysis || isExporting}
              className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg shadow-sm transition-colors flex items-center gap-2"
            >
              {isExporting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Generating {selectedFormat.toUpperCase()}...</span>
                </>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  <span>Download {selectedFormat.toUpperCase()}</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
