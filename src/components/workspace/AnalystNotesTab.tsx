import React, { useState } from 'react';
import { 
  FileEdit, 
  Printer, 
  Download, 
  Save, 
  Check, 
  FileText,
  ShieldCheck
} from 'lucide-react';
import { EmailAnalysis } from '../../types/forensics';

interface AnalystNotesTabProps {
  analysis: EmailAnalysis;
  onUpdateAnalysis: (updated: EmailAnalysis) => void;
  onOpenReportModal: () => void;
}

export const AnalystNotesTab: React.FC<AnalystNotesTabProps> = ({
  analysis,
  onUpdateAnalysis,
  onOpenReportModal
}) => {
  const [notes, setNotes] = useState(analysis.analystNotes || '');
  const [isSaved, setIsSaved] = useState(false);

  const handleSaveNotes = async () => {
    try {
      const res = await fetch(`/api/analyses/${analysis.analysisId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ notes })
      });
      if (res.ok) {
        setIsSaved(true);
        setTimeout(() => setIsSaved(false), 2000);
        onUpdateAnalysis({
          ...analysis,
          analystNotes: notes
        });
      }
    } catch (err) {
      console.error('Failed to save notes:', err);
    }
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(analysis, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `phishscope_report_${analysis.analysisId.slice(0, 8)}.json`);
    dlAnchor.click();
  };

  return (
    <div className="space-y-6">
      {/* Analyst Case Notes */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileEdit className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Analyst Case Notes (Session Scoped)
            </h3>
          </div>
          <button
            onClick={handleSaveNotes}
            className="px-3 py-1 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors flex items-center gap-1.5"
          >
            {isSaved ? <Check className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
            <span>{isSaved ? 'Saved to Session' : 'Save Notes'}</span>
          </button>
        </div>

        <p className="text-xs text-slate-400">
          Document your forensic conclusions, user interviews, firewall correlation, or ticketing references. These notes are preserved in the current browser session.
        </p>

        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Enter investigation observations, SOC ticket ID, remediation actions taken..."
          rows={7}
          className="w-full p-3 bg-slate-950 border border-slate-800 rounded text-xs font-sans text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed"
        />
      </div>

      {/* Export & Reporting Actions */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
        <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <span>Report Generation &amp; Evidence Export</span>
        </h3>

        <p className="text-xs text-slate-400">
          Generate a formal cybersecurity investigation report with full evidence provenance, candidate routing IPs, authentication alignment, and analyst findings.
        </p>

        <div className="flex flex-wrap gap-3 pt-1">
          <button
            onClick={onOpenReportModal}
            className="px-4 py-2 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex items-center gap-2"
          >
            <Printer className="w-4 h-4 text-cyan-400" />
            <span>Generate Printable Forensic Report</span>
          </button>

          <button
            onClick={handleDownloadJson}
            className="px-4 py-2 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors flex items-center gap-2"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export Structured JSON (RFC Evidence)</span>
          </button>
        </div>
      </div>
    </div>
  );
};
