import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Layers, 
  Key, 
  Link2, 
  Server, 
  Network, 
  Sparkles, 
  FileEdit,
  ArrowLeft,
  Calendar,
  User,
  Mail,
  Download
} from 'lucide-react';
import { EmailAnalysis } from '../types/forensics';
import { OverviewTab } from './workspace/OverviewTab';
import { HeaderForensicsTab } from './workspace/HeaderForensicsTab';
import { AuthenticationTab } from './workspace/AuthenticationTab';
import { ContentUrlsTab } from './workspace/ContentUrlsTab';
import { InfrastructureTab } from './workspace/InfrastructureTab';
import { GraphView } from './workspace/GraphView';
import { GeminiAssistantTab } from './workspace/GeminiAssistantTab';
import { AnalystNotesTab } from './workspace/AnalystNotesTab';
import { ExportModal } from './ExportModal';

interface InvestigationWorkspaceProps {
  analysis: EmailAnalysis;
  onUpdateAnalysis: (updated: EmailAnalysis) => void;
  onBackToDashboard: () => void;
  onOpenReportModal: () => void;
}

export const InvestigationWorkspace: React.FC<InvestigationWorkspaceProps> = ({
  analysis,
  onUpdateAnalysis,
  onBackToDashboard,
  onOpenReportModal
}) => {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);

  const tabs = [
    { id: 'overview', label: 'Overview & Risk', icon: ShieldAlert },
    { id: 'headers', label: 'Header Forensics', icon: Layers },
    { id: 'auth', label: 'Authentication', icon: Key },
    { id: 'content', label: 'URLs & Content', icon: Link2 },
    { id: 'infra', label: 'Infrastructure Intel', icon: Server },
    { id: 'graph', label: 'Relationship Graph', icon: Network },
    { id: 'ai', label: 'Gemini Assistant', icon: Sparkles },
    { id: 'notes', label: 'Notes & Report', icon: FileEdit }
  ];

  return (
    <div className="max-w-7xl mx-auto py-6 px-6 space-y-6">
      {/* Top Breadcrumb & Metadata Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="space-y-1">
          <button
            onClick={onBackToDashboard}
            className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Dashboard</span>
          </button>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Investigation:</span>
            <span className="text-cyan-300 font-mono text-base">
              {analysis.envelope.subject || 'Untitled Message'}
            </span>
          </h1>
          <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-1">
              <User className="w-3.5 h-3.5 text-slate-500" />
              <span>{analysis.envelope.from?.address || 'Unknown From'}</span>
            </span>
            <span>·</span>
            <span className="flex items-center gap-1">
              <Calendar className="w-3.5 h-3.5 text-slate-500" />
              <span>{analysis.envelope.date || analysis.createdAt}</span>
            </span>
            <span>·</span>
            <span className="text-cyan-400 font-bold uppercase">
              ID: {analysis.analysisId.slice(0, 8)}
            </span>
          </div>
        </div>

        {/* Quick Assessment Badge & Export Toolbar Action */}
        <div className="flex items-center gap-4">
          <button
            onClick={() => setIsExportModalOpen(true)}
            disabled={!analysis}
            title={!analysis ? 'No investigation selected' : 'Export this investigation as JSON, PDF, or Excel'}
            className="px-3.5 py-2 text-xs font-semibold text-slate-100 bg-slate-900 hover:bg-slate-800 hover:text-cyan-400 border border-slate-700 hover:border-cyan-500/50 rounded-lg shadow-sm transition-all flex items-center gap-2 group disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Download className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
            <span>Export Investigation</span>
          </button>

          <div className="h-8 w-px bg-slate-800 hidden sm:block" />

          <div className="text-right">
            <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
              Risk Score
            </div>
            <div className={`text-2xl font-bold font-mono tabular-nums ${
              analysis.overallAssessment.score >= 65 ? 'text-rose-400' :
              analysis.overallAssessment.score >= 35 ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {analysis.overallAssessment.score}/100
            </div>
          </div>
        </div>
      </div>

      {/* Workspace Tabs Navigation */}
      <div className="flex border-b border-slate-800 overflow-x-auto space-x-1 pb-px scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-2.5 text-xs font-medium border-b-2 transition-colors whitespace-nowrap shrink-0 ${
                isActive
                  ? 'border-cyan-400 text-cyan-400 bg-cyan-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Active Tab Viewport */}
      <div className="pt-2">
        {activeTab === 'overview' && (
          <OverviewTab
            analysis={analysis}
            onNavigateTab={setActiveTab}
          />
        )}
        {activeTab === 'headers' && (
          <HeaderForensicsTab analysis={analysis} />
        )}
        {activeTab === 'auth' && (
          <AuthenticationTab analysis={analysis} />
        )}
        {activeTab === 'content' && (
          <ContentUrlsTab analysis={analysis} />
        )}
        {activeTab === 'infra' && (
          <InfrastructureTab analysis={analysis} />
        )}
        {activeTab === 'graph' && (
          <GraphView
            nodes={analysis.graph.nodes}
            edges={analysis.graph.edges}
            title={`Infrastructure Graph: ${analysis.envelope.subject || analysis.analysisId.slice(0, 8)}`}
          />
        )}
        {activeTab === 'ai' && (
          <GeminiAssistantTab
            analysis={analysis}
            onUpdateAnalysis={onUpdateAnalysis}
          />
        )}
        {activeTab === 'notes' && (
          <AnalystNotesTab
            analysis={analysis}
            onUpdateAnalysis={onUpdateAnalysis}
            onOpenReportModal={onOpenReportModal}
          />
        )}
      </div>

      {/* Forensic Investigation Export Modal */}
      <ExportModal
        analysis={analysis}
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
      />
    </div>
  );
};
