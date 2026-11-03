import React from 'react';
import { ShieldAlert, Trash2, PlusCircle } from 'lucide-react';

interface NavbarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  analysesCount: number;
  onClearSession: () => void;
  onNewAnalysis: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onSelectTab,
  analysesCount,
  onClearSession,
  onNewAnalysis
}) => {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'ingestion', label: 'Ingest Email' },
    { id: 'workspace', label: 'Investigation Workspace' },
    { id: 'correlation', label: 'Session Correlation' },
    { id: 'tests', label: 'Automated Tests' },
    { id: 'settings', label: 'Settings' }
  ];

  return (
    <header className="flex items-center justify-between gap-8 px-6 py-3.5 bg-slate-950 border-b border-slate-800 sticky top-0 z-50">
      {/* Zone 1: Single text element wordmark */}
      <div className="flex items-center gap-3">
        <button
          onClick={() => onSelectTab('dashboard')}
          className="flex items-center gap-2.5 text-slate-100 hover:text-white transition-colors text-left"
        >
          <div className="w-8 h-8 rounded bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div className="leading-tight">
            <span className="text-base font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0">
              PhishScope
            </span>
            <span className="hidden sm:inline text-xs text-slate-400 ml-2 font-mono">
              forensics &amp; threat intel
            </span>
          </div>
        </button>
      </div>

      {/* Zone 2: Concise navigation links with hover styles */}
      <nav className="hidden lg:flex items-center gap-6 text-sm font-medium text-slate-300">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => onSelectTab(item.id)}
            className={`whitespace-nowrap shrink-0 transition-colors py-1 relative ${
              currentTab === item.id
                ? 'text-cyan-400 font-semibold'
                : 'text-slate-300 hover:text-slate-100'
            }`}
          >
            {item.label}
            {item.id === 'workspace' && analysesCount > 0 && (
              <span className="ml-1.5 text-xs font-mono text-cyan-300 bg-cyan-950 px-1.5 py-0.5 rounded border border-cyan-800/60">
                {analysesCount}
              </span>
            )}
            {currentTab === item.id && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-cyan-400" />
            )}
          </button>
        ))}
      </nav>

      {/* Zone 3: Primary action button + session utilities */}
      <div className="flex items-center gap-3 shrink-0">
        {analysesCount > 0 && (
          <button
            onClick={onClearSession}
            title="Wipe in-memory session records"
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 rounded border border-slate-800 transition-colors whitespace-nowrap shrink-0"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Wipe Session</span>
          </button>
        )}

        <button
          onClick={onNewAnalysis}
          className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors whitespace-nowrap shrink-0 shadow-sm font-sans"
        >
          <PlusCircle className="w-4 h-4" />
          <span>Analyze Email</span>
        </button>
      </div>
    </header>
  );
};
