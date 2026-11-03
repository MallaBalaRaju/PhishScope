import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { DashboardView } from './components/DashboardView';
import { IngestionView } from './components/IngestionView';
import { InvestigationWorkspace } from './components/InvestigationWorkspace';
import { GlobalCorrelationView } from './components/GlobalCorrelationView';
import { TestRunnerView } from './components/TestRunnerView';
import { SettingsView } from './components/SettingsView';
import { ReportModal } from './components/ReportModal';
import { EmailAnalysis, SessionMetrics } from './types/forensics';
import { Loader2 } from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState<EmailAnalysis | null>(null);
  const [fixtures, setFixtures] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<SessionMetrics>({
    totalAnalyzed: 0,
    phishingCount: 0,
    suspiciousCount: 0,
    legitimateCount: 0,
    inconclusiveCount: 0,
    authenticationWarningsCount: 0,
    suspiciousRoutingCount: 0
  });
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [reportModalOpen, setReportModalOpen] = useState<boolean>(false);

  const fetchSessionData = async () => {
    try {
      const [analysesRes, healthRes, fixturesRes] = await Promise.all([
        fetch('/api/analyses'),
        fetch('/api/health'),
        fetch('/api/fixtures')
      ]);

      if (analysesRes.ok) {
        const analysesData = await analysesRes.json();
        setAnalyses(analysesData);
      }
      if (healthRes.ok) {
        const healthData = await healthRes.json();
        if (healthData.sessionMetrics) {
          setMetrics(healthData.sessionMetrics);
        }
      }
      if (fixturesRes.ok) {
        const fixturesData = await fixturesRes.json();
        setFixtures(fixturesData);
      }
    } catch (err) {
      console.error('Failed to fetch session data:', err);
    }
  };

  useEffect(() => {
    fetchSessionData();
  }, []);

  const handleSelectAnalysis = async (id: string) => {
    setIsLoading(true);
    try {
      const res = await fetch(`/api/analyses/${id}`);
      if (res.ok) {
        const data: EmailAnalysis = await res.json();
        setSelectedAnalysis(data);
        setCurrentTab('workspace');
      }
    } catch (err) {
      console.error('Failed to load analysis:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnalyzeRaw = async (content: string, filename?: string, isFile = false) => {
    setIsLoading(true);
    try {
      let res: Response;
      if (isFile) {
        res = await fetch('/api/analyze/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fileContent: content, filename })
        });
      } else {
        res = await fetch('/api/analyze/paste', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content, sourceName: filename })
        });
      }

      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.error || 'Pipeline execution failed.');
      }

      const newAnalysis: EmailAnalysis = await res.json();
      setSelectedAnalysis(newAnalysis);
      setCurrentTab('workspace');
      await fetchSessionData();
    } catch (err: any) {
      alert(`Forensic analysis error: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleLoadFixture = async (fixtureId: string) => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/analyze/sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fixtureId })
      });

      if (!res.ok) {
        throw new Error('Failed to load synthetic fixture.');
      }

      const newAnalysis: EmailAnalysis = await res.json();
      setSelectedAnalysis(newAnalysis);
      setCurrentTab('workspace');
      await fetchSessionData();
    } catch (err: any) {
      alert(`Error loading fixture: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearSession = async () => {
    if (!confirm('Are you sure you want to wipe all in-memory session analyses?')) {
      return;
    }
    try {
      await fetch('/api/analyses', { method: 'DELETE' });
      setSelectedAnalysis(null);
      setCurrentTab('dashboard');
      await fetchSessionData();
    } catch (err) {
      console.error('Failed to clear session:', err);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      <Navbar
        currentTab={currentTab}
        onSelectTab={(tab) => {
          if (tab === 'workspace' && !selectedAnalysis && analyses.length > 0) {
            handleSelectAnalysis(analyses[0].analysisId);
          } else {
            setCurrentTab(tab);
          }
        }}
        analysesCount={analyses.length}
        onClearSession={handleClearSession}
        onNewAnalysis={() => setCurrentTab('ingestion')}
      />

      <main className="flex-1 pb-16">
        {currentTab === 'dashboard' && (
          <DashboardView
            metrics={metrics}
            analyses={analyses}
            onSelectAnalysis={handleSelectAnalysis}
            onNavigate={(tab) => setCurrentTab(tab)}
            onLoadSample={handleLoadFixture}
          />
        )}

        {currentTab === 'ingestion' && (
          <IngestionView
            onAnalyzeRaw={handleAnalyzeRaw}
            onLoadFixture={handleLoadFixture}
            fixtures={fixtures}
            isLoading={isLoading}
          />
        )}

        {currentTab === 'workspace' && (
          selectedAnalysis ? (
            <InvestigationWorkspace
              analysis={selectedAnalysis}
              onUpdateAnalysis={(updated) => {
                setSelectedAnalysis(updated);
                fetchSessionData();
              }}
              onBackToDashboard={() => setCurrentTab('dashboard')}
              onOpenReportModal={() => setReportModalOpen(true)}
            />
          ) : (
            <div className="max-w-xl mx-auto py-16 px-6 text-center space-y-4">
              <h2 className="text-lg font-bold text-slate-100">
                No Email Selected for Investigation
              </h2>
              <p className="text-xs text-slate-400">
                Choose an email from your dashboard history or ingest a new RFC email file to open the forensic workspace.
              </p>
              <div className="flex justify-center gap-3 pt-2">
                <button
                  onClick={() => setCurrentTab('dashboard')}
                  className="px-4 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors"
                >
                  Go to Dashboard
                </button>
                <button
                  onClick={() => setCurrentTab('ingestion')}
                  className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
                >
                  Ingest Email
                </button>
              </div>
            </div>
          )
        )}

        {currentTab === 'correlation' && (
          <GlobalCorrelationView />
        )}

        {currentTab === 'tests' && (
          <TestRunnerView />
        )}

        {currentTab === 'settings' && (
          <SettingsView onClearSession={handleClearSession} />
        )}
      </main>

      {/* Global Printable Report Modal */}
      {reportModalOpen && selectedAnalysis && (
        <ReportModal
          analysis={selectedAnalysis}
          onClose={() => setReportModalOpen(false)}
        />
      )}
    </div>
  );
}
