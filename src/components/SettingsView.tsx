import React, { useState, useEffect } from 'react';
import { 
  Settings, 
  Cpu, 
  Sparkles, 
  Globe, 
  Shield, 
  Trash2, 
  Check, 
  AlertCircle,
  Database,
  Lock,
  Server,
  Network,
  RefreshCw,
  ExternalLink,
  ShieldAlert
} from 'lucide-react';

interface SettingsViewProps {
  onClearSession: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onClearSession }) => {
  const [healthData, setHealthData] = useState<any>(null);
  const [modelEntries, setModelEntries] = useState<any[]>([]);
  const [activeModelId, setActiveModelId] = useState<string>('unconfigured-baseline');
  const [isUpdatingModel, setIsUpdatingModel] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Remote connector configuration state
  const [remoteEndpointUrl, setRemoteEndpointUrl] = useState('');
  const [remoteAuthToken, setRemoteAuthToken] = useState('');
  const [remoteTimeoutMs, setRemoteTimeoutMs] = useState(5000);
  const [allowLocalhost, setAllowLocalhost] = useState(true);
  const [isConfiguringRemote, setIsConfiguringRemote] = useState(false);

  const fetchHealthAndModels = async () => {
    try {
      const [healthRes, modelsRes, remoteRes] = await Promise.all([
        fetch('/api/health'),
        fetch('/api/models'),
        fetch('/api/models/remote')
      ]);

      if (healthRes.ok) {
        const health = await healthRes.json();
        setHealthData(health);
      }
      if (modelsRes.ok) {
        const models = await modelsRes.json();
        setModelEntries(models.models || []);
        setActiveModelId(models.active || 'unconfigured-baseline');
      }
      if (remoteRes.ok) {
        const remoteConf = await remoteRes.json();
        setRemoteEndpointUrl(remoteConf.endpointUrl || '');
        setRemoteTimeoutMs(remoteConf.timeoutMs || 5000);
        setAllowLocalhost(remoteConf.allowLocalhost !== false);
      }
    } catch (err) {
      console.error('Failed to load settings:', err);
    }
  };

  useEffect(() => {
    fetchHealthAndModels();
  }, []);

  const handleSelectModel = async (modelId: string) => {
    setIsUpdatingModel(true);
    setFeedbackMsg(null);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/models/select', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ modelId })
      });
      if (res.ok) {
        setActiveModelId(modelId);
        setFeedbackMsg(`Active ML inference adapter switched to '${modelId}'. Note: Analysis version snapshots lock at start of each run.`);
        setTimeout(() => setFeedbackMsg(null), 4000);
        await fetchHealthAndModels();
      } else {
        const errJson = await res.json();
        setErrorMsg(errJson.error || 'Failed to switch active model.');
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Error updating active model.');
    } finally {
      setIsUpdatingModel(false);
    }
  };

  const handleSaveRemoteConfig = async () => {
    setIsConfiguringRemote(true);
    setFeedbackMsg(null);
    setErrorMsg(null);
    try {
      const res = await fetch('/api/models/remote/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpointUrl: remoteEndpointUrl.trim(),
          authToken: remoteAuthToken.trim() || undefined,
          timeoutMs: remoteTimeoutMs,
          allowLocalhost
        })
      });
      const data = await res.json();
      if (res.ok) {
        setFeedbackMsg('Remote model-serving connector destination validated and updated.');
        setTimeout(() => setFeedbackMsg(null), 4000);
        await fetchHealthAndModels();
      } else {
        setErrorMsg(data.error || 'Failed to update remote endpoint configuration.');
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Error updating remote configuration.');
    } finally {
      setIsConfiguringRemote(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto py-8 px-6 space-y-6">
      <div className="border-b border-slate-800 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <Settings className="w-5 h-5 text-cyan-400" />
            <span>Model Registry &amp; System Configuration</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Provider-independent model adapter management, runtime model switching, SSRF protection, and privacy boundaries.
          </p>
        </div>

        <button
          onClick={fetchHealthAndModels}
          className="px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors flex items-center gap-1.5 self-start"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Status</span>
        </button>
      </div>

      {feedbackMsg && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-900/60 rounded text-xs text-emerald-300 flex items-center gap-2">
          <Check className="w-4 h-4 shrink-0" />
          <span>{feedbackMsg}</span>
        </div>
      )}

      {errorMsg && (
        <div className="p-3 bg-rose-950/40 border border-rose-900/60 rounded text-xs text-rose-300 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* 1. Model Registry & Selection (Requirements 1, 4, 6) */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Provider-Independent Model Registry (6 Registered Entries)
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Active: <strong className="text-cyan-300">{activeModelId}</strong>
          </span>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Switch the active model for all future analysis runs. Under <strong className="text-slate-300">Requirement 4</strong>, every ongoing analysis locks an immutable version snapshot of its active model at invocation time; changing selection here will not alter already completed or running investigations.
        </p>

        <div className="space-y-2.5 pt-1">
          {modelEntries.map((entry) => {
            const isSelected = activeModelId === entry.id;
            const health = entry.health || entry.status || {};
            const isHealthy = health.isHealthy ?? health.healthy ?? true;
            const isAvailable = health.isAvailable ?? health.available ?? false;
            const isExpValidated = health.isExperimentallyValidated ?? false;
            const classificationStr = (entry.classification || entry.classificationType || 'research_model').replace(/_/g, ' ');

            return (
              <div
                key={entry.id}
                onClick={() => handleSelectModel(entry.id)}
                className={`p-3.5 rounded border cursor-pointer transition-colors flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                  isSelected
                    ? 'border-cyan-400 bg-cyan-950/30'
                    : 'border-slate-800 hover:border-slate-700 bg-slate-950/60'
                }`}
              >
                <div className="space-y-1">
                  <div className="text-xs font-semibold text-slate-100 flex flex-wrap items-center gap-2">
                    <span>{entry.name}</span>
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">
                      v{entry.version}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                      prep: {entry.preprocessingVersion}
                    </span>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-purple-300 bg-purple-950/50 border border-purple-800 px-1.5 py-0.5 rounded">
                      {classificationStr}
                    </span>
                  </div>

                  {/* Discrete Status Flags (Requirement 6) */}
                  <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono">
                    <span className={isHealthy ? 'text-emerald-400' : 'text-rose-400'}>
                      ● {isHealthy ? 'Healthy' : 'Unhealthy'}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className={isAvailable ? 'text-emerald-400' : 'text-slate-400'}>
                      {isAvailable ? 'Available' : 'Unavailable'}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className={isExpValidated ? 'text-emerald-400' : 'text-amber-400'}>
                      {isExpValidated ? 'Experimentally Validated' : 'Not Experimentally Validated (Research Baseline)'}
                    </span>
                  </div>

                  {(health.statusMessage || health.healthMessage) && (
                    <div className="text-[11px] text-slate-400 font-sans">
                      {health.statusMessage || health.healthMessage}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${
                    isSelected ? 'border-cyan-400 bg-cyan-400' : 'border-slate-600'
                  }`}>
                    {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-slate-950" />}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 2. Remote Model-Serving Connector Configuration (Requirement 5) */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200">
              Remote HTTP Model-Serving Connector Settings
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyan-400 border border-cyan-800 bg-cyan-950 px-2 py-0.5 rounded">
            SSRF Hardened
          </span>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          Configure an external Python FastAPI, TorchServe, or Triton inference service. Security policies enforce HTTPS for external endpoints, block cloud instance metadata (169.254.169.254), apply a 5000ms timeout, and enforce zero silent fallback on error.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="sm:col-span-2 space-y-1">
            <label className="text-slate-300 font-mono text-xs">
              Inference Endpoint URL:
            </label>
            <input
              type="text"
              value={remoteEndpointUrl}
              onChange={(e) => setRemoteEndpointUrl(e.target.value)}
              placeholder="e.g. http://localhost:8000/predict or https://inference.internal.org/predict"
              className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="space-y-1">
            <label className="text-slate-300 font-mono text-xs">
              Bearer Authorization Token (Optional):
            </label>
            <input
              type="password"
              value={remoteAuthToken}
              onChange={(e) => setRemoteAuthToken(e.target.value)}
              placeholder="••••••••••••"
              className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="space-y-1">
            <label className="text-slate-300 font-mono text-xs">
              Request Timeout (ms):
            </label>
            <input
              type="number"
              value={remoteTimeoutMs}
              onChange={(e) => setRemoteTimeoutMs(parseInt(e.target.value, 10) || 5000)}
              min={1000}
              max={30000}
              className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="sm:col-span-2 flex items-center gap-2 pt-1">
            <input
              type="checkbox"
              id="allowLocalhost"
              checked={allowLocalhost}
              onChange={(e) => setAllowLocalhost(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-cyan-400 focus:ring-0"
            />
            <label htmlFor="allowLocalhost" className="text-xs text-slate-300 font-mono">
              Allow Localhost &amp; Loopback (for local development microservices on 127.0.0.1)
            </label>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={handleSaveRemoteConfig}
            disabled={isConfiguringRemote}
            className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded transition-colors"
          >
            {isConfiguringRemote ? 'Validating Destination...' : 'Save & Validate Remote Endpoint'}
          </button>
        </div>
      </div>

      {/* 3. Session Evidence Purge */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded space-y-3">
        <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
          <Trash2 className="w-4 h-4 text-rose-400" />
          <span>Session Evidence Purge &amp; Data Hygiene</span>
        </h3>

        <p className="text-xs text-slate-400">
          Immediately expunge all in-memory investigation analyses, extracted URLs, forensic findings, and correlation graphs from the server process.
        </p>

        <button
          onClick={onClearSession}
          className="px-4 py-2 text-xs font-medium text-rose-300 hover:text-white bg-rose-950 hover:bg-rose-900 border border-rose-800 rounded transition-colors flex items-center gap-2"
        >
          <Trash2 className="w-4 h-4" />
          <span>Wipe All In-Memory Session Data</span>
        </button>
      </div>
    </div>
  );
};
