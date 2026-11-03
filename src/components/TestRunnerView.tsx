import React, { useState } from 'react';
import { 
  CheckCircle2, 
  XCircle, 
  Play, 
  Loader2, 
  Terminal, 
  ShieldCheck, 
  AlertCircle,
  Clock
} from 'lucide-react';
import { TestSuiteSummary } from '../../tests/run_tests';

export const TestRunnerView: React.FC = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [suite, setSuite] = useState<TestSuiteSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRunTests = async () => {
    setIsRunning(true);
    setError(null);
    try {
      const res = await fetch('/api/test/run', { method: 'POST' });
      if (!res.ok) {
        throw new Error('Test execution endpoint failed.');
      }
      const data: TestSuiteSummary = await res.json();
      setSuite(data);
    } catch (err: any) {
      setError(err.message || 'Error running test suite.');
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto py-8 px-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400" />
            <span>Automated Forensic Verification Test Suite</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real automated unit and integration tests executing in-process against RFC email parsing, routing algorithms, auth checks, and privacy cleanup.
          </p>
        </div>

        <button
          onClick={handleRunTests}
          disabled={isRunning}
          className="px-4 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 shadow-sm font-sans"
        >
          {isRunning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Executing Tests...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-slate-950" />
              <span>Run Automated Test Suite</span>
            </>
          )}
        </button>
      </div>

      {/* Synthetic Benchmark Integrity Notice */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded flex items-start gap-3">
        <AlertCircle className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <div className="font-semibold text-slate-200">
            Testing Integrity Disclaimer (Section 20 Compliance)
          </div>
          <p className="text-slate-400 leading-relaxed">
            All test fixtures in this suite are synthetic, standardized test cases designed for software regression testing, boundary condition verification, and parser validation. They are <strong className="text-slate-200">not</strong> claimed as statistical proof of real-world operational detection performance.
          </p>
        </div>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-950/40 border border-rose-900/60 rounded text-xs text-rose-300 flex items-center gap-2">
          <XCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Summary Stats Banner when Suite has run */}
      {suite && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
            <div className="text-xs text-slate-400">Total Tests</div>
            <div className="text-xl font-bold font-mono text-slate-100 mt-1">{suite.total}</div>
          </div>
          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
            <div className="text-xs text-emerald-400">Passed</div>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{suite.passed}</div>
          </div>
          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
            <div className="text-xs text-rose-400">Failed</div>
            <div className="text-xl font-bold font-mono text-rose-400 mt-1">{suite.failed}</div>
          </div>
          <div className="p-3 bg-slate-900/60 border border-slate-800 rounded">
            <div className="text-xs text-slate-400">Execution Time</div>
            <div className="text-xl font-bold font-mono text-cyan-300 mt-1">{suite.durationMs}ms</div>
          </div>
        </div>
      )}

      {/* Test Results Table */}
      {suite ? (
        <div className="border border-slate-800 rounded overflow-hidden bg-slate-900/40">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
              <tr>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Test Identifier</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Test Name &amp; Assertion</th>
                <th className="py-2.5 px-3 text-right">Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 font-mono">
              {suite.results.map((r) => (
                <tr key={r.id} className={r.passed ? '' : 'bg-rose-950/20'}>
                  <td className="py-2.5 px-3">
                    {r.passed ? (
                      <span className="flex items-center gap-1.5 text-emerald-400 font-bold text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>PASS</span>
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 text-rose-400 font-bold text-[11px]">
                        <XCircle className="w-3.5 h-3.5" />
                        <span>FAIL</span>
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-slate-300">
                    {r.id}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">
                    {r.category}
                  </td>
                  <td className="py-2.5 px-3 font-sans text-slate-200">
                    <div>{r.name}</div>
                    {r.details && (
                      <div className="text-rose-400 text-[11px] font-mono mt-0.5">
                        {r.details}
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-right text-slate-400 tabular-nums">
                    {r.durationMs}ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="p-12 border border-dashed border-slate-800 rounded text-center bg-slate-900/30 space-y-3">
          <Terminal className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-xs font-semibold text-slate-300">
            Automated Tests Ready for Execution
          </div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Click "Run Automated Test Suite" above to verify all 14 RFC parsing, routing anomaly, IP classification, auth verification, and privacy purge tests.
          </p>
        </div>
      )}
    </div>
  );
};
