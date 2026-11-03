import React, { useState, useRef } from 'react';
import { 
  UploadCloud, 
  FileText, 
  Shield, 
  AlertCircle, 
  CheckCircle2, 
  Loader2,
  FileCode
} from 'lucide-react';
import { SyntheticFixture } from '../../server/fixtures/syntheticEmails';

interface IngestionViewProps {
  onAnalyzeRaw: (content: string, filename?: string, isFile?: boolean) => Promise<void>;
  onLoadFixture: (fixtureId: string) => Promise<void>;
  fixtures: Array<{
    id: string;
    name: string;
    category: string;
    description: string;
    expectedLabel: string;
  }>;
  isLoading: boolean;
}

export const IngestionView: React.FC<IngestionViewProps> = ({
  onAnalyzeRaw,
  onLoadFixture,
  fixtures,
  isLoading
}) => {
  const [activeMode, setActiveMode] = useState<'upload' | 'paste' | 'fixtures'>('upload');
  const [pastedText, setPastedText] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFile = (file: File) => {
    setUploadError(null);
    if (!file.name.endsWith('.eml') && !file.name.endsWith('.txt') && !file.name.endsWith('.msg')) {
      setUploadError('Unsupported file type. Please upload a standard RFC 5322 .eml or raw text message.');
      return;
    }

    if (file.size > 15 * 1024 * 1024) {
      setUploadError('File size exceeds the 15MB request safety threshold.');
      return;
    }

    const reader = new FileReader();
    reader.onload = async (e) => {
      const content = e.target?.result as string;
      if (content) {
        await onAnalyzeRaw(content, file.name, true);
      }
    };
    reader.onerror = () => {
      setUploadError('Error reading file from disk.');
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  };

  const handlePasteSubmit = async () => {
    if (!pastedText.trim()) return;
    await onAnalyzeRaw(pastedText.trim(), 'pasted_message.eml', false);
  };

  return (
    <div className="max-w-4xl mx-auto py-8 px-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">
          Email Threat Ingestion
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Ingest raw MIME email files, pasted RFC headers, or load forensic benchmark fixtures.
        </p>
      </div>

      {/* Privacy Notice Card */}
      <div className="p-4 bg-slate-900/80 border border-cyan-900/40 rounded flex items-start gap-3">
        <Shield className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-300 space-y-1">
          <div className="font-semibold text-slate-200">
            Privacy &amp; In-Memory Data Retention Boundary
          </div>
          <p className="text-slate-400 leading-relaxed">
            All uploaded <code className="font-mono text-cyan-300">.eml</code> files and pasted messages are processed exclusively in-memory in temporary request-scoped memory. Raw email content, passwords, tokens, and attachments are <strong className="text-slate-200">never permanently stored on disk</strong> and never used for model training. Session data will clear when you close your browser or click "Wipe Session".
          </p>
        </div>
      </div>

      {/* Ingestion Mode Segmented Tabs */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveMode('upload')}
          className={`px-4 py-2.5 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeMode === 'upload'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          <span>Upload .eml File</span>
        </button>

        <button
          onClick={() => setActiveMode('paste')}
          className={`px-4 py-2.5 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeMode === 'paste'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>Paste Raw / Partial Email</span>
        </button>

        <button
          onClick={() => setActiveMode('fixtures')}
          className={`px-4 py-2.5 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeMode === 'fixtures'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode className="w-4 h-4" />
          <span>Synthetic Test Fixtures</span>
        </button>
      </div>

      {/* Mode 1: File Upload */}
      {activeMode === 'upload' && (
        <div className="space-y-4">
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-colors ${
              dragOver
                ? 'border-cyan-400 bg-cyan-950/20'
                : 'border-slate-800 hover:border-slate-700 bg-slate-900/40'
            }`}
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
              accept=".eml,.txt,.msg"
              className="hidden"
            />
            {isLoading ? (
              <div className="flex flex-col items-center justify-center space-y-3">
                <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
                <div className="text-sm font-medium text-slate-200">
                  Executing Forensic Analysis Pipeline...
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Parsing MIME hops · Verifying SPF/DKIM · Resolving DNS
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="w-12 h-12 mx-auto rounded-full bg-slate-800 flex items-center justify-center text-slate-400">
                  <UploadCloud className="w-6 h-6 text-cyan-400" />
                </div>
                <div>
                  <div className="text-sm font-semibold text-slate-200">
                    Drop your raw .eml email file here, or click to browse
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    Supports complete RFC 5322 MIME messages up to 15MB.
                  </div>
                </div>
              </div>
            )}
          </div>

          {uploadError && (
            <div className="p-3 bg-rose-950/40 border border-rose-900/60 rounded text-xs text-rose-300 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}
        </div>
      )}

      {/* Mode 2: Paste Raw / Headers / Body */}
      {activeMode === 'paste' && (
        <div className="space-y-4">
          <div className="p-3 bg-slate-900 border border-slate-800 rounded text-xs text-slate-400 space-y-1">
            <div className="font-semibold text-slate-300">
              Guidance for Pasted Inputs:
            </div>
            <ul className="list-disc list-inside space-y-0.5 text-slate-400">
              <li>
                <strong className="text-slate-300">Complete Raw Message:</strong> Includes full headers (Received, From, Subject, Authentication-Results) + body. Yields complete forensic hop analysis.
              </li>
              <li>
                <strong className="text-slate-300">Headers Only:</strong> Evaluates SMTP routing, SPF/DKIM declarations, and sender alignment.
              </li>
              <li>
                <strong className="text-slate-300">Body Only:</strong> Evaluates URLs, anchor mismatches, and social engineering cues. Received hops and SPF/DKIM will be flagged as <span className="text-amber-400">Missing Evidence</span>.
              </li>
            </ul>
          </div>

          <textarea
            value={pastedText}
            onChange={(e) => setPastedText(e.target.value)}
            placeholder="Paste raw email contents or RFC 5322 headers here (e.g., Received: from ...)..."
            rows={14}
            className="w-full p-4 bg-slate-900 border border-slate-800 rounded text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 leading-relaxed"
          />

          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-slate-400">
              Characters: {pastedText.length.toLocaleString()}
            </span>
            <button
              onClick={handlePasteSubmit}
              disabled={isLoading || !pastedText.trim()}
              className="px-5 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors flex items-center gap-2"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Processing Forensics...</span>
                </>
              ) : (
                <span>Analyze Pasted Content &rarr;</span>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Mode 3: Synthetic Test Fixtures */}
      {activeMode === 'fixtures' && (
        <div className="space-y-4">
          <p className="text-xs text-slate-400">
            Select one of the pre-configured forensic fixtures to inspect specific threat signatures without needing external sample files:
          </p>

          <div className="space-y-2.5">
            {fixtures.map((f) => (
              <div
                key={f.id}
                className="p-4 bg-slate-900/60 border border-slate-800 rounded flex items-center justify-between gap-4 hover:border-slate-700 transition-colors"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5">
                    <span className="text-xs font-semibold text-slate-100">
                      {f.name}
                    </span>
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">
                      {f.category.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    {f.description}
                  </p>
                </div>

                <button
                  onClick={() => onLoadFixture(f.id)}
                  disabled={isLoading}
                  className="px-3.5 py-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800/60 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-1.5"
                >
                  {isLoading ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <span>Load &amp; Analyze</span>
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
