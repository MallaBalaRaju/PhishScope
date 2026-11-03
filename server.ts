import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { executeAnalysisPipeline } from './server/pipeline';
import { SessionStore } from './server/store/sessionStore';
import { SYNTHETIC_FIXTURES } from './server/fixtures/syntheticEmails';
import { runGeminiInvestigationAssistant } from './server/assistant/geminiAssistant';
import { buildSessionCorrelationGraph } from './server/graph/graphEngine';
import { ModelRegistry } from './server/ml/modelRegistry';
import { runAllAutomatedTests } from './tests/run_tests';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const isProd = process.env.NODE_ENV === 'production';

  // Request size limit for large .eml inputs (up to 15MB)
  app.use(express.json({ limit: '15mb' }));
  app.use(express.text({ type: ['message/rfc822', 'text/plain'], limit: '15mb' }));

  const sessionStore = SessionStore.getInstance();
  const modelRegistry = ModelRegistry.getInstance();

  // --- API ROUTES ---

  // Health and System Status
  app.get('/api/health', async (req, res) => {
    const metrics = sessionStore.getMetrics();
    const activeModel = modelRegistry.getActiveAdapter();
    const modelStatus = await activeModel.getHealth();
    res.json({
      status: 'operational',
      timestamp: new Date().toISOString(),
      privacyMode: 'in-memory-session-only (zero permanent disk retention)',
      providers: {
        geminiAssistant: {
          configured: !!process.env.GEMINI_API_KEY,
          model: 'gemini-3.8-flash',
          status: process.env.GEMINI_API_KEY ? 'Active' : 'Unconfigured (Deterministic Fallback)'
        },
        mlClassification: {
          configured: modelStatus.isConfigured,
          activeModelId: activeModel.id,
          activeModelName: activeModel.name,
          version: activeModel.version,
          status: modelStatus.isConfigured ? 'Active (Configured)' : 'Unconfigured (Research Baseline)'
        },
        dnsResolver: {
          configured: true,
          status: 'Active (Local Node.js RFC/DNS)'
        },
        externalThreatIntel: {
          configured: !!process.env.THREAT_INTEL_API_KEY,
          status: process.env.THREAT_INTEL_API_KEY ? 'Active' : 'Unconfigured'
        }
      },
      sessionMetrics: metrics
    });
  });

  // Get available synthetic fixtures
  app.get('/api/fixtures', (req, res) => {
    res.json(SYNTHETIC_FIXTURES.map(f => ({
      id: f.id,
      name: f.name,
      category: f.category,
      description: f.description,
      expectedLabel: f.expectedLabel
    })));
  });

  // Analyze: Load synthetic fixture
  app.post('/api/analyze/sample', async (req, res) => {
    try {
      const { fixtureId } = req.body;
      const fixture = SYNTHETIC_FIXTURES.find(f => f.id === fixtureId);
      if (!fixture) {
        return res.status(404).json({ error: 'Fixture not found' });
      }

      const analysis = await executeAnalysisPipeline(fixture.rawContent, {
        sourceFilename: `${fixture.id}.eml`,
        isFileUpload: false
      });

      res.json(analysis);
    } catch (err: any) {
      console.error('Error analyzing sample fixture:', err);
      res.status(500).json({ error: err.message || 'Analysis pipeline failure' });
    }
  });

  // Analyze: Paste text or headers
  app.post('/api/analyze/paste', async (req, res) => {
    try {
      const { content, sourceName } = req.body;
      if (!content || typeof content !== 'string' || content.trim().length === 0) {
        return res.status(400).json({ error: 'Email content is required.' });
      }

      const analysis = await executeAnalysisPipeline(content, {
        sourceFilename: sourceName || 'pasted_submission.eml',
        isFileUpload: false
      });

      res.json(analysis);
    } catch (err: any) {
      console.error('Error analyzing pasted content:', err);
      res.status(500).json({ error: err.message || 'Analysis pipeline failure' });
    }
  });

  // Analyze: Upload .eml file
  app.post('/api/analyze/upload', async (req, res) => {
    try {
      const { fileContent, filename } = req.body;
      if (!fileContent) {
        return res.status(400).json({ error: 'No file content received.' });
      }

      const buffer = Buffer.from(fileContent, 'utf-8');
      const analysis = await executeAnalysisPipeline(buffer, {
        sourceFilename: filename || 'uploaded_sample.eml',
        isFileUpload: true
      });

      res.json(analysis);
    } catch (err: any) {
      console.error('Error analyzing uploaded file:', err);
      res.status(500).json({ error: err.message || 'Analysis pipeline failure' });
    }
  });

  // List all session analyses
  app.get('/api/analyses', (req, res) => {
    const list = sessionStore.getAllAnalyses().map(a => ({
      analysisId: a.analysisId,
      createdAt: a.createdAt,
      inputType: a.inputType,
      sourceFilename: a.sourceFilename,
      subject: a.envelope.subject || 'No Subject',
      sender: a.envelope.from?.address || 'Unknown Sender',
      assessment: a.overallAssessment.label,
      score: a.overallAssessment.score,
      confidence: a.overallAssessment.confidenceLevel,
      candidateIpsCount: a.forensicFindings.candidateSourceIps.length,
      urlsCount: a.contentFindings.urls.length
    }));
    res.json(list);
  });

  // Get specific analysis by ID
  app.get('/api/analyses/:id', (req, res) => {
    const analysis = sessionStore.getAnalysis(req.params.id);
    if (!analysis) {
      return res.status(404).json({ error: 'Investigation record not found or session expired.' });
    }
    res.json(analysis);
  });

  // Update analyst notes for an analysis
  app.post('/api/analyses/:id/notes', (req, res) => {
    const { notes } = req.body;
    const ok = sessionStore.updateAnalystNotes(req.params.id, String(notes || ''));
    if (!ok) {
      return res.status(404).json({ error: 'Analysis record not found.' });
    }
    res.json({ success: true, notes });
  });

  // Run Gemini Investigation Assistant on structured findings
  app.post('/api/analyses/:id/assistant', async (req, res) => {
    try {
      const analysis = sessionStore.getAnalysis(req.params.id);
      if (!analysis) {
        return res.status(404).json({ error: 'Investigation record not found.' });
      }

      const aiResult = await runGeminiInvestigationAssistant(analysis);
      analysis.aiAssistantResult = aiResult;
      sessionStore.saveAnalysis(analysis);

      res.json(aiResult);
    } catch (err: any) {
      console.error('Gemini Assistant execution failed:', err);
      res.status(500).json({ error: err.message || 'Gemini Assistant execution failed' });
    }
  });

  // Global Session Correlation Graph
  app.get('/api/graph/session', (req, res) => {
    const list = sessionStore.getAllAnalyses();
    const correlationData = list.map(a => ({
      analysisId: a.analysisId,
      subject: a.envelope.subject,
      senderDomain: a.envelope.from?.domain,
      senderAddress: a.envelope.from?.address,
      candidateIps: a.forensicFindings.candidateSourceIps.map(c => c.ip),
      urlDomains: a.contentFindings.urls.map(u => u.domain)
    }));

    const graph = buildSessionCorrelationGraph(correlationData);
    res.json({
      graph,
      totalEmailsInSession: list.length,
      caveat: 'Exploratory correlation: Infrastructure sharing indicates network/hosting intersections, not confirmed attribution.'
    });
  });

  // Clear session in-memory store
  app.delete('/api/analyses', (req, res) => {
    sessionStore.clearAll();
    res.json({ success: true, message: 'Session data and in-memory evidence completely wiped.' });
  });

  // Run Automated Tests from UI
  app.post('/api/test/run', async (req, res) => {
    try {
      const summary = await runAllAutomatedTests();
      res.json(summary);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Test runner failed' });
    }
  });

  // Manage ML Model Adapters (Provider-Independent Model Registry)
  app.get('/api/models', async (req, res) => {
    try {
      const models = await modelRegistry.listModelsWithStatus();
      const activeId = modelRegistry.getConfigProvider().getActiveModelId();
      res.json({
        active: activeId,
        models,
        adapters: models // compatibility alias
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to list models' });
    }
  });

  app.get('/api/settings/models', async (req, res) => {
    try {
      const models = await modelRegistry.listModelsWithStatus();
      const activeId = modelRegistry.getConfigProvider().getActiveModelId();
      res.json({
        active: activeId,
        models,
        adapters: models
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to list models' });
    }
  });

  app.post('/api/models/select', (req, res) => {
    const { modelId, adapterId } = req.body;
    const targetId = modelId || adapterId;
    if (!targetId) {
      return res.status(400).json({ error: 'modelId is required.' });
    }
    const ok = modelRegistry.getConfigProvider().setActiveModelId(targetId);
    if (!ok) {
      return res.status(400).json({ error: `Invalid model ID: ${targetId}` });
    }
    const active = modelRegistry.getActiveAdapter();
    res.json({ success: true, activeId: active.id, activeName: active.name });
  });

  app.post('/api/settings/models/select', (req, res) => {
    const { modelId, adapterId } = req.body;
    const targetId = modelId || adapterId;
    if (!targetId) {
      return res.status(400).json({ error: 'modelId is required.' });
    }
    const ok = modelRegistry.getConfigProvider().setActiveModelId(targetId);
    if (!ok) {
      return res.status(400).json({ error: `Invalid model ID: ${targetId}` });
    }
    const active = modelRegistry.getActiveAdapter();
    res.json({ success: true, activeId: active.id, activeName: active.name });
  });

  // Remote Model-Serving Connector Configuration (Requirement 5: SSRF Protections)
  app.get('/api/models/remote', (req, res) => {
    const connector = modelRegistry.getRemoteConnector();
    if (!connector) {
      return res.status(404).json({ error: 'Remote connector adapter not found.' });
    }
    const conf = connector.getConfig();
    res.json({
      endpointUrl: conf.endpointUrl,
      hasAuthToken: !!conf.authToken,
      timeoutMs: conf.timeoutMs,
      allowLocalhost: conf.allowLocalhost
    });
  });

  app.post('/api/models/remote/configure', (req, res) => {
    const connector = modelRegistry.getRemoteConnector();
    if (!connector) {
      return res.status(404).json({ error: 'Remote connector adapter not found.' });
    }
    const { endpointUrl, authToken, timeoutMs, allowLocalhost } = req.body;
    const result = connector.updateConfig({
      endpointUrl,
      authToken,
      timeoutMs: typeof timeoutMs === 'number' ? timeoutMs : undefined,
      allowLocalhost: typeof allowLocalhost === 'boolean' ? allowLocalhost : undefined
    });

    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({ success: true, message: 'Remote inference endpoint configuration updated and validated.' });
  });

  // --- VITE MIDDLEWARE OR STATIC SERVING ---
  if (!isProd) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishScope Server listening on port ${PORT} (http://localhost:${PORT})`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
