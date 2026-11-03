import { classifyIp, extractIps } from '../server/utils/ipUtils';
import { parseEmail } from '../server/parser/emailParser';
import { parseReceivedChain } from '../server/forensics/headerForensics';
import { analyzeAuthentication } from '../server/forensics/authForensics';
import { analyzeContentUrls, defangUrl } from '../server/forensics/contentForensics';
import { ModelRegistry } from '../server/ml/modelRegistry';
import { extractStandardizedModelFeatures, FEATURE_SCHEMA_VERSION, FEATURE_EXTRACTOR_VERSION } from '../server/ml/featureExtractor';
import { RemoteHttpServingAdapter, validateInferenceEndpoint } from '../server/ml/adapters/RemoteHttpServingAdapter';
import { TfidfLinearSvmAdapter } from '../server/ml/adapters/TfidfLinearSvmAdapter';
import { TfidfLogisticRegressionAdapter } from '../server/ml/adapters/TfidfLogisticRegressionAdapter';
import { GbdtStructuredForensicsAdapter } from '../server/ml/adapters/GbdtStructuredForensicsAdapter';
import { StandardizedModelFeatures } from '../server/ml/contracts';
import { buildSessionCorrelationGraph } from '../server/graph/graphEngine';
import { SessionStore } from '../server/store/sessionStore';
import { SYNTHETIC_FIXTURES } from '../server/fixtures/syntheticEmails';
import { executeAnalysisPipeline } from '../server/pipeline';

export interface TestResultItem {
  id: string;
  name: string;
  category: string;
  passed: boolean;
  durationMs: number;
  details?: string;
}

export interface TestSuiteSummary {
  total: number;
  passed: number;
  failed: number;
  durationMs: number;
  results: TestResultItem[];
}

function createMockFeatures(overrides: Partial<StandardizedModelFeatures> = {}): StandardizedModelFeatures {
  return {
    schemaVersion: FEATURE_SCHEMA_VERSION,
    extractorVersion: FEATURE_EXTRACTOR_VERSION,
    extractedAt: new Date().toISOString(),
    subjectText: 'Test Subject',
    bodyCleanText: 'Test Body',
    hasHtmlMarkup: 'false',
    textLengthChars: 9,
    wordCount: 2,
    spfPass: 'unknown',
    dkimPass: 'unknown',
    dmarcPass: 'unknown',
    isDomainAligned: 'unknown',
    hasNegativeTransitTime: 'unknown',
    hasPrivateOriginHop: 'unknown',
    hasIntermediateLoopback: 'unknown',
    totalHopCount: 0,
    candidateIpCount: 0,
    hasDirectIpUrls: 'not_applicable',
    hasAnchorTextDivergence: 'not_applicable',
    hasPunycodeDomains: 'not_applicable',
    hasShortenerUrls: 'not_applicable',
    totalUrlCount: 0,
    suspiciousBrandMentionCount: 0,
    hasSuspiciousAttachmentType: 'not_applicable',
    attachmentCount: 0,
    missingnessMetadata: {
      authentication: 'missing',
      routing: 'inapplicable',
      urls: 'inapplicable',
      attachments: 'inapplicable'
    },
    featureProvenance: {
      subjectText: 'RFC 5322 Subject Header'
    },
    ...overrides
  };
}

export async function runAllAutomatedTests(): Promise<TestSuiteSummary> {
  const startTime = Date.now();
  const results: TestResultItem[] = [];

  async function test(id: string, name: string, category: string, fn: () => Promise<void> | void) {
    const t0 = Date.now();
    try {
      await fn();
      results.push({
        id,
        name,
        category,
        passed: true,
        durationMs: Date.now() - t0
      });
    } catch (err: any) {
      results.push({
        id,
        name,
        category,
        passed: false,
        durationMs: Date.now() - t0,
        details: err.message || String(err)
      });
    }
  }

  // 1. IP Classification Tests
  await test('T01-IP-RFC1918', 'RFC 1918 Private IP Classification', 'IP Forensics', () => {
    if (classifyIp('10.0.0.1') !== 'private') throw new Error('10.0.0.1 should be private');
    if (classifyIp('172.16.5.10') !== 'private') throw new Error('172.16.5.10 should be private');
    if (classifyIp('192.168.1.100') !== 'private') throw new Error('192.168.1.100 should be private');
    if (classifyIp('127.0.0.1') !== 'loopback') throw new Error('127.0.0.1 should be loopback');
  });

  await test('T02-IP-PUBLIC', 'Public IP vs Reserved Address Range', 'IP Forensics', () => {
    if (classifyIp('198.51.100.25') !== 'public') throw new Error('198.51.100.25 should be public');
    if (classifyIp('185.220.101.5') !== 'public') throw new Error('185.220.101.5 should be public');
    if (classifyIp('169.254.1.1') !== 'reserved') throw new Error('169.254.1.1 should be reserved link-local');
  });

  // 2. MIME Email Parsing
  await test('T03-MIME-LEGIT', 'Parse Legitimate RFC Email Fixture', 'Email Parsing', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-01-legitimate')!;
    const parsed = await parseEmail(fixture.rawContent, false);
    if (!parsed.availableEvidence.hasHeaders) throw new Error('Should detect headers in legitimate email');
    if (parsed.receivedHeaders.length !== 2) throw new Error(`Expected 2 Received headers, found ${parsed.receivedHeaders.length}`);
    if (parsed.envelope.from?.address !== 'newsletter@acme-corp.com') throw new Error('From address mismatch');
  });

  await test('T04-MIME-PARTIAL-BODY', 'Handle Pasted Body-Only Input Gracefully', 'Email Parsing', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-05-body-only-partial')!;
    const parsed = await parseEmail(fixture.rawContent, false);
    if (parsed.inputType !== 'pasted_body') throw new Error(`Expected pasted_body, got ${parsed.inputType}`);
    if (parsed.availableEvidence.hasHeaders) throw new Error('Body-only input should NOT claim hasHeaders');
  });

  // 3. Received Header & Routing Forensics
  await test('T05-ROUTING-HOPS', 'Received-Chain Chronological Normalization', 'Header Forensics', () => {
    const rawHops = [
      'from mx.destination.org by internal.dest.org; Tue, 03 Nov 2026 14:16:00 +0000',
      'from relay.sender.com ([198.51.100.25]) by mx.destination.org; Tue, 03 Nov 2026 14:15:20 +0000'
    ];
    const hops = parseReceivedChain(rawHops);
    if (hops.length !== 2) throw new Error(`Expected 2 hops, got ${hops.length}`);
    if (hops[0].hopIndex !== 1) throw new Error('First chronological hop should be hopIndex 1');
    if (hops[0].ipAddress !== '198.51.100.25') throw new Error('Earliest hop IP should be 198.51.100.25');
  });

  await test('T06-ROUTING-ANOMALY', 'Detect Negative Transit Time & Clock Reversal', 'Header Forensics', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-03-routing-anomaly')!;
    const parsed = await parseEmail(fixture.rawContent, false);
    const hops = parseReceivedChain(parsed.receivedHeaders);
    const hasNegativeTime = hops.some(h => h.suspiciousSignals.some(s => s.includes('Negative transit time')));
    if (!hasNegativeTime) throw new Error('Failed to flag negative transit time in forged header fixture');
  });

  // 4. Authentication Forensics (SPF, DKIM, DMARC)
  await test('T07-AUTH-PASS', 'Evaluate Complete SPF and DKIM Pass', 'Authentication', () => {
    const authHeaders = [
      'mx.destination.org; dkim=pass header.d=acme-corp.com; spf=pass smtp.mailfrom=newsletter@acme-corp.com; dmarc=pass'
    ];
    const envelope = {
      from: { address: 'newsletter@acme-corp.com', domain: 'acme-corp.com' },
      to: [],
      cc: []
    };
    const res = analyzeAuthentication(authHeaders, [], [], envelope as any);
    if (res.spf.result !== 'pass') throw new Error('SPF should be pass');
    if (res.dkim.result !== 'pass') throw new Error('DKIM should be pass');
    if (res.dmarc.alignmentWithFrom !== 'strict' && res.dmarc.alignmentWithFrom !== 'relaxed') {
      throw new Error('DMARC alignment should be satisfied');
    }
  });

  await test('T08-AUTH-FAIL-ALIGN', 'Evaluate SPF Failure & DMARC Misalignment', 'Authentication', () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;
    const envelope = {
      from: { address: 'support-alert@attacker-server.xyz', domain: 'attacker-server.xyz' },
      to: [],
      cc: []
    };
    const authHeaders = [
      'mx.destination.org; spf=fail smtp.mailfrom=service@paypal.com; dmarc=fail'
    ];
    const res = analyzeAuthentication(authHeaders, ['fail client-ip=185.220.101.5'], [], envelope as any);
    if (res.spf.result !== 'fail') throw new Error('SPF should be fail');
    if (res.dmarc.result !== 'fail') throw new Error('DMARC should be fail');
  });

  // 5. URL Defanging & Anchor Mismatch Detection
  await test('T09-URL-DEFANG', 'URL Defanging for Safe Analyst Inspection', 'URL Analysis', () => {
    const raw = 'http://185.220.101.5/login';
    const defanged = defangUrl(raw);
    if (defanged !== 'hxxp://185[.]220[.]101[.]5/login') {
      throw new Error(`Defanging failed: got ${defanged}`);
    }
  });

  await test('T10-ANCHOR-MISMATCH', 'Flag Anchor Display Text vs Link Destination Mismatch', 'URL Analysis', () => {
    const html = '<a href="http://185.220.101.5/login">https://www.paypal.com/security</a>';
    const res = analyzeContentUrls('', html);
    const mismatch = res.urls.find(u => u.isMismatch);
    if (!mismatch) throw new Error('Failed to detect anchor text divergence');
    if (!mismatch.isIpBased) throw new Error('Failed to flag direct IP link');
  });

  // 6. ML Model Registry & Baseline Compliance
  await test('T11-ML-UNCONFIGURED', 'Default Unconfigured ML State Conformance', 'Model Registry', async () => {
    const registry = ModelRegistry.getInstance();
    const adapter = registry.getAdapter('unconfigured-baseline')!;
    const health = await adapter.getHealth();
    if (health.isConfigured !== false) throw new Error('Default adapter must report isConfigured === false');
    if (health.isAvailable !== false) throw new Error('Default adapter must report isAvailable === false');
    if (health.isExperimentallyValidated !== false) throw new Error('Default adapter must report isExperimentallyValidated === false');

    const pred = await adapter.predict(createMockFeatures(), 'snapshot-test-unconfigured');
    if (pred.isConfigured !== false) throw new Error('Prediction must report isConfigured === false');
    if (pred.scoreSemantics.isCalibrated !== false) throw new Error('Prediction must report isCalibrated === false');
    if (pred.predictedClass !== 'inconclusive') throw new Error('Default prediction class must be inconclusive');
  });

  // 7. Graph Representation & Correlation
  await test('T12-GRAPH-CORRELATION', 'Multi-Email Infrastructure Correlation Engine', 'Graph Analysis', () => {
    const analyses = [
      {
        analysisId: 'email-001',
        subject: 'Phish Campaign 1',
        senderDomain: 'evil-phish.net',
        candidateIps: ['185.220.101.5'],
        urlDomains: ['evil-phish.net']
      },
      {
        analysisId: 'email-002',
        subject: 'Phish Campaign 2',
        senderDomain: 'fake-update.com',
        candidateIps: ['185.220.101.5'],
        urlDomains: ['rogue-server.org']
      }
    ];

    const graph = buildSessionCorrelationGraph(analyses);
    const sharedEdge = graph.edges.find(e => e.relationshipType === 'SHARES_INFRASTRUCTURE_WITH');
    if (!sharedEdge) throw new Error('Failed to correlate emails sharing common candidate IP');
    if (sharedEdge.confidence !== 'hypothesized') throw new Error('Shared edge must be marked hypothesized exploratory correlation');
  });

  // 8. Privacy & Session In-Memory Wipe
  await test('T13-PRIVACY-CLEANUP', 'Session In-Memory Wipe Verification', 'Privacy & Storage', async () => {
    const store = SessionStore.getInstance();
    const fixture = SYNTHETIC_FIXTURES[0];
    await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'test.eml' });

    const beforeCount = store.getAllAnalyses().length;
    if (beforeCount === 0) throw new Error('Analysis should be stored in memory');

    store.clearAll();
    const afterCount = store.getAllAnalyses().length;
    if (afterCount !== 0) throw new Error('Session clearAll must purge all in-memory records');
  });

  // 9. Full Pipeline Execution on Synthetic Fixtures
  await test('T14-PIPELINE-EVALUATION', 'End-to-End Pipeline Evaluation of High-Risk Phish', 'Pipeline Integration', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'credential_phish.eml' });
    if (analysis.overallAssessment.label !== 'likely_phishing') {
      throw new Error(`Expected likely_phishing, got ${analysis.overallAssessment.label}`);
    }
    if (analysis.overallAssessment.score < 65) {
      throw new Error(`Expected score >= 65, got ${analysis.overallAssessment.score}`);
    }
  });

  // ==========================================
  // REFINEMENT SPECIFICATION TESTS (T15 - T26)
  // ==========================================

  // Requirement 2: Missing vs False Feature States
  await test('T15-FEATURE-MISSING-VS-FALSE', 'Preserve Missing Evidence as Unknown, Not False', 'Feature States', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-05-body-only-partial')!;
    const parsed = await parseEmail(fixture.rawContent, false);
    const features = extractStandardizedModelFeatures({
      envelope: parsed.envelope,
      rawHeaders: parsed.rawHeaders,
      bodyText: parsed.bodyText,
      bodyHtml: parsed.bodyHtml,
      hasHeaders: parsed.availableEvidence.hasHeaders,
      hasReceivedChain: parsed.availableEvidence.hasReceivedChain,
      hasAuthenticationHeaders: parsed.availableEvidence.hasAuthenticationHeaders,
      headerFindings: { receivedHops: [], candidateSourceIps: [], routingAnomalies: [], identityMismatches: [], messageIdAnomalies: [], dateAnomalies: [] },
      authFindings: { authResultsHeaderPresent: false, spf: { result: 'missing', alignmentWithFrom: 'inapplicable', note: '' }, dkim: { result: 'missing', alignmentWithFrom: 'inapplicable', note: '' }, dmarc: { result: 'missing', alignmentWithFrom: 'inapplicable', note: '' }, provenance: 'missing', limitations: [] },
      urls: [],
      attachments: []
    });

    if (features.spfPass !== 'unknown') {
      throw new Error(`Expected spfPass: 'unknown' for body-only input, got '${features.spfPass}'`);
    }
    if (features.dkimPass !== 'unknown') {
      throw new Error(`Expected dkimPass: 'unknown' for body-only input, got '${features.dkimPass}'`);
    }
    if (features.hasDirectIpUrls !== 'not_applicable') {
      throw new Error(`Expected hasDirectIpUrls: 'not_applicable' when 0 URLs present, got '${features.hasDirectIpUrls}'`);
    }
    if (features.missingnessMetadata['authentication'] !== 'missing') {
      throw new Error(`Expected missingnessMetadata['authentication']: 'missing', got '${features.missingnessMetadata['authentication']}'`);
    }
  });

  // Requirement 3: SVM Decision Margins vs Probabilities
  await test('T16-SVM-MARGIN-SEMANTICS', 'SVM Decision Margin Distance vs Probability Rigor', 'Model Semantics', async () => {
    const adapter = new TfidfLinearSvmAdapter();
    const pred = await adapter.predict(createMockFeatures({
      subjectText: 'Urgent action required',
      bodyCleanText: 'Verify your password immediately or account suspended'
    }), 'snap_test_svm');

    if (pred.scoreSemantics.probability !== undefined) {
      throw new Error('Linear SVM must NOT report uncalibrated hyperplane margin as probability (must be undefined)');
    }
    if (pred.scoreSemantics.isCalibrated !== false) {
      throw new Error('SVM margin must report isCalibrated === false');
    }
    if (typeof pred.scoreSemantics.decisionScore !== 'number') {
      throw new Error('SVM must output a numerical decisionScore');
    }
  });

  // Requirement 3: Calibrated vs Uncalibrated Prediction Output
  await test('T17-LOGISTIC-PROBABILITY', 'Logistic Regression Native Probability and Calibration Status', 'Model Semantics', async () => {
    const adapter = new TfidfLogisticRegressionAdapter();
    const pred = await adapter.predict(createMockFeatures({
      subjectText: 'Urgent notice',
      bodyCleanText: 'Verify password immediately'
    }), 'snap_test_lr');

    if (typeof pred.scoreSemantics.probability !== 'number' || pred.scoreSemantics.probability < 0 || pred.scoreSemantics.probability > 1) {
      throw new Error('Logistic Regression must produce probability in [0, 1]');
    }
    if (pred.scoreSemantics.isCalibrated !== false) {
      throw new Error('Logistic Regression raw sigmoid probability must report isCalibrated === false');
    }
    if (pred.scoreSemantics.calibratedProbability !== undefined) {
      throw new Error('Uncalibrated Logistic Regression must have calibratedProbability === undefined');
    }
  });

  // Requirement 4: Model Version Snapshot Locking During Concurrent Analysis
  await test('T18-SNAPSHOT-VERSION-LOCK', 'Preserve Model Version Snapshot Across Concurrent Global Switches', 'Model Versioning', async () => {
    const registry = ModelRegistry.getInstance();
    registry.setActiveModel('tfidf-logistic-regression');

    // 1. Snapshot taken for Analysis A
    const { adapter: adapterA, snapshot: snapshotA } = registry.captureSnapshotForAnalysis();
    if (snapshotA.modelId !== 'tfidf-logistic-regression') throw new Error('Analysis A should capture tfidf-logistic-regression');

    // 2. Global model in Settings is switched to SVM during processing
    registry.setActiveModel('tfidf-linear-svm');

    // 3. Analysis B starts with SVM
    const { adapter: adapterB, snapshot: snapshotB } = registry.captureSnapshotForAnalysis();
    if (snapshotB.modelId !== 'tfidf-linear-svm') throw new Error('Analysis B should capture tfidf-linear-svm');

    // 4. Analysis A executes with its locked snapshotA
    const boundAdapterA = registry.getAdapterForSnapshot(snapshotA);
    if (boundAdapterA.id !== 'tfidf-logistic-regression') {
      throw new Error('Analysis A must execute with its originally locked adapter');
    }
    if ((snapshotA.modelId as string) === (snapshotB.modelId as string)) {
      throw new Error('Snapshots A and B must preserve distinct model versions');
    }

    // Reset back to unconfigured baseline
    registry.setActiveModel('unconfigured-baseline');
  });

  // Requirement 5: SSRF Protections - Block Cloud Metadata Endpoints
  await test('T19-SSRF-CLOUD-METADATA', 'Block Cloud Instance Metadata IP (169.254.169.254)', 'SSRF Security', () => {
    const res = validateInferenceEndpoint('http://169.254.169.254/latest/meta-data/', false);
    if (res.isValid) throw new Error('Security policy must block 169.254.169.254 metadata endpoint');
    if (!res.error?.includes('SSRF Violation')) throw new Error('Expected SSRF Violation message');
  });

  // Requirement 5: SSRF Protections - Block Private IP Space for Remote Services
  await test('T20-SSRF-PRIVATE-RANGES', 'Block Private RFC 1918 Address Ranges for Remote Endpoints', 'SSRF Security', () => {
    const res1 = validateInferenceEndpoint('http://10.0.1.50:8000/predict', false);
    if (res1.isValid) throw new Error('Security policy must block 10.0.0.0/8 private space');

    const res2 = validateInferenceEndpoint('http://192.168.1.1:8000/predict', false);
    if (res2.isValid) throw new Error('Security policy must block 192.168.0.0/16 private space');
  });

  // Requirement 5: SSRF Protections - Enforce HTTPS for External Hosts
  await test('T21-SSRF-HTTPS-ENFORCEMENT', 'Enforce HTTPS for Remote Non-Localhost Inference Endpoints', 'SSRF Security', () => {
    const resHttp = validateInferenceEndpoint('http://external-inference.example.com/predict');
    if (resHttp.isValid) throw new Error('Plain HTTP should be rejected for external remote hosts');

    const resHttps = validateInferenceEndpoint('https://external-inference.example.com/predict');
    if (!resHttps.isValid) throw new Error(`Valid HTTPS remote endpoint should be accepted: ${resHttps.error}`);
  });

  // Requirement 5: Zero Silent Fallback on Remote Endpoint Failure
  await test('T22-NO-SILENT-FALLBACK', 'Zero Silent Fallback When Remote Endpoint Fails or Times Out', 'Remote Connector', async () => {
    const adapter = new RemoteHttpServingAdapter('https://non-existent-fastapi-service.invalid/predict');
    adapter.updateConfig({ timeoutMs: 300 });

    const pred = await adapter.predict(createMockFeatures(), 'snap_remote_fail');

    if (pred.predictedClass !== 'unavailable') {
      throw new Error(`Failed remote endpoint must report predictedClass: 'unavailable', got '${pred.predictedClass}'`);
    }
    if (pred.modelId !== 'remote-http-serving') {
      throw new Error(`Zero silent fallback violation: modelId changed to ${pred.modelId}`);
    }
    if (!pred.rationale.includes('In accordance with Section 5 integrity rules')) {
      throw new Error('Rationale must explicitly confirm no silent model fallback was performed');
    }
  });

  // Requirement 6: Model Health vs Experimental Validation Distinction
  await test('T23-HEALTH-VS-VALIDATION', 'Distinguish Healthy Server Status from Experimental Validation', 'Model Lifecycle', async () => {
    const adapter = new GbdtStructuredForensicsAdapter();
    const health = await adapter.getHealth();
    if (!health.isHealthy) throw new Error('GBDT adapter should report isHealthy: true');
    if (health.isExperimentallyValidated !== false) {
      throw new Error('Healthy model MUST NOT report isExperimentallyValidated: true without empirical benchmark');
    }
  });

  // Requirement 7: Version Tracking Invariants
  await test('T24-VERSION-INVARIANTS', 'Feature Schema & Extraction Version Tracking Invariants', 'Version Tracking', () => {
    if (FEATURE_SCHEMA_VERSION !== '2.0.0') throw new Error(`FEATURE_SCHEMA_VERSION must be '2.0.0', got '${FEATURE_SCHEMA_VERSION}'`);
    if (FEATURE_EXTRACTOR_VERSION !== '1.1.0') throw new Error(`FEATURE_EXTRACTOR_VERSION must be '1.1.0', got '${FEATURE_EXTRACTOR_VERSION}'`);
  });

  // Requirement 1: Registry Entry Count & Classification
  await test('T25-REGISTRY-SIX-ENTRIES', 'Verify Exactly Six Standardized Entries in Registry', 'Model Registry', async () => {
    const registry = ModelRegistry.getInstance();
    const models = await registry.listModelsWithHealth();
    if (models.length !== 6) {
      throw new Error(`Expected exactly 6 registered entries in ModelRegistry, found ${models.length}`);
    }

    const baseline = models.find(m => m.id === 'unconfigured-baseline');
    if (!baseline || baseline.classification !== 'research_baseline') {
      throw new Error('Registry missing valid research_baseline entry');
    }

    const connector = models.find(m => m.id === 'remote-http-serving');
    if (!connector || connector.classification !== 'serving_connector') {
      throw new Error('Registry missing valid serving_connector entry');
    }

    const researchModels = models.filter(m => m.classification === 'research_model');
    if (researchModels.length !== 4) {
      throw new Error(`Expected exactly 4 research_model entries, found ${researchModels.length}`);
    }
  });

  // Requirement 9 & 10: Python Service Contract Serialization Compatibility
  await test('T26-PYTHON-MICROSERVICE-CONTRACT', 'Validate Python Service Contract Compatibility', 'Python Service Contract', async () => {
    const mock = createMockFeatures();
    const serialized = JSON.stringify(mock);
    const parsed = JSON.parse(serialized);
    if (parsed.schemaVersion !== '2.0.0') throw new Error('Schema version mismatch in JSON serialization');
    if (!parsed.missingnessMetadata || !parsed.featureProvenance) {
      throw new Error('Missingness and provenance metadata must be serializable');
    }
    if (typeof parsed.totalHopCount !== 'number') {
      throw new Error('totalHopCount should serialize as number or null');
    }
  });

  const durationMs = Date.now() - startTime;
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  return {
    total: results.length,
    passed,
    failed,
    durationMs,
    results
  };
}

// Allow CLI execution directly
if (process.argv[1]?.endsWith('run_tests.ts')) {
  console.log('Running PhishScope Automated Test Suite...\n');
  runAllAutomatedTests().then(suite => {
    console.log(`\n==================================================`);
    console.log(`Test Execution Summary: ${suite.passed}/${suite.total} Passed in ${suite.durationMs}ms`);
    console.log(`==================================================\n`);
    for (const r of suite.results) {
      const statusIcon = r.passed ? '✓ PASS' : '✗ FAIL';
      console.log(`[${statusIcon}] [${r.category}] ${r.name} (${r.durationMs}ms)`);
      if (r.details) {
        console.error(`       Error: ${r.details}`);
      }
    }
    console.log('\n');
    process.exit(suite.failed > 0 ? 1 : 0);
  });
}
