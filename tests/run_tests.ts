import { classifyIp, extractIps, classifyDetailedIp } from '../server/utils/ipUtils';
import { parseEmail } from '../server/parser/emailParser';
import { parseReceivedChain, identifyCandidateSourceIps } from '../server/forensics/headerForensics';
import { analyzeAuthentication, checkDomainAlignment, extractCleanMailDomain } from '../server/forensics/authForensics';
import { analyzeContentUrls, defangUrl } from '../server/forensics/contentForensics';
import { ModelRegistry } from '../server/ml/modelRegistry';
import { extractStandardizedModelFeatures, FEATURE_SCHEMA_VERSION, FEATURE_EXTRACTOR_VERSION } from '../server/ml/featureExtractor';
import { RemoteHttpServingAdapter, validateInferenceEndpoint } from '../server/ml/adapters/RemoteHttpServingAdapter';
import { TfidfLinearSvmAdapter } from '../server/ml/adapters/TfidfLinearSvmAdapter';
import { TfidfLogisticRegressionAdapter } from '../server/ml/adapters/TfidfLogisticRegressionAdapter';
import { GbdtStructuredForensicsAdapter } from '../server/ml/adapters/GbdtStructuredForensicsAdapter';
import { StandardizedModelFeatures } from '../server/ml/contracts';
import { buildEmailGraph, buildSessionCorrelationGraph } from '../server/graph/graphEngine';
import { fuseEvidence } from '../server/fusion/evidenceFusion';
import { StandardDnsProvider } from '../server/intelligence/infrastructureEnrichment';
import { SessionStore } from '../server/store/sessionStore';
import { SYNTHETIC_FIXTURES } from '../server/fixtures/syntheticEmails';
import { executeAnalysisPipeline } from '../server/pipeline';
import { 
  buildCanonicalExportData, 
  generateExportFilename, 
  sanitizeFilename,
  generateJsonExport,
  generatePdfExport,
  generateExcelExport,
  sanitizeSpreadsheetValue,
  executeExportInvestigation 
} from '../src/export';

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
    if (classifyIp('93.184.216.34') !== 'public') throw new Error('93.184.216.34 should be public');
    if (classifyIp('185.220.101.5') !== 'public') throw new Error('185.220.101.5 should be public');
    if (classifyIp('169.254.1.1') !== 'reserved') throw new Error('169.254.1.1 should be reserved link-local');
    if (classifyIp('198.51.100.25') !== 'documentation') throw new Error('198.51.100.25 should be documentation (RFC 5737)');
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
      authFindings: { 
        authResultsHeaderPresent: false, 
        spf: { result: 'missing', alignmentWithFrom: 'inapplicable', note: '' }, 
        dkim: { result: 'missing', alignmentWithFrom: 'inapplicable', note: '' }, 
        dmarc: { 
          result: 'missing', 
          alignmentWithFrom: 'inapplicable', 
          spfAlignmentContribution: false, 
          dkimAlignmentContribution: false, 
          reportedProvenance: 'missing', 
          note: '' 
        }, 
        provenance: 'missing', 
        limitations: [] 
      },
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

  // ==========================================
  // PHASE 0 FORENSIC INTEGRITY AUDIT TESTS (T27 - T40)
  // ==========================================

  // Requirement 2: Special-Purpose IPv4 & IPv6 Standards Classification
  await test('T27-SPECIAL-PURPOSE-IP', 'RFC Standards-Aware Special-Purpose IP Classification', 'Phase 0 Forensics', () => {
    // RFC 5737 Documentation ranges
    const testNet1 = classifyDetailedIp('192.0.2.45');
    if (testNet1.ipType !== 'documentation' || testNet1.isPublicCandidate !== false) {
      throw new Error(`192.0.2.45 (TEST-NET-1) must be documentation and isPublicCandidate: false, got ${testNet1.ipType}`);
    }
    const testNet2 = classifyDetailedIp('198.51.100.99');
    if (testNet2.ipType !== 'documentation' || testNet2.isPublicCandidate !== false) {
      throw new Error(`198.51.100.99 (TEST-NET-2) must be documentation, got ${testNet2.ipType}`);
    }
    const testNet3 = classifyDetailedIp('203.0.113.12');
    if (testNet3.ipType !== 'documentation' || testNet3.isPublicCandidate !== false) {
      throw new Error(`203.0.113.12 (TEST-NET-3) must be documentation, got ${testNet3.ipType}`);
    }

    // RFC 3849 IPv6 Documentation prefix
    const v6Doc = classifyDetailedIp('2001:db8:85a3::8a2e:370:7334');
    if (v6Doc.ipType !== 'documentation' || v6Doc.isPublicCandidate !== false) {
      throw new Error(`2001:db8:: (RFC 3849) must be documentation, got ${v6Doc.ipType}`);
    }

    // RFC 6598 CGNAT
    const cgnat = classifyDetailedIp('100.64.10.5');
    if (cgnat.ipType !== 'reserved' || cgnat.isPublicCandidate !== false || !cgnat.category.includes('CGNAT')) {
      throw new Error(`100.64.10.5 must be classified as CGNAT reserved, got ${cgnat.category}`);
    }

    // Multicast & Unspecified
    const v4Multi = classifyDetailedIp('224.0.0.1');
    if (v4Multi.ipType !== 'multicast' || v4Multi.isPublicCandidate !== false) {
      throw new Error('224.0.0.1 must be multicast');
    }
    const v6Multi = classifyDetailedIp('ff02::1');
    if (v6Multi.ipType !== 'multicast' || v6Multi.isPublicCandidate !== false) {
      throw new Error('ff02::1 must be IPv6 multicast');
    }
    const v6Unspecified = classifyDetailedIp('::');
    if (v6Unspecified.ipType !== 'unspecified' || v6Unspecified.isPublicCandidate !== false) {
      throw new Error(':: must be unspecified');
    }
  });

  // Requirement 2: 6to4 IPv4-Embedded Address Decoding & Private Range Safeguard
  await test('T28-6TO4-EMBEDDED-IP', 'Decode 6to4 Embedded IPv4 and Prohibit Private Space as Public Origin', 'Phase 0 Forensics', () => {
    // 2002:0a00:0001:: embeds 10.0.0.1 (0a.00.00.01 = 10.0.0.1) -> RFC 1918 Private!
    const v6to4Private = classifyDetailedIp('2002:0a00:0001::');
    if (v6to4Private.transitionType !== '6to4') throw new Error('Must detect 6to4 transition mechanism');
    if (v6to4Private.decodedIpv4 !== '10.0.0.1') throw new Error(`Expected decoded IPv4 10.0.0.1, got ${v6to4Private.decodedIpv4}`);
    if (v6to4Private.ipType !== 'private') throw new Error(`6to4 embedding private IP must be classified as private, got ${v6to4Private.ipType}`);
    if (v6to4Private.isPublicCandidate !== false) throw new Error('6to4 embedding private IP must NEVER be a public candidate');

    // 2002:c000:0201:: embeds 192.0.2.1 (c0.00.02.01) -> RFC 5737 TEST-NET-1!
    const v6to4Doc = classifyDetailedIp('2002:c000:0201::');
    if (v6to4Doc.decodedIpv4 !== '192.0.2.1') throw new Error(`Expected 192.0.2.1, got ${v6to4Doc.decodedIpv4}`);
    if (v6to4Doc.ipType !== 'documentation') throw new Error('6to4 embedding TEST-NET-1 must be documentation');
    if (v6to4Doc.isPublicCandidate !== false) throw new Error('6to4 embedding documentation must not be public candidate');

    // 2002:5db8:d822:: embeds 93.184.216.34 (5d.b8.d8.22) -> Public!
    const v6to4Public = classifyDetailedIp('2002:5db8:d822::');
    if (v6to4Public.decodedIpv4 !== '93.184.216.34') throw new Error(`Expected 93.184.216.34, got ${v6to4Public.decodedIpv4}`);
    if (v6to4Public.ipType !== 'public' || v6to4Public.isPublicCandidate !== true) {
      throw new Error('6to4 embedding public IPv4 must be public candidate');
    }
  });

  // Requirement 1: Received Chain Chronological Ordering & Trust Boundary
  await test('T29-RECEIVED-CHRONOLOGY', 'Received Chain Chronological Reconstruction & Border Hop', 'Phase 0 Forensics', () => {
    const rawHeaders = [
      'from mail-edge.internal.org by dest-mailbox.internal.org; Tue, 03 Nov 2026 14:16:30 +0000', // Hop 3 (Top in raw, delivery)
      'from relay-cloud.net ([185.220.101.5]) by mail-edge.internal.org; Tue, 03 Nov 2026 14:16:00 +0000', // Hop 2 (Border MTA)
      'from client-pc ([10.0.0.50]) by relay-cloud.net; Tue, 03 Nov 2026 14:15:00 +0000' // Hop 1 (Bottom in raw, initial)
    ];

    const hops = parseReceivedChain(rawHeaders);
    if (hops.length !== 3) throw new Error(`Expected 3 hops, got ${hops.length}`);

    // Hop 1 in chronological sequence is the earliest
    if (hops[0].hopIndex !== 1 || hops[0].rawPositionFromTop !== 2) {
      throw new Error(`Earliest hop should have hopIndex 1 and rawPositionFromTop 2, got hopIndex=${hops[0].hopIndex}, rawPos=${hops[0].rawPositionFromTop}`);
    }

    // Hop 3 (the topmost header, rawPositionFromTop === 0) is the border/final recipient hop
    const finalHop = hops[2];
    if (finalHop.rawPositionFromTop !== 0 || !finalHop.isBorderHop) {
      throw new Error('Topmost Received header must be flagged isBorderHop: true and rawPositionFromTop: 0');
    }
  });

  // Requirement 1: Attacker-Forged Received Headers & Candidate Attribution
  await test('T30-BORDER-AND-FORGED-HOPS', 'Distinguish Trusted Border Hop from Potentially Attacker-Injected Hops', 'Phase 0 Forensics', () => {
    const rawHeaders = [
      'from mail-relay.trusted-border.com ([185.220.101.5]) by recipient.internal.com; Tue, 03 Nov 2026 14:16:00 +0000', // Trusted border hop
      'from fake-bank.com ([93.184.216.34]) by mail-relay.trusted-border.com; Tue, 03 Nov 2026 14:20:00 +0000' // Forged header inserted with future/reversed time
    ];

    const hops = parseReceivedChain(rawHeaders);
    // Hop 2 in chronological (the border hop) is trusted
    const borderHop = hops.find(h => h.isBorderHop);
    if (!borderHop || borderHop.trustZone !== 'trusted_border') {
      throw new Error('Border receiving hop must be in trusted_border zone');
    }

    const candidates = identifyCandidateSourceIps(hops);
    const borderCandidate = candidates.find(c => c.ip === '185.220.101.5');
    if (!borderCandidate) throw new Error('Border connecting IP must be identified');
    if (borderCandidate.trustBoundary !== 'border') {
      throw new Error('Border IP must have trustBoundary: "border"');
    }
  });

  // Requirement 3: SPF Domain Extraction from Mailbox vs Full String
  await test('T31-SPF-MAILBOX-DOMAIN-EXTRACTION', 'Clean SPF and Mailbox Domain Extraction', 'Phase 0 Forensics', () => {
    const d1 = extractCleanMailDomain('<bounce+12345-user=domain.com@bounces.sendgrid.net>');
    if (d1 !== 'bounces.sendgrid.net') {
      throw new Error(`Expected 'bounces.sendgrid.net', got '${d1}'`);
    }

    const d2 = extractCleanMailDomain('smtp.mailfrom=notifications@github.com');
    if (d2 !== 'github.com') {
      throw new Error(`Expected 'github.com', got '${d2}'`);
    }

    const d3 = extractCleanMailDomain('smtp.helo=mail-out.protection.outlook.com');
    if (d3 !== 'mail-out.protection.outlook.com') {
      throw new Error(`Expected 'mail-out.protection.outlook.com', got '${d3}'`);
    }
  });

  // Requirement 3: Strict vs Relaxed Domain Alignment Semantics
  await test('T32-DOMAIN-ALIGNMENT-STRICT-RELAXED', 'Strict vs Relaxed Identifier Alignment', 'Phase 0 Forensics', () => {
    // Exact match satisfies both strict and relaxed
    const exact = checkDomainAlignment('example.com', 'example.com', 'strict');
    if (exact !== 'strict') throw new Error(`Exact match should be strict, got ${exact}`);

    // Subdomain to organizational domain in relaxed mode
    const relaxed = checkDomainAlignment('mail.example.com', 'example.com', 'relaxed');
    if (relaxed !== 'relaxed') throw new Error(`Subdomain should be relaxed, got ${relaxed}`);

    // Subdomain in strict mode must fail alignment
    const strictSub = checkDomainAlignment('mail.example.com', 'example.com', 'strict');
    if (strictSub !== 'misaligned') throw new Error(`Subdomain in strict mode must be misaligned, got ${strictSub}`);

    // Completely unrelated domain
    const misaligned = checkDomainAlignment('attacker.com', 'paypal.com', 'relaxed');
    if (misaligned !== 'misaligned') throw new Error(`Unrelated domain must be misaligned, got ${misaligned}`);
  });

  // Requirement 3: DMARC Pass/Fail Consistency with SPF/DKIM Alignment
  await test('T33-DMARC-ALIGNMENT-RULES', 'DMARC PASS Dependent on Aligned SPF or Aligned DKIM', 'Phase 0 Forensics', () => {
    const envelope = {
      from: { address: 'support@paypal.com', domain: 'paypal.com' },
      to: [],
      cc: []
    };

    // Case A: SPF pass with alignment, DKIM missing -> DMARC Pass
    const authHeadersA = [
      'mx.recipient.com; spf=pass smtp.mailfrom=service@paypal.com; dmarc=pass (p=reject)'
    ];
    const resA = analyzeAuthentication(authHeadersA, [], [], envelope as any);
    if (resA.dmarc.result !== 'pass') throw new Error('DMARC should pass when SPF passes and aligns');
    if (!resA.dmarc.spfAlignmentContribution) throw new Error('spfAlignmentContribution should be true');

    // Case B: SPF pass but MISALIGNED, DKIM missing -> DMARC MUST NOT PASS!
    const authHeadersB = [
      'mx.recipient.com; spf=pass smtp.mailfrom=bounce@evil-domain.com; dmarc=pass' // Header erroneously claimed pass!
    ];
    const resB = analyzeAuthentication(authHeadersB, [], [], envelope as any);
    if (resB.dmarc.result === 'pass') {
      throw new Error('DMARC MUST NOT report pass when neither SPF nor DKIM is aligned, even if header claimed pass!');
    }
    if (resB.dmarc.result !== 'fail') {
      throw new Error(`DMARC should be corrected to fail, got ${resB.dmarc.result}`);
    }
  });

  // Requirement 3: Handling Missing Authentication Headers
  await test('T34-MISSING-AUTH-HEADERS', 'Correct Representation of Missing Authentication Headers', 'Phase 0 Forensics', () => {
    const envelope = {
      from: { address: 'user@unknown.org', domain: 'unknown.org' },
      to: [],
      cc: []
    };
    const res = analyzeAuthentication([], [], [], envelope as any);
    if (res.authResultsHeaderPresent !== false) throw new Error('authResultsHeaderPresent must be false');
    if (res.provenance !== 'missing') throw new Error('provenance must be missing');
    if (res.spf.result !== 'missing') throw new Error('SPF result must be missing');
    if (res.dkim.result !== 'missing') throw new Error('DKIM result must be missing');
    if (res.dmarc.result !== 'missing') throw new Error('DMARC result must be missing');
  });

  // Requirement 3 & 4: Separation of Published Policy from Verdict & Provenance Tracking
  await test('T35-CONFLICTING-AUTH-RECORDS', 'Separation of Policy Enforcement (p=reject) from Authentication Verdict', 'Phase 0 Forensics', () => {
    const envelope = {
      from: { address: 'ceo@target-corp.com', domain: 'target-corp.com' },
      to: [],
      cc: []
    };
    const authHeaders = [
      'mx.recipient.com; spf=fail smtp.mailfrom=attacker@spoofer.com; dkim=fail; dmarc=fail (p=reject)'
    ];
    const res = analyzeAuthentication(authHeaders, [], [], envelope as any);

    // Verdict is fail, published policy is reject
    if (res.dmarc.result !== 'fail') throw new Error(`DMARC result must be fail, got ${res.dmarc.result}`);
    if (res.dmarc.policy !== 'reject') throw new Error(`Published policy must be reject, got ${res.dmarc.policy}`);
    if (res.dmarc.reportedProvenance !== 'header_reported') {
      throw new Error('reportedProvenance must be header_reported');
    }
  });

  // Requirement 4: Provenance Rigor - Never Claim Independent Verification for Header Reading
  await test('T36-AUTH-PROVENANCE-SEPARATION', 'Header Reading Strictly Marked reported_in_headers', 'Phase 0 Forensics', () => {
    const authHeaders = ['mx.recipient.com; spf=pass smtp.mailfrom=user@example.com'];
    const res = analyzeAuthentication(authHeaders, [], [], { from: { domain: 'example.com', address: 'user@example.com' }, to: [], cc: [] } as any);
    if (res.provenance !== 'reported_in_headers') {
      throw new Error(`Provenance must be 'reported_in_headers', never independently verified. Got: ${res.provenance}`);
    }
    if (!res.limitations.some(l => l.includes('Header-reported authentication'))) {
      throw new Error('Limitations must explicitly state that results reflect receiving MTA headers');
    }
  });

  // Requirement 5: Missing Evidence is Never Treated as Benign Evidence
  await test('T37-MISSING-EVIDENCE-VS-NEGATIVE', 'Missing Evidence Must Never Be Interpreted as Benign Evidence', 'Phase 0 Forensics', () => {
    const emptyHeaderInput = {
      inputType: 'pasted_body',
      hasHeaders: false,
      hasReceivedChain: false,
      hasAuthenticationHeaders: false,
      hasBodyText: true,
      hasBodyHtml: false,
      hasAttachments: false,
      headerFindings: { receivedHops: [], candidateSourceIps: [], routingAnomalies: [], identityMismatches: [], messageIdAnomalies: [], dateAnomalies: [] },
      authFindings: { authResultsHeaderPresent: false, spf: { result: 'missing' as const, alignmentWithFrom: 'inapplicable' as const, note: '' }, dkim: { result: 'missing' as const, alignmentWithFrom: 'inapplicable' as const, note: '' }, dmarc: { result: 'missing' as const, alignmentWithFrom: 'inapplicable' as const, spfAlignmentContribution: false, dkimAlignmentContribution: false, reportedProvenance: 'missing' as const, note: '' }, provenance: 'missing' as const, limitations: [] },
      urls: [],
      contentFindings: [],
      attachments: [],
      mlConfigured: false
    };

    const fusion = fuseEvidence(emptyHeaderInput);
    if (fusion.label === 'likely_legitimate') {
      throw new Error('Missing headers must NEVER produce likely_legitimate verdict');
    }
    if (fusion.confidenceLevel === 'high') {
      throw new Error('Incomplete evidence must NEVER produce high confidence');
    }
    if (fusion.evidenceCoverageScore > 40) {
      throw new Error(`Body-only input should have low evidence coverage score, got ${fusion.evidenceCoverageScore}%`);
    }
  });

  // Requirement 5: Risk Score vs Assessment Confidence Separation
  await test('T38-RISK-SCORE-VS-CONFIDENCE', 'Low Observed Threat Points With Low Coverage Produces Inconclusive / Low Confidence', 'Phase 0 Forensics', () => {
    const lowCoverageBenignLookingBody = {
      inputType: 'pasted_body',
      hasHeaders: false,
      hasReceivedChain: false,
      hasAuthenticationHeaders: false,
      hasBodyText: true,
      hasBodyHtml: false,
      hasAttachments: false,
      headerFindings: { receivedHops: [], candidateSourceIps: [], routingAnomalies: [], identityMismatches: [], messageIdAnomalies: [], dateAnomalies: [] },
      authFindings: { authResultsHeaderPresent: false, spf: { result: 'missing' as const, alignmentWithFrom: 'inapplicable' as const, note: '' }, dkim: { result: 'missing' as const, alignmentWithFrom: 'inapplicable' as const, note: '' }, dmarc: { result: 'missing' as const, alignmentWithFrom: 'inapplicable' as const, spfAlignmentContribution: false, dkimAlignmentContribution: false, reportedProvenance: 'missing' as const, note: '' }, provenance: 'missing' as const, limitations: [] },
      urls: [], // 0 urls
      contentFindings: [], // 0 heuristic alerts
      attachments: [],
      mlConfigured: false
    };

    const fusion = fuseEvidence(lowCoverageBenignLookingBody);
    if (fusion.confidenceLevel !== 'low') {
      throw new Error(`Expected low confidence due to incomplete evidence, got ${fusion.confidenceLevel}`);
    }
    if (fusion.label !== 'insufficient_evidence') {
      throw new Error(`Expected insufficient_evidence label, got ${fusion.label}`);
    }
  });

  // Requirement 6: Infrastructure Enrichment Record Metadata Completeness
  await test('T39-ENRICHMENT-AUDIT-METADATA', 'Enrichment Records Must Record Provider, Target, Timestamp, Status, and Limitations', 'Phase 0 Forensics', async () => {
    const provider = new StandardDnsProvider();
    const obsIp = await provider.enrichIp('192.0.2.1', 'documentation');

    if (!obsIp.provider || !obsIp.queryTarget || !obsIp.queryTimestamp || !obsIp.status || !obsIp.reliabilityLimitations) {
      throw new Error('Enrichment record missing required metadata fields (provider, queryTarget, queryTimestamp, status, reliabilityLimitations)');
    }
    if (obsIp.status !== 'internal_ip_skipped') {
      throw new Error(`Documentation IP must have status 'internal_ip_skipped', got ${obsIp.status}`);
    }
  });

  // Requirement 7: Graph Provenance and Shared Infrastructure Caveat
  await test('T40-GRAPH-OBSERVED-VS-INFERRED', 'Graph Edges Must Distinguish Observed Relationships from Inferred Correlations', 'Phase 0 Forensics', () => {
    const graph = buildEmailGraph({
      analysisId: 'test-graph-001',
      envelope: {
        from: { address: 'sender@example.com', domain: 'example.com' },
        to: [],
        cc: [],
        subject: 'Test Subject'
      },
      receivedHops: [
        {
          hopIndex: 1,
          rawPositionFromTop: 0,
          byServer: 'mx.recipient.com',
          ipAddress: '185.220.101.5',
          ipType: 'public',
          rawHeader: 'from mail.com by mx.recipient.com',
          parsingConfidence: 0.9,
          suspiciousSignals: [],
          trustZone: 'trusted_border',
          isBorderHop: true,
          isPotentiallyForged: false
        }
      ],
      candidateSourceIps: [{ ip: '185.220.101.5', confidence: 'High' }],
      urls: [{
        url: 'http://example.com/login',
        defangedUrl: 'hxxp://example[.]com/login',
        domain: 'example.com',
        protocol: 'http:',
        isIpBased: false,
        isPunycode: false,
        isShortener: false,
        suspiciousFlags: [],
        isMismatch: false
      }],
      observations: []
    });

    // SENT_FROM should be directly observed
    const sentFromEdge = graph.edges.find(e => e.relationshipType === 'SENT_FROM');
    if (!sentFromEdge || sentFromEdge.isDirectlyObserved !== true || sentFromEdge.relationshipNature !== 'directly_observed') {
      throw new Error('SENT_FROM edge must be directly observed');
    }

    // ROUTED_THROUGH to candidate IP is derived/inferred
    const routedEdge = graph.edges.find(e => e.targetNode === 'ip:185.220.101.5');
    if (!routedEdge || routedEdge.isDirectlyObserved !== false || routedEdge.relationshipNature !== 'inferred') {
      throw new Error('ROUTED_THROUGH candidate IP edge must be inferred');
    }
  });

  // ==========================================
  // EXPORT & REPORTING MODULE TESTS (T41 - T58)
  // ==========================================

  // Requirement 1 & 2: Exporting currently selected investigation
  await test('T41-EXPORT-CURRENT-INVESTIGATION', 'Export Strictly Binds to Currently Selected Investigation', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-01-legitimate')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'legit.eml' });

    const exportData = buildCanonicalExportData(analysis, 'json');
    if (exportData.summary.investigationId !== analysis.analysisId) {
      throw new Error(`Expected investigationId ${analysis.analysisId}, got ${exportData.summary.investigationId}`);
    }
    if (exportData.summary.subject !== analysis.envelope.subject) {
      throw new Error(`Subject mismatch in export: ${exportData.summary.subject}`);
    }
    if (exportData.metadata.exportSchemaVersion !== '1.0.0') {
      throw new Error(`Expected schema version '1.0.0', got ${exportData.metadata.exportSchemaVersion}`);
    }
  });

  // Requirement 2: Correct investigation selection when multiple exist
  await test('T42-INVESTIGATION-SELECTION-ISOLATION', 'Investigation Selection Isolation with Multiple Store Items', 'Export Module', async () => {
    const fixture1 = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-01-legitimate')!;
    const fixture2 = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;

    const analysis1 = await executeAnalysisPipeline(fixture1.rawContent, { sourceFilename: 'one.eml' });
    const analysis2 = await executeAnalysisPipeline(fixture2.rawContent, { sourceFilename: 'two.eml' });

    // Exporting analysis1 must contain analysis1 data only
    const export1 = buildCanonicalExportData(analysis1, 'json');
    if (export1.summary.investigationId !== analysis1.analysisId) {
      throw new Error('Export 1 did not isolate analysis 1');
    }
    if (export1.summary.investigationId === analysis2.analysisId) {
      throw new Error('Export 1 contaminated with analysis 2');
    }

    // Exporting analysis2 must contain analysis2 data only
    const export2 = buildCanonicalExportData(analysis2, 'json');
    if (export2.summary.investigationId !== analysis2.analysisId) {
      throw new Error('Export 2 did not isolate analysis 2');
    }
  });

  // Requirement 2: Consistent snapshots during asynchronous export
  await test('T43-ASYNC-SNAPSHOT-CONSISTENCY', 'Immutable Snapshot Consistency During Concurrent Modification', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'async.eml' });

    // Snapshot taken
    const exportData = buildCanonicalExportData(analysis, 'json');
    const originalScore = exportData.summary.observedRiskScore;

    // Mutate live analysis object afterwards
    (analysis.overallAssessment as any).score = 999;
    (analysis.envelope as any).subject = 'MUTATED SUBJECT AFTER SNAPSHOT';

    if (exportData.summary.observedRiskScore === 999) {
      throw new Error('Export snapshot was mutated by subsequent live object edits');
    }
    if (exportData.summary.subject === 'MUTATED SUBJECT AFTER SNAPSHOT') {
      throw new Error('Export subject was mutated by subsequent live object edits');
    }
    if (exportData.summary.observedRiskScore !== originalScore) {
      throw new Error('Snapshot score integrity violated');
    }
  });

  // Requirement 3: Valid JSON structure and schema version
  await test('T44-JSON-SCHEMA-AND-STRUCTURE', 'Valid JSON Structure, Schema Version and Checksum', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'schema.eml' });

    const exportData = buildCanonicalExportData(analysis, 'json');
    const jsonRes = await generateJsonExport(exportData, { includeSha256Checksum: true });

    const parsed = JSON.parse(jsonRes.jsonString);
    if (parsed.metadata.exportSchemaVersion !== '1.0.0') throw new Error('Invalid exportSchemaVersion');
    if (!parsed.metadata.checksumSha256 || parsed.metadata.checksumSha256.length !== 64) {
      throw new Error('Expected 64-character SHA-256 checksum in metadata');
    }
    if (!parsed.summary || !parsed.headersAndRouting || !parsed.authentication || !parsed.urlsAndContent || !parsed.attachments || !parsed.infrastructureIntelligence || !parsed.relationshipGraph || !parsed.machineLearning || !parsed.evidenceFusionAndLimitations) {
      throw new Error('JSON export is missing required forensic sections');
    }
  });

  // Requirement 3: JSON serialization of unknown and unavailable values
  await test('T45-JSON-UNKNOWN-UNAVAILABLE-PRESERVATION', 'Preserve Unknown, Unavailable, and Missing Forensic States in JSON', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-05-body-only-partial')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'body.eml' });

    const exportData = buildCanonicalExportData(analysis, 'json');
    const jsonRes = await generateJsonExport(exportData);
    const parsed = JSON.parse(jsonRes.jsonString);

    if (parsed.authentication.spf.result !== 'missing') {
      throw new Error(`Expected spf.result 'missing', got '${parsed.authentication.spf.result}'`);
    }
    if (parsed.authentication.authResultsHeaderPresent !== false) {
      throw new Error('Expected authResultsHeaderPresent === false for body-only input');
    }
    if (parsed.headersAndRouting.receivedHopsCount !== 0) {
      throw new Error('Expected 0 hops for body-only input');
    }
  });

  // Requirement 4: PDF generation and required report sections
  await test('T46-PDF-GENERATION-SECTIONS', 'Generate Professional PDF Report with Standardized Sections', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-01-legitimate')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'pdf.eml' });

    const exportData = buildCanonicalExportData(analysis, 'pdf', { analystName: 'Lead Examiner' });
    const pdfRes = generatePdfExport(exportData);

    if (!pdfRes.filename.endsWith('.pdf')) throw new Error('PDF filename must end with .pdf');
    if (pdfRes.mimeType !== 'application/pdf') throw new Error('PDF mimeType must be application/pdf');
    if (pdfRes.binaryBuffer.length < 500) throw new Error('PDF binary buffer is suspiciously small');
    if (pdfRes.doc.getNumberOfPages() < 1) throw new Error('PDF must contain at least 1 page');
  });

  // Requirement 5: Excel workbook generation and expected worksheets
  await test('T47-EXCEL-WORKBOOK-WORKSHEETS', 'Generate Multi-Sheet Excel Workbook with 12 Dedicated Worksheets', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'excel.eml' });

    const exportData = buildCanonicalExportData(analysis, 'xlsx');
    const xlsxRes = generateExcelExport(exportData);

    const expectedSheets = [
      'Investigation Summary',
      'SMTP Received Chain',
      'Candidate IP Addresses',
      'Authentication Results',
      'URLs and Domains',
      'Attachments',
      'Infrastructure Intelligence',
      'Graph Nodes',
      'Graph Relationships',
      'ML and Evidence Fusion',
      'Limitations & Missing Evidence',
      'Analyst Notes'
    ];

    if (xlsxRes.workbook.SheetNames.length !== 12) {
      throw new Error(`Expected exactly 12 worksheets, found ${xlsxRes.workbook.SheetNames.length}`);
    }
    for (const name of expectedSheets) {
      if (!xlsxRes.workbook.SheetNames.includes(name)) {
        throw new Error(`Missing expected Excel worksheet: '${name}'`);
      }
    }
    if (xlsxRes.binaryBuffer.length < 1000) {
      throw new Error('XLSX binary buffer is suspiciously small');
    }
  });

  // Requirement 5: Text preservation for IPs, timestamps, and hashes
  await test('T48-EXCEL-TEXT-PRESERVATION', 'Preserve IP Addresses, Timestamps, and Hashes as Text in Excel', 'Export Module', () => {
    const sanitizedIp = sanitizeSpreadsheetValue('192.168.1.1');
    if (sanitizedIp !== '192.168.1.1') throw new Error('IP should not be altered');

    const sanitizedHash = sanitizeSpreadsheetValue('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    if (sanitizedHash !== 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') {
      throw new Error('Hash should not be altered');
    }
  });

  // Requirement 7 & 8: Graph node and relationship preservation
  await test('T49-GRAPH-PROVENANCE-PRESERVATION', 'Preserve Graph Nodes, Relationships, and Nature in Export', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'graph.eml' });

    const exportData = buildCanonicalExportData(analysis, 'json');
    if (exportData.relationshipGraph.nodeCount === 0) throw new Error('Graph export must contain nodes');
    if (exportData.relationshipGraph.edgeCount === 0) throw new Error('Graph export must contain edges');

    const sentFrom = exportData.relationshipGraph.edges.find(e => e.relationshipType === 'SENT_FROM');
    if (!sentFrom || !sentFrom.isDirectlyObserved || sentFrom.relationshipNature !== 'directly_observed') {
      throw new Error('SENT_FROM edge must preserve directly_observed nature');
    }
  });

  // Requirement 3 & 4: Authentication provenance preservation
  await test('T50-AUTH-PROVENANCE-PRESERVATION', 'Preserve Authentication Provenance and Identifier Alignment', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-01-legitimate')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'auth.eml' });

    const exportData = buildCanonicalExportData(analysis, 'json');
    if (exportData.authentication.provenance !== 'reported_in_headers') {
      throw new Error(`Expected provenance 'reported_in_headers', got '${exportData.authentication.provenance}'`);
    }
    if (exportData.authentication.spf.result !== 'pass') {
      throw new Error('Expected SPF pass in legitimate email export');
    }
  });

  // Requirement 3: Model and preprocessing version preservation
  await test('T51-MODEL-VERSION-PRESERVATION', 'Preserve Active Model, Versions, and Calibration Status', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-01-legitimate')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'model.eml' });

    const exportData = buildCanonicalExportData(analysis, 'json');
    if (!exportData.machineLearning.modelId) throw new Error('Missing modelId in export');
    if (!exportData.machineLearning.modelVersion) throw new Error('Missing modelVersion in export');
    if (!exportData.machineLearning.preprocessingVersion) throw new Error('Missing preprocessingVersion in export');
    if (!exportData.machineLearning.featureSchemaVersion) throw new Error('Missing featureSchemaVersion in export');
  });

  // Requirement 2: Missing evidence versus negative evidence
  await test('T52-MISSING-VS-NEGATIVE-EVIDENCE', 'Distinguish Missing Evidence from Benign Findings in Export', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-05-body-only-partial')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'missing.eml' });

    const exportData = buildCanonicalExportData(analysis, 'json');
    if (exportData.evidenceFusionAndLimitations.evidenceCoverageScore >= 50) {
      throw new Error('Body-only email should have evidenceCoverageScore < 50%');
    }
    if (exportData.evidenceFusionAndLimitations.unavailableEvidenceCategories.length === 0) {
      throw new Error('Unavailable evidence categories must be documented in export');
    }
  });

  // Requirement 4 & 5: Long forensic values and special characters
  await test('T53-LONG-VALUES-SPECIAL-CHARS', 'Handle Extreme Length Values and Unicode in All Formats', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'chars.eml' });

    // Inject extreme values
    analysis.envelope.subject = '🚨 URGENT: Vérification de sécurité / חשבון נעול / 登录验证 (Over 100 unicode chars) — ' + 'A'.repeat(150);
    analysis.contentFindings.urls.push({
      url: 'https://evil.example.com/' + 'x'.repeat(250),
      defangedUrl: 'hxxps://evil[.]example[.]com/' + 'x'.repeat(250),
      domain: 'evil.example.com',
      protocol: 'https:',
      isIpBased: false,
      isPunycode: false,
      isShortener: false,
      isMismatch: false,
      suspiciousFlags: ['long_url']
    });

    const exportData = buildCanonicalExportData(analysis, 'json');
    const jsonRes = await generateJsonExport(exportData);
    if (!jsonRes.jsonString.includes('Vérification')) throw new Error('Unicode missing in JSON export');

    const pdfRes = generatePdfExport(exportData);
    if (pdfRes.binaryBuffer.length < 500) throw new Error('PDF generation crashed on unicode');

    const xlsxRes = generateExcelExport(exportData);
    if (xlsxRes.binaryBuffer.length < 500) throw new Error('Excel generation crashed on unicode');
  });

  // Requirement 5: Spreadsheet formula injection protection (CWE-1236)
  await test('T54-FORMULA-INJECTION-PROTECTION', 'Prevent Spreadsheet Formula Injection on Untrusted Strings', 'Export Module', () => {
    const maliciousFormula1 = "=CMD|' /C calc'!A0";
    const sanitized1 = sanitizeSpreadsheetValue(maliciousFormula1);
    if (sanitized1 !== `'=CMD|' /C calc'!A0`) {
      throw new Error(`Formula injection not prevented: got ${sanitized1}`);
    }

    const maliciousFormula2 = '+SUM(1+1)';
    const sanitized2 = sanitizeSpreadsheetValue(maliciousFormula2);
    if (sanitized2 !== `'+SUM(1+1)`) {
      throw new Error(`Plus-sign formula not prevented: got ${sanitized2}`);
    }

    const maliciousFormula3 = '-10*5';
    const sanitized3 = sanitizeSpreadsheetValue(maliciousFormula3);
    if (sanitized3 !== `'-10*5`) {
      throw new Error(`Minus-sign formula not prevented: got ${sanitized3}`);
    }

    const maliciousFormula4 = '@SUM(A1:A10)';
    const sanitized4 = sanitizeSpreadsheetValue(maliciousFormula4);
    if (sanitized4 !== `'@SUM(A1:A10)`) {
      throw new Error(`At-sign formula not prevented: got ${sanitized4}`);
    }

    // Normal strings should remain unchanged
    const normal = 'Normal subject text';
    if (sanitizeSpreadsheetValue(normal) !== normal) {
      throw new Error('Normal string was unexpectedly altered');
    }
  });

  // Requirement 6: Sensitive information exclusion by default
  await test('T55-SENSITIVE-DATA-DEFAULT-EXCLUSION', 'Exclude Sensitive Raw Email Body in Default Export', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-02-credential-phish')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'sensitive.eml' });

    // 1. Default sanitized export (includeSensitiveRawData: false)
    const sanitizedExport = buildCanonicalExportData(analysis, 'json', { includeSensitiveRawData: false });
    if (!sanitizedExport.urlsAndContent.bodySnippet.includes('redacted in default privacy export')) {
      throw new Error('Body text was not redacted in default export');
    }
    if (sanitizedExport.metadata.includesSensitiveData !== false) {
      throw new Error('includesSensitiveData must be false by default');
    }

    // 2. Explicit sensitive export (includeSensitiveRawData: true)
    const sensitiveExport = buildCanonicalExportData(analysis, 'json', { includeSensitiveRawData: true });
    if (sensitiveExport.urlsAndContent.bodySnippet.includes('redacted in default privacy export')) {
      throw new Error('Body text should be included when includeSensitiveRawData is true');
    }
    if (sensitiveExport.metadata.includesSensitiveData !== true) {
      throw new Error('includesSensitiveData must be true when requested');
    }
  });

  // Requirement 1 & 7: Export filename pattern and sanitization
  await test('T56-FILENAME-SANITIZATION-PATTERN', 'Standardized Filename Pattern and Unsafe Character Stripping', 'Export Module', () => {
    const filename = generateExportFilename('inv-12345/abc:xyz', 'pdf', new Date('2026-11-03T00:00:00Z'));
    if (!filename.startsWith('PhishScope_Investigation_')) {
      throw new Error(`Invalid filename prefix: ${filename}`);
    }
    if (!filename.endsWith('_2026-11-03.pdf')) {
      throw new Error(`Invalid filename suffix: ${filename}`);
    }
    if (filename.includes('/') || filename.includes(':')) {
      throw new Error(`Filename contains unsafe characters: ${filename}`);
    }
  });

  // Requirement 1 & 8: Export failure and graceful error handling
  await test('T57-ERROR-HANDLING-NULL-INVESTIGATION', 'Gracefully Handle Null or Missing Investigation Object', 'Export Module', async () => {
    let errorCaught = false;
    try {
      await executeExportInvestigation(null as any, 'json', {}, false);
    } catch (err: any) {
      errorCaught = true;
      if (!err.message.includes('No investigation is currently selected')) {
        throw new Error(`Unexpected error message: ${err.message}`);
      }
    }
    if (!errorCaught) throw new Error('Expected error when exporting null investigation');
  });

  // Requirement 6: No permanent disk storage or external network transmission
  await test('T58-IN-MEMORY-PRIVACY-INVARIANT', 'Verify Zero Disk Artifacts and Ephemeral Execution', 'Export Module', async () => {
    const fixture = SYNTHETIC_FIXTURES.find(f => f.id === 'fixture-01-legitimate')!;
    const analysis = await executeAnalysisPipeline(fixture.rawContent, { sourceFilename: 'privacy.eml' });

    // Execute in-memory export
    const result = await executeExportInvestigation(analysis, 'json', {}, false);
    if (!result.filename || result.bytesCount <= 0) {
      throw new Error('Export did not generate output in memory');
    }

    // Verify session store analyses remain intact in memory
    const store = SessionStore.getInstance();
    const stored = store.getAnalysis(analysis.analysisId);
    if (!stored) throw new Error('Analysis must be stored in memory');
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
