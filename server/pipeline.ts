import crypto from 'crypto';
import { EmailAnalysis, ModelResult } from '../src/types/forensics';
import { parseEmail } from './parser/emailParser';
import { runHeaderForensics } from './forensics/headerForensics';
import { analyzeAuthentication } from './forensics/authForensics';
import { analyzeContentUrls } from './forensics/contentForensics';
import { ModelRegistry } from './ml/modelRegistry';
import { extractStandardizedModelFeatures } from './ml/featureExtractor';
import { runInfrastructureEnrichment } from './intelligence/infrastructureEnrichment';
import { buildEmailGraph } from './graph/graphEngine';
import { fuseEvidence } from './fusion/evidenceFusion';
import { SessionStore } from './store/sessionStore';

export interface AnalysisPipelineOptions {
  sourceFilename?: string;
  isFileUpload?: boolean;
}

/**
 * Executes the complete forensic threat analysis pipeline on raw email input
 */
export async function executeAnalysisPipeline(
  rawInput: string | Buffer,
  options: AnalysisPipelineOptions = {}
): Promise<EmailAnalysis> {
  const analysisId = crypto.randomUUID();
  const createdAt = new Date().toISOString();

  // Snapshot model configuration lock at the exact start of this analysis (Section 4)
  const modelRegistry = ModelRegistry.getInstance();
  const { adapter: activeModel, snapshot: modelSnapshot } = modelRegistry.captureSnapshotForAnalysis();

  // 1. Email & MIME Parsing
  const parsed = await parseEmail(rawInput, options.isFileUpload);

  // 2. Header and SMTP Forensics
  const headerFindings = runHeaderForensics(
    parsed.receivedHeaders,
    parsed.envelope,
    parsed.rawHeaders
  );

  // 3. Authentication Forensics (SPF, DKIM, DMARC)
  const authFindings = analyzeAuthentication(
    parsed.authResultsHeaders,
    parsed.receivedSpfHeaders,
    parsed.dkimSignatureHeaders,
    parsed.envelope
  );

  // 4. Content and URL Analysis
  const contentResult = analyzeContentUrls(
    parsed.bodyText,
    parsed.bodyHtml,
    parsed.envelope.from?.domain
  );

  // 5. Standardized Feature Extraction (Preserving Four-State true/false/unknown/not_applicable - Section 2)
  const standardizedFeatures = extractStandardizedModelFeatures({
    envelope: parsed.envelope,
    rawHeaders: parsed.rawHeaders,
    bodyText: parsed.bodyText,
    bodyHtml: parsed.bodyHtml,
    hasHeaders: parsed.availableEvidence.hasHeaders,
    hasReceivedChain: parsed.availableEvidence.hasReceivedChain,
    hasAuthenticationHeaders: parsed.availableEvidence.hasAuthenticationHeaders,
    headerFindings,
    authFindings,
    urls: contentResult.urls,
    attachments: parsed.attachments
  });

  // 6. Machine Learning Inference via Captured Adapter Snapshot (Section 3 & 4)
  const prediction = await activeModel.predict(standardizedFeatures, modelSnapshot.snapshotId);

  const mlResult: ModelResult = {
    modelId: prediction.modelId,
    modelName: prediction.modelName,
    modelVersion: prediction.modelVersion,
    preprocessingVersion: prediction.preprocessingVersion,
    featureSchemaVersion: prediction.featureSchemaVersion,
    configurationSnapshotId: prediction.snapshotId,
    predictedClass: prediction.predictedClass,
    decisionScore: prediction.scoreSemantics.decisionScore,
    probability: prediction.scoreSemantics.probability,
    rawScore: prediction.scoreSemantics.probability ?? prediction.scoreSemantics.decisionScore,
    calibratedProbability: prediction.scoreSemantics.calibratedProbability,
    isCalibrated: prediction.scoreSemantics.isCalibrated,
    calibrationMethod: prediction.scoreSemantics.calibrationMethod,
    predictionTimestamp: prediction.predictionTimestamp,
    mlConfigured: prediction.isConfigured,
    isAvailable: prediction.predictedClass !== 'unavailable',
    isExperimentallyValidated: false, // Explicitly false per Section 6
    featureAvailability: Object.keys(standardizedFeatures.missingnessMetadata),
    rationale: prediction.rationale,
    limitations: prediction.limitations,
    contributingFeatures: prediction.contributingFeatures
  };

  // 7. Infrastructure Intelligence Enrichment
  const candidateIpsToQuery = headerFindings.candidateSourceIps.map(c => ({
    ip: c.ip,
    ipType: c.ipType
  }));

  const allDomains = [
    ...(parsed.envelope.from?.domain ? [parsed.envelope.from.domain] : []),
    ...contentResult.domains
  ];

  const infrastructureFindings = await runInfrastructureEnrichment(
    candidateIpsToQuery,
    allDomains
  );

  // 8. Graph Representation
  const graph = buildEmailGraph({
    analysisId,
    envelope: parsed.envelope,
    receivedHops: headerFindings.receivedHops,
    candidateSourceIps: headerFindings.candidateSourceIps,
    urls: contentResult.urls,
    observations: infrastructureFindings
  });

  // 9. Deterministic Evidence Fusion (Section 9: Forensic engine preserved)
  // Consumes validated probabilities only, never uncalibrated decision margins as probability!
  const fusionMlScore = (prediction.isConfigured && prediction.scoreSemantics.probability !== undefined) 
    ? prediction.scoreSemantics.probability 
    : (prediction.scoreSemantics.isCalibrated && prediction.scoreSemantics.calibratedProbability !== undefined 
        ? prediction.scoreSemantics.calibratedProbability 
        : undefined);

  const overallAssessment = fuseEvidence({
    inputType: parsed.inputType,
    hasHeaders: parsed.availableEvidence.hasHeaders,
    hasReceivedChain: parsed.availableEvidence.hasReceivedChain,
    hasAuthenticationHeaders: parsed.availableEvidence.hasAuthenticationHeaders,
    hasBodyText: parsed.availableEvidence.hasBodyText,
    hasBodyHtml: parsed.availableEvidence.hasBodyHtml,
    hasAttachments: parsed.availableEvidence.hasAttachments,
    headerFindings,
    authFindings,
    urls: contentResult.urls,
    contentFindings: contentResult.contentFindings,
    attachments: parsed.attachments,
    mlScore: fusionMlScore,
    mlConfigured: prediction.isConfigured && fusionMlScore !== undefined
  });

  // 10. Limitations compilation
  const limitations: string[] = [
    'In-memory session processing: Raw email contents and attachments are not permanently stored on disk.',
    ...authFindings.limitations
  ];
  if (!mlResult.mlConfigured) {
    limitations.push('ML classification is unconfigured; overall assessment relies strictly on deterministic forensic heuristics.');
  } else if (!mlResult.isExperimentallyValidated) {
    limitations.push(`ML model '${mlResult.modelName}' is an active research baseline; it is not certified as an experimentally validated production classifier.`);
  }

  const analysis: EmailAnalysis = {
    analysisId,
    createdAt,
    inputType: parsed.inputType,
    sourceFilename: options.sourceFilename,
    parsingStatus: parsed.parsingStatus,
    envelope: parsed.envelope,
    rawHeaders: parsed.rawHeaders,
    availableEvidence: parsed.availableEvidence,
    forensicFindings: headerFindings,
    authenticationFindings: authFindings,
    contentFindings: {
      urls: contentResult.urls,
      domains: contentResult.domains,
      suspiciousIndicators: contentResult.contentFindings,
      bodySnippet: parsed.bodyText.slice(0, 500),
      attachments: parsed.attachments
    },
    mlResult,
    infrastructureFindings,
    graph,
    overallAssessment,
    limitations
  };

  // 11. Store in temporary in-memory session store
  SessionStore.getInstance().saveAnalysis(analysis);

  return analysis;
}
