import { EmailAnalysis } from '../types/forensics';
import { CanonicalExportData, ExportFormat, ExportOptions, ExportMetadata } from './exportTypes';

export const EXPORT_SCHEMA_VERSION = '1.0.0';
export const APPLICATION_NAME = 'PhishScope Forensics & Threat Intel';
export const APPLICATION_VERSION = '1.2.0';

/**
 * Safely sanitizes filenames across Windows, macOS, and Linux
 */
export function sanitizeFilename(filename: string): string {
  return filename
    .replace(/[/\\?%*:|"<>]/g, '_')
    .replace(/\s+/g, '_')
    .replace(/_+/g, '_')
    .slice(0, 120);
}

/**
 * Generates standardized export filename:
 * PhishScope_Investigation_<investigation-id>_<YYYY-MM-DD>.<extension>
 */
export function generateExportFilename(
  investigationId: string, 
  format: ExportFormat, 
  date: Date = new Date()
): string {
  const safeId = sanitizeFilename(investigationId.slice(0, 12));
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  const ext = format === 'xlsx' ? 'xlsx' : format === 'pdf' ? 'pdf' : 'json';
  return `PhishScope_Investigation_${safeId}_${year}-${month}-${day}.${ext}`;
}

/**
 * Formats bytes into human-readable representation
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i] || 'B'}`;
}

/**
 * Creates an immutable, consistent snapshot of the active investigation for export.
 * Preserves all forensic evidence distinctions (directly observed, derived, inferred, unknown).
 * Does NOT recalculate forensic findings or alter scores.
 */
export function buildCanonicalExportData(
  analysis: EmailAnalysis,
  format: ExportFormat,
  options: ExportOptions = {}
): CanonicalExportData {
  if (!analysis || !analysis.analysisId) {
    throw new Error('Cannot export: No valid canonical investigation object was provided.');
  }

  // Deep clone to ensure asynchronous export runs on an immutable snapshot
  const snapshot: EmailAnalysis = JSON.parse(JSON.stringify(analysis));
  const now = new Date().toISOString();
  const includeSensitive = !!options.includeSensitiveRawData;

  const metadata: ExportMetadata = {
    exportSchemaVersion: EXPORT_SCHEMA_VERSION,
    applicationName: APPLICATION_NAME,
    applicationVersion: APPLICATION_VERSION,
    exportTimestamp: now,
    investigationId: snapshot.analysisId,
    exportFormat: format,
    isPartialExport: false,
    includesSensitiveData: includeSensitive,
    dataClassification: includeSensitive 
      ? 'CONFIDENTIAL_FORENSIC_EVIDENCE' 
      : 'SANITIZED_FORENSIC_SUMMARY'
  };

  // 1. Summary
  const summary = {
    investigationId: snapshot.analysisId,
    analysisTimestamp: snapshot.createdAt,
    inputType: snapshot.inputType,
    subject: snapshot.envelope.subject || 'No Subject Provided',
    senderName: snapshot.envelope.from?.name,
    senderAddress: snapshot.envelope.from?.address || 'Unknown From Address',
    senderDomain: snapshot.envelope.from?.domain || 'unknown',
    recipientAddresses: (snapshot.envelope.to || []).map(t => t.address),
    replyToAddress: snapshot.envelope.replyTo?.address,
    messageDate: snapshot.envelope.date,
    overallLabel: snapshot.overallAssessment.label,
    observedRiskScore: snapshot.overallAssessment.observedRiskScore ?? snapshot.overallAssessment.score,
    evidenceCoverageScore: snapshot.overallAssessment.evidenceCoverageScore ?? 100,
    assessmentConfidence: snapshot.overallAssessment.confidenceLevel,
    executiveSummary: snapshot.overallAssessment.summary
  };

  // 2. Headers and Routing
  const headersAndRouting = {
    envelopeFrom: snapshot.envelope.from?.address || 'None',
    returnPath: snapshot.envelope.returnPath || 'None',
    returnPathDomain: snapshot.envelope.returnPathDomain || 'None',
    messageId: snapshot.envelope.messageId || 'Missing',
    receivedHopsCount: snapshot.forensicFindings.receivedHops.length,
    chronologicalHops: snapshot.forensicFindings.receivedHops.map(h => ({
      hopIndex: h.hopIndex,
      rawPositionFromTop: h.rawPositionFromTop ?? 0,
      reportingServer: h.reportingServer || 'Unknown server',
      receivingServer: h.receivingServer || h.byServer || 'Unknown server',
      ipAddress: h.ipAddress || 'None parsed',
      ipType: h.ipType,
      trustZone: h.trustZone || 'untrusted_external',
      isBorderHop: !!h.isBorderHop,
      isPotentiallyForged: !!h.isPotentiallyForged,
      timeDeltaSeconds: h.timeDeltaSeconds !== undefined ? h.timeDeltaSeconds : null,
      timestamp: h.timestamp || 'No timestamp',
      protocol: h.protocol || 'Unknown',
      suspiciousSignals: h.suspiciousSignals || []
    })),
    candidateSourceIps: snapshot.forensicFindings.candidateSourceIps.map(c => ({
      ip: c.ip,
      ipType: c.ipType,
      confidence: c.confidence,
      justification: c.justification,
      attributionCategory: c.attributionCategory || 'candidate_originating',
      trustBoundary: c.trustBoundary || 'untrusted_external',
      isSpecialPurpose: !!c.isSpecialPurpose
    })),
    routingAnomalies: (snapshot.forensicFindings.routingAnomalies || []).map(a => ({
      findingId: a.findingId,
      findingType: a.findingType,
      value: a.value,
      status: a.status,
      explanation: a.explanation
    })),
    identityMismatches: (snapshot.forensicFindings.identityMismatches || []).map(m => ({
      findingId: m.findingId,
      findingType: m.findingType,
      value: m.value,
      status: m.status,
      explanation: m.explanation
    }))
  };

  // 3. Authentication
  const authentication = {
    provenance: snapshot.authenticationFindings.provenance,
    authResultsHeaderPresent: snapshot.authenticationFindings.authResultsHeaderPresent,
    rawAuthResultsHeader: includeSensitive ? snapshot.authenticationFindings.rawAuthResultsHeader : undefined,
    spf: {
      result: snapshot.authenticationFindings.spf.result,
      domain: snapshot.authenticationFindings.spf.domain || 'Not evaluated',
      helo: snapshot.authenticationFindings.spf.helo,
      ip: snapshot.authenticationFindings.spf.ip,
      alignmentWithFrom: snapshot.authenticationFindings.spf.alignmentWithFrom,
      alignmentMode: snapshot.authenticationFindings.spf.alignmentMode || 'relaxed',
      note: snapshot.authenticationFindings.spf.note
    },
    dkim: {
      result: snapshot.authenticationFindings.dkim.result,
      domain: snapshot.authenticationFindings.dkim.domain || 'Not evaluated',
      selector: snapshot.authenticationFindings.dkim.selector || 'Not evaluated',
      alignmentWithFrom: snapshot.authenticationFindings.dkim.alignmentWithFrom,
      alignmentMode: snapshot.authenticationFindings.dkim.alignmentMode || 'relaxed',
      note: snapshot.authenticationFindings.dkim.note
    },
    dmarc: {
      result: snapshot.authenticationFindings.dmarc.result,
      policy: snapshot.authenticationFindings.dmarc.policy || 'none',
      fromDomain: snapshot.authenticationFindings.dmarc.fromDomain || snapshot.envelope.from?.domain || 'unknown',
      alignmentWithFrom: snapshot.authenticationFindings.dmarc.alignmentWithFrom,
      alignmentMode: snapshot.authenticationFindings.dmarc.alignmentMode || { spf: 'relaxed', dkim: 'relaxed' },
      spfAlignmentContribution: !!snapshot.authenticationFindings.dmarc.spfAlignmentContribution,
      dkimAlignmentContribution: !!snapshot.authenticationFindings.dmarc.dkimAlignmentContribution,
      reportedProvenance: snapshot.authenticationFindings.dmarc.reportedProvenance || 'header_reported',
      note: snapshot.authenticationFindings.dmarc.note
    },
    verificationLimitations: snapshot.authenticationFindings.limitations || []
  };

  // 4. URLs and Content
  const urlsAndContent = {
    urlCount: (snapshot.contentFindings.urls || []).length,
    urls: (snapshot.contentFindings.urls || []).map(u => ({
      url: includeSensitive ? u.url : u.defangedUrl,
      defangedUrl: u.defangedUrl,
      domain: u.domain,
      protocol: u.protocol,
      isIpBased: !!u.isIpBased,
      isPunycode: !!u.isPunycode,
      isShortener: !!u.isShortener,
      isMismatch: !!u.isMismatch,
      displayText: u.displayText,
      suspiciousFlags: u.suspiciousFlags || []
    })),
    contentIndicators: (snapshot.contentFindings.suspiciousIndicators || []).map(i => ({
      findingId: i.findingId,
      findingType: i.findingType,
      value: i.value,
      status: i.status,
      explanation: i.explanation
    })),
    bodySnippet: includeSensitive 
      ? (snapshot.contentFindings.bodySnippet || '') 
      : '[Body text snippet redacted in default privacy export. Enable sensitive export option if required.]'
  };

  // 5. Attachments
  const attachments = {
    attachmentCount: (snapshot.contentFindings.attachments || []).length,
    items: (snapshot.contentFindings.attachments || []).map(att => ({
      filename: att.filename,
      contentType: att.contentType,
      sizeBytes: att.size,
      sizeFormatted: formatBytes(att.size),
      checksumSha256: att.checksumSha256 || 'Unavailable',
      isSuspiciousExtension: !!att.isSuspiciousExtension,
      suspicionReason: att.suspicionReason
    }))
  };

  // 6. Infrastructure Intelligence
  const infrastructureIntelligence = {
    observationCount: (snapshot.infrastructureFindings || []).length,
    items: (snapshot.infrastructureFindings || []).map(obs => ({
      entity: obs.entity,
      entityType: obs.entityType,
      provider: obs.provider,
      queryTarget: obs.queryTarget || obs.entity,
      queryTimestamp: obs.queryTimestamp || obs.retrievedAt,
      status: obs.status,
      observationData: obs.observation || {},
      reliabilityLimitations: obs.reliabilityLimitations
    }))
  };

  // 7. Relationship Graph
  const relationshipGraph = {
    nodeCount: (snapshot.graph?.nodes || []).length,
    edgeCount: (snapshot.graph?.edges || []).length,
    nodes: (snapshot.graph?.nodes || []).map(n => ({
      id: n.id,
      type: n.type,
      label: n.label,
      evidenceReferences: n.evidenceReferences || [],
      attributes: n.attributes
    })),
    edges: (snapshot.graph?.edges || []).map(e => ({
      id: e.id,
      sourceNode: e.sourceNode,
      targetNode: e.targetNode,
      relationshipType: e.relationshipType,
      confidence: e.confidence,
      relationshipNature: e.relationshipNature || (e.isDirectlyObserved ? 'directly_observed' : 'inferred'),
      isDirectlyObserved: !!e.isDirectlyObserved,
      observedAt: e.observedAt,
      supportingObservation: e.supportingObservation,
      evidenceReferences: e.evidenceReferences || []
    }))
  };

  // 8. Machine Learning
  const machineLearning = {
    modelId: snapshot.mlResult.modelId || 'unconfigured-baseline',
    modelName: snapshot.mlResult.modelName,
    modelVersion: snapshot.mlResult.modelVersion,
    preprocessingVersion: snapshot.mlResult.preprocessingVersion,
    featureSchemaVersion: snapshot.mlResult.featureSchemaVersion || '2.0.0',
    configurationSnapshotId: snapshot.mlResult.configurationSnapshotId,
    predictedClass: snapshot.mlResult.predictedClass || 'unavailable',
    decisionScore: snapshot.mlResult.decisionScore,
    probability: snapshot.mlResult.probability,
    calibratedProbability: snapshot.mlResult.calibratedProbability,
    isCalibrated: !!snapshot.mlResult.isCalibrated,
    calibrationMethod: snapshot.mlResult.calibrationMethod,
    isConfigured: !!snapshot.mlResult.mlConfigured,
    isAvailable: snapshot.mlResult.isAvailable !== false,
    isExperimentallyValidated: !!snapshot.mlResult.isExperimentallyValidated,
    rationale: snapshot.mlResult.rationale,
    limitations: snapshot.mlResult.limitations || []
  };

  // 9. Evidence Fusion & Limitations
  const evidenceFusionAndLimitations = {
    observedRiskScore: snapshot.overallAssessment.observedRiskScore ?? snapshot.overallAssessment.score,
    evidenceCoverageScore: snapshot.overallAssessment.evidenceCoverageScore ?? 100,
    assessmentConfidence: snapshot.overallAssessment.confidenceLevel,
    assessmentLabel: snapshot.overallAssessment.label,
    primaryRiskFactors: snapshot.overallAssessment.primaryRiskFactors || [],
    mitigatingFactors: snapshot.overallAssessment.mitigatingFactors || [],
    reasoningChain: snapshot.overallAssessment.reasoningChain || [],
    availableEvidenceCategories: snapshot.overallAssessment.availableEvidenceCategories || [],
    unavailableEvidenceCategories: snapshot.overallAssessment.unavailableEvidenceCategories || [],
    investigationLimitations: snapshot.limitations || [],
    analystNotes: snapshot.analystNotes || options.notes
  };

  return {
    metadata,
    summary,
    headersAndRouting,
    authentication,
    urlsAndContent,
    attachments,
    infrastructureIntelligence,
    relationshipGraph,
    machineLearning,
    evidenceFusionAndLimitations
  };
}
