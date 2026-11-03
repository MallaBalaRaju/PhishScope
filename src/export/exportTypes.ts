import { EmailAnalysis } from '../types/forensics';

export type ExportFormat = 'json' | 'pdf' | 'xlsx';

export interface ExportOptions {
  includeSensitiveRawData?: boolean;
  includeSha256Checksum?: boolean;
  analystName?: string;
  notes?: string;
}

export interface ExportMetadata {
  exportSchemaVersion: string;
  applicationName: string;
  applicationVersion: string;
  exportTimestamp: string;
  investigationId: string;
  exportFormat: ExportFormat;
  checksumSha256?: string;
  isPartialExport: boolean;
  includesSensitiveData: boolean;
  dataClassification: 'CONFIDENTIAL_FORENSIC_EVIDENCE' | 'SANITIZED_FORENSIC_SUMMARY';
}

export interface CanonicalExportData {
  metadata: ExportMetadata;
  summary: {
    investigationId: string;
    analysisTimestamp: string;
    inputType: string;
    subject: string;
    senderName?: string;
    senderAddress: string;
    senderDomain: string;
    recipientAddresses: string[];
    replyToAddress?: string;
    messageDate?: string;
    overallLabel: string;
    observedRiskScore: number;
    evidenceCoverageScore: number;
    assessmentConfidence: string;
    executiveSummary: string;
  };
  headersAndRouting: {
    envelopeFrom: string;
    returnPath: string;
    returnPathDomain: string;
    messageId: string;
    receivedHopsCount: number;
    chronologicalHops: Array<{
      hopIndex: number;
      rawPositionFromTop: number;
      reportingServer: string;
      receivingServer: string;
      ipAddress: string;
      ipType: string;
      trustZone: string;
      isBorderHop: boolean;
      isPotentiallyForged: boolean;
      timeDeltaSeconds: number | null;
      timestamp: string;
      protocol: string;
      suspiciousSignals: string[];
    }>;
    candidateSourceIps: Array<{
      ip: string;
      ipType: string;
      confidence: string;
      justification: string;
      attributionCategory: string;
      trustBoundary: string;
      isSpecialPurpose: boolean;
    }>;
    routingAnomalies: Array<{
      findingId: string;
      findingType: string;
      value: string;
      status: string;
      explanation: string;
    }>;
    identityMismatches: Array<{
      findingId: string;
      findingType: string;
      value: string;
      status: string;
      explanation: string;
    }>;
  };
  authentication: {
    provenance: string;
    authResultsHeaderPresent: boolean;
    rawAuthResultsHeader?: string;
    spf: {
      result: string;
      domain: string;
      helo?: string;
      ip?: string;
      alignmentWithFrom: string;
      alignmentMode: string;
      note: string;
    };
    dkim: {
      result: string;
      domain: string;
      selector: string;
      alignmentWithFrom: string;
      alignmentMode: string;
      note: string;
    };
    dmarc: {
      result: string;
      policy: string;
      fromDomain: string;
      alignmentWithFrom: string;
      alignmentMode: { spf: string; dkim: string };
      spfAlignmentContribution: boolean;
      dkimAlignmentContribution: boolean;
      reportedProvenance: string;
      note: string;
    };
    verificationLimitations: string[];
  };
  urlsAndContent: {
    urlCount: number;
    urls: Array<{
      url: string;
      defangedUrl: string;
      domain: string;
      protocol: string;
      isIpBased: boolean;
      isPunycode: boolean;
      isShortener: boolean;
      isMismatch: boolean;
      displayText?: string;
      suspiciousFlags: string[];
    }>;
    contentIndicators: Array<{
      findingId: string;
      findingType: string;
      value: string;
      status: string;
      explanation: string;
    }>;
    bodySnippet: string;
  };
  attachments: {
    attachmentCount: number;
    items: Array<{
      filename: string;
      contentType: string;
      sizeBytes: number;
      sizeFormatted: string;
      checksumSha256: string;
      isSuspiciousExtension: boolean;
      suspicionReason?: string;
    }>;
  };
  infrastructureIntelligence: {
    observationCount: number;
    items: Array<{
      entity: string;
      entityType: string;
      provider: string;
      queryTarget: string;
      queryTimestamp: string;
      status: string;
      observationData: Record<string, any>;
      reliabilityLimitations: string;
    }>;
  };
  relationshipGraph: {
    nodeCount: number;
    edgeCount: number;
    nodes: Array<{
      id: string;
      type: string;
      label: string;
      evidenceReferences: string[];
      attributes?: Record<string, any>;
    }>;
    edges: Array<{
      id: string;
      sourceNode: string;
      targetNode: string;
      relationshipType: string;
      confidence: string;
      relationshipNature: string;
      isDirectlyObserved: boolean;
      observedAt: string;
      supportingObservation?: string;
      evidenceReferences: string[];
    }>;
  };
  machineLearning: {
    modelId: string;
    modelName: string;
    modelVersion: string;
    preprocessingVersion: string;
    featureSchemaVersion: string;
    configurationSnapshotId?: string;
    predictedClass: string;
    decisionScore?: number | null;
    probability?: number | null;
    calibratedProbability?: number | null;
    isCalibrated: boolean;
    calibrationMethod?: string | null;
    isConfigured: boolean;
    isAvailable: boolean;
    isExperimentallyValidated: boolean;
    rationale?: string;
    limitations: string[];
  };
  evidenceFusionAndLimitations: {
    observedRiskScore: number;
    evidenceCoverageScore: number;
    assessmentConfidence: string;
    assessmentLabel: string;
    primaryRiskFactors: string[];
    mitigatingFactors: string[];
    reasoningChain: string[];
    availableEvidenceCategories: string[];
    unavailableEvidenceCategories: string[];
    investigationLimitations: string[];
    analystNotes?: string;
  };
}
