/**
 * Data contracts and evidence models for PhishScope
 * Compliant with RFC 5322, RFC 8601, RFC 7601, RFC 7208, RFC 6376, RFC 7489
 */

export type InputType = 'eml_file' | 'pasted_raw' | 'pasted_headers' | 'pasted_body';

export type AuthStatus = 
  | 'pass' 
  | 'fail' 
  | 'softfail' 
  | 'neutral' 
  | 'none' 
  | 'temperror' 
  | 'permerror' 
  | 'missing' 
  | 'unknown' 
  | 'not_independently_verified';

export type AlignmentStatus = 'aligned' | 'relaxed' | 'strict' | 'misaligned' | 'inapplicable' | 'unknown';

export type AssessmentLabel = 
  | 'likely_phishing' 
  | 'potentially_suspicious' 
  | 'likely_legitimate' 
  | 'inconclusive' 
  | 'insufficient_evidence';

export type IpType = 
  | 'public' 
  | 'private' 
  | 'reserved' 
  | 'loopback' 
  | 'documentation' 
  | 'multicast' 
  | 'unspecified' 
  | 'invalid';

export interface EvidenceFinding {
  findingId: string;
  findingType: string;
  value: string;
  status: 'pass' | 'fail' | 'warning' | 'info';
  source: string;
  observedAt: string;
  explanation: string;
  confidence?: number;
  supportingEvidenceReferences: string[];
}

export interface ReceivedHop {
  hopIndex: number;
  rawPositionFromTop: number; // 0 = topmost header (closest to recipient MTA)
  reportingServer?: string;
  receivingServer?: string;
  byServer?: string;
  ipAddress?: string;
  ipType: IpType;
  hostname?: string;
  timestamp?: string;
  timeDeltaSeconds?: number;
  protocol?: string;
  rawHeader: string;
  parsingConfidence: number;
  suspiciousSignals: string[];
  trustZone: 'trusted_border' | 'trusted_internal' | 'untrusted_external' | 'potentially_forged';
  isBorderHop: boolean;
  isPotentiallyForged: boolean;
}

export interface AttachmentMetadata {
  filename: string;
  contentType: string;
  size: number;
  checksumSha256: string;
  isSuspiciousExtension: boolean;
  suspicionReason?: string;
}

export interface ExtractedUrl {
  url: string;
  defangedUrl: string;
  domain: string;
  protocol: string;
  port?: number;
  isIpBased: boolean;
  isPunycode: boolean;
  isShortener: boolean;
  suspiciousFlags: string[];
  displayText?: string;
  isMismatch: boolean;
}

export interface ModelScoreSemantics {
  decisionScore?: number;
  probability?: number;
  calibratedProbability?: number;
  isCalibrated: boolean;
  calibrationMethod?: string | null;
}

export interface ModelHealthStatus {
  isRegistered: boolean;
  isConfigured: boolean;
  isLoaded: boolean;
  isHealthy: boolean;
  isAvailable: boolean;
  isExperimentallyValidated: boolean;
  statusMessage: string;
  lastCheckedAt: string;
}

export interface ModelResult {
  modelId?: string;
  modelName: string;
  modelVersion: string;
  preprocessingVersion: string;
  featureSchemaVersion?: string;
  configurationSnapshotId?: string;
  predictedClass?: string;
  decisionScore?: number;
  probability?: number;
  rawScore?: number;
  scoreInterpretation?: string;
  calibratedProbability?: number;
  isCalibrated: boolean;
  calibrationMethod?: string | null;
  predictionTimestamp: string;
  mlConfigured: boolean;
  isAvailable?: boolean;
  isExperimentallyValidated?: boolean;
  featureAvailability: string[];
  rationale?: string;
  limitations?: string[];
  contributingFeatures?: Array<{
    featureName: string;
    featureState: string;
    importance?: number;
    explanation?: string;
  }>;
}

export interface InfrastructureObservation {
  entity: string;
  entityType: 'ip' | 'domain' | 'asn' | 'nameserver' | 'url';
  provider: string;
  queryTarget?: string;
  queryTimestamp?: string;
  returnedValue?: Record<string, any>;
  observation: Record<string, any>;
  retrievedAt: string;
  sourceReference: string;
  status: 'available' | 'provider_unconfigured' | 'nxdomain' | 'no_records' | 'timeout' | 'error' | 'internal_ip_skipped';
  reliabilityLimitations: string;
}

export interface GraphNode {
  id: string;
  type: 'email' | 'sender_address' | 'sender_domain' | 'recipient_domain' | 'candidate_source_ip' | 'mail_server' | 'asn' | 'isp' | 'dns_record' | 'organisation' | 'url' | 'related_domain';
  label: string;
  evidenceReferences: string[];
  attributes?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  sourceNode: string;
  targetNode: string;
  relationshipType: 
    | 'SENT_FROM' 
    | 'ROUTED_THROUGH' 
    | 'RESOLVES_TO' 
    | 'HOSTED_BY' 
    | 'ASSOCIATED_WITH' 
    | 'SHARES_INFRASTRUCTURE_WITH' 
    | 'OBSERVED_IN_EMAIL' 
    | 'RELATED_TO';
  evidenceReferences: string[];
  confidence: 'confirmed_direct' | 'derived' | 'hypothesized';
  observedAt: string;
  supportingObservation?: string;
  isDirectlyObserved?: boolean;
  relationshipNature?: 'directly_observed' | 'inferred' | 'correlated';
}

export interface EmailEnvelope {
  from?: { name?: string; address: string; domain: string };
  to: Array<{ name?: string; address: string; domain: string }>;
  cc: Array<{ name?: string; address: string; domain: string }>;
  replyTo?: { name?: string; address: string; domain: string };
  returnPath?: string;
  returnPathDomain?: string;
  messageId?: string;
  date?: string;
  subject?: string;
}

export interface EmailAnalysis {
  analysisId: string;
  createdAt: string;
  inputType: InputType;
  sourceFilename?: string;
  
  parsingStatus: {
    status: 'success' | 'partial' | 'error';
    errors: string[];
    warnings: string[];
    mimeVersion?: string;
    contentType?: string;
  };
  
  envelope: EmailEnvelope;
  rawHeaders: Record<string, string | string[]>;
  availableEvidence: {
    hasHeaders: boolean;
    hasReceivedChain: boolean;
    hasAuthenticationHeaders: boolean;
    hasBodyText: boolean;
    hasBodyHtml: boolean;
    hasAttachments: boolean;
  };
  
  forensicFindings: {
    receivedHops: ReceivedHop[];
    candidateSourceIps: Array<{ 
      ip: string; 
      confidence: string; 
      justification: string; 
      ipType: IpType;
      attributionCategory?: 'confirmed_originating' | 'candidate_originating' | 'observed_relay';
      trustBoundary?: 'border' | 'untrusted_external' | 'internal_submission';
      isSpecialPurpose?: boolean;
    }>;
    routingAnomalies: EvidenceFinding[];
    identityMismatches: EvidenceFinding[];
    messageIdAnomalies: EvidenceFinding[];
    dateAnomalies: EvidenceFinding[];
  };
  
  authenticationFindings: {
    authResultsHeaderPresent: boolean;
    spf: {
      result: AuthStatus;
      domain?: string;
      scope?: string;
      helo?: string;
      ip?: string;
      mechanism?: string;
      rawSnippet?: string;
      alignmentWithFrom: AlignmentStatus;
      alignmentMode?: 'strict' | 'relaxed';
      note: string;
    };
    dkim: {
      result: AuthStatus;
      domain?: string;
      selector?: string;
      headerSnippet?: string;
      alignmentWithFrom: AlignmentStatus;
      alignmentMode?: 'strict' | 'relaxed';
      note: string;
    };
    dmarc: {
      result: AuthStatus;
      policy?: string;
      fromDomain?: string;
      alignmentWithFrom: AlignmentStatus;
      alignmentMode?: { spf: 'strict' | 'relaxed'; dkim: 'strict' | 'relaxed' };
      spfAlignmentContribution?: boolean;
      dkimAlignmentContribution?: boolean;
      publishedPolicy?: string;
      reportedProvenance?: 'header_reported' | 'independently_verified' | 'unverified' | 'missing';
      note: string;
    };
    provenance: 'reported_in_headers' | 'independently_verified' | 'unverified' | 'missing';
    rawAuthResultsHeader?: string;
    limitations: string[];
  };
  
  contentFindings: {
    urls: ExtractedUrl[];
    domains: string[];
    suspiciousIndicators: EvidenceFinding[];
    bodySnippet: string;
    attachments: AttachmentMetadata[];
  };
  
  mlResult: ModelResult;
  infrastructureFindings: InfrastructureObservation[];
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  
  overallAssessment: {
    label: AssessmentLabel;
    confidenceLevel: 'high' | 'medium' | 'low';
    score: number; // 0 - 100 risk score
    observedRiskScore?: number;
    evidenceCoverageScore?: number;
    availableEvidenceCategories?: string[];
    unavailableEvidenceCategories?: string[];
    summary: string;
    primaryRiskFactors: string[];
    mitigatingFactors: string[];
    reasoningChain: string[];
  };
  
  aiAssistantResult?: {
    observedFacts: string[];
    derivedFindings: string[];
    aiInterpretation: string;
    unknownInformation: string[];
    recommendedFurtherChecks: string[];
    executiveSummary: string;
    generatedAt: string;
    modelUsed: string;
  };
  
  limitations: string[];
  analystNotes?: string;
}

export interface SessionMetrics {
  totalAnalyzed: number;
  phishingCount: number;
  suspiciousCount: number;
  legitimateCount: number;
  inconclusiveCount: number;
  authenticationWarningsCount: number;
  suspiciousRoutingCount: number;
}
