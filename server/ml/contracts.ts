/**
 * Standardized Machine Learning Model Adapter Contracts
 * Complies with Academic Research Integrity, Decision 3.1, and Four-State Feature Representation
 */

export type FeatureState = 'true' | 'false' | 'unknown' | 'not_applicable';
export type MissingnessState = 'present' | 'missing' | 'inapplicable' | 'malformed';

export interface StandardizedModelFeatures {
  schemaVersion: string; // e.g. "2.0.0"
  extractorVersion: string; // e.g. "1.1.0"
  extractedAt: string;

  // Lexical Features
  subjectText: string | null;
  bodyCleanText: string | null;
  hasHtmlMarkup: FeatureState;
  textLengthChars: number;
  wordCount: number;

  // Authentication Four-State Features (Never coerced from missing to false)
  spfPass: FeatureState;
  dkimPass: FeatureState;
  dmarcPass: FeatureState;
  isDomainAligned: FeatureState;

  // Routing Four-State Features
  hasNegativeTransitTime: FeatureState;
  hasPrivateOriginHop: FeatureState;
  hasIntermediateLoopback: FeatureState;
  totalHopCount: number | null;
  candidateIpCount: number;

  // Content & URL Four-State Features
  hasDirectIpUrls: FeatureState;
  hasAnchorTextDivergence: FeatureState;
  hasPunycodeDomains: FeatureState;
  hasShortenerUrls: FeatureState;
  totalUrlCount: number;
  suspiciousBrandMentionCount: number;

  // Attachment Four-State Features
  hasSuspiciousAttachmentType: FeatureState;
  attachmentCount: number;

  // Provenance & Missingness Metadata
  missingnessMetadata: Record<string, MissingnessState>;
  featureProvenance: Record<string, string>;
}

export interface ModelScoreSemantics {
  /**
   * Model-specific raw output (e.g. SVM margin distance -inf..+inf, log-odds, or tree leaf values).
   * Uncalibrated decision scores must NEVER be labeled as probabilities.
   */
  decisionScore?: number;

  /**
   * Raw probability between 0.0 and 1.0 if natively supported by the model (e.g. Logistic Regression sigmoid output).
   */
  probability?: number;

  /**
   * Calibrated probability between 0.0 and 1.0 after a verified calibration process (e.g. Platt scaling).
   */
  calibratedProbability?: number;

  /**
   * Strictly indicates whether calibratedProbability was generated via an approved calibrator.
   */
  isCalibrated: boolean;

  /**
   * Documented calibration method, or null if uncalibrated.
   */
  calibrationMethod?: string | null;
}

export interface ModelHealthStatus {
  isRegistered: boolean;
  isConfigured: boolean;
  isLoaded: boolean;
  isHealthy: boolean;
  isAvailable: boolean;
  /**
   * A model must NOT be marked as experimentally validated merely because its endpoint is healthy.
   * Must remain false until research evaluation has been completed.
   */
  isExperimentallyValidated: boolean;
  statusMessage: string;
  lastCheckedAt: string;
}

export interface ModelConfigurationSnapshot {
  snapshotId: string;
  modelId: string;
  modelName: string;
  modelVersion: string;
  preprocessingVersion: string;
  featureSchemaVersion: string;
  capturedAt: string;
}

export interface StandardizedModelPrediction {
  modelId: string;
  modelName: string;
  modelVersion: string;
  preprocessingVersion: string;
  featureSchemaVersion: string;
  snapshotId: string;
  predictionTimestamp: string;
  isConfigured: boolean;
  predictedClass?: 'phishing' | 'legitimate' | 'suspicious' | 'inconclusive' | 'unavailable';
  scoreSemantics: ModelScoreSemantics;
  confidenceScore?: number;
  contributingFeatures?: Array<{
    featureName: string;
    featureState: string;
    importance?: number;
    explanation?: string;
  }>;
  inferenceLatencyMs?: number;
  rationale: string;
  limitations: string[];
}

export interface PhishingModelAdapter {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly preprocessingVersion: string;
  readonly classification: 'research_baseline' | 'research_model' | 'serving_connector';
  readonly supportedModalities: ReadonlyArray<'lexical' | 'structured' | 'hybrid'>;

  getHealth(): Promise<ModelHealthStatus>;
  getStatus?(): Promise<ModelHealthStatus>;
  predict(features: StandardizedModelFeatures, snapshotId?: string): Promise<StandardizedModelPrediction>;
}
