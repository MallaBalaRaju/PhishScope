import { ModelResult } from '../../src/types/forensics';

export interface MLFeatureExtractionInput {
  bodyText: string;
  hasHtml: boolean;
  subject?: string;
  senderDomain?: string;
  hasAuthenticationFailures: boolean;
  hasRoutingAnomalies: boolean;
  numExtractedUrls: number;
  hasIpBasedUrls: boolean;
  hasAnchorMismatch: boolean;
  numAttachments: number;
  hasSuspiciousAttachments: boolean;
}

export interface IMLClassifierAdapter {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly preprocessingVersion: string;
  readonly description: string;
  isConfigured(): boolean;
  predict(features: MLFeatureExtractionInput): Promise<ModelResult>;
}

/**
 * Default adapter when no approved research model weights or endpoint are provisioned.
 * Complying with Section 3.1: Never fabricates predictions or unapproved dataset metrics.
 */
export class UnconfiguredModelAdapter implements IMLClassifierAdapter {
  readonly id = 'unconfigured';
  readonly name = 'Pluggable ML Inference Interface';
  readonly version = '0.0.0-unconfigured';
  readonly preprocessingVersion = 'none';
  readonly description = 'Inference architecture ready for approved TF-IDF, GBDT, or Transformer models.';

  isConfigured(): boolean {
    return false;
  }

  async predict(features: MLFeatureExtractionInput): Promise<ModelResult> {
    return {
      modelName: this.name,
      modelVersion: this.version,
      preprocessingVersion: this.preprocessingVersion,
      mlConfigured: false,
      isCalibrated: false,
      predictionTimestamp: new Date().toISOString(),
      featureAvailability: [
        'Lexical TF-IDF Vectorizer (Ready for configuration)',
        'Syntactic Header & Hop Features (Ready for configuration)',
        'URL & Entity Tokenizer (Ready for configuration)'
      ],
      rationale: 'ML classification has not yet been configured. The application architecture supports interchangeable model adapters (e.g. TF-IDF + Logistic Regression, Linear SVM, GBDT with structured forensic features, or HuggingFace/ONNX Transformer classifiers) once approved research model weights are supplied.'
    };
  }
}

/**
 * Optional Test Double / Baseline Heuristic Classifier for synthetic testing & regression verification.
 * Clearly labeled as an offline test double, NOT experimentally validated research ML.
 */
export class SyntheticTestDoubleModelAdapter implements IMLClassifierAdapter {
  readonly id = 'test-double-baseline';
  readonly name = 'Baseline Heuristic Test Double (Research Baseline)';
  readonly version = '0.1.0-test-double';
  readonly preprocessingVersion = 'v1-standardized-heuristics';
  readonly description = 'Deterministic test double intended solely for CI/CD test verification, not validated ML.';

  isConfigured(): boolean {
    return true;
  }

  async predict(features: MLFeatureExtractionInput): Promise<ModelResult> {
    let score = 0.05;
    const reasons: string[] = [];

    if (features.hasAnchorMismatch) {
      score += 0.45;
      reasons.push('Anchor text divergence (+0.45)');
    }
    if (features.hasAuthenticationFailures) {
      score += 0.30;
      reasons.push('Authentication validation failure (+0.30)');
    }
    if (features.hasIpBasedUrls) {
      score += 0.25;
      reasons.push('Direct IP URL host (+0.25)');
    }
    if (features.hasSuspiciousAttachments) {
      score += 0.35;
      reasons.push('Executable or script attachment (+0.35)');
    }
    if (features.hasRoutingAnomalies) {
      score += 0.15;
      reasons.push('Routing anomalies in Received hops (+0.15)');
    }

    const clampedScore = Math.min(1.0, Math.max(0.0, score));
    const predictedClass = clampedScore >= 0.5 ? 'phishing' : 'legitimate';

    return {
      modelName: this.name,
      modelVersion: this.version,
      preprocessingVersion: this.preprocessingVersion,
      mlConfigured: true,
      predictedClass,
      rawScore: Math.round(clampedScore * 100) / 100,
      calibratedProbability: Math.round(clampedScore * 100) / 100,
      isCalibrated: false,
      predictionTimestamp: new Date().toISOString(),
      featureAvailability: [
        'hasAnchorMismatch',
        'hasAuthenticationFailures',
        'hasIpBasedUrls',
        'hasSuspiciousAttachments',
        'hasRoutingAnomalies'
      ],
      rationale: `Test double evaluation: ${reasons.join(', ') || 'Nominal baseline signals'}. Note: This is an uncalibrated test double for development validation only.`
    };
  }
}

/**
 * Model Registry managing interchangeable classifiers
 */
export class ModelRegistry {
  private static instance: ModelRegistry;
  private currentAdapter: IMLClassifierAdapter;
  private availableAdapters: Map<string, IMLClassifierAdapter> = new Map();

  private constructor() {
    const unconfigured = new UnconfiguredModelAdapter();
    const testDouble = new SyntheticTestDoubleModelAdapter();

    this.availableAdapters.set(unconfigured.id, unconfigured);
    this.availableAdapters.set(testDouble.id, testDouble);

    // Default is strictly UNCONFIGURED as mandated by Section 3.1 & Section 10
    this.currentAdapter = unconfigured;
  }

  public static getInstance(): ModelRegistry {
    if (!ModelRegistry.instance) {
      ModelRegistry.instance = new ModelRegistry();
    }
    return ModelRegistry.instance;
  }

  public getActiveAdapter(): IMLClassifierAdapter {
    return this.currentAdapter;
  }

  public setActiveAdapter(adapterId: string): boolean {
    const adapter = this.availableAdapters.get(adapterId);
    if (adapter) {
      this.currentAdapter = adapter;
      return true;
    }
    return false;
  }

  public listAdapters(): Array<{ id: string; name: string; version: string; isConfigured: boolean; description: string }> {
    return Array.from(this.availableAdapters.values()).map(a => ({
      id: a.id,
      name: a.name,
      version: a.version,
      isConfigured: a.isConfigured(),
      description: a.description
    }));
  }
}
