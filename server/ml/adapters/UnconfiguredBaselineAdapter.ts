import { 
  PhishingModelAdapter, 
  StandardizedModelFeatures, 
  StandardizedModelPrediction, 
  ModelHealthStatus 
} from '../contracts';
import { FEATURE_SCHEMA_VERSION } from '../featureExtractor';

export class UnconfiguredBaselineAdapter implements PhishingModelAdapter {
  readonly id = 'unconfigured-baseline';
  readonly name = 'Unconfigured Research Baseline';
  readonly version = '0.0.0-unconfigured';
  readonly preprocessingVersion = 'none';
  readonly classification = 'research_baseline' as const;
  readonly supportedModalities = ['lexical', 'structured', 'hybrid'] as const;

  async getHealth(): Promise<ModelHealthStatus> {
    return {
      isRegistered: true,
      isConfigured: false,
      isLoaded: false,
      isHealthy: true,
      isAvailable: false,
      isExperimentallyValidated: false,
      statusMessage: 'Baseline adapter active. No research classifier configured.',
      lastCheckedAt: new Date().toISOString()
    };
  }

  async predict(
    features: StandardizedModelFeatures, 
    snapshotId = 'default-snapshot'
  ): Promise<StandardizedModelPrediction> {
    return {
      modelId: this.id,
      modelName: this.name,
      modelVersion: this.version,
      preprocessingVersion: this.preprocessingVersion,
      featureSchemaVersion: features.schemaVersion || FEATURE_SCHEMA_VERSION,
      snapshotId,
      predictionTimestamp: new Date().toISOString(),
      isConfigured: false,
      predictedClass: 'inconclusive',
      scoreSemantics: {
        isCalibrated: false,
        calibrationMethod: null
      },
      contributingFeatures: [],
      inferenceLatencyMs: 0,
      rationale: 'ML classification has not yet been configured. Research dataset and model selection remain open per Decision 3.1. Forensic assessment proceeds independently.',
      limitations: [
        'No machine learning model weights are loaded.',
        'Predictions are not generated to prevent fabricated research metrics.'
      ]
    };
  }
}
