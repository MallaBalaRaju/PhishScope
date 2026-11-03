import { 
  PhishingModelAdapter, 
  StandardizedModelFeatures, 
  StandardizedModelPrediction, 
  ModelHealthStatus 
} from '../contracts';
import { FEATURE_SCHEMA_VERSION } from '../featureExtractor';

export class TfidfLinearSvmAdapter implements PhishingModelAdapter {
  readonly id = 'tfidf-linear-svm';
  readonly name = 'TF-IDF + Linear Support Vector Machine (SVM)';
  readonly version = '0.1.0-research-stub';
  readonly preprocessingVersion = 'v1-l2-normalized-tfidf';
  readonly classification = 'research_model' as const;
  readonly supportedModalities = ['lexical'] as const;

  async getHealth(): Promise<ModelHealthStatus> {
    return {
      isRegistered: true,
      isConfigured: true,
      isLoaded: true,
      isHealthy: true,
      isAvailable: true,
      isExperimentallyValidated: false,
      statusMessage: 'Linear SVM adapter initialized. Emits uncalibrated hyperplane decision margins.',
      lastCheckedAt: new Date().toISOString()
    };
  }

  async predict(
    features: StandardizedModelFeatures, 
    snapshotId = 'default-snapshot'
  ): Promise<StandardizedModelPrediction> {
    const t0 = Date.now();
    const text = `${features.subjectText || ''} ${features.bodyCleanText || ''}`.toLowerCase();

    // SVM decision margin: distance from separating hyperplane (w^T x + b)
    // Value can be negative or positive and is NOT bounded to [0, 1].
    let margin = -0.75; // Baseline intercept
    const contributing: Array<{ featureName: string; featureState: string; importance: number; explanation: string }> = [];

    const weights = [
      { word: 'security update', weight: 1.2 },
      { word: 'verify account', weight: 1.6 },
      { word: 'suspended', weight: 1.4 },
      { word: 'password', weight: 0.9 },
      { word: 'urgent', weight: 0.8 }
    ];

    for (const w of weights) {
      if (text.includes(w.word)) {
        margin += w.weight;
        contributing.push({
          featureName: `token:${w.word}`,
          featureState: 'present',
          importance: w.weight,
          explanation: `SVM feature weight for '${w.word}': +${w.weight} margin contribution.`
        });
      }
    }

    const latency = Date.now() - t0;
    const roundedMargin = Math.round(margin * 100) / 100;

    return {
      modelId: this.id,
      modelName: this.name,
      modelVersion: this.version,
      preprocessingVersion: this.preprocessingVersion,
      featureSchemaVersion: features.schemaVersion || FEATURE_SCHEMA_VERSION,
      snapshotId,
      predictionTimestamp: new Date().toISOString(),
      isConfigured: true,
      predictedClass: roundedMargin >= 0.0 ? 'phishing' : 'legitimate',
      scoreSemantics: {
        // Explicitly uncalibrated decision margin. probability is undefined!
        decisionScore: roundedMargin,
        probability: undefined, // SVM margin is NOT a probability per Section 3
        calibratedProbability: undefined,
        isCalibrated: false,
        calibrationMethod: null
      },
      confidenceScore: Math.min(1.0, Math.abs(roundedMargin) / 3.0),
      contributingFeatures: contributing,
      inferenceLatencyMs: latency,
      rationale: `Linear SVM calculated hyperplane decision margin of ${roundedMargin}. Margin >= 0 represents phishing hyperplane side. Crucial: Decision margins represent uncalibrated geometric distance, not statistical probabilities.`,
      limitations: [
        'Uncalibrated SVM hyperplane margin distance; cannot be interpreted as a probability score.',
        'Does not include Platt scaling or isotonic probability calibration.',
        'Lexical features only; independent of SMTP routing and DKIM/SPF authentication.'
      ]
    };
  }
}
