import { 
  PhishingModelAdapter, 
  StandardizedModelFeatures, 
  StandardizedModelPrediction, 
  ModelHealthStatus 
} from '../contracts';
import { FEATURE_SCHEMA_VERSION } from '../featureExtractor';

export class TfidfLogisticRegressionAdapter implements PhishingModelAdapter {
  readonly id = 'tfidf-logistic-regression';
  readonly name = 'TF-IDF + Logistic Regression Classifier';
  readonly version = '0.1.0-research-stub';
  readonly preprocessingVersion = 'v1-unigram-bigram-tfidf';
  readonly classification = 'research_model' as const;
  readonly supportedModalities = ['lexical'] as const;

  async getHealth(): Promise<ModelHealthStatus> {
    return {
      isRegistered: true,
      isConfigured: true,
      isLoaded: true,
      isHealthy: true,
      isAvailable: true,
      isExperimentallyValidated: false, // Explicitly false per Section 6
      statusMessage: 'Research adapter initialized (uncalibrated research stub).',
      lastCheckedAt: new Date().toISOString()
    };
  }

  async predict(
    features: StandardizedModelFeatures, 
    snapshotId = 'default-snapshot'
  ): Promise<StandardizedModelPrediction> {
    const t0 = Date.now();
    const text = `${features.subjectText || ''} ${features.bodyCleanText || ''}`.toLowerCase();

    // Lexical scoring stub based on text tokens
    let logOdds = -1.2; // Baseline prior
    const contributing: Array<{ featureName: string; featureState: string; importance: number; explanation: string }> = [];

    const suspiciousKeywords = [
      { word: 'urgent', weight: 0.8 },
      { word: 'verify your password', weight: 1.4 },
      { word: 'suspended', weight: 1.1 },
      { word: 'wire transfer', weight: 1.3 },
      { word: 'immediately', weight: 0.7 },
      { word: 'account access', weight: 0.9 }
    ];

    for (const kw of suspiciousKeywords) {
      if (text.includes(kw.word)) {
        logOdds += kw.weight;
        contributing.push({
          featureName: `token:${kw.word}`,
          featureState: 'present',
          importance: kw.weight,
          explanation: `Detected lexical token '${kw.word}' (+${kw.weight} log-odds).`
        });
      }
    }

    // Sigmoid probability function: 1 / (1 + e^-z)
    const prob = 1 / (1 + Math.exp(-logOdds));
    const rawProbability = Math.round(prob * 1000) / 1000;
    const latency = Date.now() - t0;

    return {
      modelId: this.id,
      modelName: this.name,
      modelVersion: this.version,
      preprocessingVersion: this.preprocessingVersion,
      featureSchemaVersion: features.schemaVersion || FEATURE_SCHEMA_VERSION,
      snapshotId,
      predictionTimestamp: new Date().toISOString(),
      isConfigured: true,
      predictedClass: rawProbability >= 0.5 ? 'phishing' : 'legitimate',
      scoreSemantics: {
        decisionScore: Math.round(logOdds * 100) / 100,
        probability: rawProbability,
        calibratedProbability: undefined, // Uncalibrated
        isCalibrated: false,
        calibrationMethod: null
      },
      confidenceScore: Math.abs(rawProbability - 0.5) * 2,
      contributingFeatures: contributing,
      inferenceLatencyMs: latency,
      rationale: `TF-IDF + Logistic Regression evaluated ${contributing.length} lexical tokens yielding raw probability ${rawProbability}. Note: Uncalibrated research baseline; not experimentally validated.`,
      limitations: [
        'Lexical features only; ignores SMTP routing and DKIM/SPF authentication records.',
        'Score is uncalibrated raw sigmoid output; not experimentally validated against benchmark test sets.'
      ]
    };
  }
}
