import { 
  PhishingModelAdapter, 
  StandardizedModelFeatures, 
  StandardizedModelPrediction, 
  ModelHealthStatus 
} from '../contracts';
import { FEATURE_SCHEMA_VERSION } from '../featureExtractor';

export class GbdtStructuredForensicsAdapter implements PhishingModelAdapter {
  readonly id = 'gbdt-structured-forensics';
  readonly name = 'Gradient-Boosted Decision Tree (Structured Forensics)';
  readonly version = '0.1.0-research-stub';
  readonly preprocessingVersion = 'v1-four-state-forensic-encoding';
  readonly classification = 'research_model' as const;
  readonly supportedModalities = ['structured'] as const;

  async getHealth(): Promise<ModelHealthStatus> {
    return {
      isRegistered: true,
      isConfigured: true,
      isLoaded: true,
      isHealthy: true,
      isAvailable: true,
      isExperimentallyValidated: false,
      statusMessage: 'GBDT structured forensic tree ensemble initialized.',
      lastCheckedAt: new Date().toISOString()
    };
  }

  async predict(
    features: StandardizedModelFeatures, 
    snapshotId = 'default-snapshot'
  ): Promise<StandardizedModelPrediction> {
    const t0 = Date.now();
    let ensembleLogOdds = -1.5; // Prior log-odds
    const contributing: Array<{ featureName: string; featureState: string; importance: number; explanation: string }> = [];

    // Tree Node 1: Anchor text divergence (High importance)
    if (features.hasAnchorTextDivergence === 'true') {
      ensembleLogOdds += 2.2;
      contributing.push({
        featureName: 'hasAnchorTextDivergence',
        featureState: 'true',
        importance: 0.35,
        explanation: 'Ensemble split on anchor text divergence (+2.2 log-odds).'
      });
    }

    // Tree Node 2: Authentication failures vs Unknowns (Crucial four-state distinction)
    if (features.spfPass === 'false' || features.dkimPass === 'false' || features.dmarcPass === 'false') {
      ensembleLogOdds += 1.8;
      contributing.push({
        featureName: 'authStatus',
        featureState: 'false (active failure)',
        importance: 0.28,
        explanation: 'Ensemble split on confirmed authentication failure (+1.8 log-odds).'
      });
    } else if (features.spfPass === 'unknown' && features.dkimPass === 'unknown') {
      // Unknown evidence does NOT penalize like an active cryptographic failure!
      ensembleLogOdds += 0.3;
      contributing.push({
        featureName: 'authStatus',
        featureState: 'unknown (omitted headers)',
        importance: 0.05,
        explanation: 'Ensemble split on omitted auth headers (+0.3 uncertainty adjustment).'
      });
    }

    // Tree Node 3: Direct IP in URL
    if (features.hasDirectIpUrls === 'true') {
      ensembleLogOdds += 1.5;
      contributing.push({
        featureName: 'hasDirectIpUrls',
        featureState: 'true',
        importance: 0.20,
        explanation: 'Ensemble split on direct IP URL host (+1.5 log-odds).'
      });
    }

    // Tree Node 4: Executable or script attachment
    if (features.hasSuspiciousAttachmentType === 'true') {
      ensembleLogOdds += 1.6;
      contributing.push({
        featureName: 'hasSuspiciousAttachmentType',
        featureState: 'true',
        importance: 0.22,
        explanation: 'Ensemble split on dangerous MIME attachment type (+1.6 log-odds).'
      });
    }

    // Sigmoid probability
    const prob = 1 / (1 + Math.exp(-ensembleLogOdds));
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
        decisionScore: Math.round(ensembleLogOdds * 100) / 100,
        probability: rawProbability,
        calibratedProbability: undefined,
        isCalibrated: false,
        calibrationMethod: null
      },
      confidenceScore: Math.abs(rawProbability - 0.5) * 2,
      contributingFeatures: contributing,
      inferenceLatencyMs: latency,
      rationale: `GBDT structured model evaluated ${contributing.length} four-state forensic splits yielding uncalibrated probability ${rawProbability}.`,
      limitations: [
        'Relies purely on structured categorical and numerical forensic features.',
        'Score is uncalibrated raw ensemble sigmoid probability.',
        'Not experimentally benchmarked against operational datasets.'
      ]
    };
  }
}
