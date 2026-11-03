import { 
  PhishingModelAdapter, 
  StandardizedModelFeatures, 
  StandardizedModelPrediction, 
  ModelHealthStatus 
} from '../contracts';
import { FEATURE_SCHEMA_VERSION } from '../featureExtractor';

export class RemoteHttpServingAdapter implements PhishingModelAdapter {
  readonly id = 'remote-http-serving';
  readonly name = 'Remote Python HTTP Model-Serving Connector';
  readonly version = '1.0.0-connector';
  readonly preprocessingVersion = 'remote-managed';
  readonly classification = 'serving_connector' as const;
  readonly supportedModalities = ['hybrid', 'lexical', 'structured'] as const;

  private endpointUrl: string;
  private authToken?: string;
  private allowLocalhost: boolean = true;
  private timeoutMs: number = 5000;

  constructor(endpointUrl?: string) {
    this.endpointUrl = endpointUrl || process.env.PYTHON_ML_SERVICE_URL || 'http://localhost:8000';
  }

  public getEndpointUrl(): string {
    return this.endpointUrl;
  }

  public setEndpointUrl(url: string): void {
    this.validateEndpointUrl(url);
    this.endpointUrl = url;
  }

  public getConfig() {
    return {
      endpointUrl: this.endpointUrl,
      authToken: this.authToken,
      timeoutMs: this.timeoutMs,
      allowLocalhost: this.allowLocalhost
    };
  }

  public updateConfig(conf: { endpointUrl?: string; authToken?: string; timeoutMs?: number; allowLocalhost?: boolean }) {
    try {
      if (conf.endpointUrl) {
        this.validateEndpointUrl(conf.endpointUrl);
        this.endpointUrl = conf.endpointUrl;
      }
      if (conf.authToken !== undefined) {
        this.authToken = conf.authToken;
      }
      if (typeof conf.timeoutMs === 'number' && conf.timeoutMs > 0) {
        this.timeoutMs = conf.timeoutMs;
      }
      if (typeof conf.allowLocalhost === 'boolean') {
        this.allowLocalhost = conf.allowLocalhost;
      }
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }

  /**
   * SSRF and Destination Safety Validator (Section 5)
   */
  public validateEndpointUrl(urlStr: string): void {
    const res = validateInferenceEndpoint(urlStr, this.allowLocalhost);
    if (!res.isValid) {
      throw new Error(res.error);
    }
  }

  async getHealth(): Promise<ModelHealthStatus> {
    const lastCheckedAt = new Date().toISOString();
    try {
      this.validateEndpointUrl(this.endpointUrl);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      const res = await fetch(`${this.endpointUrl}/health`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const body = await res.json().catch(() => ({}));
        return {
          isRegistered: true,
          isConfigured: true,
          isLoaded: body.isLoaded ?? true,
          isHealthy: true,
          isAvailable: true,
          isExperimentallyValidated: false, // Explicitly false per Section 6
          statusMessage: `Remote microservice connected at ${this.endpointUrl}.`,
          lastCheckedAt
        };
      } else {
        return {
          isRegistered: true,
          isConfigured: true,
          isLoaded: false,
          isHealthy: false,
          isAvailable: false,
          isExperimentallyValidated: false,
          statusMessage: `Remote service returned HTTP ${res.status}: ${res.statusText}`,
          lastCheckedAt
        };
      }
    } catch (err: any) {
      return {
        isRegistered: true,
        isConfigured: true,
        isLoaded: false,
        isHealthy: false,
        isAvailable: false,
        isExperimentallyValidated: false,
        statusMessage: `Endpoint unreachable at ${this.endpointUrl}: ${err.message}`,
        lastCheckedAt
      };
    }
  }

  async predict(
    features: StandardizedModelFeatures, 
    snapshotId = 'default-snapshot'
  ): Promise<StandardizedModelPrediction> {
    const t0 = Date.now();
    const timestamp = new Date().toISOString();

    try {
      this.validateEndpointUrl(this.endpointUrl);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      const res = await fetch(`${this.endpointUrl}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          features,
          snapshotId
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!res.ok) {
        throw new Error(`Remote prediction service returned HTTP ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();
      const latency = Date.now() - t0;

      // Validate remote prediction schema
      if (!data || typeof data !== 'object') {
        throw new Error('Remote prediction endpoint returned an invalid non-object payload.');
      }

      return {
        modelId: this.id,
        modelName: data.modelName || 'Remote Python Model Endpoint',
        modelVersion: data.modelVersion || 'remote-1.0.0',
        preprocessingVersion: data.preprocessingVersion || this.preprocessingVersion,
        featureSchemaVersion: features.schemaVersion || FEATURE_SCHEMA_VERSION,
        snapshotId,
        predictionTimestamp: timestamp,
        isConfigured: true,
        predictedClass: data.predictedClass || 'inconclusive',
        scoreSemantics: {
          decisionScore: data.scoreSemantics?.decisionScore,
          probability: data.scoreSemantics?.probability,
          calibratedProbability: data.scoreSemantics?.calibratedProbability,
          isCalibrated: !!data.scoreSemantics?.isCalibrated,
          calibrationMethod: data.scoreSemantics?.calibrationMethod || null
        },
        confidenceScore: data.confidenceScore,
        contributingFeatures: data.contributingFeatures || [],
        inferenceLatencyMs: latency,
        rationale: data.rationale || `Remote microservice inference completed in ${latency}ms.`,
        limitations: [
          'Inference delegated to external Python microservice via HTTP.',
          ...(Array.isArray(data.limitations) ? data.limitations : [])
        ]
      };
    } catch (err: any) {
      // Critical requirement: NO silent fallback to another model!
      const latency = Date.now() - t0;
      return {
        modelId: this.id,
        modelName: this.name,
        modelVersion: this.version,
        preprocessingVersion: this.preprocessingVersion,
        featureSchemaVersion: features.schemaVersion || FEATURE_SCHEMA_VERSION,
        snapshotId,
        predictionTimestamp: timestamp,
        isConfigured: true,
        predictedClass: 'unavailable',
        scoreSemantics: {
          isCalibrated: false,
          calibrationMethod: null
        },
        inferenceLatencyMs: latency,
        rationale: `Remote HTTP inference failed: ${err.message}. Crucial: In accordance with Section 5 integrity rules, the system does not silently substitute another model.`,
        limitations: [
          `Remote endpoint error: ${err.message}`,
          'Silent model fallback is prohibited to preserve prediction provenance.'
        ]
      };
    }
  }
}

/**
 * Validates endpoint URLs for SSRF safety, protocol whitelist, and host restrictions.
 */
export function validateInferenceEndpoint(
  urlStr: string,
  allowLocalhost: boolean = true
): { isValid: boolean; error?: string } {
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    return { isValid: false, error: `Invalid remote endpoint URL: "${urlStr}". Must be a valid HTTP or HTTPS URI.` };
  }

  const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';

  // SSRF Private & Link-Local IP check (e.g. AWS/GCP metadata 169.254.169.254 or RFC 1918)
  const parts = parsed.hostname.split('.').map(p => parseInt(p, 10));
  if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
    const [a, b] = parts;
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0) {
      if (!isLocalhost || !allowLocalhost) {
        return { isValid: false, error: `SSRF Violation: Requests to private/reserved RFC 1918 or link-local IP addresses (${parsed.hostname}) are prohibited.` };
      }
    }
  }

  // Disallow arbitrary schemes (e.g. file:, gopher:, ftp:)
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { isValid: false, error: `Forbidden protocol '${parsed.protocol}'. Only http: (for local testing) and https: are allowed.` };
  }

  // Require HTTPS for remote destinations outside localhost
  if (!isLocalhost && parsed.protocol !== 'https:' && (process.env.NODE_ENV === 'production' || !parsed.hostname.endsWith('.test'))) {
    return { isValid: false, error: `Remote microservices must communicate over HTTPS outside local development.` };
  }

  return { isValid: true };
}
