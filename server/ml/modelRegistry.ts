import crypto from 'crypto';
import { 
  PhishingModelAdapter, 
  ModelHealthStatus, 
  ModelConfigurationSnapshot 
} from './contracts';
import { FEATURE_SCHEMA_VERSION } from './featureExtractor';
import { UnconfiguredBaselineAdapter } from './adapters/UnconfiguredBaselineAdapter';
import { TfidfLogisticRegressionAdapter } from './adapters/TfidfLogisticRegressionAdapter';
import { TfidfLinearSvmAdapter } from './adapters/TfidfLinearSvmAdapter';
import { GbdtStructuredForensicsAdapter } from './adapters/GbdtStructuredForensicsAdapter';
import { TransformerClassifierAdapter } from './adapters/TransformerClassifierAdapter';
import { RemoteHttpServingAdapter } from './adapters/RemoteHttpServingAdapter';

/**
 * Abstraction for active model configuration storage (Section 8).
 * In-memory provider for single-process runtime, extensible to Redis/DB for multi-instance clusters.
 */
export interface IActiveModelConfigProvider {
  getActiveModelId(): string;
  setActiveModelId(id: string): Promise<boolean> | boolean;
}

export class InMemoryModelConfigProvider implements IActiveModelConfigProvider {
  private activeId: string = 'unconfigured-baseline';

  getActiveModelId(): string {
    return this.activeId;
  }

  setActiveModelId(id: string): boolean {
    this.activeId = id;
    return true;
  }
}

/**
 * Provider-Independent Model Registry
 * Manages model registration, health monitoring, and analysis-time snapshot locking.
 */
export class ModelRegistry {
  private static instance: ModelRegistry;
  private adapters: Map<string, PhishingModelAdapter> = new Map();
  private configProvider: IActiveModelConfigProvider;

  private constructor(configProvider?: IActiveModelConfigProvider) {
    this.configProvider = configProvider || new InMemoryModelConfigProvider();

    // Register all 6 models defined in Section 1
    this.register(new UnconfiguredBaselineAdapter());
    this.register(new TfidfLogisticRegressionAdapter());
    this.register(new TfidfLinearSvmAdapter());
    this.register(new GbdtStructuredForensicsAdapter());
    this.register(new TransformerClassifierAdapter());
    this.register(new RemoteHttpServingAdapter());
  }

  public static getInstance(): ModelRegistry {
    if (!ModelRegistry.instance) {
      ModelRegistry.instance = new ModelRegistry();
    }
    return ModelRegistry.instance;
  }

  public register(adapter: PhishingModelAdapter): void {
    this.adapters.set(adapter.id, adapter);
  }

  public getAdapter(id: string): PhishingModelAdapter | undefined {
    return this.adapters.get(id);
  }

  public getActiveAdapter(): PhishingModelAdapter {
    const activeId = this.configProvider.getActiveModelId();
    const adapter = this.adapters.get(activeId);
    if (!adapter) {
      // Fallback to unconfigured baseline if unknown
      return this.adapters.get('unconfigured-baseline')!;
    }
    return adapter;
  }

  public setActiveModel(id: string): boolean {
    if (!this.adapters.has(id)) {
      return false;
    }
    return Boolean(this.configProvider.setActiveModelId(id));
  }

  /**
   * Locks the active model configuration into an immutable snapshot for an analysis run (Section 4).
   * Ensures that changing Settings during an ongoing analysis will not split or race model versions.
   */
  public createModelSnapshot(): ModelConfigurationSnapshot {
    const active = this.getActiveAdapter();
    const snapshotId = `snapshot-${crypto.randomUUID().slice(0, 8)}`;
    return {
      snapshotId,
      modelId: active.id,
      modelName: active.name,
      modelVersion: active.version,
      preprocessingVersion: active.preprocessingVersion,
      featureSchemaVersion: FEATURE_SCHEMA_VERSION,
      capturedAt: new Date().toISOString()
    };
  }

  /**
   * Captures the active adapter and its immutable configuration snapshot in one atomic call.
   */
  public captureSnapshotForAnalysis(): { adapter: PhishingModelAdapter; snapshot: ModelConfigurationSnapshot } {
    const adapter = this.getActiveAdapter();
    const snapshot = this.createModelSnapshot();
    return { adapter, snapshot };
  }

  /**
   * Retrieves an adapter bound to a previously captured snapshot.
   */
  public getAdapterForSnapshot(snapshot: ModelConfigurationSnapshot): PhishingModelAdapter {
    const adapter = this.adapters.get(snapshot.modelId);
    if (!adapter) {
      return this.adapters.get('unconfigured-baseline')!;
    }
    return adapter;
  }

  /**
   * Enumerates all registered models with 6-dimensional health statuses (Section 6).
   */
  public async listModelsWithHealth(): Promise<Array<{
    id: string;
    name: string;
    version: string;
    preprocessingVersion: string;
    classification: 'research_baseline' | 'research_model' | 'serving_connector';
    classificationType?: 'research_baseline' | 'research_model' | 'serving_connector';
    supportedModalities: ReadonlyArray<'lexical' | 'structured' | 'hybrid'>;
    isActive: boolean;
    health: ModelHealthStatus;
    status?: any;
  }>> {
    const activeId = this.configProvider.getActiveModelId();
    const result = [];

    for (const [id, adapter] of this.adapters.entries()) {
      const health = await adapter.getHealth();
      result.push({
        id: adapter.id,
        name: adapter.name,
        version: adapter.version,
        preprocessingVersion: adapter.preprocessingVersion,
        classification: adapter.classification,
        classificationType: adapter.classification,
        supportedModalities: adapter.supportedModalities,
        isActive: id === activeId,
        health,
        status: {
          healthy: health.isHealthy,
          available: health.isAvailable,
          configured: health.isConfigured,
          loaded: health.isLoaded,
          isExperimentallyValidated: health.isExperimentallyValidated,
          healthMessage: health.statusMessage
        }
      });
    }

    return result;
  }

  public async listModelsWithStatus() {
    return this.listModelsWithHealth();
  }

  public getConfigProvider(): IActiveModelConfigProvider {
    return this.configProvider;
  }

  public getRemoteConnector(): RemoteHttpServingAdapter | undefined {
    return this.adapters.get('remote-http-serving') as RemoteHttpServingAdapter | undefined;
  }
}
