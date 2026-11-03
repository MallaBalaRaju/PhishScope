# Refined Model Adapter, Registry & Python ML Service Architecture

A provider-independent, research-grade machine learning model adapter architecture and dedicated Python FastAPI ML service skeleton for PhishScope.

---

## 1. Model Registry Taxonomy & Classification

The registry maintains six distinct entries across three functional classifications:

| Identifier | Classification | Description | Availability Status |
| :--- | :--- | :--- | :--- |
| `unconfigured-baseline` | Research Baseline | Unconfigured default. Transparently reports ML unavailable. | Default Active |
| `tfidf-logistic-regression` | Research Model Adapter | N-gram tokenization + logistic regression inference adapter. | Research Stub |
| `tfidf-linear-svm` | Research Model Adapter | Lexical bag-of-words + linear SVM decision margin adapter. | Research Stub |
| `gbdt-structured-forensics` | Research Model Adapter | Structured gradient-boosted decision tree on forensic indicators. | Research Stub |
| `transformer-classifier` | Research Model Adapter | Sequence-based attention classifier inference adapter. | Research Stub |
| `remote-http-serving` | Serving Connector | Authenticated, SSRF-hardened proxy to external Python microservice. | Connector |

*Crucial rule*: The remote HTTP adapter is a serving connector, not a distinct classification algorithm.

---

## 2. Four-State Feature Representation & Missingness Handling

Forensic evidence is never coerced from missing to `false`. Features utilize a four-state enumeration:

```typescript
export type FeatureState = 'true' | 'false' | 'unknown' | 'not_applicable';

export interface StandardizedModelFeatures {
  schemaVersion: string; // e.g. "2.0.0"
  extractorVersion: string; // e.g. "1.1.0"
  extractedAt: string;

  // Lexical Features
  subjectText: string | null;
  bodyCleanText: string | null;
  textLengthChars: number;
  wordCount: number;

  // Authentication Four-State Features
  spfPass: FeatureState;
  dkimPass: FeatureState;
  dmarcPass: FeatureState;
  isDomainAligned: FeatureState;

  // Routing Four-State Features
  hasNegativeTransitTime: FeatureState;
  hasPrivateOriginHop: FeatureState;
  hasIntermediateLoopback: FeatureState;
  totalHopCount: number | null;

  // Content & URL Four-State Features
  hasDirectIpUrls: FeatureState;
  hasAnchorTextDivergence: FeatureState;
  hasPunycodeDomains: FeatureState;
  hasShortenerUrls: FeatureState;
  totalUrlCount: number;

  // Attachment Four-State Features
  hasSuspiciousAttachmentType: FeatureState;
  attachmentCount: number;

  // Provenance & Missingness Metadata
  missingnessMetadata: Record<string, 'present' | 'missing' | 'inapplicable' | 'malformed'>;
  featureProvenance: Record<string, string>;
}
```

---

## 3. Rigorous Prediction Score Semantics

Predictions explicitly distinguish uncalibrated decision scores from calibrated probabilities:

- `decisionScore`: Model-specific raw output (e.g. SVM margin distance $-\infty \dots +\infty$, log-odds, or tree ensemble leaf values).
- `probability`: Raw probability ($[0.0, 1.0]$) if natively supported by model.
- `calibratedProbability`: Calibrated probability ($[0.0, 1.0]$) following documented calibration (e.g., Platt scaling or isotonic regression).
- `isCalibrated`: Boolean indicator strictly verifying if calibration has occurred.
- `calibrationMethod`: Documentation string naming calibration procedure (e.g., `'platt_scaling'`, `'isotonic_regression'`, or `null`).

*Crucial rule*: An uncalibrated SVM decision margin is never represented as a probability.

---

## 4. Analysis-Time Model Version Locking

When an email analysis begins, a snapshot of the active model configuration is captured:
- `activeModelId`
- `modelVersion`
- `preprocessingVersion`
- `featureSchemaVersion`
- `snapshotId`

The analysis execution is bound to this captured snapshot. Changes made to active models in the Settings panel take effect for subsequent analyses only, preventing race conditions or split-version records during asynchronous processing.

---

## 5. Remote HTTP Endpoint Hardening & SSRF Protection

The `RemoteHttpServingAdapter` enforces strict security boundaries:
- Restricts configuration to authorized settings.
- Destination validation with SSRF protection:
  - Disallows loopback and private IP ranges in production mode.
  - Requires explicit HTTPS for remote destinations outside localhost development.
  - Strictly prohibits using email-derived URLs or untrusted hostnames as inference endpoints.
- Timeouts: Enforces strict 5000ms request timeout.
- Schema validation: Validates remote response payload against `StandardizedModelPrediction` schema.
- No silent fallback: If the remote endpoint is unreachable, reports explicit `unavailable` status with error details; does not silently fallback to another classifier.

---

## 6. Decoupled Model Status Taxonomy

Each adapter exposes six independent status dimensions:
1. `isRegistered`: Available in registry.
2. `isConfigured`: Valid credentials / endpoint specified.
3. `isLoaded`: Weights / microservice initialized in memory.
4. `isHealthy`: Passing liveness / health check probes.
5. `isAvailable`: Ready to accept inference queries.
6. `isExperimentallyValidated`: Validated against approved experimental benchmarks (remains `false` until research evaluation).

---

## 7. Python Machine Learning Service (`ml-service/`)

A standalone FastAPI service in `ml-service/` designed for future research training and inference:
- `ml-service/main.py`: FastAPI server exposing `/health`, `/models`, and `/predict`.
- `ml-service/schemas.py`: Pydantic models matching TypeScript feature and prediction contracts.
- `ml-service/adapters/`: Implementation stubs for the 4 research models.
- `ml-service/requirements.txt`: Minimal dependencies (`fastapi`, `uvicorn`, `pydantic`).
- `ml-service/README.md`: Setup and architecture documentation.
- Decoupled from node runtime; node does not require Python installed to function.
