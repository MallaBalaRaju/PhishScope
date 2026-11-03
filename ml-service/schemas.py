from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field

FeatureState = Literal['true', 'false', 'unknown', 'not_applicable']
MissingnessState = Literal['present', 'missing', 'inapplicable', 'malformed']

class StandardizedModelFeatures(BaseModel):
    schemaVersion: str = Field(default="2.0.0", description="Feature schema contract version")
    extractorVersion: str = Field(default="1.1.0", description="Feature extraction logic version")
    extractedAt: str

    # Lexical Features
    subjectText: Optional[str] = None
    bodyCleanText: Optional[str] = None
    hasHtmlMarkup: FeatureState = "unknown"
    textLengthChars: int = 0
    wordCount: int = 0

    # Authentication Four-State Features
    spfPass: FeatureState = "unknown"
    dkimPass: FeatureState = "unknown"
    dmarcPass: FeatureState = "unknown"
    isDomainAligned: FeatureState = "unknown"

    # Routing Four-State Features
    hasNegativeTransitTime: FeatureState = "not_applicable"
    hasPrivateOriginHop: FeatureState = "not_applicable"
    hasIntermediateLoopback: FeatureState = "not_applicable"
    totalHopCount: Optional[int] = None
    candidateIpCount: int = 0

    # Content & URL Four-State Features
    hasDirectIpUrls: FeatureState = "not_applicable"
    hasAnchorTextDivergence: FeatureState = "not_applicable"
    hasPunycodeDomains: FeatureState = "not_applicable"
    hasShortenerUrls: FeatureState = "not_applicable"
    totalUrlCount: int = 0
    suspiciousBrandMentionCount: int = 0

    # Attachment Four-State Features
    hasSuspiciousAttachmentType: FeatureState = "not_applicable"
    attachmentCount: int = 0

    # Metadata & Provenance
    missingnessMetadata: Dict[str, MissingnessState] = Field(default_factory=dict)
    featureProvenance: Dict[str, str] = Field(default_factory=dict)

class ModelScoreSemantics(BaseModel):
    decisionScore: Optional[float] = None
    probability: Optional[float] = None
    calibratedProbability: Optional[float] = None
    isCalibrated: bool = False
    calibrationMethod: Optional[str] = None

class ContributingFeature(BaseModel):
    featureName: str
    featureState: str
    importance: Optional[float] = None
    explanation: Optional[str] = None

class PredictionRequest(BaseModel):
    features: StandardizedModelFeatures
    snapshotId: str = "default-snapshot"
    modelId: Optional[str] = "gbdt-structured-forensics"

class StandardizedModelPrediction(BaseModel):
    modelId: str
    modelName: str
    modelVersion: str
    preprocessingVersion: str
    featureSchemaVersion: str = "2.0.0"
    snapshotId: str
    predictionTimestamp: str
    isConfigured: bool = True
    predictedClass: Literal['phishing', 'legitimate', 'suspicious', 'inconclusive', 'unavailable'] = "inconclusive"
    scoreSemantics: ModelScoreSemantics
    confidenceScore: Optional[float] = None
    contributingFeatures: List[ContributingFeature] = Field(default_factory=list)
    inferenceLatencyMs: Optional[float] = None
    rationale: str
    limitations: List[str] = Field(default_factory=list)

class ModelHealthResponse(BaseModel):
    status: str
    serviceVersion: str = "1.0.0"
    isLoaded: bool = True
    availableModels: List[str]
    experimentallyValidated: bool = False
