import time
from datetime import datetime
from fastapi import FastAPI, HTTPException
from .schemas import (
    PredictionRequest, 
    StandardizedModelPrediction, 
    ModelHealthResponse
)
from .models import (
    TfidfLogisticRegressionModel,
    TfidfLinearSvmModel,
    GbdtStructuredForensicsModel,
    TransformerClassifierModel
)

app = FastAPI(
    title="PhishScope Python ML Microservice",
    description="Provider-independent model serving microservice for email threat classification and forensic benchmarking.",
    version="1.0.0"
)

# Registry of available Python model adapters
MODELS = {
    "tfidf-logistic-regression": TfidfLogisticRegressionModel(),
    "tfidf-linear-svm": TfidfLinearSvmModel(),
    "gbdt-structured-forensics": GbdtStructuredForensicsModel(),
    "transformer-classifier": TransformerClassifierModel()
}

@app.get("/health", response_model=ModelHealthResponse)
def health_check():
    """Health check endpoint used by PhishScope RemoteHttpServingAdapter"""
    return ModelHealthResponse(
        status="healthy",
        serviceVersion="1.0.0",
        isLoaded=True,
        availableModels=list(MODELS.keys()),
        experimentallyValidated=False
    )

@app.get("/models")
def list_models():
    """Enumerates available research model adapters in this service"""
    return [
        {
            "id": m.id,
            "name": m.name,
            "version": m.version,
            "preprocessingVersion": m.preprocessing_version,
            "isExperimentallyValidated": False
        }
        for m in MODELS.values()
    ]

@app.post("/predict", response_model=StandardizedModelPrediction)
def predict(request: PredictionRequest):
    """Standardized prediction endpoint called by TypeScript RemoteHttpServingAdapter"""
    t0 = time.time()
    now_iso = datetime.utcnow().isoformat() + "Z"

    model_id = request.modelId or "gbdt-structured-forensics"
    model = MODELS.get(model_id)

    if not model:
        raise HTTPException(
            status_code=400, 
            detail=f"Requested model '{model_id}' is not loaded in this service. Available models: {list(MODELS.keys())}"
        )

    prediction = model.predict(request.features, request.snapshotId, now_iso)
    prediction.inferenceLatencyMs = round((time.time() - t0) * 1000, 2)
    return prediction
