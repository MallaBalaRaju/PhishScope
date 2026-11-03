# PhishScope Python ML Microservice (`ml-service/`)

A standalone Python microservice built with **FastAPI** providing modular machine learning inference and decoupled training experimentation for the PhishScope application.

---

## 1. Architectural Role & Integrity Boundaries

- **Separation of Concerns**: The Node.js / TypeScript application remains the primary full-stack platform handling ingestion, RFC email MIME parsing, header forensics, DNS queries, and evidence fusion.
- **Serving Connector**: The TypeScript `RemoteHttpServingAdapter` connects over validated HTTP to this service's `/predict` and `/health` endpoints.
- **Zero Training Contamination**: Model training pipelines (`ml-service/training/train_pipeline.py`) are strictly decoupled from operational inference serving.
- **No Unapproved Datasets**: In accordance with Academic Decision 3.1, no unapproved datasets or final research models are hardcoded.

---

## 2. API Contract Endpoints

### `GET /health`
Returns service status, loaded model count, and experimental validation status (`false`).

### `GET /models`
Enumerates available research model adapters:
- `tfidf-logistic-regression`
- `tfidf-linear-svm`
- `gbdt-structured-forensics`
- `transformer-classifier`

### `POST /predict`
Accepts standardized feature payload:
```json
{
  "features": {
    "schemaVersion": "2.0.0",
    "extractorVersion": "1.1.0",
    "subjectText": "URGENT Account Notice",
    "bodyCleanText": "Please verify your credentials immediately...",
    "spfPass": "false",
    "dkimPass": "unknown",
    "hasAnchorTextDivergence": "true"
  },
  "snapshotId": "snapshot-a8f93b12",
  "modelId": "gbdt-structured-forensics"
}
```

Returns standardized prediction payload:
```json
{
  "modelId": "gbdt-structured-forensics",
  "modelName": "Python GBDT Structured Forensics",
  "modelVersion": "0.1.0-research-stub",
  "predictedClass": "phishing",
  "scoreSemantics": {
    "decisionScore": 2.5,
    "probability": 0.924,
    "isCalibrated": false
  },
  "rationale": "Python GBDT evaluated four-state structured forensic features yielding uncalibrated probability 0.924."
}
```

---

## 3. Local Setup & Execution (Optional)

*Note: The main PhishScope web application runs completely independently of Python. Python is only required if you wish to run this local microservice for benchmarking.*

```bash
cd ml-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start the microservice on port 8000
uvicorn ml-service.main:app --host 127.0.0.1 --port 8000 --reload
```
