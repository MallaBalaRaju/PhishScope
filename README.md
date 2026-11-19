# PhishScope 🔍

> **AI-Powered Email Threat Detection & Infrastructure-Aware Forensics**

PhishScope is a full-stack phishing email forensics platform built for cybersecurity analysts, SOC teams, and academic researchers. It combines RFC-compliant header forensics, SPF/DKIM/DMARC authentication analysis, real trained machine learning classifiers, infrastructure intelligence, and a Gemini AI investigation assistant — all with zero permanent data retention.

---

## ✨ Key Features

| Module | Capability |
|--------|------------|
| 📧 **Email Ingestion** | Upload raw `.eml` files, paste RFC headers, or load synthetic test fixtures |
| 🔬 **Header Forensics** | SMTP hop reconstruction, transit delta analysis, IP classification, From/Reply-To mismatch detection |
| 🔐 **Auth Forensics** | SPF, DKIM, DMARC alignment analysis with provenance distinction (reported vs. verified) |
| 🔗 **URL & Content Analysis** | Defanging, anchor/href mismatch, Punycode/IDN detection, URL shortener tracking |
| 🤖 **ML Classification** | 4 real trained models: Logistic Regression, Linear SVM, GBDT (XGBoost), Transformer TF-IDF |
| 🌐 **Infrastructure Intel** | Passive DNS, reverse PTR resolution, provider enrichment |
| 🕸️ **Graph Correlation** | Node-link graphs correlating emails that share IPs, domains, or relays |
| 🧠 **Gemini AI Assistant** | 5-pillar structured briefings with prompt-injection defense |
| 📤 **Export** | PDF, Excel, and JSON forensic report export |
| 🔒 **Privacy-First** | In-memory only — no raw email ever written to disk |

---

## 🏗️ Architecture

```
PhishScope/
├── server/                  # Node.js / Express backend (TypeScript)
│   ├── pipeline.ts          # Main analysis orchestration pipeline
│   ├── parser/              # RFC MIME email parser (mailparser)
│   ├── forensics/           # Header, auth, and content forensics modules
│   ├── fusion/              # Evidence fusion engine & scoring
│   ├── ml/                  # ML adapter registry (IMLClassifierAdapter)
│   ├── intelligence/        # Infrastructure enrichment (DNS, PTR)
│   ├── graph/               # Relationship graph engine
│   ├── assistant/           # Gemini AI investigation assistant
│   ├── store/               # In-memory session store (2hr TTL)
│   └── fixtures/            # Synthetic test email fixtures
│
├── ml-service/              # Python FastAPI ML microservice
│   ├── main.py              # FastAPI app entry point
│   ├── models.py            # Real model inference adapters
│   ├── schemas.py           # Pydantic request/response schemas
│   ├── requirements.txt     # Python dependencies
│   ├── saved_models/        # Trained .pkl model files (git-ignored)
│   └── training/            # Training scripts
│       ├── train_all_models.py
│       └── refine_gbdt.py
│
├── src/                     # React frontend (TypeScript + Tailwind)
│   ├── components/          # Dashboard, Ingestion, Workspace, Settings views
│   └── export/              # PDF, Excel, JSON export builders
│
├── tests/                   # Test suite (58 tests)
├── dataset/                 # Training datasets (git-ignored)
├── .env.example             # Environment variable template
├── run_phishscope.bat       # One-click Windows startup script
└── server.ts                # Express + Vite dev server entry point
```

---

## 🤖 ML Models

PhishScope includes **4 real trained classifiers**, all trained on 5 public phishing/spam datasets:

| Model | Algorithm | Training Data | Purpose |
|-------|-----------|--------------|---------|
| `lr_tfidf_pipeline.pkl` | Logistic Regression + TF-IDF | 157K emails | Fast, interpretable baseline |
| `svm_tfidf_pipeline.pkl` | Linear SVM + TF-IDF | 157K emails | High-precision text classification |
| `gbdt_xgboost_model.pkl` | XGBoost GBDT | Structured forensic features | SPF/DKIM/DMARC-aware scoring |
| `transformer_tfidf_pipeline.pkl` | SGD Classifier + TF-IDF | 157K emails | Transformer-style representation |

**Datasets used for training:**

| Dataset | Size | Source |
|---------|------|--------|
| `phishing_email.csv` | ~82K emails | Phishing corpus |
| `Enron.csv` | ~30K emails | Enron legitimate email corpus |
| `emails.csv` | ~5K emails | Mixed corpus |
| `CEAS_08.csv` | ~39K emails | 2008 spam competition |
| `SpamAssassin.csv` | ~5.8K emails | Holdout test set |

> The ML microservice runs on **port 8000** (Python/FastAPI) and is called by the Node backend via HTTP.

---

## 🚀 Getting Started

### Prerequisites

| Tool | Version |
|------|---------|
| Node.js | ≥ 18.x |
| Python | ≥ 3.10 |
| npm | ≥ 9.x |
| Git | any recent |

---

### 1. Clone the Repository

```bash
git clone https://github.com/MallaBalaRaju/PhishScope.git
cd PhishScope
```

---

### 2. Configure Environment Variables

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:

```env
GEMINI_API_KEY=your_gemini_api_key_here
APP_URL=http://localhost:3000
```

> **Get your Gemini API key** at [aistudio.google.com/apikey](https://aistudio.google.com/apikey)

---

### 3. Install Node.js Dependencies

```bash
npm install
```

---

### 4. Set Up Python Virtual Environment (ML Service)

```bash
cd ml-service
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
cd ..
```

---

### 5. Train the ML Models

> ⚠️ Requires the datasets in `dataset/`. Download from the links in `dataset/README.md` or place your own CSVs.

```bash
cd ml-service
python training/train_all_models.py
python training/refine_gbdt.py   # optional: refine GBDT with forensic features
cd ..
```

Trained models will be saved to `ml-service/saved_models/`.

---

### 6. Run the Application

**Option A — One-click (Windows):**

```bat
run_phishscope.bat
```

**Option B — Manual (two terminals):**

**Terminal 1 — Python ML Service:**
```bash
cd ml-service
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — Node Web App:**
```bash
npm run dev
```

**Then open:** [http://localhost:3000](http://localhost:3000)

---

## 🧪 Running Tests

```bash
npm test
```

> 58 unit and integration tests covering forensics, scoring, parsing, and adapter contracts.

---

## 🔌 ML Microservice API

The Python FastAPI microservice exposes:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service status |
| `/health` | GET | Health check |
| `/predict` | POST | Run ML classification |
| `/models` | GET | List available models |

**Example `/predict` request:**
```json
{
  "email_text": "Subject: Urgent account verification\n\nClick here to verify...",
  "features": {
    "spf_pass": false,
    "dkim_pass": false,
    "dmarc_pass": false,
    "url_count": 3,
    "has_suspicious_urls": true
  }
}
```

**Example response:**
```json
{
  "verdict": "likely_phishing",
  "confidence": 97,
  "model_scores": {
    "lr": 0.95,
    "svm": 0.98,
    "gbdt": 0.99,
    "transformer": 0.96
  }
}
```

---

## 🔒 Privacy & Security Design

- **Zero disk retention**: `.eml` files and email bodies are processed entirely in-memory per request
- **Session-scoped storage**: All session data auto-expires after **2 hours**
- **One-click wipe**: Users can clear all session data instantly
- **No training on uploads**: Raw email content is never used for model training
- **Gemini receives only sanitized metadata**: Raw bodies are never forwarded to the AI assistant
- **API keys via `.env` only**: Never hardcoded — `.env` is git-ignored

---

## 🌿 Branch Structure

| Branch | Purpose |
|--------|---------|
| `main` | Stable, production-ready code |
| `ML-Training` | ML pipeline, model training scripts, and microservice |

---

## 📦 Tech Stack

**Frontend:**
- React 19 + TypeScript
- Tailwind CSS v4
- Vite 8
- Lucide React icons
- Motion (animations)

**Backend (Node):**
- Express 4
- TypeScript / tsx
- mailparser (RFC MIME parsing)
- @google/genai (Gemini AI)
- jspdf, xlsx (export)

**ML Microservice (Python):**
- FastAPI + Uvicorn
- scikit-learn (LR, SVM, SGD)
- XGBoost (GBDT)
- pandas, numpy, joblib

---

## 🗂️ Project Status

This project is a **capstone research project** in active development.

- ✅ Phase 1 — Core forensics pipeline, UI, evidence fusion
- ✅ Phase 2 — Real ML training pipeline, 4 trained model adapters, Python microservice
- 🔄 Phase 3 — Model fine-tuning, deployment, documentation

---

## 📄 License

This project is for academic and research purposes.

---

## 👥 Authors

Developed as part of a Cybersecurity Capstone Project.

> *"Evidence-grounded, privacy-first email threat intelligence."*
#   P h i s h S c o p e  
 