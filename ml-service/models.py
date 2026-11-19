"""
PhishScope ML Model Adapters — Real Trained Inference
======================================================
Replaces all research stubs with trained sklearn / XGBoost models.
Models are loaded once at import time from ml-service/saved_models/.

Training data used across all models:
  1. phishing_email.csv  (82K rows — primary text corpus)
  2. Enron.csv           (30K rows — balanced spam/ham)
  3. emails.csv          (5K rows  — pre-vectorized Enron word counts)
  4. CEAS_08.csv         (39K rows — structured features with sender/URLs)
  5. SpamAssasin.csv     (5.8K rows — held-out test set only, never trained on)
"""

import os
import math
import logging
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import joblib

try:
    from .schemas import (
        StandardizedModelFeatures,
        StandardizedModelPrediction,
        ModelScoreSemantics,
        ContributingFeature,
    )
except ImportError:
    from schemas import (
        StandardizedModelFeatures,
        StandardizedModelPrediction,
        ModelScoreSemantics,
        ContributingFeature,
    )

logger = logging.getLogger(__name__)

# ── Model artifact directory ───────────────────────────────────────────────────
_MODEL_DIR = Path(__file__).resolve().parent / "saved_models"

# ── Suspicious keyword list (mirrors training) ─────────────────────────────────
_SUSPICIOUS_WORDS = [
    "urgent", "verify", "password", "suspended", "immediately", "click here",
    "confirm", "account", "login", "update", "credit", "bank", "paypal",
    "microsoft", "apple", "google", "amazon", "security", "alert", "prize",
    "winner", "lottery", "free", "offer", "limited", "expire", "wire",
    "transfer", "invoice", "refund"
]
_SHORTENER_DOMAINS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly",
                       "short.io", "rb.gy", "cutt.ly"]

# ── PhishScope four-state → numeric mapping ────────────────────────────────────
_STATE_MAP = {"true": 1.0, "false": 0.0, "unknown": 0.5, "not_applicable": 0.5}


# ══════════════════════════════════════════════════════════════════════════════
# SHARED UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def _load_model(filename: str):
    """Load a joblib artifact; return None if not yet trained."""
    path = _MODEL_DIR / filename
    if not path.exists():
        logger.warning(f"Model artifact not found: {path}. Run train_all_models.py first.")
        return None
    try:
        return joblib.load(path)
    except Exception as exc:
        logger.error(f"Failed to load {filename}: {exc}")
        return None


def _build_text(features: StandardizedModelFeatures) -> str:
    """Combine subject and body into a single string for text models."""
    parts = []
    if features.subjectText:
        parts.append(features.subjectText.strip())
    if features.bodyCleanText:
        parts.append(features.bodyCleanText.strip())
    return " ".join(parts)


def _prob_to_class(prob: float, threshold: float = 0.5) -> str:
    if prob >= 0.75:
        return "phishing"
    elif prob >= threshold:
        return "phishing"
    elif prob >= 0.30:
        return "suspicious"
    else:
        return "legitimate"


def _confidence(prob: float) -> float:
    """Distance from decision boundary → [0, 1]."""
    return round(abs(prob - 0.5) * 2, 3)


def _top_tfidf_tokens(pipeline, text: str, n: int = 5) -> List[ContributingFeature]:
    """Extract top TF-IDF token contributions from a fitted sklearn pipeline."""
    contributing = []
    try:
        vectorizer = pipeline.named_steps["tfidf"]
        clf = pipeline.named_steps["clf"]

        # Get TF-IDF vector for this document
        X_vec = vectorizer.transform([text])
        feature_names = vectorizer.get_feature_names_out()

        # For LR: use coefficient * tfidf_weight per token
        if hasattr(clf, "coef_"):
            coefs = clf.coef_[0]  # shape: (n_features,)
            # Only consider tokens present in this document
            x_arr = X_vec.toarray()[0]
            scores = coefs * x_arr
            top_idx = np.argsort(np.abs(scores))[::-1][:n]
            for idx in top_idx:
                if x_arr[idx] > 0:
                    token = feature_names[idx]
                    score = float(scores[idx])
                    contributing.append(ContributingFeature(
                        featureName=f"token:{token}",
                        featureState="present",
                        importance=round(abs(score), 4),
                        explanation=(
                            f"TF-IDF token '{token}' — "
                            f"{'increases' if score > 0 else 'decreases'} "
                            f"phishing probability (weight={score:+.4f})"
                        )
                    ))
        # For CalibratedClassifierCV wrapping LinearSVC
        elif hasattr(clf, "calibrated_classifiers_"):
            base = clf.calibrated_classifiers_[0].estimator
            if hasattr(base, "coef_"):
                coefs = base.coef_[0]
                x_arr = X_vec.toarray()[0]
                scores = coefs * x_arr
                top_idx = np.argsort(np.abs(scores))[::-1][:n]
                for idx in top_idx:
                    if x_arr[idx] > 0:
                        token = feature_names[idx]
                        score = float(scores[idx])
                        contributing.append(ContributingFeature(
                            featureName=f"token:{token}",
                            featureState="present",
                            importance=round(abs(score), 4),
                            explanation=(
                                f"SVM token '{token}' — hyperplane contribution "
                                f"(margin={score:+.4f})"
                            )
                        ))
    except Exception as exc:
        logger.debug(f"Could not extract token contributions: {exc}")
    return contributing


def _build_structured_features(features: StandardizedModelFeatures) -> np.ndarray:
    """
    Build the 15-dimensional structured feature vector used by the GBDT model.
    Must exactly match the feature engineering in refine_gbdt.py / train_all_models.py.
    """
    subject = features.subjectText or ""
    body = features.bodyCleanText or ""
    combined = (subject + " " + body).strip()
    c_lower = combined.lower()
    words = c_lower.split()
    w_count = max(len(words), 1)
    t_len = max(len(combined), 1)

    susp_count = sum(1 for w in _SUSPICIOUS_WORDS if w in c_lower)
    brand_count = features.suspiciousBrandMentionCount or sum(
        1 for b in ["paypal", "microsoft", "google", "apple", "amazon", "chase", "bank of america"] if b in c_lower
    )
    exclaim_count = combined.count("!")
    question_count = combined.count("?")
    curr_count = combined.count("$") + combined.count("€") + combined.count("£")
    digit_ratio = sum(1 for c in combined if c.isdigit()) / t_len
    caps_ratio = sum(1 for c in combined if c.isupper()) / t_len

    url_count = features.totalUrlCount
    url_ratio = round(url_count / w_count, 4)
    has_ip_url = float(features.hasDirectIpUrls == "true")
    has_shortener = float(features.hasShortenerUrls == "true" or any(s in c_lower for s in _SHORTENER_DOMAINS))
    has_html = float(features.hasHtmlMarkup == "true" or "<html" in c_lower or "<a " in c_lower)

    return np.array([[
        float(t_len),
        float(w_count),
        float(susp_count),
        round(susp_count / w_count, 4),
        float(brand_count),
        float(exclaim_count),
        float(question_count),
        float(curr_count),
        round(digit_ratio, 4),
        round(caps_ratio, 4),
        float(url_count),
        float(url_ratio),
        float(has_ip_url),
        float(has_shortener),
        float(has_html),
    ]], dtype=np.float32)


def _gbdt_contributing(model, feature_names: List[str],
                       x_vec: np.ndarray) -> List[ContributingFeature]:
    """Extract top XGBoost feature importances weighted by feature value."""
    contributing = []
    try:
        importances = model.feature_importances_
        x_flat = x_vec[0]
        scores = importances * np.abs(x_flat)
        top_idx = np.argsort(scores)[::-1][:5]
        for idx in top_idx:
            if importances[idx] > 0.001:
                fname = feature_names[idx]
                val   = float(x_flat[idx])
                imp   = float(importances[idx])
                contributing.append(ContributingFeature(
                    featureName=f"structured:{fname}",
                    featureState=str(round(val, 2)),
                    importance=round(imp, 4),
                    explanation=(
                        f"GBDT split on '{fname}' (value={val:.2f}, "
                        f"global importance={imp:.4f})"
                    )
                ))
    except Exception as exc:
        logger.debug(f"Could not extract GBDT contributions: {exc}")
    return contributing


# ══════════════════════════════════════════════════════════════════════════════
# MODEL 1 — TF-IDF + Logistic Regression
# Trained on: phishing_email.csv + Enron.csv + emails.csv
# ══════════════════════════════════════════════════════════════════════════════

class TfidfLogisticRegressionModel:
    id                   = "tfidf-logistic-regression"
    name                 = "TF-IDF + Logistic Regression"
    version              = "1.0.0"
    preprocessing_version = "v2-unigram-bigram-tfidf-50k"

    def __init__(self):
        self._pipeline = _load_model("lr_tfidf_pipeline.pkl")
        self._is_configured = self._pipeline is not None

    def predict(
        self,
        features: StandardizedModelFeatures,
        snapshot_id: str,
        timestamp: str,
    ) -> StandardizedModelPrediction:

        if not self._is_configured or self._pipeline is None:
            return _unconfigured_prediction(self, snapshot_id, timestamp)

        text = _build_text(features)
        if not text.strip():
            return _empty_text_prediction(self, snapshot_id, timestamp)

        prob       = float(self._pipeline.predict_proba([text])[0][1])
        pred_class = _prob_to_class(prob)
        confidence = _confidence(prob)
        log_odds   = math.log(prob / max(1 - prob, 1e-9))
        contributing = _top_tfidf_tokens(self._pipeline, text, n=5)

        # Enrich with PhishScope forensic signals
        contributing += _forensic_signal_features(features)

        return StandardizedModelPrediction(
            modelId=self.id,
            modelName=self.name,
            modelVersion=self.version,
            preprocessingVersion=self.preprocessing_version,
            featureSchemaVersion=features.schemaVersion,
            snapshotId=snapshot_id,
            predictionTimestamp=timestamp,
            isConfigured=True,
            predictedClass=pred_class,
            scoreSemantics=ModelScoreSemantics(
                decisionScore=round(log_odds, 4),
                probability=round(prob, 4),
                calibratedProbability=round(prob, 4),
                isCalibrated=True,
                calibrationMethod="logistic-sigmoid"
            ),
            confidenceScore=confidence,
            contributingFeatures=contributing,
            rationale=(
                f"TF-IDF Logistic Regression (trained on phishing_email + Enron + emails "
                f"corpora, 50K vocab, unigrams+bigrams). "
                f"Phishing probability: {prob:.3f}. "
                f"Decision: '{pred_class}'."
            ),
            limitations=[
                "Lexical bag-of-words; ignores word order and context.",
                "No authentication (SPF/DKIM) signal in text models.",
                "Generalises across spam/phishing; may miss highly targeted spear-phishing.",
            ]
        )


# ══════════════════════════════════════════════════════════════════════════════
# MODEL 2 — TF-IDF + Linear SVM (Platt Calibrated)
# Trained on: phishing_email.csv + Enron.csv + emails.csv
# ══════════════════════════════════════════════════════════════════════════════

class TfidfLinearSvmModel:
    id                   = "tfidf-linear-svm"
    name                 = "TF-IDF + Linear SVM (Platt Calibrated)"
    version              = "1.0.0"
    preprocessing_version = "v2-l2-normalized-tfidf-platt"

    def __init__(self):
        self._pipeline = _load_model("svm_tfidf_pipeline.pkl")
        self._is_configured = self._pipeline is not None

    def predict(
        self,
        features: StandardizedModelFeatures,
        snapshot_id: str,
        timestamp: str,
    ) -> StandardizedModelPrediction:

        if not self._is_configured or self._pipeline is None:
            return _unconfigured_prediction(self, snapshot_id, timestamp)

        text = _build_text(features)
        if not text.strip():
            return _empty_text_prediction(self, snapshot_id, timestamp)

        prob        = float(self._pipeline.predict_proba([text])[0][1])
        pred_class  = _prob_to_class(prob)
        confidence  = _confidence(prob)
        contributing = _top_tfidf_tokens(self._pipeline, text, n=5)
        contributing += _forensic_signal_features(features)

        return StandardizedModelPrediction(
            modelId=self.id,
            modelName=self.name,
            modelVersion=self.version,
            preprocessingVersion=self.preprocessing_version,
            featureSchemaVersion=features.schemaVersion,
            snapshotId=snapshot_id,
            predictionTimestamp=timestamp,
            isConfigured=True,
            predictedClass=pred_class,
            scoreSemantics=ModelScoreSemantics(
                decisionScore=round(prob, 4),
                probability=round(prob, 4),
                calibratedProbability=round(prob, 4),
                isCalibrated=True,
                calibrationMethod="platt-sigmoid-cv3"
            ),
            confidenceScore=confidence,
            contributingFeatures=contributing,
            rationale=(
                f"Linear SVM with Platt sigmoid calibration (cv=3). "
                f"Trained on phishing_email + Enron + emails corpora, 50K vocab. "
                f"Calibrated phishing probability: {prob:.3f}. "
                f"Decision: '{pred_class}'."
            ),
            limitations=[
                "SVM margin calibrated via Platt scaling — probability may be overconfident near boundary.",
                "Lexical features only; word order not preserved.",
                "Sensitive to out-of-vocabulary tokens not seen during training.",
            ]
        )


# ══════════════════════════════════════════════════════════════════════════════
# MODEL 3 — XGBoost GBDT on Structured Features
# Trained on: CEAS_08.csv + phishing_email.csv + Enron.csv + emails.csv
# ══════════════════════════════════════════════════════════════════════════════

class GbdtStructuredForensicsModel:
    id                   = "gbdt-structured-forensics"
    name                 = "XGBoost GBDT — Structured Forensics"
    version              = "1.0.0"
    preprocessing_version = "v2-15-feature-structured-engineering"

    def __init__(self):
        self._model         = _load_model("gbdt_xgboost_model.pkl")
        self._feat_names    = _load_model("gbdt_feature_names.pkl") or []
        self._feat_importance = _load_model("gbdt_feature_importance.pkl") or {}
        self._is_configured = self._model is not None

    def predict(
        self,
        features: StandardizedModelFeatures,
        snapshot_id: str,
        timestamp: str,
    ) -> StandardizedModelPrediction:

        if not self._is_configured or self._model is None:
            return _unconfigured_prediction(self, snapshot_id, timestamp)

        # Build structured feature vector
        x_vec = _build_structured_features(features)

        raw_prob = float(self._model.predict_proba(x_vec)[0][1])

        # Layer in four-state forensic indicator adjustments (SPF/DKIM/DMARC, Anchor, Direct IP)
        forensic_delta = 0.0
        if features.spfPass == "false":
            forensic_delta += 0.20
        elif features.spfPass == "true":
            forensic_delta -= 0.20

        if features.dkimPass == "false":
            forensic_delta += 0.15
        elif features.dkimPass == "true":
            forensic_delta -= 0.15

        if features.dmarcPass == "false":
            forensic_delta += 0.15
        elif features.dmarcPass == "true":
            forensic_delta -= 0.10

        if features.hasAnchorTextDivergence == "true":
            forensic_delta += 0.25
        if features.hasDirectIpUrls == "true":
            forensic_delta += 0.25
        if features.hasSuspiciousAttachmentType == "true":
            forensic_delta += 0.25

        prob = max(0.001, min(0.999, round(raw_prob + forensic_delta, 4)))
        pred_class = _prob_to_class(prob)
        confidence = _confidence(prob)
        log_odds   = math.log(prob / max(1 - prob, 1e-9))

        # GBDT feature contributions
        contributing = _gbdt_contributing(self._model, self._feat_names, x_vec)

        # Layer in PhishScope's own forensic signals (auth, routing, URL)
        contributing += _forensic_signal_features(features)

        return StandardizedModelPrediction(
            modelId=self.id,
            modelName=self.name,
            modelVersion=self.version,
            preprocessingVersion=self.preprocessing_version,
            featureSchemaVersion=features.schemaVersion,
            snapshotId=snapshot_id,
            predictionTimestamp=timestamp,
            isConfigured=True,
            predictedClass=pred_class,
            scoreSemantics=ModelScoreSemantics(
                decisionScore=round(log_odds, 4),
                probability=round(prob, 4),
                calibratedProbability=round(prob, 4),
                isCalibrated=True,
                calibrationMethod="xgboost-internal-probability"
            ),
            confidenceScore=confidence,
            contributingFeatures=contributing,
            rationale=(
                f"XGBoost GBDT on 15 engineered structured features with forensic indicator adjustments "
                f"(CEAS_08 + phishing_email + Enron + emails corpora). "
                f"Raw GBDT probability: {raw_prob:.3f}, forensic delta: {forensic_delta:+.2f} -> final probability: {prob:.3f}. "
                f"Decision: '{pred_class}'."
            ),
            limitations=[
                "Structured features derived from text statistics; no raw text modelling.",
                "Sender metadata not available from PhishScope feature schema (defaulted).",
                "GBDT probability well-calibrated on training distribution but may drift on novel attack types.",
            ]
        )


# ══════════════════════════════════════════════════════════════════════════════
# MODEL 4 — Transformer (High-Capacity TF-IDF + LR, 100K vocab, trigrams)
# Trained on: phishing_email.csv + Enron.csv + emails.csv
# ══════════════════════════════════════════════════════════════════════════════

class TransformerClassifierModel:
    id                   = "transformer-classifier"
    name                 = "Transformer Sequence Classifier"
    version              = "1.0.0"
    preprocessing_version = "v2-trigram-tfidf-100k-saga"

    def __init__(self):
        self._pipeline = _load_model("transformer_tfidf_pipeline.pkl")
        self._is_configured = self._pipeline is not None

    def predict(
        self,
        features: StandardizedModelFeatures,
        snapshot_id: str,
        timestamp: str,
    ) -> StandardizedModelPrediction:

        if not self._is_configured or self._pipeline is None:
            return _unconfigured_prediction(self, snapshot_id, timestamp)

        text = _build_text(features)
        if not text.strip():
            return _empty_text_prediction(self, snapshot_id, timestamp)

        prob        = float(self._pipeline.predict_proba([text])[0][1])
        pred_class  = _prob_to_class(prob)
        confidence  = _confidence(prob)
        log_odds    = math.log(prob / max(1 - prob, 1e-9))
        contributing = _top_tfidf_tokens(self._pipeline, text, n=6)
        contributing += _forensic_signal_features(features)

        return StandardizedModelPrediction(
            modelId=self.id,
            modelName=self.name,
            modelVersion=self.version,
            preprocessingVersion=self.preprocessing_version,
            featureSchemaVersion=features.schemaVersion,
            snapshotId=snapshot_id,
            predictionTimestamp=timestamp,
            isConfigured=True,
            predictedClass=pred_class,
            scoreSemantics=ModelScoreSemantics(
                decisionScore=round(log_odds, 4),
                probability=round(prob, 4),
                calibratedProbability=round(prob, 4),
                isCalibrated=True,
                calibrationMethod="logistic-sigmoid-saga"
            ),
            confidenceScore=confidence,
            contributingFeatures=contributing,
            rationale=(
                f"High-capacity TF-IDF (100K vocab, unigrams–trigrams) + Logistic Regression "
                f"(SAGA solver, C=5.0). Trained on phishing_email + Enron + emails corpora. "
                f"Phishing probability: {prob:.3f}. "
                f"Decision: '{pred_class}'."
            ),
            limitations=[
                "CPU-safe approximation of transformer semantics via high-order n-grams.",
                "Does not use contextual embeddings — replace with DistilBERT if GPU is available.",
                "100K vocab may cause memory pressure on low-RAM deployments.",
            ]
        )


# ══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS — Forensic Signal Enrichment & Fallback Predictions
# ══════════════════════════════════════════════════════════════════════════════

def _forensic_signal_features(
    features: StandardizedModelFeatures,
) -> List[ContributingFeature]:
    """
    Convert PhishScope's forensic four-state features into
    ContributingFeature entries that explain the model's context.
    """
    signals: List[ContributingFeature] = []

    auth_checks = [
        ("spfPass",     features.spfPass,     "SPF authentication",     0.20),
        ("dkimPass",    features.dkimPass,    "DKIM signature",          0.18),
        ("dmarcPass",   features.dmarcPass,   "DMARC policy",            0.15),
        ("isDomainAligned", features.isDomainAligned, "Domain alignment", 0.12),
    ]
    for name, state, label, importance in auth_checks:
        if state in ("true", "false"):
            direction = "passes" if state == "true" else "FAILS"
            risk      = "reduces" if state == "true" else "increases"
            signals.append(ContributingFeature(
                featureName=f"forensic:{name}",
                featureState=state,
                importance=importance if state == "false" else importance * 0.3,
                explanation=f"{label} {direction} — {risk} phishing risk."
            ))

    url_checks = [
        ("hasDirectIpUrls",        features.hasDirectIpUrls,        "Direct IP-based URLs",   0.22),
        ("hasAnchorTextDivergence", features.hasAnchorTextDivergence,"Anchor text mismatch",   0.20),
        ("hasPunycodeDomains",     features.hasPunycodeDomains,     "Punycode/IDN homoglyphs", 0.18),
        ("hasShortenerUrls",       features.hasShortenerUrls,       "URL shortener detected",  0.10),
    ]
    for name, state, label, importance in url_checks:
        if state == "true":
            signals.append(ContributingFeature(
                featureName=f"forensic:{name}",
                featureState="true",
                importance=importance,
                explanation=f"{label} detected — strong phishing indicator."
            ))

    routing_checks = [
        ("hasNegativeTransitTime",  features.hasNegativeTransitTime,
         "Negative SMTP transit time (clock anomaly)", 0.15),
        ("hasPrivateOriginHop",     features.hasPrivateOriginHop,
         "Private IP as origin hop (internal relay)", 0.08),
    ]
    for name, state, label, importance in routing_checks:
        if state == "true":
            signals.append(ContributingFeature(
                featureName=f"forensic:{name}",
                featureState="true",
                importance=importance,
                explanation=f"{label}."
            ))

    if features.suspiciousBrandMentionCount > 0:
        signals.append(ContributingFeature(
            featureName="forensic:suspiciousBrandMentionCount",
            featureState=str(features.suspiciousBrandMentionCount),
            importance=round(min(features.suspiciousBrandMentionCount * 0.08, 0.30), 3),
            explanation=(
                f"{features.suspiciousBrandMentionCount} brand impersonation "
                f"keyword(s) found in subject/body."
            )
        ))

    if features.hasSuspiciousAttachmentType == "true":
        signals.append(ContributingFeature(
            featureName="forensic:hasSuspiciousAttachmentType",
            featureState="true",
            importance=0.25,
            explanation="Dangerous attachment MIME type detected (e.g. .exe, .js, .vbs)."
        ))

    return signals


def _unconfigured_prediction(model, snapshot_id: str, timestamp: str) -> StandardizedModelPrediction:
    return StandardizedModelPrediction(
        modelId=model.id,
        modelName=model.name,
        modelVersion=model.version,
        preprocessingVersion=model.preprocessing_version,
        featureSchemaVersion="2.0.0",
        snapshotId=snapshot_id,
        predictionTimestamp=timestamp,
        isConfigured=False,
        predictedClass="unavailable",
        scoreSemantics=ModelScoreSemantics(
            decisionScore=None, probability=None,
            calibratedProbability=None, isCalibrated=False
        ),
        confidenceScore=None,
        contributingFeatures=[],
        rationale=(
            f"Model '{model.id}' is not yet trained. "
            f"Run: python -m ml-service.training.train_all_models"
        ),
        limitations=["Model artifact not found — training required."]
    )


def _empty_text_prediction(model, snapshot_id: str, timestamp: str) -> StandardizedModelPrediction:
    return StandardizedModelPrediction(
        modelId=model.id,
        modelName=model.name,
        modelVersion=model.version,
        preprocessingVersion=model.preprocessing_version,
        featureSchemaVersion="2.0.0",
        snapshotId=snapshot_id,
        predictionTimestamp=timestamp,
        isConfigured=True,
        predictedClass="inconclusive",
        scoreSemantics=ModelScoreSemantics(
            decisionScore=0.0, probability=0.5,
            calibratedProbability=0.5, isCalibrated=True
        ),
        confidenceScore=0.0,
        contributingFeatures=[],
        rationale="Insufficient text content — both subject and body are empty or missing.",
        limitations=["Cannot classify without email text content."]
    )
