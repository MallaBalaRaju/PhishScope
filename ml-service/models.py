import math
from typing import Tuple, List
from .schemas import (
    StandardizedModelFeatures, 
    StandardizedModelPrediction, 
    ModelScoreSemantics, 
    ContributingFeature
)

class TfidfLogisticRegressionModel:
    id = "tfidf-logistic-regression"
    name = "Python TF-IDF + Logistic Regression"
    version = "0.1.0-research-stub"
    preprocessing_version = "v1-unigram-bigram-tfidf"

    def predict(self, features: StandardizedModelFeatures, snapshot_id: str, timestamp: str) -> StandardizedModelPrediction:
        text = f"{features.subjectText or ''} {features.bodyCleanText or ''}".lower()
        log_odds = -1.2
        contributing: List[ContributingFeature] = []

        keywords = [
            ("urgent", 0.8),
            ("verify your password", 1.4),
            ("suspended", 1.1),
            ("wire transfer", 1.3),
            ("immediately", 0.7)
        ]

        for word, weight in keywords:
            if word in text:
                log_odds += weight
                contributing.append(ContributingFeature(
                    featureName=f"token:{word}",
                    featureState="present",
                    importance=weight,
                    explanation=f"Lexical n-gram match for '{word}' (+{weight} log-odds)."
                ))

        prob = 1.0 / (1.0 + math.exp(-log_odds))
        raw_prob = round(prob, 3)

        return StandardizedModelPrediction(
            modelId=self.id,
            modelName=self.name,
            modelVersion=self.version,
            preprocessingVersion=self.preprocessing_version,
            featureSchemaVersion=features.schemaVersion,
            snapshotId=snapshot_id,
            predictionTimestamp=timestamp,
            isConfigured=True,
            predictedClass="phishing" if raw_prob >= 0.5 else "legitimate",
            scoreSemantics=ModelScoreSemantics(
                decisionScore=round(log_odds, 2),
                probability=raw_prob,
                calibratedProbability=None,
                isCalibrated=False,
                calibrationMethod=None
            ),
            confidenceScore=round(abs(raw_prob - 0.5) * 2, 2),
            contributingFeatures=contributing,
            rationale=f"Python TF-IDF + Logistic Regression sigmoid evaluation yielding probability {raw_prob}.",
            limitations=[
                "Lexical features only; no DKIM/SPF integration.",
                "Uncalibrated raw sigmoid output; not experimentally validated."
            ]
        )

class TfidfLinearSvmModel:
    id = "tfidf-linear-svm"
    name = "Python TF-IDF + Linear SVM"
    version = "0.1.0-research-stub"
    preprocessing_version = "v1-l2-normalized-tfidf"

    def predict(self, features: StandardizedModelFeatures, snapshot_id: str, timestamp: str) -> StandardizedModelPrediction:
        text = f"{features.subjectText or ''} {features.bodyCleanText or ''}".lower()
        margin = -0.75
        contributing: List[ContributingFeature] = []

        keywords = [
            ("security update", 1.2),
            ("verify account", 1.6),
            ("suspended", 1.4),
            ("password", 0.9)
        ]

        for word, weight in keywords:
            if word in text:
                margin += weight
                contributing.append(ContributingFeature(
                    featureName=f"token:{word}",
                    featureState="present",
                    importance=weight,
                    explanation=f"Linear SVM weight for '{word}': +{weight} hyperplane margin."
                ))

        rounded_margin = round(margin, 2)

        return StandardizedModelPrediction(
            modelId=self.id,
            modelName=self.name,
            modelVersion=self.version,
            preprocessingVersion=self.preprocessing_version,
            featureSchemaVersion=features.schemaVersion,
            snapshotId=snapshot_id,
            predictionTimestamp=timestamp,
            isConfigured=True,
            predictedClass="phishing" if rounded_margin >= 0.0 else "legitimate",
            scoreSemantics=ModelScoreSemantics(
                decisionScore=rounded_margin,
                probability=None, # Crucial: SVM margin is NOT a probability per Section 3
                calibratedProbability=None,
                isCalibrated=False,
                calibrationMethod=None
            ),
            confidenceScore=round(min(1.0, abs(rounded_margin) / 3.0), 2),
            contributingFeatures=contributing,
            rationale=f"Python Linear SVM calculated hyperplane margin of {rounded_margin}. Margin >= 0 represents phishing classification boundary.",
            limitations=[
                "Uncalibrated SVM hyperplane margin; cannot be interpreted as a probability.",
                "Platt scaling calibration is not applied in research stub.",
                "Lexical features only."
            ]
        )

class GbdtStructuredForensicsModel:
    id = "gbdt-structured-forensics"
    name = "Python GBDT Structured Forensics"
    version = "0.1.0-research-stub"
    preprocessing_version = "v1-four-state-forensic-encoding"

    def predict(self, features: StandardizedModelFeatures, snapshot_id: str, timestamp: str) -> StandardizedModelPrediction:
        log_odds = -1.5
        contributing: List[ContributingFeature] = []

        if features.hasAnchorTextDivergence == "true":
            log_odds += 2.2
            contributing.append(ContributingFeature(
                featureName="hasAnchorTextDivergence",
                featureState="true",
                importance=0.35,
                explanation="Split on anchor text mismatch (+2.2 log-odds)."
            ))

        if features.spfPass == "false" or features.dkimPass == "false" or features.dmarcPass == "false":
            log_odds += 1.8
            contributing.append(ContributingFeature(
                featureName="authStatus",
                featureState="false",
                importance=0.28,
                explanation="Split on active SPF/DKIM authentication failure (+1.8 log-odds)."
            ))
        elif features.spfPass == "unknown" and features.dkimPass == "unknown":
            log_odds += 0.3
            contributing.append(ContributingFeature(
                featureName="authStatus",
                featureState="unknown",
                importance=0.05,
                explanation="Split on omitted authentication headers (+0.3 log-odds)."
            ))

        if features.hasDirectIpUrls == "true":
            log_odds += 1.5
            contributing.append(ContributingFeature(
                featureName="hasDirectIpUrls",
                featureState="true",
                importance=0.20,
                explanation="Split on direct IP URL target (+1.5 log-odds)."
            ))

        if features.hasSuspiciousAttachmentType == "true":
            log_odds += 1.6
            contributing.append(ContributingFeature(
                featureName="hasSuspiciousAttachmentType",
                featureState="true",
                importance=0.22,
                explanation="Split on dangerous MIME extension (+1.6 log-odds)."
            ))

        prob = 1.0 / (1.0 + math.exp(-log_odds))
        raw_prob = round(prob, 3)

        return StandardizedModelPrediction(
            modelId=self.id,
            modelName=self.name,
            modelVersion=self.version,
            preprocessingVersion=self.preprocessing_version,
            featureSchemaVersion=features.schemaVersion,
            snapshotId=snapshot_id,
            predictionTimestamp=timestamp,
            isConfigured=True,
            predictedClass="phishing" if raw_prob >= 0.5 else "legitimate",
            scoreSemantics=ModelScoreSemantics(
                decisionScore=round(log_odds, 2),
                probability=raw_prob,
                calibratedProbability=None,
                isCalibrated=False,
                calibrationMethod=None
            ),
            confidenceScore=round(abs(raw_prob - 0.5) * 2, 2),
            contributingFeatures=contributing,
            rationale=f"Python GBDT evaluated four-state structured forensic features yielding uncalibrated probability {raw_prob}.",
            limitations=[
                "Relies strictly on structured categorical/numerical forensic indicators.",
                "Uncalibrated ensemble output."
            ]
        )

class TransformerClassifierModel:
    id = "transformer-classifier"
    name = "Python Transformer Sequence Classifier"
    version = "0.1.0-research-stub"
    preprocessing_version = "v1-bpe-tokenizer-512seq"

    def predict(self, features: StandardizedModelFeatures, snapshot_id: str, timestamp: str) -> StandardizedModelPrediction:
        text = f"{features.subjectText or ''} {features.bodyCleanText or ''}".lower()
        logit = -0.9
        contributing: List[ContributingFeature] = []

        if "urgent" in text or "immediate" in text:
            logit += 0.85
            contributing.append(ContributingFeature(
                featureName="attention:temporal_coercion",
                featureState="high_attention",
                importance=0.25,
                explanation="Attention heads concentrated on temporal coercion markers."
            ))

        if "password" in text or "credentials" in text or "re-authenticate" in text:
            logit += 1.35
            contributing.append(ContributingFeature(
                featureName="attention:credential_solicitation",
                featureState="high_attention",
                importance=0.40,
                explanation="Attention heads focused on credential harvesting sequence."
            ))

        if features.hasAnchorTextDivergence == "true":
            logit += 1.4
            contributing.append(ContributingFeature(
                featureName="multimodal:anchor_divergence",
                featureState="true",
                importance=0.35,
                explanation="Multimodal embedding confirms anchor divergence."
            ))

        prob = 1.0 / (1.0 + math.exp(-logit))
        raw_prob = round(prob, 3)

        return StandardizedModelPrediction(
            modelId=self.id,
            modelName=self.name,
            modelVersion=self.version,
            preprocessingVersion=self.preprocessing_version,
            featureSchemaVersion=features.schemaVersion,
            snapshotId=snapshot_id,
            predictionTimestamp=timestamp,
            isConfigured=True,
            predictedClass="phishing" if raw_prob >= 0.5 else "legitimate",
            scoreSemantics=ModelScoreSemantics(
                decisionScore=round(logit, 2),
                probability=raw_prob,
                calibratedProbability=None,
                isCalibrated=False,
                calibrationMethod=None
            ),
            confidenceScore=round(abs(raw_prob - 0.5) * 2, 2),
            contributingFeatures=contributing,
            rationale=f"Python Transformer sequence classifier evaluated tokens yielding raw probability {raw_prob}.",
            limitations=[
                "Model weights are illustrative sequence stubs.",
                "Uncalibrated logit score; not fine-tuned on approved datasets."
            ]
        )
