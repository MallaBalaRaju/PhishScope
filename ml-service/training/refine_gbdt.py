"""
Refine and retrain Model 3: XGBoost GBDT Structured Forensics
Ensures consistent features across all 5 datasets and PhishScope runtime.
"""

import re
import warnings
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = ROOT / "dataset"
MODEL_DIR = ROOT / "ml-service" / "saved_models"

SUSPICIOUS_WORDS = [
    "urgent", "verify", "password", "suspended", "immediately", "click here",
    "confirm", "account", "login", "update", "credit", "bank", "paypal",
    "microsoft", "apple", "google", "amazon", "security", "alert", "prize",
    "winner", "lottery", "free", "offer", "limited", "expire", "wire",
    "transfer", "invoice", "refund", "ssn", "social security", "pin",
    "billing", "access", "statement", "validation", "unauthorized", "threat",
    "action required", "dear customer", "dear user", "risk", "identity",
    "deactivation", "locked", "violation"
]

BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "chase",
    "wellsfargo", "bank of america", "citi", "netflix", "fedex", "dhl", "ups"
]

SHORTENERS = [
    "bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "short.io", "rb.gy", "cutt.ly"
]

FEATURE_NAMES = [
    "text_len", "word_count", "susp_words", "susp_ratio", "brand_count",
    "exclaim_count", "question_count", "currency_count", "digit_ratio",
    "caps_ratio", "url_count", "url_ratio", "has_ip_url", "has_shortener",
    "has_html"
]


def extract_features(text: str, total_url_count: int = None, has_ip: int = None, has_short: int = None) -> list:
    t = str(text or "")
    t_lower = t.lower()
    words = t_lower.split()
    w_count = max(len(words), 1)
    t_len = max(len(t), 1)

    susp_count = sum(1 for w in SUSPICIOUS_WORDS if w in t_lower)
    brand_count = sum(1 for b in BRANDS if b in t_lower)
    exclaim_count = t.count("!")
    question_count = t.count("?")
    curr_count = t.count("$") + t.count("€") + t.count("£")
    digit_ratio = sum(1 for c in t if c.isdigit()) / t_len
    caps_ratio = sum(1 for c in t if c.isupper()) / t_len

    if total_url_count is None:
        url_matches = re.findall(r"https?://[^\s<>\"\'\)]+", t_lower)
        url_count = len(url_matches)
    else:
        url_count = total_url_count

    if has_ip is None:
        has_ip_url = int(bool(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", t_lower)))
    else:
        has_ip_url = has_ip

    if has_short is None:
        has_shortener = int(any(s in t_lower for s in SHORTENERS))
    else:
        has_shortener = has_short

    has_html = int("<html" in t_lower or "<a " in t_lower or "href=" in t_lower)

    return [
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
        round(url_count / w_count, 4),
        float(has_ip_url),
        float(has_shortener),
        float(has_html),
    ]


def extract_matrix(series_text, urls_series=None) -> np.ndarray:
    rows = []
    has_urls = urls_series is not None
    for i, t in enumerate(series_text):
        u_cnt = None
        if has_urls:
            try:
                val = urls_series.iloc[i]
                u_cnt = int(float(str(val))) if str(val) not in ("nan", "", "None") else 0
            except Exception:
                u_cnt = 0
        rows.append(extract_features(t, total_url_count=u_cnt))
    return np.array(rows, dtype=np.float32)


def main():
    print("=" * 60)
    print("  REFINING MODEL 3: XGBoost GBDT Structured Forensics")
    print("=" * 60)

    # 1. CEAS_08.csv
    print("Loading CEAS_08.csv ...", end=" ", flush=True)
    df_ceas = pd.read_csv(DATASET_DIR / "CEAS_08.csv").dropna(subset=["body"])
    df_ceas["text"] = df_ceas["subject"].fillna("") + " " + df_ceas["body"].fillna("")
    X_ceas = extract_matrix(df_ceas["text"], df_ceas["urls"])
    y_ceas = df_ceas["label"].astype(int).values
    print(f"{len(df_ceas):,} rows")

    # 2. phishing_email.csv
    print("Loading phishing_email.csv ...", end=" ", flush=True)
    df_pe = pd.read_csv(DATASET_DIR / "phishing_email.csv").dropna(subset=["text_combined"])
    X_pe = extract_matrix(df_pe["text_combined"])
    y_pe = df_pe["label"].astype(int).values
    print(f"{len(df_pe):,} rows")

    # 3. Enron.csv
    print("Loading Enron.csv ...", end=" ", flush=True)
    df_enron = pd.read_csv(DATASET_DIR / "Enron.csv").dropna(subset=["body"])
    df_enron["text"] = df_enron["subject"].fillna("") + " " + df_enron["body"].fillna("")
    X_enron = extract_matrix(df_enron["text"])
    y_enron = df_enron["label"].astype(int).values
    print(f"{len(df_enron):,} rows")

    # 4. emails.csv
    print("Loading emails.csv ...", end=" ", flush=True)
    df_em = pd.read_csv(DATASET_DIR / "emails.csv")
    word_cols = [c for c in df_em.columns if c not in ("Email No.", "Prediction")]
    def bow_to_text(row):
        tokens = []
        for col in word_cols:
            cnt = min(int(row[col]), 5)
            if cnt > 0:
                tokens.extend([col] * cnt)
        return " ".join(tokens)
    text_em = df_em.apply(bow_to_text, axis=1)
    X_em = extract_matrix(text_em)
    y_em = df_em["Prediction"].astype(int).values
    print(f"{len(df_em):,} rows")

    # Combine & Balance
    X_all = np.vstack([X_ceas, X_pe, X_enron, X_em])
    y_all = np.concatenate([y_ceas, y_pe, y_enron, y_em])

    n_min = min(np.sum(y_all == 0), np.sum(y_all == 1))
    idx0 = np.where(y_all == 0)[0]
    idx1 = np.where(y_all == 1)[0]
    rng = np.random.default_rng(42)
    idx0_s = rng.choice(idx0, n_min, replace=False)
    idx1_s = rng.choice(idx1, n_min, replace=False)
    idx_bal = np.concatenate([idx0_s, idx1_s])
    rng.shuffle(idx_bal)

    X_train = X_all[idx_bal]
    y_train = y_all[idx_bal]
    print(f"\nCombined Balanced Training Set: {len(X_train):,} rows ({n_min:,} each class)")

    # 5. SpamAssasin.csv (Held-out Test)
    print("\nLoading SpamAssasin.csv (Held-out Test) ...", end=" ", flush=True)
    df_sa = pd.read_csv(DATASET_DIR / "SpamAssasin.csv").dropna(subset=["body"])
    df_sa["text"] = df_sa["subject"].fillna("") + " " + df_sa["body"].fillna("")
    X_test = extract_matrix(df_sa["text"], df_sa["urls"])
    y_test = df_sa["label"].astype(int).values
    print(f"{len(df_sa):,} rows")

    # Train XGBoost
    print("\nTraining XGBoost Classifier ...", end=" ", flush=True)
    clf = xgb.XGBClassifier(
        n_estimators=350,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1
    )
    clf.fit(X_train, y_train)
    print("done.")

    # Evaluate
    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]
    acc = accuracy_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)

    print("\n" + "=" * 55)
    print(" MODEL 3: XGBoost GBDT Structured (Refined — SpamAssassin)")
    print("=" * 55)
    print(f"  Accuracy : {acc:.4f}")
    print(f"  ROC-AUC  : {auc:.4f}")
    print(classification_report(y_test, preds, target_names=["Legitimate", "Phishing"]))

    # Save
    joblib.dump(clf, MODEL_DIR / "gbdt_xgboost_model.pkl")
    joblib.dump(FEATURE_NAMES, MODEL_DIR / "gbdt_feature_names.pkl")
    importance = dict(zip(FEATURE_NAMES, clf.feature_importances_.tolist()))
    joblib.dump(importance, MODEL_DIR / "gbdt_feature_importance.pkl")
    print("  ✓ Saved updated model and feature names to saved_models/")

    print("\nTop Feature Importances:")
    for f, imp in sorted(importance.items(), key=lambda x: -x[1]):
        print(f"  {f:<22} {imp:.4f}")


if __name__ == "__main__":
    main()

