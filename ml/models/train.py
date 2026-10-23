"""
PhishShield ML Model Training Pipeline — Sprint 1/2
XGBoost + Logistic Regression baseline model training on 38-feature URL vectors.

Usage:
    python -m ml.models.train --data-dir ml/datasets --output-dir ml/models/weights

Datasets expected (CSV with columns: url, label [0=benign, 1=phishing]):
  - PhishTank verified phishing URLs
  - URLhaus malware URLs
  - Tranco Top-1M benign domains
"""
import argparse
import os
import sys
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, roc_auc_score,
    precision_score, recall_score, f1_score, accuracy_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.calibration import CalibratedClassifierCV
import joblib

# Add workspace root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from ml.features.url_features import extract_url_features

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    print("[WARNING] XGBoost not installed. Skipping XGBoost training.")


# ─── Feature Engineering ──────────────────────────────────────────────────────

FEATURE_COLUMNS = [
    "url_length", "hostname_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "underscore_count", "slash_count",
    "question_count", "equal_count", "at_count", "ampersand_count",
    "percent_count", "digit_count", "letter_count", "digit_ratio",
    "letter_ratio", "is_ip_address", "subdomain_count", "hostname_entropy",
    "has_punycode", "is_high_risk_tld", "is_https", "has_double_slash_in_path",
    "has_port_in_url", "keyword_count", "has_suspicious_keyword", "brand_count",
    "has_brand_in_subdomain", "url_entropy", "path_entropy",
    "dot_in_hostname", "hyphen_in_hostname", "digit_in_hostname",
    "param_count", "has_www", "consecutive_dots", "consecutive_hyphens",
]


def extract_features_batch(urls: pd.Series) -> pd.DataFrame:
    """Extracts 38-feature vectors for a batch of URLs."""
    rows = []
    for url in urls:
        try:
            feat = extract_url_features(str(url))
            rows.append({col: feat.get(col, 0) for col in FEATURE_COLUMNS})
        except Exception:
            rows.append({col: 0 for col in FEATURE_COLUMNS})
    return pd.DataFrame(rows)


# ─── Training ─────────────────────────────────────────────────────────────────

def load_dataset(data_dir: str) -> pd.DataFrame:
    """Loads and concatenates all CSV datasets from data_dir."""
    data_dir = Path(data_dir)
    dfs = []
    for csv_file in data_dir.glob("*.csv"):
        try:
            df = pd.read_csv(csv_file, usecols=["url", "label"])
            df = df.dropna()
            df["label"] = df["label"].astype(int)
            dfs.append(df)
            print(f"  Loaded {len(df)} rows from {csv_file.name}")
        except Exception as e:
            print(f"  [WARN] Could not load {csv_file.name}: {e}")
    if not dfs:
        raise FileNotFoundError(f"No valid CSV datasets found in {data_dir}.")
    full = pd.concat(dfs, ignore_index=True).drop_duplicates(subset=["url"])
    print(f"  Total dataset: {len(full)} URLs | Phishing: {full['label'].sum()} | Benign: {(full['label'] == 0).sum()}")
    return full


def evaluate_model(model, X_test, y_test, model_name: str) -> dict:
    """Computes all scientific evaluation metrics."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]
    metrics = {
        "model": model_name,
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_test, y_prob), 4),
    }
    print(f"\n{'='*50}")
    print(f"  {model_name} Evaluation Results")
    print(f"{'='*50}")
    for k, v in metrics.items():
        if k != "model":
            print(f"  {k:15s}: {v}")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Phishing"]))
    return metrics


def train(data_dir: str, output_dir: str):
    """Full training pipeline: load -> extract features -> train -> evaluate -> save."""
    print("\n[PhishShield] Starting ML Training Pipeline")
    print(f"  Data directory : {data_dir}")
    print(f"  Output directory: {output_dir}")

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    print("\n[1/4] Loading datasets...")
    df = load_dataset(data_dir)

    print("\n[2/4] Extracting 38-feature vectors (this may take several minutes)...")
    X = extract_features_batch(df["url"])
    y = df["label"].values

    # Train/test split (80/20 stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)} | Test: {len(X_test)}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, os.path.join(output_dir, "scaler.joblib"))

    print("\n[3/4] Training models...")
    all_metrics = []

    # Logistic Regression baseline
    lr = CalibratedClassifierCV(
        LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42),
        cv=5, method="isotonic",
    )
    lr.fit(X_train_scaled, y_train)
    all_metrics.append(evaluate_model(lr, X_test_scaled, y_test, "Logistic Regression (Calibrated)"))
    joblib.dump(lr, os.path.join(output_dir, "logistic_regression.joblib"))

    # Random Forest
    rf = CalibratedClassifierCV(
        RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1),
        cv=5, method="isotonic",
    )
    rf.fit(X_train, y_train)
    all_metrics.append(evaluate_model(rf, X_test, y_test, "Random Forest (Calibrated)"))
    joblib.dump(rf, os.path.join(output_dir, "random_forest.joblib"))

    # XGBoost
    if XGB_AVAILABLE:
        scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
        xgb_model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos_weight,
            use_label_encoder=False,
            eval_metric="logloss",
            random_state=42,
            n_jobs=-1,
        )
        xgb_model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False,
        )
        calibrated_xgb = CalibratedClassifierCV(xgb_model, cv="prefit", method="isotonic")
        calibrated_xgb.fit(X_train, y_train)
        all_metrics.append(evaluate_model(calibrated_xgb, X_test, y_test, "XGBoost (Calibrated)"))
        joblib.dump(calibrated_xgb, os.path.join(output_dir, "xgboost.joblib"))

    print("\n[4/4] Saving evaluation results...")
    results_path = os.path.join(output_dir, "evaluation_results.json")
    with open(results_path, "w") as f:
        json.dump(all_metrics, f, indent=2)
    print(f"  Results saved to {results_path}")
    print("\n[PhishShield] Training pipeline complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishShield ML Training Pipeline")
    parser.add_argument("--data-dir", default="ml/datasets", help="Directory containing labeled CSV datasets")
    parser.add_argument("--output-dir", default="ml/models/weights", help="Output directory for trained model weights")
    args = parser.parse_args()
    train(args.data_dir, args.output_dir)
